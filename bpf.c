/*  DISCLAIMER
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE. */

// SPDX-License-Identifier: GPL-2.0+
#define BPF_LICENSE GPL

#include "bpf.h"
#include <uapi/asm/fcntl.h>
#include <uapi/linux/ptrace.h>

#ifndef true
#define true 1
#endif
#ifndef false
#define false 0
#endif

// config data from userspace
BPF_ARRAY(config, config_t, 1);

// event patterns from userspace
BPF_ARRAY(patterns, event_pattern_t, MAX_PATTERNS);

// hash map (pid -> pidstat) to analyze file access pattern per pid and flag suspicious pid
BPF_HASH(pidstats, u32 /* pid */, pidstat_t, 1024);

#if defined(BPF_RINGBUF_OUTPUT)
#define EVENTS_RINGBUF 1
// ring buffer to report events (16 pages x 4096 bytes shared across all CPUs)
// getconf PAGESIZE returns the page size in bytes (4096)
BPF_RINGBUF_OUTPUT(events, 1 << 4);
#else
#define EVENTS_RINGBUF 0
BPF_PERF_OUTPUT(events);
#endif


// get config from BPF_ARRAY
static __always_inline config_t *get_config() {
    int zero = 0;
    return config.lookup(&zero);
}

// get pid stats from BPF_HASH
static __always_inline pidstat_t *get_stats(u32 *pid) {
    pidstat_t zero;
    __builtin_memset(&zero, 0, sizeof(zero));
    zero.event_bitmap = BITMAP_INIT;
    zero.last_reset_ts = bpf_ktime_get_ns();
    return pidstats.lookup_or_try_init(pid, &zero);
}

// update pid stats (but does not save)
static __always_inline void update_stats(config_t *conf, event_type_t type, const pidstat_t *curr, pidstat_t *updated) {
   __builtin_memcpy(updated, curr, sizeof(*updated));

    time_t now = bpf_ktime_get_ns();
    time_t time_since_reset = now - curr->last_reset_ts;
    if (conf && curr->last_reset_ts && (time_since_reset > conf->reset_period_ns)) {
        // reset counters
        __builtin_memset(updated->event_counts, 0, sizeof(counts_t) * EVENT_TYPES);
        updated->last_reset_ts = now;
    }
    // this doesnt work: updated->event_counts[type]++; - maybe try with bpf_probe_kernel_read?
    switch (type) {
        case T_OPEN:
            updated->event_counts[0]++;
            break;
        case T_CREATE:
            updated->event_counts[1]++;
            break;
        case T_DELETE:
            updated->event_counts[2]++;
            break;
        case T_ENCRYPT:
            updated->event_counts[3]++;
            break;
        case T_READ:
            updated->event_counts[4]++;
            break;
        case T_WRITE:
            updated->event_counts[5]++;
            break;
        case T_SCAN:
            updated->event_counts[6]++;
            break;
        case T_RENAME:
            updated->event_counts[7]++;
            break;
        case T_NET_SOCKET:
            updated->event_counts[8]++;
            break;
        case T_NET_CONNECT:
            updated->event_counts[9]++;
            break;
        default:
            break;
    }
    // shift and add the event_type
    updated->event_bitmap = (curr->event_bitmap << BITS_PER_EVENT) | (bitmap_t)type;
}

// analyse pid stats and compute flags
static __always_inline void analyze_stats(config_t *conf, pidstat_t* stats, event_flags_t *flags) {
    __builtin_memset(flags, 0, sizeof(event_flags_t));

    // check counters
    // TODO: consider counts per unit of time & reset counts after some delay    
    for (u8 i=0; i < EVENT_TYPES; i++) {
        if (conf && stats->event_counts[i] > conf->thresholds[i]) {
            // set the i-th bit to 1
            flags->thresholds_crossed |= (1 << i); 
            flags->severity = S_MINOR;
        }
    }

    // check pattern matches
    for (u8 i=0; i < MAX_PATTERNS; i++) {
        int k = i;
        event_pattern_t *pat = patterns.lookup(&k);
        if (pat && pat->bitmask) {
            // 0xABCDE012 & 0x00000FFF == 0x00000012
            if ((stats->event_bitmap & pat->bitmask) == pat->bitmap) {
                flags->pattern_id = i + 1;
                flags->severity = S_MAJOR;
                stats->pattern_counts++;
                // reset the bitmap
                stats->event_bitmap = BITMAP_INIT;
                break;
            }
        }
    }
}

// submit event for userspace via ring buffer
static __always_inline int submit_event(void *ctx, u32 pid, event_type_t type, event_flags_t flags, const char *filename) {
#if EVENTS_RINGBUF
    event_t *event = events.ringbuf_reserve(sizeof(event_t));
    if (!event) {
        return 1;
    }
#else
    event_t local = {};
    event_t *event = &local;
#endif
    event->ts = bpf_ktime_get_ns();
    event->pid = pid;
    event->type = type;
    event->flags = flags;

    bpf_get_current_comm(&event->comm, TASK_COMM_LEN);

    if (filename) {
        int ret = bpf_probe_read_user_str(event->filename, FILENAME_SIZE, filename);
        if (ret < 0) {
            bpf_probe_read_kernel_str(event->filename, FILENAME_SIZE, filename);
        }
    } else {
        event->filename[0] = '\0';
    }

#if EVENTS_RINGBUF
    events.ringbuf_submit(event, 0 /* flags */);
#else
    events.perf_submit(ctx, event, sizeof(*event));
#endif
    return 0;
}

// update stats, analyse and submit event
static __always_inline int update_and_submit(void *ctx, event_type_t type, const char* filename, int emit_always) {
    u32 pid = bpf_get_current_pid_tgid();

    // get config
    config_t *conf = get_config();

    // get stats from BPF_HASH
    pidstat_t *curr = get_stats(&pid);
    if (!curr) {
        // cleanup old pid entries in pidstats?
        return 0;
    }

    // update stats
    pidstat_t updated;
    update_stats(conf, type, curr, &updated);

    // analyse stats
    event_flags_t flags;
    analyze_stats(conf, &updated, &flags);

   // save stats in BPF_HASH
    pidstats.update(&pid, &updated);

    // Emit logic:
    // - Submit ALL events to userspace (for log_all.csv)
    // - But emit_always flag controls whether they go to log.csv (original logic)
    // - If emit_always = 1: submit (will be in log.csv if severity >= min_severity)
    // - If emit_always = 0: submit (will be in log.csv only if pattern matched)
    //   All events go to log_all.csv, but only filtered events go to log.csv
    return submit_event(ctx, pid, type, flags, filename);
}

// sys_open and sys_openat both have args->filename
TRACEPOINT_PROBE(syscalls, sys_enter_open) {
    // args from /sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/format
    event_type_t type = T_OPEN;
    if (args->flags & O_CREAT) {
        type = T_CREATE;
    }
    return update_and_submit(args, type, args->filename, true);
}

// sys_open and sys_openat both have args->filename
TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    // args from /sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/format
    event_type_t type = T_OPEN;
    if (args->flags & O_CREAT) {
        type = T_CREATE;
    }
    return update_and_submit(args, type, args->filename, true);
}

// sys_unlink and sys_unlinkat both have args->pathname
TRACEPOINT_PROBE(syscalls, sys_enter_unlink) {
    // args from /sys/kernel/debug/tracing/events/syscalls/sys_enter_unlink/format
    return update_and_submit(args, T_DELETE, args->pathname, true);
}

// sys_unlink and sys_unlinkat both have args->pathname
TRACEPOINT_PROBE(syscalls, sys_enter_unlinkat) {
    // args from /sys/kernel/debug/tracing/events/syscalls/sys_enter_unlink/format
    return update_and_submit(args, T_DELETE, args->pathname, true);
}

// uprobe on openssl
// int EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
//                        ENGINE *impl, const unsigned char *key, const unsigned char *iv);
// int EVP_CipherInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
//                       ENGINE *impl, const unsigned char *key, const unsigned char *iv, int enc);
int trace_encrypt1(struct pt_regs *ctx) {
    const char func[FILENAME_SIZE] = "EVP_EncryptInit_ex";
    return update_and_submit(ctx, T_ENCRYPT, func, true);
}
// int EVP_SealInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
//                  unsigned char **ek, int *ekl, unsigned char *iv,
//                  EVP_PKEY **pubk, int npubk);
int trace_encrypt2(struct pt_regs *ctx) {
    const char func[FILENAME_SIZE] = "EVP_SealInit";
    return update_and_submit(ctx, T_ENCRYPT, func, true);
}

TRACEPOINT_PROBE(syscalls, sys_enter_read) {
    const char func[FILENAME_SIZE] = "sys_read";
    return update_and_submit(args, T_READ, func, false);
}

TRACEPOINT_PROBE(syscalls, sys_enter_write) {
    const char func[FILENAME_SIZE] = "sys_write";
    return update_and_submit(args, T_WRITE, func, false);
}

TRACEPOINT_PROBE(syscalls, sys_enter_getdents64) {
    const char func[FILENAME_SIZE] = "sys_getdents64";
    return update_and_submit(args, T_SCAN, func, false);
}

TRACEPOINT_PROBE(syscalls, sys_enter_rename) {
    return update_and_submit(args, T_RENAME, args->newname, true);
}

TRACEPOINT_PROBE(syscalls, sys_enter_renameat) {
    return update_and_submit(args, T_RENAME, args->newname, true);
}

TRACEPOINT_PROBE(syscalls, sys_enter_renameat2) {
    return update_and_submit(args, T_RENAME, args->newname, true);
}

TRACEPOINT_PROBE(syscalls, sys_enter_socket) {
    const char func[FILENAME_SIZE] = "sys_socket";
    return update_and_submit(args, T_NET_SOCKET, func, false);
}

TRACEPOINT_PROBE(syscalls, sys_enter_connect) {
    const char func[FILENAME_SIZE] = "sys_connect";
    return update_and_submit(args, T_NET_CONNECT, func, false);
}
