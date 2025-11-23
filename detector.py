#!/usr/bin/python3

#   DISCLAIMER
#   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
#   SOFTWARE.

import os
import sys
import time
import ctypes
from bcc import BPF
import csv

# bitmap encoding details (keep in sync with <bpf.h>)
BITS_PER_EVENT = 4
EVENT_MASK = (1 << BITS_PER_EVENT) - 1

class EventType:
    OPEN = 0
    CREATE = 1
    DELETE = 2
    ENCRYPT = 3
    READ = 4
    WRITE = 5
    SCAN = 6
    RENAME = 7
    NET_SOCKET = 8
    NET_CONNECT = 9

# see <bpf.h>
EVENT_TYPES = EventType.NET_CONNECT + 1

EVENT_TYPE_NAMES = [
    "Open",
    "Crea",
    "Del",
    "Enc",
    "Read",
    "Writ",
    "Scan",
    "Ren",
    "Sock",
    "Conn",
]

THRESHOLD_LETTERS = [
    "O",
    "C",
    "D",
    "E",
    "R",
    "W",
    "S",
    "N",
    "K",
    "T",
]

THRESHOLD_HEADERS = [
    "OPEN",
    "CREATE",
    "DELETE",
    "ENCRYPT",
    "READ",
    "WRITE",
    "SCAN",
    "RENAME",
    "NET_SOCKET",
    "NET_CONNECT",
]

class Config(ctypes.Structure):
    _fields_ = [
        ('thresholds', ctypes.c_uint16 * EVENT_TYPES),
        ('reset_period_ns', ctypes.c_uint32),
        ('min_severity', ctypes.c_uint8),
    ]

def update_config(b: BPF):
    # 10 billion nanoseconds = 10 seconds
    thresholds = ctypes.c_uint16 * EVENT_TYPES
    b['config'][ctypes.c_int(0)] = Config(
        thresholds(
            50,   # open (same as original)
            25,   # create (same as original)
            25,   # delete (same as original)
            50,   # encrypt (same as original)
            500,  # read (increased to avoid false positives from normal processes)
            500,  # write (increased to avoid false positives from normal processes)
            200,  # scan (getdents64) - increased to avoid false positives
            40,   # rename
            20,   # net socket
            10,   # net connect
        ),
        10_000_000_000,
        0
    )

# see <bpf.h>
class Pattern(ctypes.Structure):
    _fields_ = [
        ('bitmap', ctypes.c_uint32),
        ('bitmask', ctypes.c_uint32),
    ]

def encode_pattern(sequence):
    bitmap = 0
    bitmask = 0
    for event in sequence:
        bitmap = (bitmap << BITS_PER_EVENT) | event
        bitmask = (bitmask << BITS_PER_EVENT) | EVENT_MASK
    return Pattern(bitmap, bitmask)

def update_patterns(b: BPF):
    pattern_sequences = [
        # directory traversal followed by multiple reads/writes
        [EventType.SCAN, EventType.SCAN, EventType.OPEN, EventType.READ, EventType.READ, EventType.WRITE],
        # scan + encrypt-like rename
        [EventType.SCAN, EventType.OPEN, EventType.READ, EventType.WRITE, EventType.RENAME],
        # burst of file changes followed by outbound connection
        [EventType.OPEN, EventType.WRITE, EventType.DELETE, EventType.NET_CONNECT],
    ]
    values = [encode_pattern(seq) for seq in pattern_sequences]
    patterns = b['patterns']
    for k,v in enumerate(values):
        patterns[ctypes.c_int(k)] = v

# see <bpf.h>
class Flags(ctypes.Structure):
    _fields_ = [
        ('severity', ctypes.c_uint8),
        ('pattern_id', ctypes.c_uint8),
        ('thresholds_crossed', ctypes.c_uint16),
    ]

# see <bpf.h> and <linux/sched.h>
FILENAME_SIZE = 64
TASK_COMM_LEN = 16
class Event(ctypes.Structure):
    _fields_ = [
        ('ts', ctypes.c_uint64),
        ('pid', ctypes.c_uint32),
        ('type', ctypes.c_uint),
        ('flags', Flags),
        ('filename', ctypes.c_char * FILENAME_SIZE),
        ('comm', ctypes.c_char * TASK_COMM_LEN),
    ]

def decode_type(t: ctypes.c_uint) -> str:
    try:
        return EVENT_TYPE_NAMES[t]
    except IndexError:
        return f"T{t}"

def decode_severity(s: ctypes.c_uint8) -> str:
    name = {0: "OK", 1: "MIN", 2: "MAJ"}
    return name[s]

def decode_pattern(p: ctypes.c_uint8) -> str:
    return "P%d" % p if p > 0 else "-"

def decode_thresholds(t: ctypes.c_uint16) -> str:
    output = []
    for idx, letter in enumerate(THRESHOLD_LETTERS):
        output.append(letter if t & (1 << idx) else "-")
    return "".join(output)

def unpack_thresholds(t: ctypes.c_uint16):
    output = []
    for k in range(EVENT_TYPES):
        if t & (1 << k):
            output.append(1)
        else:
            output.append(0)
    return output

# find library pathname
def find_lib(lib: str) -> str:
    for path in ['/usr/lib/', '/opt']:
        for root, _, files in os.walk(path):
            if lib in files:
                return os.path.join(root, lib)
    return None

def save_data(event: Event, writer_obj):
    # write data to csv
    writer_obj.writerow([event.ts,
                         event.pid, 
                         event.type, 
                         event.flags.severity, 
                         event.flags.pattern_id, 
                         *unpack_thresholds(event.flags.thresholds_crossed), # transforms to multiple args/columns
                         event.filename.decode('utf-8')])

def print_event(_ctx, data, _size):
    event = ctypes.cast(data, ctypes.POINTER(Event)).contents
    
    # Always save to log_all.csv (all events)
    save_data(event, writer_all)
    
    # Check if should be in log.csv (original logic):
    # - emit_always events (OPEN, CREATE, DELETE, ENCRYPT, RENAME): if severity >= min_severity
    # - analytics events (READ, WRITE, SCAN, NET): only if pattern matched (severity >= S_MAJOR)
    emit_always_types = [EventType.OPEN, EventType.CREATE, EventType.DELETE, EventType.ENCRYPT, EventType.RENAME]
    is_emit_always = event.type in emit_always_types
    
    should_log = False
    should_print = False
    
    if is_emit_always:
        # emit_always events: log and print if severity >= min_severity (which is 0 by default)
        should_log = True
        should_print = True
    else:
        # analytics events: only log and print if pattern matched (severity >= S_MAJOR = 2)
        should_log = (event.flags.severity >= 2)
        should_print = should_log
    
    # Save to log.csv only if should_log (original logic)
    if should_log:
        save_data(event, writer)
    
    # Print to terminal only if should_print
    if should_print:
        print("%-6d %-6d %-16s %-4s %-4s %-5s %-10s %-64s" % (
            int(event.ts / 1e6),
            event.pid,
            event.comm.decode('utf-8'),
            decode_type(event.type), 
            decode_severity(event.flags.severity), 
            decode_pattern(event.flags.pattern_id), 
            decode_thresholds(event.flags.thresholds_crossed), 
            event.filename.decode('utf-8')))

def handle_perf_event(_cpu, data, size):
    print_event(None, data, size)

def runas_root() -> bool:
    return os.getuid() == 0

def main():
    b = BPF(src_file="bpf.c", cflags=["-Wno-macro-redefined"], debug=4)

    # send config + patterns to ebpf programs
    update_config(b)
    update_patterns(b)

    # the path to libcrypto may differ from OS to OS
    # check symbol address with nm -gD /path/to/lib.so or readelf -Ws --dyn-syms /path/to/lib.so
    for lib in ['libcrypto.so.1.1', 'libcrypto.so.3']:
        pathname = find_lib(lib)
        if pathname:
            b.attach_uprobe(name=pathname, sym="EVP_EncryptInit_ex", fn_name="trace_encrypt1")
            b.attach_uprobe(name=pathname, sym="EVP_CipherInit_ex", fn_name="trace_encrypt1")
            b.attach_uprobe(name=pathname, sym="EVP_SealInit", fn_name="trace_encrypt2")
 
    events_map = b['events']
    use_ring_buffer = True
    try:
        events_map.open_ring_buffer(print_event)
    except Exception as exc:
        use_ring_buffer = False
        print(f"Ring buffer unavailable ({exc}), falling back to perf buffer.")
        events_map.open_perf_buffer(handle_perf_event)

    print("Printing file & crypto events, ctrl-c to exit.")
    print("%-6s %-6s %-16s %-4s %-4s %-5s %-10s %-64s" % 
          ("TS", "PID", "COMM", "TYPE", "FLAG", "PATT", "THRESH", "FILENAME"))
    # headers for both CSV files
    writer.writerow(
        ["TS", "PID", "TYPE", "FLAG", "PATTERN", *THRESHOLD_HEADERS, "FILENAME"]
    )
    writer_all.writerow(
        ["TS", "PID", "TYPE", "FLAG", "PATTERN", *THRESHOLD_HEADERS, "FILENAME"]
    )

    # loop with callback to print events
    try:
        while 1:
            if use_ring_buffer:
                b.ring_buffer_consume()
                time.sleep(0.5)
            else:
                b.perf_buffer_poll()
    except KeyboardInterrupt:
        f.close()
        f_all.close()
        sys.exit()
    
    f.close()
    f_all.close()

if __name__ == '__main__':
    if not runas_root():
        print("You must run this program as root or with sudo.")
        sys.exit()
    
    # log.csv: only events that would be emitted (original logic)
    f = open('log.csv', 'w', encoding='UTF8', newline='')
    writer = csv.writer(f)
    
    # log_all.csv: ALL events (for debugging/verification)
    f_all = open('log_all.csv', 'w', encoding='UTF8', newline='')
    writer_all = csv.writer(f_all)
    
    main()
