#!/usr/bin/python3
import sys
import time
import socket
import struct
import csv
import os
from bcc import BPF

# --- CAU HINH ---
INTERFACE = "enp6s18"        # Ten card mang
# Duong dan co dinh 
OUTPUT_FILE = "/home/minhbui/DATN_Quy/xdp_project/data/traffic_log.csv"
SRC_FILE = "src/monitor.c"
SAMPLE_RATE = 4           # Cu 4 goi tin ghi 1 dong

# --- CAC HAM HO TRO ---
def ip_to_str(ip_int):
    try:
        return socket.inet_ntoa(struct.pack("I", ip_int))
    except:
        return "0.0.0.0"

def get_tcp_flags_str(flags):
    res = []
    if flags & 0x02: res.append("SYN")
    if flags & 0x10: res.append("ACK")
    if flags & 0x01: res.append("FIN")
    if flags & 0x04: res.append("RST")
    if flags & 0x08: res.append("PSH")
    if flags & 0x20: res.append("URG")
    return "|".join(res) if res else "."

# --- KHOI TAO EBPF ---
print(f"[*] Dang compile chuong trinh eBPF tu {SRC_FILE}...")
try:
    b = BPF(src_file=SRC_FILE)
    fn = b.load_func("xdp_prog", BPF.XDP)
except Exception as e:
    print(f"[!] Loi bien dich: {e}")
    sys.exit(1)

print(f"[*] Dang gan XDP vao interface: {INTERFACE}")
mode = "NATIVE"
try:
    b.attach_xdp(INTERFACE, fn, 0)
except Exception:
    try:
        print(f"[!] Native mode that bai. Chuyen sang SKB/Generic...")
        b.attach_xdp(INTERFACE, fn, flags=BPF.XDP_FLAGS_SKB_MODE)
        mode = "SKB/GENERIC"
    except Exception as e:
        print(f"[!] Loi: Khong the gan XDP. {e}")
        sys.exit(1)

print(f"[+] Da gan thanh cong ({mode}).")

# --- KHOI TAO FILE LOG (MOT FILE DUY NHAT) ---
# Tao thu muc neu chua co
log_dir = os.path.dirname(OUTPUT_FILE)
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

header = ["timestamp_ns", "src_ip", "dst_ip", "src_port", "dst_port", 
          "protocol", "length", "tcp_flags_raw", "tcp_flags_desc", "label"]

# Kiem tra file da ton tai chua de ghi Header
file_exists = os.path.isfile(OUTPUT_FILE)

# Mo file o che do 'a' (Append - Ghi noi tiep)
# buffering=1 (Line buffering) de dam bao ghi xuong dia nhanh
f = open(OUTPUT_FILE, "a", newline="", buffering=1)
writer = csv.writer(f)

if not file_exists:
    writer.writerow(header)
    print(f"[*] Tao file moi: {OUTPUT_FILE}")
else:
    print(f"[*] Ghi vao file: {OUTPUT_FILE}")

packet_count = 0

# --- XU LY SU KIEN ---
def handle_event(cpu, data, size):
    global packet_count
    
    # Logic Lay Mau (Sampling)
    packet_count += 1
    if packet_count % SAMPLE_RATE != 0:
        return

    event = b["events"].event(data)
    
    ts = event.timestamp
    s_ip = ip_to_str(event.src_ip)
    d_ip = ip_to_str(event.dst_ip)
    s_port = event.src_port
    d_port = event.dst_port
    proto = event.proto
    length = event.len
    flags = event.tcp_flags
    flags_desc = get_tcp_flags_str(flags)

    writer.writerow([ts, s_ip, d_ip, s_port, d_port, proto, length, flags, flags_desc, "NORMAL"])
    # print(f"[{ts}] {s_ip}:{s_port} -> {d_ip}:{d_port} | Len:{length} | Flags:[{flags_desc}]")
    f.flush()

b["events"].open_perf_buffer(handle_event)

print(f"[*] Collector dang chay...  Sample 1/{SAMPLE_RATE}")
print("Nhan Ctrl+C de dung.")

try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("\n[!] Dang dung...")
finally:
    try:
        b.remove_xdp(INTERFACE, flags=BPF.XDP_FLAGS_SKB_MODE)
    except:
        b.remove_xdp(INTERFACE, 0)
    if f: f.close()
    print("[+] DONE!")