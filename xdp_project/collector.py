#!/usr/bin/python3
import sys
import time
import socket
import struct
import csv
import os
from bcc import BPF

# config
INTERFACE = "ens33"  
OUTPUT_FILE = "data/traffic_log.csv"
SRC_FILE = "src/monitor.c"

# ham
def ip_to_str(ip_int):
    """Chuyển IP số nguyên sang string (VD: 192.168.1.1)"""
    try:
        return socket.inet_ntoa(struct.pack("I", ip_int))
    except:
        return "0.0.0.0"

def get_tcp_flags_str(flags):
    """Giải mã cờ TCP để dễ đọc (cho debug)"""
    res = []
    if flags & 0x02: res.append("SYN")
    if flags & 0x10: res.append("ACK")
    if flags & 0x01: res.append("FIN")
    if flags & 0x04: res.append("RST")
    if flags & 0x08: res.append("PSH")
    if flags & 0x20: res.append("URG")
    return "|".join(res) if res else "."

# ================= MAIN LOGIC =================

print(f"[*] Compiling eBPF program from {SRC_FILE}...")
try:
    # Compile code C
    b = BPF(src_file=SRC_FILE)
    fn = b.load_func("xdp_prog", BPF.XDP)
except Exception as e:
    print(f"[!] Compilation Error: {e}")
    sys.exit(1)

print(f"[*] Attaching XDP program to interface: {INTERFACE}")
mode = "NATIVE"
try:
    b.attach_xdp(INTERFACE, fn, 0)
except Exception:
    try:
    
        print(f"[!] Native mode failed. Retrying with SKB/Generic mode (WSL compatible)...")
        b.attach_xdp(INTERFACE, fn, flags=BPF.XDP_FLAGS_SKB_MODE)
        mode = "SKB/GENERIC"
    except Exception as e:
        print(f"[!] Critical Error: Cannot attach XDP to {INTERFACE}. Check interface name or permissions.")
        print(f"Error detail: {e}")
        sys.exit(1)

print(f"[+] Successfully attached in {mode} mode.")

# file csv
header = ["timestamp_ns", "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "length", "tcp_flags_raw", "tcp_flags_desc"]
file_exists = os.path.isfile(OUTPUT_FILE)

# mo log file
try:
    os.makedirs("data", exist_ok=True)
    f = open(OUTPUT_FILE, "a", newline="")
    writer = csv.writer(f)
    if not file_exists:
        writer.writerow(header)
        print(f"[+] Created new log file: {OUTPUT_FILE}")
    else:
        print(f"[+] Appending to existing log file: {OUTPUT_FILE}")
except IOError as e:
    print(f"[!] File Error: {e}")
    sys.exit(1)

# event handler
def handle_event(cpu, data, size):
    event = b["events"].event(data)
    
    # trich xuat thong tin
    ts = event.timestamp
    s_ip = ip_to_str(event.src_ip)
    d_ip = ip_to_str(event.dst_ip)
    s_port = event.src_port
    d_port = event.dst_port
    proto = event.proto
    length = event.len
    flags = event.tcp_flags
    flags_desc = get_tcp_flags_str(flags)

    # 2. csv writer
    writer.writerow([ts, s_ip, d_ip, s_port, d_port, proto, length, flags, flags_desc])
    
    # 3. console log
    print(f"[{ts}] {s_ip}:{s_port} -> {d_ip}:{d_port} | Len:{length} | Flags:[{flags_desc}]")

# open perf buffer
b["events"].open_perf_buffer(handle_event)

print("[*] Collector is running... Press Ctrl+C to stop.")

try:
    while True:
        #lay data
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("\n[!] Stopping...")
finally:
    # xdp cleanup
    print("[*] Detaching XDP program...")
    try:
        b.remove_xdp(INTERFACE, flags=BPF.XDP_FLAGS_SKB_MODE)
    except:
        b.remove_xdp(INTERFACE, 0)
    
    f.close()
    print("[+] Done. Data saved.")