#!/usr/bin/env python3
"""
FastPing - High-Performance Concurrent IP Scanner
==================================================
Scans millions of IPv4 addresses with high throughput and near-zero memory footprint.
100% Python Standard Library - zero third-party dependencies required.

Features:
- Windows: Native IcmpSendEcho via Win32 iphlpapi (5,000 - 10,000+ IPs/sec, no admin needed)
- Linux / macOS: Unprivileged ICMP datagram sockets & raw ICMP with subprocess fallback
- TCP Ping mode: Fast connection handshake probe (ideal for CDN/Cloudflare clean IP scanning)
- Streaming generator: Zero RAM consumption for CIDR blocks or multi-gigabyte IP files
- Safe resume & checkpointing: Never destructively rewrites your input files
- Latency tracking & sorting: Records RTT in milliseconds and optionally sorts by lowest ping
- Live progress dashboard: Real-time scan rate (IPs/s), ETA, and alive statistics
"""

import sys
import os
import time
import socket
import struct
import select
import signal
import json
import argparse
import ipaddress
import threading
import queue
from datetime import timedelta
from typing import Generator, Optional, Tuple, List, TextIO

# Optional Windows keyboard support (built-in stdlib on Windows)
try:
    import msvcrt
    HAS_MSVCRT = True
except ImportError:
    HAS_MSVCRT = False


# =====================================================================
# 1. Pinger Implementations (Windows ICMP, Unix ICMP, TCP)
# =====================================================================

class WindowsIcmpPinger:
    """High-speed native ICMP using Windows iphlpapi.dll without admin rights."""
    
    def __init__(self):
        import ctypes
        from ctypes import wintypes
        
        self.ctypes = ctypes
        self.wintypes = wintypes
        self.iphlpapi = ctypes.windll.iphlpapi
        
        class IP_OPTION_INFORMATION(ctypes.Structure):
            _fields_ = [
                ('Ttl', ctypes.c_ubyte),
                ('Tos', ctypes.c_ubyte),
                ('Flags', ctypes.c_ubyte),
                ('OptionsSize', ctypes.c_ubyte),
                ('OptionsData', ctypes.c_char_p)
            ]

        class ICMP_ECHO_REPLY(ctypes.Structure):
            _fields_ = [
                ('Address', ctypes.c_ulong),
                ('Status', ctypes.c_ulong),
                ('RoundTripTime', ctypes.c_ulong),
                ('DataSize', ctypes.c_ushort),
                ('Reserved', ctypes.c_ushort),
                ('Data', ctypes.c_void_p),
                ('Options', IP_OPTION_INFORMATION)
            ]

        self.ICMP_ECHO_REPLY = ICMP_ECHO_REPLY
        
        self._IcmpCreateFile = self.iphlpapi.IcmpCreateFile
        self._IcmpCreateFile.restype = wintypes.HANDLE
        
        self._IcmpCloseHandle = self.iphlpapi.IcmpCloseHandle
        self._IcmpCloseHandle.argtypes = [wintypes.HANDLE]
        self._IcmpCloseHandle.restype = wintypes.BOOL
        
        self._IcmpSendEcho = self.iphlpapi.IcmpSendEcho
        self._IcmpSendEcho.argtypes = [
            wintypes.HANDLE,
            ctypes.c_ulong,
            ctypes.c_char_p,
            ctypes.c_ushort,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_ulong,
            ctypes.c_ulong
        ]
        self._IcmpSendEcho.restype = ctypes.c_ulong
        
        self._local = threading.local()
        self._payload = b'FastPingEchoData'
        self._reply_size = ctypes.sizeof(ICMP_ECHO_REPLY) + len(self._payload) + 16

    def _get_handle(self):
        handle = getattr(self._local, 'handle', None)
        if handle is None or handle == -1:
            handle = self._IcmpCreateFile()
            self._local.handle = handle
        return handle

    def ping(self, ip_str: str, timeout_ms: int = 800) -> Tuple[bool, float]:
        try:
            ip_val = struct.unpack('<I', socket.inet_aton(ip_str))[0]
        except Exception:
            return False, 0.0

        handle = self._get_handle()
        reply_buf = self.ctypes.create_string_buffer(self._reply_size)
        
        res = self._IcmpSendEcho(
            handle,
            ip_val,
            self._payload,
            len(self._payload),
            None,
            self.ctypes.cast(reply_buf, self.ctypes.c_void_p),
            self._reply_size,
            timeout_ms
        )
        
        if res > 0:
            reply = self.ICMP_ECHO_REPLY.from_buffer(reply_buf)
            if reply.Status == 0:  # IP_SUCCESS
                rtt = float(reply.RoundTripTime)
                return True, max(rtt, 0.1)
        return False, 0.0

    def close(self):
        handle = getattr(self._local, 'handle', None)
        if handle is not None and handle != -1:
            try:
                self._IcmpCloseHandle(handle)
            except Exception:
                pass
            self._local.handle = None


class UnixIcmpPinger:
    """Cross-platform ICMP for Linux/macOS using DGRAM/RAW sockets with subprocess fallback."""
    
    def __init__(self):
        self._socket_type = None
        self._payload = b'FastPingEchoData'
        self._test_socket()

    def _checksum(self, data: bytes) -> int:
        if len(data) % 2:
            data += b'\x00'
        s = sum(struct.unpack(f'!{len(data)//2}H', data))
        s = (s >> 16) + (s & 0xffff)
        s += s >> 16
        return (~s) & 0xffff

    def _test_socket(self):
        for st in (socket.SOCK_DGRAM, socket.SOCK_RAW):
            try:
                s = socket.socket(socket.AF_INET, st, socket.IPPROTO_ICMP)
                s.close()
                self._socket_type = st
                return
            except (PermissionError, OSError):
                continue
        self._socket_type = None  # Will fall back to subprocess ping

    def ping(self, ip_str: str, timeout_ms: int = 800) -> Tuple[bool, float]:
        timeout_s = timeout_ms / 1000.0
        if self._socket_type is not None:
            try:
                with socket.socket(socket.AF_INET, self._socket_type, socket.IPPROTO_ICMP) as s:
                    s.settimeout(timeout_s)
                    pid = os.getpid() & 0xFFFF
                    seq = 1
                    header = struct.pack('!BBHHH', 8, 0, 0, pid, seq)
                    chk = self._checksum(header + self._payload)
                    header = struct.pack('!BBHHH', 8, 0, chk, pid, seq)
                    packet = header + self._payload
                    
                    t0 = time.time()
                    s.sendto(packet, (ip_str, 1))
                    
                    while True:
                        ready = select.select([s], [], [], timeout_s)
                        if not ready[0]:
                            return False, 0.0
                        recv_packet, _ = s.recvfrom(1024)
                        elapsed = (time.time() - t0) * 1000.0
                        # ICMP reply type is 0
                        # In raw socket, IP header is first 20 bytes; in DGRAM it may start at 0
                        icmp_header = recv_packet[20:28] if len(recv_packet) >= 28 else recv_packet[:8]
                        if len(icmp_header) >= 8:
                            itype, icode = struct.unpack('!BB', icmp_header[:2])
                            if itype == 0:
                                return True, round(max(elapsed, 0.1), 1)
            except Exception:
                pass
        
        # Subprocess fallback
        import subprocess
        try:
            t0 = time.time()
            flag = '-c'
            w_flag = '-W' if sys.platform != 'darwin' else '-t'
            w_val = str(max(1, int(timeout_s)))
            cmd = ['ping', flag, '1', w_flag, w_val, ip_str]
            res = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout_s + 0.5)
            elapsed = (time.time() - t0) * 1000.0
            if res.returncode == 0:
                return True, round(max(elapsed, 0.1), 1)
        except Exception:
            pass
        return False, 0.0

    def close(self):
        pass


class TcpPinger:
    """High-speed TCP handshake probe for HTTP/HTTPS/CDN clean IP scanning."""
    
    def __init__(self, port: int = 443):
        self.port = port

    def ping(self, ip_str: str, timeout_ms: int = 800) -> Tuple[bool, float]:
        timeout_s = timeout_ms / 1000.0
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout_s)
            t0 = time.perf_counter()
            s.connect((ip_str, self.port))
            rtt = (time.perf_counter() - t0) * 1000.0
            s.close()
            return True, round(max(rtt, 0.1), 1)
        except Exception:
            return False, 0.0

    def close(self):
        pass


def get_pinger(mode: str = 'icmp', tcp_port: int = 443):
    if mode.lower() == 'tcp':
        return TcpPinger(port=tcp_port)
    if os.name == 'nt':
        return WindowsIcmpPinger()
    return UnixIcmpPinger()


# =====================================================================
# 2. IP Streamer & Generator (Zero-RAM CIDR & File Iteration)
# =====================================================================

def parse_target_source(source: str) -> Generator[str, None, None]:
    """
    Yields IP strings one-by-one from a CIDR, range, plain IP, or file path.
    Streaming and memory-friendly.
    """
    source = source.strip()
    if not source or source.startswith('#'):
        return

    # 1. CIDR notation (e.g., 104.16.0.0/16 or 1.1.1.1/32)
    if '/' in source:
        try:
            net = ipaddress.ip_network(source, strict=False)
            if net.num_addresses == 1:
                yield str(net.network_address)
            elif net.num_addresses == 2:
                for ip in net:
                    yield str(ip)
            else:
                for host in net.hosts():
                    yield str(host)
            return
        except ValueError:
            pass

    # 2. IP Range notation (e.g., 192.168.1.1-192.168.1.100 or 192.168.1.1-100)
    if '-' in source and not os.path.exists(source):
        parts = source.split('-')
        if len(parts) == 2:
            try:
                start_str, end_str = parts[0].strip(), parts[1].strip()
                if '.' not in end_str:
                    # e.g. 192.168.1.10-50
                    prefix = start_str.rsplit('.', 1)[0]
                    end_str = f"{prefix}.{end_str}"
                start_int = int(ipaddress.IPv4Address(start_str))
                end_int = int(ipaddress.IPv4Address(end_str))
                if start_int <= end_int:
                    for ip_int in range(start_int, end_int + 1):
                        yield str(ipaddress.IPv4Address(ip_int))
                    return
            except Exception:
                pass

    # 3. File path
    if os.path.isfile(source):
        with open(source, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    # A file may contain CIDRs or IPs on each line
                    yield from parse_target_source(line)
        return

    # 4. Single IP
    try:
        ipaddress.IPv4Address(source)
        yield source
    except ValueError:
        pass


def count_potential_targets(sources: List[str]) -> Optional[int]:
    """Quickly estimate total targets without expanding huge files if possible."""
    total = 0
    for src in sources:
        src = src.strip()
        if not src or src.startswith('#'):
            continue
        if '/' in src:
            try:
                net = ipaddress.ip_network(src, strict=False)
                total += max(net.num_addresses - 2, 1) if net.num_addresses > 2 else net.num_addresses
                continue
            except ValueError:
                pass
        if os.path.isfile(src):
            # File total is unknown without full scan; return None to indicate streaming mode
            return None
        total += 1
    return total if total > 0 else None


# =====================================================================
# 3. Safe Checkpointing & State Persistence
# =====================================================================

class CheckpointManager:
    """Tracks scan progress so scans can be paused and resumed safely."""

    def __init__(self, checkpoint_path: str):
        self.path = checkpoint_path

    def load(self) -> int:
        if os.path.exists(self.path):
            try:
                with open(self.path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    return data.get('processed_count', 0)
            except Exception:
                return 0
        return 0

    def save(self, processed_count: int, alive_count: int):
        try:
            tmp = f"{self.path}.tmp"
            with open(tmp, 'w', encoding='utf-8') as f:
                json.dump({
                    'processed_count': processed_count,
                    'alive_count': alive_count,
                    'timestamp': time.time()
                }, f)
            if os.path.exists(self.path):
                os.remove(self.path)
            os.rename(tmp, self.path)
        except Exception:
            pass

    def cleanup(self):
        if os.path.exists(self.path):
            try:
                os.remove(self.path)
            except Exception:
                pass


# =====================================================================
# 4. High-Performance Output Writer
# =====================================================================

class ResultWriter:
    """Buffered background writer that handles output files and latency statistics."""

    def __init__(self, output_txt: str, output_csv: Optional[str] = None, collect_sorted: bool = False):
        self.output_txt = output_txt
        self.output_csv = output_csv
        self.collect_sorted = collect_sorted
        self.queue: queue.Queue = queue.Queue(maxsize=10000)
        self.stop_event = threading.Event()
        self.alive_count = 0
        self.rtt_sum = 0.0
        self.rtt_min = float('inf')
        self.rtt_max = 0.0
        self.fastest_ip: Optional[str] = None
        self.collected: List[Tuple[str, float]] = []
        self._thread = threading.Thread(target=self._writer_loop, daemon=True)

    def start(self):
        self._thread.start()

    def record(self, ip: str, rtt: float):
        self.queue.put((ip, rtt))

    def _writer_loop(self):
        txt_file: Optional[TextIO] = None
        csv_file: Optional[TextIO] = None
        try:
            txt_file = open(self.output_txt, 'a', encoding='utf-8', buffering=65536)
            if self.output_csv:
                write_header = not os.path.exists(self.output_csv) or os.path.getsize(self.output_csv) == 0
                csv_file = open(self.output_csv, 'a', encoding='utf-8', buffering=65536)
                if write_header:
                    csv_file.write("ip,latency_ms\n")

            buffer_txt: List[str] = []
            buffer_csv: List[str] = []
            last_flush = time.time()

            while not self.stop_event.is_set() or not self.queue.empty():
                try:
                    ip, rtt = self.queue.get(timeout=0.2)
                except queue.Empty:
                    if time.time() - last_flush > 1.0:
                        if buffer_txt and txt_file:
                            txt_file.writelines(buffer_txt)
                            txt_file.flush()
                            buffer_txt.clear()
                        if buffer_csv and csv_file:
                            csv_file.writelines(buffer_csv)
                            csv_file.flush()
                            buffer_csv.clear()
                        last_flush = time.time()
                    continue

                self.alive_count += 1
                self.rtt_sum += rtt
                if rtt < self.rtt_min:
                    self.rtt_min = rtt
                    self.fastest_ip = ip
                if rtt > self.rtt_max:
                    self.rtt_max = rtt
                
                if self.collect_sorted:
                    self.collected.append((ip, rtt))

                buffer_txt.append(f"{ip}\n")
                if csv_file:
                    buffer_csv.append(f"{ip},{rtt:.1f}\n")

                if len(buffer_txt) >= 200 or (time.time() - last_flush > 1.0):
                    if txt_file:
                        txt_file.writelines(buffer_txt)
                        txt_file.flush()
                        buffer_txt.clear()
                    if csv_file:
                        csv_file.writelines(buffer_csv)
                        csv_file.flush()
                        buffer_csv.clear()
                    last_flush = time.time()

            # Final flush
            if buffer_txt and txt_file:
                txt_file.writelines(buffer_txt)
                txt_file.flush()
            if buffer_csv and csv_file:
                csv_file.writelines(buffer_csv)
                csv_file.flush()

        finally:
            if txt_file:
                txt_file.close()
            if csv_file:
                csv_file.close()

    def stop(self):
        self.stop_event.set()
        self._thread.join()

    def write_sorted_output(self, sorted_path: str):
        if not self.collected:
            return
        sorted_results = sorted(self.collected, key=lambda x: x[1])
        with open(sorted_path, 'w', encoding='utf-8') as f:
            if sorted_path.endswith('.csv'):
                f.write("ip,latency_ms\n")
                for ip, rtt in sorted_results:
                    f.write(f"{ip},{rtt:.1f}\n")
            else:
                for ip, _ in sorted_results:
                    f.write(f"{ip}\n")


# =====================================================================
# 5. High-Throughput Scanner Engine
# =====================================================================

class FastScanner:
    """Core scanning orchestrator."""

    def __init__(
        self,
        sources: List[str],
        output_txt: str = "alive_ips.txt",
        output_csv: Optional[str] = None,
        mode: str = "icmp",
        tcp_port: int = 443,
        workers: int = 400,
        timeout_ms: int = 800,
        resume: bool = False,
        sort_results: bool = False,
        sorted_output: Optional[str] = None
    ):
        self.sources = sources
        self.output_txt = output_txt
        self.output_csv = output_csv
        self.mode = mode.lower()
        self.tcp_port = tcp_port
        self.workers = max(10, min(workers, 2000))
        self.timeout_ms = timeout_ms
        self.resume = resume
        self.sort_results = sort_results
        self.sorted_output = sorted_output or ("alive_ips_sorted.csv" if output_csv else "alive_ips_sorted.txt")
        
        self.checkpoint = CheckpointManager(f".{os.path.basename(output_txt)}.checkpoint")
        self.writer = ResultWriter(self.output_txt, self.output_csv, collect_sorted=sort_results)
        
        self.task_queue: queue.Queue = queue.Queue(maxsize=self.workers * 3)
        self.stop_flag = threading.Event()
        self.user_interrupted = False
        self.processed_count = 0
        self.lock = threading.Lock()
        self.total_estimated: Optional[int] = None

    def _worker(self):
        pinger = get_pinger(self.mode, self.tcp_port)
        try:
            while not self.stop_flag.is_set():
                try:
                    ip = self.task_queue.get(timeout=0.1)
                except queue.Empty:
                    continue

                if ip is None:  # Sentinel
                    self.task_queue.task_done()
                    break

                try:
                    alive, rtt = pinger.ping(ip, timeout_ms=self.timeout_ms)
                    if alive:
                        self.writer.record(ip, rtt)
                except Exception:
                    pass
                finally:
                    with self.lock:
                        self.processed_count += 1
                    self.task_queue.task_done()
        finally:
            pinger.close()

    def _feeder(self, skip_count: int):
        skipped = 0
        for src in self.sources:
            for ip in parse_target_source(src):
                if self.stop_flag.is_set():
                    return
                if skipped < skip_count:
                    skipped += 1
                    continue
                while not self.stop_flag.is_set():
                    try:
                        self.task_queue.put(ip, timeout=0.1)
                        break
                    except queue.Full:
                        continue
        # Send sentinels
        for _ in range(self.workers):
            self.task_queue.put(None)

    def _check_key_press(self) -> bool:
        if HAS_MSVCRT and msvcrt.kbhit():
            ch = msvcrt.getch()
            if ch in (b's', b'S', b'q', b'Q', b'\x03'):
                return True
        return False

    def run(self):
        # 1. Checkpoint & Resume
        skip_count = 0
        if self.resume:
            skip_count = self.checkpoint.load()
            if skip_count > 0:
                print(f"[i] Resuming scan: skipping {skip_count:,} already checked IPs...")
                self.processed_count = skip_count
        else:
            # Clear or ensure output file exists
            if os.path.exists(self.output_txt):
                # Ask or overwrite? If not resuming, truncate to prevent duplicates
                open(self.output_txt, 'w').close()
            if self.output_csv and os.path.exists(self.output_csv):
                open(self.output_csv, 'w').close()

        self.total_estimated = count_potential_targets(self.sources)
        
        # 2. Setup Signal Handler
        def handle_signal(sig, frame):
            print("\n[!] Stop signal received. Shutting down gracefully...")
            self.user_interrupted = True
            self.stop_flag.set()

        orig_sigint = signal.signal(signal.SIGINT, handle_signal)

        # 3. Start Writer & Workers
        self.writer.start()
        
        feeder_thread = threading.Thread(target=self._feeder, args=(skip_count,), daemon=True)
        feeder_thread.start()

        threads: List[threading.Thread] = []
        for _ in range(self.workers):
            t = threading.Thread(target=self._worker, daemon=True)
            t.start()
            threads.append(t)

        start_time = time.time()
        last_checkpoint_time = time.time()
        last_print_time = 0.0

        print(f"[*] Engine: {self.mode.upper()} mode ({'Port ' + str(self.tcp_port) if self.mode == 'tcp' else 'Win32 Icmp' if os.name == 'nt' else 'Socket Icmp'})")
        print(f"[*] Concurrency: {self.workers} workers | Timeout: {self.timeout_ms}ms")
        print(f"[*] Press 's', 'q' or Ctrl+C to pause/stop safely.")
        print("-" * 70)

        # 4. Progress Loop
        try:
            while feeder_thread.is_alive() or any(t.is_alive() for t in threads):
                if self._check_key_press():
                    print("\n[!] User pressed stop key. Stopping scan...")
                    self.user_interrupted = True
                    self.stop_flag.set()
                    break

                now = time.time()
                elapsed = max(now - start_time, 0.001)

                if now - last_print_time >= 0.15:
                    last_print_time = now
                    with self.lock:
                        done = self.processed_count
                    alive = self.writer.alive_count
                    rate = (done - skip_count) / elapsed

                    # Status formatting
                    if self.total_estimated and self.total_estimated > 0:
                        pct = min(100.0, (done / self.total_estimated) * 100)
                        rem = max(0, self.total_estimated - done)
                        eta_sec = int(rem / rate) if rate > 0 else 0
                        eta_str = str(timedelta(seconds=eta_sec))
                        bar_len = 20
                        filled = int(bar_len * (pct / 100.0))
                        bar = "=" * filled + (">" if filled < bar_len else "") + " " * (bar_len - filled - 1)
                        status = (
                            f"\r[{bar[:bar_len]}] {pct:5.1f}% | Checked: {done:,}/{self.total_estimated:,} "
                            f"| Alive: {alive:,} | Speed: {rate:,.0f} IP/s | ETA: {eta_str}"
                        )
                    else:
                        status = (
                            f"\rChecked: {done:,} | Alive: {alive:,} "
                            f"| Speed: {rate:,.0f} IP/s | Elapsed: {str(timedelta(seconds=int(elapsed)))}"
                        )
                    sys.stdout.write(status.ljust(79)[:79])
                    sys.stdout.flush()

                # Periodic checkpoint every 5 seconds
                if now - last_checkpoint_time >= 5.0:
                    with self.lock:
                        self.checkpoint.save(self.processed_count, self.writer.alive_count)
                    last_checkpoint_time = now

                time.sleep(0.05)

        finally:
            self.stop_flag.set()
            signal.signal(signal.SIGINT, orig_sigint)

        # 5. Wait for finish
        feeder_thread.join(timeout=1.0)
        for t in threads:
            t.join(timeout=0.5)

        self.writer.stop()
        total_time = max(time.time() - start_time, 0.001)
        done_final = self.processed_count
        alive_final = self.writer.alive_count
        overall_rate = (done_final - skip_count) / total_time

        # Update or clean checkpoint
        if self.user_interrupted:
            self.checkpoint.save(done_final, alive_final)
        else:
            self.checkpoint.cleanup()

        # Optional sort
        if self.sort_results and alive_final > 0:
            print(f"\n[*] Sorting {alive_final:,} alive IPs by latency...")
            self.writer.write_sorted_output(self.sorted_output)

        # 6. Final Report
        avg_rtt = (self.writer.rtt_sum / alive_final) if alive_final > 0 else 0.0
        print("\n" + "=" * 70)
        print(" SCAN SUMMARY")
        print("=" * 70)
        print(f" Total Checked  : {done_final:,}")
        print(f" Alive Found    : {alive_final:,} ({(alive_final/max(done_final,1))*100:.2f}%)")
        print(f" Average Speed  : {overall_rate:,.1f} IPs/second")
        print(f" Elapsed Time   : {str(timedelta(seconds=int(total_time)))}")
        if alive_final > 0:
            print(f" Latency Range  : {self.writer.rtt_min:.1f}ms - {self.writer.rtt_max:.1f}ms (Avg: {avg_rtt:.1f}ms)")
            if self.writer.fastest_ip:
                print(f" Fastest IP     : {self.writer.fastest_ip} ({self.writer.rtt_min:.1f}ms)")
        print(f" Output File    : {self.output_txt}")
        if self.output_csv:
            print(f" CSV Report     : {self.output_csv}")
        if self.sort_results and alive_final > 0:
            print(f" Sorted Output  : {self.sorted_output}")
        if os.path.exists(self.checkpoint.path):
            print(f" Checkpoint     : Saved. Run with --resume to continue later.")
        print("=" * 70)


# =====================================================================
# 6. CLI Entrypoint
# =====================================================================

def parse_args():
    parser = argparse.ArgumentParser(
        description="FastPing - Ultra-fast concurrent IPv4 scanner for millions of IPs.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python fast_ping.py ip.txt
  python fast_ping.py 104.16.0.0/16 -o cf_alive.txt --sort
  python fast_ping.py 1.1.1.0/24 --mode tcp --port 53
  python fast_ping.py ip.txt -w 800 -t 500 --csv results.csv --resume
        """
    )
    parser.add_argument(
        "targets",
        nargs="*",
        default=["ip.txt"],
        help="Input files, CIDR blocks (e.g., 104.16.0.0/16), or IP ranges. Default: ip.txt"
    )
    parser.add_argument(
        "-o", "--output",
        default="alive_ips.txt",
        help="Output file for alive IPs (default: alive_ips.txt)"
    )
    parser.add_argument(
        "--csv",
        nargs="?",
        const="alive_ips.csv",
        default=None,
        help="Also export alive IPs with latency to CSV (default: alive_ips.csv)"
    )
    parser.add_argument(
        "-m", "--mode",
        choices=["icmp", "tcp"],
        default="icmp",
        help="Scan mode: icmp (native fast ping) or tcp (default: icmp)"
    )
    parser.add_argument(
        "-p", "--port",
        type=int,
        default=443,
        help="Target port for TCP mode (default: 443)"
    )
    parser.add_argument(
        "-w", "--workers",
        type=int,
        default=400,
        help="Number of concurrent worker threads (default: 400)"
    )
    parser.add_argument(
        "-t", "--timeout",
        type=int,
        default=800,
        help="Probe timeout in milliseconds (default: 800)"
    )
    parser.add_argument(
        "-r", "--resume",
        action="store_true",
        help="Resume previous interrupted scan using checkpoint"
    )
    parser.add_argument(
        "-s", "--sort",
        action="store_true",
        help="Sort alive IPs by lowest latency at end of scan"
    )
    parser.add_argument(
        "--sorted-output",
        default=None,
        help="Custom output filename for sorted results"
    )
    return parser.parse_args()


def main():
    args = parse_args()

    # If default 'ip.txt' is passed but doesn't exist, check if user provided other args
    if args.targets == ["ip.txt"] and not os.path.exists("ip.txt"):
        print("[!] Default input file 'ip.txt' was not found.")
        print("[i] Usage: python fast_ping.py <input_file_or_cidr>")
        print("[i] Example: python fast_ping.py 1.1.1.0/24")
        sys.exit(1)

    scanner = FastScanner(
        sources=args.targets,
        output_txt=args.output,
        output_csv=args.csv,
        mode=args.mode,
        tcp_port=args.port,
        workers=args.workers,
        timeout_ms=args.timeout,
        resume=args.resume,
        sort_results=args.sort,
        sorted_output=args.sorted_output
    )
    scanner.run()


if __name__ == "__main__":
    main()
