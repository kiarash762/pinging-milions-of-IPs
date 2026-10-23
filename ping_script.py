#!/usr/bin/env python3
"""
ping_script.py - Async High-Performance IP Scanner
===================================================
A clean, lightweight asyncio implementation designed for scanning large IP lists
without spawning expensive OS subprocesses.

Uses native Win32 ICMP (Windows) or socket ICMP (Linux/macOS) via the fast_ping engine.
Capable of scanning thousands of IPs per second while keeping RAM consumption minimal.
"""

import asyncio
import platform
import os
import sys
import time
from fast_ping import get_pinger, parse_target_source

# Windows event loop optimization (Proactor is default in Python 3.8+)
if platform.system() == 'Windows' and sys.version_info < (3, 8):
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

async def ping_ip(ip: str, pinger, timeout_ms: int = 800):
    """Pings a single IP asynchronously using the high-performance native engine."""
    ip = ip.strip()
    if not ip or ip.startswith('#'):
        return False, 0.0
    return await asyncio.to_thread(pinger.ping, ip, timeout_ms)

async def worker(queue: asyncio.Queue, pinger, out_queue: asyncio.Queue, counter: list):
    """Worker coroutine that continuously pulls IPs from the queue."""
    while True:
        ip = await queue.get()
        if ip is None:
            queue.task_done()
            break
        try:
            alive, rtt = await asyncio.to_thread(pinger.ping, ip, 800)
            if alive:
                await out_queue.put((ip, rtt))
        except Exception:
            pass
        finally:
            counter[0] += 1
            queue.task_done()

async def writer(out_queue: asyncio.Queue, output_file: str, stop_event: asyncio.Event):
    """Buffered output writer to eliminate disk I/O bottlenecks."""
    buffer = []
    last_flush = time.time()
    with open(output_file, "a", encoding="utf-8", buffering=65536) as f:
        while not stop_event.is_set() or not out_queue.empty():
            try:
                ip, rtt = await asyncio.wait_for(out_queue.get(), timeout=0.2)
                buffer.append(f"{ip}\n")
                out_queue.task_done()
            except asyncio.TimeoutError:
                pass

            if len(buffer) >= 200 or (buffer and time.time() - last_flush > 1.0):
                f.writelines(buffer)
                f.flush()
                buffer.clear()
                last_flush = time.time()

        if buffer:
            f.writelines(buffer)
            f.flush()

async def main():
    input_file = "ip.txt"
    output_file = "alive_ips.txt"

    if not os.path.exists(input_file):
        print(f"[!] Error: '{input_file}' not found!")
        print("[i] Please create 'ip.txt' with IPs or CIDR subnets (e.g. 1.1.1.0/24).")
        return

    # Clear output file for new scan
    open(output_file, "w", encoding="utf-8").close()

    pinger = get_pinger('icmp')
    concurrency = 400
    queue = asyncio.Queue(maxsize=concurrency * 2)
    out_queue = asyncio.Queue()
    stop_event = asyncio.Event()
    counter = [0]  # [checked_count]

    print(f"[*] Starting async scan on '{input_file}'...")
    print(f"[*] Concurrency: {concurrency} workers | Native ICMP engine")
    print("[*] Press Ctrl+C to stop.\n")

    # Start writer
    writer_task = asyncio.create_task(writer(out_queue, output_file, stop_event))

    # Start workers
    workers = [
        asyncio.create_task(worker(queue, pinger, out_queue, counter))
        for _ in range(concurrency)
    ]

    t0 = time.time()

    # Feeder coroutine
    async def feed():
        with open(input_file, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                for ip in parse_target_source(line):
                    await queue.put(ip)
        for _ in range(concurrency):
            await queue.put(None)

    feeder_task = asyncio.create_task(feed())

    # Progress monitor loop
    try:
        while not feeder_task.done() or any(not w.done() for w in workers):
            await asyncio.sleep(0.2)
            elapsed = max(time.time() - t0, 0.001)
            done = counter[0]
            rate = done / elapsed
            sys.stdout.write(f"\rChecked: {done:,} IPs | Speed: {rate:,.0f} IP/s | Elapsed: {int(elapsed)}s")
            sys.stdout.flush()
    except asyncio.CancelledError:
        pass

    # Wait for completion
    await queue.join()
    await feeder_task
    await asyncio.gather(*workers)

    stop_event.set()
    await writer_task
    pinger.close()

    elapsed = max(time.time() - t0, 0.001)
    print(f"\n\n[+] Scan finished in {elapsed:.2f}s ({counter[0] / elapsed:,.0f} IP/s)!")
    print(f"[+] Results saved to '{output_file}'.")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\n[!] Stopped by user.")
