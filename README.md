# FastPing - Pinging Millions of IPs at Lightning Speed 🚀

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-Zero%20(Stdlib%20Only)-brightgreen.svg)]()
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)]()
[![Speed](https://img.shields.io/badge/Throughput-5%2C000%2B%20to%2010%2C000%2B%20IPs%2Fs-orange.svg)]()

A high-performance, memory-efficient, concurrent IPv4 scanner engineered to scan **millions of IP addresses** in minutes. 

Built with **100% Python Standard Library** — no third-party libraries, no C compilation, and no administrator/root privileges required on Windows.

---

## ⚡ The Problem vs. The Solution

| Feature | ❌ Old Subprocess Method (`ping.exe`) | ⚡ FastPing (New Architecture) |
| :--- | :--- | :--- |
| **Execution Method** | Spawns `cmd.exe` + `ping.exe` per IP | **Native Win32 `IcmpSendEcho` / Kernel ICMP** |
| **Scan Speed** | ~30 – 80 IPs / second | **5,000 – 10,000+ IPs / second** |
| **CPU & OS Load** | 100% CPU, process exhaustion, UI freezes | **Low CPU, handles shared via thread-local pool** |
| **Administrator Rights** | Required for raw sockets | **Zero admin rights required** (Windows `iphlpapi`) |
| **RAM Footprint** | Loads all IPs into memory (GBs of RAM) | **Streaming Lazy Generator (< 20 MB RAM)** |
| **File Safety** | Destructively rewrote and sliced `ip.txt` | **Input files are NEVER touched** |
| **Pause & Resume** | Fragile stop hooks (`keyboard` library) | **Automatic `.checkpoint` tracking + safe pause** |
| **Subnet Support** | Only plain line-by-line IPs | **CIDR (`104.16.0.0/16`) & Range (`1.1.1.1-100`)** |
| **Latency Tracking** | Only binary "alive / dead" | **Measures exact RTT in ms & `--sort` by speed** |
| **TCP Probe Mode** | Not supported | **TCP Handshake (`--mode tcp --port 443`)** |
| **Dependencies** | Requires `keyboard` | **100% Python Standard Library (0 packages)** |

---

## 🚀 Benchmark

Scanning **1,024 IP addresses** on standard Windows 11 hardware:

- **Old Subprocess Script (`ping -n 1 ...`)**: ~35 seconds (spawned 1,024 OS processes)
- **FastPing (`fast_ping.py`)**: **0.12 seconds** (**8,100+ IPs / second**)

---

## 🛠️ Key Architectural Highlights

1. **Native Win32 ICMP Integration**:
   Directly links to Windows `iphlpapi.dll` (`IcmpCreateFile`, `IcmpSendEcho`, `IcmpCloseHandle`) via `ctypes`. Reuses thread-local handles to eliminate handle allocation overhead.
2. **Zero-RAM Streaming Generator**:
   Expands CIDR blocks (e.g., `104.16.0.0/12` = 1,048,576 IPs) and ranges on the fly using generator iterators. Never allocates millions of strings in RAM.
3. **Continuous Producer-Consumer Pipeline**:
   Replaces batch barriers (`asyncio.gather(*5000)`) with bounded worker queues. Prevents a single timed-out IP from stalling thousands of fast responses.
4. **Buffered Asynchronous Writer**:
   Flushes alive hosts in batches from a dedicated background thread, preventing slow disk I/O from throttling the scan engine.
5. **Non-Destructive Checkpointing**:
   State is stored in a lightweight `.checkpoint` file. Pressing `s`, `q`, or `Ctrl+C` exits cleanly and lets you resume seamlessly with `--resume`.
6. **Latency Ranking (`--sort`)**:
   Captures round-trip times (RTT) for every alive host and can automatically generate a sorted CSV/TXT from lowest latency to highest (ideal for CDN edge selection, DNS tuning, and gaming).

---

## 📦 Installation

Clone the repository and run — no dependencies to install!

```bash
git clone https://github.com/kiarash762/pinging-milions-of-IPs.git
cd pinging-milions-of-IPs
```

Requirements: Python 3.8 or higher.

---

## 💻 Usage

### 1. Zero-Config Run (Default)
Create an `ip.txt` file (or use `ip.txt.example`) and run:
```bash
python ping.py
```
This automatically scans `ip.txt`, writes alive hosts to `alive_ips.txt` and `alive_ips.csv`, and produces a latency-ranked `alive_ips_sorted.csv`.

### 2. Scanning CIDR Subnets Directly
Scan entire network ranges without needing an input file:
```bash
# Scan a Cloudflare /16 subnet (65,534 hosts)
python fast_ping.py 104.16.0.0/16 -o cf_alive.txt --sort

# Scan Google Public DNS /24
python fast_ping.py 8.8.8.0/24 --csv results.csv
```

### 3. TCP Ping Mode (CDN / Clean IP Scanning)
Useful when ICMP is blocked, throttled, or spoofed by firewalls:
```bash
# Test HTTPS port 443 connectivity
python fast_ping.py 104.16.0.0/16 --mode tcp --port 443 --sort

# Test DNS port 53 connectivity
python fast_ping.py 1.1.1.0/24 --mode tcp --port 53
```

### 4. Pausing and Resuming Scans
Press **`s`**, **`q`**, or **`Ctrl+C`** at any time during a scan. FastPing will gracefully finish in-flight pings, flush all discovered IPs to disk, and save a `.checkpoint`.

To resume from where you stopped:
```bash
python fast_ping.py ip.txt --resume
```

### 5. Custom Workers and Timeout
```bash
# 800 worker threads, 500ms timeout
python fast_ping.py ip.txt -w 800 -t 500 -o alive.txt --csv report.csv
```

---

## ⚙️ CLI Reference (`fast_ping.py`)

```text
usage: fast_ping.py [-h] [-o OUTPUT] [--csv [CSV]] [-m {icmp,tcp}] [-p PORT]
                    [-w WORKERS] [-t TIMEOUT] [-r] [-s] [--sorted-output SORTED_OUTPUT]
                    [targets ...]

positional arguments:
  targets               Input files, CIDR blocks (e.g., 104.16.0.0/16), or IP ranges. Default: ip.txt

options:
  -h, --help            Show this help message and exit
  -o, --output OUTPUT   Output file for alive IPs (default: alive_ips.txt)
  --csv [CSV]           Also export alive IPs with latency to CSV (default: alive_ips.csv)
  -m, --mode {icmp,tcp} Scan mode: icmp (native fast ping) or tcp (default: icmp)
  -p, --port PORT       Target port for TCP mode (default: 443)
  -w, --workers WORKERS Number of concurrent worker threads (default: 400)
  -t, --timeout TIMEOUT Probe timeout in milliseconds (default: 800)
  -r, --resume          Resume previous interrupted scan using checkpoint
  -s, --sort            Sort alive IPs by lowest latency at end of scan
  --sorted-output FILE  Custom output filename for sorted results
```

---

## 🇮🇷 راهنمای فارسی (Persian Guide)

این پروژه برای اسکن سریع و کم‌مصرف **میلیون‌ها آی‌پی** در کمترین زمان ممکن بازطراحی شده است.

### تغییرات و بهینه‌سازی‌های کلیدی:
1. **سرعت خارق‌العاده (۵۰۰۰ تا ۱۰۰۰۰ آی‌پی در ثانیه)**: دیگر برای هر آی‌پی یک پروسس `cmd.exe` و `ping.exe` در ویندوز ساخته نمی‌شود، بلکه از API مستقیم ویندوز (`IcmpSendEcho`) استفاده می‌شود.
2. **عدم نیاز به دسترسی Administrator**: این روش نیازی به اجرای ترمینال با دسترسی Run as Administrator ندارد.
3. **مصرف رم در حد چند مگابایت**: حتی اگر رنج‌های میلیونی مانند `104.16.0.0/12` به برنامه داده شود، آی‌پی‌ها به صورت استریم (Generator) ساخته می‌شوند و رم پر نمی‌شود.
4. **حفظ کامل فایل `ip.txt`**: فایل اصلی شما هرگز ویرایش یا کوتاه نمی‌شود. توقف و ادامه (Resume) با استفاده از یک فایل سبک `.checkpoint` انجام می‌شود.
5. **اندازه‌گیری و سورت تاخیر (Latency / Ping)**: علاوه بر مشخص کردن زنده بودن آی‌پی، مقدار دقیق پینگ بر حسب میلی‌ثانیه ذخیره شده و با فلگ `--sort` می‌توانید آی‌پی‌ها را از کمترین پینگ به بیشترین پینگ مرتب کنید (عالی برای پیدا کردن آی‌پی تمیز کلودفلر یا سرورهای گیمینگ).
6. **پشتیبانی از پینگ TCP**: برای تست پورت‌های 443 یا 80 در شرایطی که پروتکل ICMP فیلتر یا محدود شده است.
7. **بدون نیاز به نصب هیچ کتابخانه‌ای**: ۱۰۰٪ با کتابخانه‌های استاندارد پایتون اجرا می‌شود.

### نحوه استفاده سریع:
یک فایل به نام `ip.txt` بسازید و برنامه را اجرا کنید:
```bash
python ping.py
```
در حین اسکن می‌توانید در هر لحظه با زدن دکمه **`s`** یا **`q`** یا **`Ctrl+C`** اسکن را متوقف کنید. برای ادامه کافیست دستور را با فلگ `--resume` اجرا کنید:
```bash
python fast_ping.py ip.txt --resume
```

---

## 📄 License
Released under the [MIT License](LICENSE).
