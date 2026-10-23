#!/usr/bin/env python3
"""
ping.py - اسکنر سریع و بهینه‌سازی‌شده برای میلیون‌ها آی‌پی
=============================================================
نسخه ارتقایافته:
- سرعت خارق‌العاده (بیش از ۵۰۰۰ تا ۱۰۰۰۰ آی‌پی در ثانیه) بدون ایجاد پروسس‌های سنگین پینگ ویندوز
- عدم نیاز به نصب پکیج‌های خارجی (استفاده ۱۰۰٪ از کتابخانه‌های داخلی پایتون)
- ذخیره امن وضعیت اسکن (Resume): فایل اصلی ip.txt هرگز دستکاری یا خراب نمی‌شود
- توقف تمیز با فشردن کلید 's' یا 'q' یا Ctrl+C
- پشتیبانی از CIDR و رنج آی‌پی (مانند 104.16.0.0/16 یا 1.1.1.1-1.1.1.254)
"""

import sys
import os
from fast_ping import FastScanner, main

def run_default():
    input_file = "ip.txt"
    output_file = "alive_ips.txt"

    if not os.path.exists(input_file):
        print(f"[!] Error: '{input_file}' not found.")
        print("[i] لطفاً یک فایل به نام ip.txt بسازید و آی‌پی‌ها یا رنج‌های ساب‌نت را در آن قرار دهید.")
        print("[i] مثال:\n    1.1.1.1\n    8.8.8.8\n    104.16.0.0/24")
        sys.exit(1)

    print("=" * 70)
    print(" شروع اسکن سریع آی‌پی‌ها (Fast IP Scanner)")
    print(" برای توقف در هر لحظه کلید 's'، 'q' یا Ctrl+C را بزنید.")
    print("=" * 70)

    # چک‌پوینت خودکار فعال است تا در صورت توقف، اسکن دفعه بعد از همان نقطه ادامه یابد
    checkpoint_file = f".{os.path.basename(output_file)}.checkpoint"
    has_checkpoint = os.path.exists(checkpoint_file)

    scanner = FastScanner(
        sources=[input_file],
        output_txt=output_file,
        output_csv="alive_ips.csv",
        mode="icmp",
        workers=400,
        timeout_ms=800,
        resume=has_checkpoint,
        sort_results=True,
        sorted_output="alive_ips_sorted.csv"
    )
    scanner.run()

if __name__ == "__main__":
    if len(sys.argv) > 1:
        # اگر کاربر آرگومان خط فرمانی فرستاده بود، مستقیم به CLI بفرست
        main()
    else:
        # در غیر این صورت با تنظیمات پیش‌فرض و فایل ip.txt اجرا کن
        run_default()
