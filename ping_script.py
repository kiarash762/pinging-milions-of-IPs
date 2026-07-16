import asyncio
import platform
import os
import sys

# اصلاح حیاتی برای ویندوز: استفاده از ProactorEventLoop
if platform.system() == 'Windows':
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

async def ping_ip(ip, semaphore, output_file):
    ip = ip.strip()
    if not ip:
        return

    # دستور پینگ در ویندوز
    command = f"ping -n 1 -w 1000 {ip}"
    
    async with semaphore:
        try:
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await process.communicate()
            
            if process.returncode == 0:
                # نوشتن در فایل بلافاصله پس از موفقیت
                with open(output_file, "a") as f:
                    f.write(ip + "\n")
                return True
        except Exception as e:
            pass # خطا در اجرای یک پینگ خاص مانع بقیه نشود
    return False

async def main():
    input_file = "ip.txt"
    output_file = "alive_ips.txt"
    
    if not os.path.exists(input_file):
        print(f"Error: {input_file} not found!")
        return

    # ایجاد یا خالی کردن فایل خروجی
    open(output_file, "w").close()

    # برای ۱۱ میلیون آی‌پی، عدد ۳۰۰ روی ویندوز امن‌تر است
    semaphore = asyncio.Semaphore(300) 
    
    print("Reading file and starting scan...")
    
    tasks = []
    count = 0
    
    with open(input_file, "r") as f:
        for line in f:
            tasks.append(ping_ip(line, semaphore, output_file))
            count += 1
            
            # مدیریت حافظه: اجرای تسک‌ها در گروه‌های ۵ هزارتایی
            if len(tasks) >= 5000:
                await asyncio.gather(*tasks)
                tasks = []
                print(f"Checked {count} IPs so far...")

    if tasks:
        await asyncio.gather(*tasks)
    
    print(f"Finished! Results saved in {output_file}")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nStopped by user.")