import asyncio
import platform
import os
import keyboard  # برای تشخیص دکمه توقف

if platform.system() == 'Windows':
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

processing_pool = [] # لیست آی‌پی‌هایی که در لحظه در حال تست هستند

async def ping_ip(ip, semaphore, output_file):
    ip = ip.strip()
    if not ip: return
    
    processing_pool.append(ip) # اضافه کردن به لیست در حال پردازش
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
                with open(output_file, "a") as f:
                    f.write(ip + "\n")
            
            if ip in processing_pool:
                processing_pool.remove(ip) # پس از اتمام، از لیست حذف می‌شود
        except Exception:
            if ip in processing_pool:
                processing_pool.remove(ip)

async def main():
    input_file = "ip.txt"
    output_file = "alive_ips.txt"
    
    if not os.path.exists(input_file):
        print("'Ip.txt' not found")
        return

    semaphore = asyncio.Semaphore(300) 
    batch_size = 1000 # دسته‌های کوچک‌تر برای توقف سریع‌تر و دقیق‌تر
    
    print("--- Scan started ---")
    print("for stop progress press 's'")

    try:
        while True:
            # چک کردن دکمه توقف (S مخفف Stop)
            if keyboard.is_pressed('s'):
                print("\nStoped by user...")
                break

            # ۱. خواندن دسته جاری
            with open(input_file, "r") as f:
                all_ips = f.readlines()
            
            if not all_ips:
                print("all IPs are checked.")
                break
                
            current_batch = [line.strip() for line in all_ips[:batch_size] if line.strip()]
            remaining_ips = all_ips[batch_size:]

            # ۲. به‌روزرسانی فایل (حذف موارد در حال تست)
            with open(input_file, "w") as f:
                f.writelines(remaining_ips)

            # ۳. اجرای پینگ
            tasks = [ping_ip(ip, semaphore, output_file) for ip in current_batch]
            await asyncio.gather(*tasks)
            print(f" nubmer of checked ips:{len(current_batch)}  remaining:{len(remaining_ips)}")

    except Exception as e:
        print(f"unexpected error : {e}")
    
    finally:
        # برگشت دادن آی‌پی‌های در حال پردازش به فایل اصلی در صورت توقف
        if processing_pool:
            print(f"returning {len(processing_pool)} unfinished Ips to the file...")
            with open(input_file, "r") as f:
                remaining = f.readlines()
            
            # آی‌پی‌های ناتمام + آی‌پی‌های باقی‌مانده قبلی
            final_list = [ip + "\n" for ip in processing_pool] + remaining
            with open(input_file, "w") as f:
                f.writelines(final_list)
            
            processing_pool.clear()
        
        print(" you can leave.")

if __name__ == "__main__":
    asyncio.run(main())