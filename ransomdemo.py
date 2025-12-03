import os
import time
import sys

# Tạo thư mục giả lập dữ liệu quan trọng
TARGET_DIR = os.path.join(os.getcwd(), "Tai_Lieu_Mat")
if not os.path.exists(TARGET_DIR):
    os.makedirs(TARGET_DIR)
    # Tạo vài file giả
    for i in range(1, 10):
        with open(os.path.join(TARGET_DIR, f"bao_cao_{i}.docx"), "w") as f:
            f.write("Du lieu quan trong...")

print(f"[*] Đang tấn công thư mục: {TARGET_DIR}")
print("[*] Bắt đầu mã hóa dữ liệu...")

# Giả lập hành vi Ransomware: Đổi tên file từ từ
files = [f for f in os.listdir(TARGET_DIR) if f.endswith(".docx")]

for file_name in files:
    original = os.path.join(TARGET_DIR, file_name)
    encrypted = os.path.join(TARGET_DIR, file_name + ".LOCKED")
    
    print(f"[!] Đang mã hóa: {file_name} -> {file_name}.LOCKED")
    os.rename(original, encrypted)
    
    # Ngủ 2 giây để bạn kịp Demo (Kịp bấm nút trên UI)
    time.sleep(2) 

print("[*] Đã mã hóa toàn bộ dữ liệu!")
input("Bấm Enter để thoát...")