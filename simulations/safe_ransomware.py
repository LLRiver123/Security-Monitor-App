import os
import time
import base64
import threading
import tkinter as tk
from tkinter import ttk, messagebox
from pathlib import Path
import random

# --- CONFIG ---
TARGET_DIR = Path("simulations/dummy_data")
NUM_FILES = 50
DELAY_BETWEEN_OPS = 0.2  # Slow enough to watch, fast enough to trigger heuristics

class RansomwareSimApp:
    def __init__(self, root):
        self.root = root
        self.root.title("RANSOMWARE SIMULATION")
        self.root.geometry("600x400")
        self.root.configure(bg='#8b0000')  # Dark Red
        self.root.attributes('-topmost', True) # Always on top
        
        # Disable close button protocol to be annoying (optional, kept simple for demo)
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

        # Header
        self.lbl_header = tk.Label(root, text="YOUR FILES ARE ENCRYPTED!", 
                                   font=("Helvetica", 24, "bold"), fg="white", bg='#8b0000')
        self.lbl_header.pack(pady=30)

        # Subtext
        self.lbl_sub = tk.Label(root, text="Payment of $500 USD in Bitcoin is required.\nDO NOT CLOSE THIS WINDOW.", 
                                font=("Helvetica", 12), fg="yellow", bg='#8b0000')
        self.lbl_sub.pack(pady=10)

        # Progress Bar
        self.progress = ttk.Progressbar(root, orient=tk.HORIZONTAL, length=500, mode='determinate')
        self.progress.pack(pady=20)

        # Status Log
        self.lbl_status = tk.Label(root, text="Scanning system...", font=("Consolas", 10), fg="white", bg='#8b0000')
        self.lbl_status.pack(pady=5)

        # Control Buttons (Fake)
        frame_btns = tk.Frame(root, bg='#8b0000')
        frame_btns.pack(pady=20)
        
        self.btn_pay = tk.Button(frame_btns, text="PAY RANSOM", bg="black", fg="white", font=("Arial", 10, "bold"), command=self.pay_ransom)
        self.btn_pay.pack(side=tk.LEFT, padx=20)
        
        self.btn_decrypt = tk.Button(frame_btns, text="DECRYPT (KEY REQUIRED)", bg="gray", fg="white", font=("Arial", 10), state=tk.DISABLED)
        self.btn_decrypt.pack(side=tk.LEFT, padx=20)

        # Internal State
        self.running = True
        self.files_to_encrypt = []
        self.encrypted_count = 0

        # Start Attack in separate thread
        self.setup_dummy_data()
        self.thread = threading.Thread(target=self.run_attack)
        self.thread.daemon = True
        self.thread.start()

    def setup_dummy_data(self):
        """Create dummy files to target"""
        if TARGET_DIR.exists():
            import shutil
            shutil.rmtree(TARGET_DIR)
        
        TARGET_DIR.mkdir(parents=True, exist_ok=True)
        self.lbl_status.config(text=f"Preparing {NUM_FILES} target files...")
        
        for i in range(NUM_FILES):
            file_path = TARGET_DIR / f"confidential_financial_doc_{i}.txt"
            with open(file_path, "w") as f:
                f.write(f"This is important confidential data line {i}." * 100)
            self.files_to_encrypt.append(file_path)

    def run_attack(self):
        """The actual file modification loop"""
        time.sleep(1.5) # Dramatic pause
        
        total = len(self.files_to_encrypt)
        
        for i, fpath in enumerate(self.files_to_encrypt):
            if not self.running: break
            if not fpath.exists(): continue # Might have been deleted by Agent

            try:
                # Update UI
                filename = fpath.name
                self.root.after(0, lambda f=filename, x=i: self.update_ui(f, x, total))

                # --- SIMULATE ENCRYPTION ---
                # 1. Read
                with open(fpath, "rb") as f:
                    data = f.read()
                
                # 2. Encrypt (Fake Base64)
                encrypted_data = base64.b64encode(data)
                
                # 3. Write New
                new_path = fpath.with_suffix(".locked")
                with open(new_path, "wb") as f:
                    f.write(b"RANSOMWARE_V2" + encrypted_data)
                
                # 4. Delete Old (Triggers Agent Heuristics)
                fpath.unlink()
                
                self.encrypted_count += 1
                
                # Speed control
                time.sleep(DELAY_BETWEEN_OPS)

            except Exception as e:
                print(f"Error encrypting {fpath}: {e}")

        self.root.after(0, self.attack_finished)

    def update_ui(self, filename, current_idx, total):
        self.lbl_status.config(text=f"Encrypting: {filename}")
        self.progress['value'] = (current_idx / total) * 100

    def attack_finished(self):
        self.lbl_status.config(text=f"FINISHED. {self.encrypted_count} files encrypted.")
        self.progress['value'] = 100
        messagebox.showwarning("ATTACK COMPLETE", "All your files belong to us.\nPay immediately.")

    def pay_ransom(self):
        messagebox.showinfo("Payment", "Connecting to payment server... (This is a simulation)")

    def on_closing(self):
        if messagebox.askokcancel("Quit", "Stopping the simulation will not decrypt your files.\nAre you sure?"):
            self.running = False
            self.root.destroy()
            # Cleanup
            import shutil
            if TARGET_DIR.exists():
                shutil.rmtree(TARGET_DIR)

if __name__ == "__main__":
    try:
        root = tk.Tk()
        app = RansomwareSimApp(root)
        root.mainloop()
    except KeyboardInterrupt:
        pass