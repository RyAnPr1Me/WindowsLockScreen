import ctypes
import os
import sys
import tkinter as tk
from tkinter import messagebox
from ctypes import wintypes
from threading import Thread, Timer, Lock
import time
import hashlib
import platform
import json
import logging
from datetime import datetime
import bcrypt
from pathlib import Path

# Configure logging
logging.basicConfig(
    filename='lockscreen.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Check if running on Windows
if platform.system() != 'Windows':
    logging.error("This script only works on Windows systems.")
    sys.exit(1)

class Config:
    DEFAULT_CONFIG = {
        "unlock_code_hash": bcrypt.hashpw("QWERTY".encode(), bcrypt.gensalt()).decode(),
        "auto_unlock_minutes": 30,
        "max_attempts": 3,
        "lockout_duration": 300,  # 5 minutes in seconds
        "theme": {
            "background": "black",
            "text": "white",
            "button": "gray"
        }
    }
    
    @staticmethod
    def load():
        config_path = Path("config.json")
        if not config_path.exists():
            Config.save(Config.DEFAULT_CONFIG)
            return Config.DEFAULT_CONFIG
        
        try:
            with open(config_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            logging.error(f"Error loading config: {e}")
            return Config.DEFAULT_CONFIG
    
    @staticmethod
    def save(config):
        try:
            with open("config.json", 'w') as f:
                json.dump(config, f, indent=4)
        except Exception as e:
            logging.error(f"Error saving config: {e}")

# Load configuration
config = Config.load()

# Define constants
BLOCK_INPUT = ctypes.windll.user32.BlockInput
USER32 = ctypes.windll.user32
KERNEL32 = ctypes.windll.kernel32

class LockScreen:
    def __init__(self):
        self.root = None
        self.code_entry = None
        self.attempt_count = 0
        self.is_locked_out = False
        self.lockout_end_time = 0
        self.lock = Lock()
        self.remaining_time = config['auto_unlock_minutes'] * 60
        self.timer_label = None

    def block_input(self, enable=True):
        try:
            BLOCK_INPUT(bool(enable))
            logging.info(f"Input {'blocked' if enable else 'unblocked'}")
        except Exception as e:
            logging.error(f"Error blocking input: {e}")

    def disable_task_manager(self):
        try:
            os.system('reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v DisableTaskMgr /t REG_DWORD /d 1 /f')
            logging.info("Task Manager disabled")
        except Exception as e:
            logging.error(f"Error disabling Task Manager: {e}")

    def enable_task_manager(self):
        try:
            os.system('reg delete "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v DisableTaskMgr /f')
            logging.info("Task Manager enabled")
        except Exception as e:
            logging.error(f"Error enabling Task Manager: {e}")

    def verify_code(self):
        if self.is_locked_out:
            remaining = self.lockout_end_time - time.time()
            if remaining > 0:
                messagebox.showerror("Error", f"Account is locked. Try again in {int(remaining)} seconds.")
                return
            self.is_locked_out = False

        with self.lock:
            try:
                entered_code = self.code_entry.get()
                if bcrypt.checkpw(entered_code.encode(), config['unlock_code_hash'].encode()):
                    logging.info("Successful unlock attempt")
                    self.cleanup()
                    self.root.destroy()
                    sys.exit(0)
                else:
                    self.attempt_count += 1
                    remaining = config['max_attempts'] - self.attempt_count
                    
                    if remaining <= 0:
                        self.is_locked_out = True
                        self.lockout_end_time = time.time() + config['lockout_duration']
                        messagebox.showerror("Error", f"Too many attempts. Locked out for {config['lockout_duration']} seconds.")
                    else:
                        messagebox.showerror("Error", f"Incorrect code! {remaining} attempts remaining.")
                    
                    self.code_entry.delete(0, tk.END)
                    logging.warning(f"Failed unlock attempt ({self.attempt_count})")
            except Exception as e:
                logging.error(f"Error during code verification: {e}")

    def update_timer(self):
        if self.timer_label and self.remaining_time > 0:
            minutes = self.remaining_time // 60
            seconds = self.remaining_time % 60
            self.timer_label.config(text=f"Auto-unlock in {minutes:02d}:{seconds:02d}")
            self.remaining_time -= 1
            self.root.after(1000, self.update_timer)
        elif self.remaining_time <= 0:
            self.auto_unlock()

    def auto_unlock(self):
        logging.info("Auto-unlock timer expired")
        self.cleanup()
        self.root.destroy()
        sys.exit(0)

    def setup_lock_screen(self):
        self.root = tk.Tk()
        self.root.title("Lock Screen")
        self.root.attributes("-fullscreen", True)
        self.root.overrideredirect(1)
        self.root.configure(bg=config['theme']['background'])

        # Center frame
        frame = tk.Frame(self.root, bg=config['theme']['background'])
        frame.place(relx=0.5, rely=0.5, anchor="center")

        # Lock screen message
        tk.Label(
            frame,
            text="This device is locked. Please enter the unlock code:",
            fg=config['theme']['text'],
            bg=config['theme']['background'],
            font=("Arial", 18)
        ).pack(pady=10)

        # Timer label
        self.timer_label = tk.Label(
            frame,
            fg=config['theme']['text'],
            bg=config['theme']['background'],
            font=("Arial", 12)
        )
        self.timer_label.pack(pady=5)

        # Code entry
        self.code_entry = tk.Entry(frame, show="●", font=("Arial", 16), width=20)
        self.code_entry.pack(pady=10)
        self.code_entry.bind('<Return>', lambda e: self.verify_code())

        # Unlock button
        tk.Button(
            frame,
            text="Unlock",
            command=self.verify_code,
            font=("Arial", 14),
            bg=config['theme']['button'],
            fg=config['theme']['text']
        ).pack(pady=10)

        # Start timer updates
        self.update_timer()
        
        # Keep focus and window on top
        self.root.focus_force()
        self.root.attributes("-topmost", True)
        self.root.mainloop()

    def cleanup(self):
        self.enable_task_manager()
        self.block_input(False)
        logging.info("Cleanup completed")

    def run(self):
        try:
            self.disable_task_manager()
            self.block_input(True)
            Thread(target=self.block_shortcuts, daemon=True).start()
            self.setup_lock_screen()
        except Exception as e:
            logging.error(f"Error in main execution: {e}")
        finally:
            self.cleanup()

    def block_shortcuts(self):
        WH_KEYBOARD_LL = 13
        WM_KEYDOWN = 0x0100
        blocked_keys = {0x5B, 0x5C, 0x73, 0x09, 0x1B}  # Windows keys, F4, Alt+Tab, Esc

        def low_level_keyboard_proc(nCode, wParam, lParam):
            if nCode >= 0 and wParam == WM_KEYDOWN:
                vkCode = ctypes.cast(lParam, ctypes.POINTER(ctypes.c_int)).contents.value
                if vkCode in blocked_keys:
                    return 1
            return USER32.CallNextHookEx(None, nCode, wParam, lParam)

        HOOK_PROC = ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_int, wintypes.WPARAM, wintypes.LPARAM)
        hook = HOOK_PROC(low_level_keyboard_proc)
        hHook = USER32.SetWindowsHookExW(WH_KEYBOARD_LL, hook, KERNEL32.GetModuleHandleW(None), 0)

        if not hHook:
            logging.error("Failed to install keyboard hook")
            return

        try:
            while True:
                USER32.PeekMessageW(None, 0, 0, 0, 0)
        except Exception as e:
            logging.error(f"Error in keyboard hook: {e}")
        finally:
            USER32.UnhookWindowsHookEx(hHook)

if __name__ == "__main__":
    lock_screen = LockScreen()
    lock_screen.run()
