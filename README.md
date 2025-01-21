# System Lockdown Script

A Python-based script designed to simulate a security mechanism that locks a Windows system. This script restricts access with features like input blocking, Task Manager disabling, shortcut blocking, and an auto-unlock timer. Use it to explore system control and have fun!

---

## **Features**
- **Lock Screen**: Displays a full-screen graphical interface that prevents system access until an unlock code is provided.
- **Input Blocking**: Completely disables mouse and keyboard interactions during the lock.
- **Task Manager Restriction**: Modifies the Windows registry to disable the Task Manager, preventing users from ending processes.
- **Shortcut Blocking**: Blocks common system shortcuts like `Windows Key`, `Alt+Tab`, and `Esc` for enhanced lockdown.
- **Auto-Unlock Timer**: Automatically unlocks after 30 minutes if no correct unlock code is entered.
- **Integrity Check**: Verifies the script’s integrity using a SHA-256 hash to detect tampering.

---

## **Unlock Code**
The default unlock code is **"QWERTY"**, which is provided as a placeholder. You can replace this code with a custom value by editing the `UNLOCK_CODE` variable in the script.

---

## **How It Works**
1. **Initialization**:
   - Performs a script integrity check to ensure no modifications have been made.
   - Blocks input and disables the Task Manager to secure the system.

2. **Lock Screen**:
   - Launches a full-screen interface prompting for an unlock code.
   - Locks out all user interaction, including keyboard and mouse.

3. **Unlock Options**:
   - Enter the correct unlock code to restore system access.
   - Wait for the 30-minute auto-unlock timer to expire.

4. **Cleanup**:
   - Automatically restores Task Manager access and input control upon unlocking.

---

## **Setup and Usage**
1. Clone this repository:
   ```bash
   git clone https://github.com/yourusername/system-lockdown-script.git
