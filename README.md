# System Lockdown Script

A Python-based script designed to simulate a security mechanism that locks a Windows system. This script restricts access with features like input blocking, Task Manager disabling, shortcut blocking, and configurable security settings.

---

## **Enhanced Features**
- **Secure Password Storage**: Uses bcrypt hashing for secure storage of the unlock code
- **Configurable Settings**: JSON-based configuration for easy customization
- **Brute Force Protection**: Includes attempt limiting and temporary lockouts
- **Real-time Timer Display**: Shows minutes and seconds until auto-unlock
- **Comprehensive Logging**: Tracks all lock/unlock attempts and system events
- **Improved UI**: Customizable theme settings and responsive interface
- **Enter Key Support**: Press Enter to submit unlock code
- **Error Handling**: Robust error handling and recovery mechanisms

## **Configuration Options**
The script uses a `config.json` file with the following customizable settings:
```json
{
    "unlock_code_hash": "<bcrypt-hash>",
    "auto_unlock_minutes": 30,
    "max_attempts": 3,
    "lockout_duration": 300,
    "theme": {
        "background": "black",
        "text": "white",
        "button": "gray"
    }
}
```

## **Security Features**
- **Attempt Limiting**: After 3 failed attempts (configurable), the system locks out for 5 minutes
- **Secure Hash Storage**: Uses bcrypt for secure storage of the unlock code
- **Input Blocking**: Completely disables mouse and keyboard interactions during lock
- **Task Manager Restriction**: Prevents access to Task Manager
- **Shortcut Blocking**: Blocks system shortcuts (Windows Key, Alt+Tab, Esc)
- **Auto-unlock Timer**: Configurable auto-unlock duration
- **Event Logging**: Comprehensive logging of all security events

## **Requirements**
- Windows Operating System
- Python 3.6+
- Required packages: `bcrypt`

## **Installation**
1. Clone this repository:
   ```bash
   git clone https://github.com/yourusername/system-lockdown-script.git
   ```
2. Install required package:
   ```bash
   pip install bcrypt
   ```

## **Usage**
1. Run the script:
   ```bash
   python LockScreen.py
   ```
2. To change the unlock code, edit the config.json file and update the "unlock_code_hash" with a new bcrypt hash.
3. Customize other settings in config.json as needed.

## **Logging**
The script maintains a detailed log file (`lockscreen.log`) that tracks:
- Lock/unlock attempts
- System events
- Error messages
- Security-related activities

DISCLAIMER: This script modifies critical system settings and could potentially render your computer inoperable if used incorrectly. The author assumes no liability for any damages or system failures resulting from its use. Users are strongly advised to back up all important data and proceed only if they fully understand the risks and have the technical expertise to reverse any changes if necessary. By using this script, you acknowledge these risks and accept full responsibility for any consequences.


