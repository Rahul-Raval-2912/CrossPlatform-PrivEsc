#!/usr/bin/env python3
"""
PrivEsc-Framework Executable Builder
Creates standalone executables for distribution
"""

import os
import sys
import subprocess
import platform

def check_pyinstaller():
    """Check if PyInstaller is installed"""
    try:
        subprocess.run(['pyinstaller', '--version'], capture_output=True, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False

def install_pyinstaller():
    """Install PyInstaller"""
    print("[+] Installing PyInstaller...")
    try:
        subprocess.run([sys.executable, '-m', 'pip', 'install', 'pyinstaller'], check=True)
        return True
    except subprocess.CalledProcessError:
        print("[!] Failed to install PyInstaller")
        return False

def build_executable():
    """Build standalone executable"""
    system = platform.system()
    
    if system == "Windows":
        exe_name = "PrivEsc-Framework-Windows.exe"
    else:
        exe_name = "PrivEsc-Framework-Linux"
    
    print(f"[+] Building executable for {system}...")
    
    cmd = [
        'pyinstaller',
        '--onefile',
        '--name', exe_name.replace('.exe', ''),
        '--add-data', 'core:core',
        '--add-data', 'windows:windows', 
        '--add-data', 'linux:linux',
        '--add-data', 'rules:rules',
        '--hidden-import', 'core.os_detector',
        '--hidden-import', 'core.privilege_checker',
        '--hidden-import', 'core.report_engine',
        '--hidden-import', 'windows.enum_services',
        '--hidden-import', 'windows.enum_registry',
        '--hidden-import', 'windows.enum_tokens',
        '--hidden-import', 'windows.enum_scheduled_tasks',
        '--hidden-import', 'linux.enum_users',
        '--hidden-import', 'linux.enum_sudo',
        '--hidden-import', 'linux.enum_suid',
        '--hidden-import', 'linux.enum_cron',
        '--hidden-import', 'linux.enum_kernel',
        '--console',
        'main.py'
    ]
    
    try:
        subprocess.run(cmd, check=True)
        print(f"[+] Executable built successfully: dist/{exe_name}")
        return True
    except subprocess.CalledProcessError:
        print("[!] Failed to build executable")
        return False

def main():
    print("=" * 50)
    print("PrivEsc-Framework Executable Builder")
    print("=" * 50)
    
    if not check_pyinstaller():
        print("[!] PyInstaller not found")
        if not install_pyinstaller():
            sys.exit(1)
    
    if build_executable():
        print("\n[+] Build completed successfully!")
        print("[+] Executable created in dist/ directory")
        print("[+] You can now distribute the standalone executable")
    else:
        print("\n[!] Build failed")
        sys.exit(1)

if __name__ == "__main__":
    main()