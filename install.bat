@echo off

REM === Disable Folders in Windows Explorer ===
regedit /s "%~dp0Disable 3D Objects Folder Win10 64.reg"
regedit /s "%~dp0Disable Libraries Folder Win10 64.reg"
regedit /s "%~dp0Disable Music Folder Win10 64.reg"
regedit /s "%~dp0Disable One Drive Win10 64.reg"
regedit /s "%~dp0Disable Pictures Folder Win10 64.reg"
regedit /s "%~dp0Disable Quick Access Win10 64.reg"
regedit /s "%~dp0Disable Removable Drives File Explorer Win10 64.reg"
regedit /s "%~dp0Disable Videos Folder Win10 64.reg"

REM === Enable Take Ownership Context Menu ===
regedit /s "%~dp0enable-take-ownership-context-menu.reg"

REM === Install Classic Start ===
regedit /s "%~dp0install-classic-start.reg"

REM === Apply Other Registry Tweaks ===
regedit /s "%~dp0old.reg"

REM === Run Windows Defender Remover ===
start /wait "" "%~dp0windows-defender-remover-main\Remove defender.exe"

REM === Run PowerShell Script ===
powershell -ExecutionPolicy Bypass -File "%~dp0boxstarter.ps1"

REM === Install Date-Time-Only App ===
start /wait "" "%~dp0Date-Time-Only.AppxBundle"

REM === Run Additional Batch Scripts ===
call "%~dp0power.bat"
call "%~dp0windows-defender-remover-main\run.bat"

REM === Reboot System After Installation ===
shutdown /r /t 0
