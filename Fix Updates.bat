@echo off
title Fix Windows Updates

cls
echo 1/7 - Stopping Services
for %%s in (BITS wuauserv) do net stop %%s >nul 2>&1

echo 2/7 - Configuring services
sc config wuauserv start= auto >nul 2>&1
sc config BITS start= delayed-auto >nul 2>&1
sc config AppReadiness start= manual >nul 2>&1
sc config CryptSvc start= auto >nul 2>&1

echo 3/7 - Deleting Pending/Cached Updates
if exist "C:\Windows\Temp\" for /F "delims=" %%i in ('dir /b "C:\Windows\Temp\"') do (rmdir "C:\Windows\Temp\%%i" /s/q || del "C:\Windows\Temp\%%i" /s/q) >nul 2>&1
if exist "C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\Temporary Internet Files\%%i" in ('dir /b ""') do (rmdir "C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\Temporary Internet Files\%%i" /s/q || del "C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\Temporary Internet Files\%%i" /s/q) >nul 2>&1
if exist "C:\Windows\Prefetch\" for /F "delims=" %%i in ('dir /b "C:\Windows\Prefetch\"') do (rmdir "C:\Windows\Prefetch\%%i" /s/q || del "C:\Windows\Prefetch\%%i" /s/q) >nul 2>&1
if exist "C:\Windows\SoftwareDistribution\" for /F "delims=" %%i in ('dir /b "C:\Windows\SoftwareDistribution\"') do (rmdir "C:\Windows\SoftwareDistribution\%%i" /s/q || del "C:\Windows\SoftwareDistribution\%%i" /s/q) >nul 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired" /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\PostRebootReporting" /f >nul 2>&1

::Malformed Keys
echo 4/7 - Deleting Bad Registry Keys
setlocal EnableDelayedExpansion
set "reg_path=HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore"
for /f "tokens=*" %%k in ('reg query "%reg_path%" /s 2^>nul ^| findstr /b /i "%reg_path%"') do (
    set "full_key=%%k"
    set "delete_key=false"
    set "reason="
    for %%a in ("!full_key!") do set "key_name=%%~nxa"
    :: Skip empty or unchanged names
    if "!key_name!"=="" (
        set "reason=empty key name"
    ) else if "!key_name!"=="!full_key!" (
        set "reason=key name same as full path"
    ) else (
        :: Check for space
        set "spaced_key=!key_name: =!"
        if not "!key_name!"=="!spaced_key!" (
            set "delete_key=true"
        ) else (
            :: Check for letters
            echo /7 - !key_name! | findstr /r /c:"[a-zA-Z]" >nul
            if !errorlevel! neq 0 set "delete_key=true"
        )
    )
    if "!delete_key!"=="true" reg delete "!full_key!" /f >nul 2>&1
)
endlocal

echo 5/7 - Applying Various Fixes
rmdir /s/q %windir%\system32\catroot2 >nul 2>&1
mkdir %windir%\system32\catroot2 >nul 2>&1
attrib -h -r -s %windir%\system32\catroot2 >nul 2>&1
attrib -h -r -s %windir%\system32\catroot2\*.* >nul 2>&1
rmdir /s/q %windir%\SoftwareDistribution >nul 2>&1
mkdir %windir%\SoftwareDistribution >nul 2>&1
rmdir /s/q "%ALLUSERSPROFILE%\application data\Microsoft\Network\downloader" >nul 2>&1
mkdir "%ALLUSERSPROFILE%\application data\Microsoft\Network\downloader" >nul 2>&1
for %%d in (atl.dll msxml2.dll msxml3.dll msxml.dll wuaueng1.dll  wuaueng.dll wucltui.dll wups2.dll wups.dll wuweb.dll ) do regsvr32 /s %%d
bitsadmin /reset /allusers >nul 2>&1
netsh winsock reset >nul 2>&1
:: Get updates ASAP - Off
reg add "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v IsContinuousInnovationOptedIn /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v AllowOptionalContent /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v SetAllowOptionalContent/t REG_DWORD /d 0 /f >nul 2>&1
::Disable "Lets finish setting up your device" - Asks to change to online account
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" /v ScoobeSystemSettingEnabled /t REG_DWORD /d 0 /f >nul 2>&1
::
reg delete "HKCU\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAUAsDefaultShutdownOption /f >nul 2>&1
::
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v TargetReleaseVersionInfo /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v TargetReleaseVersion /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v ProductVersion /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v DisableOSUpgrade /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v DisableWindowsUpdateAccess /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v DoNotConnectToWindowsUpdateInternetLocations /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Policies\Microsoft\WindowsStore" /v DisableOSUpgrade /f >nul 2>&1
reg delete "HKLM\SYSTEM\Setup\UpgradeNotification" /v UpgradeAvailable /f >nul 2>&1


echo 6/7 - Finalizing
gpupdate /force >nul 2>&1


echo.
echo.
echo  Script completed. A reboot is required to finish.
echo.
echo.   Press  "Enter"  to reboot
echo.
pause
shutdown /r /t 10

