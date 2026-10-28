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
rmdir /s/q %windir%\SoftwareDistribution >nul 2>&1 & mkdir %windir%\SoftwareDistribution >nul 2>&1
for %%T in ("C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\Temporary Internet Files") do if exist "%%~T\" for /F "delims=" %%i in ('dir /b "%%~T"') do (rmdir "%%~T\%%i" /s/q || del "%%~T\%%i" /s/q) >nul 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired" /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\PostRebootReporting" /f >nul 2>&1

::Malformed Keys
echo 4/7 - Deleting Bad Registry Keys
setlocal EnableDelayedExpansion
set "reg_path=HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore"
for /f "tokens=*" %%k in ('reg query "%reg_path%" /s 2^>nul ^| findstr /b /i "%reg_path%"') do (
    set "full_key=%%k"
    set "delete_key=false"
    for %%a in ("!full_key!") do set "key_name=%%~nxa"
    rem Skip empty or unchanged names
    if not "!key_name!"=="" if not "!key_name!"=="!full_key!" (
        rem Check for space
        set "spaced_key=!key_name: =!"
        if not "!key_name!"=="!spaced_key!" (
            set "delete_key=true"
        ) else (
            rem Check for letters
            echo(!key_name!| findstr /r /c:"[a-zA-Z]" >NUL
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
rmdir /s/q "%ALLUSERSPROFILE%\application data\Microsoft\Network\downloader" >nul 2>&1
mkdir "%ALLUSERSPROFILE%\application data\Microsoft\Network\downloader" >nul 2>&1
for %%d in (atl.dll msxml2.dll msxml3.dll msxml.dll wuaueng1.dll  wuaueng.dll wucltui.dll wups2.dll wups.dll wuweb.dll ) do regsvr32 /s %%d
bitsadmin /reset /allusers >nul 2>&1
netsh winsock reset >nul 2>&1
:: Get updates ASAP - Off
reg add "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v IsContinuousInnovationOptedIn /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v AllowOptionalContent /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v SetAllowOptionalContent /t REG_DWORD /d 0 /f >nul 2>&1
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
:: 25H2 Loop
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Bfsvc" /v EspPaddingPercent /t REG_DWORD /d 0 /f >nul 2>&1


echo 6/7 - Fixing Missing Reg Keys
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{00FA007C-D99F-407F-B00B-5B3B0001D8AB}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{00FA007C-D99F-407F-B00B-5B3B0001D8AB}" /v "CLSID" /t REG_SZ /d "{9BA05972-F6A8-11CF-A442-00A0C90A8F39}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{00FA007C-D99F-407F-B00B-5B3B0001D8AB}" /v "Policy" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{054aae20-4bea-4347-8a35-64a533254a9d}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{054aae20-4bea-4347-8a35-64a533254a9d}" /v "AppName" /t REG_SZ /d "tabtip.exe" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{054aae20-4bea-4347-8a35-64a533254a9d}" /v "AppPath" /t REG_SZ /d "C:\Program Files\Common Files\Microsoft Shared\Ink" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{054aae20-4bea-4347-8a35-64a533254a9d}" /v "Policy" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{07d873dc-b9b9-44f5-af0b-fb59fa54fb7a}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{07d873dc-b9b9-44f5-af0b-fb59fa54fb7a}" /v "AppName" /t REG_SZ /d "wpcer.exe" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{07d873dc-b9b9-44f5-af0b-fb59fa54fb7a}" /v "AppPath" /t REG_SZ /d "C:\Windows\System32" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{07d873dc-b9b9-44f5-af0b-fb59fa54fb7a}" /v "Policy" /t REG_DWORD /d 3 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{1138506a-b949-46a7-b6c0-ee26499fdeaf}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{1138506a-b949-46a7-b6c0-ee26499fdeaf}" /v "AppName" /t REG_SZ /d "wuapp.exe" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{1138506a-b949-46a7-b6c0-ee26499fdeaf}" /v "AppPath" /t REG_SZ /d "C:\Windows\System32" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{1138506a-b949-46a7-b6c0-ee26499fdeaf}" /v "Policy" /t REG_DWORD /d 3 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{186e0934-aee9-11da-961b-0014223d2a70}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{186e0934-aee9-11da-961b-0014223d2a70}" /v "AppName" /t REG_SZ /d "dfsvc.exe" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{186e0934-aee9-11da-961b-0014223d2a70}" /v "AppPath" /t REG_SZ /d "C:\Windows\microsoft.net\framework64\v2.0.50727" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{186e0934-aee9-11da-961b-0014223d2a70}" /v "Policy" /t REG_DWORD /d 3 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{186e0935-aee9-11da-961b-0014223d2a70}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{186e0935-aee9-11da-961b-0014223d2a70}" /v "AppName" /t REG_SZ /d "dfsvc.exe" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{186e0935-aee9-11da-961b-0014223d2a70}" /v "AppPath" /t REG_SZ /d "C:\Windows\microsoft.net\framework64\v2.0.50727" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{186e0935-aee9-11da-961b-0014223d2a70}" /v "Policy" /t REG_DWORD /d 3 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{1F1E561D-AF17-4510-B996-351BBA0862A7}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{1F1E561D-AF17-4510-B996-351BBA0862A7}" /v "CLSID" /t REG_SZ /d "{20FD4E26-8E0F-4F73-A0E0-F27B8C57BE6F}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{1F1E561D-AF17-4510-B996-351BBA0862A7}" /v "Policy" /t REG_DWORD /d 3 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{2391d819-9d17-44ec-9ac1-f6aa07549469}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{2391d819-9d17-44ec-9ac1-f6aa07549469}" /v "AppName" /t REG_SZ /d "wermgr.exe" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{2391d819-9d17-44ec-9ac1-f6aa07549469}" /v "AppPath" /t REG_EXPAND_SZ /d "%%systemroot%%\system32" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{2391d819-9d17-44ec-9ac1-f6aa07549469}" /v "IID" /t REG_SZ /d "{aa586b2c-26ee-491f-955d-3dd0ac95c45b}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{2391d819-9d17-44ec-9ac1-f6aa07549469}" /v "Policy" /t REG_DWORD /d 3 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{26fe7361-bd5a-4dcb-b309-c6f42dde661c}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{26fe7361-bd5a-4dcb-b309-c6f42dde661c}" /v "AppName" /t REG_SZ /d "ieinstal.exe" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{26fe7361-bd5a-4dcb-b309-c6f42dde661c}" /v "AppPath" /t REG_SZ /d "C:\Program Files\Internet Explorer" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{26fe7361-bd5a-4dcb-b309-c6f42dde661c}" /v "Policy" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{2dec4925-1312-4d7f-a6f5-89272d848dcf}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{2dec4925-1312-4d7f-a6f5-89272d848dcf}" /v "AppName" /t REG_SZ /d "IMJPUEX.exe" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{2dec4925-1312-4d7f-a6f5-89272d848dcf}" /v "AppPath" /t REG_EXPAND_SZ /d "%%WINDIR%%\system32\IME\IMEJP\\" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{2dec4925-1312-4d7f-a6f5-89272d848dcf}" /v "Policy" /t REG_DWORD /d 3 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{357FBE87-6C8E-490D-A059-4746C864AE6F}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{357FBE87-6C8E-490D-A059-4746C864AE6F}" /v "AppName" /t REG_SZ /d "InputPersonalization.exe" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{357FBE87-6C8E-490D-A059-4746C864AE6F}" /v "AppPath" /t REG_SZ /d "C:\Program Files\Common Files\Microsoft Shared\Ink" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{357FBE87-6C8E-490D-A059-4746C864AE6F}" /v "Policy" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{38f2c092-34df-4c12-9d9e-c9679bf0ab31}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{38f2c092-34df-4c12-9d9e-c9679bf0ab31}" /v "AppName" /t REG_SZ /d "presentationhost.exe" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{38f2c092-34df-4c12-9d9e-c9679bf0ab31}" /v "AppPath" /t REG_SZ /d "C:\Windows\SysWOW64" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{38f2c092-34df-4c12-9d9e-c9679bf0ab31}" /v "Policy" /t REG_DWORD /d 2 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{38f2c092-34df-4c12-9d9e-c9679bf0ab31}" /v "Unmarshaler" /t REG_SZ /d "{4B181F0F-48C8-4e80-A2AF-E3099AAC069B}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{49E561B1-1091-4E65-98A0-AFCA4996CD1D}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{49E561B1-1091-4E65-98A0-AFCA4996CD1D}" /v "AppName" /t REG_SZ /d "RuntimeBroker.exe" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{49E561B1-1091-4E65-98A0-AFCA4996CD1D}" /v "AppPath" /t REG_SZ /d "C:\Windows\System32" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{49E561B1-1091-4E65-98A0-AFCA4996CD1D}" /v "Policy" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{4D256DB0-6C34-4EC1-9704-02182D6503A6}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{4D256DB0-6C34-4EC1-9704-02182D6503A6}" /v "CLSID" /t REG_SZ /d "{4D256DB0-6C34-4EC1-9704-02182D6503A6}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{4D256DB0-6C34-4EC1-9704-02182D6503A6}" /v "Policy" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{4FA8381C-2705-4DC2-ADF3-347D4D619350}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{4FA8381C-2705-4DC2-ADF3-347D4D619350}" /v "AppName" /t REG_SZ /d "imecfmui.exe" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{4FA8381C-2705-4DC2-ADF3-347D4D619350}" /v "AppPath" /t REG_EXPAND_SZ /d "%%WINDIR%%\system32\IME\shared" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{4FA8381C-2705-4DC2-ADF3-347D4D619350}" /v "Policy" /t REG_DWORD /d 3 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{61bd7005-d55e-4693-a191-0caa33601426}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{61bd7005-d55e-4693-a191-0caa33601426}" /v "CLSID" /t REG_SZ /d "{de50c7bb-faa7-4a7f-ba47-bf0efcfe433d}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{61bd7005-d55e-4693-a191-0caa33601426}" /v "Policy" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{6bf52a52-394a-11d3-b153-00c04f79faa6}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{6bf52a52-394a-11d3-b153-00c04f79faa6}" /v "AppName" /t REG_SZ /d "wmplayer.exe" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{6bf52a52-394a-11d3-b153-00c04f79faa6}" /v "AppPath" /t REG_EXPAND_SZ /d "%%ProgramFiles%%\Windows Media Player" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{6bf52a52-394a-11d3-b153-00c04f79faa6}" /v "Policy" /t REG_DWORD /d 3 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{6bf52a52-394a-11d3-b153-00c04f79faa6}-32" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{6bf52a52-394a-11d3-b153-00c04f79faa6}-32" /v "AppName" /t REG_SZ /d "wmplayer.exe" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{6bf52a52-394a-11d3-b153-00c04f79faa6}-32" /v "AppPath" /t REG_EXPAND_SZ /d "%%ProgramFiles(x86)%%\Windows Media Player" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{6bf52a52-394a-11d3-b153-00c04f79faa6}-32" /v "Policy" /t REG_DWORD /d 3 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{70f641fd-9ffc-4d5b-a4dc-962af4ed7999}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{70f641fd-9ffc-4d5b-a4dc-962af4ed7999}" /v "AppName" /t REG_SZ /d "iedw.exe" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{70f641fd-9ffc-4d5b-a4dc-962af4ed7999}" /v "AppPath" /t REG_SZ /d "C:\Program Files\Internet Explorer" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{70f641fd-9ffc-4d5b-a4dc-962af4ed7999}" /v "Policy" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{734A9EB3-A34D-4fb7-9DB4-549C28F7EF97}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{734A9EB3-A34D-4fb7-9DB4-549C28F7EF97}" /v "CLSID" /t REG_SZ /d "{9A4B1918-0A2F-4422-89DD-35B3F455999C}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{734A9EB3-A34D-4fb7-9DB4-549C28F7EF97}" /v "Policy" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{78c7b664-c9bf-4ce9-8b3a-b05d442e451e}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{78c7b664-c9bf-4ce9-8b3a-b05d442e451e}" /v "AppName" /t REG_SZ /d "CertEnrollCtrl.exe" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{78c7b664-c9bf-4ce9-8b3a-b05d442e451e}" /v "AppPath" /t REG_SZ /d "C:\Windows\System32\\" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{78c7b664-c9bf-4ce9-8b3a-b05d442e451e}" /v "Policy" /t REG_DWORD /d 3 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{7aaae723-5fb5-4b2d-9327-75519f336825}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{7aaae723-5fb5-4b2d-9327-75519f336825}" /v "CLSID" /t REG_SZ /d "{33246F92-D56F-4E34-837A-9A49BFC91DF3}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{7aaae723-5fb5-4b2d-9327-75519f336825}" /v "Policy" /t REG_DWORD /d 3 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{7eb01fb2-f185-445a-94e4-ec4e1ba2202c}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{7eb01fb2-f185-445a-94e4-ec4e1ba2202c}" /v "AppName" /t REG_SZ /d "verclsid.exe" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{7eb01fb2-f185-445a-94e4-ec4e1ba2202c}" /v "AppPath" /t REG_SZ /d "C:\Windows\System32" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{7eb01fb2-f185-445a-94e4-ec4e1ba2202c}" /v "Policy" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{7f7bd411-f034-4ac0-9424-224bd7ab4e4e}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{7f7bd411-f034-4ac0-9424-224bd7ab4e4e}" /v "AppName" /t REG_SZ /d "IMEPADSV.exe" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{7f7bd411-f034-4ac0-9424-224bd7ab4e4e}" /v "AppPath" /t REG_EXPAND_SZ /d "%%WINDIR%%\system32\IME\SHARED\\" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{7f7bd411-f034-4ac0-9424-224bd7ab4e4e}" /v "Policy" /t REG_DWORD /d 3 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{812954F9-FAA2-4aee-A9E7-3C4FDE2166A6}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{812954F9-FAA2-4aee-A9E7-3C4FDE2166A6}" /v "CLSID" /t REG_SZ /d "{69B1A7D7-C09E-40e9-A1DF-688007A2D9E4}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{812954F9-FAA2-4aee-A9E7-3C4FDE2166A6}" /v "Policy" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{85fc331e-bb64-4c53-ba25-3d8a956c02fd}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{85fc331e-bb64-4c53-ba25-3d8a956c02fd}" /v "AppName" /t REG_SZ /d "ctfmon.exe" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{85fc331e-bb64-4c53-ba25-3d8a956c02fd}" /v "AppPath" /t REG_SZ /d "C:\Windows\System32" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{85fc331e-bb64-4c53-ba25-3d8a956c02fd}" /v "Policy" /t REG_DWORD /d 3 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{877467C0-F9E4-4561-84F0-65AA7539833C}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{877467C0-F9E4-4561-84F0-65AA7539833C}" /v "AppName" /t REG_SZ /d "CredentialUIBroker.exe" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{877467C0-F9E4-4561-84F0-65AA7539833C}" /v "AppPath" /t REG_SZ /d "C:\Windows\System32" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{877467C0-F9E4-4561-84F0-65AA7539833C}" /v "Policy" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{8cec58ae-07a1-11d9-b15e-000d56bfe6ee}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{8cec58ae-07a1-11d9-b15e-000d56bfe6ee}" /v "AppName" /t REG_SZ /d "helppane.exe" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{8cec58ae-07a1-11d9-b15e-000d56bfe6ee}" /v "AppPath" /t REG_SZ /d "C:\Windows" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{8cec58ae-07a1-11d9-b15e-000d56bfe6ee}" /v "Policy" /t REG_DWORD /d 3 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{989F13EE-B25B-4FAB-9AED-C4336C8CCF0C}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{989F13EE-B25B-4FAB-9AED-C4336C8CCF0C}" /v "CLSID" /t REG_SZ /d "{989F13EE-B25B-4FAB-9AED-C4336C8CCF0C}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{989F13EE-B25B-4FAB-9AED-C4336C8CCF0C}" /v "Policy" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{98E3C2D3-E92F-469F-87EB-76054F640517}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{98E3C2D3-E92F-469F-87EB-76054F640517}" /v "AppName" /t REG_SZ /d "imesearch.exe" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{98E3C2D3-E92F-469F-87EB-76054F640517}" /v "AppPath" /t REG_EXPAND_SZ /d "C:\Windows\System32\IME\SHARED\\" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{98E3C2D3-E92F-469F-87EB-76054F640517}" /v "Policy" /t REG_DWORD /d 3 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{a1ad1bbb-3b33-4260-a74c-5fd8bc1479fc}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{a1ad1bbb-3b33-4260-a74c-5fd8bc1479fc}" /v "AppName" /t REG_SZ /d "splwow64.exe" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{a1ad1bbb-3b33-4260-a74c-5fd8bc1479fc}" /v "AppPath" /t REG_EXPAND_SZ /d "C:\Windows" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{a1ad1bbb-3b33-4260-a74c-5fd8bc1479fc}" /v "Policy" /t REG_DWORD /d 3 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{a4fbcbc6-4be5-4c3d-8ab5-8b873357a23e}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{a4fbcbc6-4be5-4c3d-8ab5-8b873357a23e}" /v "CLSID" /t REG_SZ /d "{a4fbcbc6-4be5-4c3d-8ab5-8b873357a23e}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{a4fbcbc6-4be5-4c3d-8ab5-8b873357a23e}" /v "Policy" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{a5a2d52a-4944-47c4-a3e0-8bd92e14d953}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{a5a2d52a-4944-47c4-a3e0-8bd92e14d953}" /v "AppName" /t REG_SZ /d "xpsviewer.exe" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{a5a2d52a-4944-47c4-a3e0-8bd92e14d953}" /v "AppPath" /t REG_SZ /d "C:\Windows\SysWOW64\xpsviewer" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{a5a2d52a-4944-47c4-a3e0-8bd92e14d953}" /v "Policy" /t REG_DWORD /d 3 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{afe26134-8a16-4149-b798-242574f3f4a9}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{afe26134-8a16-4149-b798-242574f3f4a9}" /v "AppName" /t REG_SZ /d "IMTCPROP.exe" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{afe26134-8a16-4149-b798-242574f3f4a9}" /v "AppPath" /t REG_EXPAND_SZ /d "%%SystemRoot%%\system32\IME\IMETC\\" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{afe26134-8a16-4149-b798-242574f3f4a9}" /v "Policy" /t REG_DWORD /d 3 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{aff735eb-cdf9-4894-aa69-3e3131128618}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{aff735eb-cdf9-4894-aa69-3e3131128618}" /v "AppName" /t REG_SZ /d "cmd.exe" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{aff735eb-cdf9-4894-aa69-3e3131128618}" /v "AppPath" /t REG_SZ /d "C:\Windows\System32" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{aff735eb-cdf9-4894-aa69-3e3131128618}" /v "Policy" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{B43A0C1E-B63F-4691-B68F-CD807A45DA01}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{B43A0C1E-B63F-4691-B68F-CD807A45DA01}" /v "AppName" /t REG_SZ /d "TSWbPrxy.exe" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{B43A0C1E-B63F-4691-B68F-CD807A45DA01}" /v "AppPath" /t REG_EXPAND_SZ /d "%%systemroot%%\system32" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{B43A0C1E-B63F-4691-B68F-CD807A45DA01}" /v "Policy" /t REG_DWORD /d 3 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{C8999AEC-AECE-4E27-9BCB-5358B13F9FF9}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{C8999AEC-AECE-4E27-9BCB-5358B13F9FF9}" /v "AppName" /t REG_SZ /d "dfsvc.exe" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{C8999AEC-AECE-4E27-9BCB-5358B13F9FF9}" /v "AppPath" /t REG_SZ /d "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\\" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{C8999AEC-AECE-4E27-9BCB-5358B13F9FF9}" /v "Policy" /t REG_DWORD /d 3 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{c9abcf16-8dc2-4a95-bae3-24fd98f2ed29}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{c9abcf16-8dc2-4a95-bae3-24fd98f2ed29}" /ve /t REG_SZ /d "IEToEdge Handler" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{c9abcf16-8dc2-4a95-bae3-24fd98f2ed29}" /v "AppName" /t REG_SZ /d "ie_to_edge_stub.exe" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{c9abcf16-8dc2-4a95-bae3-24fd98f2ed29}" /v "Policy" /t REG_DWORD /d 3 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{c9abcf16-8dc2-4a95-bae3-24fd98f2ed29}" /v "AppPath" /t REG_SZ /d "C:\Program Files (x86)\Microsoft\Edge\Application\156.0.4314.42\BHO" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{dc6bf185-7ae4-444e-8c35-e447b0d2bd1e}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{dc6bf185-7ae4-444e-8c35-e447b0d2bd1e}" /v "AppName" /t REG_SZ /d "notepad.exe" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{dc6bf185-7ae4-444e-8c35-e447b0d2bd1e}" /v "AppPath" /t REG_SZ /d "C:\Windows\System32" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{dc6bf185-7ae4-444e-8c35-e447b0d2bd1e}" /v "Policy" /t REG_DWORD /d 3 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{eee261cc-4b3e-46e7-affb-61f297155bf2}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{eee261cc-4b3e-46e7-affb-61f297155bf2}" /v "AppName" /t REG_SZ /d "presentationhost.exe" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{eee261cc-4b3e-46e7-affb-61f297155bf2}" /v "AppPath" /t REG_SZ /d "C:\Windows\System32" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{eee261cc-4b3e-46e7-affb-61f297155bf2}" /v "Policy" /t REG_DWORD /d 2 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{eee261cc-4b3e-46e7-affb-61f297155bf2}" /v "Unmarshaler" /t REG_SZ /d "{4B181F0F-48C8-4e80-A2AF-E3099AAC069B}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{f5d04f46-b4b2-4202-a191-f780421b4200}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{f5d04f46-b4b2-4202-a191-f780421b4200}" /v "AppName" /t REG_SZ /d "imjpdct.exe" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{f5d04f46-b4b2-4202-a191-f780421b4200}" /v "AppPath" /t REG_EXPAND_SZ /d "%%WINDIR%%\system32\IME\IMEJP\\" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{f5d04f46-b4b2-4202-a191-f780421b4200}" /v "Policy" /t REG_DWORD /d 3 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{fa6f0991-f729-4899-b095-d3fbca253cf6}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{fa6f0991-f729-4899-b095-d3fbca253cf6}" /v "CLSID" /t REG_SZ /d "{ba6ee7d8-190d-423a-93cc-1270e6599195}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{fa6f0991-f729-4899-b095-d3fbca253cf6}" /v "Policy" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{00FA007C-D99F-407F-B00B-5B3B0001D8AB}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{00FA007C-D99F-407F-B00B-5B3B0001D8AB}" /v "CLSID" /t REG_SZ /d "{9BA05972-F6A8-11CF-A442-00A0C90A8F39}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{00FA007C-D99F-407F-B00B-5B3B0001D8AB}" /v "Policy" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{054aae20-4bea-4347-8a35-64a533254a9d}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{054aae20-4bea-4347-8a35-64a533254a9d}" /v "AppName" /t REG_SZ /d "tabtip.exe" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{054aae20-4bea-4347-8a35-64a533254a9d}" /v "AppPath" /t REG_SZ /d "C:\Program Files (x86)\Common Files\Microsoft Shared\Ink" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{054aae20-4bea-4347-8a35-64a533254a9d}" /v "Policy" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{07d873dc-b9b9-44f5-af0b-fb59fa54fb7a}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{07d873dc-b9b9-44f5-af0b-fb59fa54fb7a}" /v "AppName" /t REG_SZ /d "wpcer.exe" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{07d873dc-b9b9-44f5-af0b-fb59fa54fb7a}" /v "AppPath" /t REG_SZ /d "C:\Windows\SysWOW64" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{07d873dc-b9b9-44f5-af0b-fb59fa54fb7a}" /v "Policy" /t REG_DWORD /d 3 /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{08f24d68-9087-4b24-81ad-7b34af3e3ed5}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{08f24d68-9087-4b24-81ad-7b34af3e3ed5}" /v "AppName" /t REG_SZ /d "Acrobat Elements.exe" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{08f24d68-9087-4b24-81ad-7b34af3e3ed5}" /v "AppPath" /t REG_SZ /d "C:\Program Files (x86)\adobe\acrobat 6.0\Acrobat Elements" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{08f24d68-9087-4b24-81ad-7b34af3e3ed5}" /v "Policy" /t REG_DWORD /d 3 /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{1138506a-b949-46a7-b6c0-ee26499fdeaf}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{1138506a-b949-46a7-b6c0-ee26499fdeaf}" /v "AppName" /t REG_SZ /d "wuapp.exe" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{1138506a-b949-46a7-b6c0-ee26499fdeaf}" /v "AppPath" /t REG_SZ /d "C:\Windows\SysWOW64" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{1138506a-b949-46a7-b6c0-ee26499fdeaf}" /v "Policy" /t REG_DWORD /d 3 /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{186e0934-aee9-11da-961b-0014223d2a70}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{186e0934-aee9-11da-961b-0014223d2a70}" /v "AppName" /t REG_SZ /d "dfsvc.exe" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{186e0934-aee9-11da-961b-0014223d2a70}" /v "AppPath" /t REG_SZ /d "C:\Windows\microsoft.net\framework\v2.0.50727" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{186e0934-aee9-11da-961b-0014223d2a70}" /v "Policy" /t REG_DWORD /d 3 /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{1F1E561D-AF17-4510-B996-351BBA0862A7}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{1F1E561D-AF17-4510-B996-351BBA0862A7}" /v "CLSID" /t REG_SZ /d "{20FD4E26-8E0F-4F73-A0E0-F27B8C57BE6F}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{1F1E561D-AF17-4510-B996-351BBA0862A7}" /v "Policy" /t REG_DWORD /d 3 /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{26fe7361-bd5a-4dcb-b309-c6f42dde661c}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{26fe7361-bd5a-4dcb-b309-c6f42dde661c}" /v "AppName" /t REG_SZ /d "ieinstal.exe" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{26fe7361-bd5a-4dcb-b309-c6f42dde661c}" /v "AppPath" /t REG_SZ /d "C:\Program Files (x86)\Internet Explorer" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{26fe7361-bd5a-4dcb-b309-c6f42dde661c}" /v "Policy" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{2dec4925-1312-4d7f-a6f5-89272d848dcf}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{2dec4925-1312-4d7f-a6f5-89272d848dcf}" /v "AppName" /t REG_SZ /d "IMJPUEX.exe" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{2dec4925-1312-4d7f-a6f5-89272d848dcf}" /v "AppPath" /t REG_EXPAND_SZ /d "%%WINDIR%%\system32\IME\IMEJP\\" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{2dec4925-1312-4d7f-a6f5-89272d848dcf}" /v "Policy" /t REG_DWORD /d 3 /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{357FBE87-6C8E-490D-A059-4746C864AE6F}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{357FBE87-6C8E-490D-A059-4746C864AE6F}" /v "AppName" /t REG_SZ /d "InputPersonalization.exe" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{357FBE87-6C8E-490D-A059-4746C864AE6F}" /v "AppPath" /t REG_SZ /d "C:\Program Files (x86)\Common Files\Microsoft Shared\Ink" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{357FBE87-6C8E-490D-A059-4746C864AE6F}" /v "Policy" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{49E561B1-1091-4E65-98A0-AFCA4996CD1D}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{49E561B1-1091-4E65-98A0-AFCA4996CD1D}" /v "AppName" /t REG_SZ /d "RuntimeBroker.exe" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{49E561B1-1091-4E65-98A0-AFCA4996CD1D}" /v "AppPath" /t REG_SZ /d "C:\Windows\SysWOW64" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{49E561B1-1091-4E65-98A0-AFCA4996CD1D}" /v "Policy" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{4becf16c-74f0-429b-8d3e-4fba507ac661}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{4becf16c-74f0-429b-8d3e-4fba507ac661}" /v "AppName" /t REG_SZ /d "acrord32.exe" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{4becf16c-74f0-429b-8d3e-4fba507ac661}" /v "AppPath" /t REG_SZ /d "C:\Program Files (x86)\adobe\acrobat 7.0\reader" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{4becf16c-74f0-429b-8d3e-4fba507ac661}" /v "Policy" /t REG_DWORD /d 3 /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{4D256DB0-6C34-4EC1-9704-02182D6503A6}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{4D256DB0-6C34-4EC1-9704-02182D6503A6}" /v "CLSID" /t REG_SZ /d "{4D256DB0-6C34-4EC1-9704-02182D6503A6}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{4D256DB0-6C34-4EC1-9704-02182D6503A6}" /v "Policy" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{4FA8381C-2705-4DC2-ADF3-347D4D619350}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{4FA8381C-2705-4DC2-ADF3-347D4D619350}" /v "AppName" /t REG_SZ /d "imecfmui.exe" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{4FA8381C-2705-4DC2-ADF3-347D4D619350}" /v "AppPath" /t REG_EXPAND_SZ /d "%%WINDIR%%\system32\IME\shared" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{4FA8381C-2705-4DC2-ADF3-347D4D619350}" /v "Policy" /t REG_DWORD /d 3 /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{61bd7005-d55e-4693-a191-0caa33601426}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{61bd7005-d55e-4693-a191-0caa33601426}" /v "CLSID" /t REG_SZ /d "{de50c7bb-faa7-4a7f-ba47-bf0efcfe433d}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{61bd7005-d55e-4693-a191-0caa33601426}" /v "Policy" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{6bf52a52-394a-11d3-b153-00c04f79faa6}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{6bf52a52-394a-11d3-b153-00c04f79faa6}" /v "AppName" /t REG_SZ /d "wmplayer.exe" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{6bf52a52-394a-11d3-b153-00c04f79faa6}" /v "AppPath" /t REG_EXPAND_SZ /d "%%ProgramFiles%%\Windows Media Player" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{6bf52a52-394a-11d3-b153-00c04f79faa6}" /v "Policy" /t REG_DWORD /d 3 /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{6bf52a52-394a-11d3-b153-00c04f79faa6}-32" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{6bf52a52-394a-11d3-b153-00c04f79faa6}-32" /v "AppName" /t REG_SZ /d "wmplayer.exe" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{6bf52a52-394a-11d3-b153-00c04f79faa6}-32" /v "AppPath" /t REG_EXPAND_SZ /d "%%ProgramFiles(x86)%%\Windows Media Player" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{6bf52a52-394a-11d3-b153-00c04f79faa6}-32" /v "Policy" /t REG_DWORD /d 3 /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{70f641fd-9ffc-4d5b-a4dc-962af4ed7999}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{70f641fd-9ffc-4d5b-a4dc-962af4ed7999}" /v "AppName" /t REG_SZ /d "iedw.exe" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{70f641fd-9ffc-4d5b-a4dc-962af4ed7999}" /v "AppPath" /t REG_SZ /d "C:\Program Files (x86)\Internet Explorer" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{70f641fd-9ffc-4d5b-a4dc-962af4ed7999}" /v "Policy" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{734A9EB3-A34D-4fb7-9DB4-549C28F7EF97}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{734A9EB3-A34D-4fb7-9DB4-549C28F7EF97}" /v "CLSID" /t REG_SZ /d "{9A4B1918-0A2F-4422-89DD-35B3F455999C}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{734A9EB3-A34D-4fb7-9DB4-549C28F7EF97}" /v "Policy" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{78c7b664-c9bf-4ce9-8b3a-b05d442e451e}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{78c7b664-c9bf-4ce9-8b3a-b05d442e451e}" /v "AppName" /t REG_SZ /d "CertEnrollCtrl.exe" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{78c7b664-c9bf-4ce9-8b3a-b05d442e451e}" /v "AppPath" /t REG_SZ /d "C:\Windows\SysWOW64\\" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{78c7b664-c9bf-4ce9-8b3a-b05d442e451e}" /v "Policy" /t REG_DWORD /d 3 /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{7aaae723-5fb5-4b2d-9327-75519f336825}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{7aaae723-5fb5-4b2d-9327-75519f336825}" /v "CLSID" /t REG_SZ /d "{33246F92-D56F-4E34-837A-9A49BFC91DF3}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{7aaae723-5fb5-4b2d-9327-75519f336825}" /v "Policy" /t REG_DWORD /d 3 /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{7eb01fb2-f185-445a-94e4-ec4e1ba2202c}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{7eb01fb2-f185-445a-94e4-ec4e1ba2202c}" /v "AppName" /t REG_SZ /d "verclsid.exe" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{7eb01fb2-f185-445a-94e4-ec4e1ba2202c}" /v "AppPath" /t REG_SZ /d "C:\Windows\SysWOW64" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{7eb01fb2-f185-445a-94e4-ec4e1ba2202c}" /v "Policy" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{7f7bd411-f034-4ac0-9424-224bd7ab4e4e}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{7f7bd411-f034-4ac0-9424-224bd7ab4e4e}" /v "AppName" /t REG_SZ /d "IMEPADSV.exe" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{7f7bd411-f034-4ac0-9424-224bd7ab4e4e}" /v "AppPath" /t REG_EXPAND_SZ /d "%%WINDIR%%\sysnative\IME\SHARED\\" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{7f7bd411-f034-4ac0-9424-224bd7ab4e4e}" /v "Policy" /t REG_DWORD /d 3 /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{812954F9-FAA2-4aee-A9E7-3C4FDE2166A6}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{812954F9-FAA2-4aee-A9E7-3C4FDE2166A6}" /v "CLSID" /t REG_SZ /d "{69B1A7D7-C09E-40e9-A1DF-688007A2D9E4}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{812954F9-FAA2-4aee-A9E7-3C4FDE2166A6}" /v "Policy" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{85fc331e-bb64-4c53-ba25-3d8a956c02fd}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{85fc331e-bb64-4c53-ba25-3d8a956c02fd}" /v "AppName" /t REG_SZ /d "ctfmon.exe" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{85fc331e-bb64-4c53-ba25-3d8a956c02fd}" /v "AppPath" /t REG_SZ /d "C:\Windows\SysWOW64" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{85fc331e-bb64-4c53-ba25-3d8a956c02fd}" /v "Policy" /t REG_DWORD /d 3 /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{877467C0-F9E4-4561-84F0-65AA7539833C}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{877467C0-F9E4-4561-84F0-65AA7539833C}" /v "AppName" /t REG_SZ /d "CredentialUIBroker.exe" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{877467C0-F9E4-4561-84F0-65AA7539833C}" /v "AppPath" /t REG_SZ /d "C:\Windows\SysWOW64" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{877467C0-F9E4-4561-84F0-65AA7539833C}" /v "Policy" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{8cec58ae-07a1-11d9-b15e-000d56bfe6ee}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{8cec58ae-07a1-11d9-b15e-000d56bfe6ee}" /v "AppName" /t REG_SZ /d "helppane.exe" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{8cec58ae-07a1-11d9-b15e-000d56bfe6ee}" /v "AppPath" /t REG_SZ /d "C:\Windows" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{8cec58ae-07a1-11d9-b15e-000d56bfe6ee}" /v "Policy" /t REG_DWORD /d 3 /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{95a4104c-1c49-4c2a-9830-1be0f47e926c}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{95a4104c-1c49-4c2a-9830-1be0f47e926c}" /v "AppName" /t REG_SZ /d "acrobat.exe" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{95a4104c-1c49-4c2a-9830-1be0f47e926c}" /v "AppPath" /t REG_SZ /d "C:\Program Files (x86)\adobe\acrobat 7.0\Acrobat" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{95a4104c-1c49-4c2a-9830-1be0f47e926c}" /v "Policy" /t REG_DWORD /d 3 /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{989F13EE-B25B-4FAB-9AED-C4336C8CCF0C}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{989F13EE-B25B-4FAB-9AED-C4336C8CCF0C}" /v "CLSID" /t REG_SZ /d "{989F13EE-B25B-4FAB-9AED-C4336C8CCF0C}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{989F13EE-B25B-4FAB-9AED-C4336C8CCF0C}" /v "Policy" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{98E3C2D3-E92F-469F-87EB-76054F640517}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{98E3C2D3-E92F-469F-87EB-76054F640517}" /v "AppName" /t REG_SZ /d "imesearch.exe" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{98E3C2D3-E92F-469F-87EB-76054F640517}" /v "AppPath" /t REG_EXPAND_SZ /d "C:\Windows\SysWOW64\IME\SHARED\\" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{98E3C2D3-E92F-469F-87EB-76054F640517}" /v "Policy" /t REG_DWORD /d 3 /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{9da1d2cb-796d-4bec-bbaa-0aa9ccd80e15}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{9da1d2cb-796d-4bec-bbaa-0aa9ccd80e15}" /v "AppName" /t REG_SZ /d "Acrobat Elements.exe" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{9da1d2cb-796d-4bec-bbaa-0aa9ccd80e15}" /v "AppPath" /t REG_SZ /d "C:\Program Files (x86)\adobe\acrobat 7.0\Acrobat Elements" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{9da1d2cb-796d-4bec-bbaa-0aa9ccd80e15}" /v "Policy" /t REG_DWORD /d 3 /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{a1ad1bbb-3b33-4260-a74c-5fd8bc1479fc}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{a1ad1bbb-3b33-4260-a74c-5fd8bc1479fc}" /v "AppName" /t REG_SZ /d "splwow64.exe" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{a1ad1bbb-3b33-4260-a74c-5fd8bc1479fc}" /v "AppPath" /t REG_EXPAND_SZ /d "C:\Windows" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{a1ad1bbb-3b33-4260-a74c-5fd8bc1479fc}" /v "Policy" /t REG_DWORD /d 3 /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{a4fbcbc6-4be5-4c3d-8ab5-8b873357a23e}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{a4fbcbc6-4be5-4c3d-8ab5-8b873357a23e}" /v "CLSID" /t REG_SZ /d "{a4fbcbc6-4be5-4c3d-8ab5-8b873357a23e}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{a4fbcbc6-4be5-4c3d-8ab5-8b873357a23e}" /v "Policy" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{a5a2d52a-4944-47c4-a3e0-8bd92e14d953}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{a5a2d52a-4944-47c4-a3e0-8bd92e14d953}" /v "AppName" /t REG_SZ /d "xpsviewer.exe" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{a5a2d52a-4944-47c4-a3e0-8bd92e14d953}" /v "AppPath" /t REG_SZ /d "C:\Windows\SysWOW64\xpsviewer" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{a5a2d52a-4944-47c4-a3e0-8bd92e14d953}" /v "Policy" /t REG_DWORD /d 3 /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{afe26134-8a16-4149-b798-242574f3f4a9}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{afe26134-8a16-4149-b798-242574f3f4a9}" /v "AppName" /t REG_SZ /d "IMTCPROP.exe" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{afe26134-8a16-4149-b798-242574f3f4a9}" /v "AppPath" /t REG_EXPAND_SZ /d "%%SystemRoot%%\system32\IME\IMETC\\" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{afe26134-8a16-4149-b798-242574f3f4a9}" /v "Policy" /t REG_DWORD /d 3 /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{aff735eb-cdf9-4894-aa69-3e3131128618}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{aff735eb-cdf9-4894-aa69-3e3131128618}" /v "AppName" /t REG_SZ /d "cmd.exe" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{aff735eb-cdf9-4894-aa69-3e3131128618}" /v "AppPath" /t REG_SZ /d "C:\Windows\SysWOW64" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{aff735eb-cdf9-4894-aa69-3e3131128618}" /v "Policy" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{B43A0C1E-B63F-4691-B68F-CD807A45DA01}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{B43A0C1E-B63F-4691-B68F-CD807A45DA01}" /v "AppName" /t REG_SZ /d "TSWbPrxy.exe" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{B43A0C1E-B63F-4691-B68F-CD807A45DA01}" /v "AppPath" /t REG_EXPAND_SZ /d "%%systemroot%%\system32" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{B43A0C1E-B63F-4691-B68F-CD807A45DA01}" /v "Policy" /t REG_DWORD /d 3 /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{C8999AEC-AECE-4E27-9BCB-5358B13F9FF9}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{C8999AEC-AECE-4E27-9BCB-5358B13F9FF9}" /v "AppName" /t REG_SZ /d "dfsvc.exe" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{C8999AEC-AECE-4E27-9BCB-5358B13F9FF9}" /v "AppPath" /t REG_SZ /d "C:\Windows\Microsoft.NET\Framework\v4.0.30319\\" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{C8999AEC-AECE-4E27-9BCB-5358B13F9FF9}" /v "Policy" /t REG_DWORD /d 3 /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{C8999AED-AECE-4E27-9BCB-5358B13F9FF9}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{C8999AED-AECE-4E27-9BCB-5358B13F9FF9}" /v "AppName" /t REG_SZ /d "dfsvc.exe" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{C8999AED-AECE-4E27-9BCB-5358B13F9FF9}" /v "AppPath" /t REG_SZ /d "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\\" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{C8999AED-AECE-4E27-9BCB-5358B13F9FF9}" /v "Policy" /t REG_DWORD /d 3 /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{c9abcf16-8dc2-4a95-bae3-24fd98f2ed29}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{c9abcf16-8dc2-4a95-bae3-24fd98f2ed29}" /ve /t REG_SZ /d "IEToEdge Handler" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{c9abcf16-8dc2-4a95-bae3-24fd98f2ed29}" /v "AppName" /t REG_SZ /d "ie_to_edge_stub.exe" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{c9abcf16-8dc2-4a95-bae3-24fd98f2ed29}" /v "Policy" /t REG_DWORD /d 3 /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{c9abcf16-8dc2-4a95-bae3-24fd98f2ed29}" /v "AppPath" /t REG_SZ /d "C:\Program Files (x86)\Microsoft\Edge\Application\156.0.4314.42\BHO" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{dc6bf185-7ae4-444e-8c35-e447b0d2bd1e}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{dc6bf185-7ae4-444e-8c35-e447b0d2bd1e}" /v "AppName" /t REG_SZ /d "notepad.exe" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{dc6bf185-7ae4-444e-8c35-e447b0d2bd1e}" /v "AppPath" /t REG_SZ /d "C:\Windows\SysWOW64" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{dc6bf185-7ae4-444e-8c35-e447b0d2bd1e}" /v "Policy" /t REG_DWORD /d 3 /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{e5f90a07-7db7-4dcb-bd6d-d3fecd376ca3}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{e5f90a07-7db7-4dcb-bd6d-d3fecd376ca3}" /v "AppName" /t REG_SZ /d "acrord32.exe" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{e5f90a07-7db7-4dcb-bd6d-d3fecd376ca3}" /v "AppPath" /t REG_SZ /d "C:\Program Files (x86)\adobe\acrobat 6.0\reader" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{e5f90a07-7db7-4dcb-bd6d-d3fecd376ca3}" /v "Policy" /t REG_DWORD /d 3 /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{eee261cc-4b3e-46e7-affb-61f297155bf2}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{eee261cc-4b3e-46e7-affb-61f297155bf2}" /v "AppName" /t REG_SZ /d "presentationhost.exe" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{eee261cc-4b3e-46e7-affb-61f297155bf2}" /v "AppPath" /t REG_SZ /d "C:\Windows\SysWOW64" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{eee261cc-4b3e-46e7-affb-61f297155bf2}" /v "Policy" /t REG_DWORD /d 2 /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{eee261cc-4b3e-46e7-affb-61f297155bf2}" /v "Unmarshaler" /t REG_SZ /d "{4B181F0F-48C8-4e80-A2AF-E3099AAC069B}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{f5d04f46-b4b2-4202-a191-f780421b4200}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{f5d04f46-b4b2-4202-a191-f780421b4200}" /v "AppName" /t REG_SZ /d "imjpdct.exe" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{f5d04f46-b4b2-4202-a191-f780421b4200}" /v "AppPath" /t REG_EXPAND_SZ /d "%%WINDIR%%\system32\IME\IMEJP\\" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{f5d04f46-b4b2-4202-a191-f780421b4200}" /v "Policy" /t REG_DWORD /d 3 /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{fa6f0991-f729-4899-b095-d3fbca253cf6}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{fa6f0991-f729-4899-b095-d3fbca253cf6}" /v "CLSID" /t REG_SZ /d "{ba6ee7d8-190d-423a-93cc-1270e6599195}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{fa6f0991-f729-4899-b095-d3fbca253cf6}" /v "Policy" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{fb9e068b-c612-4fa8-bdb9-d728a716a420}" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{fb9e068b-c612-4fa8-bdb9-d728a716a420}" /v "AppName" /t REG_SZ /d "acrobat.exe" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{fb9e068b-c612-4fa8-bdb9-d728a716a420}" /v "AppPath" /t REG_SZ /d "C:\Program Files (x86)\adobe\acrobat 6.0\Acrobat" /f >nul 2>&1
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{fb9e068b-c612-4fa8-bdb9-d728a716a420}" /v "Policy" /t REG_DWORD /d 3 /f >nul 2>&1




echo 7/7 - Finalizing
gpupdate /force >nul 2>&1


echo.
echo.
echo  Script completed. A reboot is required to finish.
echo.
echo.   Press  "Enter"  to reboot
echo.
pause
shutdown /r /t 10
