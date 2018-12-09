@echo off
setlocal enableDelayedExpansion
mode con: cols=51 lines=12
echo.
echo.
echo.
echo       Administrator Permissions REQUIRED^^!
echo             Detecting permissions...
net session >nul 2>&1
if %errorLevel% == 0 (
    echo Success^^! Administrative Privileges successfully aquired..
	GOTO CONSENT
) else (
    echo Failure. Requesting for Administrator Privileges..
	GOTO init
)
:CONSENT
mode con: cols=43 lines=9
color 4f
echo   WARNING^^!^^! THIS PROGRAM WILL MODIFY YOUR 
echo   REGISTRY! WE ARE NOT RELIABLE FOR BROKEN 
echo   WINDOWS PC'S^^!^^!^^!  
echo           -Private-Locker Team
echo.
echo   (This is a 25 second Pause to decide.)
echo              Loading File...
Echo       [                          ]<nul
<nul set /p=
for /l %%a in (0,1,25) do (
   ping -n 2 -w 1000 127.0.0.1 >NUL
   set /p .= ^|<nul
)
echo.
cls
color 0f
echo.
echo        Thank you for Using this tool..
timeout /t 2 /NOBREAK >NUL
cls
GOTO REGTWEAK

:init
setlocal DisableDelayedExpansion
set "batchPath=%~0"
for %%k in (%0) do set batchName=%%~nk
set "vbsGetPrivileges=%temp%\OEgetPriv_%batchName%.vbs"
setlocal EnableDelayedExpansion
:checkPrivileges
NET FILE 1>NUL 2>NUL
if '%errorlevel%' == '0' ( goto gotPrivileges ) else ( goto getPrivileges )
:getPrivileges
if '%1'=='ELEV' (echo ELEV & shift /1 & goto gotPrivileges)
ECHO Set UAC = CreateObject^("Shell.Application"^) > "%vbsGetPrivileges%"
ECHO UAC.ShellExecute "!batchPath!", args, "", "runas", 1 >> "%vbsGetPrivileges%"
"%SystemRoot%\System32\WScript.exe" "%vbsGetPrivileges%"
exit /B
:gotPrivileges
setlocal & pushd .
cd /d %~dp0
if '%1'=='ELEV' (del "%vbsGetPrivileges%" 1>nul 2>nul  &  shift /1)
GOTO CONSENT
:REGTWEAK
mode con:cols=60 lines=25
echo ==========================================================
echo  Welcome to Private-Locker's Windows Tweaks for improving
echo  mining and overall experience on Windows Machines.
echo.
echo  You will get to choose prompt style on your Options,
echo  there is multiple groups of tweaks in this code.
echo.
echo  -Registry Mining Tweaks
echo  -Registry Running Services Tweaks
echo  -Schedule Task Tweaks
echo  -Remove Windows Bloatware (Xbox, Zune, 3d editors, etc)
echo  -Remove Telementry(Data Reporting) Serivces
echo ==========================================================
echo.
echo.
echo 1. Add Registry Tweaks
echo 2. Remove Registry Tweaks
echo.
echo.
echo.
echo 0. Exit
echo.
echo.
echo.
set option=null
set /p option="Select a Option[0-2] and Press ENTER to contine: "
if "%option%" EQU "1" GOTO START
if "%option%" EQU "2" GOTO START2 
if "%option%" EQU "0" GOTO EXIT
GOTO REGTWEAK
cls

:START2
echo ==========================================================
echo ================ Mining Registry Tweaks ==================
echo ==========================================================
ECHO.
set /p removal="You sure you want to remove Our Registry Tweaks? y/n: "
if "%removal%" EQU "n" goto REGTWEAK
if "%removal%" EQU "N" goto REGTWEAK
if "%removal%" EQU "y" GOTO rem1
if "%removal%" EQU "Y" GOTO rem1
GOTO START2
:rem1
echo Testing
pause
GOTO EXIT

:START
echo ==========================================================
echo ================ Mining Registry Tweaks ==================
echo ==========================================================
ECHO.
set /p registry="You sure you want to apply Our Registry Tweaks? y/n: "
if '%registry%' == 'n' goto servstart2
if /i "%registry%" equ "y" ( GOTO reg0start ) else ( GOTO servstart2 )

:reg0start
set /p reg0="Replace Utilman with CMD? (Backdoor for if Locked Out) y/n: "
if '%reg0%' == 'n' goto reg2start
if /i "%reg0%" neq "y" goto reg0start
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe" /v "Debugger" /t REG_SZ /d "cmd.exe" /f > NUL 2>&1

:reg2start
set /p reg2="Show Computer shortcut on Desktop? y/n: "
if '%reg2%' == 'n' goto reg3start
if /i "%reg2%" neq "y" goto reg2start
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /t REG_DWORD /d 0 /f > NUL 2>&1

:reg3start
set /p reg3="Show File Extensions? (.txt, .jpg, etc) y/n: "
if '%reg3%' == 'n' goto reg4start
if /i "%reg3%" neq "y" goto reg3start
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d 0 /f > NUL 2>&1

:reg4start
set /p reg4="Disable Windows Lockscreen? y/n: "
if '%reg4%' == 'n' goto reg5start
if /i "%reg4%" neq "y" goto reg4start
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v "NoLockScreen" /t REG_DWORD /d 1 /f > NUL 2>&1

:reg5start
set /p reg5="Enable Classic Control Panel view? y/n: "
if '%reg5%' == 'n' goto reg6start
if /i "%reg5%" neq "y" goto reg5start
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "ForceClassicControlPanel" /t REG_DWORD /d 1 /f > NUL 2>&1

:reg6start
set /p reg6="Hide indication for compressed NTFS files? y/n: "
if '%reg6%' == 'n' goto reg7start
if /i "%reg6%" neq "y" goto reg6start
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowCompColor" /t RED_DWORD /d 0 /f > NUL 2>&1

:reg7start
set /p reg7="Disable Windows Update sharing? y/n: "
if '%reg7%' == 'n' goto reg8start
if /i "%reg7%" neq "y" goto reg7start
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DownloadMode" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DODownloadMode" /t REG_DWORD /d 0 /f > NUL 2>&1

:reg8start
set /p reg8="Remove Pin to start? y/n: "
if '%reg8%' == 'n' goto reg9start
if /i "%reg8%" neq "y" goto reg8start
reg delete "HKEY_CLASSES_ROOT\exefile\shellex\ContextMenuHandlers\PintoStartScreen" /f > NUL 2>&1
reg delete "HKEY_CLASSES_ROOT\Folder\shellex\ContextMenuHandlers\PintoStartScreen" /f > NUL 2>&1
reg delete "HKEY_CLASSES_ROOT\mscfile\shellex\ContextMenuHandlers\PintoStartScreen" /f > NUL 2>&1

:reg9start
set /p reg9="Classic vertical icon spacing? y/n: "
if '%reg9%' == 'n' goto reg10start
if /i "%reg9%" neq "y" goto reg9start
reg add "HKCU\Control Panel\Desktop\WindowMetrics" /v "IconVerticalSpacing" /t REG_SZ /d "-1150" /f > NUL 2>&1

:reg10start
set /p reg10="Remove versioning tab from properties? y/n: "
if '%reg10%' == 'n' goto reg12start
if /i "%reg10%" neq "y" goto reg10start
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v NoPreviousVersionsPage /t REG_DWORD /d 1 /f > NUL 2>&1

:reg12start
set /p reg12="Remove telemetry and data collection? y/n: "
if '%reg12%' == 'n' goto reg13start
if /i "%reg12%" neq "y" goto reg12start
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /v PreventDeviceMetadataFromNetwork /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v DontOfferThroughWUAU /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableUAR" /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\COMPONENTS\DerivedData\Components\amd64_microsoft-windows-c..lemetry.lib.cortana_31bf3856ad364e35_10.0.10240.16384_none_40ba2ec3d03bceb0" /v "f!dss-winrt-telemetry.js" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\COMPONENTS\DerivedData\Components\amd64_microsoft-windows-c..lemetry.lib.cortana_31bf3856ad364e35_10.0.10240.16384_none_40ba2ec3d03bceb0" /v "f!proactive-telemetry.js" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\COMPONENTS\DerivedData\Components\amd64_microsoft-windows-c..lemetry.lib.cortana_31bf3856ad364e35_10.0.10240.16384_none_40ba2ec3d03bceb0" /v "f!proactive-telemetry-event_8ac43a41e5030538" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\COMPONENTS\DerivedData\Components\amd64_microsoft-windows-c..lemetry.lib.cortana_31bf3856ad364e35_10.0.10240.16384_none_40ba2ec3d03bceb0" /v "f!proactive-telemetry-inter_58073761d33f144b" /t REG_DWORD /d 0 /f > NUL 2>&1

:reg13start
set /p reg13="Apply Internet Explorer 11 tweaks? y/n: "
if '%reg13%' == 'n' goto reg14start
if /i "%reg13%" neq "y" goto reg13start
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "DoNotTrack" /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "Search Page" /t REG_SZ /d "http://www.google.es" /f > NUL 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "Start Page Redirect Cache" /t REG_SZ /d "http://www.google.es" /f > NUL 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "DisableFirstRunCustomize" /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "RunOnceHasShown" /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "RunOnceComplete" /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Main" /v "DisableFirstRunCustomize" /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Main" /v "RunOnceHasShown" /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Main" /v "RunOnceComplete" /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKCU\Software\Policies\Microsoft\Internet Explorer\Main" /v "DisableFirstRunCustomize" /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKCU\Software\Policies\Microsoft\Internet Explorer\Main" /v "RunOnceHasShown" /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKCU\Software\Policies\Microsoft\Internet Explorer\Main" /v "RunOnceComplete" /t REG_DWORD /d 1 /f > NUL 2>&1

:reg14start
set /p reg14="Disable Cortana, Bing Search and Searchbar? y/n: "
if '%reg14%' == 'n' goto reg15start
if /i "%reg14%" neq "y" goto reg14start
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CortanaEnabled" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d 0 /f > NUL 2>&1

:reg15start
set /p reg15="Change Logon screen background with accent color? y/n: "
if '%reg15%' == 'n' goto reg16start
if /i "%reg15%" neq "y" goto reg15start
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "DisableLogonBackgroundImage" /t REG_DWORD /d 1 /f > NUL 2>&1

:reg16start
set /p reg16="Disable Windows Error Reporting? y/n: "
if '%reg16%' == 'n' goto reg17start
if /i "%reg16%" neq "y" goto reg16start
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d 1 /f > NUL 2>&1

:reg17start
set /p reg17="Disable automatic Windows Updates? y/n: "
if '%reg17%' == 'n' goto reg18start
if /i "%reg17%" neq "y" goto reg17start
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v "AUOptions" /t REG_DWORD /d 2 /f > NUL 2>&1

:reg18start
set /p reg18="Disable Hibernation? y/n: "
if '%reg18%' == 'n' goto servstart
if /i "%reg18%" neq "y" goto reg18start
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t REG_DWORD /d 0 /f > NUL 2>&1
timeout /t 2 /NOBREAK >NUL
echo Registry Set 1 Done..
timeout /t 2 /NOBREAK >NUL
goto servstart2
:servstart2
cls
echo ==========================================================
echo ============ Tweaks for Services and Tasks ===============
echo ==========================================================
echo.
:servstart
set /p services="Apply 2nd Set of Registry tweaks for Running Services? y/n: "
if '%services%' == 'n' goto schedstart2
if /i "%services%" equ "y" ( GOTO serv0start ) else ( GOTO schedstart2 )

:serv0start
set /p serv0="Disable tracking services? y/n: "
if '%serv0%' == 'n' goto serv1start
if /i "%serv0%" neq "y" goto serv0start
sc config DiagTrack start= disabled > NUL 2>&1
sc config diagnosticshub.standardcollector.service start= disabled > NUL 2>&1
sc config TrkWks start= disabled > NUL 2>&1
sc config WMPNetworkSvc start= disabled > NUL 2>&1

:serv1start
set /p serv1="Disable WAP Push Message Routing Service? y/n: "
if '%serv1%' == 'n' goto serv2start
if /i "%serv1%" neq "y" goto serv1start
sc config dmwappushservice start= disabled > NUL 2>&1

:serv2start
set /p serv2="Disable Windows Search? y/n: "
if '%serv2%' == 'n' goto serv3start
if /i "%serv2%" neq "y" goto serv2start
sc config WSearch start= disabled > NUL 2>&1
del "C:\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb" /s > NUL 2>&1

:serv3start
set /p serv3="Disable Superfetch? y/n: "
if '%serv3%' == 'n' goto serv4start
if /i "%serv3%" neq "y" goto serv3start
sc config SysMain start= disabled > NUL 2>&1

:serv4start
set /p serv4="Disable Windows Defender? y/n: "
if '%serv4%' == 'n' goto schedstart
if /i "%serv4%" neq "y" goto serv4start
sc config WinDefend start= disabled > NUL 2>&1
sc config WdNisSvc start= disabled > NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d 1 /f > NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiVirus" /t REG_DWORD /d 1 /f > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Verification" /Disable > NUL 2>&1
del "C:\ProgramData\Microsoft\Windows Defender\Scans\mpcache*" /s > NUL 2>&1
ECHO Done...
timeout /t 2 /NOBREAK >NUL
goto schedstart2
:schedstart2
cls
echo ==========================================================
echo ================ Remove Scheduled Tasks ==================
echo ==========================================================
ECHO.
:schedstart
set /p schedules="Remove Scheduled Tasks? y/n: "
if '%schedules%' == 'n' goto winappstart2
if /i "%schedules%" equ "y" ( GOTO schedstart0 ) else ( GOTO winappstart2 )
:schedstart0
schtasks /Change /TN "Microsoft\Windows\AppID\SmartScreenSpecific" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\NetTrace\GatherNetworkInfo" /Disable > NUL 2>&1
schtasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable > NUL 2>&1
ECHO Done...
timeout /t 2 /NOBREAK >NUL
:winappstart2
cls
echo ==========================================================
echo ============== Remove Windows Default Apps ===============
echo ==========================================================
ECHO.
:winappstart
set /p winapps="Remove Windows Default Apps? y/n: "
if '%winapps%' == 'n' goto odrivestart2
if /i "%winapps%" equ "y" ( GOTO winappstart0 ) else ( GOTO odrivestart2 )
:winappstart0
powershell "Get-AppxPackage *3d* | Remove-AppxPackage" > NUL 2>&1
powershell "Get-AppxPackage *bing* | Remove-AppxPackage" > NUL 2>&1
powershell "Get-AppxPackage *zune* | Remove-AppxPackage" > NUL 2>&1
powershell "Get-AppxPackage *photo* | Remove-AppxPackage" > NUL 2>&1
powershell "Get-AppxPackage *communi* | Remove-AppxPackage" > NUL 2>&1
powershell "Get-AppxPackage *solit* | Remove-AppxPackage" > NUL 2>&1
powershell "Get-AppxPackage *phone* | Remove-AppxPackage" > NUL 2>&1
powershell "Get-AppxPackage *soundrec* | Remove-AppxPackage" > NUL 2>&1
powershell "Get-AppxPackage *camera* | Remove-AppxPackage" > NUL 2>&1
powershell "Get-AppxPackage *people* | Remove-AppxPackage" > NUL 2>&1
powershell "Get-AppxPackage *office* | Remove-AppxPackage" > NUL 2>&1
powershell "Get-AppxPackage *xbox* | Remove-AppxPackage" > NUL 2>&1
ECHO Done...
timeout /t 2 /NOBREAK >NUL
:odrivestart2
cls
echo ==========================================================
echo ============== Disable / Remove OneDrive =================
echo ==========================================================
ECHO.
:odrivestart
set /p onedrive="Disable OneDrive? y/n: "
if '%onedrive%' == 'n' goto hoststart2
if /i "%onedrive%" equ "y" ( GOTO odrivestart0 ) else ( GOTO hoststart2 )
:odrivestart0
reg add "HKLM\Software\Policies\Microsoft\Windows\OneDrive" /v DisableFileSyncNGSC /t REG_DWORD /d 1 /f > NUL 2>&1
ECHO Done...
timeout /t 2 /NOBREAK >NUL
:hoststart2
cls
echo ==========================================================
echo ============= Blocking Telemetry Servers =================
echo ==========================================================
ECHO.
:hoststart
set /p hostsblock="Blocking Telemetry Servers (Data Reporting) ? y/n: "
if '%hostsblock%' == 'n' goto EXIT
if /i "%hostsblock%" equ "y" ( GOTO hoststart0 ) else ( GOTO EXIT )
:hoststart0
copy "%WINDIR%\system32\drivers\etc\hosts" "%WINDIR%\system32\drivers\etc\hosts.bak" > NUL 2>&1
attrib -r "%WINDIR%\system32\drivers\etc\hosts" > NUL 2>&1
FIND /C /I "vortex.data.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 vortex.data.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "vortex-win.data.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 vortex-win.data.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "telecommand.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 telecommand.telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "telecommand.telemetry.microsoft.com.nsatc.net" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 telecommand.telemetry.microsoft.com.nsatc.net>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "oca.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 oca.telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "oca.telemetry.microsoft.com.nsatc.net" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 oca.telemetry.microsoft.com.nsatc.net>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "sqm.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 sqm.telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "sqm.telemetry.microsoft.com.nsatc.net" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 sqm.telemetry.microsoft.com.nsatc.net>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "watson.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 watson.telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "watson.telemetry.microsoft.com.nsatc.net" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 watson.telemetry.microsoft.com.nsatc.net>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "redir.metaservices.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 redir.metaservices.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "choice.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 choice.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "choice.microsoft.com.nsatc.net" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 choice.microsoft.com.nsatc.net>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "df.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 df.telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "reports.wes.df.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 reports.wes.df.telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "services.wes.df.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 services.wes.df.telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "sqm.df.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 sqm.df.telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "watson.ppe.telemetry.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 watson.ppe.telemetry.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "telemetry.appex.bing.net" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 telemetry.appex.bing.net>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "telemetry.urs.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 telemetry.urs.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "telemetry.appex.bing.net:443" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 telemetry.appex.bing.net:443>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "settings-sandbox.data.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 settings-sandbox.data.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
FIND /C /I "vortex-sandbox.data.microsoft.com" %WINDIR%\system32\drivers\etc\hosts
IF %ERRORLEVEL% NEQ 0 ECHO ^0.0.0.0 vortex-sandbox.data.microsoft.com>>%WINDIR%\system32\drivers\etc\hosts
attrib +r "%WINDIR%\system32\drivers\etc\hosts" > NUL 2>&1
cls
GOTO REGTWEAK
:EXIT
cls
echo.
echo.
echo.
echo.
echo.
echo   We recommend you restart your PC/Local Machine for all
echo    effects to take place.
echo.
echo                -Private-Locker Team
echo           https://www.private-locker.com 
timeout /t 3 /NOBREAK>NUL
exit /b