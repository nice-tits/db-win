###########################################
# Get the base URI path from the ScriptToCall value
$bstrappackage = "-bootstrapPackage"
$helperUri = $Boxstarter['ScriptToCall']
$strpos = $helperUri.IndexOf($bstrappackage)
$helperUri = $helperUri.Substring($strpos + $bstrappackage.Length)
$helperUri = $helperUri.TrimStart("'", " ")
$helperUri = $helperUri.TrimEnd("'", " ")
$helperUri = $helperUri.Substring(0, $helperUri.LastIndexOf("/"))
$helperUri += "/scripts"
write-host "helper script base URI is $helperUri"

function executeScript {
    Param ([string]$script)
    write-host "executing $helperUri/$script ..."
	iex ((new-object net.webclient).DownloadString("$helperUri/$script"))
}

#--- Setting up Windows ---
executeScript "SystemConfiguration.ps1";
executeScript "FileExplorerSettings.ps1";
executeScript "RemoveDefaultApps.ps1";
executeScript "CommonDevTools.ps1";
###########################################################################






#
write-color "setting execution policy to bypass" -color green
Set-ExecutionPolicy Bypass -Force
 

# Install boxstarter:
write-color "getting boxstarter from web" -color magenta

 	. { iwr -useb http://boxstarter.org/bootstrapper.ps1 } | iex; get-boxstarter -Force


# Boxstarter and choco stuff
write-color "setting boxstarter and choco options" -color green
$Boxstarter.RebootOk = $false# Allow reboots?
$Boxstarter.NoPassword = $false # Is this a machine with no login password?
$Boxstarter.AutoLogin = $true # Save my password securely and auto-login after a reboot
$ConfirmPreference = "None" #ensure installing powershell modules don't prompt on needed dependencies
Update-ExecutionPolicy Bypass -Force
disable-MicrosoftUpdate
disable-UAC
choco --acceptlicense
choco feature enable -y allowGlobalConfirmation 
choco feature enable useRememberedArgumentsForUpgrades

#--- Enable developer mode on the system ---
Set-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\AppModelUnlock -Name AllowDevelopmentWithoutDevLicense -Value 1

# Need this to download via Invoke-WebRequest
[net.servicepointmanager]::securityprotocol = [system.security.authentication.sslprotocols] "tls, tls11, tls12"


#--- powershell core ---
choco install powershell-core -y

# Trust the psgallery for installs
write-color 'Setting PSGallery as a trusted installation source...' -color magenta
Set-PSRepository -Name PSGallery -InstallationPolicy Trusted

# Need to set Nuget as a provider before installing modules via PowerShellGet
Install-PackageProvider -Name NuGet -Force

# Powershell Modulee
powershell Import-Module Boxstarter.Chocolatey
powershell Install-Module PackageManagement -Force -AllowClobber - ErrorAction:SilentlyContinue
powershell Install-Module PowerShellGet -Force -AllowClobber -ErrorAction:SilentlyContinue
powershell Install-Module PSScriptAnalyzer -Force -AllowClobber -ErrorAction:SilentlyContinue
powershell Install-Module PSDecode -Force -AllowClobber -ErrorAction:SilentlyContinue
powershell Install-Module Configuration -Force -AllowClobber -ErrorAction:SilentlyContinue
powershell Install-Module SharePointPnPPowerShellOnline -Force -AllowClobber -ErrorAction:SilentlyContinue
powershell Install-Module WindowsCompatibility -Force -AllowClobber -ErrorAction:SilentlyContinue
powershell Install-Module PowerShellProTools -Force -AllowClobber -ErrorAction:SilentlyContinue
powershell Install-Module PSWriteColor -Force -AllowClobber -ErrorAction:SilentlyContinue
powershell Install-Module WslInterop -Force -AllowClobber -ErrorAction:SilentlyContinue


#--- Windows Subsystems/Features ---
choco install  Microsoft-Hyper-V-All -source WindowsFeatures -y
choco install  VirtualMachinePlatform -source WindowsFeatures -y
choco install  Microsoft-Windows-Subsystem-Linux -source WindowsFeatures -y
choco install  HypervisorPlatform -source WindowsFeatures -y
choco install  Containers-DisposableClientVM -source WindowsFeatures -y
choco install  NetFx3 -all -source WindowsFeatures -y


#--- Tools ---
choco upgrade sysinternals -y
choco install oh-my-posh -y

#--- VSCode ---
choco upgrade -y vscode-insiders -y
choco install vscode-prettier -y
choco install vscode-arduino -y
choco install chocolatey-vscode -y
choco install chocolatey-vscode.extension -y
choco install onedarkpro-vscode -y
choco install vscode-powershell -y

refreshenv

#--- Browsers ---
choco upgrade opera -y
choco install rainmeter -y
choco install googlechrome -y

#--- Apps ---
choco install everything -y
choco install adobereader -y
choco install lockhunter -y
choco install winaero-tweaker.portable -y
choco install rufus.portable -y
choco install everything.portable -y

choco install 7zip-zstd -y
choco install iobit-uninstaller -y
choco install bleachbit.portable -y
choco install peazip -y
choco install godmode -y
choco install nugetpackageexplorer -y

#################################################
## some other shit ##
######################################


# Remove AutoLogger file and restrict directory
Function DisableAutoLogger {
    Write-Host "Removing AutoLogger file and restricting directory..."
    $autoLoggerDir = "$env:PROGRAMDATA\Microsoft\Diagnosis\ETLLogs\AutoLogger"
    If (Test-Path "$autoLoggerDir\AutoLogger-Diagtrack-Listener.etl") {
        Remove-Item -Path "$autoLoggerDir\AutoLogger-Diagtrack-Listener.etl"
    }
    icacls $autoLoggerDir /deny SYSTEM:`(OI`)`(CI`)F | Out-Null
}

# Stop and disable Diagnostics Tracking Service
Function DisableDiagTrack {
    Write-Host "Stopping and disabling Diagnostics Tracking Service..."
    Stop-Service "DiagTrack" -WarningAction SilentlyContinue
    Set-Service "DiagTrack" -StartupType Disabled
}

# Stop and disable WAP Push Service
Function DisableWAPPush {
    Write-Host "Stopping and disabling WAP Push Service..."
    Stop-Service "dmwappushservice" -WarningAction SilentlyContinue
    Set-Service "dmwappushservice" -StartupType Disabled
}

##########
# Service Tweaks
##########

# Disable Wi-Fi Sense
Function DisableWiFiSense {
    Write-Host "Disabling Wi-Fi Sense..."
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "Value" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "Value" -Type DWord -Value 0
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "AutoConnectAllowedOEM" -Type Dword -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "WiFISenseAllowed" -Type Dword -Value 0
}

# Disable Web Search in Start Menu
Function DisableWebSearch {
    Write-Host "Disabling Bing Search in Start Menu..."
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Type DWord -Value 0
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -Type DWord -Value 1
}
Write-Host "trying to disable web search in start menu"
# Disable implicit administrative shares
Function DisableAdminShares {
    Write-Host "Disabling implicit administrative shares..."
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "AutoShareWks" -Type DWord -Value 0
}

# Disable obsolete SMB 1.0 protocol - Disabled by default since 1709
Function DisableSMB1 {
    Write-Host "Disabling SMB 1.0 protocol..."
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
}

# Disable automatic installation of network devices
Function DisableNetDevicesAutoInst {
    Write-Host "Disabling automatic installation of network devices..."
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -Name "AutoSetup" -Type DWord -Value 0
}


# Disable Controlled Folder Access (Defender Exploit Guard feature) - Not applicable to Server
Function DisableCtrldFolderAccess {
    Write-Host "Disabling Controlled Folder Access..."
    Set-MpPreference -EnableControlledFolderAccess Disabled
}

# Disable Windows Update automatic restart
Function DisableUpdateRestart {
    Write-Host "Disabling Windows Update automatic restart..."
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU")) {
	New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Force | Out-Null }
}
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoRebootWithLoggedOnUsers" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUPowerManagement" -Type DWord -Value 0

# Disable Shared Experiences - Not applicable to Server
Function DisableSharedExperiences {
    Write-Host "Disabling Shared Experiences..."
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CDP" -Name "RomeSdkChannelUserAuthzPolicy" -Type DWord -Value 0
}

# Disable Remote Assistance - Not applicable to Server (unless Remote Assistance is explicitly installed)
Function DisableRemoteAssistance {
    Write-Host "Disabling Remote Assistance..."
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWord -Value 0
}

# Disable Autoplay
Function DisableAutoplay {
    Write-Host "Disabling Autoplay..."
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Type DWord -Value 1
}

# Disable Autorun for all drives
Function DisableAutorun {
    Write-Host "Disabling Autorun for all drives..."
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Type DWord -Value 255
}
# Disable Advertising ID
Function DisableAdvertisingID {
    Write-Host "Disabling Advertising ID..."
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Type DWord -Value 0
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" -Name "TailoredExperiencesWithDiagnosticDataEnabled" -Type DWord -Value 0
}
Write-Host "trying to disable ad id"
# Disable Cortana
Function DisableCortana {
    Write-Host "Disabling Cortana..."
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Type DWord -Value 0
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value 1
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value 1
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Type DWord -Value 0
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Type DWord -Value 0
}
Write-Host "trying to disable cortana"
# Disable Error reporting
Function DisableErrorReporting {
    Write-Host "Disabling Error reporting..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type DWord -Value 1
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Windows Error Reporting\QueueReporting" | Out-Null
}

###############################################################################
## UI ##
###############################

# Disable Action Center
Function DisableActionCenter {
    Write-Host "Disabling Action Center..."
    If (!(Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer")) {
        New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer" | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "DisableNotificationCenter" -Type DWord -Value 1
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "ToastEnabled" -Type DWord -Value 0
}

# Disable Sticky keys prompt
Function DisableStickyKeys {
    Write-Host "Disabling Sticky keys prompt..."
    Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Type String -Value "506"
}

# Show Task Manager details
Function ShowTaskManagerDetails {
    Write-Host "Showing task manager details..."
    If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager")) {
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Force | Out-Null
    }
    $preferences = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -ErrorAction SilentlyContinue
    If (!($preferences)) {
        $taskmgr = Start-Process -WindowStyle Hidden -FilePath taskmgr.exe -PassThru
        While (!($preferences)) {
            Start-Sleep -m 250
            $preferences = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -ErrorAction SilentlyContinue
        }
        Stop-Process $taskmgr
    }
    $preferences.Preferences[28] = 0
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -Type Binary -Value $preferences.Preferences
}

# Show file operations details
Function ShowFileOperationsDetails {
    Write-Host "Showing file operations details..."
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" -Name "EnthusiastMode" -Type DWord -Value 1
}


# Hide Task View button
Function HideTaskView {
    Write-Host "Hiding Task View button..."
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 0
}

# Show small icons in taskbar
Function ShowSmallTaskbarIcons {
    Write-Host "Showing small icons in taskbar..."
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarSmallIcons" -Type DWord -Value 1
}

# Hide titles in taskbar
Function HideTaskbarTitles {
    Write-Host "Hiding titles in taskbar..."
    Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarGlomLevel" -ErrorAction SilentlyContinue
}

# Hide Taskbar People icon
Function HideTaskbarPeopleIcon {
    Write-Host "Hiding People icon..."
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -Type DWord -Value 0
}

# Set Control Panel view to icons (Classic) - Note: May trigger antimalware
Function SetControlPanelViewIcons {
    Write-Host "Setting Control Panel view to icons..."
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "ForceClassicControlPanel" -Type DWord -Value 1
}
# Show known file extensions
Function ShowKnownExtensions {
    Write-Host "Showing known file extensions..."
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 0
}

# Show hidden files
Function ShowHiddenFiles {
    Write-Host "Showing hidden files..."
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Type DWord -Value 1
}

# Hide sync provider notifications
Function HideSyncNotifications {
    Write-Host "Hiding sync provider notifications..."
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSyncProviderNotifications" -Type DWord -Value 0
}

# Disable display and sleep mode timeouts
Function DisableSleepTimeout {
    Write-Host "Disabling display and sleep mode timeouts..."
    powercfg /X monitor-timeout-ac 0
    powercfg /X monitor-timeout-dc 0
    powercfg /X standby-timeout-ac 0
    powercfg /X standby-timeout-dc 0
}


# Adjusts visual effects for performance - Disables animations, transparency etc. but leaves font smoothing and miniatures enabled
Function SetVisualFXPerformance {
    Write-Host "Adjusting visual effects for performance..."
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "DragFullWindows" -Type String -Value 0
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "MenuShowDelay" -Type String -Value 0
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "UserPreferencesMask" -Type Binary -Value ([byte[]](0x90, 0x12, 0x03, 0x80, 0x10, 0x00, 0x00, 0x00))
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name "MinAnimate" -Type String -Value 0
    Set-ItemProperty -Path "HKCU:\Control Panel\Keyboard" -Name "KeyboardDelay" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewAlphaSelect" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewShadow" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAnimations" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Type DWord -Value 3
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM" -Name "EnableAeroPeek" -Type DWord -Value 0
}

# Hide recently and frequently used item shortcuts in Explorer
Function HideRecentShortcuts {
    Write-Host "Hiding recent shortcuts..."
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowRecent" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowFrequent" -Type DWord -Value 0
}

# Change default Explorer view to This PC
Function SetExplorerThisPC {
    Write-Host "Changing default Explorer view to This PC..."
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Type DWord -Value 1
}

# Hide 3D Objects icon from This PC - The icon remains in personal folders and open/save dialogs
Function Hide3DObjectsFromThisPC {
    Write-Host "Hiding 3D Objects icon from This PC..."
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -Recurse -ErrorAction SilentlyContinue
}

# Hide 3D Objects icon from Explorer namespace - Hides the icon also from personal folders and open/save dialogs
Function Hide3DObjectsFromExplorer {
    Write-Host "Hiding 3D Objects icon from Explorer namespace..."
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"
    If (!(Test-Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag")) {
        New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"
}

# Dark Theme for Windows
If (-Not (Test-Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize)) {
	New-Item -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes -Name Personalize | Out-Null
}
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize -Name AppsUseLightTheme -Type DWord -Value 0


##################################################################################

# Privacy settings

Write-Output "Applying Privacy settings..."

# Disable search for app in store for unknown extensions
 Write-Host "Disabling search for app in store for unknown extensions..."
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoUseStoreOpenWith" -Type DWord -Value 1
# Send info about how I write: Disable
Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Input\TIPC -Name Enabled -Type DWord -Value 0
# Send contacts to MS: Disable
Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore -Name HarvestContacts -Type DWord -Value 0
# Handwriting recognition personalization: Disable
Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\InputPersonalization -Name RestrictImplicitInkCollection -Type DWord -Value 1
Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\InputPersonalization -Name RestrictImplicitTextCollection -Type DWord -Value 1
# Let apps use my advertising ID: Disable
If (-Not (Test-Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo)) {
    New-Item -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo | Out-Null
}
Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo -Name Enabled -Type DWord -Value 0
# SmartScreen Filter for Store Apps: Disable
Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost -Name EnableWebContentEvaluation -Type DWord -Value 0

# WiFi Sense: HotSpot Sharing: Disable
If (-Not (Test-Path HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting)) {
    New-Item -Path HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting | Out-Null
}
Set-ItemProperty -Path HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting -Name value -Type DWord -Value 0
# WiFi Sense: Shared HotSpot Auto-Connect: Disable
Set-ItemProperty -Path HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots -Name value -Type DWord -Value 0


# Disable Telemetry (requires a reboot to take effect)
Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection -Name AllowTelemetry -Type DWord -Value 0
Get-Service DiagTrack,Dmwappushservice | Stop-Service | Set-Service -StartupType Disabled

# Activity Tracking: Disable
@("EnableActivityFeed", "PublishUserActivities", "UploadUserActivities") |% {
  Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\System -Name $_ -Type DWord -Value 0
}

# Start Menu: Disable Bing Search Results
Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search -Name BingSearchEnabled -Type DWord -Value 0
# Start Menu: Disable Cortana
If (-Not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
  New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name AllowCortana -Type DWord -Value 0

# Disable unwanted services
$services = @(
  # Diagnostics services
  "diagnosticshub.standardcollector.service"
  "DiagTrack"
  # HomeGroup
  "HomeGroupListener"
  "HomeGroupProvider"
  # Geolocation
  "lfsvc"
  # Downloaded maps manager
  "MapsBroker"
  # Routing and remote access
  "RemoteAccess"
  "RemoteRegistry"

  # Interet Connection Sharing (ICS)
  "SharedAccess"
  # Distributed Link Tracking Client
  "TrkWks"
  # Windows Media Player network sharing
  "WMPNetworkSvc"
  # Xbox Live
  "XblAuthManager"
  "XblGameSave"
  "XboxNetApiSvc"
)

foreach ($service in $services) {
  Get-Service -Name $service | Set-Service -StartupType Disabled
}



Write-Output "Privacy settings have been applied."





# Windows Update settings

Write-Output "Applying Windows Update settings..."

# Notify to schedule restart
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings -Name UxOption -Type DWord -Value 1
# Disable P2P Update downlods outside of local network
If (-Not (Test-Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization)) {
  New-Item -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization | Out-Null
  New-Item -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config | Out-Null
}
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config -Name DODownloadMode -Type DWord -Value 1
If (-Not (Test-Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization)) {
  New-Item -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization | Out-Null
}
Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization -Name SystemSettingsDownloadMode -Type DWord -Value 3

Write-Output "Windows Update settings have been changed."


#--- Uninstall unecessary applications that come with Windows out of the box ---
 Write-Host "Uninstalling default Microsoft applications..."
# Alarms
Write-Host "trying to remove alarms"
    Get-AppxPackage Microsoft.WindowsAlarms | Remove-AppxPackage
# Feedback Hub
Write-Host "trying to remove feedback hub"
    Get-AppxPackage Microsoft.WindowsFeedbackHub | Remove-AppxPackage
# Comms Phone
Write-Host "trying to remove comms phone"
    Get-AppxPackage Microsoft.CommsPhone | Remove-AppxPackage
# Get Started
Write-Host "trying to remove get started"
    Get-AppxPackage Microsoft.Getstarted | Remove-AppxPackage
# Mail & Calendar
Write-Host "trying to remove mail and calander"
    Get-AppxPackage microsoft.windowscommunicationsapps | Remove-AppxPackage
# Maps
Write-Host "trying to remove maps"
    Get-AppxPackage Microsoft.WindowsMaps | Remove-AppxPackage
# Messaging
Write-Host "trying to remove messaging"
    Get-AppxPackage Microsoft.Messaging | Remove-AppxPackage
# Office Hub
Write-Host "trying to remove officehub"
    Get-AppxPackage Microsoft.MicrosoftOfficeHub | Remove-AppxPackage
# One Connect
Write-Host "trying to remove one connect"
    Get-AppxPackage Microsoft.OneConnect | Remove-AppxPackage
# OneNote
Write-Host "trying to remove onenote"
    Get-AppxPackage Microsoft.Office.OneNote | Remove-AppxPackage
# People
Write-Host "trying to remove people"
    Get-AppxPackage Microsoft.People | Remove-AppxPackage
# Phone
Write-Host "trying to remove phone"
    Get-AppxPackage Microsoft.WindowsPhone | Remove-AppxPackage
# Photos
Write-Host "trying to remove photos"
    Get-AppxPackage Microsoft.Windows.Photos | Remove-AppxPackage
# Solitaire
Write-Host "trying to remove solitaire"
    Get-AppxPackage *Solitaire* | Remove-AppxPackage
# Sticky Notes
Write-Host "trying to remove sticky notes"
    Get-AppxPackage Microsoft.MicrosoftStickyNotes | Remove-AppxPackage
# Sway
Write-Host "trying to remove sway"
    Get-AppxPackage Microsoft.Office.Sway | Remove-AppxPackage
# Twitter
Write-Host "trying to remove twitter"
    Get-AppxPackage *Twitter* | Remove-AppxPackage
# Zune Music, Movies & TV
Write-Host "trying to remove zune shit"
    Get-AppxPackage Microsoft.ZuneMusic | Remove-AppxPackage
    Get-AppxPackage Microsoft.ZuneVideo | Remove-AppxPackage
# Skype (Metro version)
Write-Host "trying to remove skype"
    Get-AppxPackage Microsoft.SkypeApp | Remove-AppxPackage
# Sound Recorder
Write-Host "trying to remove sound recorder"
    Get-AppxPackage Microsoft.WindowsSoundRecorder | Remove-AppxPackage
# Facebook
Write-Host "trying to remove facebook"
    Get-AppxPackage *Facebook* | Remove-AppxPackage
# Bing Weather, News, Sports, and Finance (Money):
Write-Host "trying to remove bing shit"
    Get-AppxPackage Microsoft.BingNews | Remove-AppxPackage
    Get-AppxPackage Microsoft.BingSports | Remove-AppxPackage
    Get-AppxPackage Microsoft.BingWeather | Remove-AppxPackage
    Get-AppxPackage Microsoft.BingFinance | Remove-AppxPackage


# Disable Xbox features
    Write-Host "Disabling Xbox features..."
    Get-AppxPackage "Microsoft.XboxApp" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.XboxIdentityProvider" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.XboxSpeechToTextOverlay" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.XboxGameOverlay" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.Xbox.TCUI" | Remove-AppxPackage
    Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Type DWord -Value 0
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Type DWord -Value 0

Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -Name "AllowDevelopmentWithoutDevLicense" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -Name "AllowAllTrustedApps" -Type DWord -Value 1
   
   
   # Remove default printers
    Remove-Printer -Name "Microsoft XPS Document Writer" -ErrorAction:SilentlyContinue
    Remove-Printer -Name "Microsoft Print to PDF" -ErrorAction:SilentlyContinue
    Remove-Printer -Name "Fax" -ErrorAction:SilentlyContinue
    
    

# Prevent applications from re-installing
$cdm = @(
  "ContentDeliveryAllowed"
  "FeatureManagementEnabled"
  "OemPreInstalledAppsEnabled"
  "PreInstalledAppsEnabled"
  "PreInstalledAppsEverEnabled"
  "SilentInstalledAppsEnabled"
  "SubscribedContent-314559Enabled"
  "SubscribedContent-338387Enabled"
  "SubscribedContent-338388Enabled"
  "SubscribedContent-338389Enabled"
  "SubscribedContent-338393Enabled"
  "SubscribedContentEnabled"
  "SystemPaneSuggestionsEnabled"
)

foreach ($key in $cdm) {
  Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name $key -Type DWord -Value 0
}

If (-Not (Test-Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent)) {
  New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent | Out-Null
}
Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent -Name DisableWindowsConsumerFeatures -Type DWord -Value 1

######################################################    
write-host " setting time zone to Mountain Standard
#--- Set TimeZone ---
Set-TimeZone -Id "Mountain Standard Time" -PassThru

##################################################
write-host "Changing Computer Name"

# Rename the computer (requires restart)
 $name = "TiTTiEs"
 
 Rename-Computer -NewName "$name" -Force -PassThru

Write-Output "Computer has been renamed to $name.""

#########################################################
## WSL2 ##
#########################################################
choco install -y Microsoft-Windows-Subsystem-Linux --source="'windowsfeatures'"
# update
wsl --update  
  
#--- Arch ---

# run the distro once and have it install locally with root user, unset password

RefreshEnv



wsl --set-default-version 2
wsl --set-default, -s arch
arch run pacman -Syu
arch run pacman-key --init
arch run pacman-key --populate archlinux
ach run touch /etc/wsl.conf
arch run echo "[boot] systemd = true" >> /etc/wsl.conf
arch run echo "[automount] enabled = true" >> /etc/wsl.conf

  #Inside_wsl2_commands
```sh
sudo start-systemd
export LIBGL_ALWAYS_INDIRECT=Yes
export DISPLAY=$(netsh.exe interface ip show address "vEthernet (WSL)" | awk '/IP[^:]+:/ {print $2}' | tr -d '\r'):0
```
############################################################  
  
  
  
  
#--- Restore Temporary Settings ---
Enable-MicrosoftUpdate
Install-WindowsUpdate -acceptEula