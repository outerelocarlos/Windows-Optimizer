##########
#
# Windows Optimizer - Preset Generator
#
# Original Author: Disassembler <disassembler@dasm.cz>
# Original Author Source: https://github.com/Disassembler0/Win10-Initial-Setup-Script (Version: v3.10, 2020-07-15)
# 
# Continued and improved by Carlos Outerelo <outerelocarlos@gmail.com>
# New Source: https://github.com/outerelocarlos/Windows-Optimizer
#
##########

### Folder Generation

$folder_main = 'Presets'
$folder_custom = 'Custom Presets'
<# $W10_folder = 'Windows 10 Presets'
$W10_folder_custom = 'Windows 10 Custom Presets'
$W11_folder = 'Windows 11 Presets (BETA)'
$W11_folder_custom = 'Windows 11 Custom Presets (BETA)' #>
$folder_tweaks = 'Tweaks'
$folder_tweaks_W11UI = $folder_tweaks + '\Windows 11 UI Tweaks'

if (!(Test-Path($folder_main))) {
	New-Item -Path $folder_main -ItemType Directory | Out-Null
}

if (!(Test-Path($folder_custom))) {
	New-Item -Path $folder_custom -ItemType Directory | Out-Null
}

<# if (!(Test-Path($W10_folder))) {
	New-Item -Path $W10_folder -ItemType Directory | Out-Null
}

if (!(Test-Path($W10_folder_custom))) {
	New-Item -Path $W10_folder_custom -ItemType Directory | Out-Null
}

if (!(Test-Path($W11_folder))) {
	New-Item -Path $W11_folder -ItemType Directory | Out-Null
}

if (!(Test-Path($W11_folder_custom))) {
	New-Item -Path $W11_folder_custom -ItemType Directory | Out-Null
} #>

if (!(Test-Path($folder_tweaks))) {
	New-Item -Path $folder_tweaks -ItemType Directory | Out-Null
}

if (!(Test-Path($folder_tweaks_W11UI))) {
	New-Item -Path $folder_tweaks_W11UI -ItemType Directory | Out-Null
}

### Blank Template Generation

(gc "Filegen.preset") | Out-File ($folder_main + "\Blank Template.preset") -Encoding utf8
# (gc "Filegen.preset") | Out-File ($W10_folder + "\Blank Template.preset") -Encoding utf8
# (gc "Filegen.preset") | Out-File ($W11_folder + "\Blank Template.preset") -Encoding utf8

$cmd = '@powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0..\Core.ps1" -include "%~dp0..\Functions.psm1" -include "%~dp0..\Functions_Upgrade.psm1" -preset "%~dpn0.preset" -log "%~dpn0.log"'
$cmd | Set-Content ($folder_main + "\Blank Template.cmd")
# $cmd | Set-Content ($W10_folder + "\Blank Template.cmd")
# $cmd | Set-Content ($W11_folder + "\Blank Template.cmd")

### Preset Generation Function

Function Generator {
	Param($preset, $selection, $folder)
	
	Write-Host Building the $preset preset in $folder ...

	$file1 = $folder + "\" + $preset + ".preset"
	$file2 = $folder + "\" + $preset + ".cmd"

	(gc "Filegen.preset") | Out-File $file1 -Encoding utf8
	$cmd | Set-Content $file2
	
	(gc $file1) -replace 'Blank Template', ($preset + ' Preset') | Out-File $file1 -Encoding utf8
	
	foreach ($item in $selection) {
		(gc $file1) -replace ("# " + $item), $item | Out-File $file1 -Encoding utf8
	}
	
	foreach ($item in $deprecated) {
		(gc $file1) -replace $item, '[Deprecated function]' | Out-File $file1 -Encoding utf8
	}
	
	foreach ($item in $windows_fault) {
		(gc $file1) -replace $item, '[This function is not working as intended due to a Windows bug]' | Out-File $file1 -Encoding utf8
	}
}

Function Tester_Basic {
	Param($preset, $folder)
	
	Write-Host Building the $preset in $folder ...

	$file1 = $folder + "\" + $preset + ".preset"
	$file2 = $folder + "\" + $preset + ".cmd"
	
	(gc "Filegen.preset") | Out-File $file1 -Encoding utf8
	$cmd | Set-Content $file2

	(gc $file1) -replace 'Blank Template', $preset | Out-File $file1 -Encoding utf8

	foreach ($item in $tester_setup) {
		(gc $file1) -replace $item | Out-File $file1 -Encoding utf8
	}
	
	foreach ($item in $issues) {
		(gc $file1) -replace $item | Out-File $file1 -Encoding utf8
	}
}

Function Tester_Full {
	Param($preset, $folder)

	Write-Host Building the $preset in $folder ...
	
	$file1 = $folder + "\" + $preset + ".preset"
	$file2 = $folder + "\" + $preset + ".cmd"
	
	(gc "Filegen.preset") | Out-File $file1 -Encoding utf8
	$cmd | Set-Content $file2

	(gc $file1) -replace 'Blank Template', $preset | Out-File $file1 -Encoding utf8

	foreach ($item in $tester_setup) {
		(gc $file1) -replace $item | Out-File $file1 -Encoding utf8
	}
}

### Function selection for each preset

$basic = @(
	'CreateRestorePoint'
	
	'DisableThirdPartyTelemetry'
	'DisableCortana'
	'DisableWiFiSense'
	'DisableWebSearch'
	'DisableAppSuggestions'
	'DisableTailoredExperiences'
	'DisableAdvertisingID'
	'DisableErrorReporting'
	'SetP2PUpdateLocal'
	'DisableAutoLogger'
	'DisableDiagTrack'
	
	'DisableUWPAccountInfo'
	'DisableUWPDiagInfo'
	
	'SetUACLow'
	'EnableDotNetStrongCrypto'
	'EnableF8BootMenu'
	'EnableBootRecovery'
	'EnableRecoveryAndReset'
	
	'IncreaseIRPStackSize'
	
	'DisableUpdateAutoDownload'
	'DisableUpdateRestart'
	'DisableMaintenanceWakeUp'
	'EnableRestorePoints'
	'DisableStorageSense'
	'EnableDefragmentation'
	'DisableSuperfetch'
	'EnableNTFSLongPaths'
	'DisableFastStartup'
	'OptimizeServiceHost'
	
	'DisableAccessibilityKeys'
	'ShowTaskManagerDetails'
	'ShowFileOperationsDetails'
	'HideTaskbarPeopleIcon'
	'HideMeetNowFromTaskbar'
	'DisableSearchAppInStore'
	'DisableNewAppPrompt'
	'EnableNumlock'
	'DisableEnhPointerPrecision'
	'EnableVerboseStatus'
	
	'ShowKnownExtensions'
	'HideSyncNotifications'
	'Hide3DObjectsFromThisPC'
	'Hide3DObjectsFromExplorer'
	'MenuShowDelay_20 '

	'HideChatFromTaskbar'
	'HideWidgetsFromTaskbar'
	
	'UninstallWorstThirdPartyBloat'
	
	'DisableFullscreenOptims'
	'DisableEdgeShortcutCreation'
	'InstallPDFPrinter'
)

$recommended = $basic + @(
	'ShutUpStandard '
	
	'DisableTelemetry'
	
	'EnableRemoteDesktop'
	
	'DisableAeroShake'
	'DisableNewsAndInterests'

	'SetClassicContextMenu'
	'EnableExplorerCompactView'
	
	'DisableOneDrive'
	'UninstallOneDrive'
	'UninstallWorstMsftBloat'
)

$advanced = $recommended + @(
	'DisableSmartScreen'
	
	'DisableDownloadBlocking'
	
	'DisableAutoplay'
	'DisableAutorun'
	'EnableHAGS'
	
	'HideTaskbarSearch'
	'ShowHiddenFiles'
	'EnableDoForAllCopyPaste'
	'ShowEncCompFilesColor'
	'DisableIEFirstRun'
	'EnableDeveloperMode'

	'EnableExplorerRibbonBar'
)

$outerelocarlos = @(
	'CreateRestorePoint'
	'ShutUpCustom '
	
	'DisableTelemetry'
	'DisableThirdPartyTelemetry'
	'DisableCortana'
	'DisableWiFiSense'
	'DisableSmartScreen'
	'DisableWebSearch'
	'DisableAppSuggestions'
	'DisableActivityHistory'
	'EnableLocation'
	'EnableFindMyDevice'
	'DisableTailoredExperiences'
	'DisableAdvertisingID'
	'DisableErrorReporting'
	'SetP2PUpdateLocal'
	'DisableAutoLogger'
	'DisableDiagTrack'
	'DisableClearRecentFiles'
	'DisableRecentFiles'

	'DisableUWPAccountInfo'
	'DisableUWPDiagInfo'

	'SetUACLow'
	'EnableSharingMappedDrives'
	'DisableDownloadBlocking'
	'EnableBootRecovery'
	'EnableRecoveryAndReset'

	'IncreaseIRPStackSize'
	'EnableRemoteDesktop'
	'DisableUpdateAutoDownload'
	'DisableUpdateRestart'
	'DisableMaintenanceWakeUp'
	'DisableAutoRestartLogin'
	'DisableAutoplay'
	'DisableAutorun'
	'EnableRestorePoints'
	'DisableStorageSense'
	'EnableDefragmentation'
	'DisableSuperfetch'
	'EnableNTFSLongPaths'
	'DisableHibernation'
	'DisableFastStartup'
	'EnableAutoRebootOnCrash'
	'OptimizeServiceHost'
	'EnableHAGS'

	'DisableAccessibilityKeys'
	'ShowTaskManagerDetails'
	'ShowFileOperationsDetails'
	'HideTaskbarSearch'
	'ShowTaskView'
	'SetTaskbarCombineWhenFull'
	'DisableNewsAndInterests'
	'HideMeetNowFromTaskbar'
	'HideTaskbarPeopleIcon'
	'ShowTrayIcons'
	'ShowSecondsInTaskbar'
	'DisableSearchAppInStore'
	'DisableNewAppPrompt'
	'HideMostUsedApps'
	'SetWinXMenuPowerShell'
	'SetControlPanelSmallIcons'
	'DisableShortcutInName'
	'HideShortcutArrow'
	'EnableNumlock'
	'DisableEnhPointerPrecision'
	'EnableVerboseStatus'

	'ShowKnownExtensions'
	'ShowHiddenFiles'
	'EnableDoForAllCopyPaste'
	'EnableRestoreFldrWindows'
	'ShowEncCompFilesColor'
	'HideSelectCheckboxes'
	'HideSyncNotifications'
	'HideRecentShortcuts'
	'SetExplorerThisPC'
	'Hide3DObjectsFromThisPC'
	'Hide3DObjectsFromExplorer'
	'MenuShowDelay_20 '

	'SetStartMenuLeft'
	'SetClassicContextMenu'
	'EnableExplorerCompactView'
	'EnableExplorerRibbonBar'
	'HideChatFromTaskbar'
	'HideWidgetsFromTaskbar'

	'DisableOneDrive'
	'UninstallOneDrive'
	'UninstallCustomMsftBloat'
	'UninstallCustomThirdPartyBloat'
	'DisableFullscreenOptims'
	'DisableEdgeShortcutCreation'
	'DisableIEFirstRun'
	'EnableDeveloperMode'
	'InstallLinuxSubsystem'
	'InstallPDFPrinter'
)

$basic_desktop = $basic + @(
	'DisableHibernation'
)

$basic_laptop = $basic + @(
	'EnableLocation'
	'EnableFindMyDevice'
)

$recommended_desktop = $recommended + @(
	'DisableHibernation'
)

$recommended_laptop = $recommended + @(
	'EnableLocation'
	'EnableFindMyDevice'
)

$advanced_desktop = $advanced + @(
	'DisableHibernation'
)

$advanced_laptop = $advanced + @(
	'EnableLocation'
	'EnableFindMyDevice'
)

### List of functions to be omitted due to different issues

$deprecated = @(
	'RemoveENKeyboard'
	'AddENKeyboard'
)

$windows_fault = @(
	'DisableSMB1'
	'EnableSMB1'
	'DisableRemoteAssistance'
	'EnableRemoteAssistance'
	'UninstallMediaPlayer'
	'InstallMediaPlayer'
	'UninstallInternetExplorer'
	'InstallInternetExplorer'
	'UninstallHelloFace'
	'InstallHelloFace'
	'UninstallMathRecognizer'
	'InstallMathRecognizer'
	'UninstallPowerShellISE'
	'InstallPowerShellISE'
	'UninstallSSHClient'
	'InstallSSHClient'
	'UninstallSSHServer'
	'InstallSSHServer'
	'UninstallNET23'
	'InstallNET23'
	'UninstallFaxAndScan'
	'InstallFaxAndScan'
	'HideNewsAndInterests'
	'ShowNewsAndInterestsIcon'
	'ShowNewsAndInterestsTextbox'
)

$issues = $deprecated + $windows_fault

### Preset Generation Process

Generator -preset "Level 1 - Basic (Desktop)" -selection $basic_desktop -folder $folder_main
Generator -preset "Level 2 - Recommended (Desktop)" -selection $recommended_desktop -folder $folder_main
Generator -preset "Level 3 - Advanced (Desktop)" -selection $advanced_desktop -folder $folder_main

Generator -preset "Level 1 - Basic (Laptop)" -selection $basic_laptop -folder $folder_main
Generator -preset "Level 2 - Recommended (Laptop)" -selection $recommended_laptop -folder $folder_main
Generator -preset "Level 3 - Advanced (Laptop)" -selection $advanced_laptop -folder $folder_main

Generator -preset "outerelocarlos" -selection $outerelocarlos -folder $folder_custom

### Building the Function Testers

$tester_setup = @(
	$('# ', ''),
	$('ShutUpStandard_', '# ShutUpStandard_'),
	$('ShutUpHardcore', '# ShutUpHardcore'),
	$('ShutUpCustom', '# ShutUpCustom')
)

Tester_Basic -preset "Level 1 Tester" -folder $folder_custom
Tester_Full -preset "Level 2 Tester" -folder $folder_custom

### Tweak Generation Process

$cmd_tweaks = '@powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0..\Core.ps1" -include "%~dp0..\Functions.psm1" -include "%~dp0..\Functions_Upgrade.psm1" -log "%~dpn0.log" '
Write-Host Building the premade tweaks...

($cmd_tweaks + 'UninstallWorstThirdPartyBloat WaitForY Restart') | Set-Content ($folder_tweaks + "\Bloatware Uninstaller (Level 1 - Crapware Removal).cmd")
($cmd_tweaks + 'UninstallWorstThirdPartyBloat UninstallWorstMsftBloat WaitForY Restart') | Set-Content ($folder_tweaks + "\Bloatware Uninstaller (Level 2 - Microbloat Removal).cmd")
($cmd_tweaks + 'UninstallWorstThirdPartyBloat UninstallBestThirdPartyBloat UninstallWorstMsftBloat UninstallBestMsftBloat DisableOneDrive UninstallOneDrive WaitForY Restart') | Set-Content ($folder_tweaks + "\Bloatware Uninstaller (Level 3 - Complete Removal).cmd")
($cmd_tweaks + 'DisableIndexing WaitForY Restart') | Set-Content ($folder_tweaks + "\Disable Indexing.cmd")
($cmd_tweaks + 'EnableIndexing WaitForY Restart') | Set-Content ($folder_tweaks + "\Enable Indexing.cmd")
($cmd_tweaks + 'DisableOneDrive UninstallOneDrive WaitForY Restart') | Set-Content ($folder_tweaks + "\Disable OneDrive.cmd")
($cmd_tweaks + 'EnableOneDrive InstallOneDrive WaitForY Restart') | Set-Content ($folder_tweaks + "\Enable OneDrive.cmd")
($cmd_tweaks + 'DisableSmartScreen SetUACLow DisableDownloadBlocking WaitForY Restart') | Set-Content ($folder_tweaks + "\Disable Security Prompts and Blocks.cmd")
($cmd_tweaks + 'EnableSmartScreen SetUACHigh EnableDownloadBlocking WaitForY Restart') | Set-Content ($folder_tweaks + "\Enable Security Prompts and Blocks.cmd")
($cmd_tweaks + 'DisableLogin WaitForY Restart') | Set-Content ($folder_tweaks + "\Disable Login.cmd")
($cmd_tweaks + 'EnableLogin WaitForY Restart') | Set-Content ($folder_tweaks + "\Enable Login.cmd")
($cmd_tweaks + 'DisableCortana DisableAppSuggestions DisableTailoredExperiences DisableAdvertisingID DisableErrorReporting DisableAutoLogger DisableDiagTrack WaitForY Restart') | Set-Content ($folder_tweaks + "\Disable Telemetry (Level 1 - Basic).cmd")
($cmd_tweaks + 'EnableCortana EnableAppSuggestions EnableTailoredExperiences EnableAdvertisingID EnableErrorReporting EnableAutoLogger EnableDiagTrack WaitForY Restart') | Set-Content ($folder_tweaks + "\Enable Telemetry (Level 1 - Basic).cmd")
($cmd_tweaks + 'ShutUpStandard DisableTelemetry DisableThirdPartyTelemetry DisableCortana DisableAppSuggestions DisableTailoredExperiences DisableAdvertisingID DisableErrorReporting DisableAutoLogger DisableDiagTrack WaitForY Restart') | Set-Content ($folder_tweaks + "\Disable Telemetry (Level 2 - Recommended).cmd")
($cmd_tweaks + 'ShutUpStandard_Reverse EnableTelemetry EnableThirdPartyTelemetry EnableCortana EnableAppSuggestions EnableTailoredExperiences EnableAdvertisingID EnableErrorReporting EnableAutoLogger EnableDiagTrack WaitForY Restart') | Set-Content ($folder_tweaks + "\Enable Telemetry (Level 2 - Recommended).cmd")
($cmd_tweaks + 'ShutUpHardcore DisableTelemetry DisableThirdPartyTelemetry DisableCortana DisableAppSuggestions DisableTailoredExperiences DisableAdvertisingID DisableErrorReporting DisableAutoLogger DisableDiagTrack WaitForY Restart') | Set-Content ($folder_tweaks + "\Disable Telemetry (Level 3 - Harcore).cmd")
($cmd_tweaks + 'ShutUpHardcore_Reverse EnableTelemetry EnableThirdPartyTelemetry EnableCortana EnableAppSuggestions EnableTailoredExperiences EnableAdvertisingID EnableErrorReporting EnableAutoLogger EnableDiagTrack WaitForY Restart') | Set-Content ($folder_tweaks + "\Enable Telemetry (Level 3 - Hardcore).cmd")
($cmd_tweaks + 'DisableW11_TPMRequirement WaitForY Restart') | Set-Content ($folder_tweaks + "\Disable Windows 11 TPM Requirement.cmd")
($cmd_tweaks + 'EnableW11_TPMRequirement WaitForY Restart') | Set-Content ($folder_tweaks + "\Enable Windows 11 TPM Requirement.cmd")
($cmd_tweaks + '"sfc /scannow" WaitForY Restart') | Set-Content ($folder_tweaks + "\Repair Windows.cmd")
($cmd_tweaks + 'RestoreMissingPowerPlans WaitForY Restart') | Set-Content ($folder_tweaks + "\Restore Missing Power Plans.cmd")

$cmd_tweaks_W11UI = '@powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0..\..\Core.ps1" -include "%~dp0..\..\Functions.psm1" -include "%~dp0..\..\Functions_Upgrade.psm1" -log "%~dpn0.log" '

($cmd_tweaks_W11UI + 'DisableExplorerCompactView WaitForY Restart') | Set-Content ($folder_tweaks_W11UI + "\Disable Explorer Compact View.cmd")
($cmd_tweaks_W11UI + 'EnableExplorerCompactView WaitForY Restart') | Set-Content ($folder_tweaks_W11UI + "\Enable Explorer Compact View.cmd")
($cmd_tweaks_W11UI + 'DisableExplorerRibbonBar WaitForY Restart') | Set-Content ($folder_tweaks_W11UI + "\Disable Explorer Ribbon Bar.cmd")
($cmd_tweaks_W11UI + 'EnableExplorerRibbonBar WaitForY Restart') | Set-Content ($folder_tweaks_W11UI + "\Enable Explorer Ribbon Bar.cmd")
($cmd_tweaks_W11UI + 'SetClassicContextMenu WaitForY Restart') | Set-Content ($folder_tweaks_W11UI + "\Set Classic Context Menu.cmd")
($cmd_tweaks_W11UI + 'SetModernContextMenu WaitForY Restart') | Set-Content ($folder_tweaks_W11UI + "\Set Modern Context Menu.cmd")
($cmd_tweaks_W11UI + 'SetStartMenuCenter WaitForY Restart') | Set-Content ($folder_tweaks_W11UI + "\Set Start Menu Center.cmd")
($cmd_tweaks_W11UI + 'SetStartMenuLeft WaitForY Restart') | Set-Content ($folder_tweaks_W11UI + "\Set Start Menu Left.cmd")

($cmd_tweaks_W11UI + 'EnableExplorerCompactView EnableExplorerRibbonBar SetClassicContextMenu SetStartMenuLeft WaitForY Restart') | Set-Content ($folder_tweaks_W11UI + "\Set Windows 10 Style.cmd")
($cmd_tweaks_W11UI + 'DisableExplorerCompactView DisableExplorerRibbonBar SetModernContextMenu SetStartMenuCenter WaitForY Restart') | Set-Content ($folder_tweaks_W11UI + "\Set Windows 11 Style.cmd")