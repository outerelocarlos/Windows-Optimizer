@powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0..\Core.ps1" -include "%~dp0..\Functions.psm1" -include "%~dp0..\Functions_Upgrade.psm1" -log "%~dpn0.log" ShutUpHardcore_Reverse EnableTelemetry EnableThirdPartyTelemetry EnableCortana EnableAppSuggestions EnableTailoredExperiences EnableAdvertisingID EnableErrorReporting EnableAutoLogger EnableDiagTrack WaitForY Restart
