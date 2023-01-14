$LogFile = "$($PSScriptRoot)\Logs\VulnerabilityLog.txt"
function Write-ToVulnerabilityLog {
    param ([string]$LogFileContent)
    if (!(Test-Path -Path "$($PSScriptRoot)\Logs\VulnerabilityLog.txt")){
        New-Item -ItemType File -Path "$($PSScriptRoot)\Logs" -Name "VulnerabilityLog.txt" | Out-Null
    }
    Add-Content $LogFile -Value $LogFileContent
}

function Add-RegistryKeys {
    #Stig item ID V-73669, turning AutoPlay off for non-volume devices
    #High
    if ((Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows")){
        New-Item -Name "Explorer" -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows" -Force
        New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoAutoplayfornonVolume" -PropertyType DWORD -Value 1 -Force
        Write-ToVulnerabilityLog "  Registry Key applied: HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\NoAutoplayfornonVolume"
    }

    #Stig item V-73547
    #High
    if (!(Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer")){
        New-Item -Name "Explorer" -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies" -Force
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutorun" -PropertyType DWORD -Value 1 -Force
        Write-ToVulnerabilityLog "  Registry Key applied: HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoAutorun"
    }else {
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutorun" -PropertyType DWORD -Value 1 -Force
        Write-ToVulnerabilityLog "  Registry Key applied: HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoAutorun"
    }

    #Stig item V-73549
    #High
    if (!(Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer")){
        New-Item -Name "Explorer" -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies" -Force
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -PropertyType DWORD -Value 255 -Force
        Write-ToVulnerabilityLog "  Registry Key applied: HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDriveTypeAutoRun"
    }else {
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -PropertyType DWORD -Value 255 -Force
        Write-ToVulnerabilityLog "  Registry Key applied: HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDriveTypeAutoRun"
    }
    #Stig item V-73585, forcing UAC to elevate permissions when running installers
    #High
    if (!(Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer")){
        New-Item -Name "Installer" -Path "HKLM:\Software\Policies\Microsoft\Windows" -Force
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -PropertyType DWORD -Value 0 -Force
        Write-ToVulnerabilityLog "  Registry Key applied: HKLM:\Software\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated"
    }else {
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -PropertyType DWORD -Value 0 -Force
        Write-ToVulnerabilityLog "  Registry Key applied: HKLM:\Software\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated"
    }

    #Stig item V-73599, preventing WinRM from using basic authentication for the service
    #High
    if ((Test-Path -Path "HKLM:\Software\Policies\Microsoft\Windows")){
        New-Item -Name "WinRM" -Path "HKLM:\Software\Policies\Microsoft\Windows"
        New-Item -Name "Service" -Path "HKLM:\Software\Policies\Microsoft\Windows\WinRM"
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service" -Name "AllowBasic" -PropertyType DWORD -Value 0 -Force
        Write-ToVulnerabilityLog "  Registry Key applied: HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service\AllowBasic"
    }

    #Stig item V-73593, preventing WinRM from using basic authentication for client
    #High
    if (!(Test-Path -Path "HKLM:\Software\Policies\Microsoft\Windows\WinRM")){
        New-Item -Name "WinRM" -Path "HKLM:\Software\Policies\Microsoft\Windows"
        New-Item -Name "Client" -Path "HKLM:\Software\Policies\Microsoft\Windows\WinRM"
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client" -Name "AllowBasic" -PropertyType DWORD -Value 0 -Force
        Write-ToVulnerabilityLog "  Registry Key applied: HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client\AllowBasic"
    }else {
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client" -Name "AllowBasic" -PropertyType DWORD -Value 0 -Force
        Write-ToVulnerabilityLog "  Registry Key applied: HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client\AllowBasic"
    }

    #Stig item V-73691, Preventing lan manager from using anything less than ntlm v2
    #High
    if (!(Test-Path -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa")){
        New-Item -Name "Lsa" -Path "HKLM:\SYSTEM\CurrentControlSet\Control"
        New-ItemProperty -Path -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -PropertyType DWORD -Value 5 -Force
        Write-ToVulnerabilityLog "  Registry Key applied: HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\LmCompatibilityLevel"
    }else {
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -PropertyType DWORD -Value 5 -Force
        Write-ToVulnerabilityLog "  Registry Key applied: HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\LmCompatibilityLevel"
    }

    #Stig item V-73675, preventing anonymous users from accessing shares/pipes
    #High
    if ((Test-Path -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters")){
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "RestrictNullSessAccess" -PropertyType DWORD -Value 1 -Force
        Write-ToVulnerabilityLog "  Registry Key applied: HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\RestrictNullSessAccess"
    }

    #Stig item V-73687, preventing LAN man hashes from being saved
    #High
    if ((Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa")){
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictNullSessAccess" -PropertyType DWORD -Value 1 -Force
        Write-ToVulnerabilityLog "  Registry Key applied: HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\RestrictNullSessAccess"
    }
}

function Edit-ADSettings {
    #Stig item V-73325, ensuring no AD accounts have passwords that are stored in encryption methods that are reversable
    Get-ADUser -Filter "UserAccountControl -band 128" -Properties UserAccountControl | ForEach-Object { Set-ADAccountControl -Identity $_.Name -AllowReversiblePasswordEncryption $false}
    Write-ToVulnerabilityLog "  Set User UAP to not allow users to store password hashes that are reversable"
    }

function Edit-LocalSecurityPolicy {
    if (Test-Path -Path "C:\Windows\Security\database\secedit.sdb"){
        New-Item -Path "$($PSScriptRoot)\Logs" -Name Temp -ItemType Directory
        $ExportPath = "$($PSScriptRoot)\logs\temp\secDataBase"
        secedit /export /cfg $ExportPath
        $LinesToReplace = Get-Content -Path "$($PSScriptRoot)\Logs\Temp\secDataBase" | Select-String "seCreateToken" | Select-Object -ExcludeProperty Line
        $Replace = Get-Content -Path "$($PSScriptRoot)\Logs\Temp\secDataBase"
        $Replace | ForEach-Object { $_ -replace $LinesToReplace, "seCreateTokenPrivilege = "} | Set-Content -Path "$($PSScriptRoot)\Logs\Temp\Corrected.cfg"
        $CorrectedPath = "$($PSScriptRoot)\Logs\Temp\Corrected.cfg"
        secedit /configure /db secedit.sdb /cfg $CorrectedPath
        Remove-Item -Path "$($PSScriptRoot)\Logs\Temp" -Recurse -Force
        Write-ToVulnerabilityLog "  Edited local group policy to not allow any users to have token creation privileges"
    }
}