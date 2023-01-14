<#
Author: TacticalTimbz
Version: 1.0
Purpose: Query AD environment
#>

$LogFile = "$($PSScriptRoot)\Logs\GeneralInfo.txt"
if (!(Test-Path -Path "$($PSScriptRoot)\Logs")){
New-Item -ItemType Directory -Name "Logs" -Path "$($PSScriptRoot)" | Out-Null
}

function Write-ToLog {
    param ([string]$LogFileContent)
    if (!(Test-Path -Path "$($PSScriptRoot)\Logs\GeneralInfo.txt")){
        New-Item -ItemType File -Path "$($PSScriptRoot)\Logs" -Name "GeneralInfo.txt" | Out-Null
    }
    Add-Content $LogFile -Value $LogFileContent
}
function Test-ForModules {
    if ((Get-Module -ListAvailable -Name ActiveDirectory | Select-Object Name -ExpandProperty Name) -eq "ActiveDirectory" ) {
            Write-Host "Host has AD modules installed"
            Write-ToLog "$($env:COMPUTERNAME) is a Domain Controller and has AD modules installed"
    }Else{
        Exit
        Write-ToLog "$($env:COMPUTERNAME) does not have AD modules installed"
    }
}

function Get-ADInformation {
    Write-ToLog "Users:"
    $Users = Get-ADUser -Filter "*" | Select-Object Name -ExpandProperty Name
    $Users | ForEach-Object { Write-ToLog "         $($_)"}
    $Groups = Get-ADGroup -Filter * | Select-Object SamAccountName -ExpandProperty SamAccountName
    Write-ToLog "Groups:"
    $Groups | ForEach-Object { Write-ToLog "        $($_)"}
    $UsersAndGroups = New-Object -TypeName psobject
    @(ForEach ($group in $Groups){
            $AddGroup = $group
            $Addusers =  $(Get-ADGroupMember -Identity $group | Select-Object SamAccountName -ExpandProperty SamAccountName)
            Add-Member -InputObject $UsersAndGroups -MemberType NoteProperty -Name $AddGroup -Value $Addusers
            Write-Host $group
            Write-host "    $(Get-ADGroupMember -Identity $group | Select-Object SamAccountName -ExpandProperty SamAccountName)"
            })
}

function Get-ADGroupInfo {
    Write-ToLog "Important Group Info:"
    $ImportantGroups = "Domain Admins", "Enterprise Admins", "Hyper-V Administrators"
    @(ForEach ($group in $ImportantGroups){
        $UsersToAdd = Get-ADGroupMember -Identity $group | Select-Object Name -ExpandProperty Name
        Write-ToLog "   Members of $($group)"
        Write-ToLog "       $($UsersToAdd)"
    })
}

function Get-OUInfo {
    Write-ToLog "OUs:"
    $OUs = Get-ADOrganizationalUnit -Filter * | Select-Object Name -ExpandProperty Name
    $OUs | ForEach-Object { Write-ToLog "       $($_)"}
}

function Get-SYSVOLReport {
    if (Test-Path "C:\Windows\SYSVOL\*") {
    $domain = $env:userdnsdomain
    Write-ToLog "SYSVOL Report:"
    $SysVolScripts =  Get-ChildItem -Path "C:\Windows\SYSVOL\sysvol\$domain\Scripts"
    $SysVolPolicies = Get-ChildItem -Path "C:\Windows\SYSVOL\sysvol\$domain\Policies"
    Write-ToLog "   Scripts:"
    $SysVolScripts | ForEach-Object { Write-ToLog "         $_"}
        Write-ToLog "   Policies:"
    $SysVolPolicies | ForEach-Object { Write-ToLog "        $_"}
    }else {
        Write-Warning "SYSVOL check not needed"
    }
}

function Get-ADAdminAccess {
    #Stig item V-93029, high, server 2019
    $ADDir = icacls C:\Windows\NTDS\*
    $ADDir > "$($PSScriptRoot)\Logs\AD Admin Access.txt"
}

function Get-ServerFeatures {
    $features = Get-WindowsFeature | Where-Object { $_.InstallState -eq "Installed"}
    $features > "$($PSScriptRoot)\Logs\Server Features.txt"
}

function Get-DnsServerSettings {
    $DnsSettings = Get-DnsServerSetting -all
    $DnsCacheSettings = Get-DnsServerCache
    if ((Get-DnsServerRecursion | Select-Object Enable -ExpandProperty Enable) -eq "true"){
        Write-ToLog "DNS Server Concerns:"
        Write-ToLog "       DNS Recursion is turned ON"
    }
    if ($DnsSettings.RoundRobin -eq "True"){
        Write-ToLog "       DNS Round Robin is turned ON"
    }
    if (($DnsCacheSettings | Select-Object EnablePollutionProtection -ExpandProperty EnablePollutionProtection) -eq $false){
        Write-ToLog "       DNS Pollution Protection is turned OFF"
    }
}

function Get-InstalledPrograms {
    $programs = Get-WmiObject -Class Win32_Product | Select-Object Name, Version
    Write-ToLog "Installed Programs:"
    Write-ToLog "   $($programs)"
}

function Get-LocalListeningPorts {
    $TestConn = Get-NetTCPConnection | Where-Object { $_.State -eq "Listen"}
    $Ports = $TestConn | Select-Object LocalPort
    Write-ToLog "Local Ports Listening:"
    $Ports | ForEach-Object {Write-ToLog "  $($_)"}
}

function Find-ServerVersion {
    $Version = (Get-WmiObject Win32_OperatingSystem).Caption
    Write-ToLog "Server Version:"
    Write-ToLog "   $($Version)"
}

function Start-Analysis {
    $Date = Get-Date
    Write-ToLog "##################### LOG ENTRY $($Date) ##########################"
    Test-ForModules
    Get-ADInformation
    Get-OUInfo
    Get-ADGroupInfo
    Get-SYSVOLReport
    Get-ADAdminAccess
    Get-ServerFeatures
    Get-DnsServerSettings
    Get-InstalledPrograms
    Get-LocalListeningPorts
    Find-ServerVersion
}

Start-Analysis

