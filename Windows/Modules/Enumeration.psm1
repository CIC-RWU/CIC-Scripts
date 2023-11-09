Import-Module "$PSScriptRoot\Support.psm1"

<#
Author: TacticalTimbz
Version: 1.1, last updated 09/17/2023
Purpose: A module designed for RWUs Cyber Competition
Overview of regions: 
    Logging
    Windows Environment Enumeration
    Active Directory Enumeration
#>

######################----- Start Region: Windows Environment Enumeration -----######################

<#
.SYNOPSIS
    This function will get all the installed roles and features of server
.DESCRIPTION
    The function will get all the installed roles and features of a server and then write it to a log that is obvious

    Created by: Orlando Yeo, Roger William University.
    Last Updated by: Orlando Yeo, Roger Williams University.

    Version: 1.0 - Script Creation.
.NOTES 
    None
.EXAMPLE
    Get-RolesAndFeatures
.Output
    Log file with roles and features
#>

function Get-RolesAndFeatures {
    $installedRolesAndFeatures = Get-windowsFeature | Where-Object { $_.InstallState -eq "Installed"} | Select-Object -ExpandProperty DisplayName
    $installedRolesAndFeatures | ForEach-Object { Write-ToLog -LogFileContent $_ -LogName "Installed Roles and Features" -Title "Installed Roles and Features" }
    return $installedRolesAndFeatures
}

<#
.SYNOPSIS
    This function will get all the installed programs on a Windows server/host
.DESCRIPTION
    The function will gather all the installed programs on a Windows Server/host and then write them to a log

    Created by: Orlando Yeo, Roger William University.
    Last Updated by: Orlando Yeo, Roger Williams University.

    Version: 1.0 - Script Creation.
.NOTES 
    None
.EXAMPLE
    Get-InstalledPrograms
.Output
    Log file with installed programs
#>

function Get-InstalledPrograms {
    $installedPrograms = Get-Package | Select-Object Name, Version, ProviderName
    $installedPrograms | ForEach-Object { Write-ToLog -LogFileContent $_ -LogName "Installed Programs" -Title "Installed Programs" }
    return $installedPrograms
}

<#
.SYNOPSIS
    This function will get all the ports that are in a state of listening
.DESCRIPTION
    This function will get all the ports that are in a state of listening

    Created by: Orlando Yeo, Roger William University.
    Last Updated by: Orlando Yeo, Roger Williams University.

    Version: 1.0 - Script Creation.
.NOTES 
    None
.EXAMPLE
    Get-LocalListeningPorts
.Output
    Log file with listening ports
#>

function Get-LocalListeningPorts {
    $listeningPorts = Get-NetTCPConnection | Where-Object { $_.State -eq "Listen"} | Select-Object LocalPort
    $listeningPorts | ForEach-Object { Write-ToLog -LogFileContent $_ -LogName "Firewall Information" -Title "Listening Ports"}
}

<#
.SYNOPSIS
    This function will get all the server version
.DESCRIPTION
    This function will get This function will get all the server version and write that information to a log

    Created by: Orlando Yeo, Roger William University.
    Last Updated by: Orlando Yeo, Roger Williams University.

    Version: 1.0 - Script Creation.
.NOTES 
    None
.EXAMPLE
    Find-ServerVersion
.Output
    Log file with listening ports
#>

function Find-ServerVersion {
    $serverVersion = (Get-WmiObject Win32_OperatingSystem).Caption
    Write-ToLog -LogFileContent $serverVersion -LogName "General Information" -Title "Operating System"   
}


<#
.SYNOPSIS
    This function will get all the file shares on a local computer, it will enumerate properties about them
.DESCRIPTION
    This function will get all the file shares on a local computer, it will enumerate properties about them

    Created by: Orlando Yeo, Roger William University.
    Last Updated by: Orlando Yeo, Roger Williams University.

    Version: 1.0 - Script Creation.
.NOTES 
    None
.EXAMPLE
    Get-FileShareInformation
.Output
    Log file with file share info
#>

function Get-FileShareInformation{
    $fileShares = Get-FileShare | Select-Object -ExpandProperty Name
    $fileShares | ForEach-Object { Write-ToLog -LogFileContent $_ -LogName "File Share Information" -Title "Host File Shares"}
}

function Get-IPAddressInfo {
    $activeNic = Get-NetAdapter | Select-Object -ExpandProperty IfIndex
    $hashtable = [ordered]@{}
    $hashtable.Add("Hostname", $env:COMPUTERNAME)
    $hashtable.Add("IPv4 Address", (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.ifIndex -eq $activeNic} | Select-Object -ExpandProperty IPAddress))
    $hashtable.Add("IPv6 Address", (Get-NetIPAddress -AddressFamily IPv6 | Where-Object { $_.ifIndex -eq $activeNic} | Select-Object -ExpandProperty IPAddress))
    $hashtable.Add("MAC Address", (Get-NetAdapter | Select-Object -ExpandProperty MacAddress))
    return $hashtable
}

function Get-LinuxNetworkInformation {
    param(
        $ComputerName
    )
    $IPInfo = Invoke-SSHCommand -Computer $ComputerName -Command "ip a"
    Write-Host $IPInfo
    $refinedIP = Get-DataFromString -String $IPInfo -IPAddress
    $refinedMac = Get-DataFromString -String $IPInfo -MACAddress
    return ($refinedIP + $refinedMac)
}

function Get-LinuxPackageInformation {
    param (
        $ComputerName
    )
    $packageInformation = Invoke-SSHCommand -Computer $ComputerName -Command "apt list --installed | sed -r 's/\x1B\[([0-9]{1,3}(;[0-9]{1,2};?)?)?[mGK]//g'"
    return $packageInformation
}

######################----- End Region: Windows Environment Enumeration -----######################

######################----- Start Region: Active Directory Environment Enumeration -----######################

<#
.SYNOPSIS
    This function will gather important Active Directory information and log it for review
.DESCRIPTION
    The function will gather all users, groups, and group members. It will then log this information.

    Created by: Orlando Yeo, Roger William University.
    Last Updated by: Orlando Yeo, Roger Williams University.

    Version: 1.0 - Script Creation.
.NOTES 
    None
.EXAMPLE
    Get-ADInformation
.Output
    Log file with roles AD info
#>

function Get-ADInformation {
    $users = Get-ADUser -Filter "*" | Select-Object -ExpandProperty SamAccountName
    $groups = Get-ADGroup -Filter * | Select-Object -ExpandProperty SamAccountName
    $users | ForEach-Object { Write-ToLog -LogFileContent $_ -LogName "Active Directory" -Title "All Domain Users"}
    $groups | ForEach-Object { Write-ToLog -LogFileContent $_ -LogName "Active Directory" -Title "All Domain Groups"}
    $usersAndGroups = @{}
    foreach ($group in $groups) {
        $usersInGroup = Get-ADGroupMember -Identity $group | Select-Object -ExpandProperty Name
        $usersAndGroups.Add($group, $usersInGroup)
        }
    $usersAndGroups.GetEnumerator() | ForEach-Object { 
        if ($null -ne $_.Value) {
            Write-ToLog -LogFileContent "$($_.Key): $([String]::Join(', ', $_.Value))`n" -LogName "Active Directory" -Title "Group Membership Breakdown"
        }
    }
}

function Get-BuiltInAdminsMembers {
    $distinguishedName = Get-ADGroup -Filter 'Name -like "Administrators"' | Select-Object -ExpandProperty DistinguishedName
    $groupMembers = Get-ADGroupMember -Identity $distinguishedName | Select-Object -ExpandProperty Name
    $groupMembers | ForEach-Object { Write-ToLog -LogFileContent $_ -LogName "Active Directory" -Title "Users and Groups in the Builtin Administrators group"}
    return $groupMembers
}

<#
.SYNOPSIS
    This function will gather all the Organizational Units in Active Directory
.DESCRIPTION
    This function will gather all the Organizational Units in Active Directory

    Created by: Orlando Yeo, Roger William University.
    Last Updated by: Orlando Yeo, Roger Williams University.

    Version: 1.0 - Script Creation.
.NOTES 
    None
.EXAMPLE
    Get-OUs
.Output
    Log file with OU info
#>

function Get-OUs {
    $OUs = Get-ADOrganizationalUnit -Filter * | Select-Object Name -ExpandProperty Name
    $OUs | ForEach-Object { Write-ToLog -LogFileContent $_ -LogName "Active Directory" -Title "Organizational Units"}
}

<#
.SYNOPSIS
    This function will gather all the Active Directory Containers
.DESCRIPTION
    This function will gather all the Active Directory Containers, filter out the GUIDs, and then write it to a log

    Created by: Orlando Yeo, Roger William University.
    Last Updated by: Orlando Yeo, Roger Williams University.

    Version: 1.0 - Script Creation.
.NOTES 
    None
.EXAMPLE
    Get-ADContainers
.Output
    Log file with CN info
#>

function Get-ADContainers {
    $distinguishedName = (Get-ADDomain).DistinguishedName
    $domainObjects = Get-ADObject -Filter * -SearchBase $distinguishedName
    $ADContainers = $domainObjects | Where-Object { 
        ((Get-ADObject -Identity $_).ObjectClass -eq "Container") -and `
        ($_ -notmatch '(\b\w+-\w+-\w+-\w+\b-\w+)') } | `
        Select-Object -ExpandProperty Name
    $ADContainers | ForEach-Object { Write-ToLog -LogFileContent $_ -LogName "Active Directory" -Title "Active Directory Containers"}
}

<#
.SYNOPSIS
    This function will gather a brief report on the system volume
.DESCRIPTION
    This function will gather all the scripts and policies that are being shared out to the domain. It reports the items in a human
    readable format. It will do a conversion of guids on the GPOs

    Created by: Orlando Yeo, Roger William University.
    Last Updated by: Orlando Yeo, Roger Williams University.

    Version: 1.0 - Script Creation.
.NOTES 
    None
.EXAMPLE
    Get-SYSVOLReport
.Output
    Log file with sysvol info
#>

function Get-SYSVOLReport {
    if (Test-Path "C:\Windows\SYSVOL\*") {
        $sysVolScripts = Get-ChildItem -Path "C:\Windows\SYSVOL\domain\scripts\" | Select-Object -ExpandProperty Name
        $sysVolPolicies = (
            Get-ChildItem -Path "C:\Windows\SYSVOL\domain\Policies\" | `
            Select-Object -ExpandProperty Name).Replace("{", "").Replace("}", "") | `
            ForEach-Object { (Get-GPO -Guid $_ | `
            Select-Object DisplayName) }
        $sysVolScripts | ForEach-Object { Write-ToLog -LogFileContent $_ -LogName "SysVol Report" -Title "SysVol Scripts"}
        $sysVolPolicies | ForEach-Object { Write-ToLog -LogFileContent $_ -LogName "SysVol Report" -Title "Domain Policies"}
    }
}

<#
.SYNOPSIS
    This function will gather the permissions for the Active Directory Database files
.DESCRIPTION
    This function will gather the permissions for the Active Directory Database files and then write it to a log

    Created by: Orlando Yeo, Roger William University.
    Last Updated by: Orlando Yeo, Roger Williams University.

    Version: 1.0 - Script Creation.
.NOTES 
    None
.EXAMPLE
    Get-ADDataBaseAccess
.Output
    Log file with ad database perms
#>

function Get-ADDataBaseAccess {
    #Stig item V-93029, high, server 2019
    $ADDDatabaseFilesPermissions = icacls C:\Windows\NTDS\* | Out-String
    $ADDDatabaseFilesPermissions | ForEach-Object {Write-ToLog -LogFileContent $_ -LogName "Active Directory" -Title "NTDS Permissions"}
}

<#
.SYNOPSIS
    This function will gather vulnerable Active Directory accounts
.DESCRIPTION
    This function will gather vulnerable Active Directory accounts and write it to a log

    Created by: Orlando Yeo, Roger William University.
    Last Updated by: Orlando Yeo, Roger Williams University.

    Version: 1.0 - Script Creation.
.NOTES 
    None
.EXAMPLE
    Get-VulnerableADAccounts
.Output
    Log file with ad vuln accounts
#>

function Get-VulnerableADAccounts {
    $noPasswordRequired = Get-ADUser -Filter * -Properties * | Where-Object { ($_.userAccountControl) -eq 32 -or ( $_.userAccountControl -eq 544)} | Select-Object -ExpandProperty Name
    $noPasswordRequired | ForEach-Object { Write-ToLog -LogFileContent $_ -LogName "Active Directory" -Title "AD Accounts that do not have to provide a password to UAC up" } 
    $noKerberosPreAuthRequired = Get-ADUser -Filter * -Properties * | Where-Object { $_.userAccountControl -eq 4194304}
    $noKerberosPreAuthRequired | ForEach-Object { Write-ToLog -LogFileContent $_ -LogName "Active Directory" -Title "AD Accounts that do not have to have Kerberos Pre Auth"}
    $accountsWithReversableEncryption = Get-ADUser -Filter * -Properties * | Where-Object { $_.allowReversiblePasswordEncryption -eq $true} | Select-Object -ExpandProperty Name
    $accountsWithReversableEncryption | ForEach-Object { Write-ToLog -LogFileContent $_ -LogName "Active Directory" -Title "The following accounts have reversable passwords" }
    $accountsSetToChangePasswordOnNextLogon = Get-ADUser -Filter * -Properties * | Where-Object { $_.pwdLastSet -eq 0} | Select-Object -ExpandProperty Name 
    $accountsSetToChangePasswordOnNextLogon | ForEach-Object { Write-ToLog -LogFileContent $_ -LogName "Active Directory" -Title "The following accounts are set to change passwords at next logon"}
    $catchAll = Get-ADUser -Filter * -Properties * | Where-Object { $_.userAccountControl -ne 512} | Select-Object -ExpandProperty Name
    $catchAll | ForEach-Object { Write-ToLog -LogFileContent $_ -LogName "Active Directory" -Title "The following accounts should be reveiwed for vulnerabilites"}
}

<#
.SYNOPSIS
    This function will gather all Active Directory computer objects
.DESCRIPTION
    This function will gather all Active Directory Computer Objects, log the information, and then fill a text file with the computer names

    Created by: Orlando Yeo, Roger William University.
    Last Updated by: Orlando Yeo, Roger Williams University.

    Version: 1.0 - Script Creation.
.NOTES 
    None
.EXAMPLE
    Get-VulnerableADAccounts
.Output
    Log file with ad vuln accounts
#>

function Get-AllComputerObjects {
    $domainComputers = Get-ADComputer -Filter * | Select-Object -ExpandProperty Name
    $domainComputers | ForEach-Object { Write-ToLog -LogFileContent $_ -LogName "Active Directory" -Title "Domain Computer Objects"} 
    Set-Content -Value $domainComputers -Path "$PSScriptRoot\SupportingDocuments\ListOfComputers.txt" -Force
    return $domainComputers
}

<#
.SYNOPSIS
    Gets all scheduled tasks
.DESCRIPTION
    Simplifies the Get-Scheduledtask function a little 

    Created by: Zachary Rousseau, Roger William University.
    Last Updated by: Orlando Yeo,  Roger Williams University.

    Version: 1.0 - Script Creation.
    Version: 1.1 - Removing positional parameters, removing alias commands, rolling this cmdlet into the inventory tool
.NOTES 
    Ensure to run 'set-executionpolicy unrestricted' on the server
.EXAMPLE
    Get-AllScheduled -ready
#>
function Get-AllScheduledTasks{
    [CmdletBinding()]
    param(
        [parameter()]
        [switch]$ready,
        [parameter()]
        [switch]$running
    )
    if($ready){
        Get-ScheduledTask | Where-Object { $_.State -eq "Ready" }
    }
    if($running){
        Get-ScheduledTask | Where-Object { $_.State -eq "Running" }
    }
    if(!($running) -and !($ready)){
        Get-ScheduledTask
    }
}



Export-ModuleMember -Function *