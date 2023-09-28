<#
Author: TacticalTimbz
Version: 1.1, last updated 09/17/2023
Purpose: A module designed for RWUs Cyber Competition
Overview of regions: 
    Logging
    Windows Environment Enumeration
    Active Directory Enumeration
#>

######################----- Start Region: Logging and Support Functions -----######################
 
<#
.SYNOPSIS
    This function creates a log file
.DESCRIPTION
    The function will create a log file based on the name you wish to title it. It will validate that path and create the "Logs" directory

    Created by: Orlando Yeo, Roger William University.
    Last Updated by: Orlando Yeo, Roger Williams University.

    Version: 1.0 - Script Creation.
.PARAMETER Name
    Mandatory, specifies the title of the log file. Do not put the file extension, only the name you wish to call it
.NOTES 
    None
.EXAMPLE
    New-LogFile -Name "Active Directory"
.Output
    A .log file
#>

function New-LogFile {
    param(
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name
    )
    if (!(Test-Path -Path "$($PSScriptRoot)\Logs")){
        New-Item -ItemType Directory -Name "Logs" -Path $PSScriptRoot | Out-Null
    }
    if (!(Test-Path -Path "$($PSScriptRoot)\Logs\$($Name)")){
        New-Item -ItemType File -Name "$($Name).log" -Path "$($PSScriptRoot)\Logs" | Out-Null
    }
}

<#
.SYNOPSIS
    This function writes to a log file in a specific format
.DESCRIPTION
    The function will take content you wish to log, the log file you wish to write it to, and a title for the log section. 
    The function takes the content and writes it to the log. It does some quality of life things with log headers and whatnot.

    Created by: Orlando Yeo, Roger William University.
    Last Updated by: Orlando Yeo, Roger Williams University.

    Version: 1.0 - Script Creation.
.PARAMETER LogFileContent
    Mandatory, this is the content you want to put into the log. It can be anything, best to use a string.
.PARAMETER LogName
    Mandatory, this is a string of the title you wish to log to. If the log does not exist, the function will create the log for you
.PARAMETER Title
    Not mandatory, this will create a title section of the log, i.e., if you are logging Active Directory information, the parameter
    will make it painfully obvious where this content is in the log file
.NOTES 
    None
.EXAMPLE
    Write-ToLog -LogFileContent "I am testing this function" -LogName "MyNewLog" -Title "Important Information"
.Output
    Log file content
#>

function Write-ToLog {
    param (
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$LogFileContent,
        [parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [string]$LogName,
        [parameter(Mandatory=$false)]
        [string]$Title
    )
    $logFileSpace = "       -"
    if (!(Test-Path -Path "$($PSScriptRoot)\Logs\$LogName.log")){
        New-LogFile -Name $LogName
    }
    $Script:titleCheck = $false
    if ($null -ne $Title){
        $logContent = Get-Content -Path "$PSScriptRoot\Logs\$LogName.log"
        $logContent | ForEach-Object {
            if ($_ -match $Title.ToUpper()) {
                $Script:titleCheck = $true
            } else {
                return
            }
        }
    }
    if ($Script:titleCheck -eq $false) {
        Add-Content -Path "$PSScriptRoot\Logs\$LogName.log" -Value ("#---------- $($Title.ToUpper()) ----------#")
    }
    Add-Content -Path "$PSScriptRoot\Logs\$LogName.log" -Value ( "[$(Get-Date -Format "dddd MM/dd/yyyy HH:mm:")]" + $logFileSpace + $LogFileContent)
}

<#
.SYNOPSIS
    This function will analyze the registry for vulnerabilities
.DESCRIPTION
    The function uses a pre-made .csv file that contains various headers with information about properly configured registry items. The function
    will determine if a key needs to be created, then set the key, value name, and value. It will also determine if the key exists and then analyze
    the name and values. There is a flag to set this function to recon only mode, which only presents information in a vulns log

    Created by: Orlando Yeo, Roger William University.
    Last Updated by: Orlando Yeo, Roger Williams University.

    Version: 1.0 - Script Creation.
.PARAMETER InputFilePath
    Mandatory, this is the path to the .csv file
.PARAMETER ReconOnly
    Non-mandatory, this is a switch to turn on recon only mode
.NOTES
    Please do not mess with this script unless you encounter an error or if you can improve upon it, it's very challenging to deal 
    with the registry correctly in an automated way
.EXAMPLE
    Confirm-RegistryConfiguration -InputFilePath "C:\Path\To\File.csv"
    Confirm-RegistryConfiguration -InputFilePath "C:\Path\To\File.csv" -ReconOnly
.Output
    Log file content or massive registry changes
#>

function Confirm-RegistryConfiguration {
    param(
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$InputFilePath,
        [parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [switch]$ReconOnly
    )
    $csvImport = Import-Csv -Path $InputFilePath
    if($ReconOnly){
        $csvImport | ForEach-Object {
            if((Test-Path -Path $_.Key) -eq $false){
                Write-ToLog -LogFileContent ("Missing Registry Key: " + (($_.Key).Split("\") | Select-Object -Last 1) + ", " + $_.Reason + ", " + $_.FindingID) -LogName "Vulnerabilities" -Title "Misconfigured Registry Items"
            } elseif (((Get-ItemProperty -Path $_.Key).PSObject.Properties.Name -contains $_.Name) -eq $false) {
                Write-ToLog -LogFileContent ("Missing Value Name: " + $_.Name + ", " + $_.Reason + ", " + $_.FindingID) -LogName "Vulnerabilities" -Title "Misconfigured Registry Items"
            } elseif ((Get-ItemProperty -Path $_.Key -Name $_.Name).PSObject.Properties | Where-Object { $_.Name -eq $_.Name} | Select-Object -ExpandProperty Value) {
                Write-ToLog -LogFileContent ("Registry Value for " + $_.Name + " is the incorrect value, " + $_.Reason + ", " + $_.FindingID) -LogName "Vulnerabilities" -Title "Misconfigured Registry Items"
            } else {
                Write-ToLog -LogFileContent "An unknown error occured when determining the status of the $($_.Name) Registry Value, in the $($_.Key) Key"
            }
        }
    } else {
        $csvImport | ForEach-Object {
            if ((Test-Path -Path $_.Key) -eq $false){
                New-Item -Name (($_.Key).Split("\") | Select-Object -Last 1) -Path ((($_.Key).Split("\") | Select-Object -SkipLast 1) -join "\")
                New-ItemProperty -Path $_.Key -Name $_.Name -PropertyType $_.Type -Value $_.Value
                Write-ToLog -LogFileContent ("Fixing: " + $_.Reason) -LogName "Remediated Vulnerabilites" -Title "Vulnerabilities fixed by configuring registry keys"
            }
        }
    }
}

<#
.SYNOPSIS
    This function will run commands on remote computers within a domain
.DESCRIPTION
    The function takes a list of computers, or gathers all the computers in the domain, determine if the user is the Domain admin, determing if
    WinRM is functioning correctly, and then run commands on remote computers. It will then log the commands it runs on, on the computers it 
    runs them on, in a log file

    Created by: Orlando Yeo, Roger William University.
    Last Updated by: Orlando Yeo, Roger Williams University.

    Version: 1.0 - Script Creation.
.PARAMETER ListOfComputers
    (String) Non-mandatory, this is so a person can supply just a set of computers. For example, an administrator could specify only workstations or 
    only servers
.PARAMETER Command
    (ScriptBlock) Mandatory, this is the command you want to run on the remote computer
.PARAMETER ComputerName
    (String) Non-mandatory, this is a flag you can set to specify a single computer
.NOTES
    None
.EXAMPLE
    Invoke-RemoteComputersCommand -Command {New-Item -Path "C:\Users\Administrator\Desktop" -Name NotAPasswordFile.txt -Type File}
        The above command will create a new text document called "NotAPasswordFile.txt" on the administrators desktop for every computer in the
        domain
    Invoke-RemoteComputersCommand -Command {New-Item -Path "C:\Users\Administrator\Desktop" -Name NotAPasswordFile.txt -Type File} -ListOfComputers "C:\Users\Administrator\Desktop\ListOfWorkstations.txt"
        The above command will create a new text document called "NotAPasswordFile.txt" on the administrators desktop for every workstation in the domain
    Invoke-RemoteComputersCommand -Command {New-Item -Path "C:\Users\Administrator\Desktop" -Name NotAPasswordFile.txt -Type File} -ComputerName "OrlandoPC"
        The above command will create a new text document called "NotAPasswordFile.txt" on the computer called OrlandoPC
    
.Output
    Log file content or massive registry changes
#>

function Invoke-RemoteComputersCommand { 
    param(
        [parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [array]$ListOfComputers,
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [scriptblock]$Command,
        [parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$ComputerName,
        [parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]
        $Credential = $(Get-Credential)

    )
    if ($null -eq $Credential){
        $Credential = Get-Credential
    }
    if (($null -eq $ListOfComputers) -and ($null -eq $ComputerName)){
        $ListOfComputers = Get-AllComputerObjects
    }
    if ((Get-Service | Select-Object | Where-Object { $_.Name -like "WinRM"} | Select-Object -ExpandProperty Status) -ne "Running"){
        Write-Warning "WinRM is not running, exiting"
        return
    }
    $domainAdminCheck = ((Get-ADPrincipalGroupMembership -Identity $env:USERNAME | Select-Object -ExpandProperty Name) -contains "Domain Admins")
    $nestedDomainAdminCheck = (((Get-ADPrincipalGroupMembership -Identity $env:USERNAME | Select-Object -ExpandProperty Name) | ForEach-Object { (Get-ADPrincipalGroupMembership -Identity $_ | Select-Object -ExpandProperty Name) -contains "Domain Admins"}))
    if ($domainAdminCheck -ne $true){
        if ( $nestedDomainAdminCheck -contains "True" ){
            continue
        } else {
            Write-Warning "Current user is not a Domain Admin, exiting script"
            return
        }
    }
    if ($null -ne $ListOfComputers) {
        Write-ToLog -LogFileContent "Running the following command: $($Command) on the following computers: $($ListOfComputers -join ",")" -LogName "Remote Command History" -Title "Commands run on remote computers"
        foreach ($computer in $ListOfComputers) {
            Invoke-Command -Credential $Credential -ComputerName $computer -ScriptBlock $Command
        }
    } else {
        Write-ToLog -LogFileContent "Running the following command: $($Command) on the following computer: $($ComputerName)" -LogName "Remote Command History" -Title "Commands run on remote computers"
        Invoke-Command -Credential $Credential -ComputerName $ComputerName -ScriptBlock $Command
    }
}

<#
.SYNOPSIS
    This function will return a secure string
.DESCRIPTION
    The function will return a string that is in the object type of Secure.String. This allows the user to use these strings as passwords in 
    functions and other things like that. It will also salt a password if the switch is enabled

    Created by: Orlando Yeo, Roger William University.
    Last Updated by: Orlando Yeo, Roger Williams University.

    Version: 1.0 - Script Creation.
.NOTES
    So, I beleive this can be foiled by a few means but it will 100% slow people down from tracking down good hashes to use and will prevent
    things like keyloggers from being effective
.EXAMPLE
    Get-SecureString
.Output
    None
#>
function Get-SecureString {
    param(
        [parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [switch]$Salt,
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [int]$AmountOfCharacters
    )
    $characters = 'a','b','c','d','e','f','g','h','i','j', 'k', 'l', 'm','n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '!', '@', '#', '$', '%', '^', '&', '*', '1', '2', '3', '4', '5' , '6', '7' , '8', '9'
    [string]$password = Get-Random -InputObject $characters -Count $AmountOfCharacters
    if ($Salt) {
        [string]$saltStart = Get-Random -InputObject $characters -Count 5
        [string]$saltEnd = Get-Random -InputObject $characters -Count 5
        $secure = ConvertTo-SecureString -AsPlainText (($saltStart + $password + $saltEnd).Replace(" ", "")) -Force
        return $secure
    } else {
        $secure = ConvertTo-SecureString -String ($password.Replace(" ", ""))
        return $secure
    }
}

######################----- End Region: Logging and Support Functions -----######################

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
    $installedPrograms = Get-Package | Select-Object -ExpandProperty Name
    $installedPrograms | ForEach-Object { Write-ToLog -LogFileContent $_ -LogName "Installed Programs" -Title "Installed Programs" }
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
    $noPasswordRequired = Get-ADUser -Filter * -Properties * | Where-Object { $_.userAccountControl -eq 32}
    $noPasswordRequired | Write-ToLog -LogFileContent $_ -LogName "Active Directory" -Title "AD Accounts that do not have to provide a password to UAC up"
    $noKerberosPreAuthRequired = Get-ADUser -Filter * -Properties * | Where-Object { $_.userAccountControl -eq 4194304}
    $noKerberosPreAuthRequired | Write-ToLog -LogFileContent $_ -LogName "Active Directory" -Title "AD Accounts that do not have to have Kerberos Pre Auth"
    $accountsWithReversableEncryption = Get-ADUser -Filter * -Properties * | Where-Object { $_.allowReversiblePasswordEncryption -eq $true} | Select-Object -ExpandProperty Name
    $accountsWithReversableEncryption | Write-ToLog -LogFileContent $_ -LogName "Active Directory" -Title "The following accounts have reversable passwords"
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

######################----- End Region: Active Directory Environment Enumeration -----######################

######################----- Start Region: Common Blue Team Tasks -----######################

function Block-IPAddress {
    param(
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$IPAddress,
        [parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [array]$IPList,
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$ComputerName,
        [parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [array]$ComputerList,
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$DisplayName,
        [parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [switch]$EntireDomain
    )
    if ($EntireDomain){
        if ($IPList) {
            $IPList | ForEach-Object { 
                Invoke-RemoteComputersCommand -Command { New-NetFirewallRule -DisplayName $DisplayName -Direction Inbound -Action Block -RemoteAddress $_} -ListOfComputers 
            }
            else {
                Invoke-RemoteComputersCommand -Command { New-NetFirewallRule -DisplayName $DisplayName -Direction Inbound -Action Block -RemoteAddress $IPAddress} -ListOfComputers $ComputerName
            }
        }
    } else {
        if ($IPList) {
            
        } else {
            
        }
    }
}

<#
.SYNOPSIS
    This function will secure a local windows guest account
.DESCRIPTION
    This function will rename, reset the password, and disable the built-in local guest account and write the command history to a log

    Created by: Orlando Yeo, Roger William University.
    Last Updated by: Orlando Yeo, Roger Williams University.

    Version: 1.0 - Script Creation.
.PARAMETER Computers
    (Array) Non-mandatory, this is a list of computer names. By default, if this parameter is null the function will gather every computer object
    in the domain
.NOTES 
    None
.EXAMPLE
    Get-SecureGuestAccounts -Computers "Yeet-Server1", "Yeet-Workstation1"
.Output
    Guest account changes
#>

function Get-SecureGuestAccounts {
    param(
        [parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [array]$Computers
    )
    if ($null -eq $Computers){
        $Computers = Get-AllComputerObjects 
    }
    $creds = Get-Credential
    $arrayOfPasswords = New-Object System.Collections.ArrayList
    foreach($number in 1..100){
        $add = Get-SecureString -Salt -AmountOfCharacters 15
        $arrayOfPasswords.Add($add) > $null
    }
    $password = $arrayOfPasswords | Get-Random
    $Computers | ForEach-Object {
        Invoke-RemoteComputersCommand -ComputerName $_ -Credential $creds -Command { Rename-LocalUser -Name "Guest" -NewName "notAGuest" }
        Invoke-RemoteComputersCommand -ComputerName $_ -Credential $creds -Command { Set-LocalUser -Name "notAGuest" -Password ($Using:password)}
        Invoke-RemoteComputersCommand -ComputerName $_ -Credential $creds -Command { Disable-LocalUser -Name "notAGuest"}
    }
}

<#
.SYNOPSIS
    This function will secure a local Windows administrator account
.DESCRIPTION
    This function will rename, reset the password, and disable the built-in local administrator account and write the command history to a log

    Created by: Orlando Yeo, Roger William University.
    Last Updated by: Orlando Yeo, Roger Williams University.

    Version: 1.0 - Script Creation.
.PARAMETER Computers
    (Array) Non-mandatory, this is a list of computer names. By default, if this parameter is null the function will gather every computer object
    in the domain
.NOTES 
    None
.EXAMPLE
    Get-SecureGuestAccounts -Computers "Yeet-Server1", "Yeet-Workstation1"
.Output
    Guest account changes
#>

function Get-SecureAdministratorAccounts {
    param(
        [parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [array]$Computers
    )
    if ($null -eq $Computers){
        $Computers = Get-AllComputerObjects 
    }
    $creds = Get-Credential
    $arrayOfPasswords = New-Object System.Collections.ArrayList
    foreach($number in 1..100){
        $add = Get-SecureString -Salt -AmountOfCharacters 15
        $arrayOfPasswords.Add($add) > $null
    }
    $password = $arrayOfPasswords | Get-Random
    $Computers | ForEach-Object {
        Invoke-RemoteComputersCommand -ComputerName $_ -Credential $creds -Command { Rename-LocalUser -Name "Administrator" -NewName "notAdministrator" }
        Invoke-RemoteComputersCommand -ComputerName $_ -Credential $creds -Command { Set-LocalUser -Name "notAdministrator" -Password ($Using:password)}
        Invoke-RemoteComputersCommand -ComputerName $_ -Credential $creds -Command { Disable-LocalUser -Name "notAdministrator"}
    }
}

######################----- End Region: Common Blue Team Tasks -----######################


######################----- Start Region: TODO/TO Work On -----######################
# function Get-DnsServerSettings {
#     $DnsSettings = Get-DnsServerSetting -all
#     $DnsCacheSettings = Get-DnsServerCache
#     if ((Get-DnsServerRecursion | Select-Object Enable -ExpandProperty Enable) -eq "true"){
#         Write-ToLog "DNS Server Concerns:"
#         Write-ToLog "       DNS Recursion is turned ON"
#     }
#     if ($DnsSettings.RoundRobin -eq "True"){
#         Write-ToLog "       DNS Round Robin is turned ON"
#     }
#     if (($DnsCacheSettings | Select-Object EnablePollutionProtection -ExpandProperty EnablePollutionProtection) -eq $false){
#         Write-ToLog "       DNS Pollution Protection is turned OFF"
#     }
# }

# function Edit-ADSettings {
#     #Stig item V-73325, ensuring no AD accounts have passwords that are stored in encryption methods that are reversable
#     Get-ADUser -Filter "UserAccountControl -band 128" -Properties UserAccountControl | ForEach-Object { Set-ADAccountControl -Identity $_.Name -AllowReversiblePasswordEncryption $false}
#     Write-ToVulnerabilityLog "  Set User UAP to not allow users to store password hashes that are reversable"
#     }

# function Edit-LocalSecurityPolicy {
#     if (Test-Path -Path "C:\Windows\Security\database\secedit.sdb"){
#         New-Item -Path "$($PSScriptRoot)\Logs" -Name Temp -ItemType Directory
#         $ExportPath = "$($PSScriptRoot)\logs\temp\secDataBase"
#         secedit /export /cfg $ExportPath
#         $LinesToReplace = Get-Content -Path "$($PSScriptRoot)\Logs\Temp\secDataBase" | Select-String "seCreateToken" | Select-Object -ExcludeProperty Line
#         $Replace = Get-Content -Path "$($PSScriptRoot)\Logs\Temp\secDataBase"
#         $Replace | ForEach-Object { $_ -replace $LinesToReplace, "seCreateTokenPrivilege = "} | Set-Content -Path "$($PSScriptRoot)\Logs\Temp\Corrected.cfg"
#         $CorrectedPath = "$($PSScriptRoot)\Logs\Temp\Corrected.cfg"
#         secedit /configure /db secedit.sdb /cfg $CorrectedPath
#         Remove-Item -Path "$($PSScriptRoot)\Logs\Temp" -Recurse -Force
#         Write-ToVulnerabilityLog "  Edited local group policy to not allow any users to have token creation privileges"
#     }
# }