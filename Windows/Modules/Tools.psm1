Import-Module "$PSScriptRoot\Support.psm1"
Import-Module "$PSScriptRoot\Enumeration.psm1"
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

function Get-Inventory {
    param(
        [parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]
        $Credential,
        [parameter(Mandatory=$true)]
        $LinuxAccount,
        [parameter(Mandatory=$false)]
        $LinuxPemKey
    )
    Write-Host "Gathering all computer objects present in Active Directory" -ForegroundColor Green
    $computers = Get-AllComputerObjects
    foreach($computer in $computers){
        if(!(Test-Path -Path "$($env:USERPROFILE)\Desktop\Inventory")){
            Write-Host "Creating the Inventory directory" -ForegroundColor Green
            New-Item -Path "$($env:USERPROFILE)\Desktop" -ItemType "Directory" -Name "Inventory" | Out-Null
        }
        if(!(Test-Path -Path "$($env:USERPROFILE)\Desktop\Inventory\$computer")){
            Write-Host "Creating a directory for: $computer" -ForegroundColor Green
            New-Item -Path  "$($env:USERPROFILE)\Desktop\Inventory" -ItemType "Directory" -Name "$computer" | Out-Null
        }
        Write-Host "#----- Collecting Inventory on: $computer -----#" -ForegroundColor DarkBlue -BackgroundColor Yellow
        if ((Get-OperatingSystem -Computer $computer) -eq "Windows") {
            $remoteComputerType = Invoke-RemoteComputersCommand -ComputerName $computer -Command "(Get-CimInstance -ClassName Win32_OperatingSystem).ProductType" -Credential $Credential
            if (($remoteComputerType -eq 1) -or ($remoteComputerType -eq 3)) {
                Write-Host "Identified $computer is a Windows Machine, running remote command to gather network inventory" -ForegroundColor Green
                $computerIPInfo = Invoke-RemoteComputersCommand -ComputerName $computer -Command "Get-IPAddressInfo" -Credential $Credential
                $computerIPInfo.GetEnumerator() | Select-Object Name, Value | Export-Csv -NoTypeInformation -Path "$($env:USERPROFILE)\Desktop\Inventory\$computer\$computer-Network Information.csv"
                Write-Host "Running remote command to gather package information" -ForegroundColor Green
                $packageInformation = Invoke-RemoteComputersCommand -ComputerName $computer -Command "Get-Package | Select-Object Name, Version, ProviderName" -Credential $Credential
                $packageInformation | Export-Csv -NoTypeInformation -Path "$($env:USERPROFILE)\Desktop\Inventory\$computer\$computer-Installed Programs.csv"
                Write-Host "Running remote command to gather service information" -ForegroundColor Green
                $services = Invoke-RemoteComputersCommand -ComputerName $computer -Command "Get-Service | Select-Object Status, Name, DisplayName" -Credential $Credential
                $services | Export-Csv -NoTypeInformation -Path "$($env:USERPROFILE)\Desktop\Inventory\$computer\$computer-Service Information.csv"
                Write-Host "Running remote command to gathering local users" -ForegroundColor Green
                $localUsers = Invoke-RemoteComputersCommand -ComputerName $computer -Command "Get-LocalUser | Select-Object Name, Enabled, Description" -Credential $Credential
                $localUsers | Export-Csv -NoTypeInformation -Path "$($env:USERPROFILE)\Desktop\Inventory\$computer\$computer-Local Accounts.csv"
                Write-Host "Running remote command to gather scheduled task information" -ForegroundColor Green
                $tasks = Invoke-RemoteComputersCommand -ComputerName $computer -Command "Get-AllScheduledTasks" -Credential $Credential
                if ($null -ne $tasks) {
                    $tasks | Export-Csv -NoTypeInformation -Path "$($env:USERPROFILE)\Desktop\Inventory\$computer\$computer-Scheduled Task Information.csv"
                }
            } else {
                if ($env:COMPUTERNAME -eq $computer) {
                    Write-Host "Identified $computer is a Windows Machine, running command to gather network inventory" -ForegroundColor Green
                    $computerIPInfo = Get-IPAddressInfo
                    $computerIPInfo.GetEnumerator() | Select-Object Name, Value | Export-Csv -NoTypeInformation -Path "$($env:USERPROFILE)\Desktop\Inventory\$computer\$computer-Network Information.csv"
                    Write-Host "Running command to gather package information" -ForegroundColor Green
                    $packageInformation = Get-Package | Select-Object Name, Version, ProviderName
                    $packageInformation | Export-Csv -NoTypeInformation -Path "$($env:USERPROFILE)\Desktop\Inventory\$computer\$computer-Installed Programs.csv"
                    Write-Host "Running command to gather service information" -ForegroundColor Green
                    $services = Get-Service | Select-Object Status, Name, DisplayName
                    $services | Export-Csv -NoTypeInformation -Path "$($env:USERPROFILE)\Desktop\Inventory\$computer\$computer-Service Information.csv"
                    $tasks = Get-AllScheduledTasks
                    if ($null -ne $tasks) {
                        $tasks | Export-Csv -NoTypeInformation -Path "$($env:USERPROFILE)\Desktop\Inventory\$computer\$computer-Scheduled Task Information.csv"
                    }
                    Write-Host "Determined the local machine IS a domain controller, running the domain enumeration scripts" -ForegroundColor Green
                    Get-ADInformation
                    Get-OUs
                    Get-ADContainers
                    Get-SYSVOLReport
                    Get-ADDataBaseAccess
                    Get-VulnerableADAccounts
                    Get-BuiltInAdminsMembers
                } else {
                    Write-Host "Orlando please write code for remote domain controller enumeration" -ForegroundColor Green
                }
            }
    } else {
            Write-Host "Determined the remote machine is a Linux machine"
            Write-Host "Running remote commands to gather network information"
            $computerIPInfo = Get-LinuxNetworkInformation -ComputerName $computer -LinuxAccount $LinuxAccount
            $computerIPInfo > "$($env:USERPROFILE)\Desktop\Inventory\$computer\$computer-NetworkInformation.txt"
        }
    }
}

<#
.SYNOPSIS
    This function will disable all accounts but managed service accounts 
.DESCRIPTION
    This function will disable all AD accounts but managed service accounts. 

    Created by: Zachary Rousseau, Roger William University.
    Last Updated by: Zachary Rousseau,  Roger Williams University.

    Version: 1.0 - Script Creation.
    Version: 1.1 - Removing requirement to have user enter anything
.PARAMETER exclude
    Accepts an array of SAM Account Names. Verifies they are real names. Does not disable these accounts 
.NOTES 
    Ensure to run 'set-executionpolicy unrestricted' on the server
.EXAMPLE
    Disable-AllADAccounts -exclude Administrator 
    Disable-AllADAccounts -exclude "Administrator", "Orlando"
#>

function Disable-AllADAccounts{
    [CmdletBinding()]
    param(
        [parameter(Position=0)][string[]]$exclude
    )
    Process{
        try {
            foreach ( $exclusion in $exclude ) {
                Write-Verbose "Excluding $exclusion"
                Get-ADUser $exclusion | Out-null  
            }
        }
        catch {
            Write-Warning "Unable to find the exclusion, exiting"
            Start-Sleep 10
            Exit
        }
        $ADIdentities = @()
        # Gets all enabled AD Accounts 
        $ADIdentities = (Get-ADUser -Filter 'enabled -eq $true')
        $count = 0
        # Disables accounts not excluded
        foreach($account in $ADIdentities){
            if(!($account.samaccountname -in $exclude)){
                $SamAccountName = $account.samaccountname
                Write-Verbose "Disabling $SamAccountName"
                Disable-ADAccount -Identity $SamAccountName
                $count ++
            }
        }
        Write-Output "Disabled $count account(s)"
    }
}