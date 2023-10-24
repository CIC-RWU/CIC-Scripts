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
    $computers = Get-AllComputerObjects
    foreach($computer in $computers){
        if(!(Test-Path -Path "$($env:USERPROFILE)\Desktop\Inventory")){
            New-Item -Path "$($env:USERPROFILE)\Desktop" -ItemType "Directory" -Name "Inventory" | Out-Null
        }
        if(!(Test-Path -Path "$($env:USERPROFILE)\Desktop\Inventory\$computer")){
            New-Item -Path  "$($env:USERPROFILE)\Desktop\Inventory" -ItemType "Directory" -Name "$computer" | Out-Null
        }
        if ((Get-OperatingSystem -Computer $computer) -eq "Windows") {
        $computerIPInfo = Invoke-RemoteComputersCommand -ComputerName $computer -Command "Get-IPAddressInfo" -Credential $Credential
        $computerIPInfo.GetEnumerator() | Select-Object Name, Value | Export-Csv -NoTypeInformation -Path "$($env:USERPROFILE)\Desktop\Inventory\$computer\$computer-Network Information.csv"
        Get-Package | Select-Object Name, Version, ProviderName | Export-Csv -NoTypeInformation -Path "$($env:USERPROFILE)\Desktop\Inventory\$computer\$computer-Installed Programs.csv"
        Get-Service | Select-Object Status, Name, DisplayName | Export-Csv -NoTypeInformation -Path "$($env:USERPROFILE)\Desktop\Inventory\$computer\$computer-Service Information.csv"
        $scheduledTasks = Get-AllScheduledTasks
        if ($null -ne $scheduledTasks) {
            Export-Csv -NoTypeInformation -Path "$($env:USERPROFILE)\Desktop\Inventory\$computer\$computer-Scheduled Task Information.csv"
        }
        if ($null -ne (Get-ADDomainController)) {
            Get-LocalUser | Export-Csv -NoTypeInformation -Path "$($env:USERPROFILE)\Desktop\Inventory\$computer\$computer-Local Accounts.csv"
        }
    } else {
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