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

function Get-Inventory {
    param(
        [parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]
        $Credential,
        [parameter(Mandatory=$true)]
        $LinuxAccount
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

        # Verifying the exclusions
        try{
            foreach($exclusion in $exclude){
                Write-Verbose "Excluding $exclusion"
                Get-ADUser $exclusion | Out-null
                
            }
        }
        catch{
            $abort = Read-Host "Unable to find $exclusion. Would you like to abort? (y/n)"

            if(($abort -eq "y") -or ($abort -eq "yes")){
                Break
            }

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

<#
.SYNOPSIS
    Gets all scheduled tasks
.DESCRIPTION
    Simplifies the Get-Scheduledtask function a little 

    Created by: Zachary Rousseau, Roger William University.
    Last Updated by: Zachary Rousseau,  Roger Williams University.

    Version: 1.0 - Script Creation.
.NOTES 
    Ensure to run 'set-executionpolicy unrestricted' on the server
.EXAMPLE
    Get-AllScheduled -ready
#>
function Get-AllScheduledTasks{
    [CmdletBinding()]
    param(
        [parameter(Position=0)][switch]$ready,
        [parameter(Position=0)][switch]$running
    )

    if($ready){
        get-scheduledtask | where state -eq 'Ready'
    }
    if($running){
        get-scheduledtask | where state -eq 'Running'
    }
    if(!($running) -and !($ready)){
        get-scheduledtask
    }

}