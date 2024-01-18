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


function Get-Inventory {
    param(
        [parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]
        $Credential,
        [parameter(Mandatory=$false)]
        $LinuxPemKey,
        [parameter(Mandatory=$false)]
        [string[]]$ListOfComputers
    )
    if (($PSBoundParameters.ContainsKey("ListOfComputers") -eq $true)) {
        $computers = Get-Content -Path $ListOfComputers
        Get-InventoryDirectoryStructure -ListOfComputers $computers
        Group-ComputerAndTakeInventory -Computers $computers -Credential $Credential -LinuxPemKey $LinuxPemKey
    } else {
        Write-Host "List of computers not specified, gathering all computer objects present in Active Directory" -ForegroundColor Green
        $computers = Get-ADComputer -Filter * | Select-Object -ExpandProperty Name
        Get-InventoryDirectoryStructure -ListOfComputers $computers
        Group-ComputerAndTakeInventory -Computers $computers -Credential $Credential -LinuxPemKey $LinuxPemKey
    }
}

function Remove-RDPSession {
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        $AccountName,
        [Parameter(Mandatory=$false)]
        $ComputerName,
        [Parameter(Mandatory=$false)]
        [switch]$AllComputers
    )
    if ($PSBoundParameters.ContainsKey("ComputerName") -eq $true){
        $query = query session 
    } else {
        $query = query session
        foreach ($element in $query){
            if ($element -like "*$AccountName*"){
                Write-Host "RDP Session detected for user: $AccountName on computer: $env:COMPUTERNAME, removing session"
                $sessionToRemove = query session $AccountName
                $sessionNameToRemove = (($sessionToRemove[1]).substring(0, 10)).trim().Replace(">", "")
                if ($sessionNameToRemove -like "*rdp-tcp#*") {
                    reset session $sessionNameToRemove
                } else {
                    Write-Host "This is a console session and could be the users logged in session, exiting script"
                }
            }
        }
    }
}

function Remove-TCPReverseShell {
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$BadIPAddress
    )
    $tcpConnections = netstat -anop TCP
    foreach ($connection in $tcpConnections) {
        if ($connection -like "*$BadIPAddress*") {
            $processID = ($connection.substring($connection.Length - 8)).Replace(' ', '')
            Write-Host "Detected a TCP connection from $BadIPAddress with a PID of $processID on $env:COMPUTERNAME"
            taskkill /pid $processID /f
        }
    }
}

function Remove-AllTCPReverseShells {
    param(
        [Parameter(Mandatory=$false)]
        [string]$BadIPAddress,
        [Parameter(Mandatory=$false)]
        [string]$DomainComputer,
        [Parameter(Mandatory=$false)]
        [string[]]$ListOfComputers,
        [switch]$AllWindowsComputers
    )
    $creds = Get-Credential
    if ($AllWindowsComputers) {
        $allComputers = Get-ADComputer -Filter * | Select-Object -ExpandProperty Name
        foreach ($computer in $allComputers) {
            if ((Get-OperatingSystem -Computer $computer) -eq "Windows") {
                Invoke-RemoteComputersCommand -ComputerName $computer -Credential $creds -Command "Remove-TCPReverseShell -BadIPAddress $BadIPAddress"
            }
        }
    } elseif ($PSBoundParameters.ContainsKey("DomainComputer") -and $PSBoundParameters.ContainsKey("BadIPAddress")) {
        Invoke-RemoteComputersCommand -ComputerName $DomainComputer -Command "Remove-TCPReverseShell -BadIPAddress $BadIPAddress"
    } elseif ($PSBoundParameters.ContainsKey("ListOfComputers") -and $PSBoundParameters.ContainsKey("BadIPAddress")) {
        foreach ($computer in $ListOfComputers) {
            if ((Get-OperatingSystem -Computer $computer) -eq "Windows"){
                Invoke-RemoteComputersCommand -ComputerName $DomainComputer -Command "Remove-TCPReverseShell -BadIPAddress $BadIPAddress"
            }
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

function Reset-ADPasswords {
    [CmdletBinding()]
    param(
        [parameter(Mandatory=$true)]
        [string[]]$ExcludeList
    )
    $users = Get-ADUser -Filter * | Select-Object -ExpandProperty SamAccountName | Where-Object { $_ -notlike "krbtgt"}
    $cleanUserList = @()
    foreach($user in $users){
        if ($ExcludeList -notcontains $user) {
            $cleanUserList += $user
        }
    }
    Write-Host "Resetting passwords for the following users:" -ForegroundColor
    foreach ($user in $cleanUserList) {
        $password = Get-SecurePassword
        Write-Host "Resetting password for: " $user
        Set-ADAccountPassword -Identity $user -Reset -NewPassword $password
    }
}