
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
    if ($null -eq $LogFileContent) {
        continue
    } else {
        Add-Content -Path "$PSScriptRoot\Logs\$LogName.log" -Value ( "[$(Get-Date -Format "dddd MM/dd/yyyy HH:mm:")]" + $logFileSpace + $LogFileContent)
    }
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
    This function will take a locally defined custom cmdlet and push it to a remote session so it can be called
.DESCRIPTION
    The function will take a module that is in the local session and then invoke a command on the remote computer and define the funciton there,
    so it can be used remotely with out copying any files

    Created by: Orlando Yeo, Roger William University.
    Last Updated by: Orlando Yeo, Roger Williams University.

    Version: 1.0 - Script Creation.
.PARAMETER Command
    (String, or string array) Mandatory, this is the command you wish to run on the remote computer
.PARAMETER Session
    (Not defined) Mandatory, this is the session with the remote computer
.NOTES
    None
.EXAMPLE
    $remoteSession = New-PSSession -ComputerName = Yeet-Server1
    Push-CommandToRemoteSession -Command "Get-RolesAndFeatures" -remoteSession = $remotesession
    invoke-Command -Session $remoteSession -scriptBlock {Get-RolesAndFeatures}
.Output
    None
#>

Function Push-CommandToRemoteSession() {
    Param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty]
        [string[]] $Command,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty]
        $remoteSession
    )
    $functionToImport = Get-Command -Name $Command
    $remoteDefinition = @"
        $($functionToImport.CommandType) $Command(){
            $($functionToImport.Definition)
        }
"@
    Invoke-Command -Session $remoteSession -ScriptBlock { Param($push) . ([scriptblock]::Create($push))} -ArgumentList $remoteDefinition
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
    Command on remote computer
#>

function Invoke-RemoteComputersCommand { 
    param(
        [parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [array]$ListOfComputers,
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Command,
        [parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$ComputerName,
        [parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]
        $Credential = $(Get-Credential),
        [parameter(Mandatory=$false)]
        [switch]$CustomCmdlet
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
    if ($CustomCmdlet -and $ListOfComputers) {
  
    } else {
        
    }

    if ($ListOfComputers) {
        
    } else {
        
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

Export-ModuleMember -Function *