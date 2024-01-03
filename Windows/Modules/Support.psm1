
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
        [string]$Name,
        [Parameter(Mandatory=$false)]
        [string]$LogDirectory = "$($env:USERPROFILE)\Desktop\Logs"
    )
    if (!(Test-Path -Path "$($LogDirectory)")){
        New-Item -ItemType Directory -Name "Logs" -Path "$LogDirectory" | Out-Null
    }
    if (!(Test-Path -Path "$($LogDirectory)\Logs\$($Name)")){
        New-Item -ItemType File -Name "$($Name).log" -Path "$LogDirectory" | Out-Null
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
        [string]$Title,
        [parameter(Mandatory=$false)]
        [switch]$Separator,
        [parameter(Mandatory=$false)]
        [string]$LogDirectory = "$($env:USERPROFILE)\Desktop\Logs"
    )
    $logFileSpace = "       -"
    $logFileSeparator = "------------------------------------------------------------------------"
    if (!(Test-Path -Path "$LogDirectory\$LogName.log")){
        New-LogFile -Name $LogName
    }
    $Script:titleCheck = $false
    if ($null -ne $Title){
        $logContent = Get-Content -Path "$LogDirectory\$LogName.log"
        $logContent | ForEach-Object {
            if ($_ -match $Title.ToUpper()) {
                $Script:titleCheck = $true
            } else {
                return
            }
        }
    }
    if ($Script:titleCheck -eq $false) {
        Add-Content -Path "$LogDirectory\$LogName.log" -Value ("#---------------------- $($Title.ToUpper()) ----------------------#")
    }
    if ($null -eq $LogFileContent) {
        continue
    } else {
        if($Separator){
            Add-Content -Path "$LogDirectory\$LogName.log" -Value $logFileSeparator
            Add-Content -Path "$LogDirectory\$LogName.log" -Value ( "[$(Get-Date -Format "dddd MM/dd/yyyy HH:mm:")]" + $logFileSpace + $LogFileContent)
            Add-Content -Path "$LogDirectory\$LogName.log" -Value $logFileSeparator
        } else {
            Add-Content -Path "$LogDirectory\$LogName.log" -Value ( "[$(Get-Date -Format "dddd MM/dd/yyyy HH:mm:")]" + $logFileSpace + $LogFileContent)
        }
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

function Get-DataFromString {
    param(
        [parameter(Mandatory=$true)]
        [string]$String,
        [parameter(Mandatory=$false)]
        [switch]$IPAddress,
        [parameter(Mandatory=$false)]
        [switch]$MACAddress
    )
    if ($IPAddress) {
        $refinedIP = Select-String -InputObject [string]$IPInfo -Pattern "\b(([01]?\d?\d|2[0-4]\d|25[0-5])\.){3}([01]?\d?\d|2[0-4]\d|25[0-5])\b" -AllMatches | ForEach-Object { $_.Matches} | Select-Object -ExpandProperty Value
        if ($null -ne $refinedIP) {
            return $refinedIP
        } else {
            Write-Warning "Unable to detect IP address in string"
        }
    }
    if ($MACAddress) {
        $refinedMAC = $null
        if ($null -ne $refinedMAC) {
            return $refinedMAC
        } else {
            Write-Warning "Unable to detect MAC address in string"
        }
    }
}

<#
.SYNOPSIS
    This function will take a locally defined custom cmdlet and push it to a remote session so it can be called in a session
.DESCRIPTION
    The function will take a module that is in the local session and then invoke a command on the remote computer and define the funciton there,
    so it can be used remotely with out copying any files

    Created by: Orlando Yeo, Roger William University, 10-1-2023
    Last Updated by: Orlando Yeo, Roger Williams University, 10-23-2023

    Version: 1.0 - Script Creation.
    Version: 1.1 - Added support for remotely loading functions with variables and all the custom functions

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
        [string[]] $Command,
        [Parameter(Mandatory=$true)]        
        $remoteSession
    )
    $baseCommand = $Command -split " " | Select-Object -First 1
    try {
        Get-Command -Name $baseCommand -ErrorAction Stop | Out-Null
    }
    catch {
        Write-Warning "Unable to import command, ensure your session contains the command you are attempting to run. Exiting script in 10 seconds"
        Start-Sleep 10
        Exit
    }
    $functionToImport = Get-Command -Name $baseCommand
    $remoteDefinition = @"
        $($functionToImport.CommandType) $baseCommand (){ $($functionToImport.Definition) }
"@
    $allCustomCmdlets = Get-Module | Where-Object { ($_.Name -like "Support") -or ($_.Name -like "Enumeration") -or ($_.Name -like "Tools") } | Select-Object -ExpandProperty ExportedCommands      
    $dependencies = $allCustomCmdlets.keys
    foreach ($dependency in $dependencies){
        try {
            Get-Command -Name $dependency -ErrorAction Stop | Out-Null
        }
        catch {
            Write-Warning "Unable to import command, ensure your session contains the command you are attempting to run. Exiting script in 10 seconds"
            Start-Sleep 10
            Exit
        }
        $dependencyToImport = Get-Command -Name $dependency
        $dependencyDefinition = @"
        $($dependencyToImport.CommandType) $dependency (){ $($dependencyToImport.Definition) }
"@
        Invoke-Command -Session $remoteSession -ScriptBlock { Param($push) . ([scriptblock]::Create($push))} -ArgumentList $dependencyDefinition
    }
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
.PARAMETER Credential
    (PSCredential) Not-mandatory, but encouraged. This is passed on to most other cmdlets that need credentials 
.PARAMETER CustomCmdlet
    (String) Not-mandatory, this is a parameter that specifies a cmdlet that is defined outside of the installed modules or powershell core, this 
    parameter will remotely load the cmdlet and allow the session to have access to it
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

function Get-OperatingSystem {
    param(
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Computer
    )
    if ((Get-ADComputer -Identity $Computer -Properties * | Select-Object -ExpandProperty OperatingSystem) -like "*Windows*") {
        return "Windows"
    } else {
        return "Linux"
    }
}

function Invoke-SSHCommand {
    param(
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Computer,
        [parameter(Mandatory=$false)]
        [string]$AccountName,
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Command
    )
    if ($null -like $AccountName) {
        $AccountName = Read-Host "Enter Account Name For $Computer"
    }
    if ($output -like "*port 22: Connection refused*") {
        Write-Warning "Connection to port 22 was refused, ensure SSH is working correctly"
    } else {
        $commandToPush = @"
            $Command
"@ -replace "`r", "`n"
        $result = ssh -t $AccountName@$Computer $commandToPush
        return $result
    }
}

function Invoke-SSHScript {
    param (
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Computer,
        [parameter(Mandatory=$false)]
        [string]$AccountName,
        [parameter(Mandatory=$false)]
        [string]$ScriptPath
    )
    if ($null -like $AccountName) {
        $AccountName = Read-Host "Enter Account Name For $Computer"
    }
    $command = & cmd.exe /C "ssh -t $AccountName@$Computer < $ScriptPath"
    return $command
}

function Start-SessionWithCommand {
    param(
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Computer,
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Command,
        [parameter(Mandatory=$true)]
        [System.Management.Automation.PSCredential]
        $Credential,
        [parameter(Mandatory=$false)]
        [switch]$PushCommand
    )
    if ($PushCommand) {
        $remoteSession = New-PSSession -ComputerName $Computer -Credential $Credential
        Push-CommandToRemoteSession -Command $Command -remoteSession $remoteSession
        $result = Invoke-Command -Session $remoteSession -ScriptBlock ([scriptblock]::Create($Command))
        Remove-PSSession -Session $remoteSession
        return $result
    } else {
        $remoteSession = New-PSSession -ComputerName $ComputerName -Credential $Credential
        $result = Invoke-Command -Session $remoteSession -ScriptBlock ([scriptblock]::Create($Command))
        Remove-PSSession -Session $remoteSession
        return $result
    }
}

function Get-ComputerTypeFilter {
    param (
        [paramter(Mandatory=$false)]
        $ListOfComputers,
        [paramter(Mandatory=$false)]
        [string]$WindowsServers,
        [paramter(Mandatory=$false)]
        [string]$WindowsWorkstations
    )



}

function Invoke-RemoteComputersCommand {
    param(
        [parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [array]$ListOfComputers,
        [parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$Command,
        [parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$ComputerName,
        [parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]
        $Credential = $(Get-Credential),
        [parameter(Mandatory=$false)]
        [string]$SSHAccount,
        [parameter(Mandatory=$false)]
        [string]$LinuxCommand,
        [parameter(Mandatory=$false)]
        [string]$LinuxScriptPath,
        [parameter(Mandatory=$false)]
        [string]$WindowsServers,
        [parameter(Mandatory=$false)]
        [string]$WindowsWorkstations
    )
    #orlando from the past, please make an option to specify computer types. I.e., Windows computers, or windows servers only and workstations only
    $CustomCmdlet = $false
    $allCustomCmdlets = Get-Module | Where-Object { ($_.Name -like "Support") -or ($_.Name -like "Enumeration") -or ($_.Name -like "Tools") } | Select-Object -ExpandProperty ExportedCommands
    if ($allCustomCmdlets.keys -contains ($Command -split " " | Select-Object -First 1)){
        $CustomCmdlet = $true
    }
    if ($null -eq $Credential){
        $Credential = Get-Credential
    }
    if (($PSBoundParameters.ContainsKey("ListOfComputers") -eq $false) -and ($PSBoundParameters.ContainsKey("ComputerName") -eq $false)){
        Write-Warning "No computer name or list of computers specified, getting all computer objects"
        $ListOfComputers = Get-ADComputer -Filter * | Select-Object -ExpandProperty Name
    }
    if ((Get-Service | Select-Object | Where-Object { $_.Name -like "WinRM"} | Select-Object -ExpandProperty Status) -ne "Running"){
        Write-Warning "WinRM is not running, exiting"
        return
    }
    
    #orlando from the past, please make an option to specify computer types. I.e., Windows computers, or windows servers only and workstations only

    # if () {
        
    # }
    #filter out current list of computers by function
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
        Write-ToLog -LogFileContent "Running the following command: $($Command) on the following computers: $($ListOfComputers -join ",")" -LogName "Remote Command History" -Title "Commands run on remote computers"
        foreach($computer in $ListOfComputers) {
            if ((Get-OperatingSystem -Computer $computer) -eq "Windows"){
                Start-SessionWithCommand -Computer $computer -Command $Command -Credential $Credential -PushCommand
            } else {
                if (($PSBoundParameters.ContainsKey("SSHAccount") -eq $false) -and ($PSBoundParameters.ContainsKey("LinuxCommand") -eq $false)){
                    Write-Warning "No Linux Parameters specified, skipping $computer, 1"
                    continue
                } else {
                    Invoke-SSHCommand -Computer $computer -Command $LinuxCommand
                }
            }
        }
    } elseif ($CustomCmdlet -and $ComputerName) {
        if ((Get-OperatingSystem -Computer $ComputerName) -eq "Windows"){
            Start-SessionWithCommand -Computer $ComputerName -Command $Command -Credential $Credential -PushCommand
        }
    } elseif ($ListOfComputers) {
        foreach($computer in $ListOfComputers) {
            if ((Get-OperatingSystem -Computer $computer) -eq "Windows") {
                Start-SessionWithCommand -Computer $computer -Command $Command -Credential $Credential -PushCommand
            } else {
                if (($PSBoundParameters.ContainsKey("SSHAccount") -eq $false)){
                    Write-Warning "No Linux Parameters specified, skipping $computer, 1"
                    continue
                } else {
                    if (($PSBoundParameters.ContainsKey("LinuxScriptPath") -eq $true)) {
                        Invoke-SSHScript -Computer $computer -AccountName $SSHAccount -ScriptPath $LinuxScriptPath
                    } else {
                        Invoke-SSHCommand -Computer $computer -Command $LinuxCommand
                    }
                }
            }
        }
    } else {
        if ((Get-OperatingSystem -Computer $ComputerName) -like "Windows") {
            Start-SessionWithCommand -Computer $ComputerName -Command $Command -Credential $Credential
        } else {
            if (($PSBoundParameters.ContainsKey("SSHAccount") -eq $false) -and ($PSBoundParameters.ContainsKey("LinuxCommand") -eq $false)){
                Write-Host $computer
                Write-Warning "No Linux Parameters specified, skipping $ComputerName, 3"
                continue
            } else {
                if (($PSBoundParameters.ContainsKey("LinuxScriptPath") -eq $true)) {
                    Invoke-SSHScript -Computer $ComputerName -AccountName $SSHAccount -ScriptPath $LinuxScriptPath
                } else {
                    Invoke-SSHCommand -Computer $ComputerName -Command $LinuxCommand
                }
            }
        }
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

function Get-SecurePassword {
    $arrayOfPasswords = New-Object System.Collections.ArrayList
    foreach($number in 1..100){
        $add = Get-SecureString -Salt -AmountOfCharacters 15
        $arrayOfPasswords.Add($add) > $null
    }
    return ($arrayOfPasswords | Get-Random)
}

function Get-SecureWindowsLocalAccount {
    param(
        $AccountName,
        $NewAccountName
    )
    $password = Get-SecurePassword
    Rename-LocalUser -Name $AccountName -NewName $NewAccountName
    Set-LocalUser -Name $NewAccountName -Password $password
    Disable-LocalUser -Name $NewAccountName
}

function Get-WindowsComputerInformation {
    param(
        [parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential] $Credential
    )
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
        Get-ActiveDirectoryEnumeration
        } else {
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
        }   
}

function Get-LinuxComputerInformation {
    $scriptPath = "$($env:USERPROFILE)\Desktop\CIC-Scripts\Linux\Modules\LinuxEnumeration.sh"
    $scriptResults = Invoke-SSHScript -Computer $computer -ScriptPath $scriptPath
    $scriptResults > "$($env:USERPROFILE)\Desktop\Inventory\$computer\$computer-Enumeration.txt"
}

function Get-InventoryDirectoryStructure {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [string[]]$ListOfComputers
    )
    if(!(Test-Path -Path "$($env:USERPROFILE)\Desktop\Inventory")){
        Write-Host "Creating the Inventory directory" -ForegroundColor Green
        New-Item -Path "$($env:USERPROFILE)\Desktop" -ItemType "Directory" -Name "Inventory" | Out-Null
    }
    foreach ($computer in $ListOfComputers){
        if (!(Test-Path -Path "$($env:USERPROFILE)\Desktop\Inventory\$computer")) {
            Write-Host "Creating a directory for: $computer" -ForegroundColor Green
            New-Item -Path  "$($env:USERPROFILE)\Desktop\Inventory" -ItemType "Directory" -Name "$computer" | Out-Null
        }
    }
}

function Group-ComputerAndTakeInventory {
    param (
        [Parameter(Mandatory=$true)]
        [System.Array] $Computers,
        [Parameter(Mandatory=$true)]
        [System.Management.Automation.PSCredential] $Credential,
        [Parameter(Mandatory=$false)]
        $LinuxPemKey
    )
    foreach($computer in $computers){
        Write-Host "#----- Collecting Inventory on: $computer -----#" -ForegroundColor DarkBlue -BackgroundColor Yellow
        if ((Get-OperatingSystem -Computer $computer) -eq "Windows") {
            if ($env:COMPUTERNAME -eq $computer) {
                Write-Host "Identified $computer is a Windows Machine and the local machine, running local commands to gather network inventory" -ForegroundColor Green
                Get-WindowsComputerInformation -Credential $Credential
            } else {
                Write-Host "Identified $computer is a Windows Machine and not the local machine, running remote command to gather network inventory" -ForegroundColor Green
                $remoteComputerType = Invoke-RemoteComputersCommand -ComputerName $computer -Command "(Get-CimInstance -ClassName Win32_OperatingSystem).ProductType" -Credential $Credential
                #Per the Microsoft technical documentation, a computer type of 1 is a workstation, 2 is a domain controller, and three is a server
                if (($remoteComputerType -eq 1) -or ($remoteComputerType -eq 3)) {
                    Get-WindowsComputerInformation -Credential $Credential
                }
            }
    } else {
        Write-Host "Determined the remote machine is a Linux machine" -ForegroundColor Green
        Write-Host "Running remote commands to gather network information"
        Get-LinuxComputerInformation
        }
    }
}

Export-ModuleMember -Function *