
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

    # An if statement to determine if there a log file present in the log directory, this directory defaults to the users desktop\logs
    if (!(Test-Path -Path "$($LogDirectory)")){
        New-Item -ItemType Directory -Name "Logs" -Path "$LogDirectory" | Out-Null
    }

    # An if statement to determine if there is a log file present with the name that was provided when calling this function
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

    # The below two lines are used to format the spacing of the logs and content, so that I could read them easier
    $logFileSpace = "       -"
    $logFileSeparator = "------------------------------------------------------------------------"
    
    # An if statement to determine if a log file exists at the path, calls a function to build that if it does not exist
    if (!(Test-Path -Path "$LogDirectory\$LogName.log")){
        New-LogFile -Name $LogName
    }

    # A scoped variable declaration for the title of the section of the log
    $Script:titleCheck = $false
    
    <#
        The if statement below determines if the log contains the Title
        The if statement will loop through the lines of the text file and determine if any lines match the title
        If the above statement is the case the script will then set the titleCheck variable to true
    #>
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
    
    # The below if statement will write a header to the log if the titleCheck variable is false
    if ($Script:titleCheck -eq $false) {
        Add-Content -Path "$LogDirectory\$LogName.log" -Value ("#---------------------- $($Title.ToUpper()) ----------------------#")
    }
    
    <#
        I'm sure there is a cleaner way to do the next thing but the if/else statement below is to prevent errors when the script encounters 
        errors when the content being written is null. Additionally, the option to provide an in-your-face content separator. I think I did
        this because I was using this to review active direcotry but, again, there's a better way to do this
    #>    
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

    # Variable to hold the CSV content
    $csvImport = Import-Csv -Path $InputFilePath

    # The below if/else statement handles the case of wanting to only learn information, honestly this may be better off being a 
    # If you have any interest in learning how this works please come and find Orlando Yeo, I do not want to type out the logic behind this, sorry
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
    This function will look for patterns in strings
.DESCRIPTION
    The function will review a string for different types of patterns, i.e., IP addresses or MAC addresses

    Created by: Orlando Yeo, Roger William University.
    Last Updated by: Orlando Yeo, Roger Williams University.

    Version: 1.0 - Script Creation.
.PARAMETER String
    Mandatory, this is the string to be reviewed
.PARAMETER IPAddress
    Non-mandatory, a switch to review the string for IP addresses
.PARAMETER MACAddress
    Non-mandatory, a switch to review the string for MAC Addresses
.NOTES
    This should probably be broken up into multiple functions for discoverability purposes
.EXAMPLE
    Get-DataFromString -String "hello this is a string with 192.168.69.420 and I need to just get the ip" -IPAddress
.Output
    Returns a refined string with only the information a person is looking for (hopefully)
#>

function Get-DataFromString {
    param(
        [parameter(Mandatory=$true)]
        [string]$String,
        [parameter(Mandatory=$false)]
        [switch]$IPAddress,
        [parameter(Mandatory=$false)]
        [switch]$MACAddress
    )
    
    # An if statement to use a regex statement to grab an IP address. Truthfully, I am not that talented with regex and this could be updated
    if ($IPAddress) {
        $refinedIP = Select-String -InputObject [string]$IPInfo -Pattern "\b(([01]?\d?\d|2[0-4]\d|25[0-5])\.){3}([01]?\d?\d|2[0-4]\d|25[0-5])\b" -AllMatches | ForEach-Object { $_.Matches} | Select-Object -ExpandProperty Value
        if ($null -ne $refinedIP) {
            return $refinedIP
        } else {
            Write-Warning "Unable to detect IP address in string"
        }
    }
    
    # An if statement for mac address that is not complete, damn I thought I did this
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

    <#
        The below variable takes the command you are running and just gets the base cmdlet. I.e., if you ran "Get-LocalUser -Name"
        you would be left with "Get-LocalUser"

        This is done because you need to check if a function, especially a custom defined cmdlet, is defined in the local PowerShell
        process. The script will exit if the function does not exist. Realistically, with how I've designed it custom cmdlets should
        not be caught here, but if a computer has PowerShell v2 I suspect this coudl catch things
    #>
    $baseCommand = $Command -split " " | Select-Object -First 1
    try {
        Get-Command -Name $baseCommand -ErrorAction Stop | Out-Null
    }
    catch {
        Write-Warning "Unable to import command, ensure your session contains the command you are attempting to run. Exiting script in 10 seconds"
        Start-Sleep 10
        Exit
    }

    # The below variable stores the cmdlet definition of the base command
    $functionToImport = Get-Command -Name $baseCommand
    
    # The below varible stores what will be pushed to the remote session, a here-string that is the command type and definition
    $remoteDefinition = @"
        $($functionToImport.CommandType) $baseCommand (){ $($functionToImport.Definition) }
"@
  
    <#
        The below couple varibles gather all the custom cmdlets that are present on the machine. I have hard coded these to be the three
        modules that I have created. The Support, Enumeration, and Tools modules. The allCustomCmdlets gets those modules. When you get 
        the module it returns as a hashtabale where the keys are the names of the custom cmdlets. It then attempts to verify that those
        exist in the session and it does the same here-string manipulation as above. Then the ending of the for loop and the this function
        will take the definitions and use invoke-command to push those to the specified remote session
    #>
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
    This function returns what type of an operating system a computer is
.DESCRIPTION
    The function takes a computer name and then searches Active Directory for the computer object, and tries to see if it can 
    glean the type of computer

    Created by: Orlando Yeo, Roger William University.
    Last Updated by: Orlando Yeo, Roger Williams University.

    Version: 1.0 - Script Creation.
.PARAMETER Computer
    The name of the computer
.NOTES
    This function kinda sucks and should do other things than just searching active directory
.EXAMPLE
    Get-OperatingSystem -Computer Yeet-PC
.Output
    string of computer name
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

<#
.SYNOPSIS
    The function runs a command on a Linux machine and returns the result
.DESCRIPTION
	The function will take a computer name of a Linux machine, an account name, and a command. The function then removes any new line
    characters and attempts to ssh and run that command

    Created by: Orlando Yeo, Roger William University.
    Last Updated by: Orlando Yeo, Roger Williams University.

    Version: 1.0 - Script Creation.
.PARAMETER Computer
    This parameter is the name of the target computer to run the SSH command on
.Parameter AccountName
    This is the account in which you want to SSH with
.Parameter command
    This is command you want to run on the Linux machine
.NOTES
    There is no error handling for this and is kind of a risky function but whatever
.EXAMPLE
    Invoke-SSHCommand -Computer "LinuxBOX" -AccountName "LinuxSucksAdmin:/" -Command "ip a"
.Output
    The result of bash commands in a string format
#>

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

<#
.SYNOPSIS
    This cmdlet runs an bash script on a Linux machine
.DESCRIPTION
    The cmdlet will take a computer name, an account name, and a path to a script. It then uses a shell to SSH to a computer and then
    run that script

    Created by: Orlando Yeo, Roger William University.
    Last Updated by: Orlando Yeo, Roger Williams University.

    Version: 1.0 - Script Creation.
.PARAMETER Computer
    The name of a Linux computer
.PARAMETER AccountName
    This is the account you wish to SSH to the Linux machine with
.PARAMETER ScriptPath
    This is the path to the bash script
.NOTES
    None
.EXAMPLE
    Invoke-SSHScript -Computer "LinuxPC" -AccountName "OrlandoAdmin" -ScriptPath "C:\Users\oyeo\Desktop\script.sh"
.Output
    Command on remote computer
#>

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

    # The below statement uses a command shell to run the ssh command below, ssh has quite a few options and some are nifty
    $command = & cmd.exe /C "ssh -t $AccountName@$Computer < $ScriptPath"
    return $command
}

<#
.SYNOPSIS
    Starts a WinRM session and executes the commands
.DESCRIPTION
    The function will take a computer name, a command, credentials, and a switch to push commands to a remote session. It will then 
    start a session with that computer and execute the commands. The function returns the results of those commands

    Created by: Orlando Yeo, Roger William University.
    Last Updated by: Orlando Yeo, Roger Williams University.

    Version: 1.0 - Script Creation.
.PARAMETER Computer
    The remote computer you wish to start a remote session with and execute commands on 
.PARAMETER Command
    This is a string version of the command you want to run. The string encompases all parts of the command, even variables
.PARAMETER Credential
    These are the credentials that have access to the remote computer
.PARAMETER PushCommand
    This switch specifies if you want to push the command to the remote session. This is used for custom commands
.NOTES
    None
.EXAMPLE
    Start-SessionWithCommand -Computer "OrlandoPC" -Command "Get-LocalUser | Select-Object Name, Description" -Credential $creds
    Start-SessionWithCommand -Computer "OrlandoPC" -Command "Get-MySuperCoolCmdlet" -Credential $creds -PushCommand
.Output
    Command on remote computer
#>

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

    <#
        The below if/else statement revolves around the PushCommand switch. If it's true, it uses another function to push the custom
        command to the remote computer and then it runs that on the remote machine. It will return the result of whatever that is. 
        If there is no switch it will just try to run the command on the remote machine and then return that. Additionally, it closes
        the WinRM session every time and does not leave sessions around
    #>
    if ($PushCommand) {

        # Creating a session with the remote computer
        $remoteSession = New-PSSession -ComputerName $Computer -Credential $Credential
        
        # Calling the function to push the command and definition to the remote session
        Push-CommandToRemoteSession -Command $Command -remoteSession $remoteSession
        
        # The below variable contains the result of running the custom command on the remote session
        $result = Invoke-Command -Session $remoteSession -ScriptBlock ([scriptblock]::Create($Command))
        
        # A line to remove the session, a security catch
        Remove-PSSession -Session $remoteSession
        return $result
    } else {
        $remoteSession = New-PSSession -ComputerName $ComputerName -Credential $Credential
        
        <#
            The following sets of commands do the same thing as above, in where they attempt to run commands
            on a remote computer. Difference here is that they are builtin functions that come with PowerShell.
            There is some additional handling to determine if the remote session has the commands I am trying
            to run. This is a catch to compensate for different PowerShell versions. Here's an example: 
            Get-LocalUser exists in PSv5 but not PSv4. Well, I run that command all the time and need 
            to know if what is happening on the other end. So I break the command I am trying to run into the
            remote session, check if that exists, and then return an error message if it does not. Doing it this
            way will allow the script to continue running in a pretty fashion even though we have encountered 
            errors
        #>
        $baseCommand = $Command -split " " | Select-Object -First 1
        $refinedBaseCommand = $baseCommand.Replace("(", "")
        $testCommand = "Get-Command $refinedBaseCommand -ErrorAction SilentlyContinue"
        $testResults = Invoke-Command -Session $remoteSession -ScriptBlock ([scriptblock]::Create($testCommand))
        if ($null -eq $testResults) {
            Write-Warning "Unable to run $command on remote machine, there was no remote command definition. This may be a PowerShell Version issue"
        } else {
            $result = Invoke-Command -Session $remoteSession -ScriptBlock ([scriptblock]::Create($Command))
            Remove-PSSession -Session $remoteSession
            return $result        
        }
    }
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
        Write-Host "Running commands to gather network information, package information, service information, local user information, and scheduled task information`n" -ForegroundColor Green
        Write-Host "The above information is going to be written to a desktop folder`n" -ForegroundColor Green
        
        $computerIPInfo = Get-IPAddressInfo
        $computerIPInfo.GetEnumerator() | Select-Object Name, Value | Export-Csv -NoTypeInformation -Path "$($env:USERPROFILE)\Desktop\Inventory\$computer\$computer-Network Information.csv"
        
        $packageInformation = Get-Package | Select-Object Name, Version, ProviderName
        $packageInformation | Export-Csv -NoTypeInformation -Path "$($env:USERPROFILE)\Desktop\Inventory\$computer\$computer-Installed Programs.csv"

        $services = Get-Service | Select-Object Status, Name, DisplayName
        $services | Export-Csv -NoTypeInformation -Path "$($env:USERPROFILE)\Desktop\Inventory\$computer\$computer-Service Information.csv"
        
        $localUsers = Get-LocalUser | Select-Object Name, Enabled, Description
        $localUsers | Export-Csv -NoTypeInformation -Path "$($env:USERPROFILE)\Desktop\Inventory\$computer\$computer-Local Accounts.csv"
        
        $tasks = Get-AllScheduledTasks
        if ($null -ne $tasks) {
            $tasks | Export-Csv -NoTypeInformation -Path "$($env:USERPROFILE)\Desktop\Inventory\$computer\$computer-Scheduled Task Information.csv"
            }
        } else {
            Write-Host "Running remote commands to gather network information, package information, service information, local user information, and scheduled task information`n" -ForegroundColor Green
            Write-Host "The above information is going to be written to a desktop folder`n" -ForegroundColor Green
            
            $computerIPInfo = Invoke-RemoteComputersCommand -ComputerName $computer -Command "Get-IPAddressInfo" -Credential $Credential
            $computerIPInfo.GetEnumerator() | Select-Object Name, Value | Export-Csv -NoTypeInformation -Path "$($env:USERPROFILE)\Desktop\Inventory\$computer\$computer-Network Information.csv"
            
            $packageInformation = Invoke-RemoteComputersCommand -ComputerName $computer -Command "Get-Package | Select-Object Name, Version, ProviderName" -Credential $Credential
            $packageInformation | Export-Csv -NoTypeInformation -Path "$($env:USERPROFILE)\Desktop\Inventory\$computer\$computer-Installed Programs.csv"
            
            $services = Invoke-RemoteComputersCommand -ComputerName $computer -Command "Get-Service | Select-Object Status, Name, DisplayName" -Credential $Credential
            $services | Export-Csv -NoTypeInformation -Path "$($env:USERPROFILE)\Desktop\Inventory\$computer\$computer-Service Information.csv"
            
            $localUsers = Invoke-RemoteComputersCommand -ComputerName $computer -Command "Get-LocalUser | Select-Object Name, Enabled, Description" -Credential $Credential
            $localUsers | Export-Csv -NoTypeInformation -Path "$($env:USERPROFILE)\Desktop\Inventory\$computer\$computer-Local Accounts.csv"
            
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
        $LinuxPemKey # not implemented yet
    )
    foreach($computer in $computers){
        Write-Host "#----- Collecting Inventory on: $computer -----#" -ForegroundColor DarkBlue -BackgroundColor Yellow
        Write-Host "`n"
        if ($env:COMPUTERNAME -eq $computer) {
            Write-Host "Identified $computer is the local device and a Windows machine`n" -ForegroundColor Green
            $computerType = (Get-CimInstance -ClassName Win32_OperatingSystem).ProductType
            switch ($computerType) {
                1 {
                    Write-Host "Identified $computer is a Windows workstation, exiting scripts`n"
                    Write-Warning "Ensure you run these scripts on a Domain Controller`n"
                    Exit
                }
                2 {
                    Write-Host "Identified $computer is a Windows Domain Controller, running domain enumeration scripts`n" -ForegroundColor Green
                    Get-ActiveDirectoryEnumeration
                    Get-WindowsComputerInformation -Credential $Credential 
                }
                3 {
                    Write-Host "Identified $computer is a Server, exiting scripts`n" -ForegroundColor Green
                    Write-Warning "Ensure you run these scripts on a Domain Controller`n" -ForegroundColor Green
                    Exit
                }
            }
        } else {
            if ((Get-OperatingSystem -Computer $computer) -eq "Windows") {
                Write-Host "Identified $computer is a Windows machine and NOT the local machine`n" -ForegroundColor Green
                $remoteComputerType = Invoke-RemoteComputersCommand -ComputerName $computer -Command "(Get-CimInstance -ClassName Win32_OperatingSystem).ProductType" -Credential $Credential
                switch ($remoteComputerType) {
                    1 {
                        Write-Host "Identified $computer is a Windows workstation`n" -ForegroundColor Green
                        Get-WindowsComputerInformation -Credential $Credential
                    }
                    2 {
                        Write-Host "Identified $computer is a Windows Domain Controller`n" -ForegroundColor Green
                        Write-Host "In the event this is a weird environment, running the domain enumeration scripts on this machine`n" -ForegroundColor Green
                        Invoke-RemoteComputersCommand -ComputerName $computer -Command "Get-ActiveDirectoryEnumeration" -Credential $Credential
                        Get-WindowsComputerInformation -Credential $Credential
                        
                    }
                    3 {
                        Write-Host "Identified $computer is a Windows Server`n" -ForegroundColor Green
                        Get-WindowsComputerInformation -Credential $Credential
                    }
                }
            } else {
                Write-Host "Determined the remote machine is a Linux machine`n" -ForegroundColor Green
                Write-Host "Running remote commands to gather network information`n"
                Get-LinuxComputerInformation
            }
        }
    } 
}

Export-ModuleMember -Function *