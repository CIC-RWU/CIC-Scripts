$dir=$PWD.Path

#Check to make sure the script is running with elevated privliges

Write-Host "Checking for elevated permissions..."
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
	[Security.Principal.WindowsBuiltInRole] "Administrator")) {
	Write-Warning "Insufficient permissions to run this script. Open the PowerShell console as an administrator and run this script again."
	return "Run with Administrative Privs Please!!!!!!!!!"
}
else {
	Write-Host "Code is running as administrator — go on executing the script..." -ForegroundColor Green
}


function check_passwd() {
	if (Test-Path nonauth_users.txt) {
		Remove-Item nonauth_users.txt
		New-Item nonauth_users.txt | Out-Null
	}
	else {
		New-Item nonauth_users.txt | Out-Null
	}

	$names = @()
	$badusers = @()
	foreach($line in Get-Content $args[0]) {
		$names += $line
	}
	$accounts = $(Get-LocalUser -Name *).Name
	Write-Output $names
	foreach ($account in $accounts) {
		$authed = "N"
		foreach ($name in $names) {
			if ($account -eq $name) {
				$authed = "Y"
			}
		}
		if ($authed -eq "N") {
			Write-Output $account >> .\nonauth_users.txt
			$badusers += $account
		}
	}

	Write-Host "The Unauthorized Users Include:"
	for ($i = 0; $i -lt $badusers.length; $i ++) {
		Write-Host $badusers[$i]
	}

	$delusers_prompt = Read-Host -Prompt "Do you want to delete those users (y/n)?"
	if ($delusers_prompt -eq "y") {
		foreach ($delname in $badusers) {
			Remove-LocalUser -Name $delname
		}
	}
	
	$null, $args = $args
}

#Prompts the user for the name of the authorized users list (Default: users)
function get_auth_list() {
	$auth_list = Read-Host "Authorized Users List File [Add + to end of name if admin] (Default: users.txt): "
	if (!$auth_list) {
		$auth_list = "users.txt"
	}
	$auth_users = @()
	$admins = @()

	foreach ($name in Get-Content $dir\$auth_list) {
		if ($name -Match "+") {
			$name = $string -replace “.$”
			$admins.Add($name)
		}
		$auth_users.Add($name)
	}

	check_passwd $auth_users
}


#Manual user and group edits
Function usersMsc() {
    lusrmgr.msg
}

#Set password policy
Function pwPol() {
    #remember 24 pws, max age 60 days, min age 1 day, min length 12 chars, lockout after 5 fails, lockout for 30 minutes, observation window is 30 minutes
    net accounts /UniquePw:24 /MaxPwAge:60 /MinPwAge:1 /MinPwLen:12 /LockoutThreshold:5 /LockoutWindow:30 /LockoutDuration:30
}

#Rename and disable Guest
Function renameGuest() {
	Disable-LocalUser -Name "Guest"
	$guestAccount = Get-WMIObject Win32_UserAccount -Filter "Name='Guest'"
	$guestAccount.Rename("guestBOI")
}

#Rename and disable Admin
Function renameAdmin() {
	if ($env:UserName -eq "Administrator") {
		Write-Host "Not disabling or renaming Administrator, because YOU are Administrator"
	}
	else {
		Disable-LocalUser -Name "Administrator"
		$guestAccount = Get-WMIObject Win32_UserAccount -Filter "Name='Administrator'"
		$guestAccount.Rename("adminBOI")
	}
}



#Change all passwords but currently logged in user
Function changePWs() {
    	Get-WmiObject win32_useraccount | Foreach-object {
			if ($_.Name -ne $env:UserName) {
				([adsi]("WinNT://"+$_.caption).replace("\","/")).SetPassword("Asecurepassword123!") 
			} 
		}
}

#View administrators
Function viewAdmins() {
    net localgroup Administrators
}

#Open up secpol.msc for manual security policies
Function openSecpol() {
    secpol.msc
}

#Enable all audit policies
Function auditAll() {
    auditpol /set /category:* /success:enable /failure:enable
}

#Check run keys for backdoor startup execution
Function checkRKs() {
    #local machine
	    reg query hklm\Software\Microsoft\Windows\CurrentVersion\Run #priority
	#current user
	    reg query hkcu\Software\Microsoft\Windows\CurrentVersion\Run #priority
	#users
	    reg query hku\Software\Microsoft\Windows\CurrentVersion\Run
	#current config
	    reg query hkcc\Software\Microsoft\Windows\CurrentVersion\Run
	#classes root
	    reg query hkcr\Software\Microsoft\Windows\CurrentVersion\Run
	#Userinit key
	    reg query HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit
}

#Manually check the firewall settings
Function firewallGUI() {
    firewall.cpl
}

#Enable all firewall profiles
Function enableFirewall() {
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
}

Function configureFirewall() {
    Set-NetFirewallProfile -DefaultInboundAction Block -DefaultOutboundAction Allow -NotifyOnListen True -AllowUnicastResponseToMulticast True -LogFileName %SystemRoot%\System32\LogFiles\Firewall\pfirewall.log
    #Set network profile to public for most scrutiny
    Set-NetConnectionProfile -NetworkCategory Public
    #Disable network discovery
    netsh advfirewall firewall set rule group="Network Discovery" new enable=No
    #Disable file and printer sharing
    netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=No
}

#Copy the hosts file for inspection
Function hostsFile() {
    New-Item -Path C:\Users\$user\Desktop\hosts -ItemType directory
	Get-ChildItem -Path "C:\Windows\System32\drivers\etc\hosts" | Copy-Item -Destination C:\Users\$user\Desktop\hosts
    #Read the hosts file
    Get-ChildItem -Path "C:\Windows\System32\drivers\etc\hosts" | Get-Content
}

#Flush DNS
Function flushDNS() {
    ipconfig /flushdns
}

#SMB Share management
Function smbShares() {
   		#Delete shares
		net share C$ /delete
		net share ADMIN$ /delete
    	#View shares in GUI (only $IPC leftover)
		fsmgmt.msc
}

#Check for netcat backdoor
Function netcatCheck() {
    #All listening ports
    netstat -naob | select-string -context 0,1 "LISTENING"
    #Startup programs
    wmic startup list full
    #nc.exe specifically
    netstat -naob | select-string -context 1,0 "\[nc.exe\]"
}

#Automatic Updates
Function autoUpdates() {
    reg add "HKLM\SOFTWARE\Microsoft\WINDOWS\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions /t REG_DWORD /d 3 /f
}

#Firewall block common ports of services we probably don't want
Function firewallRules() {
	New-NetFirewallRule -DisplayName "sshTCP" -Direction Inbound -LocalPort 22 -Protocol TCP -Action Block #ssh
	New-NetFirewallRule -DisplayName "ftpTCP" -Direction Inbound -LocalPort 21 -Protocol TCP -Action Block #ftp
	New-NetFirewallRule -DisplayName "telnetTCP" -Direction Inbound -LocalPort 23 -Protocol TCP -Action Block #telnet
	New-NetFirewallRule -DisplayName "SMTPTCP" -Direction Inbound -LocalPort 25 -Protocol TCP -Action Block #SMTP
	New-NetFirewallRule -DisplayName "POP3TCP" -Direction Inbound -LocalPort 110 -Protocol TCP -Action Block #POP3
	New-NetFirewallRule -DisplayName "SNMPTCP" -Direction Inbound -LocalPort 161 -Protocol TCP -Action Block #SNMP
}

#Secure? Registry hacks
Function regEdit() {
	#Turns on UAC
	reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 1 /f
	#Restrict CD ROM drive
	reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AllocateCDRoms /t REG_DWORD /d 1 /f
	#Automatic Admin logon
	reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_DWORD /d 0 /f
	#Logon message text
	Set-Variable /p body=Please enter logon text: 
		reg ADD "HKLM\SYSTEM\microsoft\Windwos\CurrentVersion\Policies\System\legalnoticetext" /v LegalNoticeText /t REG_SZ /d "%body%"
	#Logon message title bar
	Set-Variable /p subject=Please enter the title of the message: 
		reg ADD "HKLM\SYSTEM\microsoft\Windwos\CurrentVersion\Policies\System\legalnoticecaption" /v LegalNoticeCaption /t REG_SZ /d "%subject%"
	#Wipe page file from shutdown
	reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v ClearPageFileAtShutdown /t REG_DWORD /d 1 /f
	#Disallow remote access to floppie disks
	reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AllocateFloppies /t REG_DWORD /d 1 /f
	#Prevent print driver installs 
	reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" /v AddPrinterDrivers /t REG_DWORD /d 1 /f
	#Limit local account use of blank passwords to console
	reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f
	#Auditing access of Global System Objects
	reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v auditbaseobjects /t REG_DWORD /d 1 /f
	#Auditing Backup and Restore
	reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v fullprivilegeauditing /t REG_DWORD /d 1 /f
	#Do not display last user on logon
	reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v dontdisplaylastusername /t REG_DWORD /d 1 /f
	#UAC setting (Prompt on Secure Desktop)
	reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop /t REG_DWORD /d 1 /f
	#Enable Installer Detection
	reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableInstallerDetection /t REG_DWORD /d 1 /f
	#Undock without logon
	reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v undockwithoutlogon /t REG_DWORD /d 0 /f
	#Maximum Machine Password Age
	reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v MaximumPasswordAge /t REG_DWORD /d 15 /f
	#Disable machine account password changes
	reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v DisablePasswordChange /t REG_DWORD /d 1 /f
	#Require Strong Session Key
	reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v RequireStrongKey /t REG_DWORD /d 1 /f
	#Require Sign/Seal
	reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v RequireSignOrSeal /t REG_DWORD /d 1 /f
	#Sign Channel
	reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v SignSecureChannel /t REG_DWORD /d 1 /f
	#Seal Channel
	reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v SealSecureChannel /t REG_DWORD /d 1 /f
	#Don't disable CTRL+ALT+DEL even though it serves no purpose
	reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v DisableCAD /t REG_DWORD /d 0 /f 
	#Restrict Anonymous Enumeration #1
	reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v restrictanonymous /t REG_DWORD /d 1 /f 
	#Restrict Anonymous Enumeration #2
	reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v restrictanonymoussam /t REG_DWORD /d 1 /f 
	#Idle Time Limit - 45 mins
	reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v autodisconnect /t REG_DWORD /d 45 /f 
	#Require Security Signature - Disabled pursuant to checklist
	reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v enablesecuritysignature /t REG_DWORD /d 0 /f 
	#Enable Security Signature - Disabled pursuant to checklist
	reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v requiresecuritysignature /t REG_DWORD /d 0 /f 
	#Disable Domain Credential Storage
	reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v disabledomaincreds /t REG_DWORD /d 1 /f 
	#Don't Give Anons Everyone Permissions
	reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v everyoneincludesanonymous /t REG_DWORD /d 0 /f 
	#SMB Passwords unencrypted to third party
	reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanWorkstation\Parameters /v EnablePlainTextPassword /t REG_DWORD /d 0 /f
	#Null Session Pipes Cleared
	reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v NullSessionPipes /t REG_MULTI_SZ /d "" /f
	#remotely accessible registry paths cleared
	reg ADD HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedExactPaths /v Machine /t REG_MULTI_SZ /d "" /f
	#remotely accessible registry paths and sub-paths cleared
	reg ADD HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedPaths /v Machine /t REG_MULTI_SZ /d "" /f
	#Restict anonymous access to named pipes and shares
	reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v NullSessionShares /t REG_MULTI_SZ /d "" /f
	#Allow to use Machine ID for NTLM
	reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v UseMachineId /t REG_DWORD /d 0 /f
	#Enables DEP
	bcdedit.exe /set {current} nx AlwaysOn
}


#Disable bad features
Function disableFeatures() {
	dism /online /disable-feature /featurename:IIS-WebServerRole
	dism /online /disable-feature /featurename:IIS-WebServer
	dism /online /disable-feature /featurename:IIS-CommonHttpFeatures
	dism /online /disable-feature /featurename:IIS-HttpErrors
	dism /online /disable-feature /featurename:IIS-HttpRedirect
	dism /online /disable-feature /featurename:IIS-ApplicationDevelopment
	dism /online /disable-feature /featurename:IIS-NetFxExtensibility
	dism /online /disable-feature /featurename:IIS-NetFxExtensibility45
	dism /online /disable-feature /featurename:IIS-HealthAndDiagnostics
	dism /online /disable-feature /featurename:IIS-HttpLogging
	dism /online /disable-feature /featurename:IIS-LoggingLibraries
	dism /online /disable-feature /featurename:IIS-RequestMonitor
	dism /online /disable-feature /featurename:IIS-HttpTracing
	dism /online /disable-feature /featurename:IIS-Security
	dism /online /disable-feature /featurename:IIS-URLAuthorization
	dism /online /disable-feature /featurename:IIS-RequestFiltering
	dism /online /disable-feature /featurename:IIS-IPSecurity
	dism /online /disable-feature /featurename:IIS-Performance
	dism /online /disable-feature /featurename:IIS-HttpCompressionDynamic
	dism /online /disable-feature /featurename:IIS-WebServerManagementTools
	dism /online /disable-feature /featurename:IIS-ManagementScriptingTools
	dism /online /disable-feature /featurename:IIS-IIS6ManagementCompatibility
	dism /online /disable-feature /featurename:IIS-Metabase
	dism /online /disable-feature /featurename:IIS-HostableWebCore
	dism /online /disable-feature /featurename:IIS-StaticContent
	dism /online /disable-feature /featurename:IIS-DefaultDocument
	dism /online /disable-feature /featurename:IIS-DirectoryBrowsing
	dism /online /disable-feature /featurename:IIS-WebDAV
	dism /online /disable-feature /featurename:IIS-WebSockets
	dism /online /disable-feature /featurename:IIS-ApplicationInit
	dism /online /disable-feature /featurename:IIS-ASPNET
	dism /online /disable-feature /featurename:IIS-ASPNET45
	dism /online /disable-feature /featurename:IIS-ASP
	dism /online /disable-feature /featurename:IIS-CGI 
	dism /online /disable-feature /featurename:IIS-ISAPIExtensions
	dism /online /disable-feature /featurename:IIS-ISAPIFilter
	dism /online /disable-feature /featurename:IIS-ServerSideIncludes
	dism /online /disable-feature /featurename:IIS-CustomLogging
	dism /online /disable-feature /featurename:IIS-BasicAuthentication
	dism /online /disable-feature /featurename:IIS-HttpCompressionStatic
	dism /online /disable-feature /featurename:IIS-ManagementConsole
	dism /online /disable-feature /featurename:IIS-ManagementService
	dism /online /disable-feature /featurename:IIS-WMICompatibility
	dism /online /disable-feature /featurename:IIS-LegacyScripts
	dism /online /disable-feature /featurename:IIS-LegacySnapIn
	dism /online /disable-feature /featurename:IIS-FTPServer
	dism /online /disable-feature /featurename:IIS-FTPSvc
	dism /online /disable-feature /featurename:IIS-FTPExtensibility
	dism /online /disable-feature /featurename:TFTP
	dism /online /disable-feature /featurename:TelnetClient
	dism /online /disable-feature /featurename:TelnetServer
	dism /online /disable-feature /featurename:"SMB1Protocol"
	Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
}

#Start and enable good services
Function enableGoodSvcs() {
    cmd.exe /c 'sc start wuauserv'
    cmd.exe /c 'sc config wuauserv start= auto'
    cmd.exe /c 'sc start EventLog'
    cmd.exe /c 'sc config EventLog start= auto'
    cmd.exe /c 'sc start MpsSvc'
    cmd.exe /c 'sc config MpsSvc start= auto'
    cmd.exe /c 'sc start WinDefend'
    cmd.exe /c 'sc config WinDefend start= auto'
    cmd.exe /c 'sc start WdNisSvc'
    cmd.exe /c 'sc config WdNisSvc start= auto'
    cmd.exe /c 'sc start Sense'
    cmd.exe /c 'sc config Sense start= auto'
    cmd.exe /c 'sc start Schedule'
    cmd.exe /c 'sc config Schedule start= auto'
    cmd.exe /c 'sc start SCardSvr'
    cmd.exe /c 'sc config SCardSvr start= auto'
    cmd.exe /c 'sc start ScDeviceEnum'
    cmd.exe /c 'sc config ScDeviceEnum start= auto'
    cmd.exe /c 'sc start SCPolicySvc'
    cmd.exe /c 'sc config SCPolicySvc start= auto'
    cmd.exe /c 'sc start wscsvc'
    cmd.exe /c 'sc config wscsvc start= auto'
}

#Stop and disable bad services
Function disableBadSvcs() {
    cmd.exe /c 'sc stop tlntsvr'
	cmd.exe /c 'sc config tlntsvr start= disabled'
	cmd.exe /c 'sc stop msftpsvc'
	cmd.exe /c 'sc config msftpsvc start= disabled'
	cmd.exe /c 'sc stop snmptrap'
	cmd.exe /c 'sc config snmptrap start= disabled'
	cmd.exe /c 'sc stop SNMP'
	cmd.exe /c 'sc config SNMP start= disabled'
	cmd.exe /c 'sc stop ssdpsrv'
	cmd.exe /c 'sc config ssdpsrv start= disabled'
	cmd.exe /c 'sc stop termservice'
	cmd.exe /c 'sc config termservice start= disabled'
	cmd.exe /c 'sc stop sessionenv'
	cmd.exe /c 'sc config sessionenv start= disabled'
	#cmd.exe /c 'sc stop remoteregistry'
	#cmd.exe /c 'sc config remoteregistry start= disabled'
	cmd.exe /c 'sc stop Messenger'
	cmd.exe /c 'sc config Messenger start= disabled'
	cmd.exe /c 'sc stop upnphos'
   	cmd.exe /c 'sc config upnphos start= disabled'
	cmd.exe /c 'sc stop WAS'
	cmd.exe /c 'sc config WAS start= disabled'
	cmd.exe /c 'sc stop RemoteAccess'
	cmd.exe /c 'sc config RemoteAccess start= disabled'
	cmd.exe /c 'sc stop mnmsrvc'
	cmd.exe /c 'sc config mnmsrvc start= disabled'
	cmd.exe /c 'sc stop NetTcpPortSharing'
	cmd.exe /c 'sc config NetTcpPortSharing start= disabled'
	cmd.exe /c 'sc stop RasMan'
	cmd.exe /c 'sc config RasMan start= disabled'
	cmd.exe /c 'sc stop TabletInputService'
	cmd.exe /c 'sc config TabletInputService start= disabled'
	cmd.exe /c 'sc stop RpcSs'
	cmd.exe /c 'sc config RpcSs start= disabled'
	cmd.exe /c 'sc stop SENS'
	cmd.exe /c 'sc config SENS start= disabled'
	cmd.exe /c 'sc stop EventSystem'
	cmd.exe /c 'sc config EventSystem start= disabled'
	cmd.exe /c 'sc stop XblAuthManager'
	cmd.exe /c 'sc config XblAuthManager start= disabled'
	cmd.exe /c 'sc stop XblGameSave'
	cmd.exe /c 'sc config XblGameSave start= disabled'
	cmd.exe /c 'sc stop XboxGipSvc'
	cmd.exe /c 'sc config XboxGipSvc start= disabled'
	cmd.exe /c 'sc stop xboxgip'
	cmd.exe /c 'sc config xboxgip start= disabled'
	cmd.exe /c 'sc stop xbgm'
	cmd.exe /c 'sc config xbgm start= disabled'
	cmd.exe /c 'sc stop SysMain'
	cmd.exe /c 'sc config SysMain start= disabled'
	cmd.exe /c 'sc stop seclogon'
	cmd.exe /c 'sc config seclogon start= disabled'
	cmd.exe /c 'sc stop TapiSrv'
	cmd.exe /c 'sc config TapiSrv start= disabled'
	cmd.exe /c 'sc stop p2pimsvc'
	cmd.exe /c 'sc config p2pimsvc start= disabled'
	cmd.exe /c 'sc stop simptcp'
	cmd.exe /c 'sc config simptcp start= disabled'
	cmd.exe /c 'sc stop fax'
	cmd.exe /c 'sc config fax start= disabled'
	cmd.exe /c 'sc stop iprip'
	cmd.exe /c 'sc config iprip start= disabled'
	cmd.exe /c 'sc stop ftpsvc'
	cmd.exe /c 'sc config ftpsvc start= disabled'
	cmd.exe /c 'sc stop RasAuto'
	cmd.exe /c 'sc config RasAuto start= disabled'
	cmd.exe /c 'sc stop W3svc'
	cmd.exe /c 'sc config W3svc start= disabled'
	cmd.exe /c 'sc stop Smtpsvc'
	cmd.exe /c 'sc config Smtpsvc start= disabled'
	cmd.exe /c 'sc stop Dfs'
	cmd.exe /c 'sc config Dfs start= disabled'
	cmd.exe /c 'sc stop TrkWks'
	cmd.exe /c 'sc config TrkWks start= disabled'
	cmd.exe /c 'sc stop MSDTC'
	cmd.exe /c 'sc config MSDTC start= disabled'
	cmd.exe /c 'sc stop ERSvc'
	cmd.exe /c 'sc config ERSvc start= disabled'
	cmd.exe /c 'sc stop NtFrs'
	cmd.exe /c 'sc config NtFrs start= disabled'
	cmd.exe /c 'sc stop Iisadmin'
	cmd.exe /c 'sc config Iisadmin start= disabled'
	cmd.exe /c 'sc stop IsmServ'
	cmd.exe /c 'sc config IsmServ start= disabled'
	cmd.exe /c 'sc stop WmdmPmSN'
	cmd.exe /c 'sc config WmdmPmSN start= disabled'
	cmd.exe /c 'sc stop helpsvc'
	cmd.exe /c 'sc config helpsvc start= disabled'
	cmd.exe /c 'sc stop Spooler'
	cmd.exe /c 'sc config Spooler start= disabled'
	cmd.exe /c 'sc stop RDSessMgr'
	cmd.exe /c 'sc config RDSessMgr start= disabled'
	cmd.exe /c 'sc stop RSoPProv'
	cmd.exe /c 'sc config RSoPProv start= disabled'
	cmd.exe /c 'sc stop SCardSvr'
	cmd.exe /c 'sc config SCardSvr start= disabled'
	cmd.exe /c 'sc stop lanmanserver'
	cmd.exe /c 'sc config lanmanserver start= disabled'
	cmd.exe /c 'sc stop Sacsvr'
	cmd.exe /c 'sc config Sacsvr start= disabled'
	cmd.exe /c 'sc stop TermService'
	cmd.exe /c 'sc config TermService start= disabled'
	cmd.exe /c 'sc stop uploadmgr'
	cmd.exe /c 'sc config uploadmgr start= disabled'
	cmd.exe /c 'sc stop VDS'
	cmd.exe /c 'sc config VDS start= disabled'
	cmd.exe /c 'sc stop VSS'
	cmd.exe /c 'sc config VSS start= disabled'
	cmd.exe /c 'sc stop WINS'
	cmd.exe /c 'sc config WINS start= disabled'
	cmd.exe /c 'sc stop CscService'
	cmd.exe /c 'sc config CscService start= disabled'
	cmd.exe /c 'sc stop hidserv'
	cmd.exe /c 'sc config hidserv start= disabled'
	cmd.exe /c 'sc stop IPBusEnum'
	cmd.exe /c 'sc config IPBusEnum start= disabled'
	cmd.exe /c 'sc stop PolicyAgent'
	cmd.exe /c 'sc config PolicyAgent start= disabled'
	#cmd.exe /c 'sc stop SCPolicySvc'
	#cmd.exe /c 'sc config SCPolicySvc start= disabled'
	cmd.exe /c 'sc stop SharedAccess'
	cmd.exe /c 'sc config SharedAccess start= disabled'
	cmd.exe /c 'sc stop SSDPSRV'
	cmd.exe /c 'sc config SSDPSRV start= disabled'
	cmd.exe /c 'sc stop Themes'
	cmd.exe /c 'sc config Themes start= disabled'
	cmd.exe /c 'sc stop upnphost'
	cmd.exe /c 'sc config upnphost start= disabled'
	cmd.exe /c 'sc stop nfssvc'
	cmd.exe /c 'sc config nfssvc start= disabled'
	cmd.exe /c 'sc stop nfsclnt'
	cmd.exe /c 'sc config nfsclnt start= disabled'
	cmd.exe /c 'sc stop MSSQLServerADHelper'
	cmd.exe /c 'sc config MSSQLServerADHelper start= disabled'
	cmd.exe /c 'sc stop SharedAccess'
	cmd.exe /c 'sc config SharedAccess start= disabled'
	#cmd.exe /c 'sc stop UmRdpService'
	#cmd.exe /c 'sc config UmRdpService start= disabled'
	cmd.exe /c 'sc stop SessionEnv'
	cmd.exe /c 'sc config SessionEnv start= disabled'
	cmd.exe /c 'sc stop Server'
	cmd.exe /c 'sc config Server start= disabled'
	cmd.exe /c 'sc stop TeamViewer'
	cmd.exe /c 'sc config TeamViewer start= disabled'
	cmd.exe /c 'sc stop TeamViewer7'
	cmd.exe /c 'sc config start= disabled'
	cmd.exe /c 'sc stop HomeGroupListener'
	cmd.exe /c 'sc config HomeGroupListener start= disabled'
	cmd.exe /c 'sc stop HomeGroupProvider'
	cmd.exe /c 'sc config HomeGroupProvider start= disabled'
	cmd.exe /c 'sc stop AxInstSV'
	cmd.exe /c 'sc config AXInstSV start= disabled'
	cmd.exe /c 'sc stop Netlogon'
	cmd.exe /c 'sc config Netlogon start= disabled'
	cmd.exe /c 'sc stop lltdsvc'
	cmd.exe /c 'sc config lltdsvc start= disabled'
	cmd.exe /c 'sc stop iphlpsvc'
	cmd.exe /c 'sc config iphlpsvc start= disabled'
	cmd.exe /c 'sc stop AdobeARMservice'
	cmd.exe /c 'sc config AdobeARMservice start= disabled'
}

Function userAdministration() {
    $table = 
    "
    1. Local Users and Groups .msc
    2. 
    3. Password Policies
    4. Edit Users and Groups
    Type 'back'

    "
    while ($true) {
        Write-Output("What do you want to run?")
        $response = Read-Host($table)
        switch ($response)
            {
            1 {lusrmgr.msc}
            2 {"Passwords"}
            3 {"Option 3"}
            "back" {return "Going backwards!"}
            }
    }
}



Function main() {
    $table = 
    "
    1. User Administration
    2. Service Administration
    3. GPOs
    4. Registry Hacks
    5. Admin Intervention
    Type 'quit'

    "
    while ($true) {
        Write-Output("Welcome to Litch's script!")
        $response = Read-Host($table)
        switch ($response)
            {
            1 {userAdministration}
            2 {"Option 2"}
            3 {"Option 3"}
            "quit" {return "Quitting!"}
            }
    }
}
#main