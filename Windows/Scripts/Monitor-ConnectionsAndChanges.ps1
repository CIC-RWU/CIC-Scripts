Write-Host "Starting monitoring on $($env:COMPUTERNAME)"

while ($true) {
    $initialSSHValue = Get-CimInstance -ClassName Win32_Process -Filter "Name = 'sshd.exe'" | Get-CimAssociatedInstance -Association Win32_SessionProcess | Get-CimAssociatedInstance -Association Win32_LoggedOnUser | Where-Object {$_.Name -ne 'SYSTEM'}
    Write-Warning "$($initialSSHValue.Name) has connected to $($env:COMPUTERNAME)"

}