Write-Host "Starting monitoring on $($env:COMPUTERNAME)"

while ($true) {
    # Values to monitor
    $initialSSHValue = Get-CimInstance -ClassName Win32_Process -Filter "Name = 'sshd.exe'" | Get-CimAssociatedInstance -Association Win32_SessionProcess | Get-CimAssociatedInstance -Association Win32_LoggedOnUser | Where-Object {$_.Name -ne 'SYSTEM'}

    # Wait statement
    Start-Sleep 10

    # Redefining the values we are monitoring
    $checkSSHValue = Get-CimInstance -ClassName Win32_Process -Filter "Name = 'sshd.exe'" | Get-CimAssociatedInstance -Association Win32_SessionProcess | Get-CimAssociatedInstance -Association Win32_LoggedOnUser | Where-Object {$_.Name -ne 'SYSTEM'}

    if ($checkSSHValue -notlike $checkSSHValue) {
        Write-Warning "$($checkSSHValue.Name) has connected to $($env:COMPUTERNAME)"
    }
    


}