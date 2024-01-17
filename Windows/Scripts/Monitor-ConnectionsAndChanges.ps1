Write-Host "Starting monitoring on $($env:COMPUTERNAME)"

while ($true) {
    Start-Sleep 5
    $initialSSHValue = Get-CimInstance -ClassName Win32_Process -Filter "Name = 'sshd.exe'" | Get-CimAssociatedInstance -Association Win32_SessionProcess | Get-CimAssociatedInstance -Association Win32_LoggedOnUser | Where-Object {$_.Name -ne 'SYSTEM'}
    if ($null -ne $initialSSHValue) {
        $initialSSHValue | ForEach-Object {
            Write-Warning "$($_.Name) has an active SSH session on $env:COMPUTERNAME"
        }
    } else {
        Write-Host "`n"
        Continue
    }
}