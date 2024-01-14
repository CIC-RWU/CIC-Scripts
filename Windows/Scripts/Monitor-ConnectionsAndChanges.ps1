Write-Host "Starting monitoring on $($env:COMPUTERNAME)"

while ($true) {
    # Values to monitor
    $initialSSHValue = Get-CimInstance -ClassName Win32_Process -Filter "Name = 'sshd.exe'" | Get-CimAssociatedInstance -Association Win32_SessionProcess | Get-CimAssociatedInstance -Association Win32_LoggedOnUser | Where-Object {$_.Name -ne 'SYSTEM'}

    # Redefining the values we are monitoring
    $checkSSHValue = Get-CimInstance -ClassName Win32_Process -Filter "Name = 'sshd.exe'" | Get-CimAssociatedInstance -Association Win32_SessionProcess | Get-CimAssociatedInstance -Association Win32_LoggedOnUser | Where-Object {$_.Name -ne 'SYSTEM'}

    # Comparing the two cim instance objects
    $compare = ((Compare-Object -ReferenceObject $initialSSHValue -DifferenceObject $checkSSHValue).InputObject.Name)

    if ($null -notlike $compare) {
        Write-Warning "$compare has connected to $($env:COMPUTERNAME)"
    }
}