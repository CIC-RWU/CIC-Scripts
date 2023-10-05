Import-Module "$PSScriptRoot\Modules\Enumeration.psm1"
Import-Module "$PSScriptRoot\Modules\Support.psm1"
Import-Module "$PSScriptRoot\Modules\Tools.psm1"

function Get-RemoteIPAddressInfo {
    param(
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$ComputerName,
        [parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]
        $Credential = $(Get-Credential)
    )
    if ($null -eq $Credential){
        $Credential = Get-Credential
    }
    $computerType = Get-ADComputer -Identity $ComputerName -Properties * | Select-Object -ExpandProperty OperatingSystem
    Write-Host $computerType
    if ($computerType -like "*Windows*") {
        $test = Invoke-RemoteComputersCommand -ComputerName $ComputerName -Credential $Credential -Command { "Get-RolesAndFeatures"}
        # $activeNic = Invoke-RemoteComputersCommand -ComputerName $ComputerName -Credential $Credential -Command { (Get-NetConnectionProfile | Select-Object -ExpandProperty InterfaceIndex)}
        # $ipInfo = Invoke-RemoteComputersCommand -ComputerName $ComputerName -Credential $Credential -Command { Get-NetIPAddress -InterfaceIndex $Using:activeNic -AddressFamily IPv4 | Select-Object -ExpandProperty IPAddress}
        # return $ipInfo
        return $test
    } else {
        if ($computerType -like "*linux*"){
            write-host "linux check works"
            continue
        }
    }
}