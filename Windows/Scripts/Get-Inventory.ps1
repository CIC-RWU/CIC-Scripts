Param (
    [String]$ListOfComputers
)

$creds = Get-Credential -Message "Enter a set of domain administrator credentials"
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
Import-Module ..\Modules\Support.psm1, ..\Modules\Enumeration.psm1, ..\Modules\Tools.psm1
Get-Inventory -Credential $creds -ListOfComputers $ListOfComputers