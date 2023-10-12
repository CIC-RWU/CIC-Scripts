Import-Module "$PSScriptRoot\Modules\Enumeration.psm1"
Import-Module "$PSScriptRoot\Modules\Support.psm1"
Import-Module "$PSScriptRoot\Modules\Tools.psm1"
Set-ExecutionPolicy Bypass -Scope Process


$creds = Get-Credential
New-NetworkMap -Credential $creds