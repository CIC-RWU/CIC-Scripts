<#
    .SYNOPSIS
        A collection of scripts and functions that will do recon on an unknown environment and then apply fixes to vulnerabilities it finds.
    .DESCRIPTION
        Conducts recon on Active Directory users, Security Groups, Who is apart of important security groups, and server roles installed. It will also return general 
        server info. The fixes it applies are mostly CAT I registry fixes with some other CAT I issues mixed in. It mostly targets Windows Server 2016.

        These set of scripts are portable.

        Created by: Orlando Yeo, Roger William University.
        Last Updated by: Orlando Yeo, Roger Williams University.

        Version: 1.0 - Script Creation  .
    .PARAMETER OnlyRecon
        Only Conducts recon on the enviornment and does not alter system.
    .NOTES 
        Script must be ran from the directory DomainHardening
    .EXAMPLE
        Only conducting recon: ./Harden-Server.ps1 -OnlyRecon
        Run script and alter system: ./Harden-Server.ps1
#>

#This is going to be painful

[CmdletBinding()]
param (
    [Parameter(Mandatory=$false)]
    [Switch]$OnlyRecon
)

if($OnlyRecon){
    Import-Module -Name $PSScriptRoot\Determine-Environment.ps1
}else {
    Import-Module -Name $PSScriptRoot\Determine-Environment.ps1
    Import-Module -Name $PSScriptRoot\Stig-Functions.ps1
    Write-ToVulnerabilityLog "Vulnerability Fixes That Have Been Applied: "
    Add-RegistryKeys
    Edit-ADSettings
    Edit-LocalSecurityPolicy
}