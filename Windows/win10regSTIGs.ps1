
# $services = Get-Service SNMPTRAP  | Where-Object {$_.Status -eq "Stopped"}
# echo $services

# Registry Variables
If(Test-Path HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters)
{
    Set-ItemProperty -Path  HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\ -Name RestrictNullSessAccess 1
}
else{
    echo "Locate HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\"
}
If(Test-Path HLKM:\SYSTEM\CurrentControlSet\Control\Lsa\){
    Set-ItemProperty -Path HLKM:\SYSTEM\CurrentControlSet\Control\Lsa\ -Name RestrictAnonymous 1
    Set-ItemProperty -Path HLKM:\SYSTEM\CurrentControlSet\Control\Lsa\ -Name RestrictAnonymousSAM 1
    Set-ItemProperty -Path HLKM:\SYSTEM\CurrentControlSet\Control\Lsa\ -Name NoLMHash 1
    Set-ItemProperty -Path HLKM:\SYSTEM\CurrentControlSet\Control\Lsa\ -Name LMCompatibilityLevel 5

}
else {
    echo "Locate HLKM:\SYSTEM\CurrentControlSet\Control\Lsa\"    
}
If(Test-Path "HLKM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\"){
    Set-ItemProperty -Path "HLKM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\" -Name fAllowToGetHelp 0
}
else {
    echo "Locate HLKM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\"
}
If(Test-Path HLKM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\){
    Set-ItemProperty -Path HLKM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\ -Name NoAutorun 1
    Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer\ -Name NoDriveTypeAutoRun 255
}
else {
    echo "Locate HLKM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\"
}
If(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel\"){
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel\" -Name DisableExceptionChainValidation 0
}
else {
    echo "Locate HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel\"
}
if (Test-Path HLKM:\SOFTWARE\Policies\Microsoft\Windows\Installer\){
    Set-ItemProperty -Path HLKM:\SOFTWARE\Policies\Microsoft\Windows\Installer\ -Name AlwaysInstallElevated 0
}
else{
    echo "Locate HLKM:\SOFTWARE\Policies\Microsoft\Windows\Installer\"
}
If (Test-Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\){
    Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\ -Name AllowBasic 0 
}
else{
    echo "Locate HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\"
}
If(Test-Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\){
    Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\ -Name AllowBasic 0 
}  
else {
    echo "Locate HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\"
}
If(Test-Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\){
    Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\ -Name NoAutoplayfornonVolume 1
}
else{
    echo "Locate HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\"
}
# DEP OptOut
BCDEDIT /set "{current}" nx OptOut

Pause