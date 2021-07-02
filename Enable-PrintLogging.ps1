if((Get-LogProperties 'Microsoft-windows-printservice/operational').enabled -eq $false){
    $logdeets  = Get-LogProperties 'Microsoft-windows-printservice/operational'
    $logdeets.enabled = $true
    Set-LogProperties -LogDetails $logdeets
}

Get-ItemProperty 'HKLM:\system\CurrentControlSet\Control\Print\Environments\Windows x64\Drivers\Version-3'

