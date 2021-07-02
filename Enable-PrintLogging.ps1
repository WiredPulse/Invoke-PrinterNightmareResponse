if((Get-LogProperties 'Microsoft-windows-printservice/operational').enabled -eq $false){
    $logdeets  = Get-LogProperties 'Microsoft-windows-printservice/operational'
    $logdeets.enabled = $true
    Set-LogProperties -LogDetails $logdeets
}


