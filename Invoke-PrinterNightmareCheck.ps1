<#
    .SYNOPSIS
        The current two POCs will write the DLL supplied during exploitatio to 'C:\Windows\System32\spool\drivers\x64\3' and to 
        'C:\Windows\System32\spool\drivers\x64\3\Old'. This code retrieves all unsigned DLLs in the first location checks if any are in the second 
        location. If a DLL is in both locations, that could be indicative of possible malicious activity.

    .LINK
        https://github.com/afwu/PrintNightmare
#>

$dll = Get-ChildItem C:\Windows\System32\spool\drivers\x64\3
$sigs = Get-AuthenticodeSignature $dll.fullname -ErrorAction SilentlyContinue
foreach($sig in $sigs){
    if($sig.status -ne "valid"){
        $unsigned += @($sig.path)
    }
}

$unsignedShort = Split-Path $unsigned -Leaf
$old = (get-childitem C:\Windows\System32\spool\drivers\x64\3\Old -File -Recurse | Sort-Object name -Unique).name
foreach($item in $old){
    if($unsignedShort -contains $item)
        {
        write-host -ForegroundColor Cyan "[+] " -NoNewline; Write-Host -ForegroundColor red "$item possibly indicative of CVE-2021-1675 explotation activity"
    }
}

