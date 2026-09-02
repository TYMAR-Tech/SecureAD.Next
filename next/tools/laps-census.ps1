$rows = foreach ($d in (Get-ADForest).Domains) {
    $s = (Get-ADDomain $d).PDCEmulator
    $props = @('operatingSystem','userAccountControl','primaryGroupID','ms-Mcs-AdmPwdExpirationTime','msLAPS-PasswordExpirationTime')
    Get-ADComputer -Server $s -Filter * -Properties $props | ForEach-Object {
        $os = $_.operatingSystem
        if (-not $os) { $os = '(none)' }
        $isDc = ((($_.userAccountControl -band 0x2000) -ne 0) -or ($_.primaryGroupID -eq 516) -or ($_.primaryGroupID -eq 521))
        $laps = 'none'
        if ($_.'msLAPS-PasswordExpirationTime') { $laps = 'Windows' }
        elseif ($_.'ms-Mcs-AdmPwdExpirationTime') { $laps = 'Legacy' }
        [pscustomobject]@{ Domain = $d; OS = $os; IsDC = $isDc; Laps = $laps }
    }
}

"TOTAL COMPUTERS: $($rows.Count)"
""
$rows | Group-Object Domain, OS, IsDC, Laps | Sort-Object Name | Format-Table Count, Name -AutoSize | Out-String -Width 220
