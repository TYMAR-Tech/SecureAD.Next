$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..\..')

# Which documents does a test OPEN, as opposed to merely mention in a comment?
# Scans quoted string literals only. Doing this with git grep and a quoted pattern fails:
# PowerShell strips the quotes from the pattern, so XML doc comments match too and every
# cited document looks like a document that is read.
$literals = @{}
foreach ($cs in (git ls-files 'next/tests/*.cs')) {
    foreach ($m in [regex]::Matches((Get-Content $cs -Raw), '"([^"\r\n]*\.md)"')) {
        $doc = $m.Groups[1].Value
        if (-not $literals[$doc]) { $literals[$doc] = @() }
        $literals[$doc] += (Split-Path $cs -Leaf)
    }
}

"Documents named in a test STRING LITERAL (these are specification, not prose):"
foreach ($k in $literals.Keys | Sort-Object) {
    "{0,-52} {1}" -f $k, (($literals[$k] | Sort-Object -Unique) -join ', ')
}
