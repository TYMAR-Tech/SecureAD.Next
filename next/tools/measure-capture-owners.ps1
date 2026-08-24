$root = 'C:\Users\jistrand\source\repos\razamus\SecureAD.Next'
$reg = [System.IO.File]::ReadAllLines((Join-Path $root 'docs\next\SURFACE-REGISTER.md'))

$types = @()
foreach ($line in $reg) {
    if ($line -match 'what-we-capture') {
        $types += ($line -split '\|')[1].Trim()
    }
}

$docs = Get-ChildItem -Path (Join-Path $root 'docs\layers') -Recurse -Filter *.md

foreach ($t in $types) {
    $hits = @()
    foreach ($d in $docs) {
        $text = [System.IO.File]::ReadAllText($d.FullName)
        # exact identifier inside backticks, qualified name counts for its head
        $found = $false
        $parts = $text.Split('`')
        for ($i = 1; $i -lt $parts.Length; $i += 2) {
            foreach ($half in $parts[$i].Split('.')) {
                if ($half -ceq $t) { $found = $true }
            }
        }
        if ($found) { $hits += ($d.Directory.Name + '/' + $d.Name) }
    }
    '{0,-38} {1}  {2}' -f $t, $hits.Count, ($hits -join ' ; ')
}
