$bin = 'C:\Users\jistrand\source\repos\SecureAD.Next\next\tests\SecureAD.Next.Tests\bin\Debug\net10.0-windows'
$src = 'C:\Users\jistrand\source\repos\SecureAD.Next\next\src'

Add-Type -AssemblyName System.Runtime | Out-Null
$null = [System.Reflection.Assembly]::LoadFrom((Join-Path $bin 'SecureAD.Kernel.dll'))
$null = [System.Reflection.Assembly]::LoadFrom((Join-Path $bin 'SecureAD.Evidence.dll'))
$null = [System.Reflection.Assembly]::LoadFrom((Join-Path $bin 'SecureAD.Audit.dll'))
$null = [System.Reflection.Assembly]::LoadFrom((Join-Path $bin 'SecureAD.Judgement.dll'))

$shapes = @('Errors','Warnings','Verdict','Verdicts','IsComplete','Completeness',
            '*AreComplete','*WereAsked','FailedPhase','FailedPhases','DidNotRun')

function MatchesShape($shape, $name) {
    if ($shape.StartsWith('*')) { return $name.EndsWith($shape.Substring(1)) -and $name.Length -gt ($shape.Length - 1) }
    return $name -ceq $shape
}

$flags = [System.Reflection.BindingFlags]::Public -bor
         [System.Reflection.BindingFlags]::Instance -bor
         [System.Reflection.BindingFlags]::Static -bor
         [System.Reflection.BindingFlags]::DeclaredOnly

# where each type is declared in source
$fileOf = @{}
Get-ChildItem $src -Recurse -Filter *.cs | ForEach-Object {
    $text = [System.IO.File]::ReadAllText($_.FullName)
    foreach ($m in [regex]::Matches($text, '(?m)^\s*(?:public|internal)\s+(?:sealed\s+|abstract\s+|static\s+|partial\s+)*(?:record|class|struct|enum|interface)\s+(\w+)')) {
        if (-not $fileOf.ContainsKey($m.Groups[1].Value)) { $fileOf[$m.Groups[1].Value] = $_.FullName }
    }
}

$rows = @()
foreach ($asm in @('SecureAD.Kernel','SecureAD.Evidence','SecureAD.Audit','SecureAD.Judgement')) {
    $a = [System.Reflection.Assembly]::LoadFrom((Join-Path $bin "$asm.dll"))
    foreach ($t in $a.GetTypes()) {
        if (-not $t.IsPublic) { continue }
        foreach ($mem in $t.GetMembers($flags)) {
            if ($mem.MemberType -notin 'Property','Field') { continue }
            $hit = $false
            foreach ($s in $shapes) { if (MatchesShape $s $mem.Name) { $hit = $true } }
            if (-not $hit) { continue }

            $kind = if ($mem.MemberType -eq 'Property') { $mem.PropertyType } else { $mem.FieldType }
            $file = if ($fileOf.ContainsKey($t.Name)) { $fileOf[$t.Name] } else { '?' }
            $line = ''
            if ($file -ne '?') {
                $lines = [System.IO.File]::ReadAllLines($file)
                for ($i = 0; $i -lt $lines.Count; $i++) {
                    if ($lines[$i] -match ("\b" + [regex]::Escape($mem.Name) + "\b")) { $line = $i + 1; break }
                }
            }
            $rows += [pscustomobject]@{
                Type = $t.Name; Member = $mem.Name; Kind = $kind.Name
                File = (Split-Path $file -Leaf); Line = $line
            }
        }
    }
}

"total vouching declaration sites (reflection): $($rows.Count)"
''
'--- BOOLEAN vouchers (a bool is where a constant hides) ---'
$rows | Where-Object { $_.Kind -eq 'Boolean' } | Sort-Object Type |
    ForEach-Object { '{0,-26} {1,-34} {2}:{3}' -f $_.Type, $_.Member, $_.File, $_.Line }
''
'--- NON-BOOLEAN vouchers ---'
$rows | Where-Object { $_.Kind -ne 'Boolean' } | Sort-Object Kind, Type |
    ForEach-Object { '{0,-26} {1,-30} {2,-22} {3}:{4}' -f $_.Type, $_.Member, $_.Kind, $_.File, $_.Line }
