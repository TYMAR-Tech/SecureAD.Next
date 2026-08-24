$bin = 'C:\Users\jistrand\source\repos\razamus\SecureAD.Next\next\tests\SecureAD.Next.Tests\bin\Debug\net10.0-windows'

$null = [System.Reflection.Assembly]::LoadFrom((Join-Path $bin 'SecureAD.Kernel.dll'))
$null = [System.Reflection.Assembly]::LoadFrom((Join-Path $bin 'SecureAD.Evidence.dll'))
$null = [System.Reflection.Assembly]::LoadFrom((Join-Path $bin 'SecureAD.Audit.dll'))

$shapes = @('IsComplete','*AreComplete','*WereAsked','DidNotRun')

function MatchesShape($shape, $name) {
    if ($shape.StartsWith('*')) { return $name.EndsWith($shape.Substring(1)) -and $name.Length -gt ($shape.Length - 1) }
    return $name -ceq $shape
}

$flags = [System.Reflection.BindingFlags]::Public -bor
         [System.Reflection.BindingFlags]::Instance -bor
         [System.Reflection.BindingFlags]::Static -bor
         [System.Reflection.BindingFlags]::DeclaredOnly

foreach ($asm in @('SecureAD.Kernel','SecureAD.Evidence','SecureAD.Audit')) {
    $a = [System.Reflection.Assembly]::LoadFrom((Join-Path $bin "$asm.dll"))
    foreach ($t in $a.GetTypes()) {
        if (-not $t.IsPublic) { continue }
        foreach ($mem in $t.GetMembers($flags)) {
            if ($mem.MemberType -notin 'Property','Field') { continue }
            $kind = if ($mem.MemberType -eq 'Property') { $mem.PropertyType } else { $mem.FieldType }
            if ($kind.FullName -ne 'System.Boolean') { continue }
            $hit = $false
            foreach ($s in $shapes) { if (MatchesShape $s $mem.Name) { $hit = $true } }
            if (-not $hit) { continue }

            "=== $($t.Name).$($mem.Name)   [$($t.FullName)]"
            foreach ($c in $t.GetConstructors()) {
                "    ctor(" + (($c.GetParameters() | ForEach-Object { "$($_.ParameterType.Name) $($_.Name)" }) -join ', ') + ")"
            }
            foreach ($m in $t.GetMethods([System.Reflection.BindingFlags]::Public -bor [System.Reflection.BindingFlags]::Static -bor [System.Reflection.BindingFlags]::DeclaredOnly)) {
                if ($m.ReturnType -ne $t) { continue }
                "    static $($m.Name)(" + (($m.GetParameters() | ForEach-Object { "$($_.ParameterType.Name) $($_.Name)" }) -join ', ') + ")"
            }
            $p = $t.GetProperty($mem.Name)
            if ($p -and $p.SetMethod) { "    SETTABLE (init or set)" }
        }
    }
}
