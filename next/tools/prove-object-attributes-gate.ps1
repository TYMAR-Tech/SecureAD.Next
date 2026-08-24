$doc = 'C:\Users\jistrand\source\repos\razamus\SecureAD.Next\docs\layers\evidence\what-an-object-holds.md'
$next = 'C:\Users\jistrand\source\repos\razamus\SecureAD.Next\next'
$original = [System.IO.File]::ReadAllText($doc)

$mutations = @(
    @{ Name = 'A: the page stops naming ObjectAttribute.OnlyValue'
       From = '`ObjectAttribute.OnlyValue` is the first value or null'
       To   = 'The first-value accessor gives the first value or null' },
    @{ Name = 'B: the page names a member that does not exist'
       From = '`ObjectAttributes.DistinguishedName` is the object'
       To   = '`ObjectAttributes.DistinguishedNames` is the object' },
    @{ Name = 'C: the page claims a byte value also carries text'
       From = '| Binary | null | the octets the directory sent |'
       To   = '| Binary | the characters the directory sent | the octets the directory sent |' },
    @{ Name = 'D: the page describes storage the code cannot produce'
       From = '| Binary | null | the octets the directory sent | those octets in uppercase hexadecimal |'
       To   = "| Binary | null | the octets the directory sent | those octets in uppercase hexadecimal |`r`n| Reference | a distinguished name | null | that name |" },
    @{ Name = 'E: the STORED table is moved to another document'
       From = '<!-- STORED:BEGIN -->'
       To   = '<!-- MOVED:BEGIN -->' }
)

foreach ($m in $mutations) {
    if (-not $original.Contains($m.From)) {
        "!! $($m.Name): anchor text not found - mutation did not apply"
        continue
    }

    [System.IO.File]::WriteAllText($doc, $original.Replace($m.From, $m.To))

    Push-Location $next
    $out = dotnet test SecureAD.Next.sln --no-build --nologo `
        --filter 'FullyQualifiedName~ObjectAttributesDocumentationTests' 2>&1
    Pop-Location

    [System.IO.File]::WriteAllText($doc, $original)

    ''
    "=== $($m.Name)"
    $out | Select-String 'Failed |error|Failed!|Passed!' | Select-Object -First 12
}

if ([System.IO.File]::ReadAllText($doc) -ne $original) { throw 'The document was not restored.' }
''
'Document restored.'
