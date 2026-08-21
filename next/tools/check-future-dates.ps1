# Reports any date in the tree that is later than today.
#
# WHY THIS EXISTS. Sessions have repeatedly written dates into documents and comments that had
# not happened yet - on 2026-08-21 a scan found 32 of them, running up to three weeks ahead, in
# 17 files. They are not typos in the ordinary sense: they read as records of when something was
# seen, decided or confirmed, and several were being cited by later work as settled fact. A
# statement anchored to a date that never happened cannot be checked against anything.
#
# Nothing else in this repository notices. check-document-encoding.ps1 looks for double-encoded
# text and check-area-file-rows.ps1 looks for lost table cells; a well-formed sentence carrying an
# impossible date passes both, and passes the build, and passes review, because it looks exactly
# like the true ones beside it.
#
# HOW A DATE GETS REPAIRED. git blame gives the commit that wrote the line, and a line cannot
# describe something that happened after it was written, so the commit date is a provable upper
# bound. Every session in this repository has committed the same day it worked, so in practice
# that bound is the real date. That is how the 29 found on 2026-08-21 were corrected.
#
# WHAT IS DELIBERATELY IGNORED. Test fixtures. A test that asserts a stored date value, or the
# wording of a formatted timestamp, is describing invented data rather than claiming a day.
# Correcting those would break the tests and would be correcting fiction. They are listed below by
# path, so adding one is a visible decision rather than a silent exemption. The example dates are
# not repeated here: this file is scanned like any other, and a literal in this comment would make
# the checker report itself.

$ErrorActionPreference = 'Stop'

$Root = Resolve-Path (Join-Path $PSScriptRoot '..\..')

$fixtures = @(
    'next/tests/SecureAD.Next.Tests/Evidence/BundleWriterTests.cs',
    'next/tests/SecureAD.Next.Tests/Kernel/Security/DirectoryTimeTests.cs'
)

Push-Location $Root
try {
    $today = (Get-Date).ToString('yyyy-MM-dd')
    $decoder = New-Object System.Text.UTF8Encoding($false)
    $found = 0

    foreach ($file in (git ls-files)) {
        if ($file -notmatch '\.(md|cs|ps1|xaml|csproj|json)$') { continue }
        if ($fixtures -contains $file) { continue }

        $full = Join-Path $Root ($file -replace '/', '\')
        if (-not (Test-Path -LiteralPath $full)) { continue }

        $lines = $decoder.GetString([System.IO.File]::ReadAllBytes($full)) -split "`r`n|`n"

        for ($i = 0; $i -lt $lines.Count; $i++) {
            $dates = @([regex]::Matches($lines[$i], '\b\d{4}-\d{2}-\d{2}\b') |
                Where-Object { $_.Value -gt $today } |
                Select-Object -ExpandProperty Value -Unique)

            if ($dates.Count -eq 0) { continue }

            $snippet = $lines[$i].Trim()
            if ($snippet.Length -gt 100) { $snippet = $snippet.Substring(0, 100) + '...' }

            Write-Output ("{0}:{1}  [{2}]" -f $file, ($i + 1), ($dates -join ', '))
            Write-Output ("      {0}" -f $snippet)
            $found += $dates.Count
        }
    }

    Write-Output ''
    Write-Output ("Dates later than today ({0}): {1}" -f $today, $found)

    if ($found -gt 0) { exit 1 }
}
finally {
    Pop-Location
}
