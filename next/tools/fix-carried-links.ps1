#Requires -Version 7.0
# Windows PowerShell 5.1 reads UTF-8 files as Windows-1252, turning every em dash into three
# characters. This script writes documents, so running it under 5.1 would corrupt them silently.

$ErrorActionPreference = 'Stop'
$docs = 'C:\Users\jistrand\source\repos\SecureAD.Next\docs'

function Edit-Line {
    param([string]$Path, [string]$Find, [string]$Replace)
    $full = Join-Path $docs $Path
    $text = Get-Content $full -Raw
    if (-not $text.Contains($Find)) { Write-Host "  ! not found in ${Path}: $Find"; return }
    Set-Content -LiteralPath $full -Value ($text.Replace($Find, $Replace)) -NoNewline -Encoding UTF8
    Write-Host "  edited $Path"
}

# 1. README.md - the documentation-audit citation.
Edit-Line 'README.md' `
    '[work/DOCUMENTATION-AUDIT.md](work/DOCUMENTATION-AUDIT.md). **Both carry a banner saying so.**' `
    '`work/DOCUMENTATION-AUDIT.md`, which stayed in the predecessor repository. **Both carry a banner saying so.**'

# 2. README.md - the review rule citation.
Edit-Line 'README.md' `
    'This is rule 8 in [review/README.md](review/README.md).' `
    'This is rule 8 in `review/README.md`, which stayed in the predecessor repository.'

# 3. CONFIGURATION.md - same audit citation.
Edit-Line 'CONFIGURATION.md' `
    '> The gap is measured in [work/DOCUMENTATION-AUDIT.md](work/DOCUMENTATION-AUDIT.md), and the' `
    '> The gap is measured in `work/DOCUMENTATION-AUDIT.md` in the predecessor repository, and the'

# 4. history/S-7 - a script that belongs to the old application.
Edit-Line 'history\S-7-capture-dispositions.md' `
    '- **How to run it.** [`tools/Measure-CredentialChildObjects.ps1`](../../tools/Measure-CredentialChildObjects.ps1),' `
    '- **How to run it.** `tools/Measure-CredentialChildObjects.ps1` in the predecessor repository,'

# 5. README.md - the Work queues section describes documents that did not travel.
$readme = Join-Path $docs 'README.md'
$lines = Get-Content $readme
$start = ($lines | Select-String -Pattern '^## Work queues$' -SimpleMatch:$false | Select-Object -First 1).LineNumber
$next = ($lines | Select-String -Pattern '^## Two kinds of document$' | Select-Object -First 1).LineNumber
if (-not $start -or -not $next) { throw 'Could not locate the Work queues section boundaries.' }

$replacement = @(
    '## Work queues',
    '',
    'The working documents - `work/PUNCH-LIST.md`, `work/PRODUCT-REVIEW.md`,',
    '`work/DOCUMENTATION-AUDIT.md`, `work/RUN-MODEL-DESIGN.md` and the `review/` architecture review -',
    'stayed in the predecessor repository when the rebuild was cut loose. They routed work on the old',
    'application and were never the source of truth about how this system behaves.',
    '',
    'Two files came across because session prompts cite them by name: `review/TEMPLATE.md` and',
    '`review/SESSION-LOG.md`. They are here so the record of what each session was told stays',
    'readable, not because they describe the product.',
    ''
)

$new = @()
$new += $lines[0..($start - 2)]
$new += $replacement
$new += $lines[($next - 1)..($lines.Count - 1)]
Set-Content -LiteralPath $readme -Value $new -Encoding UTF8
Write-Host "  rewrote README.md Work queues section (lines $start-$($next - 1))"
