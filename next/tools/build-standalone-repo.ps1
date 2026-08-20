$ErrorActionPreference = 'Continue'
$repo = 'C:\Users\jistrand\source\repos\razamus\SecureAD'
$dest = 'C:\Users\jistrand\source\repos\razamus\SecureAD.Next'
$wt = Join-Path $env:TEMP 'securead-carry-export'

if (Test-Path $dest) { Write-Host "$dest already exists. Remove it first if you mean to rebuild it."; exit 1 }
if (Test-Path $wt) { & git -C $repo worktree remove --force $wt 2>&1 | Out-Null }

Write-Host '=== clean export of tracked files at HEAD ==='
& git -C $repo worktree add --detach $wt HEAD 2>&1 | Out-Null
if (-not (Test-Path (Join-Path $wt 'next'))) { Write-Host 'worktree export failed'; exit 1 }
Write-Host '  exported'

try {
    New-Item -ItemType Directory -Path $dest -Force | Out-Null

    # 1. The four inherited build files, plus repo-level files the docs link to.
    foreach ($f in @('Directory.Build.props', 'Directory.Packages.props', 'global.json', '.editorconfig', '.gitignore', '.gitattributes', 'README.md')) {
        $src = Join-Path $wt $f
        if (Test-Path $src) { Copy-Item $src (Join-Path $dest $f) -Force; Write-Host "  + $f" }
        else { Write-Host "  ! missing $f" }
    }

    # 2. .github - three session prompts link to copilot-instructions.md
    & robocopy (Join-Path $wt '.github') (Join-Path $dest '.github') /E /NFL /NDL /NJH /NJS /NP | Out-Null
    Write-Host '  + .github/'

    # 3. The rebuild.
    & robocopy (Join-Path $wt 'next') (Join-Path $dest 'next') /E /NFL /NDL /NJH /NJS /NP | Out-Null
    Write-Host '  + next/'

    # 4. Documentation, minus review/ (except two files the session prompts cite) and work/.
    & robocopy (Join-Path $wt 'docs') (Join-Path $dest 'docs') /E /NFL /NDL /NJH /NJS /NP /XD 'review' 'work' | Out-Null
    Write-Host '  + docs/ (excluding review/ and work/)'

    New-Item -ItemType Directory -Path (Join-Path $dest 'docs\review') -Force | Out-Null
    foreach ($f in @('TEMPLATE.md', 'SESSION-LOG.md')) {
        Copy-Item (Join-Path $wt "docs\review\$f") (Join-Path $dest "docs\review\$f") -Force
        Write-Host "  + docs/review/$f"
    }

    Write-Host ''
    Write-Host '=== RESULT ==='
    $docs = Get-ChildItem (Join-Path $dest 'docs') -Recurse -Filter *.md -File
    $words = ($docs | ForEach-Object { (Get-Content $_.FullName -Raw) -split '\s+' }).Count
    "  documents: {0}  ({1:N0} words)" -f $docs.Count, $words
    "  next/ files: {0}" -f (Get-ChildItem (Join-Path $dest 'next') -Recurse -File).Count
    "  old app present: {0}" -f (Test-Path (Join-Path $dest 'src'))
}
finally {
    & git -C $repo worktree remove --force $wt 2>&1 | Out-Null
    Write-Host ''
    Write-Host "export worktree removed: $(-not (Test-Path $wt))"
}
