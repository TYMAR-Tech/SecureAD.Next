#requires -Version 7.0
<#
.SYNOPSIS
Publishes the current checkout's normal Release GUI into a new, separately identified folder.
.EXAMPLE
.\next\tools\Publish-Release.ps1
.EXAMPLE
.\next\tools\Publish-Release.ps1 -WhatIf
#>
[CmdletBinding(SupportsShouldProcess)]
param([string]$OutputDirectory)

$ErrorActionPreference = 'Stop'
$repo = Split-Path (Split-Path $PSScriptRoot)
$project = Join-Path $repo 'next\src\SecureAD.Shell\SecureAD.Shell.csproj'
$profile = Join-Path $repo 'next\src\SecureAD.Shell\Properties\PublishProfiles\FolderProfile.pubxml'
if (!(Test-Path -LiteralPath $project -PathType Leaf) -or !(Test-Path -LiteralPath $profile -PathType Leaf)) {
    throw 'The GUI project or its normal Release publish profile is missing.'
}
$head = & git -C $repo rev-parse HEAD
if ($LASTEXITCODE -ne 0) { throw 'Could not identify the current Git commit.' }
$branch = & git -C $repo branch --show-current
if ($LASTEXITCODE -ne 0) { throw 'Could not identify the current Git branch.' }
$label = 'release-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + $head.Substring(0, 8) + '-' + [guid]::NewGuid().ToString('N').Substring(0, 8)
$output = if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    Join-Path $repo ('next\artifacts\' + $label)
} else {
    [IO.Path]::GetFullPath($OutputDirectory)
}
if (Test-Path -LiteralPath $output) { throw "Refusing to overwrite an existing package or folder: $output" }
if (!$PSCmdlet.ShouldProcess($output, "Publish the current checkout using the normal Release FolderProfile")) { return }

function Read-PublishSources {
    $paths = @(& git -C $repo ls-files --cached --others --exclude-standard -- 'next\src' 'Directory.*.props' 'Directory.*.targets' 'global.json' 'NuGet.Config' 'nuget.config' '.editorconfig')
    if ($LASTEXITCODE -ne 0) { throw 'Could not enumerate publication sources.' }
    if ($paths.Count -eq 0) { throw 'No publication sources were identified.' }
    @($paths | Sort-Object -Unique | ForEach-Object {
        $path = Join-Path $repo $_.Replace('/', '\')
        [pscustomobject]@{ Path = $_; SHA256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash }
    })
}

$work = Join-Path $repo ('.v-publish-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
[void](New-Item -ItemType Directory -Path $work)
$temporary = Join-Path $work 'tmp'
[void](New-Item -ItemType Directory -Path $temporary)
$previousTemp = $env:TEMP
$previousTmp = $env:TMP
$env:TEMP = $temporary
$env:TMP = $temporary
$build = Join-Path $work 'build'
$publishLog = Join-Path $work 'publish.log'
$record = [ordered]@{
    StartedUtc = [DateTime]::UtcNow.ToString('O')
    SourceRoot = $repo
    Commit = $head
    Branch = $branch
    Output = $output
    Profile = $profile
    ProfileSHA256 = (Get-FileHash -LiteralPath $profile -Algorithm SHA256).Hash
    BuildDirectory = $build
    Temporary = $temporary
    Published = $false
}
try {
    $record.Sources = @(Read-PublishSources)
    $record.WorkingTree = @(& git -C $repo --no-pager status --short)
    if ($LASTEXITCODE -ne 0) { throw 'Could not record the working-tree state.' }
    $arguments = @('publish', $project, '-c', 'Release', '-p:PublishProfile=FolderProfile',
        '--no-restore', '--artifacts-path', $build, '-o', $output, '--nologo')
    $record.Arguments = $arguments
    Write-Host "Publishing $branch at $($head.Substring(0, 8)); current uncommitted source changes are included."
    Write-Host "Build log: $publishLog"
    & dotnet @arguments *> $publishLog
    if ($LASTEXITCODE -ne 0) {
        $errors = @(Select-String -LiteralPath $publishLog -Pattern ': error ([A-Z]+\d+):' |
            ForEach-Object { $_.Matches[0].Groups[1].Value } | Sort-Object -Unique)
        if ($errors.Count -eq 1 -and $errors[0] -eq 'NETSDK1004') {
            Move-Item -LiteralPath $publishLog -Destination (Join-Path $work 'publish-missing-assets.log')
            & dotnet restore $project '-p:PublishProfile=FolderProfile' '--artifacts-path' $build --nologo *> (Join-Path $work 'restore.log')
            if ($LASTEXITCODE -ne 0) { throw "Dependency restore failed; see $work" }
            & dotnet @arguments *> $publishLog
        }
    }
    $record.PublishExit = $LASTEXITCODE
    if ($LASTEXITCODE -ne 0) {
        Get-Content -LiteralPath $publishLog -Tail 20 | Write-Host
        throw "Release publication failed; its output and logs are retained under $work"
    }
    $after = @(Read-PublishSources)
    if (Compare-Object ($record.Sources | ForEach-Object { $_.Path + ':' + $_.SHA256 }) ($after | ForEach-Object { $_.Path + ':' + $_.SHA256 })) {
        throw 'Sources changed during publication; the retained output is not verified.'
    }
    $executable = Join-Path $output 'SecureAD.exe'
    if (!(Test-Path -LiteralPath $executable -PathType Leaf) -or (Get-Item -LiteralPath $executable).Length -eq 0) {
        throw 'Publication reported success without producing a nonempty SecureAD.exe.'
    }
    $record.Files = @(Get-ChildItem -LiteralPath $output -File -Recurse | ForEach-Object {
        [pscustomobject]@{
            Path = [IO.Path]::GetRelativePath($output, $_.FullName)
            Bytes = $_.Length
            SHA256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
        }
    })
    $record.Executable = $executable
    $record.Published = $true
    Write-Host "Published: $executable"
    Write-Host 'This command does not launch the application, start judging, commit or push.'
} catch {
    $record.Published = $false
    $record.Error = $_.ToString()
    throw
} finally {
    $record.FinishedUtc = [DateTime]::UtcNow.ToString('O')
    $env:TEMP = $previousTemp
    $env:TMP = $previousTmp
    $record | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $work 'publication.json') -Encoding utf8
}
[pscustomobject]@{ Executable = $record.Executable; Record = (Join-Path $work 'publication.json') }
