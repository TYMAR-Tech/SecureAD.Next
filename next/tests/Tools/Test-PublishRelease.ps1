#requires -Version 7.0
param(
    [string]$PublisherPath = (Join-Path (Split-Path (Split-Path $PSScriptRoot)) 'tools\Publish-Release.ps1'),
    [string]$Case
)
$ErrorActionPreference = 'Stop'
$repo = Split-Path (Split-Path (Split-Path $PSScriptRoot))
$root = Join-Path ([IO.Path]::GetTempPath()) ('publish-tests-' + [guid]::NewGuid().ToString('N'))
[void](New-Item -ItemType Directory -Path $root)
$cases = @('what-if','existing-output','success','publish-failure','missing-executable','changed-source','restore-success','restore-failure')
if ($Case) {
    if ($Case -notin $cases) { throw 'Unknown publishing check.' }
    $cases = @($Case)
}
$results = [Collections.Generic.List[object]]::new()

function Require([bool]$Condition, [string]$Message) {
    if (!$Condition) { throw $Message }
}
function Fails([scriptblock]$Action, [string]$Message) {
    try { & $Action }
    catch {
        Require $_.Exception.Message.Contains($Message) "The wrong failure was observed: $_"
        return
    }
    throw "The expected failure was not reported: $Message"
}
function global:git {
    $CommandArguments = @($args)
    $global:LASTEXITCODE = 0
    if ($CommandArguments -contains 'rev-parse') { return '4deef9fbd5b9e5227ca127b2b9ffb7f7ff0e43e8' }
    if ($CommandArguments -contains 'branch') { return 'isolated-publish-test' }
    if ($CommandArguments -contains 'ls-files') {
        return @('next/src/SecureAD.Shell/SecureAD.Shell.csproj','next/src/SecureAD.Shell/Properties/PublishProfiles/FolderProfile.pubxml')
    }
    if ($CommandArguments -contains 'status') { return ' M next/src/SecureAD.Shell/SecureAD.Shell.csproj' }
    throw 'The publisher invoked an unexpected Git operation.'
}
function global:dotnet {
    $CommandArguments = @($args)
    $global:PublishTestCalls.Add(@($CommandArguments))
    $global:LASTEXITCODE = 0
    if ($CommandArguments[0] -eq 'restore') {
        if ($global:PublishTestCase -eq 'restore-failure') { $global:LASTEXITCODE = 1; 'error NU1301: simulated restore failure' }
        return
    }
    Require ($CommandArguments[0] -eq 'publish') 'Only restore and publish may be invoked.'
    if ($global:PublishTestCase -in 'restore-success','restore-failure' -and $global:PublishTestCalls.Count -eq 1) {
        $global:LASTEXITCODE = 1
        'trial : error NETSDK1004: simulated missing assets'
        return
    }
    if ($global:PublishTestCase -eq 'publish-failure') {
        $global:LASTEXITCODE = 1
        'trial : error CS1001: simulated compilation failure'
        return
    }
    $index = [Array]::IndexOf($CommandArguments, '-o')
    Require ($index -ge 0) 'A fresh explicit package destination is required.'
    $output = [string]$CommandArguments[$index + 1]
    [void](New-Item -ItemType Directory -Path $output -Force)
    if ($global:PublishTestCase -ne 'missing-executable') {
        Set-Content -LiteralPath (Join-Path $output 'SecureAD.exe') -Value 'Simulated build output; never executed.' -Encoding utf8
    }
    if ($global:PublishTestCase -eq 'changed-source') {
        Add-Content -LiteralPath ([string]$CommandArguments[1]) -Value '<!-- simulated concurrent edit -->'
    }
}

try {
    foreach ($name in $cases) {
        $test = Join-Path $root $name
        $tools = Join-Path $test 'next\tools'
        $shell = Join-Path $test 'next\src\SecureAD.Shell'
        [void](New-Item -ItemType Directory -Path $tools)
        [void](New-Item -ItemType Directory -Path (Join-Path $shell 'Properties\PublishProfiles') -Force)
        Copy-Item -LiteralPath $PublisherPath -Destination (Join-Path $tools 'Publish-Release.ps1')
        Copy-Item -LiteralPath (Join-Path $repo 'next\src\SecureAD.Shell\SecureAD.Shell.csproj') -Destination $shell
        Copy-Item -LiteralPath (Join-Path $repo 'next\src\SecureAD.Shell\Properties\PublishProfiles\FolderProfile.pubxml') `
            -Destination (Join-Path $shell 'Properties\PublishProfiles')
        $publisher = Join-Path $tools 'Publish-Release.ps1'
        $output = Join-Path $test 'package'
        $global:PublishTestCalls = [Collections.Generic.List[object]]::new()
        $global:PublishTestCase = $name
        $temp = $env:TEMP
        $tmp = $env:TMP
        $passed = $false
        try {
            switch ($name) {
                'what-if' {
                    & $publisher -OutputDirectory $output -WhatIf
                    Require ($global:PublishTestCalls.Count -eq 0) 'WhatIf launched a build.'
                    Require (!(Test-Path -LiteralPath $output)) 'WhatIf created a package.'
                    Require (@(Get-ChildItem -LiteralPath $test -Directory -Force | Where-Object Name -like '.v-publish-*').Count -eq 0) 'WhatIf created build artifacts.'
                }
                'existing-output' {
                    [void](New-Item -ItemType Directory -Path $output)
                    Set-Content -LiteralPath (Join-Path $output 'keep.txt') -Value 'original'
                    Fails { & $publisher -OutputDirectory $output } 'Refusing to overwrite'
                    Require ($global:PublishTestCalls.Count -eq 0) 'An existing output triggered a build.'
                    Require ((Get-Content (Join-Path $output 'keep.txt') -Raw).Trim() -eq 'original') 'Existing package content changed.'
                }
                'publish-failure' { Fails { & $publisher -OutputDirectory $output } 'Release publication failed' }
                'missing-executable' { Fails { & $publisher -OutputDirectory $output } 'without producing a nonempty SecureAD.exe' }
                'changed-source' { Fails { & $publisher -OutputDirectory $output } 'Sources changed during publication' }
                'restore-failure' { Fails { & $publisher -OutputDirectory $output } 'Dependency restore failed' }
                default { & $publisher -OutputDirectory $output }
            }
            Require ($env:TEMP -eq $temp -and $env:TMP -eq $tmp) 'Temporary paths were not restored.'
            if ($name -notin 'what-if','existing-output') {
                $work = @(Get-ChildItem -LiteralPath $test -Directory -Force | Where-Object Name -like '.v-publish-*')
                Require ($work.Count -eq 1) 'Exactly one retained publication record is required.'
                $record = Get-Content (Join-Path $work[0].FullName 'publication.json') -Raw | ConvertFrom-Json
                $success = $name -in 'success','restore-success'
                Require ($record.Published -eq $success) 'The saved publication state is wrong.'
                if ($success) {
                    Require ($record.Sources.Count -eq 2) 'Source identity was not recorded.'
                    Require ($record.WorkingTree.Count -eq 1) 'Uncommitted changes were not recorded.'
                    Require ($record.Files.Count -eq 1 -and $record.Files[0].SHA256 -eq (Get-FileHash (Join-Path $output 'SecureAD.exe')).Hash) 'Package fingerprint is wrong.'
                    $publish = @($global:PublishTestCalls | Where-Object { $_[0] -eq 'publish' })
                    foreach ($call in $publish) {
                        Require ($call -contains '-p:PublishProfile=FolderProfile' -and $call -contains 'Release' -and $call -contains '--artifacts-path') 'The normal isolated Release profile was not used.'
                    }
                } else {
                    Require (![string]::IsNullOrWhiteSpace($record.Error)) 'Failure details were not retained.'
                }
                $expectedCalls = switch ($name) { 'restore-success' {3} 'restore-failure' {2} default {1} }
                Require ($global:PublishTestCalls.Count -eq $expectedCalls) 'Unexpected build/restore operations.'
            }
            $passed = $true
        } finally {
            $results.Add([pscustomobject]@{Case=$name; Passed=$passed; Directory=$test})
        }
    }
} finally {
    $results | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $root 'results.json') -Encoding utf8
    Remove-Item Function:\git,Function:\dotnet
}
"Passed $($results.Count) isolated publishing checks; no real build, publication or Git operation ran."
"Results: $(Join-Path $root 'results.json')"
