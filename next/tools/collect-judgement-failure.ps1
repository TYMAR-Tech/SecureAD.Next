[CmdletBinding(DefaultParameterSetName = 'Collect')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Collect')]
    [string]$RunDirectory,

    [Parameter(Mandatory, ParameterSetName = 'Collect')]
    [string]$OutputPath,

    [Parameter(ParameterSetName = 'SelfTest')]
    [switch]$SelfTest
)

$ErrorActionPreference = 'Stop'

Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

public static class SecureADFileAllocation
{
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetCompressedFileSizeW(string fileName, out uint high);

    public static ulong Get(string path)
    {
        uint high;
        uint low = GetCompressedFileSizeW(path, out high);
        if (low == 0xFFFFFFFF)
        {
            int error = Marshal.GetLastWin32Error();
            if (error != 0)
                throw new Win32Exception(error);
        }

        return ((ulong)high << 32) | low;
    }
}
'@

function Resolve-NormalizedPath([string]$Path, [switch]$MustExist) {
    if ($MustExist) {
        return (Resolve-Path -LiteralPath $Path).Path.TrimEnd('\')
    }

    return [System.IO.Path]::GetFullPath($Path).TrimEnd('\')
}

function Test-IsInside([string]$Child, [string]$Parent) {
    $separator = [System.IO.Path]::DirectorySeparatorChar
    return $Child.StartsWith($Parent + $separator, [System.StringComparison]::OrdinalIgnoreCase)
}

function Read-SharedText([string]$Path) {
    $stream = [System.IO.FileStream]::new(
        $Path,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete)
    try {
        $reader = [System.IO.StreamReader]::new(
            $stream, [System.Text.Encoding]::UTF8, $true, 4096, $true)
        try {
            return $reader.ReadToEnd()
        }
        finally {
            $reader.Dispose()
        }
    }
    finally {
        $stream.Dispose()
    }
}

function Get-FileFact([string]$Directory, [string]$Name) {
    $path = Join-Path $Directory $Name
    if (-not [System.IO.File]::Exists($path)) {
        return [ordered]@{
            name = $Name
            exists = $false
        }
    }

    try {
        $file = Get-Item -LiteralPath $path -Force
        $allocation = $null
        $allocationStatus = 'available'
        try {
            $allocation = [SecureADFileAllocation]::Get($file.FullName)
        }
        catch {
            $allocationStatus = 'unavailable:' + $_.Exception.GetType().Name
        }

        return [ordered]@{
            name = $Name
            exists = $true
            logicalBytes = [long]$file.Length
            allocatedBytes = $allocation
            allocatedBytesStatus = $allocationStatus
            createdUtc = $file.CreationTimeUtc.ToString('o')
            lastWriteUtc = $file.LastWriteTimeUtc.ToString('o')
            attributes = @($file.Attributes.ToString().Split(',').Trim())
        }
    }
    catch {
        return [ordered]@{
            name = $Name
            exists = $true
            inspectionError = $_.Exception.GetType().Name
        }
    }
}

function Find-AnalysisFiles([string]$Directory) {
    $names = [System.Collections.Generic.List[string]]::new()
    try {
        foreach ($path in [System.IO.Directory]::EnumerateFiles(
            $Directory, '*', [System.IO.SearchOption]::TopDirectoryOnly)) {
            $name = [System.IO.Path]::GetFileName($path)
            if ($name -match '^(derivation|judgement)\.[0-9a-fA-F]{32}\.db(\.seal|-wal|-shm|-journal)?$') {
                $names.Add($name)
            }
        }
        return [ordered]@{
            status = 'available'
            names = @($names | Sort-Object -Unique)
        }
    }
    catch {
        return [ordered]@{
            status = 'unavailable:' + $_.Exception.GetType().Name
            names = @()
        }
    }
}

function ConvertFrom-RunLogDetail([string]$Text) {
    $result = [ordered]@{}
    $pattern = '(?<key>[A-Za-z][A-Za-z0-9]*)=(?<value>"(?:\\"|[^"])*"|[^\s]+)'
    foreach ($match in [regex]::Matches($Text, $pattern)) {
        $value = $match.Groups['value'].Value
        if ($value.StartsWith('"') -and $value.EndsWith('"')) {
            $value = $value.Substring(1, $value.Length - 2).Replace('\"', '"')
        }
        $result[$match.Groups['key'].Value] = $value
    }
    return $result
}

function Select-Fields([System.Collections.IDictionary]$Source, [string[]]$Names) {
    $selected = [ordered]@{}
    foreach ($name in $Names) {
        if ($Source.Contains($name)) {
            $selected[$name] = $Source[$name]
        }
    }
    return $selected
}

function Select-BoundedSamples([System.Collections.Generic.List[object]]$Samples, [int]$Limit) {
    if ($Samples.Count -le $Limit) {
        return @($Samples)
    }

    $selected = [System.Collections.Generic.List[object]]::new()
    for ($index = 0; $index -lt $Limit; $index++) {
        $sourceIndex = [Math]::Round($index * ($Samples.Count - 1) / ($Limit - 1))
        $selected.Add($Samples[$sourceIndex])
    }
    return @($selected)
}

function Read-JudgingLog([string]$Directory) {
    $path = Join-Path $Directory 'run.log'
    if (-not [System.IO.File]::Exists($path)) {
        return [ordered]@{
            status = 'missing'
            sessionFound = $false
            phases = @()
            statusSamplesObserved = 0
            statusSamplesReturned = 0
            statusSamplesDownsampled = $false
            statusSamples = @()
            latestPartMeasurements = @()
            operationalEvents = @()
            ruleTimings = @()
            errors = @()
            buildIdentity = $null
        }
    }

    try {
        $lines = (Read-SharedText $path) -split "\r?\n"
    }
    catch {
        return [ordered]@{
            status = 'unreadable:' + $_.Exception.GetType().Name
            sessionFound = $false
            phases = @()
            statusSamplesObserved = 0
            statusSamplesReturned = 0
            statusSamplesDownsampled = $false
            statusSamples = @()
            latestPartMeasurements = @()
            operationalEvents = @()
            ruleTimings = @()
            errors = @()
            buildIdentity = $null
        }
    }

    $start = -1
    for ($index = 0; $index -lt $lines.Count; $index++) {
        if ($lines[$index] -match '^==== .+  judging ====$') {
            $start = $index
        }
    }

    if ($start -lt 0) {
        return [ordered]@{
            status = 'read'
            sessionFound = $false
            phases = @()
            statusSamplesObserved = 0
            statusSamplesReturned = 0
            statusSamplesDownsampled = $false
            statusSamples = @()
            latestPartMeasurements = @()
            operationalEvents = @()
            ruleTimings = @()
            errors = @()
            buildIdentity = $null
        }
    }

    $phases = [System.Collections.Generic.List[object]]::new()
    $statusSamples = [System.Collections.Generic.List[object]]::new()
    $latestParts = [ordered]@{}
    $operationalEvents = [System.Collections.Generic.List[object]]::new()
    $ruleTimings = [System.Collections.Generic.List[object]]::new()
    $errors = [System.Collections.Generic.List[object]]::new()
    $buildIdentity = $null
    $finished = $null

    $headlines = [ordered]@{
        'post-pass status' = @(
            'generation', 'stage', 'kind', 'outcome', 'activePart', 'elapsedMs',
            'accountedMs', 'unaccountedMs', 'memoryKind', 'memoryStatus',
            'workingSetBytes', 'privateBytes', 'managedEstimatedBytes',
            'processAllocatedBytes', 'processGen0', 'processGen1', 'processGen2')
        'post-pass part' = @(
            'generation', 'stage', 'outcome', 'part', 'completedMs', 'activeMs')
        'a rule finished' = @('rule', 'outcome', 'judged', 'notAbout', 'ms')
        'judging build' = @(
            'attempt', 'processFileSha256', 'entryAssembly', 'entryMvid',
            'engineAssembly', 'engineMvid', 'engineVersion', 'engineConfiguration',
            'engineFileSha256', 'runtime', 'architecture')
        'path-requester-attempt' = @(
            'attempt', 'state', 'policy', 'generation', 'requesterDaclRequests',
            'ownAccountRequests', 'membershipDaclRequests', 'offlineSelection')
        'finished' = @('state', 'objects', 'ruleMs')
        'phase' = @('name')
    }

    for ($lineIndex = $start + 1; $lineIndex -lt $lines.Count; $lineIndex++) {
        $line = $lines[$lineIndex]
        if ($line -match '^==== ') {
            break
        }
        if ($line.Length -lt 53 -or $line -notmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z  ') {
            continue
        }

        $timestamp = $line.Substring(0, 20)
        $level = $line.Substring(22, 5).Trim()
        $phase = $line.Substring(29, [Math]::Min(22, $line.Length - 29)).Trim()
        if ($phase -ne 'Judge' -or $line.Length -le 53) {
            continue
        }

        $rest = $line.Substring(53)
        if ($level -in @('WARN', 'ERROR')) {
            $code = ($rest -split '\s+', 2)[0]
            $errors.Add([ordered]@{ timestampUtc = $timestamp; level = $level; code = $code })
            continue
        }

        foreach ($headline in $headlines.Keys) {
            if ($rest -eq $headline -or $rest.StartsWith($headline + ' ')) {
                $detailText = if ($rest.Length -gt $headline.Length) {
                    $rest.Substring($headline.Length + 1)
                } else {
                    ''
                }
                $parsed = ConvertFrom-RunLogDetail $detailText
                $details = Select-Fields $parsed $headlines[$headline]
                if ($headline -eq 'post-pass status') {
                    foreach ($entry in $parsed.GetEnumerator()) {
                        if (-not $details.Contains($entry.Key) -and $entry.Value -match '^-?\d+$') {
                            $details[$entry.Key] = $entry.Value
                        }
                    }
                }
                $record = [ordered]@{ timestampUtc = $timestamp }
                foreach ($entry in $details.GetEnumerator()) {
                    $record[$entry.Key] = $entry.Value
                }

                switch ($headline) {
                    'phase' { $phases.Add($record) }
                    'post-pass status' { $statusSamples.Add($record) }
                    'post-pass part' {
                        $partKey = [string]$record.stage + '|' + [string]$record.part
                        $latestParts[$partKey] = $record
                    }
                    'a rule finished' { $ruleTimings.Add($record) }
                    'judging build' { $buildIdentity = $record }
                    'finished' { $finished = $record }
                    default { $operationalEvents.Add($record) }
                }
                break
            }
        }
    }

    $boundedStatus = @(Select-BoundedSamples $statusSamples 240)
    return [ordered]@{
        status = 'read'
        sessionFound = $true
        phases = @($phases)
        statusSamplesObserved = $statusSamples.Count
        statusSamplesReturned = $boundedStatus.Count
        statusSamplesDownsampled = $statusSamples.Count -gt $boundedStatus.Count
        statusSamples = $boundedStatus
        latestPartMeasurements = @($latestParts.Values)
        operationalEvents = @($operationalEvents)
        ruleTimings = @($ruleTimings)
        errors = @($errors)
        buildIdentity = $buildIdentity
        finished = $finished
    }
}

function Read-Outcome([string]$Directory) {
    $path = Join-Path $Directory 'run-outcome.json'
    if (-not [System.IO.File]::Exists($path)) {
        return [ordered]@{ status = 'missing' }
    }

    try {
        $value = Read-SharedText $path | ConvertFrom-Json
        return [ordered]@{
            status = 'read'
            outcome = $value.outcome
            endedUtc = $value.endedUtc
            detailExcluded = $true
        }
    }
    catch {
        return [ordered]@{
            status = 'unreadable:' + $_.Exception.GetType().Name
        }
    }
}

function Read-AnalysisManifest([string]$Directory, [string]$Name) {
    $path = Join-Path $Directory $Name
    if (-not [System.IO.File]::Exists($path)) {
        return [ordered]@{ name = $Name; status = 'missing' }
    }

    try {
        $file = Get-Item -LiteralPath $path -Force
        if ($file.Length -gt 65536) {
            return [ordered]@{ name = $Name; status = 'unreadable:oversized' }
        }
        $value = Read-SharedText $path | ConvertFrom-Json
        return [ordered]@{
            name = $Name
            status = 'read'
            version = $value.version
            generationId = $value.generationId
        }
    }
    catch {
        return [ordered]@{
            name = $Name
            status = 'unreadable:' + $_.Exception.GetType().Name
        }
    }
}

function Invoke-Collector([string]$SourceDirectory, [string]$Destination) {
    $source = Resolve-NormalizedPath $SourceDirectory -MustExist
    if (-not [System.IO.Directory]::Exists($source)) {
        throw "RunDirectory is not a directory: $SourceDirectory"
    }

    $destination = Resolve-NormalizedPath $Destination
    if ($destination -eq $source -or (Test-IsInside $destination $source)) {
        throw 'OutputPath must be outside the run directory so collection cannot consume its remaining disk space.'
    }
    if ([System.IO.Directory]::Exists($destination)) {
        throw 'OutputPath must name a JSON file, not a directory.'
    }
    if ([System.IO.Path]::GetExtension($destination) -ne '.json') {
        throw 'OutputPath must end in .json.'
    }

    $parent = [System.IO.Path]::GetDirectoryName($destination)
    if (-not [System.IO.Directory]::Exists($parent)) {
        throw "The OutputPath directory does not exist: $parent"
    }

    $fileNames = @(
        'evidence.db', 'evidence.db-wal', 'evidence.db-shm',
        'evidence.db.partial', 'evidence.db.partial-wal', 'evidence.db.partial-shm',
        'derivation.db', 'derivation.db-wal', 'derivation.db-shm',
        'derivation.db.partial', 'derivation.db.partial-wal', 'derivation.db.partial-shm',
        'judgement.db', 'judgement.db-wal', 'judgement.db-shm',
        'judgement.db.partial', 'judgement.db.partial-wal', 'judgement.db.partial-shm',
        'derivation.current.json', 'derivation.current.json.partial',
        'judgement.current.json', 'judgement.current.json.partial', 'judgement.write.lock',
        'run.log', 'run-outcome.json', 'run-summary.txt')
    $analysisFiles = Find-AnalysisFiles $source
    $fileNames = @($fileNames + $analysisFiles.names | Sort-Object -Unique)

    $root = [System.IO.Path]::GetPathRoot($source)
    $drive = [System.IO.DriveInfo]::new($root)
    $report = [ordered]@{
        schemaVersion = 2
        collectedUtc = [DateTime]::UtcNow.ToString('o')
        safety = [ordered]@{
            databaseContentsOpened = $false
            databaseFilesCopied = $false
            databaseFilesHashed = $false
            sqliteLoaded = $false
            runDirectoryNameExcluded = $true
            runLogIdentityFieldsExcluded = $true
            outcomeDetailExcluded = $true
            activeWriterCheck = 'unavailable:no-safe-reliable-metadata-only-check'
        }
        volume = [ordered]@{
            totalBytes = $drive.TotalSize
            freeBytes = $drive.AvailableFreeSpace
        }
        analysisFileEnumerationStatus = $analysisFiles.status
        files = @($fileNames | ForEach-Object { Get-FileFact $source $_ })
        analysisManifests = @(
            Read-AnalysisManifest $source 'derivation.current.json'
            Read-AnalysisManifest $source 'derivation.current.json.partial'
            Read-AnalysisManifest $source 'judgement.current.json'
            Read-AnalysisManifest $source 'judgement.current.json.partial')
        judgingLog = Read-JudgingLog $source
        runOutcome = Read-Outcome $source
    }

    $json = $report | ConvertTo-Json -Depth 12
    [System.IO.File]::WriteAllText(
        $destination, $json + [Environment]::NewLine, [System.Text.UTF8Encoding]::new($false))
    return $report
}

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) {
        throw "Self-test failed: $Message"
    }
}

function Get-TestFileSha256([string]$Path) {
    $algorithm = [System.Security.Cryptography.SHA256]::Create()
    $stream = [System.IO.File]::OpenRead($Path)
    try {
        return [BitConverter]::ToString($algorithm.ComputeHash($stream)).Replace('-', '')
    }
    finally {
        $stream.Dispose()
        $algorithm.Dispose()
    }
}

function Invoke-SelfTest {
    $scratch = Join-Path ([System.IO.Path]::GetTempPath()) ('securead-collector-' + [Guid]::NewGuid().ToString('N'))
    $run = Join-Path $scratch 'synthetic-run'
    $output = Join-Path $scratch 'report.json'
    [System.IO.Directory]::CreateDirectory($run) | Out-Null

    try {
        [System.IO.File]::WriteAllBytes(
            (Join-Path $run 'evidence.db'), [byte[]](0x53, 0x51, 0x4c, 0x69))
        [System.IO.File]::WriteAllBytes(
            (Join-Path $run 'judgement.db.partial-shm'), [byte[]](1..32))
        $generationName = 'judgement.11111111111111111111111111111111.db'
        [System.IO.File]::WriteAllBytes(
            (Join-Path $run $generationName), [byte[]](0x53, 0x51, 0x4c, 0x69))
        [System.IO.File]::WriteAllText(
            (Join-Path $run 'judgement.current.json'),
            '{"version":1,"generationId":"11111111-1111-1111-1111-111111111111"}')
        [System.IO.File]::SetAttributes(
            (Join-Path $run 'evidence.db'), [System.IO.FileAttributes]::ReadOnly)
        $log = @'

==== 2026-10-08T01:00:00Z  judging ====
2026-10-08T01:00:00Z  INFO   Judge                   judging build attempt=7e0068f0-9d2a-49e0-b90c-d7efbd54c123 processPath="C:\Customer\Secret\SecureAD.Cli.exe" processFileSha256=AAAA entryAssembly=SecureAD.Cli entryMvid=11111111-1111-1111-1111-111111111111 engineAssembly=SecureAD.Judgement engineMvid=22222222-2222-2222-2222-222222222222 engineVersion=1.0 engineConfiguration=Release enginePath="C:\Customer\Secret\SecureAD.Judgement.dll" engineFileSha256=BBBB runtime=".NET 10" architecture=X64
2026-10-08T01:00:01Z  INFO   Judge                   phase name=BuildingTier0Paths
2026-10-08T01:00:02Z  INFO   Judge                   post-pass part stage=Tier0Paths outcome=running part=write-proof completedMs=1200 activeMs=300 target="CN=Tier Zero,DC=customer,DC=invalid"
2026-10-08T01:00:03Z  INFO   Judge                   post-pass status stage=Tier0Paths activePart=write-proof elapsedMs=2000 workingSetBytes=1234 privateBytes=2345 managedEstimatedBytes=3456 processAllocatedBytes=4567 targetsTotal=12 targetsProcessed=3
2026-10-08T01:00:04Z  ERROR  Judge                   JudgementWriteFailed target="CN=Tier Zero,DC=customer,DC=invalid"
                                                     disk or database is full at C:\Customer\Secret\judgement.db.partial
'@
        $statusBurst = 0..299 | ForEach-Object {
            '2026-10-08T01:01:00Z  INFO   Judge                   post-pass status stage=Tier0Paths activePart=write-proof elapsedMs={0} targetsTotal=300 targetsProcessed={1}' -f (3000 + $_), $_
        }
        $log += [Environment]::NewLine + ($statusBurst -join [Environment]::NewLine)
        [System.IO.File]::WriteAllText((Join-Path $run 'run.log'), $log)
        [System.IO.File]::WriteAllText(
            (Join-Path $run 'run-outcome.json'),
            '{"outcome":"Failed","detail":"customer secret","endedUtc":"2026-10-08T01:00:05Z"}')

        $before = Get-TestFileSha256 (Join-Path $run 'evidence.db')
        $evidenceLock = [System.IO.File]::Open(
            (Join-Path $run 'evidence.db'),
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read,
            [System.IO.FileShare]::None)
        $sidecarLock = [System.IO.File]::Open(
            (Join-Path $run 'judgement.db.partial-shm'),
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read,
            [System.IO.FileShare]::None)
        $generationLock = [System.IO.File]::Open(
            (Join-Path $run $generationName),
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read,
            [System.IO.FileShare]::None)
        try {
            $report = Invoke-Collector $run $output
        }
        finally {
            $generationLock.Dispose()
            $sidecarLock.Dispose()
            $evidenceLock.Dispose()
        }
        $after = Get-TestFileSha256 (Join-Path $run 'evidence.db')
        $json = [System.IO.File]::ReadAllText($output)

        Assert-True ($before -eq $after) 'a database file changed'
        Assert-True ($report.safety.databaseContentsOpened -eq $false) 'safety declaration changed'
        Assert-True ($report.safety.runDirectoryNameExcluded -eq $true) 'run-directory exclusion was not declared'
        Assert-True (-not $report.Contains('runDirectoryName')) 'the run directory name was exported'
        Assert-True ($report.files.Where({ $_.name -eq 'judgement.db.partial-shm' }).logicalBytes -eq 32) 'SHM metadata was not collected'
        Assert-True ($report.files.Where({ $_.name -eq 'judgement.db.partial' }).exists -eq $false) 'a missing database was not explicit'
        Assert-True ($report.files.Where({ $_.name -eq $generationName }).logicalBytes -eq 4) 'a generation database was not discovered'
        Assert-True ($report.analysisManifests.Where({ $_.name -eq 'judgement.current.json' }).generationId -eq '11111111-1111-1111-1111-111111111111') 'the selected generation was not reported'
        Assert-True ($report.judgingLog.phases.Count -eq 1) 'the judging phase was not extracted'
        Assert-True ($report.judgingLog.statusSamplesObserved -eq 301) 'status samples were not counted'
        Assert-True ($report.judgingLog.statusSamples.Count -eq 240) 'status samples were not bounded'
        Assert-True ($report.judgingLog.statusSamplesDownsampled) 'status downsampling was not reported'
        Assert-True ($report.judgingLog.statusSamples[0].managedEstimatedBytes -eq '3456') 'managed memory was not extracted'
        Assert-True ($report.judgingLog.statusSamples[-1].targetsProcessed -eq '299') 'a stage counter was not extracted'
        Assert-True ($report.judgingLog.latestPartMeasurements[0].completedMs -eq '1200') 'the latest part measurement was not extracted'
        Assert-True ($report.judgingLog.errors[0].code -eq 'JudgementWriteFailed') 'the stable error code was not extracted'
        Assert-True ($report.judgingLog.buildIdentity.processFileSha256 -eq 'AAAA') 'the executable hash was not extracted'
        Assert-True (-not $report.judgingLog.buildIdentity.Contains('processPath')) 'the executable path was exported'
        Assert-True (-not $report.judgingLog.buildIdentity.Contains('enginePath')) 'the engine path was exported'
        Assert-True (-not $json.Contains('CN=Tier Zero')) 'a customer identity escaped into the report'
        Assert-True (-not $json.Contains('Customer')) 'a customer path escaped into the report'
        Assert-True (-not $json.Contains('customer secret')) 'outcome detail escaped into the report'
        Assert-True ((Get-Item $output).Length -lt 262144) 'the synthetic report is not compact'

        $inside = Join-Path $run 'unsafe.json'
        $refused = $false
        try {
            Invoke-Collector $run $inside | Out-Null
        }
        catch {
            $refused = $_.Exception.Message.Contains('outside the run directory')
        }
        Assert-True $refused 'an output inside the run directory was not refused'
        'Collector self-test passed.'
    }
    finally {
        if ([System.IO.File]::Exists((Join-Path $run 'evidence.db'))) {
            [System.IO.File]::SetAttributes(
                (Join-Path $run 'evidence.db'), [System.IO.FileAttributes]::Normal)
        }
        [System.IO.Directory]::Delete($scratch, $true)
    }
}

if ($SelfTest) {
    Invoke-SelfTest
}
else {
    Invoke-Collector $RunDirectory $OutputPath | Out-Null
    "Wrote compact judgement failure report to $OutputPath"
}
