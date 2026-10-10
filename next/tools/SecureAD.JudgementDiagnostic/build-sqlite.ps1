param([Parameter(Mandatory)][string]$OutputDirectory)
$ErrorActionPreference = 'Stop'
$output = [IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Path $output -Force | Out-Null
$archive = Join-Path $output 'sqlite.zip'
$expected = '1D3049DD0F830A025A53105FC79FD2AB9431AEA99E137809D064D8EE8356B032'
if (-not (Test-Path -LiteralPath $archive)) {
    Invoke-WebRequest 'https://www.sqlite.org/2025/sqlite-amalgamation-3500400.zip' -OutFile $archive
}
if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -ne $expected) {
    throw 'The SQLite source archive does not match the pinned official-source fingerprint.'
}
Expand-Archive -LiteralPath $archive -DestinationPath $output -Force
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$installation = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $installation) { throw 'Visual Studio C++ x64 build tools are required to build the diagnostic SQLite library.' }
$vcvars = Join-Path $installation 'VC\Auxiliary\Build\vcvars64.bat'
# A diagnostic-only SQLite build: no change to the native library shipped by SecureAD.
$command = 'call "{0}" >nul && cd /d "{1}" && cl /nologo /O2 /MT /LD /DSQLITE_API=__declspec(dllexport) /DSQLITE_ENABLE_DBSTAT_VTAB /DSQLITE_THREADSAFE=1 /DSQLITE_TEMP_STORE=3 /DSQLITE_OMIT_LOAD_EXTENSION sqlite-amalgamation-3500400\sqlite3.c /link /OUT:diagnostic_sqlite3.dll' -f $vcvars, $output
& $env:ComSpec /c $command
if ($LASTEXITCODE -ne 0) { throw 'Building diagnostic SQLite failed.' }
