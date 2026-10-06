#Requires -Version 7.0
# Windows PowerShell 5.1 reads UTF-8 files as Windows-1252, turning every em dash into three
# characters. This script writes documents, so running it under 5.1 would corrupt them silently.

$ErrorActionPreference = 'Stop'
$path = 'C:\Users\jistrand\source\repos\SecureAD.Next\Directory.Build.props'

$content = @'
<Project>
  <PropertyGroup>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>

    <!-- Product version, inherited from the repository this rebuild was cut out of.

         NOTHING IN THIS REPOSITORY READS IT. The comment that stood here described
         ToolVersion.Current reading it and run.tool_version recording it so a bundle could
         name the code that produced it, and CompareCompatibilityValidator comparing only the
         major component. None of those types travelled - all four names resolve to zero
         references here. The machinery is in the predecessor repository with the old
         application.

         The value is left as it was rather than guessed at, because choosing the rebuild's
         version is a product decision and inventing one would be worse than carrying a
         number that is at least traceable. When the rebuild records its own version in a
         bundle, this comment should describe what does the reading. -->
    <Version>3.0.0</Version>

    <!-- Static analysis: the .NET and code-style analyzers, at the curated high-signal
         "minimum" set - genuine correctness, reliability and security rules rather than the
         full recommended set. Warnings are surfaced but not treated as errors, so findings
         are visible in build output and the IDE without breaking a green build. Per-rule
         severities are tuned in .editorconfig.

         The reasoning for "minimum" was that the recommended set floods an established
         123K-line codebase with style nits. That codebase was the old application. This one
         is 32,348 lines, so the original justification no longer holds and the setting is
         worth revisiting on its own merits rather than inherited. -->
    <EnableNETAnalyzers>true</EnableNETAnalyzers>
    <AnalysisLevel>latest-minimum</AnalysisLevel>
    <EnforceCodeStyleInBuild>true</EnforceCodeStyleInBuild>
  </PropertyGroup>
</Project>
'@

Set-Content -LiteralPath $path -Value $content -Encoding UTF8
Write-Host "rewrote $path"
