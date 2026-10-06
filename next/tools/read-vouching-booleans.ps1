$src = 'C:\Users\jistrand\source\repos\SecureAD.Next\next\src'

$booleans = @(
    'PermissionWording|RightsAreComplete'
    'UserAccountControlWording|FlagsAreComplete'
    'DirectoryTree|BranchesAreComplete'
    'ObjectPage|ObjectsAreComplete'
    'PartitionCoverage|ContinuationReferencesAreComplete'
    'RuleDefinition|IsComplete'
    'RuleVerdict|IsComplete'
    'RunCoverage|AllDeclaredUnitsAreComplete'
    'RunScope|AllDeclaredDomainsAreComplete'
    'StoredFindings|DidNotRun'
    'SysvolCoverage|AllDeclaredPoliciesAreComplete'
    'CapturePlan|IsComplete'
    'ContinuationReferenceReconciliation|IsComplete'
    'ControllerSelection|IsComplete'
    'DomainPreflight|IsComplete'
    'DomainSelection|IsComplete'
    'ForestRoles|IsComplete'
    'ForestTopology|IsComplete'
    'GpoInventory|DeclaredPoliciesAreComplete'
    'IDirectoryChannel|IsComplete'
    'LdapDirectoryChannel|IsComplete'
    'PreflightContents|AllDomainsWereAsked'
    'PreflightDomainRecord|AllQuestionsWereAsked'
    'PreflightReport|IsComplete'
)

$files = Get-ChildItem $src -Recurse -Filter *.cs

foreach ($entry in $booleans) {
    $type, $member = $entry.Split('|')
    ''
    "########## $type.$member"

    $found = $false
    foreach ($f in $files) {
        $lines = [System.IO.File]::ReadAllLines($f.FullName)

        # only look in a file that declares the type
        if (-not ($lines -match ("(record|class|struct|interface)\s+" + [regex]::Escape($type) + "\b"))) { continue }

        for ($i = 0; $i -lt $lines.Count; $i++) {
            if ($lines[$i] -notmatch ("\b" + [regex]::Escape($member) + "\b")) { continue }
            # a declaration, not a use: bool in the line, or an => on it
            if ($lines[$i] -notmatch 'bool|=>|,\s*$|\)\s*$') { continue }

            "  [$($f.Name):$($i+1)]"
            $lo = [Math]::Max(0, $i - 1)
            $hi = [Math]::Min($lines.Count - 1, $i + 3)
            $lo..$hi | ForEach-Object { '      ' + $lines[$_].TrimEnd() }
            $found = $true
            break
        }
        if ($found) { break }
    }
    if (-not $found) { "  !! declaration not located" }
}
