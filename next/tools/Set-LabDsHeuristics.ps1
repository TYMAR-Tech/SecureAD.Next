<#
.SYNOPSIS
    Sets, shows or clears the forest's dSHeuristics AdminSDHolder exclusion mask, for verifying
    SecureAD against a real directory.

.DESCRIPTION
    dSHeuristics is a forest-wide string in which each character position is a separate setting
    (MS-ADTS 6.1.1.2.4.1.2). Character 16, dwAdminSDExMask, removes operator groups from the set
    AdminSDHolder protects:

        bit 0 (1) Account Operators    bit 2 (4) Print Operators
        bit 1 (2) Server Operators     bit 3 (8) Backup Operators

    THIS MAKES A REAL SECURITY CHANGE TO A REAL FOREST. The groups named stop being protected
    across every domain, from one write. Run it against a throwaway lab and nothing else.

    Two rules make hand-editing this dangerous, and both are enforced here:

    1. Every tenth character is a checksum the server enforces - character 10 must be "1",
       character 20 must be "2", character 30 must be "3". A string that breaks this is rejected
       outright by the domain controller.
    2. Existing characters must be preserved. Overwriting the whole value would silently change
       every other forest-wide setting it carries.

.PARAMETER Mask
    The hex digit for character 16. 'f' excludes all four groups; '1' excludes Account Operators
    alone. Valid values are 0-9 and a-f.

.PARAMETER Show
    Report the current value and what it resolves to, and change nothing.

.PARAMETER Revert
    Restore character 16 to '0'. If that leaves the string with nothing but defaults, the attribute
    is cleared entirely.

.PARAMETER Server
    The forest root domain controller to write to. Defaults to the current forest's schema master,
    which is always in the root domain.

.EXAMPLE
    .\Set-LabDsHeuristics.ps1 -Show

.EXAMPLE
    .\Set-LabDsHeuristics.ps1 -Mask f

.EXAMPLE
    .\Set-LabDsHeuristics.ps1 -Revert

.NOTES
    Requires the ActiveDirectory module and Enterprise Admin rights in the forest root.

    Reverting does not immediately re-protect the affected groups. SDProp resumes on its next
    cycle (60 minutes by default), and adminCount and the inheritance flag on already-affected
    objects persist until it runs. Not a problem in a lab, but do not read the intermediate state
    as a defect in the product.
#>

[CmdletBinding(DefaultParameterSetName = 'Show', SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(ParameterSetName = 'Set', Mandatory)]
    [ValidatePattern('^[0-9a-fA-F]$')]
    [string] $Mask,

    [Parameter(ParameterSetName = 'Show')]
    [switch] $Show,

    [Parameter(ParameterSetName = 'Revert', Mandatory)]
    [switch] $Revert,

    [string] $Server
)

$ErrorActionPreference = 'Stop'

# The position of dwAdminSDExMask, one-based as MS-ADTS numbers it.
$MaskPosition = 16

# An explicit array rather than a hashtable keyed by the bit value. An [ordered] hashtable's .Keys
# are boxed objects, so enumerating them and indexing back in silently returned the wrong names -
# mask 'f' reported two groups and two blanks. Pairs cannot drift the same way.
$GroupsByBit = @(
    [pscustomobject]@{ Bit = 1; Name = 'Account Operators (S-1-5-32-548)' }
    [pscustomobject]@{ Bit = 2; Name = 'Server Operators  (S-1-5-32-549)' }
    [pscustomobject]@{ Bit = 4; Name = 'Print Operators   (S-1-5-32-550)' }
    [pscustomobject]@{ Bit = 8; Name = 'Backup Operators  (S-1-5-32-551)' }
)

function Get-DirectoryServiceDn {
    param([string] $Server)

    $rootDse = if ($Server) { Get-ADRootDSE -Server $Server } else { Get-ADRootDSE }
    "CN=Directory Service,CN=Windows NT,CN=Services,$($rootDse.configurationNamingContext)"
}

function Resolve-Mask {
    <#
        Applies the same rules the product's DirectoryHeuristics does, so a disagreement between
        this script and SecureAD is a real disagreement rather than two different readings.

        $Value is deliberately untyped. A [string] parameter coerces $null to '', which would
        collapse "the forest holds no attribute" into "the forest holds an empty one" - the exact
        distinction the product keeps apart, erased by a type annotation.
    #>
    param($Value)

    if ($null -eq $Value) {
        return [pscustomobject]@{ State = 'NotRead'; Character = $null; Excluded = @() }
    }

    if ($Value.Length -lt $MaskPosition) {
        # Past the end of the string is normal: the order is fixed and truncation is the only way
        # to omit a character, so every value is a prefix of a longer one nobody wrote.
        return [pscustomobject]@{ State = 'DefaultedByAbsence'; Character = '0'; Excluded = @() }
    }

    $character = $Value[$MaskPosition - 1]
    $digit = 0

    if (-not [int]::TryParse(
            $character, [Globalization.NumberStyles]::HexNumber,
            [Globalization.CultureInfo]::InvariantCulture, [ref] $digit)) {

        # Microsoft documents no behaviour for a character outside 0-9a-f. The product excludes
        # nothing in that case, because the larger protected set is the direction that cannot
        # hide a group.
        return [pscustomobject]@{ State = 'Undocumented'; Character = $character; Excluded = @() }
    }

    $excluded = @($GroupsByBit | Where-Object { $digit -band $_.Bit } | ForEach-Object { $_.Name })
    [pscustomobject]@{ State = 'Stated'; Character = $character; Excluded = $excluded }
}

function New-HeuristicsValue {
    <#
        Builds the value to write, preserving every character already present and honouring the
        every-tenth-character checksum the server enforces.
    #>
    param($Existing, [char] $NewMaskCharacter)

    $characters = [char[]]::new($MaskPosition)

    for ($i = 0; $i -lt $MaskPosition; $i++) {
        $position = $i + 1

        $characters[$i] =
            if ($Existing -and $i -lt $Existing.Length) { $Existing[$i] }
            elseif ($position % 10 -eq 0) { [char]([int][char]'0' + ($position / 10)) }
            else { '0' }
    }

    $characters[$MaskPosition - 1] = $NewMaskCharacter

    # Anything beyond position 16 that the forest already had is kept verbatim.
    $tail = if ($Existing -and $Existing.Length -gt $MaskPosition) { $Existing.Substring($MaskPosition) } else { '' }

    (-join $characters) + $tail
}

function Assert-Checksums {
    param([string] $Value)

    for ($position = 10; $position -le $Value.Length; $position += 10) {
        $expected = [char]([int][char]'0' + ($position / 10))
        if ($Value[$position - 1] -ne $expected) {
            throw "Character $position must be '$expected' or the domain controller rejects the write. " +
                  "Built '$Value', which a controller would refuse. This is a defect in this script - " +
                  "do not work around it by editing the value by hand."
        }
    }
}

function Write-State {
    # $Value untyped for the reason Resolve-Mask gives: [string] would turn $null into ''.
    param([string] $Dn, $Value)

    $resolved = Resolve-Mask $Value

    $shown =
        if ($null -eq $Value) { '<attribute not present>' }
        elseif ($Value -eq '') { "'' (present, empty)" }
        else { "'$Value'" }

    Write-Host ''
    Write-Host "  Object : $Dn"
    Write-Host "  Value  : $shown"
    Write-Host "  Char 16: $(if ($resolved.Character) { "'$($resolved.Character)'" } else { '-' })  ($($resolved.State))"

    if ($resolved.Excluded.Count -eq 0) {
        Write-Host '  Excluded from AdminSDHolder protection: none' -ForegroundColor Green
    }
    else {
        Write-Host '  Excluded from AdminSDHolder protection:' -ForegroundColor Yellow
        $resolved.Excluded | ForEach-Object { Write-Host "    - $_" -ForegroundColor Yellow }
    }

    Write-Host ''
}

# --- main ---------------------------------------------------------------------------------------

Import-Module ActiveDirectory -ErrorAction Stop

if (-not $Server) {
    # The schema master is always in the forest root, which is where this attribute lives.
    $Server = (Get-ADForest).SchemaMaster
    Write-Verbose "No -Server given; using the schema master $Server."
}

$dn = Get-DirectoryServiceDn -Server $Server
$current = (Get-ADObject $dn -Properties dSHeuristics -Server $Server).dSHeuristics

Write-Host ''
Write-Host "Forest : $((Get-ADForest).Name)" -ForegroundColor Cyan
Write-Host "Server : $Server" -ForegroundColor Cyan
Write-Host '--- current ---'
Write-State -Dn $dn -Value $current

if ($PSCmdlet.ParameterSetName -eq 'Show') { return }

$target =
    if ($Revert) { New-HeuristicsValue -Existing $current -NewMaskCharacter '0' }
    else { New-HeuristicsValue -Existing $current -NewMaskCharacter $Mask[0] }

# A string of nothing but defaults is indistinguishable from an absent attribute, and MS-ADTS says
# the attribute does not exist by default. Clearing it is the truer revert.
$clearInstead = $Revert -and ($target -replace '0', '' -replace '1', '') -eq '' -and $target.Length -le $MaskPosition

Write-Host '--- proposed ---'
if ($clearInstead) {
    Write-Host ''
    Write-Host "  Clear dSHeuristics entirely (every character would be its default)."
    Write-Host ''
}
else {
    Assert-Checksums $target
    Write-State -Dn $dn -Value $target
}

if ($current -and -not $Revert) {
    Write-Host 'This forest already holds a value. Every character outside position 16 has been' -ForegroundColor Yellow
    Write-Host 'preserved above - check it against the current value before continuing.' -ForegroundColor Yellow
    Write-Host ''
}

$action = if ($clearInstead) { 'Clear dSHeuristics' } else { "Set dSHeuristics to '$target'" }

if (-not $PSCmdlet.ShouldProcess("$dn on $Server", $action)) { return }

if ($clearInstead) {
    Set-ADObject $dn -Clear dSHeuristics -Server $Server
}
else {
    Set-ADObject $dn -Replace @{ dSHeuristics = $target } -Server $Server
}

Write-Host 'Written. Replicating...' -ForegroundColor Green
& repadmin /syncall $Server /AeD | Out-Null

$after = (Get-ADObject $dn -Properties dSHeuristics -Server $Server).dSHeuristics

Write-Host '--- after ---'
Write-State -Dn $dn -Value $after

Write-Host 'Next: take a FRESH capture. A bundle captured before catalogue version 5 has no column' -ForegroundColor Cyan
Write-Host 'for this attribute and can never be re-read for it.' -ForegroundColor Cyan
Write-Host ''
