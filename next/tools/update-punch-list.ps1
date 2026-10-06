#Requires -Version 7.0
# Windows PowerShell 5.1 reads UTF-8 files as Windows-1252, turning every em dash into three
# characters. This script writes documents, so running it under 5.1 would corrupt them silently.

$path = 'C:\Users\jistrand\source\repos\SecureAD.Next\docs\PUNCH-LIST.md'
$lines = [System.IO.File]::ReadAllLines($path)

function Expect($index, $fragment) {
    if (-not $lines[$index].Contains($fragment)) {
        throw "line $index does not contain '$fragment' - refusing to edit blind"
    }
}

# --- 1. P-60: the contention was an artefact of the anchor -----------------------------------
Expect 375 '| P-60 |'
$lines[375] = '| P-60 | **Seven types were named by more than one layer document, and the register allows each type exactly one owner.** Recorded as six; measured 2026-08-22 as seven, the entry having inherited its table rather than counted it - ' +
    '`CapturedAttribute` was missing and `CapturedAttributeCatalog` was named by four pages, not three. **Closed 2026-08-22, and not by ruling seven cases.** The contention was an artefact of the anchor, exactly as `P-61` predicted: anchored to *mentions*, seven types had two to four claimants; anchored to *declarations* - the type''s row in a page''s `TYPES` table - 28 of the 31 rows had exactly one owner and none had two. ' +
    'The three undeclared were `ObjectAttributes`, `ObjectAttribute` and `AttributeValue`, which `what-an-object-holds.md` now claims, plus `NamingContextKind`, ruled to `run-identity-and-coverage.md` because `the-search-capture-issues.md` disowns it in writing and the coverage page describes the member it types. Measured by `next/tools/measure-declared-owners.ps1` | done | - |'

# --- 2. P-61: the stronger anchor is identified, and is only on 8 of 22 pages -----------------
Expect 376 '| P-61 |'
$lines[376] = '| P-61 | **`P-52` measures something slightly weaker than its name.** It treats *named by a layer document* as *documented there*, and `P-60` showed the two differ - a page may mention another folder''s type in passing. So it can call an area file redundant before its content is genuinely consumed. It errs in the safe direction, failing early rather than passing falsely. ' +
    '**The stronger anchor P-61 asked for exists and is already in the tree:** a page''s `TYPES` table declares what it owns, and `P-60` was dissolved by reading it. It is not yet universal - measured 2026-08-22, 8 of 22 layer documents carry one, and the 14 without include every page under `docs/layers/evidence` and `docs/layers/connect`. Giving every layer document a `TYPES` table, bound in both directions as `what-an-object-holds.md` binds its own, would let `P-52` anchor to ownership instead of to mentions | open | - |'

# --- 3. the deletion-progress table: the row is gone because the file is ----------------------
Expect 358 '`what-we-capture`'
$lines = $lines[0..357] + $lines[359..($lines.Count - 1)]

# --- 4. the two open findings the area file carried, moved rather than deleted ----------------
Expect 339 '| P-64 |'
$moved = @(
    '| P-65 | **The product may say "The user cannot change the password." when it cannot know that.** Microsoft states on two pages that 0x00000040 cannot be set directly and that the real restriction is a permission entry on the account, so an account can carry the restriction with the bit clear and our sentence is then a confident false negative. Zero of 2,082 accounts in both lab bundles set the bit, which is consistent and proves nothing on its own. Lab check: in Active Directory Users and Computers open a test user, Account tab, tick **User cannot change password**, apply; take a capture, open that user, and read the account-state card. If the sentence is absent while the box is ticked, the wording is misleading and must change. Moved here 2026-08-22 from `docs/areas/what-we-capture.md`, which was deleted; it was F-0080-1 there, and `docs/MICROSOFT-VERIFICATION.md` cites it. Severity deliberately unassigned | open | a lab run |',
    '| P-66 | **The logon-script flag may be a bit we word and the directory never sets.** Microsoft states that ADS_UF_SCRIPT "does not work for the ADSI LDAP provider on either read or write operations", and capture reads over LDAP. If so, "The logon script is executed." is a sentence about a bit that carries no information. Zero of 2,082 accounts in both lab bundles set it. Lab check: in Active Directory Users and Computers open a test user, Profile tab, set a **Logon script** name, apply; take a capture and see whether that user shows the sentence. If a user with a logon script does not, the bit is not readable over LDAP and the entry should stop being worded. Moved here 2026-08-22 from `docs/areas/what-we-capture.md`, which was deleted; it was F-0080-2 there, and `docs/MICROSOFT-VERIFICATION.md` cites it. Severity deliberately unassigned | open | a lab run |'
)
$lines = $lines[0..339] + $moved + $lines[340..($lines.Count - 1)]

[System.IO.File]::WriteAllLines($path, $lines, (New-Object System.Text.UTF8Encoding $false))

$after = [System.IO.File]::ReadAllLines($path)
"lines before: 423   after: $($after.Count)"
"rows citing what-we-capture: " + (($after | Select-String 'what-we-capture').Count)
"longest line: " + (($after | ForEach-Object { $_.Length } | Measure-Object -Maximum).Maximum)
