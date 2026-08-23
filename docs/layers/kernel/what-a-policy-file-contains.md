# What a policy file contains

**Component.** `next/src/SecureAD.Kernel/GroupPolicy/` — the half that parses the files behind a
Group Policy object. Eleven types across three unrelated file formats.

The other half — what a policy says about itself in the directory — is
[`what-a-policy-declares.md`](what-a-policy-declares.md). Nothing on this page reads a directory
attribute; nothing on that page parses a file.

The governing area file is [`group-policy.md`](../../areas/group-policy.md).

---

## What this is for

Three file formats live under a policy's folder in SYSVOL, and each says something different about
what the policy does to a machine:

| File | Format | Says |
|---|---|---|
| `Registry.pol` | Binary, [MS-GPREG] §2.2 | Registry values the policy sets |
| `GptTmpl.inf` | INI-style, UTF-16LE with a mark | Privileges granted, and group membership forced |
| Preference XML | XML | Whether a credential is stored in SYSVOL |

**All three parsers are pure.** No OS calls, no file access, no registry access — bytes in, records
out. Every one of them takes a `ReadOnlySpan<byte>` or a string and returns a record carrying what
was read beside what could not be.

**And all three were written from public specification.** The registry parser from [MS-GPREG]; the
preference parser from [MS-GPPREF] and MS14-025; the template parser from the published Windows
Security Templates documentation. None is derived from a third-party parser.

---

## The types

| Type | What it is |
|---|---|
| `RegistryPolicyParser` | Reads `Registry.pol` bytes |
| `ParsedRegistryPolicy` | The entries read, beside any errors |
| `RegistryPolicyEntry` | One registry value, raw bytes preserved |
| `RegistryValueType` | The REG_* constants a value can carry |
| `SecurityTemplateParser` | Reads `GptTmpl.inf` bytes or text |
| `ParsedSecurityTemplate` | Every section, losslessly, plus two typed readings |
| `SecurityTemplateSetting` | One name/value line from a section |
| `RestrictedGroup` | One principal's forced membership |
| `GroupPolicyPreferenceParser` | Scans preference XML for stored credentials |
| `ParsedGppFile` | The findings, beside any errors |
| `GppPasswordFinding` | That a credential is present, and where |

---

## The registry policy file

An 8-byte header — the signature `PReg` and a version — followed by entries of the shape
`[key;value;type;size;data]`, encoded UTF-16LE, where the key and value are null-terminated strings
and the type and size are little-endian 32-bit numbers.

**Three refusals, and they are graded differently.**

| Condition | What happens |
|---|---|
| Fewer than 8 bytes | Error, no entries returned |
| Signature is not `PReg` | Error, no entries returned |
| Version is not 1 | **Error recorded, and parsing continues** |

The third is the one worth noticing. An unexpected version is reported, but the file is still read,
because the entry format may be unchanged and refusing outright would report nothing about a policy
that is probably readable. The operator is told; the data is not withheld.

Within the entries the parse is **partial by design**: a structural fault records an entry-scoped
message naming the entry index and byte offset, then stops, returning everything read up to that
point. A truncated file yields the entries before the truncation, not an exception and not nothing.

### Raw bytes are kept, and typing is on demand

`RegistryPolicyEntry` preserves `Data` verbatim and interprets it only when asked. The accessors
return null when the type does not match, rather than a zero or an empty string.

`AsMultiString` is the case to read. It returns **null** for a value that is not a multi-string, and
an **empty list** for a multi-string holding no strings. Those are different answers, and returning
the same empty list for both is precisely the ambiguity gate 4 and
[`0002`](../../decisions/0002-absent-view-means-degraded-run.md) exist to prevent.

An unknown raw type is preserved by the cast rather than rejected — compare against the raw
`RegistryType` when fidelity matters.

---

## The security template

INI-style: `[Section]` headers, `Name = Value` lines, `;`-prefixed comments, blank lines.

**The encoding is detected from a byte-order mark** — UTF-16LE, UTF-16BE, or UTF-8 — falling back to
UTF-8 when there is no mark. Real templates are typically UTF-16LE with a mark, and a template read
as UTF-8 would be unintelligible rather than merely wrong.

**Every section is kept losslessly** as raw name/value settings, in file order, keyed
case-insensitively. A duplicate section header appends into the existing section rather than
replacing it. Two sections are additionally given a typed reading; the rest remain reachable as raw
settings.

A missing section reads as **empty, not as an error**. A malformed section header, a line with no
`=`, and a setting appearing before any section header are each recorded with a line number, and
parsing continues to the next line.

### The two typed readings

**Privilege rights** maps a privilege constant to the trustees granted it. **Group membership** —
Restricted Groups — combines the `__Members` and `__Memberof` lines for each principal, preserving
first-seen order so output is deterministic. A line in that section matching neither suffix is
skipped from the typed reading and remains in the raw section.

In both, the security-template `*` SID prefix is stripped, so a trustee arrives as a bare SID such
as `S-1-5-32-544`, or as a name.

---

## The stored credential

A non-empty `cpassword` attribute in a preference file is an encrypted credential sitting in SYSVOL.
Because the AES key is **published in [MS-GPPREF]**, any authenticated user who can read SYSVOL can
decrypt it. Its mere presence is therefore a credential exposure, not a risk of one. This is
MS14-025 / CVE-2014-1812.

**Presence-only, and this is enforced by the shape of the types rather than by care.** The parser
reads the attribute solely to test whether it is present and non-empty, then discards it.
`GppPasswordFinding` has no field that could hold the value, encrypted or decrypted. The credential
never enters the type system, so it cannot be returned, logged or persisted.

**The published decryption key is deliberately absent from this codebase** — checked against the
code, not recalled. The product locates the exposure; operators verify natively.

A finding carries three things and no more: the element type carrying the password, the account name
when the file names one, and which attribute named it. The element type reported is the **parent**
element — `User`, `NTService`, `Task`, `DataSource`, `Drive`, `SharedPrinter` — because in these
files the attribute lives on an inner `Properties` element, and reporting that would tell an operator
nothing. Element names are tracked by depth so the parent is available when the attribute is found.

One finding is raised per affected account, not one per file.

### The XML reader is hardened

These files come from SYSVOL and could be attacker-influenced, so DTD processing is **prohibited**
and the resolver is null. A hostile preference file cannot make the product fetch anything, and
entity expansion cannot be used against it. Malformed XML returns an error rather than throwing. A
UTF-8 byte-order mark is skipped before parsing, because a leading mark is invalid at the document
root.

---

## What is not here, checked against the code

- **Nothing judges any of this.** These are readers. The rules that would decide whether a privilege
  grant or a forced membership is dangerous are largely unwritten, and which questions matter has not
  been settled. That question is tracked as `P-46` in [`PUNCH-LIST.md`](../../PUNCH-LIST.md).
- **No `cpassword` value is decrypted, stored, or returned**, and the key is not in the repository.
- **Only two template sections are given a typed reading.** The rest are kept, not interpreted.
- **Nothing here opens a file.** Fetching is capture's, gated by
  [`what-a-policy-declares.md`](what-a-policy-declares.md).

---

## What an operator can do

| An operator can… | Proven by | Confirmed in lab |
|---|---|---|
| have a policy's registry settings read from the file behind it | `RegistryPolicyParserTests.WhenDwordEntry_ThenKeyValueAndTypeParsed` |  |
| be certain a corrupt registry policy file reports an error rather than throwing | `RegistryPolicyParserTests.WhenInvalidSignature_ThenReturnsError` |  |
| be certain a policy file of an unexpected version is still parsed, and says so | `RegistryPolicyParserTests.WhenUnexpectedVersion_ThenReturnsErrorButStillParses` |  |
| have a security template read whatever encoding it was written in | `SecurityTemplateParserTests.WhenUtf16LeWithBom_ThenParsesSections` |  |
| see which principals a policy grants a privilege to | `SecurityTemplateParserTests.WhenPrivilegeRights_ThenTrusteesSplitAndStarStripped` |  |
| be certain a missing template section is empty rather than an error | `SecurityTemplateParserTests.WhenSectionAbsent_ThenGetSectionReturnsEmpty` |  |
| be certain the raw settings of a template are preserved rather than interpreted away | `SecurityTemplateParserTests.WhenSystemAccessSection_ThenRawSettingsPreserved` |  |
| find a password stored in a Group Policy preference | `GroupPolicyPreferenceParserTests.WhenCpasswordPresent_ThenValueNeverAppearsInResult` |  |
| be certain that finding never carries the password itself | `GroupPolicyPreferenceParserTests.WhenFindingType_ThenHasNoPasswordProperty` |  |
| be certain one finding is raised per affected account | `GroupPolicyPreferenceParserTests.WhenMultipleUsersWithCpassword_ThenOneFindingEach` |  |
| be certain a hostile preference file cannot make the product fetch anything | `GroupPolicyPreferenceParserTests.WhenDtdExternalEntity_ThenParsesWithoutResolvingEntity` |  |
| be certain malformed policy XML returns an error rather than throwing | `GroupPolicyPreferenceParserTests.WhenMalformedXml_ThenReturnsErrorNotThrow` |  |

Copied from the area file's *What is built* table, which keeps them.

---

## What reads this

Capture fetches these files only for policies that declare an analysable client-side extension. The
rule catalogue is held as data and the rule logic as code —
[`0010`](../../decisions/0010-the-rule-catalogue-is-data-the-rule-logic-is-code.md) — so the rules that
will read these records are separate from the parsers on this page.
