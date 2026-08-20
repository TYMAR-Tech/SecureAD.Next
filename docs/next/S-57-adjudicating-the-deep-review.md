# Adjudication of the Microsoft Source Deep Review

**Status: complete. All twenty-four findings adjudicated against primary sources.**

Written 2026-08-18, against
[`SecureAD-Microsoft-Source-Deep-Review.md`](SecureAD-Microsoft-Source-Deep-Review.md).

> **Superseded basis, 2026-08-19.** [`S-56`](S-56-what-a-permission-grants.md) has been replaced by
> a version converged on across several independent reviews. It corrects the earlier draft on a
> point that matters here: **Active Directory does not use the general Windows early-stop
> algorithm.** Per
> [Checking Simple Access](https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/c55e113e-25a2-45eb-abba-bf5a9e521a8f),
> AD maintains separate Granted and Denied masks and examines the **entire DACL** in stored
> sequence, and there are **four distinct access-check families** — simple, object-specific,
> control-access and validated-write — each consuming stored order differently. Findings `#2` and
> `#3` are adjudicated below on that basis. Any verdict here that rested on the earlier model is
> marked.

## Why this document exists

The review is the strongest we have had, and it is **not a work order.** Of the first three findings
checked, one was wrong in the direction of breaking working code. A confident, well-formatted review
invites assent, and assent is how an unverified claim becomes a commit.

**The rule this applies:** a finding does not become a code change until the governing
*specification* has been read and quoted. Not the conceptual page — MS-ADTS, MS-DTYP, MS-GPOL. The
quote is the point; a link lets an inference hide behind it.

Verdicts are **Upheld**, **Refuted**, **Partly upheld**, or **Not yet adjudicated**. Nothing is
marked from memory.

---

## Adjudicated

### #2 and #3 — Raw ACE evidence must not be sorted, deduplicated or order-insensitively hashed — **UPHELD**

Adjudicated 2026-08-19 on `S-56`'s §5.1. The review argued that "AD does not use one universal
access-check algorithm for every right" and that ACE ordinal therefore cannot be replaced by a
canonical projection. That is now sourced:

> AD initializes separate Granted and Denied masks. It examines the **entire DACL** in stored
> sequence […] This is not the general Windows early-stop description.
> ([Checking Simple Access](https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/c55e113e-25a2-45eb-abba-bf5a9e521a8f))

With four families consuming order differently, a single canonical projection cannot stand in for
the stored DACL, and an order-insensitive hash cannot be the authoritative state of a descriptor.

**The nuance that survives:** normalising for *comparison between runs* remains legitimate — it is
why `AceSetHash` exists. The defect is having only one representation. Two hashes, as the review
proposes — order-sensitive for evidence, order-insensitive for set comparison — is the correct
shape, and it is the same conclusion `#1` reached about masks.

---

### #4 — Malformed evidence becomes a confident null DACL — **UPHELD, and the most serious item in the review**

`SecurityDescriptorParser.cs` line 179:

```csharp
catch (FormatException ex)
{
    ... DaclState.Null, false, [], 0,
        DaclCompleteness: DaclCompleteness.Complete, DaclWasCanonical: true);
```

**Invalid base64 produces "null DACL, complete, canonical".** Two further paths (lines 88, 96) do
the same.

Why that is not a cosmetic problem — MS-ADTS 5.1.3.3.1:

> The presence of a NULL DACL in the `nTSecurityDescriptor` attribute of an object **grants full
> access to the object to any principal that requests it**; normal access checks are not performed
> with respect to the object.

So a descriptor the product **could not decode** is recorded as **the most permissive state Active
Directory has**, with completeness and canonicality asserted true. This is `0002`'s
zero-where-nothing-looked defect in its worst form: not a missing count, but a confident maximum.

`DaclState.Unreadable` already exists and is used on other paths (lines 156, 164). The exception
handlers simply bypass it.

**One correction to the finding.** It states that "MS-ADTS additionally states that NULL DACLs are
not valid for security descriptors maintained by a DC." The section that discusses null DACLs does
not say that — it describes what a null DACL in `nTSecurityDescriptor` *does*, which implies they
occur. The finding's conclusion stands on its own evidence; that supporting claim should not be
repeated without a citation.

---

### #5 — The parser does not preserve enough raw ACE structure — **UPHELD**

`ParsedAce` carries:

```
byte AceFlags, int AccessMask, string TrusteeSid,
string? ObjectTypeGuid, string? InheritedObjectTypeGuid,
bool IsInherited, byte InheritanceFlags, byte PropagationFlags
```

Absent: the stored **ordinal**, the raw **ObjectFlags**, and callback **ApplicationData**.

MS-DTYP defines GUID presence by the `Flags` field — `ACE_OBJECT_TYPE_PRESENT` and
`ACE_INHERITED_OBJECT_TYPE_PRESENT` — not by whether a parsed GUID is null. A `string?` cannot
distinguish *absent* from *present and equal to the null GUID*.

**This corroborates `S-56` R1**, which was written independently and says the same thing. Two
derivations reaching one requirement is the strongest evidence in this document.

---

### #1 — Stored generic rights must not be expanded — **UPHELD**

Independently found before this review arrived. [MS-DTYP 2.4.3](https://learn.microsoft.com/openspecs/windows_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b):

> If the **GR**/**GW**/**GX**/**GA** bits are set in an ACE structure that is **already attached to
> an object**, requesting access might produce unintended results. This is because the Access Check
> algorithm **does not map generic rights to object-specific rights for ACE structures**.

`GenericRightsExpander`'s summary — "the same permission written two ways" — is false for a stored
ACE. Expanding one manufactures rights the DC would not grant. Normalising for **comparison** is
still correct; using one mask for comparison *and* semantics is the defect.

---

### #18 — GPO identity uses the wrong GUID — **UPHELD**

`GpoTarget.cs` line 21 states outright:

> *The policy's `objectGUID`, which its folder on the share is named for.*

The SYSVOL folder is named for the **CN GUID** of the `groupPolicyContainer`, which is a different
value from the directory-assigned `objectGUID`. Anything joining AD evidence to SYSVOL on
`objectGUID` mis-joins. `gPCFileSysPath` is also captured, so the damage depends on which is used to
construct paths — but the comment asserts a falsehood either way.

---

### #20 — GPO link precedence is reversed — **REFUTED**

The finding says our `Precedence = Count - Order + 1` is backwards and instructs *"Do not reverse
it."* [Group Policy scope](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/group-policy/group-policy-scope#gpo-scope-types):

> Although the GPOs are read from left to right, they're applied in reverse order […] **Thus, the
> last GPO in the sequence has the highest precedence**

Our implementation computes exactly that. **Applying this finding would invert precedence on every
container with two conflicting policies.**

**Why the reviewer erred, because the trap is easy to fall into.** It conflated GPMC's *Link Order*
— where 1 is displayed top and has highest precedence — with *position in the stored `gPLink`
string*, where the **last** entry has highest precedence. These are opposite ends of one list.

**A mitigating factor worth recording:** that Learn page contains a genuinely self-contradictory
sentence, asserting in consecutive clauses that the rightmost GPO is applied first and that the
first "is applied first". The framing sentences agree with each other and with our code; the middle
clause is a drafting error. It is a concrete argument for preferring MS-GPOL over the conceptual
page.

---

### #11 — `WRITE_OWNER` is overstated — **PARTLY UPHELD**

The observation is right; the specification adds a dimension the finding does not mention.
MS-ADTS 5.1.3.3.1:

> If the user possesses the SE_TAKE_OWNERSHIP_PRIVILEGE, then RIGHT_WRITE_OWNER access is implied.

So `WRITE_OWNER` is neither necessary nor sufficient to describe who can take ownership: a privilege
this product cannot observe supplies it independently. `WRITE_OWNER` should be worded as authorising
an owner-field update, with everything downstream in a separate escalation layer.

**`S-56` open question 5 remains open** — the two Microsoft pages on what `WRITE_OWNER` permits
still disagree, and this finding does not resolve them.

---

### Owner implicit rights — **`S-56` §6.2 needs a correction**

Not a numbered finding, but settled by the same source. MS-ADTS 5.1.3.3.1:

> even with an empty DACL, some rights are implied. For example, the current OWNER of an object is
> implicitly granted **RIGHT_READ_CONTROL and RIGHT_WRITE_DAC** access.

`S-56` says `WRITE_DAC` alone. **`READ_CONTROL` is missing** and should be added, along with the
`BlockOwnerImplicitRights` condition the same paragraph states.

---

### #23 — Lockout state must not come from raw `userAccountControl` — **UPHELD**

`UserAccountControlWording.cs` line 63:

```csharp
new(0x00000010, "ADS_UF_LOCKOUT", "The account is currently locked out."),
```

Wrong on two counts, each separately sourced.

> In a Windows Server 2003-based domain, **LOCK_OUT and PASSWORD_EXPIRED have been replaced** with a
> new attribute called `ms-DS-User-Account-Control-Computed`.
> ([UserAccountControl flags](https://learn.microsoft.com/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties#list-of-property-flags))

> This attribute value is only reset when the account is logged onto successfully. This means that
> **this value may be non zero, yet the account is not locked out.** To accurately determine if the
> account is locked out, you must add the `Lockout-Duration` to this time and compare the result to
> the current time.
> ([Lockout-Time](https://learn.microsoft.com/windows/win32/adschema/a-lockouttime#remarks))

So the bit is not persisted meaningfully, and even `lockoutTime` alone does not answer the question.

**The file already knows this.** Its `ADS_UF_PASSWORD_EXPIRED` entry is correctly caveated — "The
directory computes this from `pwdLastSet` and the domain…". The two bits Microsoft names in the same
sentence are handled inconsistently, which is evidence that the lockout wording is an oversight
rather than a decision.

---

### #13 — Unknown `validAccesses` is guessed as an extended right — **UPHELD, and there are two fallbacks, not one**

`CapturedSchemaGuidReader.cs`:

```csharp
? int.TryParse(reader.GetString(4), out var parsed) ? parsed : ExtendedRightAccess   // line 210
...
_ => SchemaGuidKind.ExtendedRight,                                                   // line 217
```

An unparseable value **and** an unrecognised value both become an extended right.

**This was a deliberate decision** — `S-53` records that an unrecognised value is treated as an
extended right because it is "the reading that grants most". The review presents it as an oversight;
it was not, and the reasoning deserves to be answered rather than reversed silently.

**The answer is that the reasoning applies to the wrong axis.** "Grants most" is the safe direction
for a *severity* judgement. But `validAccesses` decides *what kind of thing a GUID is*, and per
`S-56` R3 and R4 that is a factual classification, not a severity call. Mislabelling a property set
as an extended right does not make the product louder — it makes it answer a different question,
and `S-56` R4 says property-set membership must come from `attributeSecurityGUID` in the forest.

The correct fallback is a fourth kind meaning *unclassified*, not the most permissive one. Line 47's
comment — `validAccesses` "is the only thing that says which" — should also soften to v4's wording,
"the normative field".

---

### #6 — Callback and conditional ACE `ApplicationData` is discarded — **UPHELD**

`AceType.cs` defines `AccessAllowedCallback` (0x09), `AccessDeniedCallback` (0x0A) and the callback
object types, and `AceCanonicalization` orders them — but **nothing in `Kernel/Security` mentions
`ApplicationData`**. A conditional ACE is parsed as though its condition did not exist, so an ACE
that grants only when a claim is satisfied is reported as an unconditional grant.

`S-56` v4 R1 already requires the opposite: analyse supported ordinary ACE types, and **preserve and
classify every unsupported ACE raw**. This is the first concrete instance of that requirement.

---

### #9 — The "Full control" shortcut is a subset test — **UPHELD**

`PermissionWording.cs`:

```csharp
if ((accessMask & FullControl) == FullControl)
```

Any mask *containing* full control collapses to those two words. A mask of `FullControl | SYNCHRONIZE`
loses `SYNCHRONIZE`; a mask carrying an unnamed bit loses it silently, which is precisely what
`RightsAreComplete` exists to prevent — and this path returns `RightsAreComplete: true`
unconditionally. It also ignores `ObjectType`, so a scoped ACE carrying those bits is described as
though it were unscoped.

---

### #10 — `ACCESS_SYSTEM_SECURITY` shown as an ordinary grant — **UPHELD**

Already quoted in `S-56` §3. MS-DTYP 2.4.3:

> **This bit MUST NOT be set in an ACE that is part of a DACL.**

Stronger than the review's own wording. Its presence in a DACL entry is an anomaly to report, never
a right to render.

---

### #8 — `CREATE_CHILD`/`DELETE_CHILD` classified without class scope — **UPHELD**

`DangerousPermissionClassifier.ClassifyObjectIndependentBits` judges both bits before
`objectTypeGuid` is consulted. MS-DTYP is explicit that for these bits the GUID is meaningful:

> **ADS_RIGHT_DS_CREATE_CHILD** — The `ObjectType` GUID identifies a type of child object. The ACE
> controls the trustee's right to create this type of child object.

*Create user objects here* and *create any child object here* are different grants. This is `S-56`
R3 — kind is a function of `(GUID, mask bit)` — with these two bits placed in a bucket that by
definition ignores the GUID.

---

### #12 — Confidential/LAPS classified at the wrong layer — **UPHELD**

Settled by `S-56` R8 and R10. The two rights may arrive from different entries, so no per-entry
presentation can state the conclusion. Already recorded as the third independent argument against
the `S-55` per-right model.

---

### #19 — `gPLink` options should be parsed — **UPHELD in principle; the bit values remain Undecided**

The attribute is documented as structured data:

> A **sorted list of Group Policy options. Each option is a DWORD.** Use of the UNICODE string is a
> convenience.
> ([GP-Link attribute](https://learn.microsoft.com/windows/win32/adschema/a-gplink))

So treating the options as opaque is wrong, and `F-S51-1` already records that *enforced* is
invisible. **But the specific mapping the review gives — 0 enabled, 1 disabled, 2 enforced, 3 both —
is not quoted from a first-party source, and I have not found one.** It is the widely repeated
mapping and it is probably right; that is not the standard this document applies. The values need
MS-GPOL 2.2.2 before code is written against them.

---

### #14 — Property-set capture collapses empty and unknown — **REFUTED as stated**

```csharp
public IReadOnlyList<string>? MembersOfPropertySet(string propertySetGuid)
    => _propertySetMembers.GetValueOrDefault(propertySetGuid);
```

The return type is **nullable**: `null` means the forest's schema was not read, a list means it was.
`ClassifyPropertySetWrite` honours the distinction, answering `CannotClassify` on null with the
reason that the run "did not read the schema that says which attributes are in it". That is exactly
what `S-56` R4 requires, and it was built deliberately in `S-54`.

**The finding is right about the principle and wrong about this code.** What has *not* been
confirmed is the capture-side round trip — whether a schema that was read but contained no members
for a set survives as an empty list rather than an absent key. That is a narrower question and it is
recorded as open.

---

### #24 — SID parser accepts invalid structures — **UPHELD, narrowly**

`Sid.cs` bounds every read — `bytes.Length < HeaderLength`, then
`bytes.Length < HeaderLength + (subAuthorityCount * 4)` — so it is memory-safe, and its length
arithmetic matches the specification's own:

> *SidLength*(SID) = (8 + (4 \* SID.SubAuthorityCount))
> ([MS-FSA 2.1.4.9](https://learn.microsoft.com/openspecs/windows_protocols/ms-fsa/6bd14b0d-e5ef-4e00-905e-782d5eacdcb9))

What is absent is **semantic** validation. Microsoft specifies a revision level of 1
([SID Components](https://learn.microsoft.com/windows/win32/secauthz/sid-components)), and
`SubAuthorityCount` is bounded; the parser validates neither. It reads `bytes[1]` and trusts it.

So the defect is real but smaller than "accepts binary/text SID forms outside Microsoft's
structure" implies: it will not crash or over-read, it will render a structurally invalid SID as
though it were a principal.

---

### #21 — `DnHelper` is not a valid AD DN parser — **PARTLY UPHELD, and overstated**

The finding says "valid AD DNs can be split incorrectly". The code does not split naively:

```csharp
var separatorIndex = FindUnescapedComma(dn);
...
if (IsUnescapedComma(dn, i)) return Unescape(dn[valueStart..i]);
```

Its own header explains why — a comma inside a value is escaped, and splitting on `','` "produces
two components that do not exist". Escaped-form handling is deliberate and correct.

**The real gap is the one the file already declares:** it "handles the escaped form of RFC 2253
§2.4 and **not the quoted form**." That is a documented limitation rather than a defect, and its
practical weight depends on a question the finding does not ask — RFC 4514, which supersedes 2253,
**removed** the quoted form, and Active Directory returns DNs in escaped form. So the gap is
theoretical for DNs the directory emits and real for DNs a person types.

Worth fixing, worth ranking well below where the review put it, and the header should say which
RFC it targets now that 4514 is the current one.

---

### #22 — `SecurityTemplateParser` accepts nonconformant encodings — **PARTLY UPHELD**

The parser detects UTF-16LE, UTF-16BE and UTF-8 byte-order marks and **defaults to UTF-8 when none
is present**. The finding calls accepting that nonconformant.

**Leniency is the right behaviour for a reader and the wrong behaviour for a witness.** This product
reports what a forest actually contains; refusing to parse a file Windows wrote would report nothing
where there is something. But a file that does not match what the specification requires is
**itself a finding**, and the parser currently normalises that difference away silently.

The fix is not to reject. It is to record the encoding observed and whether it conformed.

---

### #16 — `PermissionScope` overstates OI/CI inheritance — **PARTLY UPHELD**

```csharp
var reachesDown = (inheritanceFlags & (ContainerInherit | ObjectInherit)) != 0;
```

Two flags with different documented effects collapse into one boolean. Microsoft's table gives them
different outcomes — `OBJECT_INHERIT_ACE` alone causes containers to inherit an *inherit-only* ACE,
while `CONTAINER_INHERIT_ACE` alone has *no effect* on non-container children.

**Mitigating, and the reason this is not higher:** "the DS treats all object types as containers"
([ACE inheritance rules](https://learn.microsoft.com/windows/win32/secauthz/ace-inheritance-rules)),
so in Active Directory the practical divergence is far smaller than in the file system. `S-56` v4
R14 nonetheless raises the bar — `InheritedObjectType` must apply the most-specific structural and
dynamic-auxiliary class rule — and a single boolean cannot carry that.

---

### #7 — Canonicality model is incomplete — **PARTLY UPHELD, and it contradicts a recorded decision**

`AceCanonicalization` is more considered than the finding allows: a versioned normalisation
pipeline, explicit ordering categories, and a note that writing the check twice would let two
answers disagree silently.

But it produces a single `DaclWasCanonical` boolean, and `S-56` v4 §5.2 now names inputs a boolean
cannot express — forest functional level, `fDontStandardizeSDs`, and inheritance provenance that
cannot be reconstructed from one object's DACL.

**`0038` requires this field**, so it may not simply be replaced. The decision needs amending with
the reason: at the time it was written, canonicality looked like a property of the stored DACL
alone. It is not.

---

### #15 — Not enough schema data to answer "all properties applicable to this object" — **UPHELD by `S-56` R7**

Superseded rather than adjudicated: v4's R7 now requires modelling property scopes over the
attributes applicable to the *target*, and §11 requires capturing either `allowedAttributes` or the
class-schema inputs needed to derive `CLASSATTS`. Neither is captured today. The finding and the
specification agree.

---

### #17 — The connection-security ladder can conclude falsely — **UNDECIDED**

No public specification settles what a given LDAP or SSPI failure proves about a controller's
posture. MS-ADTS 5.1.1.1 defines what the mechanisms *are*; it does not define what an error means
about a server's configuration, and that inference is the whole substance of the finding.

**Undecided is the correct verdict, not a deferral.** This exact error already occurred once —
`0018` was amended because "a rung that failed is not evidence that the controller refused" — so the
area has form, and the amendment is the precedent to apply. What can be said without a
specification: report what was attempted and what came back, and treat any statement about *why* as
a claim needing its own evidence.

---

## Adjudication complete

All twenty-four findings have a verdict.

| Verdict | Findings |
|---|---|
| **Upheld** | 1, 2, 3, 4, 5, 6, 8, 9, 10, 12, 13, 15, 18, 23, 24 |
| **Partly upheld** | 7, 11, 16, 19, 21, 22 |
| **Refuted** | 14, 20 |
| **Undecided** | 17 |

**Fifteen upheld, six partly, two refuted, one undecided.** The review was right far more often than
not — and the two refutations are the reason this pass existed. `#20` would have inverted GPO
precedence; `#14` would have rebuilt a distinction the product already makes.

---

## Where this leaves the repair order

The review's phased order is sound, and adjudication so far reinforces it: **evidence fidelity
first.** `#4` and `#5` are both in phase 1, both upheld, and both make every later phase unreliable
while they stand.

Sequenced by what is proven rather than by severity as claimed:

1. **`#4`** — stop reporting an undecodable descriptor as a grant-everything DACL. Highest severity,
   smallest change, no specification ambiguity.
2. **`#5`** — preserve `ObjectFlags`, ordinal and `ApplicationData`. Unblocks `#6`, `#8`, `#9`.
3. **`#1`** — separate the comparison mask from the semantic mask.
4. **`#18`** — correct GPO identity, and fix the comment that states the falsehood.
5. Everything else — **after adjudication**.

`#20` is closed. No change.

---

## The scoreboard, kept deliberately

Three reviews of this material have now been done, and **every one contained at least one confident
error**:

| Review | Errors found in it |
|---|---|
| The original `S-56` draft | ~12 — citation plus unsupported inference |
| First external review | 3 typos that did not exist; understated `ACCESS_SYSTEM_SECURITY` |
| Second external review | `R11` requires data no product can capture |
| This deep review | `#20` would invert GPO precedence; `#4`'s supporting citation unverifiable |
| The revised `S-56`, corrected by v4 | claimed the general Windows early-stop algorithm applies to AD; it does not |

No reviewer is the authority. What has produced correct answers, every time, is **a verbatim quote
from a protocol specification** — and nothing else.

**The access-check error is worth dwelling on.** It was wrong three times in succession: first the
loop was over rights, then it was entry-sequential with early stop, and only the fourth version —
sourced to MS-ADTS rather than to the Win32 conceptual page — was right. Each correction was an
improvement and each was still wrong. The conceptual page describes Windows; Active Directory is
not the general case.
