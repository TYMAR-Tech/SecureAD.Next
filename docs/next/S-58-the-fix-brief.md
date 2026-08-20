# S-58: The fix brief

**Status: in progress. Repair orders 1-5 (`#4`, `#5`, `#1`, `#18`, `#8`) are done, and `#9` and
`#10` with them. The remainder are not started.**
*Status line updated 2026-08-19 by the repair session. It previously read "not started … no code has
changed against it", which stopped being true once `#4` landed, and then "orders 1-4 … order 5
(`#8`) and the remainder are not started", which stopped being true once `#8` landed.*

Written 2026-08-19.

This exists so the repair can be done in a session that did not write the verdicts. The reasoning
lives in [`S-57`](S-57-adjudicating-the-deep-review.md); the specification lives in
[`S-56`](S-56-what-a-permission-grants.md). **This document adds only two things S-57 does not
carry: a measured baseline, and an acceptance criterion per finding.**

## Why a separate session

S-57 and the repair should be independently reviewable. A fix written in the session that produced
the verdicts is hard to check against them, because the same train of thought wrote both. Kept
apart, S-56 and S-57 become specifications the fix session is *measured against* rather than
documents it co-authored.

There is a second reason, recorded honestly. Across this work the recurring failure has been a true
citation attached to an unsupported conclusion. A repair session working from written verdicts to
named files, with a compiler and 1,673 tests as the oracle, is the shape where that failure is least
likely. Loading it with the history of how the verdicts were reached adds material to generalise
from and no material to check against.

---

## The measured baseline

Measured 2026-08-19 against `Lab Databases/ad.lab-20260819-000843/evidence.db`: **8,361 objects, 363
security descriptors, 12,600 ACEs.**

This is here so the fix session can prove its changes moved what it intended and nothing else. Any
number below that changes without a stated reason is a defect in the fix, not a discovery.

<!-- BEGIN MEASURED BASELINE -->

| Finding | Trigger measured | Count | Live on screen today? |
| --- | --- | --- | --- |
| `#4` | descriptors recorded unreadable, or with a parse error | **0** of 363 | No — all 363 are `Present` / `Complete` / canonical |
| `#1` | stored ACEs retaining a generic bit (`0xF0000000`) | **0** of 12,600 | No — the expander is a no-op on this data |
| `#6` | callback or conditional ACE types present | **0** | No |
| `#23` | accounts with `userAccountControl` bit `0x10` set | **0** of 2,082 | No |
| `#9` | masks containing full control plus further bits | **6** | Yes, marginally — extra bits invisible |
| `#10` | `ACCESS_SYSTEM_SECURITY` present in a DACL ACE | **6** | Yes, marginally — same six rows, unconfirmed |
| `#8` | `CreateChild`/`DeleteChild` **scoped to a class** | **905** across **230 objects** | **Yes — the only finding that moves the numbers** |
| `#8` | `CreateChild`/`DeleteChild` unscoped, for contrast | 1,624 | Correctly marked today |

<!-- END MEASURED BASELINE -->

The classes those 905 are scoped to are what a delegation wizard produces — group (192), user (188),
printQueue (182), inetOrgPerson (173), computer (167).

**Three corrections to what was said earlier in the session that produced this.** `#23`, `#1` and
`#4` were each predicted to be visible. They are not. The prediction was wrong in the same way three
times: severity was reasoned about, frequency was assumed.

**What the zeros mean.** Not "no defect". They mean this forest does not exercise the path, so the
fix is unobservable here and cannot be validated by looking at the screen. `#4` is still first: a
descriptor that failed to decode is currently recorded as a null DACL, and per MS-ADTS 5.1.3.3.1 a
null DACL "grants full access to the object to any principal that requests it". Failing silently
into the most permissive state Active Directory has is worth fixing before something triggers it.

---

## Repair order

Ordered by severity against ambiguity, not by finding number.

| Order | Finding | File | Why here |
| --- | --- | --- | --- |
| 1 | `#4` | `SecurityDescriptorParser.cs` | Highest severity, smallest change, zero ambiguity |
| 2 | `#5` | `ParsedAce.cs` | `#1`, `#6` and `#9` all need the fields it adds |
| 3 | `#1` | `GenericRightsExpander.cs` | Depends on `#5` for a raw mask to keep alongside |
| 4 | `#18` | `GpoTarget.cs` | Comment-only; independent of the others |
| 5 | `#8` | `DangerousPermissionClassifier.cs` | **Handle separately — see the constraint below** |

`#9`, `#10`, `#12`, `#23`, `#24` follow. `#7` must not be started until `0038` is amended, because
the finding contradicts it and the decision record is currently the authority. `#19` must not be
started until MS-GPOL 2.2.2 has been read — the bit values are widely repeated and probably right,
which is not the standard this work applies.

---

## Acceptance criteria

One per finding. Each states what must be true when the change is done, drawn from the verdict in
S-57 rather than restated from memory.

### `#4` — malformed evidence must not become a confident null DACL

`DaclState.Unreadable` already exists and is used at lines 156 and 164. The exception paths (49, 88,
96, 179) bypass it.

- Every path that fails to decode a descriptor yields `DaclState.Unreadable`.
- No such path asserts `DaclCompleteness.Complete` or `DaclWasCanonical: true`.
- A test proves invalid base64 does **not** produce `Null` / `Complete` / canonical.
- The baseline count of 0 unreadable descriptors is unchanged for the lab bundle — this fix must be
  invisible on data that never triggered it. If that count moves, the fix changed decoding.

Do **not** repeat the finding's supporting claim that MS-ADTS says null DACLs are invalid on a DC.
S-57 checked; the cited section does not say that. The verdict stands on its own evidence.

### `#5` — the parser must preserve raw ACE structure

- `ParsedAce` carries the stored **ordinal**, the raw **ObjectFlags**, and callback
  **ApplicationData**.
- GUID presence is determined by `ACE_OBJECT_TYPE_PRESENT` / `ACE_INHERITED_OBJECT_TYPE_PRESENT`,
  not by whether a parsed GUID is null — *absent* and *present and equal to the null GUID* are
  distinguishable.
- This satisfies `S-56` R1, which was written independently and reached the same requirement.

### `#1` — stored generic rights must not be expanded into semantics

- The raw mask and any expanded mask are both retained and separately addressable (`S-56` R2).
- `GenericRightsExpander`'s summary no longer claims the two are "the same permission written two
  ways" — false for a stored ACE per MS-DTYP 2.4.3.
- Expansion is used for **comparison** only, never to state what a stored ACE grants.
- `GenericWriteIsDangerousBecauseItExpandsToUnscopedPropertyWrite` encodes the wrong model and must
  be revised, not deleted quietly.
- The four mappings themselves are **verified correct** (131220 / 131112 / 131076 / 983551). Do not
  change the values.
- S-55 added `Expand()` into `PermissionEntryViewModel` as a "safety net". That call is part of this
  defect.

### `#18` — the SYSVOL folder is named for the CN GUID

- `GpoTarget.cs` line 21 no longer asserts the folder is named for `objectGUID`.
- Any join between AD evidence and SYSVOL is confirmed to use the CN GUID or `gPCFileSysPath`.

### `#8` — class scope must be consulted before the verdict

`ClassifyObjectIndependentBits` returns `Dangerous` on `CreateChild`/`DeleteChild` at lines 261–273
and returns before line 235 ever reads `objectTypeGuid`.

- Both bits are judged with the GUID in hand, per `S-56` R3 — kind is a function of `(GUID, bit)`.
- A grant scoped to one class is worded differently from an unscoped grant.
- **Every one of the 905 whose verdict changes is accounted for by reason.**

> **The constraint, from `F-S54-2`.** This fix moves the Dangerous count **down**. A count moving in
> the reassuring direction can hide a silenced true positive. Some subset of the 905 also carry
> `WriteDac` or `WriteOwner` and must stay Dangerous for a different and correct reason — those are
> caught earlier in the same method and should not move at all. **Account for every moved verdict by
> reason, not by count.** A total is not evidence that the right ones moved.

### `#9` — "Full control" must not be a subset test

- `(accessMask & FullControl) == FullControl` no longer collapses a superset to two words.
- `RightsAreComplete` is not returned `true` unconditionally on that path — it exists precisely to
  prevent a silently dropped bit.
- `ObjectType` is not ignored: a scoped ACE carrying those bits is not described as unscoped.
- Expect **6** rows to change wording in the lab bundle.

### `#10` — `ACCESS_SYSTEM_SECURITY` is an anomaly, not a right

- Its presence in a DACL entry is reported as an anomaly and never rendered as a granted right.
- MS-DTYP 2.4.3: "This bit MUST NOT be set in an ACE that is part of a DACL."
- Expect **6** rows, probably the same six as `#9` — confirm rather than assume.

### `#12` — confidential attributes are judged across entries, not within one

- `ClassifyAttributeRead(string name)` sees the mask, not just the name.
- Confidential access requires `READ_PROP` **and** `CONTROL_ACCESS`, which may arrive from
  *different* entries (`S-56` R8 and R10).
- Therefore no per-entry presentation can state this conclusion. This is the third independent
  argument against the S-55 per-right model, and the fix must not pretend otherwise.

### `#23` — lockout must not come from raw `userAccountControl`

- `UserAccountControlWording.cs` line 63 no longer presents `ADS_UF_LOCKOUT` as current state.
- Microsoft: `LOCK_OUT` and `PASSWORD_EXPIRED` "have been replaced" by
  `msDS-User-Account-Control-Computed`, and `lockoutTime` "may be non zero, yet the account is not
  locked out".
- The file already caveats `PASSWORD_EXPIRED` correctly at lines 113–114. Match that treatment.
- **0 accounts** in the lab bundle trigger this, so it cannot be validated by inspection.

### `#13` — an unknown `validAccesses` must not be guessed as an extended right

- Both fallbacks are addressed: line 210 (unparseable string) and line 217 (`_ =>
  SchemaGuidKind.ExtendedRight`). **There are three, not two — see `F-S58-7`.** Line 206 returns the
  same guess when `validAccesses` is absent.
- `S-53` recorded this as deliberate — "the reading that grants most". S-57's answer: that argument
  applies to **severity**, not to **classification**. Amend `S-53` rather than contradicting it
  silently. **Done; see Order 7.**

### `#24` — the SID parser must reject invalid structures

Upheld narrowly. Scope the change to what S-57 actually upheld; do not broaden it. **Done; see
Order 9.**

---

## What the repair session did

Recorded 2026-08-19, by the session that made the changes. Full suite green at **1,694** tests
throughout, from a baseline of 1,673 before any of this. No golden hash was edited.

| Order | Finding | Outcome | Visible on the lab forest? |
| --- | --- | --- | --- |
| 1 | `#4` | Every failed decode yields `Unreadable` / `Unknown` / not canonical | No — 0 of 363, measured |
| 2 | `#5` | `ParsedAce` carries `Ordinal`, `ObjectFlags`, `ApplicationData`; presence read from flags | No |
| 3 | `#1` | Shorthand named rather than translated; expander summary corrected | No — 0 of 12,600, measured |
| 4 | `#18` | Comment corrected; joins confirmed to use `gPCFileSysPath` | No — comment only |
| — | `#9` | Full-control shortcut no longer a subset test | **Yes — 6 rows** |
| — | `#10` | `ACCESS_SYSTEM_SECURITY` worded as an anomaly, not a right | **Yes — the same 6 rows** |
| 5 | `#8` | Child bits judged with the GUID in hand; class-scoped grants recorded, not answered | **Yes — all 905 rows** |
| 6 | `#23` | `ADS_UF_LOCKOUT` no longer worded as current state; names the attribute that replaced it | No — 0 of 2,082, measured |
| 7 | `#13` | An unreadable `validAccesses` is `Unclassified` rather than guessed as an extended right | No — 0 of 82, measured |
| 8 | `#6` | A callback entry says its applicability was not evaluated, at the verdict and on the row | No — 0 of 12,600, measured |
| 9 | `#24` | The SID reader enforces the revision and the sub-authority bound, both sourced | No — 0 of 1,138, measured |
| 10 | `#7` | The canonicality flag states what it proves; the AD access-check rule is corrected everywhere it was wrong | Yes — the notice on every non-canonical object |

### Order 5 (`#8`) — what moved, and by what reason

Done 2026-08-19 in its own session, as the brief required. Suite green at **1,702**, from 1,694:
eight tests added, none deleted, two revised in place. No golden hash edited.

`CreateChild`/`DeleteChild` were removed from `ClassifyObjectIndependentBits` and now reach
`ClassifyUnscoped` and `ClassifyScoped`, which is `S-56` R3 — kind is a function of `(GUID, bit)`.

**Accounted for by reason, not by count**, as the constraint requires:

| Population | Measured | Verdict before | Verdict after | Reason |
| --- | --- | --- | --- | --- |
| Unscoped, allow | 1,616 | `Dangerous` | `Dangerous` | With no `ObjectType` the grant is every class the schema permits under the container — the takeover `SEC-060` describes. Arms placed **first** in `ClassifyUnscoped` so precedence and wording are bit-for-bit what they were. |
| Unscoped, deny | 8 | `NotDangerous` | `NotDangerous` | Short-circuits before any of this. |
| Scoped, also carrying `WriteDac`/`WriteOwner` | **0** | — | — | The constraint's protected subset. **It is empty on this data** — see `F-S58-4`. Covered by test rather than by evidence. |
| Scoped to one class | **905** | `Dangerous` | `DangerousInCombination` | The whole of the move, below. |

**Why `DangerousInCombination` and not `NotDangerous`.** This was the session's decision and it is
the one to overturn if any is. No source document states the verdict — `S-56`, `S-57` and `#8`'s
criteria all say only that a scoped grant must be *worded* differently and judged with the GUID in
hand. The direction comes from the constraint, which says the count moves down.

`NotDangerous` was rejected on evidence. `docs/rules/SEC-121.md` treats `CreateChild` scoped to the
**`computer`** class as **Critical** on the Domain Controllers OU — it is rogue domain controller
injection — and 167 of the 905 are exactly that mask on exactly that class. Whether one class is a
takeover depends on the container, and `Classify` is handed neither the container's identity nor
its place in the directory. Answering `NotDangerous` would set this component's word against a
shipped rule specification on the same ACE, which is the disagreement between six classifiers that
this component exists to have ended, re-created inside it.

So the entry is **recorded rather than answered**, and the layer that can see the container decides
— the same escape hatch the replication rights already use, and the same one the class doc calls
"rather than a verdict it is not entitled to". `PermissionVerdict.DangerousInCombination` was
defined narrowly, as *"which other rights the same principal holds"*; its doc comment has been
**widened explicitly** to cover *"what else the entry sits on"*, rather than being stretched
quietly to fit. That widening is the second thing to check if this decision is revisited.

**Measured on the lab bundle, none of the 167 sit on `OU=Domain Controllers,%`.** There is no live
true positive being silenced here. The verdict is chosen for the general case, not this forest.

**One test's name was corrected rather than deleted.**
`TakeoverClassBitsAreDangerousWhateverTheAceIsScopedTo` listed `CreateChild` and `DeleteChild`
among its cases, and **every case it passes is unscoped** — the name's claim about scope was never
exercised for any bit. The two child bits are now a separate theory that says what it tests.

**The screen was corrected after the fact, and that is worth recording as a miss.** The verdict
change was proved at the classifier and the suite was green, but nothing covered the path from
verdict to the mark an operator reads — so the `In combination` counter kept an explanation written
for the replication case alone: *"a component of a takeover needing other rights alongside them.
Whether any principal holds the whole set…"*. That sentence does not describe the 905, which are
there for a container reason and have no missing companion right. An operator would have gone
looking for one. The enum's contract had been widened and the screen was left saying the old thing.

Corrected in `ObjectSections.cs`: the counter's explanation now names both reasons, as do
`DangerousInCombinationCount` and `PermissionRisk.DangerousInCombination`. Three tests were added
across the seam that had none — the mark for a class-scoped child right, the mark for an unscoped
one, and the counter movement itself.

**The counters are the answer to `F-S54-2` on screen.** `Dangerous` and `In combination` sit side
by side on the strip, so on those 230 objects the 905 visibly leave one and arrive in the other.
The movement is legible rather than a number quietly falling — which is what the constraint was
asking for, and it is a property of the screen rather than of this fix.


### Order 7 (`#13`) — the guess is gone, and it was in three places

Done 2026-08-19. Suite green at **1,723**, from 1,718: five tests added, one retired and replaced.
No golden hash edited. **The block was cleared first** — `S-53` is amended, with its original text
left standing and the retired sentence marked rather than deleted.

**The argument, checked rather than inherited.** `S-57` says "grants most" is the safe direction for
a severity judgement but that `validAccesses` decides what kind of thing a GUID is, which per
`S-56` R3 and R4 is a factual classification. That holds, and the concrete harm is sharper than
"answers a different question": the kind **selects the branch** in `ClassifyScoped`. A property set
called an extended right is judged by `ClassifyExtendedRight` and can never reach
`ClassifyPropertySetWrite`, so the verdict is computed by a rule that was never about that right —
and the wrong branch can be *quieter* than the right one, which is the exact failure "grants most"
was chosen to prevent. The reasoning was retired on its own terms.

| Fallback | Was | Now |
| --- | --- | --- |
| `validAccesses` absent (`IsDBNull`, line 206) | `ExtendedRight` | `Unclassified` |
| Value will not parse (line 210) | `ExtendedRight`, via the literal `256` | `Unclassified` |
| Value unrecognised (line 217, the `_` arm) | `ExtendedRight` | `Unclassified` |

**`S-57` undercounted, and this is `F-S58-7`.** Its verdict names two fallbacks and there are three.
The missing one is the `IsDBNull` return at line 206 — a `controlAccessRight` that publishes no
`validAccesses` at all took the same guess, and it sat in no adjudicated verdict. It is also the
likeliest of the three in production, because absent is a commoner state than malformed. Verified
against the source before acting on it, as the handoff required. The switch's default arm is now
`Unclassified` and `ExtendedRight` is an explicitly matched value, so a fourth way to arrive at the
guess cannot be added by accident.

**A false negative was nearly introduced, and this is the part worth reading.** `CapturedOver` puts
captured entries ahead of shipped ones and deduplicates by name. An entry that is now `Unclassified`
would therefore have *claimed the name* and suppressed the shipped entry that classifies the same
GUID correctly — so a well-known extended right whose forest row happens to carry no `validAccesses`
would have gone from `Dangerous` to `CannotClassify`. That is `F-S54-2` precisely: a fix for a false
positive quietly manufacturing a false negative, with the count moving the reassuring way. An
unclassified entry now yields to any entry of either layer that classifies the same GUID, and a test
pins it. **Nothing in `#13`, `S-57` or the acceptance criteria predicted this**; it was found by
reading the merge rather than by a failing test, which is the uncomfortable part.

**Measured: 0 of 82.** Every captured control access right in the lab bundle classifies cleanly —
60 at `256`, 16 at `48`, 6 at `8`, with no NULL, unparseable or unrecognised value anywhere. So the
fix changes nothing on this forest and **cannot be validated here**, per this document's own rule
about what the zeros mean. It is also the expected shape: the lab is a clean default forest, and
this defect bites where a forest carries schema extensions or a third-party product publishing its
own control access rights — which is everywhere else.

**No binding gate fired, and that is `F-S58-8`.** A new public member was added to a type registered
in `SURFACE-REGISTER.md` and nothing required it to be documented anywhere: both
`ConceptRegistryTests` and `SchemaGuidDocumentationTests` exclude enum types deliberately, on the
reasoning that enum members are a vocabulary rather than an answer. That reasoning is sound for the
concept registry and leaves a real gap in the documentation gate — `SchemaGuidKind.Unclassified`
changes what a caller must handle just as much as a new method would. `S-3` was updated by hand,
which is exactly the thing gates exist to stop depending on. Compare `F-S53-1`: an enum member
escaping notice is a shape this repository has been bitten by once already.

**One test was retired rather than edited.** `AnUnrecognisedValidAccessesIsTreatedAsTheWidestKind`
asserted the behaviour and its summary restated the reasoning being amended, so renaming it would
have left the retired argument in the suite as documentation. It is replaced by one test per
fallback.

---

### Order 8 (`#6`) — a conditional entry now says so, twice

Done 2026-08-19. Suite green at **1,733**, from 1,723: ten tests added, none deleted, none revised.
No golden hash edited, and no schema change — the fix works from `ace_type` alone.

`AccessAllowedCallback` and `AccessAllowedCallbackObject` passed `Enum.IsDefined`, missed `IsDeny`
and `IsAudit`, and fell straight into the ordinary mask arms. So *grants Modify Permissions* was
said of an entry that may grant nothing at all. `WhetherItApplies` now qualifies the reason, and
`PermissionEntry.Type` renders the row as *Allow (conditional)* rather than *Allow*.

**The verdict is qualified, not withdrawn, and that is the owner's decision to overturn if any is.**
A literal reading of `S-56` v4 R1 — callback types "must be reported as unsupported or unclassified
and must not be interpreted through the ordinary ACE model" — makes this `CannotClassify`. It was
put to the owner as a fork and decided the other way, on these grounds: a conditional entry granting
full control is a real takeover to anybody who satisfies the condition, and answering
`CannotClassify` takes its mark off the screen and its row out of the Dangerous count. That is
`F-S54-2` — a false positive traded for a false negative, with the count moving the reassuring way —
and this repository has now been bitten by that shape three times. R1 is met by reporting the entry
as unsupported *in the sentence an operator reads*, rather than by declining to judge a mask that is
dangerous whenever it does apply.

**`WhereItLands` is the precedent and the pattern.** `INHERIT_ONLY_ACE` is the same shape — the
grant is real, its applicability is qualified — and was solved by prefixing the reason rather than
refusing to judge. `WhetherItApplies` follows its two stated rules: only a claim of danger is
rewritten, because `NotDangerous` and `CannotClassify` assert nothing a condition can falsify; and
the original sentence is kept whole. **The two compose** — an inherit-only conditional entry earns
both sentences, which is why the new qualifier runs after the reach one rather than instead of it,
and there is a test for exactly that.

**Deny-callbacks are deliberately untouched.** *A deny entry grants no access* is true whether or
not the condition fires, so nothing it claims needs qualifying. They are still named in `IsCallback`
so the set means *callback* rather than *callback we happen to rewrite*.

**A latent bug was found at the screen while fixing the screen.** `IsDenial` was
`Type == "Deny"` — an exact match. Qualifying the word would have quietly stopped a conditional
denial counting as a denial, and `HasDenials` with it, so a denial would have read as a grant. It is
now a prefix test with a test of its own. Nothing about `#6` predicted this; it was found because
the row was read rather than assumed, which is the lesson Order 5 recorded and this is the first
time it was applied in advance.

**Measured: 0 of 12,600.** Every ACE in the lab bundle is `AccessAllowed`, `AccessAllowedObject`,
`AccessDenied` or `AccessDeniedObject` — not one callback type — so the fix is unvalidatable there,
per this document's rule about what the zeros mean. Conditional ACEs come from Dynamic Access
Control and from products that write their own, so this is a defect about the forests the tool will
be pointed at rather than the one it was built against. **No existing test broke**, which says the
same thing from the other side: nothing covered a callback ACE at either layer.

---

### Order 9 (`#24`) — two values Microsoft constrains, neither of them checked

Done 2026-08-19. Suite green at **1,741**, from 1,733: eight tests added, none deleted, none
revised. No golden hash edited.

`Sid.ToText` bounded every read, so it could not crash or over-read, and then took `bytes[0]` on
trust. `[MS-DTYP]` 2.4.2.2 constrains two values and neither was enforced, so a structurally
invalid SID rendered as though it were a principal.

| Constraint | Source | Was | Now |
| --- | --- | --- | --- |
| Revision `MUST` be `0x01` | `[MS-DTYP]` 2.4.2.2 | read and used as the printed revision | refused |
| At most 15 sub-authorities | `[MS-DTYP]` 2.4.2.2 | unbounded up to `byte.MaxValue` | refused above 15 |

**The bound was verified before code was written against it, which is the point.** `S-57`'s verdict
says only that `SubAuthorityCount` "is bounded" — it gives no number and cites no source for one.
That is the standard this work refused to accept on `#19`, where a widely repeated `gPLink` bit
mapping was blocked for want of a first-party source, and on `S-56` R11. `[MS-DTYP]` 2.4.2.2 was
read and states it outright: "The maximum number of elements allowed is 15."

**Both directions were changed, because they have to agree.** `ToBytes` checked
`subAuthorityCount > byte.MaxValue` and never looked at the revision at all, so text existed that
converted happily and then could not be read back. A parser pair that disagrees about what a SID is
would be the drift `Sid` was extracted to prevent, in miniature.

**Nothing else was added, and the restraint is deliberate.** The brief said to scope this to what
S-57 upheld. So a SID longer than its own count is still accepted — the span may legitimately be a
window onto a larger buffer — and the identifier authority is still unvalidated, because every
48-bit value is structurally legal. A test names exactly fifteen sub-authorities as legal, so the
bound cannot later be tightened by accident into refusing SIDs the directory may hand over.

**Measured: 0 of 1,138.** Every trustee in the lab bundle is revision 1 with five sub-authorities
or fewer, so nothing real is refused by this change — it closes a hole rather than moving a count.
The one implementation is used from three places and `SecurityDescriptorParser` already fails
closed on a null, which `#4`'s repair turns into `Unreadable`/`Unknown` rather than a silent skip.

---

### Order 10 (`#7`) — a right decision resting on the wrong rule

Done 2026-08-19. Suite green at **1,742**, from 1,741: one test added, none deleted, none broken.
No golden hash edited and no schema change. **The block was cleared first** — `0038` is amended,
with its original text left standing.

**The finding was that one boolean makes a claim needing four**, and that is recorded and only
partly addressed here. What was found on the way is worse and is fixed in full.

**`0038` justified itself with an access-check rule that is not AD's.** Its Context says Windows
"evaluates a DACL in stored order and **stops at the first entry that matches**". That is the general
Windows description. MS-ADTS 5.1.3.3.2 *Checking Simple Access* — the same source `S-57` used to
uphold `#2`/`#3` — says AD sets granted and denied masks to zero, examines **every** ACE to the end
of the DACL, adds a deny only for rights *not already in* `G`, and adds an allow only for rights
*not already in* `D`.

**The decision survives its wrong reason, which is why nobody caught it.** An allow preceding a deny
still wins — by precedence rather than by termination — so every requirement `0038` states is
unchanged and the evasion it describes is exactly as real. **A wrong reason attached to a right
conclusion travels further than a wrong conclusion**, because nothing it produces looks incorrect.
It had reached six places: the decision record, `AceCanonicalization` twice, three test files, and
the notice shown to an operator. All corrected.

**An operator was being told something false.** The object screen said Windows "stops at the first
entry that matches" and that a denial "may never be reached". It now says the directory works
through the whole list and will not deny a right it has already granted — same warning, same force,
true mechanism. This is the third session running in which the screen was carrying a claim the
kernel had outgrown.

**What `#7` asked for, and what was done about it.** `S-56` v4 R5 wants four separate claims.
`dacl_was_canonical` is one, and now says so rather than implying the rest:

| R5 claim | State |
| --- | --- |
| Stored ordinal preserved and displayed | `#2`/`#3`'s subject, not this one |
| AD canonicality by the forest's applicable rules | **Not checked.** Regular-before-object ACEs and lexicographic ordering at applicable functional levels are not tested |
| Whether the DC was expected to standardise | **Cannot be answered.** Needs forest functional level and `fDontStandardizeSDs`; neither is captured |
| Locally provable defects, separate from provenance | **This is what the flag is**, and it is now documented as that |

**The flag was not split, deliberately, and the owner agreed the bundle is expendable.** The reason
is not bundle compatibility. Two of the four claims need inputs no capture collects, so new columns
would have nothing to put in them; and `#2`/`#3` with `F-S58-11` needs a schema change of its own.
One schema change serving both, after the capture side can fill it, is one re-audit rather than two.

**The gap is asserted, not just described.** `TheFlagCannotSeeInheritedGenerationOrderAndDoesNotClaimTo`
puts two inherited allows in either sequence and shows both pass, because an inherited ACE carries
no depth field. A later reader finds the limit as a test rather than as a sentence.

---

**`#9` and `#10` are one defect, confirmed not assumed.**
check whether they were the same six. Measured against the lab bundle: 6 supersets of full control,
6 carrying `ACCESS_SYSTEM_SECURITY`, and **6 carrying both**. The subset shortcut was concealing a
bit MS-DTYP says must never appear in a DACL behind the words *Full control*.

**Three decisions worth knowing.**

- **`#4` line 88 was split rather than converted.** The brief listed it as an exception path. It is
  not: an absent DACL or a zero `OffsetDacl` is a genuine null DACL per MS-DTYP 2.4.6. It still
  reports `Null`, but only when the header can be believed — a wrong revision or a non-self-relative
  descriptor now yields `Unreadable`, because those offsets do not mean what the code read them as.
- **`#5` was scoped to the parser.** Persisting the new fields is a schema change; see `F-S58-1`.
- **`#1` left the classifier expanding for severity.** S-57 drew that line on `#13`: reading the
  mask that grants most is sound for severity, not for saying what an entry grants.

**One decision was the owner's**, taken 2026-08-19: a stored shorthand bit is named plainly and
flagged as doubtful — `Full control (shorthand - may not be enforced)` — rather than translated,
hidden, or left unclassifiable. Removing the translation without this would have been a *worse*
defect than leaving it: the wording had no word for the shorthand, so the row would have shown one
unnameable right, been refused classification, and fallen silent about what is probably full
control.

**Two tests were revised rather than deleted**, per this brief's instruction:
`GenericWriteIsDangerousBecauseItExpandsToUnscopedPropertyWrite` and
`AnUnexpandedGenericAllIsStillReadAsFullControl` both asserted the defective behaviour. Their names
now say what is actually true, and their comments record what they used to claim and why it was
wrong.

---

## Findings raised while repairing

### `F-S58-1` — the stored ACE ordinal is discarded downstream, not only in `ParsedAce`

**Severity: low. Status: open, not actioned.** Raised 2026-08-19 while doing repair order 2.

`#5` is satisfied at the parser: `ParsedAce` now carries the position the directory stored an entry
in. It stops there. `AceNormalizer` sorts the entries and `CanonicalAce` carries no ordinal, and
`BundleWriter.WriteAce` is called with the index into the **sorted** list — so the `ace.ordinal`
column in a bundle holds the canonical position, not the stored one.

This is not a defect in `#5`'s fix and it is not obviously a defect at all.
[`0038`](../decisions/0038-a-descriptor-records-whether-its-dacl-was-canonical.md) decided
deliberately that `CanonicalAce` keeps no ordinal, on the grounds that the bundle stores the
descriptor's raw bytes and exact order is recoverable by re-parsing. That reasoning still holds.
Recorded because the column name `ordinal` reads as *stored position* and means something else,
which is the kind of thing a later reader takes at face value.

**CLOSED 2026-08-19, by `0038`'s own argument being carried out.** The reasoning was right and
nothing had acted on it: exact order was recoverable by re-parsing and no reader re-parsed.
`ObjectPermissions` now reads the stored DACL out of `security_descriptor.raw_bytes`, so
`PermissionEntry.Ordinal` is the position the directory stored. `ace.ordinal` still holds the
canonical index and is still correctly named for what that table is — the projection `ace_set_hash`
compares runs by. Per `S-57` on `#2`/`#3`: the defect was having only one representation, and there
are now two.

**Measured on lab bundle `ad.lab-20260819-232425`**, so the size of it is on the record rather than
asserted: 12,603 entries stored against 12,600 projected — **three entries on three objects of
8,361** were being discarded by deduplication before any reader could see them. 363 distinct
descriptors, 611 KB of `raw_bytes` in total, mean 1,684 bytes, so re-parsing one descriptor for one
screen costs nothing and re-parsing the whole forest costs almost nothing. Cost was the objection
to doing this and the measurement removed it.

**One claim made while scheduling this was wrong and is withdrawn.** It was said several times that
`ObjectPermissions` inferring GUID presence from `object_type_guid IS NULL` was *the guessing
`S-56` §2 forbids*, and that this was the substance of `#2`/`#3`. Measured across all 12,603
entries: nullity and `ACE_OBJECT_TYPE_PRESENT` **never disagree**, and cannot, because the parser
populates a GUID only when the flag is set. The projection's answer was correct — correct by
coincidence of implementation rather than by contract, and now taken from the flag as `S-56` R1
asks, but not wrong. The reasoning came from a doc comment rather than from the data.

### `F-S58-2` — `CaptureRunEndToEndTests` fails intermittently on a disposed SQLite handle

**Severity: low, but it corrodes the oracle. Status: open, not investigated.** Raised 2026-08-19.

`CaptureRunEndToEndTests.EveryObjectTheControllerServedIsStored` failed once during a full run with
`System.ObjectDisposedException: SQLitePCL.sqlite3` from `Query()` at
`CaptureRunEndToEndTests.cs:427`. It then passed in isolation and on two subsequent full runs. It
shares no code path with anything this session changed.

This matters more than one flaky test usually would. The whole method of this repair — every
acceptance criterion checked against a green suite — rests on the suite meaning something. A test
that fails at random trains a reader to re-run rather than to look, and the day it fails for a real
reason it will be re-run too.

### `F-S58-3` — `next/tools/measure-findings*.ps1` are empty, and untracked artefacts are accumulating

**Severity: low. Status: untracked half CLEARED 2026-08-19; a tracked remainder is open.**
Raised 2026-08-19.

`next/tools/` holds `measure-findings.ps1`, `measure-findings2.ps1` and `measure-findings3.ps1`,
all untracked and all **zero bytes**. Their names claim exactly the measuring this brief requires,
and they do nothing. This session recreated that measurement from scratch in `%TEMP%` without
checking whether tooling existed — the names would have been found by a search that was never run.
Three empty scripts named after a task are worse than none, because a later reader assumes they
work.

Also untracked in `next/`: `REVIEW-MANIFEST.md` and five `COMMIT_MSG_*.txt` files. The latter are
the artefact `.github/copilot-instructions.md` explicitly says not to create.

**Cleared 2026-08-19.** All **18** untracked files were checked and every one was **zero bytes** —
the nine `next/tools/*.ps1`, the five `COMMIT_MSG_*.txt`, and `REVIEW-MANIFEST.md`. Nothing in
`next/**/*.cs` or `docs/**/*.md` referenced any of them except this finding. Removed, guarded so
that any file with content would have been skipped; none was.

**What the sweep turned up, and did not touch.** Six more empty scripts are **tracked**, so they
did not appear in an untracked listing: `.commit-message.txt` and `Rename-LedgerIdentifiers.ps1`,
`Rename-LedgerProse.ps1`, `Rename-LedgerProse2.ps1`, `Rename-LedgerProse3.ps1`,
`Rename-LedgerProse4.ps1`. Each has exactly **one revision and it is zero bytes**, so no content
was ever lost — they were committed empty. Nothing references them.

This is the same defect as the one above, committed rather than merely lying around, and it is
worse in the same way: a name that claims a task and a file that does nothing. It is left open
because deleting tracked files is a change to the repository rather than a tidy-up, and the request
that prompted the sweep was about uncommitted files.

The two tools in `next/tools/` that **do** have content — `Build-DecisionIndex.ps1` and
`Replace-InventoryRow.ps1` — are referenced across the session documents and one is enforced by
`DecisionIndexTests`. Neither was touched.

### `F-S58-4` — the `#8` constraint's premise does not hold on the lab bundle

**Severity: medium. Status: open, and it changed how order 5 was done.** Raised 2026-08-19 while
doing repair order 5.

The constraint beneath the `#8` criteria says: *"Some subset of the 905 also carry `WriteDac` or
`WriteOwner` and must stay Dangerous for a different and correct reason — those are caught earlier
in the same method and should not move at all."*

Measured against `Lab Databases/ad.lab-20260819-000843/evidence.db`: **that subset is empty.** All
905 are `AccessAllowedObject` with an access mask of **exactly `3`** — `CreateChild | DeleteChild`
and no other bit. None carries `WriteDac`, `WriteOwner`, `ControlAccess`, `WriteProperty`,
`ReadProperty` or `Self`.

This matters because it removes the evidence the constraint was designed to produce. The intended
check was *"these moved, those stayed, each for a stated reason"*. With nothing staying, **all 905
move**, and the only thing standing between this fix and a silenced true positive is the verdict
chosen for a class-scoped child right. That is why the verdict was not chosen silently —
see the decision recorded under order 5.

The premise is not wrong in principle; a mask carrying both is legal and the code still handles it,
with a test. It is simply absent from this forest. The same failure the baseline section already
records applies to the constraint itself: **the combination was reasoned about, its frequency was
assumed.**

### `F-S58-5` — the baseline's class list for `#8` is short by one class

**Severity: low. Status: open.** Raised 2026-08-19 while doing repair order 5.

The baseline says the 905 are scoped to *"group (192), user (188), printQueue (182), inetOrgPerson
(173), computer (167)"*. Those five counts are each exactly right and they sum to **902**.

The remaining **3** are scoped to `ce206244-5827-4a86-ba1c-1c0c386c1b64`,
**`msDS-ManagedServiceAccount`**, which the list does not name. There are **six** distinct class
GUIDs among the 905, not five.

Trivial in effect and worth recording in kind: the sentence reads as an enumeration, a later
session would take it as one, and 902 was never checked against 905. Related: `inetOrgPerson` — the
largest single class at 173 — is **absent from `SchemaGuidCatalog.Embedded`** and resolves only
from captured forest schema, so its verdict depends on the run having read the schema. On a run
that did not, those 173 are `CannotClassify` rather than the class-scoped verdict. That is correct
behaviour, not a defect, but it means the 905 do not all land in the same bucket.

### `F-S58-6` — `INHERIT_ONLY` never reaches the classifier, so the mark claims a grant on an object the entry does not reach

**Severity: medium. Status: FIXED 2026-08-19.** Raised while auditing `S-56` R1–R20 against code,
after order 5 was committed. **Independent of `#8`** — not in the deep review, not adjudicated by
S-57, and no repair order covered it. Fixed on the owner's instruction that the code must be right
for the forests it will be pointed at, not for the one measured here.

`S-56` **R13** is one line: *"INHERIT_ONLY suppresses a local grant claim."* MS-DTYP 2.4.4.1 is
that `INHERIT_ONLY_ACE` means the entry **does not control access to the object it is attached
to**; it exists to be copied to children.

The classifier is never told. `PermissionEntryViewModel.Assess` calls
`classifier.Classify(aceType, right.Bits, entry.ObjectTypeGuid)`. `InheritanceFlags` and
`PropagationFlags` are read two lines earlier — into `_scope`, for the Scope column — and are not
passed. `Classify` has no parameter for them, so an entry that grants nothing here is judged
exactly as one that grants everything here.

**Measured** against `Lab Databases/ad.lab-20260819-000843/evidence.db`:

| | Count |
| --- | --- |
| `INHERIT_ONLY` ACEs | **5,640** of 12,600 |
| of those, allow-type | **5,640** |
| of those, carrying `WriteDac`/`WriteOwner`/`CreateChild`/`DeleteChild` | **66** |
| of those, whose Scope column would read `Nothing` | **0** |

**The last row is a correction to this session's own first claim.** It asserted that rows would
read *governs nothing* beside a takeover mark. They do not. `PermissionScope.AppliesTo` returns
`"Nothing"` only when `INHERIT_ONLY` is set *and* neither inherit flag is, and **that combination
does not occur in this bundle** — all 5,640 reach down. The claim came from reading line 116 rather
than from counting, which is the failure this work exists to report. Caught before it was written
down, and recorded because catching it late is not the same as not making it.

**What is wrong is narrower, and still wrong.** Those 66 rows show a mark whose reason reads
*"hands somebody control of this object"* beside a scope reading *"All descendant objects"*. The
scope is right; the mark asserts a grant on an object the entry explicitly does not reach. It
over-reports, which is the safe direction — and it is one row with two components disagreeing,
which is the defect `DangerousPermissionClassifier` was built to end, turning up between the
classifier and the scope rather than between two classifiers.

**Not actioned**, because it is not a wording change. Either `Classify` gains the flags, or the
caller declines to ask about an entry that grants nothing locally. Which is right depends on
whether a mark is a statement about *this object* or about *the entry*.

**What was done.** `Classify` gained the flags, via a new `EntryReach` and `EntryReachReader` in
`SecureAD.Kernel.Security`. The other two options were rejected: returning `NotDangerous` would
silence a grant that genuinely hands over every descendant, and suppressing the mark would remove
the danger from a product that does not model propagation to children, so it would have nowhere to
reappear.

- **The verdict does not move.** An inherit-only grant of Modify Permissions is exactly as
  dangerous, to the objects it reaches. Only the reason changes, so no count anywhere shifts.
- **Only `Dangerous` and `DangerousInCombination` reasons are corrected.** `NotDangerous`
  ("grants no write over the object") and `CannotClassify` ("has not been assessed") remain true of
  an inherit-only entry and are left untouched rather than decorated.
- **The original sentence is kept whole** and prefixed, because it still describes the grant
  correctly — the correction is about *where* it lands, not *what* it is.
- The three-argument `Classify` asserts `ThisObject`, which is what an entry means unless
  `INHERIT_ONLY_ACE` says otherwise, so the ~50 existing call sites keep their meaning.

**Two architecture gates caught the change and were right to.** `SurfaceRegisterTests` and
`SecurityDocumentationTests` both failed on the new public types until they were entered in
`SURFACE-REGISTER.md` and bound to `S-4`. The repo's rule that a public type no document names is a
piece of the component nobody knows exists did its job on the first run.

Suite green at **1,714**, from 1,702.

---

## What must not change

Three things were checked and found **correct**. A fix session that "corrects" them makes the
product wrong:

- **`PolicyLinkList.Precedence`** — `links.Count - l.Order + 1` is right. "The last GPO in the
  sequence has the highest precedence." Finding `#20`'s proposed fix inverts it.
- **`SchemaGuidCatalog.MembersOfPropertySet`** — returning `IReadOnlyList<string>?` already
  distinguishes empty from unknown. Finding `#14` is refuted as stated.
- **`GenericRightsExpander`'s four mapping values** — verified against published decimals.

---

## What is left to do

The state of the work order as at 2026-08-19, so the next session does not have to reconstruct it.

**Every unblocked finding in this brief is now done.** `#13`, `#6`, `#24` and `#7` were taken after
the list below was written; their records are Orders 7, 8, 9 and 10. What remains is `#12`, which is
not a repair, and the two findings still blocked on a source.

**`#12` is upheld and is not a fix.** Confidential access requires `READ_PROP` **and**
`CONTROL_ACCESS`, which may arrive from *different entries*, so no per-entry presentation can state
the conclusion — the acceptance criteria say so themselves. Satisfying it means the per-principal
layer that `F-S4-2` records as having no owner. That is a design decision about where a verdict
lives, not a defect to repair, and it should be taken as one.

**The largest remaining piece of work is `#2`/`#3` with `F-S58-11`.** They were upheld and never
scheduled, and `F-S58-11` now gives them a concrete demonstrable case rather than a principle: ACEs
differing only in their condition are deduplicated away before they are written. It needs a golden
hash conversation before it starts.

**Updated 2026-08-19.** The golden hash conversation happened and `F-S58-11` is repaired — see its
entry below. What remains of `#2`/`#3` is the **read path**, and it needs no schema change: every
reader goes through the `ace` table, so `ObjectPermissions` infers GUID presence from
`object_type_guid IS NULL` rather than from `ObjectFlags`, which is the guessing `S-56` §2 forbids
and what `#5` existed to prevent. Storing the columns instead would duplicate evidence `raw_bytes`
already holds, which `0025` argues against and `0038` already declined once.

**`#2`/`#3` DONE 2026-08-19.** `ObjectPermissions` reads the stored DACL from `raw_bytes` in stored
order with nothing deduplicated; the `ace` table remains the comparison projection. No schema
change, as expected. **Two sentences above are withdrawn:** the GUID-presence claim was wrong — see
`F-S58-1`, where the measurement is recorded — and what the change actually recovers is three
discarded entries and the stored ordinal.

### Order 6 (`#23`) — the two bits the directory stopped keeping

Done 2026-08-19. Suite green at **1,718**, from 1,714. Four tests added, none deleted, no golden
hash edited.

`UserAccountControlWording.cs` line 63 read *"The account is currently locked out."* The word
*currently* was the whole defect: Microsoft's sentence is that in a Windows Server 2003 domain
`LOCK_OUT` and `PASSWORD_EXPIRED` *"have been replaced with a new attribute called
`ms-DS-User-Account-Control-Computed`"*, so the stored bit is not the current state of anything.

The brief said to **match the treatment `ADS_UF_PASSWORD_EXPIRED` already gets**, and that is what
was done — the entry now states the flag and then names where the answer lives, in the same shape
as its pair. It also closes the obvious fallback, because that is wrong too: Learn's `Lockout-Time`
remarks say the value *"may be non zero, yet the account is not locked out"*, and only `lockoutTime`
plus the domain's `Lockout-Duration` decides.

**Prioritised on production correctness, not on the lab.** 0 of 2,082 accounts in the bundle set
the bit, so this fix is invisible here — and any forest with real users has locked accounts, which
is the only reason it matters. Per the baseline section's own rule about what the zeros mean.

**The pair is now tested together**, because the two bits being treated differently is precisely
what showed the lockout wording was an oversight rather than a decision. A theory covers both so
they cannot drift apart again.

**Order 5 (`#8`) is done** — see the record above. Two things about it were left open for a
session that did not write them. **Both were reviewed and ratified**, by a later session, on the
grounds below:

- The verdict for a class-scoped child right is `DangerousInCombination`, and **no source document
  states it**. **Ratified.** `docs/rules/SEC-121.md` is in fact stronger than the record above
  claims: its in-scope control-type list is `CreateChild` *unqualified* on
  `OU=Domain Controllers,%`, with the `computer` class given as the rationale rather than as a
  filter. `NotDangerous` would therefore set this component against a shipped rule on the whole of
  that mask, not merely on 167 of the 905; and `Dangerous` is the false positive `S-57` upheld `#8`
  to remove. No third answer is available to a method handed neither container nor place.
- `PermissionVerdict.DangerousInCombination` was **widened** to admit "what else the entry sits on"
  alongside "which other rights the principal holds". **Ratified; a fifth verdict is not
  warranted.** The member's distinguishing property is what this component may *say* — recorded,
  and the layer holding the missing evidence decides — not which evidence is missing. Both halves
  have that shape and the same marking policy under `0074`, so a fifth value would be handled
  identically by `PermissionRisk`, the counter and the template trigger. The container half is also
  the better-owned of the two: `F-S4-2` records that nothing yet reads the per-principal set,
  whereas the rule layer already reads the container.
- **One correction was needed.** `S-4`'s verdict table still gave the pre-widening reading — *"one
  entry cannot see the set"* — while the three code sites had been widened. Corrected in place. The
  miss is the same one the record above already confesses at the screen: the contract was widened
  in the enum and left stale wherever it was restated.

**Unblocked by this session:**

- `#13` — was blocked on `S-53`. The amendment is written, the original text is preserved, and
  Order 7 above records what was done.
- `#7` — was blocked on `0038`. The amendment is written, the original text is preserved, and
  Order 10 above records what was done. It also corrects an error in `0038`'s own reasoning that
  the finding did not mention.

**Raised by the `#6` session:**

- **`F-S58-10`** — **`ApplicationData` is parsed and dropped before the bundle.** `#5` added it to
  `ParsedAce` and nothing consumes it: `AceNormalizer.NormalizeAce` does not carry it into
  `CanonicalAce`, the `ace` table has no column for it, and the read side sees only `ace_type`. So
  the product can say *this entry is conditional* and can never say *this is the condition* — and
  cannot distinguish a conditional ACE from a callback ACE carrying no condition at all. `#6` is
  fixed from `ace_type` alone and does not depend on this, but the wording is deliberately weaker
  than it would otherwise be.
- **`F-S58-11`** — **Two ACEs differing only in their condition are silently deduplicated, and this
  is evidence loss rather than a display gap.** `ComputeAceHash` hashes object, trustee, mask, both
  GUIDs, inheritance, flags and ACE type — **not** `ApplicationData` — and `AceNormalizer` then
  calls `Deduplicate`, which drops any ACE whose hash it has already seen. So an object carrying
  *allow X when Department = IT* and *allow X when Department = HR*, or a conditional entry
  alongside an otherwise identical unconditional one, keeps **one row** and the other is discarded
  before it is ever written. This is `#2`/`#3` territory, which `S-57` upheld: raw ACE evidence must
  not be sorted, deduplicated or order-insensitively hashed.
  **Not actioned, deliberately.** Putting the bytes into the hash invalidates every stored
  `ace_hash` and every golden value in the tests — `AceCanonicalization`'s own header says so — and
  a golden hash change is a conversation rather than a side effect of an unrelated fix. Raised with
  the owner during `#6` and separated on their decision. **It should be taken with `#2`/`#3`, not
  with `#6`**, and it is the more serious of the two: `#6` misreports an entry, this one destroys
  it.

  **REPAIRED 2026-08-19, and one sentence above is withdrawn.** The owner took the golden hash
  decision; `ApplicationData` is the tenth hash field and `AceCanonicalization.Version` is `3`. The
  eight golden constants were recomputed from the written recipe by a calculator first validated
  against all eight version 2 values, so they were never read out of the code they now check. Three
  permanent tests in `AceNormalizerTests` cover the two collisions and the hash, and each was
  mutation-tested by removing the field — all three fail without it. Suite 1,742 → 1,745.

  **The withdrawn sentence is "this one destroys it."** It does not. `security_descriptor.raw_bytes`
  is `NOT NULL` and holds the descriptor as it arrived, so both conditions survived in the bundle
  throughout; what was destroyed is the *projection* over it. That is the same loss the `ace.ordinal`
  case has, not a worse one. The finding was right that it needed fixing and wrong about why — every
  read path goes through the `ace` table rather than the bytes, which is the actual defect and is
  still open as the read-path half of `#2`/`#3`.

**Raised by the `#7` session:**

- **`F-S58-12`** — **A decision record justified itself with the wrong algorithm, and the error
  propagated to six places including the screen.** `0038` cited the general Windows early-stop
  access check; AD does not early-stop. Because the *conclusion* was right, every repetition looked
  correct and nothing tested it — a test can pin behaviour, and no test pins the reason given for
  behaviour. The general shape is worth keeping: **a wrong rationale under a right decision is
  invisible to the suite**, so it survives exactly as long as nobody re-reads the source. Both
  `S-56` and `S-57` quoted the correct algorithm while the code carried the wrong one.
- **`F-S58-13`** — **`S-56` v4 R11 is confirmed, and the brief's doubt about it can be closed.**
  This document listed R11 as needing verification before code is written against it, on the
  grounds that MS-ADTS 5.1.3.3.1 grants an owner only `READ_CONTROL` and `WRITE_DAC` implicitly.
  MS-ADTS **5.1.3.3.2** rule 3 is explicit for AD simple access: "If the SID in the Owner field of
  the object's security descriptor matches any SID in the requester's security context, then add
  the bits Read Control (RC), Write DACL (WD) and **Write Owner (WO)** to G." R11's claim is
  correct as written. Found while sourcing `#7`; no code depends on it yet.

**Blocked, and must stay blocked:**

- `#19` — until MS-GPOL 2.2.2 has been read. The bit values are widely repeated and probably right,
  which is not the standard this work applies.
- `#17` — Undecided, and stays Undecided until a source settles it.
- ~~`S-56` v4 **R11** — verify before writing code against it.~~ **Verified and closed 2026-08-19.**
  MS-ADTS 5.1.3.3.2 rule 3 states the owner grant as RC, WD **and** WO for AD simple access, so
  R11's claim is correct as written. See `F-S58-13`.

**Raised by this session:** `F-S58-1`, `F-S58-2`, `F-S58-3`, `F-S58-4`, `F-S58-5`, `F-S58-6` above.

**Raised by the `#13` session:**

- **`F-S58-7`** — **`S-57`'s `#13` verdict undercounts the fallbacks.** It names two; there are
  three. A `controlAccessRight` with no `validAccesses` at all took the same guess from line 206 and
  appears in no adjudicated verdict. Verdicts state findings, and a finding that miscounts what it
  found will be implemented to its own count.
- **`F-S58-8`** — **A new public enum member crossed a registered surface with no gate noticing.**
  `ConceptRegistryTests` and `SchemaGuidDocumentationTests` both exclude enum types on purpose. For
  the concept registry that is right; for the documentation gate it leaves members of registered
  public vocabularies undocumentable-by-omission. `F-S53-1` is the same shape.
- **`F-S58-9`** — **`next/tools` held eight zero-byte scripts, and the tidy-up had stopped half way
  through on purpose.** `F-S58-3`'s session cleared nine untracked ones, then found six more that
  were *tracked* — `.commit-message.txt` and five `Rename-Ledger*.ps1` — and deliberately left them,
  on the stated grounds that deleting tracked files is a change to the repository rather than a
  tidy-up. That reasoning was right and it is recorded above. What was not noticed is that three
  untracked ones survived as well: `tmp-r13.ps1`, `tmp-s56-audit.ps1`, `tmp-s58-8.ps1`, which are
  the category that session did intend to clear. **All nine are deleted as part of this session's
  work**, with the owner's agreement for the tracked six; each was verified to have exactly one
  revision of zero bytes, so no content was lost. The finding worth keeping is the smaller one: a
  a good reason still needs the remainder to be somebody's, or it reads later as a cleanup that
  failed.

**Still owed from before this work**, untouched and not superseded: surfacing `HasCapturedEntries`;
the base-schema disagreement `0014` describes; `F-S51-1` (gPLink enforced still invisible);
`F-S50-2` (capture never writes `trustee.unresolved_reason`); `primaryGroupID`/`memberOf` as
principals. The S-55 layout defects also remain — the repeated "Takeover" word, `Type`/`Scope`
top-alignment, and the near-full-control entry that does not collapse.

---

## Open, and deliberately not actioned

- ~~`S-56` v4 R11 — verify before writing code against it.~~ **Closed 2026-08-19.** MS-ADTS
  5.1.3.3.2 rule 3 states the AD simple-access owner grant as RC, WD **and** WO, so R11 is correct
  as written. The doubt came from reading 5.1.3.3.1 alone. See `F-S58-13`.
- `#17` is Undecided. It stays Undecided until a source settles it.
- `#19` needs MS-GPOL 2.2.2 for the option bit values.
- ~~`#7` needs `0038` amended first.~~ **Done 2026-08-19**, see Order 10.
- **The one schema change that is now owed**, serving `#7`'s R5 split and `#2`/`#3` with
  `F-S58-11` together. It needs capture-side work first — forest functional level and
  `fDontStandardizeSDs` for R5, the condition bytes for `F-S58-11` — and it invalidates existing
  bundles, which the owner has accepted as a re-audit rather than a loss. Doing it once serves
  both.

## Still owed from before this work

Untouched, and not superseded: surfacing `HasCapturedEntries`; the base-schema disagreement `0014`
describes; `F-S51-1` (gPLink enforced still invisible); `F-S50-2` (capture never writes
`trustee.unresolved_reason`); `primaryGroupID`/`memberOf` as principals. The S-55 layout defects also
remain — the repeated "Takeover" word, `Type`/`Scope` top-alignment, and the near-full-control entry
that does not collapse.
