# The production forest's shape, measured 2026-09-25

**This is the anchor.** Every figure `P-280` rests on came off a synthetic bundle this
codebase generated, so it could only contain assumptions the code already held. This is
the first measurement of the owner's own forest that can contradict them, and the
argument for taking it is [`F-S44-2`](../../../docs/PUNCH-LIST.md): the captured attribute
catalogue had three sound test suites agreeing with each other in both directions while
fifteen attributes nobody had written a rule for were silently missing. Internal
consistency cannot supply an external anchor however thorough it is.

| | |
|---|---|
| File | `ad.ssa.gov-20260924-020431.json` |
| SHA-256 | `f723380e9e2216eb9575e8124a48ec69bc9f788b30fc9a85775e1039b681990c` |
| Capture | `ad.ssa.gov-20260924-020431`, taken 2026-09-24 |
| Taken with | `SecureAD.Measure --shape-profile`, build `3b3e6c0` |
| Run by | the owner, inside the production environment, 2026-09-25 |

## Do not redistribute this copy

**Line 2 carries the capture's name**, which is the forest's DNS name. That was a defect
in the build that produced it - a capture folder is named after the directory it was taken
from, and the field reported the folder name on the reasoning that only a *full path*
carries anything identifying. Fixed in `419f133`; the field is now a fingerprint of the
name rather than the name. The current build reports this capture as
**`e245e7645e764785`**, so a future profile of it can be tied to this one.

**The file is kept exactly as it came out.** It is the real output of a real run, and
editing a measurement by hand is how a figure stops being checkable - the same reason a
golden hash that needs changing is a finding rather than a fix. It is safe where it is:
the capture is already named in `docs/specs/P280-JUDGEMENT-OCCURRENCE-ROWS.md`. It is not
safe to send anywhere. A re-run with the current build produces a redistributable copy and
costs nothing beyond being in the environment already.

## What it says

| | |
|---|---|
| Objects captured | 940,067 |
| Of those, with a descriptor stored | 659,196 |
| **With no descriptor stored at all** | **280,871** |
| Unreadable, partly parsed, or reporting errors | **0, 0, 0** |
| Descriptors stored / used by an object | 271,901 / 267,550 |
| Permission occurrences | 330,856,576 |
| Domains | 9 |

| Spread | min | p50 | p90 | p99 | max | mean |
|---|---|---|---|---|---|---|
| Entries per descriptor | 2 | 533 | 585 | 681 | **1,278** | 529.6 |
| Objects per descriptor | 1 | **1** | 2 | 25 | **4,568** | 2.46 |
| Name, bytes | 19 | 105 | 132 | 158 | 250 | 106.1 |
| Name, depth | 3 | 10 | 11 | 13 | 16 | 9.5 |

Objects per domain: 187,633 / 92,831 / 90,496 / 77,314 / 62,213 / 62,059 / 52,756 /
30,227 / 3,667.

### The permission entries themselves

| | Occurrences | Share |
|---|---|---|
| Allow / deny | 294,727,869 / 36,128,707 | 89% / 11% |
| **Inherited / set directly** | **322,433,893 / 8,422,683** | **97.5% / 2.5%** |
| Carrying an object type | 238,118,809 | 72% |
| Carrying an inherited object type | 205,792,883 | 62% |
| **Carrying `S-1-5-10` (`PRINCIPAL SELF`)** | **20,454,613** | 6.2% |
| Trustee is well-known / is not | 73,028,129 / 257,828,447 | 22% / 78% |
| Inherit-only, no-propagate, callback data | 0, 0, 0 | |

## Four things it settles, and one it corrects

**1. The occurrence count is confirmed by two independent routes.** 330,856,576, identical
to what `--judgement-forecast` reported on 2026-09-24. Two separately written passes over
the same evidence. Neither was used to produce the other.

**2. `P-285` is measured: 20,454,613.** Because the resolved trustee name is inside the
sharing identity, every occurrence of `S-1-5-10` gets its own `permission_entry` row.
`P-279` took that table from 17,164,866 rows to 24,098 on the bench; on this forest `SELF`
alone would put up to twenty million back. That moves `P-285` from a tidy-up to the
question of whether `P-279` worked at all on a real directory.

**3. Reuse is far more skewed than an average shows.** The median descriptor is carried by
**one** object and the largest by **4,568**. `P-280`'s shape C - keying per descriptor -
still cuts 330 million rows to 141 million, because the mean is 2.46. But the saving comes
almost entirely from a small number of enormously shared descriptors, not from a broad
average, and anything designed around "descriptors are shared about twice" will be wrong
about half the table.

**4. Nothing failed to parse.** Every one of the 659,196 stored descriptors read
completely. `P-284`'s distinction was worth making and the honest answer here is none.
Separately, 280,871 objects - just under a third of the forest - have no descriptor stored
at all, and that is not the same as holding no permissions.

**5. It corrects the specification: not every name is ASCII.** The specification recorded
*"Every name is ASCII - 106.1 bytes and 106.1 characters"*, concluded from the byte mean
and the character mean agreeing to one decimal place. They agree because a handful of
accented names cannot move a mean across 659,196 objects. The profile compares byte length
against character length **per object** and answers `EveryNameIsAscii: false`. The
conclusion was sound-looking and the test behind it was weaker than it appeared, which is
the shape this repository keeps finding in itself. Nothing rests on it - the code already
pays in bytes - but the claim was wrong.

## What the bench looked like beside it

Taken the same day against `next/artifacts/p279-after`, which is what every `P-280` figure
was calculated from:

| | Bench | This forest |
|---|---|---|
| Entries per descriptor, p50 / p99 / max | 521 / 521 / 521 | 533 / 681 / 1,278 |
| Objects per descriptor, p50 / max | 1 / 3 | 1 / 4,568 |
| Name bytes, p50 / max | 97 / 97 | 105 / 250 |
| Domains | 1 | 9 |
| Carrying an object type | **0** | 238,118,809 |
| Carrying `S-1-5-10` | **0** | 20,454,613 |
| Well-known trustees seen | **0** | 19 |

**A forest where the median, the 99th percentile and the maximum agree to the unit is not
a forest; it is a constant.** The bench has no object-type GUIDs at all, so the part of the
`P-280` model that prices 14.9 GB of duplicated GUID text has never been checked against
anything. Teaching the generator to build a forest at the shape measured here is step 2b,
and until it is done nothing downstream should be believed on the bench's authority.

## A limitation of the profile itself, not a finding about the forest

904 distinct object-type GUIDs and 75 inherited ones are outside the catalogue shipped
with the product, covering 150,184,579 and 81,439,251 occurrences. **That is not 904
customer extensions.** The shipped catalogue is a curated set of security-relevant GUIDs
rather than the whole Active Directory schema, so most of those will be ordinary
attributes and classes it simply does not list. The profile cannot tell an unlisted
standard GUID from a local extension, and deliberately names neither.

Two consequences. Step 2b needs the distinction, because a generator has to know whether
to emit standard GUIDs or invented ones. And the product itself is unaffected: capture
reads the forest's schema partition per
`docs/decisions/0014-capture-reads-the-schema-partition.md`, so judging names these from
the forest's own schema rather than from the shipped list.
