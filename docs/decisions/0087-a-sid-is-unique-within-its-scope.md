# 0087 - A SID is unique within its scope, not within the forest

Date: 2026-08-28
Status: Accepted.

Sits under [0052](0052-the-domain-is-the-only-unit-of-scope.md), which makes the domain the unit of
scope for what a run *reads*. This record says the same thing about what a derivation *keys on*: the
domain is a component of a principal's identity, and dropping it merges principals that are not the
same.

This record reverses an assumption stated in `DerivationSchema` and corrects a defect inherited from
the predecessor.

## Context

Stage 2a crashed on the first multi-domain forest it was pointed at:

```
SQLite Error 19: 'UNIQUE constraint failed: sid_identity.sid_id'
```

`SidInterner` keys principals by SID text, and `sid_identity` carries `PRIMARY KEY (sid_id)`. Both
encode the assumption that one SID names one principal across a whole forest.

**Microsoft says otherwise, in as many words.** From
[Security identifiers](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-security-identifiers#sid-architecture):

> SIDs for built-in accounts and groups always have the same domain identifier value, 32. This value
> identifies the domain, Builtin, which exists on every computer that's running a version of the
> Windows Server operating system. **It's never necessary to distinguish one computer's built-in
> accounts and groups from another computer's built-in accounts and groups, because they're local in
> scope.**

and:

> SIDs are unique **within their scope** (domain or local), and they're never reused.

So `S-1-5-32-544` is `BUILTIN\Administrators` in *every* domain, and those are different groups with
different members. The domain identifier `32` is not a domain the forest issued; it is a constant.

**The lab bundle measures how ordinary this is.** `ad.lab-20260827-110600`, a three-domain forest,
holds 32 SIDs carried by more than one captured object, across 100 objects:

| Kind | Objects |
|---|---|
| Builtin (`S-1-5-32-*`) | 84 |
| ForeignSecurityPrincipal | 12 |
| WellKnown Security Principals | 4 |

This is not an edge case. It is roughly the number of builtin aliases multiplied by the number of
domains, every time. A single-domain forest never meets it, which is why the assumption survived to
the first real capture.

**The predecessor had the same defect and never noticed.** `DerivedStoreSchema` declares:

```sql
CREATE TABLE dim_principal (
    sid          TEXT PRIMARY KEY,   -- the forest-wide key
    domain_fqdn  TEXT,               -- captured, but not part of the key
    ...)

CREATE TABLE fact_group_membership_direct (
    group_sid    TEXT NOT NULL,
    member_sid   TEXT NOT NULL,
    domain_fqdn  TEXT NOT NULL,      -- again, not part of the key
    PRIMARY KEY (group_sid, member_sid))
```

and `DirectGroupMemberWriter` populates the second with `INSERT OR IGNORE`. `GroupExpansionService`
matches: `HashSet<string>` throughout, joined `ON a.trustee_sid = p.sid`.

So all three `BUILTIN\Administrators` collapsed into one row, their members unioned, and
`INSERT OR IGNORE` absorbed every collision without a word. The domain was *captured* and simply
never reached the key.

## Decision

**A SID is interned under its scope.** A SID in the `S-1-5-32` range is keyed by
`(domain, sid)`. Every other SID is keyed by `(sid)`, because domain SIDs
(`S-1-5-21-<domain>-<rid>`) are unique by construction and Microsoft guarantees it.

**Being seen on more than one object is not the same as being more than one principal.** Two
situations are separated deliberately:

| Seen twice because | Same principal? | Handling |
|---|---|---|
| BUILTIN alias exists in every domain | **No** | Distinct ids, one per domain |
| Universal well-known SID (`S-1-5-11`) appears once per domain as a stub | Yes | One id, one row |
| `foreignSecurityPrincipal` stands in for a principal from another domain | Yes | One id; the real principal wins over the stub |

**What is collapsed is counted.** A stub folded onto a real principal is recorded in the run log and
in the derivation's completeness, for the same reason an unresolved trustee is: a fidelity loss
nobody is told about is one nobody can check. A built-in SID with no domain to scope it by is
counted the same way, and unlike a collapsed stub it makes the derivation incomplete - folding a
stub loses no fact, but an unscoped built-in may have merged two principals that are not the same.

## Why not the alternatives

**Keep SIDs forest-wide and add a scope column to `principal`.** The column would not be in any key,
so the merge would still happen — this is precisely the shape the predecessor shipped, and the
column it already had.

**`INSERT OR IGNORE`, first row wins.** The smallest possible change, and the reason the predecessor
was wrong in silence for years. It converts a loud crash into a fabricated finding: one domain's
local Administrators reported as containing another domain's Domain Admins. An audit tool inventing
a cross-domain privilege path is the single failure this product exists to prevent.

**Refuse to derive when a SID repeats.** Over-correction. The repetition is the directory behaving
exactly as documented, not a fault in the capture.

## Consequences

`DerivationSchema` gains a scope on the SID dictionary and its uniqueness index changes, so the
schema version moves. `SidInterner.Intern` requires a scope from its caller, which means
`ObjectAttributes` must carry the `domain_fqdn` the evidence already records — the fact was captured
all along and only needed surfacing.

**The crash was the design working.** A strict primary key turned an inherited silent wrong answer
into a loud stop on the first forest that could expose it. That is the argument for keeping
constraints strict in the derivation store, and it is worth remembering the next time one is
inconvenient.
