# 0038 - A descriptor records whether its DACL arrived in canonical order, and the raw bytes stay the authority

Date: 2026-08-13
Status: Accepted

## Context

Windows evaluates a DACL **in stored order** and stops at the first entry that matches. Canonical
order puts denies before allows, so in a canonical DACL a deny wins. In a **non-canonical** DACL -
one where an allow for a trustee precedes a deny for the same trustee - the allow wins, and the
access is granted.

That is not a curiosity. It is a known evasion: tooling which assumes canonical order reports the
deny, and the system honours the allow. It also arises innocently, because the LDAP and ADSI paths
that write descriptors do not all reorder, so a script can leave one behind without meaning to.
Either way it is worth an auditor's attention, and either way it is only visible if somebody looked
at the order the directory actually stored.

`AceNormalizer` sorts every DACL into canonical order before anything else happens to it, and
`CanonicalAce` carries no record of where an entry sat before the sort. So
`S-21` found that the product would report the deny
that Windows will not honour, and could not say that the order had been unusual, because after the
sort nothing said so.

**The sort is not the defect and must not be removed.** It is what makes `ace_hash` and
`ace_set_hash` deterministic; a hash that depended on the order the directory happened to return
entries in would report a change on every run against an object nobody touched. The defect is that
the sort was lossy and silent.

The obvious fix was to store each entry's original index. It was rejected. **`security_descriptor`
already stores `raw_bytes` for every distinct descriptor**, so the original order is not lost from a
bundle at all - it is lost only from the canonical projection over it, and re-parsing recovers it
exactly. An ordinal column would therefore store a fact that is always recomputable from evidence
already held, which is the near-duplicate mechanism [`0025`](0025-the-run-library-is-a-managed-root.md)
argues against by name: this repository already has three ways to ask one question about
distinguished names, and that is how it happened.

What is genuinely missing is not the order. It is a cheap way to ask *did this need reordering* over
a whole forest, which re-parsing several million descriptors is not.

## Decision

**Every descriptor records whether its DACL arrived in canonical order**, as one boolean, computed
during the parse that already runs while the entries are still in the order the directory sent them.

**Canonical order is the documented one**: explicit deny, explicit allow, inherited deny, inherited
allow. A DACL is canonical when that sequence never goes backwards. This is the same classification
the normaliser sorts by, and it is stated in **one** place that both the parser and the normaliser
call, so the two cannot drift apart.

**No original ordinal is stored.** `raw_bytes` is the authority for exact order and re-analysis
recovers it. The boolean answers *is this worth looking at*; the bytes answer *what exactly was it*.

**The sort is unchanged**, and so are `ace_hash`, `ace_set_hash` and the canonicalisation version.
Order of arrival is not a hash input and must not become one.

**A non-canonical DACL is a finding, not a repair.** The product reports the order was unusual. It
does not attempt to evaluate the object the way Windows would, because a tool that silently computed
the "real" answer would hide the thing the auditor most needs to see.

## Consequences

**A forest-wide question becomes one indexed column.** *Show me every object whose permissions are
in non-standard order* is a query rather than a re-parse of every descriptor in the bundle.

**The product will report something it previously could not**, and on most forests the answer will
be zero, which is the correct and boring result. On the forests where it is not zero, it is likely
to be the most interesting line in the report.

**Exact order still costs a re-parse**, deliberately. If a rule ever needs true evaluation order it
reads `raw_bytes`, and that rule pays for what it uses rather than every descriptor paying a column
for it in advance.

**One classifier, two callers.** Moving the deny-versus-allow and explicit-versus-inherited
classification out of `AceNormalizer` and into `AceCanonicalization` means the parser's judgement of
canonical order and the normaliser's sort agree by construction. Two lists of ACE types that had to
stay in step would not have.

**A descriptor whose entries did not all parse cannot be judged**, and the flag says what it saw
rather than guessing. Whether that matters is
[`0037`](0037-an-unreadable-dacl-says-so.md)'s question, not this one.

## Amendment, 2026-08-19 â€” the decision is right, and the reason given for it is not AD's

Recorded by the session that took `S-58` finding `#7`. **The Context above is left standing**, for
the reason every amendment in this repository gives: a decision record that quietly loses what it
decided cannot be audited afterwards.

### The mechanism stated above is the general Windows one, not Active Directory's

The Context says Windows "evaluates a DACL **in stored order** and stops at the first entry that
matches". That is the general early-stop description. **AD does not do this.** MS-ADTS 5.1.3.3.2
*Checking Simple Access* defines the algorithm for an Active Directory object:

> Let G and D denote the access rights that are granted and denied, respectively, on the object. Set
> both to a value of 0 initially. [â€¦] Evaluate the DACL by examining **each ACE in sequence**,
> starting with the first ACE. [â€¦] If the ACE type is "Access Denied" and the access rights in M are
> **not in G**, then add the rights in M to D. If the ACE type is "Access Allowed" and the access
> rights in M are **not in D**, then add the rights in M to G. [â€¦] When the **end of the DACL** is
> reached, the access rights in G is the maximum standard access available.
> ([Checking Simple Access](https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/c55e113e-25a2-45eb-abba-bf5a9e521a8f))

There is no early stop. Every ACE is examined.

### The decision survives, and its evasion is real, by a different route

Order still decides the outcome, so **nothing about what this decision requires changes**. An allow
that precedes a deny for the same trustee still wins â€” not because evaluation halts, but because the
rights are already in `G` by the time the deny is read, and a deny only adds to `D` for rights *not
in* `G`. The tooling failure the Context describes is therefore exactly as real as it says: a tool
assuming canonical order reports the deny, and the directory grants the access.

This is the same source `S-57` used to uphold `#2`/`#3`, and it is worth stating plainly because the
early-stop sentence was repeated wherever this decision was implemented â€” twice in
`AceCanonicalization`, in three test files, and in the notice shown to an operator on the object
screen. All are corrected. **A wrong reason attached to a right conclusion propagates further than
a wrong conclusion**, because nothing it produces looks incorrect.

### What one boolean cannot say, which is `#7`

`S-56` v4 Â§5.2 and R5 ask for four separate claims, and `dacl_was_canonical` is one:

1. **Stored ordinal preserved and displayed** â€” a claim about evidence, and `#2`/`#3`'s subject.
2. **AD canonicality by the rules applicable to the forest** â€” MS-ADTS ACE ordering adds regular
   ACEs before object ACEs, and lexicographic ordering within groups at applicable forest functional
   levels. The flag checks neither.
3. **Whether the DC was expected to standardise the ACL at all** â€” forest functional level and
   `fDontStandardizeSDs`, character 12 of forest-wide `dSHeuristics`. Neither is captured, so this
   cannot be answered today by any means.
4. **Locally provable defects reported separately from inheritance provenance** â€” an inherited ACE
   carries no depth field, so a single DACL cannot prove that inherited entries are in
   inheritance-generation order. Establishing that needs ancestor descriptors, schema applicability,
   inheritance flags and protection boundaries.

So the flag answers a narrower question than its name: *were the entries I recognised in
explicit-deny, explicit-allow, inherited-deny, inherited-allow order*. That is a locally provable
defect check and a useful one â€” it is what catches the evasion â€” but it is not claim 2, and it is
silent about 3 and 4.

### What changes now, and what does not

**The field stays, and so does everything this decision requires of it.** It is still computed
before the sort, still one indexed column, still a finding rather than a repair, and still not a
hash input.

**What changes is what the product claims for it**, in the code and on the screen: the flag is
stated as a locally provable ordering check rather than a verdict on AD canonicality, and the reason
given for why order matters is now AD's.

**Splitting the flag into R5's four claims is not done here.** Two of the four need inputs no
capture collects, so a column would have nothing to put in it, and `#2`/`#3` needs a schema change
of its own. Recorded in `S-58` so the two are taken together rather than breaking bundle
compatibility twice.
