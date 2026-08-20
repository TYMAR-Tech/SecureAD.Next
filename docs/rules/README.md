# Rule reference

One card per findings rule. These describe the `SEC-*` rules defined in
`src/SecureAD.Core/Findings/Rules/rules.yaml` — what each rule is for, how it detects, what it
filters out, what evidence it emits, and where its limits are.

This is a **permanent reference, not a review**. The per-rule audit that created it is finished;
what remains is the description of the rules as they are, and it is expected to be kept true. A
rule and its card change together.

Internal rather than user-facing: cards carry implementation detail, verification status, and
open improvement items.

## Contents

| File | Purpose |
|---|---|
| `SEC-XXX.md` | One card per rule: intent, detection logic, filters, evidence, known limitations, and verification status. |
| `FIRST-PARTY-VERIFICATION.md` | Claim-level ledger: each atomic fact a rule depends on (GUIDs, access-mask bits, SID/RIDs, UAC flags, baselines) verified **once** against a first-party Microsoft source and mapped to the rules that consume it. |
| `IMPROVEMENTS.md` | Cross-rule improvement backlog and the `[IMP-*]` tag taxonomy referenced in code comments. |
| `_NEXT.md` | Scratch/next-up notes for in-progress rule work. |
| `_template.md` | Template for a new rule card. |

## How to use it

- **Adding or changing a rule?** Update (or add) its `SEC-XXX.md` card in the same change, and if
  the rule introduces a new atomic fact, add a row to `FIRST-PARTY-VERIFICATION.md` citing the
  first-party source.
- **A Windows version or Microsoft guidance changed a value?** Find the claim row in
  `FIRST-PARTY-VERIFICATION.md`; it lists every rule that depends on that value to re-check.
- **A card contradicts the code?** The code is what runs. Fix the card, and check whether the
  rule is doing what the card says it should — a drifted card usually means one of the two moved
  without the other.

The guiding principle is "trust no doc": a claim is only `Verified` when the cited Microsoft page
actually states the value. Internal consistency is not correctness — every implementation in the
codebase can agree with the others and still be wrong.

## Note on the `Reviewer` field

Cards carry a `Reviewer` row naming who or what verified them. Those are records of a past
verification and are left as written; they are not a claim about who maintains the card now.
