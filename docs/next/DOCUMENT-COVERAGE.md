# What the documentation tests actually check

**A dated snapshot, taken 2026-08-16, to answer one question: how much of each session document in
`docs/next/` is held true by the build, and how much is prose nobody checks.**

**This page is not authoritative and it will go stale.** It exists to be consumed by the decisions it
informs — which documents stay live, which are renamed, which are stamped and moved to
`docs/history/`. Once those are made, it has done its job.

---

## The headline

**Twenty-three session documents sit in `docs/next/`. Thirteen are bound to the code by a test. Ten
are not.**

Production code cites ten documents, and **every one of the ten is in the bound thirteen**. Nothing
in the product points at a document that nothing validates. That is the reassuring part.

**The unsettling part is the pattern.** Every unbound document is `S-28` or later. The practice of
binding a document to the code did not decay gradually — it stopped, and the ten most recent
session documents carry no enforcement at all.

---

## What a binding is worth

A binding is strong about **structure** and silent about **prose**.

Take `S-14-the-connection.md`, the one read in full. Its test reads the ladder table out of the
document and compares it **element by element, in order** against `ConnectionSecurityLadder.Rungs` —
level, port, TLS, sign, seal and the declaration flag of every rung. It carries a scanner self-test
and a negative control that would catch a parser accidentally matching the whole document.

It also asserts the document is longer than 6,000 characters. **That is a floor on the prose, not a
check of it.**

So for every bound document below: **believe the table, and treat the paragraphs around it as
discussion.** The failure recorded in `docs/history/README.md` — `S-15` saying capture "takes a
destination" for days after `0025` decided the opposite — was prose, not a table. No test that
exists today would have caught it.

**Most bindings check both directions**, which is what makes them worth having: the document names
everything the code has, *and* names nothing the code does not. Several also carry a negative
control against a member name being matched by a substring.

---

## The thirteen that are bound

| Document | Held true by | What is machine-checked |
|---|---|---|
| `S-1-security-descriptor-parsing.md` | `SecurityDocumentationTests` | every public type of the component, both directions; every DACL state; the canonicalization version the code declares |
| `S-2-distinguished-name-manipulation.md` | `DistinguishedNameDocumentationTests` | every public type and member; the namespace the code declares |
| `S-3-schema-guid-catalogue.md` | `SchemaGuidDocumentationTests` | every public type and member; the namespace; that the handover names a real inventory row |
| `S-4-dangerous-permission-classification.md` | `PermissionClassificationDocumentationTests` | every public type and member; **every verdict is explained**; the DCSync question is handed to a row carrying it as a prerequisite |
| `S-8-captured-attribute-catalogue.md` | `CapturedAttributeCatalogDocumentationTests` | every attribute the catalogue requests, both directions; cardinality and storage agree with the code; every attribute names something that reads it; the catalogue version |
| `S-9-the-capture-unit.md` | `CaptureUnitDocumentationTests` | every property of the search, described **and described correctly**, both directions |
| `S-10-politeness.md` | `PolitenessDocumentationTests` | every limit the code names, both directions, with the same default in both places; every failure code the retry policy answers; that the wait doubles and starts long |
| `S-11-reading-what-a-controller-returns.md` | `LdapEntryReaderDocumentationTests` | every completeness state, both directions; every conversion offered, both directions; block size and limits identical in both places; the no-partial-answer rule |
| `S-12-the-capture-passes.md` | `CapturePassesDocumentationTests` | every way a pass can end, both directions; the scanner reads the real loop |
| `S-14-the-connection.md` | `ConnectionDocumentationTests` | the whole ladder, element by element and in order; that only the bottom rung needs a declaration |
| `S-16-the-bundle.md` | `BundleDocumentationTests`, `HistoricalRecordDocumentationTests` | every table the schema creates, both directions; **every table says what its absence means**; checked against a real database |
| `S-18-run-identity-and-comparability.md` | `RunComparabilityDocumentationTests` | every public type and member; every comparability outcome, both directions; every run state, both directions; every run state says how it is observed |
| `S-23-what-capture-must-read.md` | `CapturedAttributeDerivationDocumentationTests` | every attribute the derivation calls captured is in the catalogue, and every one it calls absent is not; the derivation accounts for every attribute requested; every rule named is a real card |

## The ten that are bound by nothing

| Document | Cited by production code? |
|---|---|
| `S-28-the-entry-point.md` | no |
| `S-29-finishing-the-entry-point.md` | no |
| `S-30-coverage-that-measures.md` | no |
| `S-31-the-group-that-is-too-big.md` | no |
| `S-33-the-first-read-that-is-allowed-to-fail.md` | no |
| `S-35-a-shell-you-can-click.md` | no |
| `S-37-preflight.md` | no |
| `S-39-discovery-and-selection.md` | no |
| `S-40-wiring-discovery-into-capture.md` | no |
| `S-41-the-new-audit-wizard.md` | no |

**Nothing enforces these and nothing in the product relies on them.** There is no claim here to
validate — only a claim to stop relying on. Reading them to check them would be work spent on
documents that are already, in practice, history.

---

## What this says about the way forward

**Auditing all twenty-three by hand is `S-26` again.** That session reconciled the documentation
once, by reading, and it did not hold, because nothing enforced the result. Twenty-three
hand-checked documents are twenty-three documents that were true on the day they were read.

**The durable version is migration, not audit.** As each area file is written, the claims that
matter move into it, where the area gate holds every capability to a named test and every link to a
real record. What is left behind is stamped and stops mattering, because nothing may rely on it.

The ten unbound documents can move to `docs/history/` without being read, today. The thirteen bound
ones should keep their tests, whatever else happens to them — and if any is renamed, the test's
constant and the citations in the source move with it, or the build fails.

