# Where the product stands

A snapshot taken on 2026-08-12, written to be disagreed with.

This is not a changelog and not a summary of the decision records. It is what came out of reading
every record against every other, and every load-bearing claim against the code rather than against
a document describing the code. It says what the product does today, what each decision decided,
which decisions have been overtaken and by what, and what is actually built as against what is
merely agreed.

**Read this first if you have been away.** Then read the records themselves for the reasoning; each
line below is a pointer, not a replacement.

---

## What the product is

**SecureAD reads an entire Active Directory forest once, writes down what it found, and tells you
what is dangerous about it.** Reading the forest is the only thing that touches a customer's
network. Everything else works from what was written down.

That written-down thing is a **bundle**: one directory holding the evidence database, a seal, and
the customer's own annotations. A **seal** adds up the bytes of the evidence into one number and
writes that number beside it, so a file that has changed no longer matches. It catches an
interrupted copy, a bad disk, or a capture cut short by a full disk. It is not a signature and there
is no key in this product, so it proves nothing about who produced the file. That was decided
twice - once for the mechanism, once for the word.

**How you check whether something has been fixed is to read the forest again and compare the two
runs.** There is no live look-up of a single object. That capability existed and was removed,
because it could answer a question about one object at a time and this tool exists to answer
questions about four thousand.

---

## What is actually running

**Nothing.** The product does not run end to end and has not since the rebuild started.

Sixty-nine files of production code exist across three projects. They are libraries: a security
descriptor parser, a permission classifier, a connection that walks a security ladder, a capture
that can read a partition, a bundle that can store one, and the rules that decide whether two runs
may be compared. **Nothing joins them.** There is no entry point, no run driver, and no screen.

This is deliberate and it is recorded honestly - the surface register names, per type, the future
component expected to call it, and three entries currently say *no caller yet* rather than looking
finished. But it is the single most important fact about the state of this project, and it is worth
stating plainly rather than leaving it to be inferred from a table.

**Fourteen components of two hundred and fifty-six are done.** Five in the kernel, two in connect,
five in capture, one in storage, and six in the run model.

---

## What each decision decided

One line each. **Overtaken** means a later record replaced part of it; the record still stands and
says what replaced what.

| # | Decided | Standing |
|---|---|---|
| 0001 | Nothing is kept backward compatible, because nothing has shipped | Accepted |
| 0002 | Missing output is a fact about the capture, never about the forest | Accepted |
| 0003 | Re-analysis refuses a source that cannot show it finished | Overtaken by 0030 as to *signature* |
| 0004 | A count the run cannot vouch for prints as *unknown*, naming the phase that failed | Overtaken by 0030 as to *signing* |
| 0005 | A withheld count is withheld across the whole column, and the reason is stated once | Accepted |
| 0006 | *Worth attacking* and *unremarkably privileged* are two different lists | Accepted |
| 0007 | The assessment mode is never shown to a user | Superseded by 0031 |
| 0008 | Live directory look-up is removed; re-capture and compare is the only verification | Overtaken by 0014 as to the schema partition |
| 0009 | The rebuild happens in this repository | Overtaken by 0013 (the seam), 0012 (the location), 0030 (*signed*) |
| 0010 | What a rule is called and how bad it is are data; how it detects is code | Accepted |
| 0011 | Rebuild documentation is written fresh, and is not documentation until a test binds it | Accepted |
| 0012 | The rebuild lives at `next/` with its own solution | Accepted |
| 0013 | The rebuild owes the old application nothing and writes whatever schema it needs | Accepted |
| 0014 | Capture reads the schema partition, so permissions can be named | Accepted |
| 0015 | A recognised delegation pattern gets a name; it never excuses a finding | Overtaken by 0030 as to *signed* |
| 0016 | The filtered-set replication route is our judgement, not a Microsoft-documented fact | Accepted |
| 0017 | Capture reads the whole forest; scope filters reading, never evidence | Overtaken by 0030 as to *signed* |
| 0018 | Connection security is a four-rung ladder walked from the top, and the bottom rung must be declared before the run | Accepted |
| 0019 | The bundle carries a seal, and the partial-file rename is what stops a half-written bundle being read | Superseded by 0020; its rename rule restated live in 0029 |
| 0020 | The seal detects corruption, not tampering, and only an intact bundle opens | Accepted |
| 0021 | Re-analysis produces a new bundle and never touches the one it read | Accepted |
| 0022 | An object is one row of typed columns, and what was never seen is recorded by reference | Accepted |
| 0023 | A finding is identified by rule, subject and object, and an acceptance that no longer matches is reported rather than dropped | Accepted |
| 0024 | A rule number is permanent and is never reused | Accepted |
| 0025 | The tool owns one root directory the operator chooses, and a baseline belongs to a forest | Overtaken by 0027 as to its exclusion reasoning |
| 0026 | One component answers *may these runs be compared*, and the drift card has three shapes | Overtaken by 0027 as to its state table |
| 0027 | Coverage varies only by failure or by the forest changing, and a failed run is refused | Accepted |
| 0028 | Six words for what became of a run, each reached from something observed | Accepted |
| 0029 | A run that ends badly writes down why, and whether a run is alive is asked of the file system | Accepted |
| 0030 | The product produces sealed evidence, never signed | Accepted |
| 0031 | There is no assessment mode | Accepted |
| 0032 | A decision record is corrected in place, and git is the history | Accepted |
| 0033 | Nothing inherited is definitive — the map, the old code and the old documentation are evidence, not answers | Accepted |
| 0034 | Capture reads every object class except a shipped list of noise; the operator switch only ever widens it | Accepted |
| 0035 | Coverage is recorded once per capture unit; domain and run coverage are derived from those rows | Accepted |
| 0036 | Capture never requests the SACL; the product reports nothing about audit configuration and needs no privilege on a domain controller | Accepted |
| 0037 | A DACL the run could not read says so, and every descriptor records how many entries its header declared | Corrected the same day as to the *entry count*, which gate 4 refused |
| 0038 | A descriptor records whether its DACL arrived in canonical order; the raw bytes stay the authority for exact order | Accepted |

---

## What is built against what is only decided

A decision with nothing built against it is not a problem - most of these are ahead of the code by
design. A decision *contradicted* by what was built is a problem, and there is one.

**Built and matching the decision:** 0006, 0010, 0012, 0014, 0016, 0018, 0027, 0028, 0029. The
connection ladder is real code with the four rungs named. The run states are the six words, each
reached by the observation procedure the record specifies. The comparability outcomes are a closed
set of nine, matching the ten situations in 0027 - two of which are both *fully comparable* and
differ only in whether anything changed.

**Built, and known not to match the decision:** the schema and writers in `SecureAD.Evidence` were
written on 2026-08-12 and superseded by review the next day. They store attributes the way 0022
replaced, have no re-analysis path 0021 restored, and frame the seal the way 0020 rejected. This is
already flagged prominently in the rebuild README and the ledger rows say *rebuilding after review*.
Nothing here is worse than was already known.

**Decided with nothing built yet:** 0001, 0002, 0003, 0004, 0005, 0011 in part, 0013, 0015, 0017 in
part, 0020, 0021, 0022, 0023, 0024, 0025, 0026. These are ahead of the code and that is the intended
order.

**Decided, and contradicted by what was built:** none, as of 2026-08-12. There was one. **0007**
ruled that the assessment mode stays in the bundle partly because *"compare refuses to compare runs
whose modes differ"*, and nothing in the rebuild had an assessment mode at all while the closed set
of reasons a comparison may be refused had no member for one. The owner ruled the same day that
there is no assessment mode, and [`0031`](../decisions/0031-there-is-no-assessment-mode.md)
supersedes `0007` entirely.

---

## What this review found

Recorded in full, with severities, in [`S-19`](S-19-the-point-in-time-review.md). In short:

**One contradiction between accepted records, now resolved by the owner.** Five records described
the bundle as *signed* while the record governing the mechanism said there is no key and it is not a
signature. Two documents repeated the claim to a customer. The word is withdrawn by 0030; every
decision in the five records survives.

**Six findings recorded and left.** A record whose reasoning was overtaken without a pointer; a
record that never got its forward pointer to the one that moved the rebuild; the 0007 clause above;
a production comment arguing against a decision the file beside it implements; a bundle's file names
having two owners; and scratch files inside the repository.

---

## What would still catch nothing

Being honest about the limits of this exercise.

A test now checks that this document names every decision record and no record that does not exist,
and that what it says about supersession matches each record's own status line. That is the check
that would have caught the index silently missing two records, and it would have caught 0025 and
0026 resting on a removed mechanism only if somebody had written the status note.

**It cannot check that a decision is right, or that two decisions are compatible.** The *signed*
contradiction was found by a person reading thirty documents in one sitting, and no test would have
found it. This review is a snapshot, and it starts going out of date the moment it is written.
Whether it is worth repeating is a judgement about how fast the records are changing, not something
the build can decide.
