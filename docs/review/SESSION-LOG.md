# Session log

**Plain language, newest first.** One entry per session, written for someone who has not read the
diffs and does not want to. Findings, slice files and commit messages carry the detail and the
evidence; this file carries *what changed, what is still true, and what is next*, in the fewest
words that are still honest.

It exists because the person who owns this product is not a developer and works alone, and a review
that can only be followed by reading its own output is not resumable by the person it is for.

This is an **event** document: entries accumulate and are never edited to match later understanding.
If an entry turns out to be wrong, the next entry says so.

---

## 2026-08-09 — the safety net exists, and it already found its own blind spots

**What this was.** The tool decides which accounts in a forest are dangerous — "Tier 0", "high
value". Nothing was checking that those decisions stay the same. Three separate changes to that
logic had gone in over the past fortnight and the entire 4,296-test suite stayed green through all
three. Not because the changes were harmless, but because nothing was looking. This session built
the thing that looks.

**What it does now.** Two real captures from the lab are frozen in the repository along with the
tool's verdict on every single account in them — 2,192 accounts in one, 2,193 in the other. Every
test run recomputes those verdicts and compares. If a verdict moves, the test fails and names the
accounts that moved.

**The decision you flagged, and how it went.** The lab databases are 58 MB and deliberately not in
the repository, so the choice was a small committed fixture or a test that skips itself when the
lab isn't there. Committed fixture, as you asked — and it turned out to be cheap. The two pieces of
code being checked only read four tables and fourteen columns; everything else in those 58 MB is
irrelevant to them. Pulled out and compressed, each capture is 555 KB. The tests run on any machine,
with no lab present, and never skip. The suite still has exactly three skipped tests and they are
still the same three as before.

**One thing I deliberately did not do.** I could have shrunk the fixture much further by keeping
only the rows that currently matter. I didn't, because "currently matter" is decided by the very
code being tested — so if someone later widened that code, it would find nothing new to act on and
the test would stay green while the behaviour changed. The fixture keeps every row and throws away
only unused columns.

**The check that proves it isn't fooling itself.** One of the two captures has a permission that was
granted by hand in the lab, on purpose, months ago — so its correct answer is known independently of
this codebase. The two frozen sets differ by exactly one account, flagged for exactly that reason.
That is asserted by name, so nobody can quietly accept a future change that erases it.

**Then I broke the code four times on purpose to see whether the net would notice.** It caught two
and missed two. It missed them because the lab forest simply does not contain the conditions those
two changes would affect — nobody in it holds that particular permission on a sensitive object, and
every account with half of the "can steal all passwords" right already has the other half. So a
change in either of those two directions would still ship unnoticed today.

**I have written that down rather than quietly not mentioning it**, in the review README and beside
the fixture itself. A safety net whose gaps are undocumented is worse than a smaller net that is
honest about its edges, because people trust it further than it reaches. Two of the six reasons the
tool can promote an account to "Tier 0" are also never triggered by this lab forest, for related
reasons, and that is written down too — as an exact list, so if a future capture does trigger one,
the suite says so instead of silently widening.

**Full test suite: 4,303 tests, all green.** Seven more than last time; all seven are mine.

**What's next.** The safety net was the precondition for the real job, which is now unblocked: the
tool has four separate lists of "which accounts count as privileged", they overlap, and they don't
entirely agree. Next session sorts those rows into two piles — the ones that are simply duplicated,
and the ones where the lists genuinely disagree and somebody has to decide which is right. The
second pile becomes decisions for you. That work can now proceed safely, because if consolidating
the lists changes anyone's verdict, the net will say so by name.

**The one way to waste this.** When the net fails, it writes out what the tool now says, so it can
be compared line by line against what it said before. Copying that over the top without reading it
turns the whole thing into a rubber stamp. That is spelled out in both places someone would look.

**What is not fixed.** The two blind spots above can't be closed by a bigger fixture. They need a
capture of a forest that actually contains those conditions, which means planting them in the lab —
that is the third and last activity of the reset, and it is still ahead of us.

---

## 2026-08-09 — the half-finished one is finished, and it can't come back

**What this was.** The one dangerous half-built item from last time: opening a run while another was
loaded released the old run's connections without waiting for its background work to stop. Fixed.

**What you would have seen before.** Open run B while run A is loaded, on a big bundle, and run A's
tree and dashboard queries could still be reading files that were being closed underneath them. That
shows up as a crash on a background thread, or as run A's folder staying locked so the run library
can't delete it — while correctly telling you the run is closed.

**What was done, and why it's more than the missing line.** Closing a run does four things in order:
shut the pop-out windows, cancel the pending work, *wait* for the work already running, then close
the files. Opening a run was doing two of them. The tempting fix is to add the missing wait. I didn't,
because that's the third time someone would have copied part of this sequence into a new place and the
part left behind is invisible. The four steps are now one method that both paths call, so a future
path gets all of it or none of it.

**How I know it's actually fixed.** Two new checks were added to the test that already owns this
rule, and then I broke the code on purpose to watch them fail: removing the wait failed exactly the
check about waiting, and putting the old opening path back failed both. A test that has never been
seen to fail is not evidence.

**One piece of documentation was wrong and is now right.** `ARCHITECTURE.md` listed a database
method that was deleted a week and a half ago. That is the failure mode this review keeps meeting —
not missing documentation, but confident documentation describing something that no longer exists.
The rule for releasing a run now lives there too, in plain terms, rather than only inside a finding.

**Full test suite: 4,296 tests, all green.** Four more than last time; two are mine and two came from
the routing commit that asked for this work. Worth saying because the recorded number was two behind
reality, and a baseline nobody reconciles drifts in the direction of looking fine.

**What's next.** Nothing in the backlog is half-built any more, so the ranking reset you agreed to
starts properly: run the current classifiers over a real capture from the lab and freeze exactly what
they produce. That's the safety net that makes it safe to consolidate the four overlapping
definitions of "privileged" afterwards — and it needs no forest work. The next session's plan is
written out in full in the review README, including the one decision it has to make first: the lab
databases are 58 MB and deliberately not in the repository, so the frozen answers need a small
committed fixture rather than a test that quietly skips itself when the lab isn't there.

**Tidied up on the way out.** Five leftover commit-message scratch files had collected in the review
folder, and the rule meant to ignore them named a filename nothing has used for weeks. Both fixed;
the working folder is clean.

---

## 2026-08-08 (third entry) — changing how the work is chosen, and finding the one thing left half-done

**What this was.** Not repair work. You asked whether the review is a sensible way to use AI on a
codebase this size, whether you should start over instead, and whether anything in the backlog is
sitting in a dangerous half-finished state. Three answers.

**Is anything half-finished and dangerous — yes, one thing.** When you open a run while another is
loaded, the app closes the old run's connections *without waiting for its background work to stop*.
The closing path waits properly; the opening path doesn't. The symptom is a crash on a background
thread, or the old run's files staying locked so you can't delete it. It's half-built because the
sweep that goes with it was added and the wait wasn't. That's next, and the fix is to make both paths
share one release sequence rather than patch the missing line — because this is the second time half
that sequence got copied.

**The one that looked worse turned out to be fixed.** The finding about deleting a run and destroying
half its bundle still read "still open" in its write-up. It isn't — it was fixed on 8 August, under a
different finding's name, and nobody went back to update this one. Interesting detail: the index was
right and the article was wrong, which is the reverse of the usual failure here.

**Something worth knowing about documentation.** That stale write-up contained a claim that had been
properly verified with a search command on 8 August — "this method has exactly one caller". By today
it had two. Nobody was careless; the document just aged. **A document that gets verified is right
once. A document that fails the build is right continuously.** That's the argument for spending
effort on tests that check documents against code — you already have three — rather than on more
careful reading.

**On starting over.** I measured rather than argued. In the eleven days of this review, not one line
of product code has been reverted; the churn you're feeling is in my write-ups, not in your app.
Your code also isn't naive about Active Directory — it handles the things that catch people out. And
what a rewrite would throw away isn't the 82,000 lines, it's the 58,000 lines of tests and the
capture code that works against your actual forest. With AI, a rewrite is deceptively fast to produce
and just as slow to *prove* — and proving is the part you'd be discarding.

**What we're changing instead, and you drove all three.**

*The work is ranked by one question from now on:* **what could make this tool report a forest as safer
than it is?** You were right that the goal kept moving — it moved because the queue was ordered by
which folder the code lives in, and a folder name says nothing about whether a defect can mislead a
customer. Under the new ordering, the column we deleted this morning ranks near the bottom and the
swallowed database errors rank at the top. Under the old one they ranked the same.

*You corrected my ordering, and you were right.* I said validate against your forest first, then
consolidate the duplicated definitions. You said get the definitions in one place first so the
infrastructure is there when you test. I'd conflated "is it correct" with "did it change" — you only
need the second to refactor safely, and you can get that from the lab captures you already have,
without touching the forest. Your order also self-corrects: validation afterwards catches any mistake
the consolidation made. Mine paid the expensive lab cost twice.

*And the new documents mostly shouldn't exist.* I proposed a validation ledger; you asked whether it
fits what's already there. It does — `docs/rules/FIRST-PARTY-VERIFICATION.md` is that ledger, 314
lines of it, already mapping every fact to the rules that depend on it. What's missing is one column:
those statuses all mean "checked against a Microsoft page", and your worry is about "checked against
a real directory". One new column beats one new folder. I was about to build a second home for facts
that already had one, which is the exact mistake this review exists to catch.

**One correction to something I told you earlier today.** I raised the alarm that Tier-0 identity is
defined in four or five places. The accurate version is narrower: the values live in *catalogues*,
which is the right shape, and the open question is only whether those catalogues answer four
genuinely different questions or duplicate one. That's a real question and worth settling — but you
were forming a view on my overstatement, so it needs correcting.

**Where this leaves the rewrite question.** Undecided, deliberately, and now decidable. Within a few
sessions of validating against your lab forest you'd have a number — how many planted conditions the
tool finds and which it misses. That replaces a feeling with evidence, and the answer transfers
whichever way you go.

**A process note, since it happened twice in one day.** Writing this entry I deleted the heading of
the entry below it, exactly as I did when writing the first entry this morning — the same edit, the
same mistake, four hours apart. It is caught and fixed both times, but a mistake that repeats
identically is a missing guard, not carelessness: nothing checks that this file's entries each keep
a heading. That belongs with the other document guards.

---

## 2026-08-08 (later the same day) — you were right to stop me, and the answer was already written down


**What happened.** You read the entry below and said you thought we'd already settled how torn runs
are handled. I checked, and three things came out of it, in this order.

**First I agreed with you, and I was wrong to.** I found a comment in the code about not pooling
unidentified runs, decided that meant excluding damaged bundles was deliberate, and told you my
change had broken it. I reached that from a code comment and your recollection, without reading the
record. That is the same shortcut the whole review exists to stop, and being confidently wrong in
your favour is not better than being confidently wrong against you.

**Then I read the record, and it had already decided this — the other way.** Back on 30 July, when
run grouping was reworked, the deciding point was explicitly that a cancelled, failed or crashed run
**should keep its group**, because the forest name is written the instant a capture starts and
survives any abnormal ending. Losing the small file that holds a run's name was meant to cost you the
name, not the grouping. The "unknown profile" label was kept only for the *other* kind of capture the
tool used to do — and that kind no longer exists. So my change agrees with what was decided; I just
hadn't read it, and neither of us remembered it.

**Then the real answer, which is smaller than my first entry claimed.** The bug I described cannot
actually happen. The mode and the forest name are written together in the same row at the start of
every capture, so a run either has both or has neither. If the database is unreadable you get
neither, and the run correctly gets no group. There is no bundle this tool can produce that lands in
between. **The fix is still right** — the code had two different answers to one question, and one of
them named a kind of capture that doesn't exist — but nobody was ever going to hit it. I've corrected
the entry below: it was a tidy-up, not a rescue.

**And the test I wrote to prove it was fiction.** It built a run containing an `invocation.json`
file. Nothing in the product writes that file — not since long before this session — and the record
it's built from doesn't even have a place to put the mode. I deleted the test. What it was reaching
for was already covered by an older test that uses a real run.

**Which uncovered something worth having.** There are thirty-odd lines in the run library that read
that `invocation.json` file whenever the database can't supply something — a recovery path for
damaged bundles that cannot ever run, because the file is never written. It was kept last month as
"compatibility for older bundles", and the day after that was written we established there are no
older bundles: nothing has ever shipped. A comment in the code still calls that file "the first
artifact in every evidence bundle". It is not in any of them. Written up as the next thing to look
at; I have not touched it.

**The honest summary.** You caught a wrong claim in my write-up by remembering the product better
than I read it. I then produced a second wrong claim inside five minutes. What settled it was the
written record from 30 July — which is the entire argument for keeping these documents, and it only
worked because you refused the first two answers.

---

## 2026-08-08 — the Mode column is gone, and it was hiding a real bug

**Correction, written later the same day: the "real bug" was not one.** See the entry above. The
code was genuinely confused and the fix stands, but no run you could produce would have hit it. The
paragraph below overstates it, and is left as written because that is what this log is for.

**What this session was for.** Your decision from last time: delete the "Mode" column from the Run
Library, and the same word from the run summary on the home screen. Straightforward work, and it
was — but pulling on it found something that was not cosmetic at all.

**What changed on screen.** The Run Library grid now shows Run ID, Domain, Created and State. The
recent-runs list on the home screen shows the domain and the state, without the word "Security" in
front of it. Nothing else moved. The remaining columns are slightly wider, because there is one
fewer sharing the space.

**The bug it was hiding.** When the tool opens a saved run it reads the run's "mode" out of the
bundle. If it could not read it — a corrupt file, a run that was interrupted before it wrote that
part — the code was labelling the run **"Configuration"**, a kind of capture this product has not
been able to perform for months. That much was already known and had supposedly been fixed. It had
not: the fix was written at the bottom of the method and the old line at the top still won, silently,
because both still compiled.

That mattered more than a wrong label, and this is the part worth your attention. The same value
decides whether a run can be **grouped with the other runs of its forest**. So a run whose metadata
read failed was not just mislabelled — it was cut off. It could not be compared against, it could not
be made a baseline, and it appeared in the library as *"Unknown profile — capture metadata missing"*.
Nothing was wrong with the capture. One read had failed. Fixed, and there is now a test that fails if
it comes back.

**A wrong answer this session produced, and caught.** When I wrote that bug up, I recommended a
one-line fix: delete the bad line and let the good one take over. That was wrong, and I only found
out because I applied it and the test still failed. Deleting the line fixes the label and leaves the
run still cut off from its group, because the grouping check runs earlier than the good line. The
finding now records the wrong recommendation next to the right fix, rather than quietly showing only
the version that worked.

**Something similar with a test.** There was a test building a fake run marked "Configuration" — a
shape the tool cannot produce — and checking it read back. The plan was to make it honest by pairing
it with a second test. I tried that, then deliberately broke the code it was supposed to be watching,
and both tests stayed green. They could not tell the difference between *reading the value* and
*not finding it and assuming the only one that exists*. So the check came out, with a note in the
test saying why, so the next person does not "fix" it by putting the impossible value back.

**Nothing was covered.** Four things were deleted this session — a grid column, a caption, a property
and a branch — and the 4,286 existing tests did not notice any of them. That is not a complaint about
this change; it is the reason the new tests were written first and watched fail before anything was
deleted. Seven new tests, suite green at 4,293.

**Written down where it will be found.** There is now a short record saying the product shows no
capture mode because it only has one, and the data documentation says what the stored value means. If
a second kind of capture is ever wanted, that is a new decision — the code that refuses to compare
two runs of different modes was deliberately **kept**, so that day fails loudly instead of quietly
comparing things it should not.

**What is next.** The one remaining item that touches captured data: one capture step writes a
different name for its own results than its three siblings do, and two separate pieces of code
quietly paper over the difference. It is the last item on the list that could actually cost you data
in a report. After that, two small deletions and the twenty stale comments.

---

## 2026-08-07 — a list of the things that were removed and did not leave

**What this session was for.** Your diagnosis, that we keep fighting the design rather than fixing
bugs, and that the reason is old design decisions that were deleted halfway. This session did not
fix anything. It went looking for all of them and wrote the list down, because meeting them one at
a time by accident is what has been costing whole sessions.

**What was found.** Seven items, in `docs/review/S3-removed-design-residue.md`. The one that
matters to you is the **"Mode"** column in the Run Library, and the same value in the run summary
on the home screen. It looks like a per-run fact sitting next to real per-run facts, so a reader
takes it as evidence that this run was captured one way and another might not have been. There is
only one way. The tool has written the word "Security" into every run it has ever produced, and it
cannot write anything else. That was checked properly rather than assumed — every place in the code
that can write that value was traced first, because the note routing this session warned that
guessing at it is exactly what went wrong last time.

The rest are cheaper: a detail panel built fresh every time you connect to a domain controller and
then shown to nobody; a comment promising that the tool can still read files made by a program that
no longer exists; a compare warning about mismatched modes that can never appear; two pieces of
bundle information that get read but are never written; and the phrase "Config Mode" still sitting
in twenty comments across the code, six times more than we thought. One of those comments tells the
reader that a kind of capture the product cannot perform produces no findings.

**Two things that were fine, which is worth as much.** The old live/helpdesk tools were removed
properly — not one trace of them left in the code. That proves clean removal is achievable here,
which was not obvious. And an earlier prediction that the live directory browser would end up
orphaned turned out to be wrong: it is still wired up and still in use. It is now recorded as
refuted, rather than left as a note someone acts on in six months.

**What is next.** Clearing the residue, which is a repair session and was deliberately not started
here — half a list is worse than none, because the half you did not reach is what you meet by
accident later.

**You answered the one question, in this session: delete the "Mode" column.** That is written into
the finding and into the routing, so the next session starts with it already decided instead of
asking you again. While scoping it, four things turned up that change the job: one property that
looks like it needs editing has no users at all and simply goes; a second dead branch sits next to
it; the home screen caption needs its separator removed too, or it reads "· contoso.com"; and a
test builds a run in the old mode and checks it reads back, which cannot happen any more. That last
one is filed on its own, because the obvious fix — change the word to "Security" — would leave a
test that passes even if the code under it were deleted. We have now hit that same shape five
times, and it is worth naming rather than quietly fixing.

---

## 2026-08-07 — the attestation check that could never fail

**What was broken.** The product lets you exclude a domain from an audit, and then asks you to
attest that the excluded domain held nothing dangerous. It is supposed to *test* that claim against
the data it did capture, and mark the run degraded if the claim turns out to be false.

It never could. The check looked up the wrong column — the domain of the *group*, when it needed the
domain of the *member* — so the excluded domain was never something it could find, and every
attestation passed. On a real capture of the lab forest, the forest root was excluded, attested
empty, and five captured records named principals inside it, two of them Enterprise Admins and
Schema Admins. The product recorded no contradiction at all.

That fed into coverage and into whether a run could be used as a baseline. So a run that had not
looked at the domain holding the most powerful accounts in the forest reported full confidence.

**What was done.** The member's own domain is now recorded at capture time in its own column, and
the check reads that. Re-run against the same capture, the claim is now contradicted, with five
pieces of evidence behind it.

**The part worth knowing.** Two test fixtures were building data in a shape the real product cannot
produce, and both were self-consistent, so the tests passed while the check did nothing. Fixing the
fixtures *first*, before touching the product, turned five tests red — and every one of them was a
"this should have been caught" test, while every test that stayed green was a "nothing to catch"
test. That split is what a check that can only ever pass looks like from the outside.

**Still true.** The full test suite passes: 4,286 tests, 4,283 passed, 3 skipped by design, none
failed.

---

## 2026-08-07 — sorting out a backlog item that had been stuck for three sessions

**The problem.** A finding called F-01-30 listed 67 places in the code where a database error is
caught and quietly ignored. Three separate sessions picked it up and put it down again. The
instruction said "split it up by area of the codebase," and that turned out to be impossible,
because a single file contained several different kinds of problem.

**What was found.** Sorted by *meaning* instead of by location, the 67 split cleanly:

- **8 are already correct** and are finished work. They record that the query failed, separately from
  the answer being zero. They were struck off rather than queued, because leaving them in invites
  someone to "fix" what is already right.
- **18 are defending against a shape of database this product can no longer create.** Some cite
  "older databases" — there are none, the product has never shipped. Some cite a "Config Mode" that
  was deleted from the product ten days earlier. These need no decision from anyone; a rule already
  written down covers them.
- **41 are the real remainder**, and each needs its own judgement about what "no result" means.

**A mistake, recorded because it matters.** During this work I stated confidently that Config Mode
was still a real part of the product, based on finding its name in a few files. It was not — the
owner corrected me. What I had found were leftover comments and doc-strings, not working code. This
is the exact error the review's own rules warn about: finding a name is not the same as finding
behaviour.

---

## 2026-08-07 — why the same problems keep coming back

**The owner's diagnosis, and the evidence agreed with it:** these long detours are not caused by bad
design. They are caused by **design decisions that were removed but never fully cleared away.**

When a feature is deleted, the code path goes. What stays behind is the defensive code written to
handle it, the comments explaining it, and branches that can no longer run — because all of that
still compiles. And it then reads as *current knowledge* to whoever opens the file next. That is not
theoretical: it is what misled me about Config Mode, in a session specifically about being careful.

**What was added.**

- **A new standing rule (C-3):** a removal is not finished until its leftovers are gone. Leftovers
  are worse than dead code — dead code does nothing, while a stale comment actively teaches
  something false, with the authority of sitting next to working code.
- **A written record of how to drive this repository safely** — which search tools lie, which shell
  commands get mangled, how to restore a file safely after deliberately breaking it. None of this
  was written down anywhere; it was being retyped from memory every session.
- **The start-of-session instructions were cut down to four lines.** They had grown into a wall of
  text that copied the rules, the test counts and the task list out of the repository — copies that
  drift, and silently. That already happened once here, with two different test counts recorded in
  two places and nothing to reconcile them.
- **A test that checks those four lines still point at things that exist.** It found two dead
  references immediately — both in text written that same hour, by someone who knew about the
  problem. That is the clearest possible argument for having a machine check it.

**What is next.** A single session that does nothing but *list* the leftovers of every removed
feature — no fixing. The list is the deliverable, because the reason these keep costing whole
sessions is that they are met one at a time, by accident, while doing something else.

The strongest lead is a setting called `AssessmentMode`. The concept behind it was deleted, but the
name survives in 15 files and appears to only ever hold one value — which would mean a compatibility
check that can never trigger and a column in the interface that can only ever say one thing. **That
is written down as unconfirmed on purpose**, with the exact check needed, because it is the same
shape of claim I got wrong about Config Mode.

**Not next, but queued and not forgotten:** making the test data able to express Tier-0 security
policy at all (F-S2-6), which currently no test can check, and the domain-identity helper (F-S1-1)
that two other findings are waiting on — one of them a Critical.

## 2026-08-09 — a complete list of what gets rebuilt, before deciding any of it

The map describes the old product in 256 named pieces. Until today there was nothing recording what
happens to each one, so "we haven't missed anything" was a hope rather than a claim anyone could
check.

**The port ledger now exists**, at `docs/next/WHAT-THE-OLD-APP-HAD.md`, with one row per map component. The
rows were generated from the map's own headings rather than typed out, because typing 256 of
anything is how items go missing. The generator refuses to write the file unless it finds exactly
256 components and no duplicates — the same count the map states about itself.

**Almost all of it is deliberately blank.** 25 rows carry a decision: the 21 live-verification
components and one cross-cutting piece are marked Delete because a recorded decision already removed
that feature, the unused error-code enums are marked Delete, the security-descriptor parser is the
one thing marked Port, and the "is this permission dangerous" question is marked Rebuild because
there are currently five answers to it that disagree. The other 231 say `(undecided)`, which is
written out in full rather than left empty. A guessed decision is worse than no decision, because it
looks settled to whoever reads it next.

**Four tests hold the ledger to the map.** Every component has exactly one row; every row names a
real component; every row says something in the disposition column, even if what it says is "not
decided yet". The fourth test is the one that matters most and is the easiest to forget: it checks
that the reader found the map at all. Without it, the first three pass when the map cannot be read,
because an empty list matches an empty list. That is not theoretical — when the heading pattern was
deliberately broken as a check, the completeness test passed while finding nothing, and only the
fourth test caught it.

Each guard was broken on purpose and watched fail, then restored and watched pass: a row deleted, a
row duplicated, a row invented for a component that does not exist, a disposition emptied, and the
map reader pointed at nothing.

**What is next.** One ledger row, or one small group of them, per session — starting with the rows
that are already decided. The map sized every component, which is what makes a session scoped to a
single one an honest promise rather than an open-ended one.

## 2026-08-10 — the first component moves across, and the null-default gate finds its first offender

The security descriptor parser and ACE canonicaliser are the first piece of the old product to
exist in the new one. This is the piece that turns the raw bytes Active Directory stores against
each object into a list of permissions that can be compared between two runs. Without it the
product could read a directory but could not say what had changed in it, which is the question
customers actually ask.

**The tests moved first, and were watched failing.** All of them were red for the right reason —
the types they name did not exist yet — before a line of production code was written. The point of
that order is that a test written after the code it tests only proves the code does what it does.

**The golden values were copied, not recomputed.** One of the old test files holds a set of hash
constants that were computed once and written down, as a record of exactly what the old code
produced. Every one of them was carried across character for character, and every one still passes.
That is the strongest statement available that the move changed nothing: not "the new code looks
right", but "the new code produces the same bytes the old code produced". If one of them had needed
editing, that would have been a finding to stop and discuss, not a number to update.

**Three behaviours were checked rather than assumed.** A DACL that is absent grants everyone full
control; a DACL that is present and lists nothing grants nobody anything. Both hold zero
permissions and they mean opposite things, so the code keeps them apart and now says so in its
tests. A permission written as "everything" and the same permission written out in full are the
same grant, and comparing them without expanding one produces a change report on an object nobody
touched. And permissions arriving in the wrong order are ordinary rather than damage — they must
sort into the same canonical order as any others, or two identical sets of permissions would be
reported as different because of the order somebody happened to write them in.

**Gate 1 is now fully enforced, and immediately caught something.** The rule is that no parameter
may quietly default to nothing. That sounds pedantic until you see what it prevents: in the old
product, progress reporting, cancellation and the performance log were all built, all correct, and
all unused, because each was introduced as an optional parameter, every caller took the default,
and nothing ever had to say so. The guard's first run found two offences — in the very type that is
the other half of the same gate. They were mild: an optional piece of context text rather than a
missing collaborator. The defaults came out anyway. A gate whose author exempts himself on its
first day is not a gate.

Both new guards were deliberately broken and watched fail, then restored and watched pass, in each
direction: a defaulted parameter introduced and removed, the scanner pointed at a directory that
does not exist and then back, and a type name deleted from the new documentation and restored.

**Two things were written down rather than fixed.** A version number moved between projects,
because the new layering does not let the lowest layer reach the storage project it used to live
in; the value is unchanged, so nothing recomputes. And the fingerprint each permission carries does
not include whether it allows or denies. That is harmless as the code stands, and would not be if
anything later treated that fingerprint as a permission's identity, so it is recorded as an open
question to answer before anything does.

**What is next.** The next ledger row, or the next small group of them. K15 is finished in the
sense the ledger means: code, documentation, and a test binding the two.

## 2026-08-10 (later) — a correction: the thing I called harmless is not

The entry above says the fingerprint each permission carries leaves out whether it allows or
denies, and that this is harmless as the code stands. **That was wrong, and it is worth saying why
it was wrong as much as what the truth is.**

It was wrong because I reached that conclusion by reading the code instead of running it. Checking
took ten minutes and contradicted it immediately. Two permissions that differ only in whether they
allow or deny are recorded as one — the second is silently discarded. And a second case is more
likely than that one: Active Directory permits a permission to be written in a form that carries no
extra detail, and in that form it is indistinguishable from the ordinary kind in every field the
fingerprint covers. Those two also collapse into one, and **which of them survives depends on the
order they happened to arrive in.**

That last part is the serious one. The whole purpose of this step is to put permissions into a
settled, comparable form, so that the same set of permissions always looks the same however it was
written down. It does not currently do that. Two objects with identical permissions can produce
different records.

Microsoft's own documentation settles it: every permission entry is defined by four things, and
whether it allows or denies is one of the four. We were fingerprinting three of them.

Nothing is broken for a customer today, because nothing has been captured or stored with the new
code yet. That is also why this is the cheapest moment it will ever be to fix. The fix needs one
decision from me first, which is recorded as an open question rather than made quietly: correcting
it changes every fingerprint the code produces, which means the frozen values copied across from
the old implementation have to be recomputed. Those values did their job - they proved the move
changed nothing - but they cannot prove it a second time once they are recomputed, and the old
implementation is going away.

**The lesson worth keeping.** The "verified-safe" section of a review exists so nobody re-checks
what has already been checked. I put a claim in that section that I had reasoned about rather than
tested. That is the one section where doing so is most expensive, because it is the section people
trust. The claim has been withdrawn in place rather than deleted, so the next reader sees that it
was checked, and got the wrong answer, and why.

## 2026-08-10 (later still) — the fix, and how the frozen values were replaced without cheating

The defect described in the correction above is fixed. Whether a permission allows or denies is now
part of its fingerprint, and it is also the final tiebreak when two permissions would otherwise sort
identically. Both halves were needed: the first stops two different permissions being recorded as
one, the second stops the order they arrived in deciding which one survives.

**The interesting part is the frozen values, and it is worth explaining because the obvious approach
would have been worthless.** Those eight values pin the exact output of this step. Changing the
fingerprint necessarily changed all of them. The tempting move is to run the new code, see what it
prints, and paste that in - after which the test asserts that the code does what the code does, which
is no test at all.

So they were computed a second way instead. The recipe for the fingerprint is written down: a list of
fields joined in a fixed order, encoded a particular way, hashed. I implemented that recipe
separately, in a different language, without reference to the product code. **Then, before trusting
it, I pointed it at the old recipe and checked whether it reproduced the eight original values. It
reproduced all eight.** That is what makes it evidence rather than a second guess: an implementation
that can reproduce known-correct answers is implementing the recipe correctly, so the answers it
gives for the new recipe can be relied on.

The new values went in first, and the code was run against them afterwards. It agreed on all eight.
The test now checks the product against the written specification rather than against its own
output, which is a stronger arrangement than what it replaced.

**What we gave up, stated plainly.** The old values proved the move from the old codebase had changed
nothing. They did that, it held, and it is recorded. They cannot prove it a second time. That is not
evidence destroyed - it is a property we deliberately stopped wanting, because we decided the old
behaviour was wrong. The old code and its own frozen values are still in the repository and still
pass, untouched.

Every change was broken on purpose and watched fail: remove the fingerprint field and both collisions
come back; remove the tiebreak and the order flips. Restored, all pass.

**One small thing worth noticing.** The test that ties the written documentation to the code caught
that the document still said version 1 while the code said version 2. Nobody had to remember; the
build said so. That is the whole argument for binding documents with tests, demonstrated on the
document it was written for, three days after it was written.

## 2026-08-10 (fourth) — the dead-code alarm had no sensor in it

Six of the automatic checks in this rebuild exist because the old codebase went wrong the same way
more than once. The fifth of them is meant to stop the product accumulating parts that nothing uses.
That is not housekeeping: the old SecureAD carries **six screens no user can reach and twenty-eight
buttons wired to nothing**. Each was built for a reason, each stopped being connected, and nobody
noticed because nothing was watching. For a tool people make security decisions on, a screen that
looks like it reports something and reports nothing is worse than no screen at all.

**The check, as written down, would have passed while measuring nothing.** It asked whether anything
else in the code mentioned each piece. Every one of the fourteen pieces built so far passes that —
because they all mention each other. The clearest case: the security-descriptor reader is the front
door of everything built this week, and in the entire product it is mentioned exactly once, inside a
comment. Comments are notes for people. They do not run.

That is worse than having no check. A missing check is honestly missing. One that always says yes
looks like protection. A smoke alarm that beeps to tell you it is working, with no sensor inside.

**The right question turned out to be a different one.** Not "does anything mention this" — the six
unreachable screens mention plenty, and mention each other — but "can anything that actually runs
get to this". That is a different measurement, and it is the one that would have caught them.

**And it cannot be made yet, for an honest reason.** That measurement has to start somewhere: at the
part of the program that runs, following the trail of what calls what. The rebuild has no such part
yet. There is nowhere to start the trail. So the check is now split in two, and both halves are
written down: the half that can be enforced today, and the half that waits, with the specific piece
of work that will unblock it named rather than left as "later".

**The half that landed today** is a register listing all fourteen public pieces, each naming the
future piece of work expected to be its first user. Five checks hold it: nothing missing, nothing
listed that does not exist, every named piece of work real, the register readable at all, and — the
one that matters — an entry cannot outlive the work it is waiting for. Once that work is done, either
the piece is used and the entry goes, or it is not and that is exactly the dead weight this exists to
find.

Fourteen entries today. It will never be smaller. That is the whole argument for doing it now rather
than when there are sixty and someone signs off the list without reading it.

Each check was broken on purpose and watched fail, then restored: an entry pointed at finished work,
an entry pointed at work that does not exist, an entry renamed, and the reader blinded so it found
nothing at all.

**A note on how this session went, which matters more than the check.** Partway through I drifted
into talking to the owner as though he were a developer — unexplained jargon, and then asking him to
settle a technical trade-off about test tooling that was mine to settle. He is a security and Active
Directory administrator. He knows what this product must do; he is relying on me to build it. That is
now written at the top of the repository's instructions, so it is the first thing every future
session reads rather than something that has to be noticed again.

## 2026-08-10 — the most-used piece of the old product moves across, and its documentation guard was broken on the first try

Today's piece is the one that reads Active Directory names. Every object in a directory has a full
name that spells out where it sits — the person, the folder they are in, the domain that folder is
in — and the product needs three things from it constantly: what is this thing called, what contains
it, and which domain is it in.

**This is the most-used single file in the old product.** Thirty-four other files call into it —
the capture code, the storage code, the analysis, and eighteen different screens. Nothing else in
the product comes close.

**Why it is worth a piece of its own rather than a line of code repeated in thirty-four places.**
The parts of a directory name are separated by commas, but a name can also *contain* a comma —
"Smith, John" is how a great many directories write a person's name by default. The real separator
and the comma inside the name look identical unless you know to look. Split on every comma and you
get a person called "Smith" living in a folder that does not exist. Thirty-four copies of that logic
would be thirty-four chances to get it wrong, in thirty-four different ways.

**The decision I had to make.** The old code sat in the folder belonging to the feature that
happened to need it first, back in 2025 — even though thirty-three of its thirty-four users are
nothing to do with that feature. I moved it to the shared foundation where the rebuild already says
names belong. The behaviour was not touched. This was a "move it, do not redesign it" job, and I
kept to that.

**Four things about directory names I was asked to check the old tests covered.** Escaped commas —
yes, well covered, and I extended it. Case — no, never tested, though the code handles it; now
tested. Names written with quotes instead of escaping — no, and the code does not handle them at
all. Re-pointing a name from one domain to another — no, and there is no such code anywhere in the
product, despite the map saying there is.

The last two are gaps in the product, not gaps in the tests, so they are written down as findings
rather than quietly fixed under a job that was supposed to be a move. I also found that comparing
two directory names has no home: four different places in the old product each wrote their own
comparison, and one of them can say an object lives inside a folder that is not a folder. That is
filed as the important one, because deciding which folder an object is in is most of what an audit
tool does.

**The part worth recording.** Every document in the rebuild has to be held to the code by a check,
so it cannot quietly go stale. I wrote that check, then deliberately broke the document to watch the
check complain — and it did not. The check was looking for the name anywhere in the text, so a
renamed thing still matched, because the new name contained the old one. It would have sat there
looking like protection and protecting nothing.

That is the same failure as the dead-code alarm two sessions ago: a check that always says yes is
worse than no check, because a missing check is visibly missing. Fixed, broken again in both
directions, and watched to fail both times. A test now holds the fix in place so the weakness cannot
come back unnoticed.

The whole rebuild suite is at 178 checks, all passing.

## 2026-08-10 (later) — two lists of the same facts become one, and the danger flag is handed on

The product has to translate. When Active Directory records that somebody may change something, it
writes down a long meaningless code rather than a name. `bf967a68-0de6-11d0-a285-00aa003049e2` is
the setting that controls whether an account needs a password at all. Without a lookup list, the
tool can only tell a customer that someone has permission over *something*, which is not a report
anybody can act on.

The old product kept **two** such lists. Two folders, two formats, two sets of category names, and
only one file in the whole product ever looked at both. They covered overlapping but different
ground, and each carried notes about entries that had once pointed at the wrong thing and been
corrected. Two lists of the same facts means two places to be wrong and two places to fix, and the
notes show that had already happened in both.

They are now one list, and it answers questions in both directions.

**This was not just tidying.** The two attributes where Windows stores local administrator passwords
were in one list and missing from the other, and one of the product's rules is about who can read
exactly those. Nothing was reported wrongly, because that rule reads the values from its own query,
but "does the tool know about this?" genuinely had two answers, and one of them was no.

**The decision I had to make, and why.** The old list also carried a flag saying whether each entry
was dangerous. I did not carry that across, and it is worth saying plainly why, because it moves
work rather than removing it.

What a code *means* is a fact about Active Directory. It is true whether or not this product exists,
it is the same for every customer, and anyone can check it against Microsoft's published reference
one line at a time. That belongs in a list.

Whether a permission is *dangerous* is this product's own judgement. It is the thing a customer acts
on, and it depends on more than the code: the same attribute read is harmless and written is not.
There is already a job on the list for that judgement, and it exists precisely because the old
product answered "is this dangerous?" in **five** different places that did not agree with each
other. Putting a sixth answer into a lookup table would have made that worse.

So the nine entries the old list called dangerous are written down in the new document, by name, as
an explicit handover to that job, rather than being silently dropped. Two of them are things the
next session should settle rather than inherit: one replication permission the old list left
unflagged although its two siblings are flagged, and two settings that let an attacker run code on
every machine in scope, which one of the five old answers called dangerous and the list called safe.

**One thing the old list did that the new one refuses to.** Some codes mean more than one thing. The
same code is both "may add yourself to this group" and "the group membership itself", and which one
applies is decided elsewhere. Both old lists picked whichever entry happened to be written down
first and said nothing about the other, which is answering a question nobody asked. The new list
hands back everything the code can mean and lets the caller that actually knows decide.

**And one hazard removed.** The old list could be changed while the program was running: reading the
directory's own schema merged extra entries into it, so the same question could get different
answers depending on what had happened earlier in that session, and there was no way to get back to
the answer the product shipped with. For a tool whose entire value is that two runs can be compared,
that is a serious problem. The new one cannot be changed once built. Not by policy, but because
there is nothing to call.

**The part worth recording.** I broke the new documentation check on purpose, three ways, to make
sure it complains. Two of the three worked first time. The third did not: I deleted a member from
the document's table and the check stayed happy, because the *record of me deleting it* mentioned
the name, and the check was looking for the name anywhere in the document rather than in the table
that explains it. That is a milder version of last session's problem, and the honest thing was to
write the weakness down in the document rather than quietly pick a mutation that worked. The check
does catch the failure that actually happens, a member the document does not mention at all, and I
proved that separately.

The whole rebuild suite is at 245 checks, all passing.

## 2026-08-10 (third) — a conversation about GUIDs found a hole in the product, and a decision record that hid it

This session wrote no new capability. It wrote down five things that were only in a conversation,
and one of them is a genuine hole in what the product can see.

**The hole.** Active Directory writes permissions down as long meaningless codes. Some of those
codes are the same in every organisation and can be shipped in a table — that is what the previous
session built. But every real network also has codes that exist only in *that* network: attributes
added by Exchange, by a management tool, or by somebody in 2014. The only way to learn those is to
ask the directory for its own dictionary.

The old product did ask — but only if the operator happened to click into a live browsing screen
first. And that screen is being deleted.

Worse, the decision record that deletes it says, in plain words, that the capture covers this.
It does not. Nothing covers it. I checked every file that reads the directory's dictionary and
there is exactly one, inside the screen being removed.

**Why that matters to a customer.** The component that works out who controls what recognises nine
codes, hardcoded in its own file. A permission over a code it does not recognise produces nothing
at all — not "checked and found harmless", but never examined. So in any network with add-on
products installed, which is all of them, there is a category of permission the report is silent
about, and nothing says so.

The fix is cheap and the owner spotted it before I did: read the dictionary during the capture.
Two queries, a few thousand entries, a cost that does not grow with the size of the network, no
special permissions. It is now written down as a decision with a row that owns it, rather than an
assumption in a record that was wrong.

**A bonus that came free.** The same queries also return the friendly wording — "Reset Password"
rather than the schema's formal name. Last session I left those out on the grounds that display
text does not belong beside behavioural data. That was half right and reached the wrong answer: the
person reading an audit report knows the wording from the Windows dialogs, and a report speaking a
vocabulary the reader does not share is a report that does not land. The resolution is that nobody
has to invent the wording, because the directory already holds it. Recorded as a correction rather
than quietly changed.

**Two decisions the owner made.**

The first is about honesty in labelling. The product can recognise a set of permissions as a named
pattern — "Reset user passwords", "Join a computer to the domain" — the way the delegation wizard
does in reverse. The rule now written down is that **naming a pattern never excuses it.** A
dangerous permission inside a recognised delegation is exactly as dangerous as outside one. That
sounds obvious and is precisely the kind of thing that erodes quietly when somebody later argues
that a *known* delegation surely does not need flagging.

The second is what to do about patterns the product does not recognise, which in a real network is
most of them. The obvious answer is to let customers define their own. We talked it through and
rejected it: building that editor means asking an administrator to describe permissions in terms
most would not want to learn, and when their definition fails to match, nothing tells them why.

The better answer inverts it. Rather than asking people to describe what to look for, show them what
was found — *this exact set of four permissions appears on forty organisational units* — and let
them put a name on it. No editor, no failure to match, and it starts from their own network.

The part I like most is what looks like a weakness. Because the grouping is exact, one container
with one extra permission falls out of the group and is reported as a variant. That is the finding
an auditor actually wants — the one place where somebody added something to the standard and nobody
noticed — and a cleverer, more tolerant matcher would have swallowed it silently.

**On the single-source question.** The old product wrote these codes down in five separate files.
One component declared nine of its own while a ninety-three entry table already existed a folder
away. That is not carelessness; it is what happens when a correct table exists and nothing obliges
anyone to use it. So there is now a build failure: a code written anywhere in the new product except
the one table breaks the build. Tests are exempt, deliberately and on the record, because a test
that asks the table what it thinks is checking the table against itself.

**The part worth recording.** I broke that new guard three ways to be sure it complains. The third
attempt is the interesting one: I blinded it, so it was looking at nothing at all. The main check
**passed** — an empty tree contains no violations. Two companion checks failed and named the
problem.

That is the exact failure this project has hit twice before: a check that says "all clear" while
measuring nothing. It is the reason every guard here carries a self-test, and it is satisfying to
watch the arrangement work as designed rather than having to trust it.

The whole rebuild suite is at 251 checks, all passing.

## 2026-08-10 (fourth) — six answers to "is this dangerous" become one, and the word "safe" stops being the default

The product had six different definitions of a dangerous permission. Two of them were the live and
stored effective-access screens — the two panels a customer opens side by side precisely to compare
them. They disagreed about `gPLink`, `scriptPath` and `userAccountControl`. So the feature was to
compare two answers, and the two answers were computed by different rules.

There is one now, in the kernel, and it reads both halves of the question: the access mask (what
kind of thing may be done) and the GUID (what it may be done to). Neither answers alone, which is
why the old bitmask classifier missed DCSync entirely and the old per-GUID flag could not tell
reading an attribute from writing it.

**The part that matters most is what it says when it does not know.** The old classifier returned
yes or no, and a permission carrying a GUID it did not recognise came back as *no*. Not "I have not
looked at this" — *no*. A screen printing that is telling an administrator a permission is safe on
the strength of never having examined it, which is the one thing an audit tool must not do. The new
verdict has four states and one of them is "not assessed", and it can never be rendered as safe.

A fourth state was also needed for an honest reason. Replication rights are dangerous as a *set* —
two of them together read every password in the domain — and a classifier looking at one permission
at a time cannot see a set. Calling either one safe would be false and calling it dangerous would be
over-claiming, so it says "this is a component of something, and the thing that looks at whole
principals decides". That half does not exist yet, and it is written down as owed rather than
quietly skipped.

Nine right names were handed over from last session with a warning not to lose them. All nine
landed, and the test that checks it does not merely search the document for the words — it runs the
classifier over each name and fails if any comes back unclassified. I proved that by deleting one
from the code: the document still said the right thing and the check failed anyway, which is the
whole point.

**One thing needs your decision, and it is in the write-up.** Should writing `gPLink` or
`scriptPath` count as dangerous? Whoever can write a logon script chooses what program runs as that
user. Whoever can write a policy link can also *unlink* a hardening policy — which needs no other
privilege, leaves nothing visibly wrong, and simply stops the policy applying. I have recommended
yes and built it that way, because the alternative is reporting a real code-execution path as safe.
The cost is noise in environments that delegate organizational units properly. Say the word and it
changes.

Two things were found and neither is mine to settle: the two DCSync rule specifications still
contradict each other, and one architectural guard turned out to be unable to express "this is used
now" the first time anything actually got used. Both are recorded with the reasoning.

The rebuild suite is at 322 checks, all passing.

## 2026-08-10 — the build now refuses a second answer to a question that already has one

The recurring defect in the old product was the same question answered several times, differently.
It is not an abstract worry: two of the five pieces rebuilt so far were instances of it. There were
two hand-maintained tables of the same Active Directory facts, in different folders, neither aware
of the other, both carrying corrections for entries that had been wrong. And there were six separate
answers to "is this permission dangerous" — two of which drove the live and the stored
effective-access screens, the two screens a customer opens precisely so he can compare them against
each other. They disagreed.

Both were found by a person reading carefully. There are 251 pieces left to rebuild, and reading
carefully does not scale to that. So from today the seventh duplicate fails the build.

There is now a short document listing seven **concepts** — a concept is just a question the product
has to answer, like *what does this GUID mean* or *is this permission dangerous* — and, beside each,
the one type allowed to answer it. If any other type grows a member that answers the same question,
the build stops. It is written as a table anybody can read rather than as code, because the useful
column is the one saying, in sentences, what went wrong without an owner.

The part that decides whether this is worth anything is what counts as "the same question". Too
loose and it fires on everything and gets switched off; too tight and it misses the case it exists
for. So it is not argued, it is tested: the check is run against the member names the *old*
duplicate code actually used, and if the rule is ever narrowed until it would no longer have caught
the original defect, the build fails. A gate that would not have caught the thing it was built for
has not been shown to work.

**It found a fault in itself, which is the reason I trust it more than I would a clean run.** While
deliberately breaking things to prove the check can fail, an editing accident chopped a row of the
table in half. Every check went on reporting the registry in perfect order, because a damaged row
was quietly skipped. That is the worst kind of failure — a check that says yes while measuring
nothing — and it is exactly what a previous guard here did. A malformed row now fails the build.

Two smaller things went in with it. A caveat that had no owner — deciding whether a *person* is
dangerous from the whole set of permissions they hold, which a check on one permission at a time
cannot do — has been written into the piece of work that will have to answer it, and a test now
keeps it there. A caveat that lives only in a write-up has already been lost once here. And the
status line saying one component had been ported said one when it was five.

Nothing a customer can see moved this session. This is the sort of work that is cheap now and
impossible later: the equivalent guard for dead screens could not be retrofitted onto the old
codebase at all, which is why that one still carries six screens nobody can reach.

The rebuild suite is at 359 checks, all passing.

## 2026-08-10 (later) — the build now refuses an answer that cannot say whether anyone looked

There is one mistake this product is not allowed to make. If a screen says *no dangerous permissions
found* when the truth was *that check never ran*, a customer reads a clean bill of health and leaves
a way into his directory open. He has no way to tell the difference, because both answers arrive as
the same thing: zero, or an empty grid.

This is not a worry about something that might happen. The old product did it. Four places in it
counted things by running a database query and, if the query failed, quietly answering nought. Those
numbers printed at the top of the exported forest report, directly underneath a banner warning that
sections might be missing — and a precise number beats a vague warning every time. Worse, a report
is the thing most likely to be emailed onward to somebody who never saw the banner at all.

The build now refuses two shapes of that mistake. A method whose name promises a count may not hand
back a plain number, and a method may not hand back a list unless whatever it came from also says
whether it managed to look. The way out is already in the code: three pieces of the rebuild carry
their errors, or a verdict, alongside the answer, so an empty list sitting next to a filled-in error
list is visibly not an empty directory.

**The hard part was deciding where the line falls, and it is the reason this could have been
worthless.** Not every number is a count. One method here returns a number that is a Windows
permission bit-pattern; forbidding it would be nonsense, and a rule that complained about every
number in the codebase would have been switched off within a week. A rule tightened until it
complains about nothing was never a check at all. So the rule is not argued, it is tested: it is run
against the names the *old* broken methods actually had, and if anybody ever narrows it until it
would no longer have caught those, the build fails.

The same test was applied to the check itself, in both directions. Ten deliberate breakages were
made and each one was confirmed to have actually landed in the file before its result was believed —
a habit that exists because a breakage that silently failed to apply has twice produced a false
all-clear here. Two of the ten matter more than the rest: they are the two ways this check could have
been turned into something that says yes while looking at nothing, which is the worst failure
available. Both now fail the build.

One exception was needed. The catalogue of Active Directory identifiers is a table compiled into the
product; it opens nothing and cannot fail, so an empty answer from it means one thing only. That
exception is written down with the thing that ends it: the moment the catalogue can be loaded from a
live forest — which a decision already on the books says is coming — an empty answer starts meaning
two things again, and the build will fail rather than let the exception quietly become permanent.

Nothing already finished had to be reopened. With the exception switched off, the check finds
exactly the two catalogue methods and nothing else in the five completed pieces of work, so there
was no trade-off to bring back about fixing something now against leaving it.

Two limits are written down rather than papered over. A yes/no answer can lie the same way a zero
can — *false* can mean "no" or "never ran" — but there is no way to tell those apart from the
outside, and a rule over every yes/no in the codebase would complain about all of them. And a count
produced by a database query rather than by code is out of reach, which is exactly the route the
original defect took. Both are recorded with what would have to change to close them.

Nothing a customer can see moved this session.

The rebuild suite is at 414 checks, all passing.

## 2026-08-10 (third) — what the audit is allowed to see was decided before anything was built to see it

No code this session. The twelve components that make up the first half of capture — the part that
reads a forest — had no decision recorded against any of them, and that was blocking every session
that might have started one. They now have one each, with the reasoning written down and a check
that fails the build if the reasoning and the plan ever disagree.

Eleven of the twelve are rebuilt rather than moved across. One is deliberately put off.

The one put off is running several domains at once. The old product did this, and the machinery it
needed is larger than it sounds: a separate database file per domain, a hand-kept list of which
tables go in those files, a merge step to fold them back together, a test whose only job is to
notice when that hand-kept list drifts, and a coverage figure that has to be written twice because
the first one is wrong by construction. Five moving parts, none of which changes a single number in
a customer's report, all of which have to work before the product can read a forest at all. The only
thing that justifies them is a speed measurement, and nobody in the rebuild has taken one. So
capture is built to read one domain at a time, and the question comes back the moment there is
something to measure — which is a deliberate bet that the wait is cheaper than the machinery, and
the bet is written down with what it costs if it is wrong.

The most useful thing found this session came from Microsoft's own documentation rather than from
our code. When you ask a domain controller for everything under a domain, it does not just answer —
it also hands back pointers to the child domains and to two other parts of the directory, expecting
you to follow them. Combined with the technique used to read large results a page at a time, this is
documented as broken: the client loses its place, and the search stops after the first page without
reporting an error. Applied to this product that would mean capturing a thousand objects out of nine
million and presenting the result as a completed audit of the forest. There is no fix, only ways to
avoid it, and the avoidance is now a written property of how a search is issued rather than
something an implementer might or might not know.

Four of the twelve were not decided quietly, because they are not really technical, and each is put
back to the owner with a recommendation and the cost of going either way.

The first is what the product reads out of the directory at all. Whatever is not read is not in the
evidence, is not in the report, and cannot be added later without going back to the forest. A
customer cannot tell the difference between "this is not a risk in your forest" and "we never looked
at that". The recommendation is to keep the deliberate, named list the old product had, add the two
parts of the directory it never read — which is why a permission granted over anything unusual
currently produces no finding at all rather than an unknown one — and make the list answerable in
both directions, so an attribute nothing uses and a rule needing something nobody captured both fail
the build. It is not free: some attributes are readable only by administrators and come back missing
rather than refused, which the product then has to tell apart from genuinely empty.

The second is letting a customer exclude part of their directory. The recommendation is to keep it
and change what it means. An exclusion is a hole in the evidence and must appear in the report as
loudly as a finding. Two smaller things go with that. The product already refuses to let anyone
exclude one container that hides service accounts, and it refuses silently — so an administrator who
asked believes he succeeded. And an exclusion is never watertight anyway, because a group outside it
can hold members inside it, so the report must not claim otherwise.

The third and fourth are the domain-at-a-time questions above.

Two things are recorded as still open rather than answered. What the product says when it cannot put
a name to something is asked in three separate places now, by three separate decisions, and all
three deserve the same answer before any of them ships. And whether inherited permissions are stored
or recomputed later is now a free choice for the first time, because the file format no longer has
to satisfy the old application.

Nothing a customer can see moved this session.

The rebuild suite is at 438 checks, all passing.

## 2026-08-10 (fourth) — going through the capture decisions one at a time removed a feature

Working through the twelve decisions with the owner rather than presenting them finished. Two of the
four questions are now answered, and the second one ended somewhere neither of us expected.

The first was what the product reads out of the directory. Confirmed as recommended, with two
additions that came out of the conversation rather than the analysis. The container that holds the
directory's own list of special permissions turns out to hold three different kinds of thing, not
one — the special operations, the named bundles of attributes, and the checked writes — so reading
it is not a feature about one of them, it is how two thirds of the permissions in a forest get a
meaning at all. And a second, unglamorous item was added to the list of things capture reads: the
link from each attribute back to the bundle it belongs to. Without it the product can say a
permission grants "write account restrictions" and cannot say what that actually reaches.

Which turned up something worth chasing. The delegation every organisation performs — letting the
helpdesk reset passwords — appears to grant write access to a bundle of attributes that includes two
the product itself classifies as dangerous, one of them the basis of a well-known takeover
technique. The bundle's contents are confirmed from Microsoft. That the standard delegation grants
the bundle rather than the single attribute is not, and rests only on the old product's own code, so
it is filed as suspected and goes on the checklist for the lab session that has to happen anyway.
This is the same mistake pattern a decision record was written about three days ago: a plausible
mechanism with a confirmed premise, believed because it fits.

The second question was whether to keep letting a customer exclude part of their directory from the
audit. It started as "keep it and make it loud" and finished as "remove it", because every argument
for making it loud turned out to be an argument for not having it.

An exclusion does not remove a region of risk from the report. It removes the names and the
arithmetic and leaves the risk. A dangerous permission held by someone inside the excluded area
still shows up — on the object they have power over — but the holder is a number nobody can resolve.
Counts of how far a permission reaches are quietly short by exactly the size of the exclusion. And
the one thing genuinely hidden is who controls the excluded container, which is the first thing an
auditor would ask.

The owner's own account of where the feature came from is what settled it. A customer had an
enormous container kept for legal reasons which, when reviewed at the time, held nothing of security
relevance. That was a fair judgement. It is also a judgement about a container on a date, and
nothing re-made it as the years passed and things accumulated inside.

Two facts made removal safe rather than merely principled. Capture is the cheap half of a run — it
reads a thousand objects per request and finishes in minutes; the analysis afterwards is what takes
the time. And a filter can be added back in a few lines later, whereas evidence never gathered
cannot be recovered, so removal is the direction that can be undone.

What replaces it is a filter on reading rather than on gathering. The customer runs the audit, sees
the result, and the product offers — from their own data — the containers that held many objects and
no risk. Ticking one drops it from the screens and from the exported document immediately, and
unticking it puts it back, with no need to go near the directory again. Two things are different
from before: a figure that has been filtered says so, and a route that passes *through* the filtered
area to reach something the customer does care about is still found and still reported. Under the
old design that route did not exist to be found.

The signed file is never filtered. Otherwise ticking a box would produce an artefact carrying this
product's name that is clean by omission, which is the thing two earlier decisions already refuse in
other forms. A customer who forwards that file to their insurer is forwarding everything, and the
product should say so rather than let it be discovered.

This is written down as its own decision record, because it is a position about what the product is
for and not a note about a component.

The honest cost is that runs now do work they used to skip, and nobody has measured how much. It
lands in the same place as the deferred question about capture concurrency, and one measurement
settles both. The filtering itself saves no time at all: the route-through case means the analysis
has to be complete regardless. It buys a report someone will read.

One check was found to be weaker than it claimed, by breaking it accidentally. A row of the ledger
lost two of its seven columns during testing, including the one recording what documentation the row
owes before it can be called finished — and every existing test still passed, because they each read
one specific column and a shortened row still has those. Repaired the same day: rows must now carry
every column, and the expected columns are checked against the table's own heading so the two cannot
drift apart. Both directions were deliberately broken to confirm the new check notices.

Nothing a customer can see moved this session.

The rebuild suite is at 440 checks, all passing.

## 2026-08-11 — checking two decisions that were already written down, and finding a trap in one

Two more capture decisions were due: what one unit of reading the directory is, and whether to build
the machinery that reads several parts of the forest at once. Both already had a provisional answer
written down. The job was to test them rather than agree with them, because the last session did the
same thing to a third decision and the provisional answer turned out to be wrong.

Both answers held. Neither held for the reasons written down.

The first one is about a real trap in how Windows Active Directory answers a large query. When the
product asks a domain controller for everything in a domain, the controller answers a thousand
objects at a time and hands back a bookmark so the next thousand can be asked for. It also mentions
the other parts of the forest — child domains, the two forest-wide partitions, the DNS data. If the
product follows those mentions, and it does so by default, the bookmark gets overwritten. The product
then believes it has reached the end. Microsoft's own article on this says there is no fix, only ways
to avoid it. The consequence, if it were left unavoided, is a report that describes a thousand
objects out of nine million and says nothing went wrong. That is the one thing an audit tool cannot
do, so this is a correctness decision rather than a speed one.

The decision is that the product reads one partition of the directory at a time, deliberately, and
follows nothing. That happens to be the same thing an earlier decision already required for a
different reason, which is what makes it the right avoidance rather than merely an acceptable one.

What was new this session is the avoidance that was refused. Microsoft lists searching the global
catalog as an alternative — one server, no mentions to follow, the whole forest in one pass. It looks
much cheaper and it is silently wrong. The global catalog holds every object but only some of each
object's information; if you ask it about information it does not hold, it does not say so, it
answers as though the answer were no. One of the pieces the product needs — the one that says which
group of properties a permission is really granting, added by the previous session — is specifically
not held there, and the DNS parts of the forest are not held there at all. Meanwhile the permission
itself is held there, so the first thing anyone would check to see whether this route works comes
back looking fine. This is now written into the decision, because someone looking for a faster
capture in a year will find the same article and the same suggestion.

A smaller thing came out of it. Even when the product follows nothing, the controller still mentions
the other parts of the forest. The old design would have thrown those away. They are better than
that — together they are the controller's own account of what else exists, so the product now checks
them against the list of partitions it planned to read, and anything unexpected becomes a stated gap
in coverage rather than silence.

The second decision, about reading several parts of the forest at once, stays deferred. The reason
changed, and improved. It was deferred because nobody has measured the benefit, which is a one-sided
argument. There is also a documented cost: a domain controller keeps the bookmarks for large queries
in one shared pot, and when that pot is full it quietly throws away the oldest one. Several
simultaneous large queries against one controller compete for it, and losing a bookmark without being
told is the same failure as the trap above, reached from the other end. So doing several at once is
not free speed. That matters most for the two forest-wide partitions, which exist on every
controller and so cannot be spread around the way domains can.

The condition for revisiting it is now stated precisely enough to be checked: one measurement, taken
on a real customer or pilot forest of the size this product exists for, comparing how long reading
the directory takes against how long analysing it takes. It only revisits if reading is the larger
of the two and a single-threaded read misses the customer's maintenance window. A measurement taken
in the lab does not count, and an earlier decision already says why. The same measurement also settles
something the previous session left owing: removing the option to skip parts of the forest means every
run now reads more than it used to, and nobody has priced that. One run answers both.

Five findings were recorded, and one machine-checked cross-reference was updated so the ledger and the
capture document cannot disagree about these two rows. No product code was written.

Nothing a customer can see moved this session.

## 2026-08-11 (later) — the owner asked whether I had read the old documentation, and the answer was no

The two decisions above were finished. What followed was the owner asking questions about them, and
each question turning up something the decisions had assumed rather than checked. Six more decisions
came out of it. No product code was written in any of it.

**The first question was about DNS, and I got it wrong twice.** I had recorded that the DNS portions
of the directory were deliberately left out for good reasons. Checking properly, the reasons were
real but they were not the reason — the omission had simply fallen out of where the search started,
and nobody had decided it. Then I checked again and found something worse: the product does not
examine DNS permissions *anywhere*. What it has instead is four separate pieces of code whose only
job is to hide the DNS objects that arrive by accident when an operator picks the advanced capture
mode. So the position was never "we assess DNS partially" — it was "we assess no DNS at all, and we
clean up after the DNS data we accidentally collect."

The owner decided the scope: the DNS zones, records and containers stay out; the two DNS
administrative groups stay in, because those are ordinary groups the product already reads and
assessing them needs no new collection at all. The report has to say precisely which of the two it
means. Adding DNS zone permissions later was checked and costs only historical coverage — the work
itself is additive and nothing being designed now gets in its way.

**Then the DNS groups turned out to be invisible for a structural reason.** Every way the product
decides "is this a privileged target" relies on a fixed numeric identifier, or on the group being
inside another privileged group. The DNS administrators group has neither: its identifier is handed
out from the domain's ordinary pool when the DNS role is installed, so it is different in every
forest, and it is not a member of anything. So a permission letting an ordinary account add itself
to a group that has full control of all DNS records is not reported, and cannot be until the
definition of "privileged" admits something other than a number. The evidence is already in every
bundle, which is what makes this safe to leave as future work.

**The owner settled what happens when a domain controller is lost mid-capture.** The run ends. No
switching to another controller, no retry, no asking the operator — detect it, stop, and say which
controller failed and what it did, because an unresponsive controller is something the organisation
needs to know about. I spent some time designing a fallback scheme before the owner pointed out that
domain controllers do not vanish at random and organisations know their own maintenance windows.
That was right and the scheme was dropped.

What survived from it is the harder half. A controller going away is the *easy* case to detect. The
dangerous cases are the ones where the controller stays up, stays polite, and hands back less than
everything — a search that hits the server's two-minute limit, a bookmark discarded under load, a
large group truncated. Those produce a report that looks complete. So the check cannot be "did
anything go wrong"; it has to be "did the directory tell me I had reached the end." Checking the old
code, one of those three is already handled properly and carefully.

**The load control does nothing.** The product offers three capture speeds, labelled by their effect
on production. Underneath is a rate limiter, and it is correctly built and correctly connected —
there is no bug in it. It simply cannot ever engage, because the product asks for one page of
results and waits for it before asking for the next, so it is already ten to sixty times slower than
its own speed limit. The owner's measurement of a real nine-domain forest confirms the scale. So an
operator picks between Safe, Balanced and Fast, and no domain controller anywhere experiences any
difference. That is worse than having no setting, because it reads as a lever over production impact
and is not one. It is removed, along with the three presets.

Removing it transfers an obligation, and that is recorded. The pacing that makes it safe is an
accident of how the code is written rather than a stated rule. With the limiter gone, someone later
making capture faster by fetching pages in parallel would multiply the load on a customer's
production controller with nothing to stop them. That constraint now has to be written down and
enforced by the build.

**One more control turned out to be live and harmful rather than dead.** The choice between the two
capture modes is a real screen, on the main path, two steps into the audit wizard. But the settings
panel reads nine capture settings in and writes exactly one back out — so an operator who chooses the
advanced mode, then opens Settings for any reason and presses Apply, silently loses that choice along
with seven other settings, including several the panel had just displayed. The product then reports
that the settings were applied. The bundle still honestly records what actually ran, so the evidence
is not damaged; the operator is simply not given what they chose.

**The lesson underneath all of it.** I do not read two of the old documentation folders, by
instruction — they describe code being deleted, and sessions that wander in start proposing repairs
to it. I had quietly widened that into avoiding the old documentation altogether, which the
instruction does not say. Reading the old material to understand *why* something was done is not the
same act as reading it to fix things, and only the second is forbidden. Worse, the evidence that
would have corrected the DNS mistake was in the first search I ran, and I read it as boilerplate
rather than as proof that the thing being excluded actually occurs. The owner caught this rather
than the process catching it, which is the part worth fixing.

Seven findings were recorded across the two halves of the day, on top of the five above. Nothing a
customer can see moved.

---

## 2026-08-11 — What the product is allowed to see

Today's row decides, permanently, what SecureAD is able to look at. Capture asks a domain controller
for a named list of attributes; anything not on the list is not in the bundle, is in no report, and
cannot be added later without capturing the whole forest again. Nobody can go back and re-read last
quarter. So this is not a list that can be fixed in the next release.

I did not carry the old one across. The previous product had a hand-written list per object type,
grown over years, and copying it would have imported every choice in it that nobody remembers
making. Instead every attribute now has to name something that reads it, and a test fails the build
if one cannot. Twelve attributes the old product collected could not name a reader and are recorded
as deliberately dropped, each with what it would cost to change my mind — mostly "a full recapture",
which is why they are listed rather than quietly deleted. The one I would most expect to be
overruled is the creation and last-changed dates on objects: they are the obvious way to ask how old
a delegation is, and no rule that needs them exists yet.

**Three things had to be decided, and all three were arguments the product was having with itself.**

*A forest whose schema cannot be read now produces nothing at all.* The row said such a run should
carry on in a degraded state. A decision made yesterday said the opposite: a part of the directory
that cannot be read fully ends the run. I went with ending it. Without the schema, the product
cannot put a name to any permission scoped to something a customer created themselves — and those
are exactly the interesting ones. A bundle like that would have to hedge on every finding it
touches, which is evidence nobody can act on. Reading the schema needs no special privilege and
takes seconds, so a failure there is a broken connection rather than something a customer withheld.
The cost is real: an unlucky moment now loses a run instead of most of an audit.

*The two capture modes become one, and the second one turns out to have been hiding a hole.* The old
wizard offered "known security classes" or "all objects" as a choice on screen. The second mode
looked like clutter — its only visible effect was to drag in hundreds of thousands of DNS records —
but the reason someone built it was sound. Under the first mode, an object belonging to a class the
product had never heard of had **no permissions read at all**. A dangerous delegation on some vendor
application's objects was simply invisible, and the report did not say so. So capture now reads
every object whatever its class, and the only exclusion is DNS zones and records, named out loud so
a report can say DNS was not examined. This costs bundle size and analysis time, and it means the
product will start reporting delegations on objects customers do not recognise. That is the correct
kind of noise.

*Half of what this row owed cannot honestly be built yet.* The row asked for a check in both
directions: an attribute nobody reads should fail the build, and a rule needing an attribute nobody
captured should fail the build too. There are no rules in the rebuild yet, so the second check would
have walked an empty list, found nothing wrong, and passed forever while measuring nothing. That is
the exact failure we already got caught by once. So it is split: the first half is built and
working, the second is written down as owed, against the row that will make it possible.

**One thing I broke and the guard caught.** While deliberately breaking each new check to prove it
actually fires, a script aborted half way and left the document damaged; the next run then treated
the damaged version as the good one. The new test found it. The routine check I would normally use
to spot a mangled file could not see it, because these files were brand new and not yet committed —
worth remembering.

Four findings recorded. This is the sixth of the ledger's 256 rows to be finished, and the first
outside the foundations — and nothing a customer can see moved today.

---

## 2026-08-11, later — The vendor objects, and a filter I should have asked about

I decided something this morning that was not mine to decide, and the owner caught it. The record of
why the old product ignored certain directory objects turned out to still exist, in two places I had
not looked: a screen the product shows customers, and a list in the tree-view code.

**What the evidence says.** The old product's own words to customers: capturing every object *"avoids
large volumes of smart-card, credential, vendor, and system objects that can triple capture size
without improving the user and group risk picture."* The objects are named elsewhere in the code as
credential and single-sign-on records nested underneath each user account — three of them from one
customer's sign-on product, and beside those four that are not specific to anyone: registered
devices, TPM records, foreign principals, and BitLocker recovery records. A computer accumulates
BitLocker recovery records, so this is not one customer's problem. It is every organisation that
encrypts its laptops.

**What I had written was understated.** I had priced this as "some extra vendor objects, amount
unknown". The real claim on file is three times the capture. That correction is now in the record,
marked as a correction rather than quietly rewritten, because how it was got wrong is the useful
part: I read a filter in the old code and looked for the reason only in the new documentation.

**But the number has never been measured.** It appears exactly once in the whole repository, in that
one sentence to customers. Nothing behind it. And the second half of that sentence — *"without
improving the user and group risk picture"* — is a security judgement that was made once and never
looked at again. The objects being skipped are the credential-bearing ones.

**The owner's decisions, three of them.** Whether someone can read a BitLocker recovery key is a
question this product will answer — so those objects stay in scope whatever the volume turns out to
be. Capture stays as it is, reading everything except DNS, while a real production capture settles
whether the tripling is true. And the question that settles it is now written down so the exercise
is decisive rather than a fishing trip: *do any of these objects carry a permission they did not
inherit from the account above them?* If they all simply inherit, they hold no delegation of their
own and skipping them loses nothing — and that would be the old judgement confirmed on evidence
instead of on memory. If any does not inherit, someone has handed out control of credential material
directly, which is the thing this product exists to find. Neither answer needs a name, a key, or any
personal data.

**One consequence had to be built immediately.** Saying "we audit the object that holds the BitLocker
key" is one careless line away from "we collect BitLocker keys". The key and the permissions that
protect it sit on the same object. So the product now has a rule with teeth: it reads permissions on
credential material and never the material, and the build fails if the list of things capture asks
for ever names a password, a recovery key, a password history or a key-distribution root key. It
also fails if the permissions on those objects stop being collected, because a rule that could be
satisfied by looking away entirely would quietly undo the decision it exists to protect.

**And I had to withdraw a claim I made this morning.** I had written that whether a missing value was
withheld or simply unset could be worked out from two schema flags, citing a single sentence of
Microsoft's. Checking the BitLocker attribute showed Microsoft shipping an attribute with both flags
set in a combination that sentence says cannot happen. So the clean rule is not a rule. The product
now records both flags and leaves the interpretation to whoever reads them, having checked. That is
the same mistake decision 0016 exists to prevent, committed in a document that cites 0016 as a
warning.

Four more findings recorded. Nothing a customer can see moved, and the capture behaviour is unchanged
pending the measurement.

## 2026-08-11 — How a search is asked for, and how hard it pushes

Two pieces of capture, built. Neither is a feature. Both are the kind of thing that costs nothing
to get right today and cannot be retrofitted later.

**The first is about a way a capture can lie.** When you search a domain from the top, the domain
controller answers with the objects you asked for and also with pointers to everything else nearby —
the configuration and schema partitions, the DNS partitions, and every child domain, all the way
down. If the software follows those pointers while it is reading page by page, Microsoft documents
what happens: the bookmark that says "you are on page four" gets overwritten, the software concludes
it has reached the end, and it stops. No error. Microsoft's own article says there is no fix for
this — only four ways of not walking into it.

What that would mean for a customer is the worst thing this product could do. A capture reads a
thousand objects out of nine million, reports success, and the report presents that thousand as the
whole forest. Every finding in it is true and the absence of every other finding means nothing, and
nothing on the screen tells the difference.

The old product avoided it, by luck. Two lines in two different files, no test on either, and a
comment beside the first giving three reasons that are not the real one. Anybody tidying that code
would remove it, and the capture would keep working perfectly against every test forest — because
the trap only springs on a forest with child domains, and lab forests do not have them.

So the avoidance is now the design rather than an accident. What capture reads in one go is one
partition, on one controller, and it follows nothing. The three other ways of avoiding the trap are
written down as **refused**, with the reason for each, because the most tempting of them — read the
global catalog instead, one server, no pointers, whole forest — is wrong in three ways that are all
silent, and the next person to look for a faster capture will find the same article and the same
suggestion.

And the build now refuses to lose any of it: there is one place in the code allowed to construct a
search, and turning the pointer-following back on fails the build rather than the forest.

**The second is about how hard the product leans on a customer's servers.** It used to have a speed
limiter with three settings — Safe, Balanced, Fast. It was properly built and properly wired and it
could never do anything, because the product only ever asks one question at a time and waits for the
answer. An operator choosing "Safe" changed nothing a server experienced. That is worse than having
no setting at all, because it reads like a lever over production impact.

It was removed two days ago, and removing it quietly made something else load-bearing: the only
thing now keeping the product gentle is that it never asks two questions at once. Nothing said so,
and nothing enforced it. A later session wanting a faster capture would reach for the obvious
change, and it would multiply the load on a customer's domain controller with no ceiling — and can
also make the capture *wrong*, because a controller keeps only one budget of bookkeeping for
page-by-page reads and throws the oldest away when it fills.

So that is now a rule the build enforces, and beside it a document naming the limits the servers
themselves impose — page size, query time, how many values of one attribute come back, how long a
quiet connection lives — each taken from Microsoft's published defaults rather than guessed, and
each saying what the product does about it. One of them is listed purely so that nobody cites it:
it looks like a safety margin and has not been enforced since 2003.

**Two things I got wrong, and one near miss.** A claim in the ledger about what the software does
by default cited the wrong piece of Microsoft's documentation — the right conclusion from the wrong
page — and is withdrawn and re-sourced. And the two precautions above turn out to interfere: the
second one asks the server not to send those pointers at all, and the pointers are also how the
product notices a partition nobody planned for. Left alone, that would have produced a report saying
"no unplanned partitions found" when the truth was "we asked not to be told". It now says which,
and cannot say the first when it means the second.

The near miss: an edit truncated a row of one of the registries, dropping its contents. It was
caught immediately by a guard written after the same accident happened before, whose failure message
described the accident exactly. That is the fifth time, and it is now written down with the way to
avoid it.

Nothing runs yet. Nothing has issued a search, and both documents say so plainly rather than
implying they have measured something they have not.

## 2026-08-11, later — Reviewing the old capture code against the new, and settling retry

I went back and read the old capture code properly — the shard definition, the rate limiter, the
shared paging helpers, the connection manager — and compared it against what I had just built. That
found one real defect of mine, two places where my writing was wrong while the code was fine, and
one row I had marked finished that was not.

**The defect.** My search builder could only ever ask for the first page. The old one took the
server's bookmark as an input, so it could ask for page two, page three, and so on; mine did not,
and the guard I had written stopped anything else from building its own request. The next piece of
work would have hit a wall and either worked around the guard or quietly broken it. Fixed, with
tests, including one that refuses to ask for a page when the server has already said there are no
more — which would otherwise read the whole domain twice.

**The row I had wrongly closed.** Retry. The row is literally called "paging, retry and rate
limiting"; I built the paging, deleted the rate limiting, and never decided retry at all. That is
now settled, and the shape of it is worth writing down because it is not obvious.

A page-by-page read holds a bookmark that only means something inside one live conversation with
one domain controller. So what matters when something fails is not the error so much as whether the
conversation survived it. If the controller was simply busy, ask again — three times, waiting five
seconds then ten, because a server that has just said it is busy is the last one to badger. If the
connection dropped, the bookmark died with it, and there is no way in LDAP to say "carry on from
object forty thousand" — so that domain is read again from the start, once. Anything else stops the
run. There is deliberately no fourth option that appears to resume, because that would be a partial
capture reported as a whole one, which is the thing this product cannot do.

**Your idea about offering a different domain controller is the right one**, and it is written down
as the point where that choice gets made — but not built. You also told me something more useful
than the feature request: that you have run many captures against production with the old tool and
it has never once failed during capture. That turns the dialog into machinery for an event nobody
has ever seen, which is exactly how the old product ended up with twenty-eight buttons wired to
nothing. So the seam is named and the automatic behaviour is built; the dialog waits until
something actually fails. Your observation is recorded in its own right, labelled as recollection
rather than measurement, because it is currently the only real-world evidence anyone has about
this.

And no, there is no button to skip a domain and carry on. You were right to lean away from it.

**Two things your comments broke open.**

You said you want the capture units to run in parallel. The build rule I had written the same
morning would have forbidden that — and it was wrong to. The actual requirement is that one domain
controller never gets two requests at once; reading nine domains at once, each on its own
controller, is nine servers each seeing a polite single-file client. My rule banned all of it. It
now says something narrower and truer: a piece of code may run things in parallel, or it may talk
to a directory, but not both. I proved it both ways — it still catches the dangerous case and it no
longer blocks the safe one.

There is one genuine trap waiting there, and it is now written down. Every domain sits on its own
controllers, so those spread out naturally. The configuration and schema partitions sit on *every*
controller, and the current decision deliberately puts both on one. Read in parallel, those two
become two simultaneous page-by-page reads on one server, competing for a single pool of
bookkeeping that the server empties by throwing away the oldest — silently. Under parallel capture
they need a controller each, which costs nothing since every controller has both.

You also said capture is quick and the analysis is what costs. That exposed a flaw in the test
guarding the parallel-capture decision: it required capture to be slower than analysis *and* to
miss the maintenance window, before parallel work could be justified. But analysis never touches a
customer's directory — it runs on the file afterwards. Only capture uses up the maintenance
window. So the test would have refused parallel capture for a reason that has nothing to do with
capture. Corrected, and left for the session that takes that decision on properly.

**One more thing about the documents.** You asked that the new documentation stop explaining itself
by reference to the old program, since the old program is going away and no future reader will have
seen it. That was right and it was wider than one sentence, because the new documentation folder
does not get thrown away — it becomes the documentation. I have gone through everything written
this session and restated the reasoning so it stands on its own. The rules are the same; they no
longer depend on a codebase that will not exist.

## 2026-08-11 — Making sure a big group reads as a big group

This session built the piece that turns what a domain controller sends back into values the rest of
the product can use. Most of it is dull and necessary — reading text as text and bytes as bytes.
One part of it is not dull at all, and it is the reason the row exists.

**A domain controller will not send you all of a large group, and it does not tell you so.** There
is a limit on how many values of one attribute it will return for one object. It is 1,500 by
default. An administrator cannot raise it out of the way either: since Windows Server 2008 there is
a hard ceiling of 5,000 that overrides whatever the policy says, and Microsoft's own worked example
of it is a group with more than 5,000 members coming back with 5,000. The client has to ask for the
values a block at a time — a thousand at a time is the size that is safe against every server — and
keep asking until the controller marks a block as its last. A reader that does not do this reports
Domain Users as a group of fifteen hundred, and reports it calmly, with no error anywhere. That is
this product telling a customer something false about a privileged group, so it is now held by a
test rather than by a comment.

**Two files became one.** The old code did this job in two files with interchangeable names, split
along no line anybody could see. They are now one reader.

**Four things I decided, and why.**

*There is no limit on how many blocks a retrieval takes.* The old code stopped after a thousand
rounds, logged a warning, and handed back what it had as though it were the whole thing. At 1,500
values a round that is one and a half million members, so it would realistically never have fired —
but the shape is exactly the defect. A cap that is reached has to either give up quietly or fail,
and giving up quietly is how a large group becomes a small one. Putting a big number on it does not
change what it is; it changes how rarely it happens, which makes it harder to find. So what bounds
the loop instead is progress: every block has to move forward, and a block that does not is a
failure with a name, which ends the run. It cannot spin, and it cannot settle for part of the
answer.

*A partial read cannot describe itself as anything else.* The values and the statement "these are
all of them" are one thing rather than a list with a flag beside it that somebody might not look at.
There is no way to get at the values without also holding the answer.

*"The attribute did not come back" is kept separate from "the object has none".* This is the
question you left open, and I have not closed it, deliberately. An attribute is missing from a
response when nobody ever set it, and it is equally missing when we were not allowed to read it —
some attributes are marked confidential and are simply withheld, silently. The rule that looked like
it would tell those apart does not survive contact with the schema Microsoft ships, which is a
finding from the previous session. So the reader has a third answer, "did not come back", that no
code downstream can mistake for an empty list. Whoever settles what it means in a given forest now
has something to attach the answer to. Guessing it this week would have been the same mistake twice.

*Whether an attribute needs this treatment is never decided by its name.* It is read from the
catalogue, where every multi-valued attribute is marked as one. A hand-kept list of "the ones that
need it" agrees on the day it is written and stops agreeing the moment somebody adds the next one.

**How it is tested, since there is no forest here.** I put a stand-in domain controller in front of
the reader: an object holding ten thousand members that behaves the way the documents say a real one
behaves — it will not send more than the limit at once, it answers under a ranged name, and it marks
the last block. The reader then runs a whole retrieval against it, at the 1,500 default and again at
the 5,000 ceiling, and has to come back with ten thousand. That exercises the real rule end to end.

What it does not prove is that a production controller spells things exactly the way my stand-in
does. That is a claim about a server and no test in this repository can settle it, so it is written
down as an open finding for the lab session rather than left implied by a green test. If I am wrong
about the spelling the failure is visible rather than silent — a group would report as an attribute
that never arrived, which is wrong and obvious, rather than as a smaller group, which is wrong and
invisible. That is the safe direction to be wrong in, and it is why I was willing to ship it.

**Two corrections to earlier work.** A sentence written last session said that past the limit the
attribute is "absent from the entry". That is tidier than anything Microsoft actually says — their
wording is that results "may appear truncated or incomplete" and that "in some occasions, you may
not get any results". The behaviour I built handles both, but the sentence claimed more than the
evidence, which is the exact habit we have a rule against. Corrected in the two places it appeared,
and recorded so nobody tightens it again.

And a new build rule: the text that spells a range — `;range=` — may now appear in exactly one file
in the product. A second place that spells one is a second opinion about where a block of values
ends, and the two do not disagree loudly. Both look plausible, one of them fetches fewer values, and
nothing says so.

Everything above was tested in both directions: I deliberately broke each new check, confirmed the
break reached the file, and confirmed the check caught it — six times, including breaking the
document to make sure the document check is not just reading itself.

## 2026-08-12 — The part that actually reads a forest

Everything built so far described what a capture would do. This is the piece that does it: take one
partition, ask the domain controller for it, take the objects it sends back a page at a time, and
know when it has finished. It is a small amount of code and it carries the one failure this product
cannot have.

**The failure.** A domain controller sends a large answer in pages, and it tells the client "here is
a bookmark, ask me again with this" until it has nothing left. There is a known defect where the
client library throws that bookmark away — it happens when the search wanders off toward another
partition — and the application then sees "nothing left" on the very first page and stops. A thousand
objects out of nine million, no error anywhere, and a report where everything it says is true and
everything it does not say means nothing. Nobody looking at the screen could tell.

**What I could not do about it.** I looked for a way to spot it happening. There isn't one, and
Microsoft says so plainly: on the network the controller sent a perfectly good bookmark, and the
client library discarded it before the application ever saw anything. By the time our code looks,
the evidence is gone. Their own article's Resolution section says, in full, that there is no
resolution.

**What I did instead.** The loop does not try to detect it. It refuses to make the claim. A partition
is never reported as read whole unless the connection has told it, before a single request is sent,
that the search could not have wandered anywhere. Two tests are the proof and they only work as a
pair: one points the loop at a controller holding two and a half thousand objects over a connection
that would wander, and checks that *nothing is sent at all*; the other points it at the identical
controller with that turned off, and checks the partition is read. Either test on its own would look
like it proved something it didn't.

**How a finished pass says it is finished.** There is one successful outcome and it is a record that
only the loop can create, at the only moment it is true. "It ran and didn't crash" is not a statement
that a partition was read — a capture that reads one page and stops also doesn't crash. So there is
no flag to check afterwards and nothing that could be set by accident. Anything other than a whole
partition ends the run and says which naming context and why. Six named endings, each one written
down and each one held to the code by a test in both directions.

**Two passes became one.** The old implementation walked every object in the forest twice — once for
who things are, once for who can change them — and nobody had written down why. It turns out the
reason was a setting on the request, and the setting can simply be on the one request. So a
nine-million-object forest is now walked once rather than twice.

**A real gap closed on the way.** That same setting is what tells a controller "give me the
permissions but not the audit configuration". Asking for the audit half needs a privilege on every
domain controller in the forest — something a customer would have to be persuaded to grant before the
tool would read anything. The old product asked correctly. The rebuild had lost it, in the gap
between the session that built the request and this one that issues it. It is back, and now a test
fails if anyone puts the audit half back in.

**A big group, mid-partition.** A controller will not hand over more than about fifteen hundred
members of a group at once, so the rest have to be asked for in blocks. I had to decide when to ask.
The answer is: as soon as the object arrives, before asking for the next page, so an object is never
handed onward half-read and nothing has to be held in memory for the length of a partition. I have
written down why I believe that is safe to do mid-search, and also that it is reasoning from
documentation rather than something I have watched a real controller do. That goes on the list for
the lab.

**Three things wait for a real domain controller**, and they are on the list rather than implied by
green tests: whether a controller spells a block of values the way my stand-in does, whether it
minds a second question arriving mid-search, and what the client actually sees when a controller
quietly forgets a bookmark — which is a real thing that happens on long searches and which our
failure table currently has no answer for. That last one only ever stops a run; it cannot cause a
wrong report.

**The honest part about progress.** I expected this to be the row that unblocks the check we have had
parked since the rebuild started — the one that proves every published piece of the product is
actually reachable by something running. It does not. What I built is a loop, not a run: nothing
chooses a domain controller, nothing opens a connection, and nothing writes what is read to a file.
Those are two other branches and neither is decided. So the check stays parked, and I moved it — with
the sixteen pieces of the product that were all waiting on this row — to the row where a run driver
will land, and wrote down that the forecast was wrong. That is the second time a forecast like this
has been wrong for the same reason, which is exactly why the register makes you state your grounds
rather than just naming a row.

**One thing about my own method.** The first time I deliberately broke a check to prove it works, all
sixteen tests passed — because the test runner had not recompiled, so it measured the old code with
the break sitting unused in the file. That is the same shape as every check we have caught measuring
nothing, and it would have produced a table in a document saying a guard was unnecessary. Every
break is now compiled explicitly before it is run, the first run is recorded in the table rather than
quietly replaced by the second, and it is written down in case it happens again.

Two more of the same kind happened before I was finished, and I would rather they were in the record
than tidied out of it. Tidying five of the error messages into a shared helper stopped the document
check from being able to find them, so it went on comparing two much smaller lists and finding them
consistent — caught only because that check counts how many it finds and complains if the number
drops. And one of my deliberate breaks is designed to make the loop run forever, so the test run
hangs; that command got cancelled from outside, the cleanup step never ran, and the break stayed in
the file. I found it by checking the file straight afterwards rather than by trusting the cleanup.
Both are written down properly. The pattern in all three is the same: the thing that catches a
broken check is a check that counts, and the thing that catches a broken cleanup is looking.

**Where this leaves us.** A partition can now be read whole, correctly, and it will say so only when
it is true. A forest cannot, because nothing yet chooses which domain controller to talk to, opens a
connection to it, or writes down what comes back. Those are the next two pieces.

---

## 2026-08-12 — Branch A: the connection, and what a customer's credentials cross

**The problem.** The rebuild could read one partition and could not read a forest, because nothing
opened a connection. The piece that reads a partition was written against a description of a
connection, with nothing real on the other end — so the one setting the whole capture stage depends
on was written down, guarded, and applied to nothing. This session is the other end.

**This is the branch where a customer's password and a customer's evidence go over a network.**
Everything else in this product reads a file. That happens once, during capture, and there is nothing
afterwards that could notice it went wrong. So the question you settled on how we connect is not a
technical preference; it is the one moment where getting it wrong is a promise the product cannot
keep.

**What you decided, and what I built to it.** We try the most protected way of connecting first and
work downwards until a domain controller accepts one: LDAPS, then an encrypted and signed connection,
then a signed one, then an unprotected one. It is written as a list rather than as a series of
if-this-else-that branches, so that adding a fifth way later is one new line rather than an edit to
everywhere that assumed there were four.

**The unprotected one is out of reach unless somebody said so before the run started.** Not a
fallback that happens quietly — a declaration, made in advance, with a reason attached in the
auditor's own words. There is no prompt at the moment it would be needed, because this tool gets
scheduled overnight and a run that stops at three in the morning waiting for somebody to click a
button has produced nothing by breakfast. And it is not remembered between runs. We have already
deleted a batch of settings that somebody switched on once and nobody thought about again; this one is
a real switch, so it gets pulled fresh every time.

Ticking it does not buy silence, either. A domain controller that will not accept a protected
connection is a weakness in the customer's environment whether or not we minded, and we are standing
right there when it happens — so we say so. A run that used an unprotected connection says that too.
Neither of those can be written yet, because there is no report and no findings engine, so both are
registered against the rows that will write them rather than left as an intention in a document.

**Something worth a moment.** Walking the ladder produces, for free, a list of exactly what each of a
customer's domain controllers will accept. We have to connect to all of them anyway. So a capture now
also answers *"which of my twelve domain controllers still allow unsigned LDAP"* — which is a
question people normally pay for separately.

**All ten rows of this branch are now decided.** The one that changed most is the routing table that
picked a different domain controller when one stopped answering. It is deleted. We already decided
that a partition is read from one named controller chosen before the run starts, and that when a read
fails we retry it there rather than moving; half a partition from one server and half from another is
two views of a directory that is changing underneath you, stitched together with nothing recording
the seam.

The preflight check survives and gets bigger — it now also asks whether we can connect at all and on
which rung, so a run that needed a declaration and did not get one finds out in its first minute
rather than its third hour. It is slower than the old one, deliberately: the old one asked four
controllers at once, and asking more than one thing at a time is precisely what we forbade in order
to stop a capture quietly truncating itself. A minute of asking, against hours of reading, is not a
trade worth reopening.

**Nothing runs yet, and that is the third time in a row.** Opening a connection sounds like the thing
that finally makes the product start. It is not: it opens a connection when something asks it to, and
nothing asks. That has now been the wrong guess three times running — a library each time — so I have
written down what is actually still missing rather than guessing again: something to drive a run,
somewhere to write down what it read, and a starting point. All three are named, on named rows.

**Three of my own mistakes, in the record rather than tidied out of it.** A script I wrote to edit
one of our tracking documents silently mangled the accented characters in ten rows it was not even
supposed to touch — caught because we count the lines a change touched, and it touched twenty when it
should have touched ten. A second edit, to one row, replaced the whole row instead of the sentence I
meant, deleting it — caught by the check that every component has exactly one row. And a check I
wrote this session to make sure every decision has real reasoning behind it turned out to be blind for
the last decision in the document: I shortened that one to a single word and the check happily
passed. That is the same failure we have now caught four times — a check that looks like it is
measuring something and is measuring nothing — and it was found only because I deliberately broke
things to see whether the check would notice.

**Where this leaves us.** We can now open a connection to a domain controller, over the best
protection it will accept, and we know and record which that was. We can read a partition whole
through it. We still cannot read a forest, because nothing works out which partitions a forest has,
nothing drives the reading, and nothing writes down what comes back. Those are the next pieces.

## 2026-08-12 — Branch C: somewhere to write it all down

Until today, the product could reach a customer's domain controller, read a whole partition of
their directory, and then throw the result away. There was nowhere to put it. That is what this
session was for, and it is why four separate later pieces of work — working out who can take over
what, applying the rules, showing it on a screen, comparing two runs — have all been sitting
undecided. They all read one file, and the file did not exist.

Nine pieces of work now have decisions behind them, and most of them are built. A run can create a
bundle, write objects and permissions into it, seal it, and refuse to open one that has been
tampered with.

**The most important decision is the seal, and I renamed it.** The old product called it a
signature. It is not one. There is no key anywhere in this product, so what it actually proves is
that the bytes of the file have not changed since the run finished — it catches corruption, a
truncated file, and somebody editing evidence in a database tool. It does not catch somebody who
knows what they are doing, because anyone who can change the file can recompute the seal beside
it. Calling that a signature promises a customer something we do not deliver, and the customer
weighing an audit finding is exactly the person who would take the word at face value. So it is a
seal, and what it cannot prove is written down where a future reader will trip over it rather than
buried.

**And a second change to it, which is subtler and matters more.** The old product had three
answers: sealed, unsealed, and modified — and if the signature file was damaged and could not be
read, it called that *unsealed*. That is backwards. "Nobody ever sealed this" and "something has
happened to the seal" are close to opposite statements, and reporting the second as the first
turns a warning into a shrug. There are now four answers, the damaged case has its own, and only
one of the four opens a bundle at all.

**I also removed the shortcut that skipped the check.** The old product cached the result, keyed on
the file's size and timestamp, so reopening a large bundle did not have to re-read it. That saves
real time, and it also means the integrity check can be made not to run by anything that preserves
a timestamp. A cache whose whole purpose is to avoid performing a security check is a way for that
check to quietly never happen. It costs us: a large bundle now gets re-read every time it is
opened, which will be seconds of waiting. I have written that cost down against the piece of work
that will have to deal with it, rather than pretending it away.

**What stops a half-finished bundle being read as a finished one is its name.** A run in progress
writes to a file called `evidence.db.partial`. The very last thing a finished run does is rename
it. Everything that reads a bundle asks for `evidence.db` — so a run that crashed, or is still
going, simply has no file by the name anyone asks for. I preferred this to a check because a check
has to be remembered everywhere a bundle is opened, and a name has to be remembered nowhere. A run
that failed also now keeps its partial file: the old product deleted the whole thing on failure,
which throws away the only evidence of how far it got, on a judgement made by the code that has
just failed.

**Re-analysing an existing capture is gone.** It let you re-run the analysis over a forest you had
already read, without going back to the domain controllers — but it re-sealed the result, so the
bundle could no longer say what it was when it was captured. That is a real capability and losing
it is not free: a customer who upgrades and finds their existing evidence cannot be re-examined
will either re-read production or not bother. So I have written down what has to replace it —
producing a *new* bundle from the old one and leaving the original sealed and untouched — against
the piece of work that will build it.

**Two things I got wrong, both caught by checks rather than by me.**

The first was a forecast. We keep a list saying "nothing uses this piece yet, and this future piece
of work will" — and when that future work lands, the promise comes due. Twenty-two of those pointed
at the two writers I built today, and not one of them was right, because the writer deliberately
does not know the name of a single Active Directory attribute. It stores whatever it is handed.
The thing that actually reads `nTSecurityDescriptor` by name is the piece that joins reading to
writing, and that is still to come.

The second was worse and I am glad it was caught. My first version of the storage layout identified
an object by its name and its position in the file. Both of those change: a name changes when
somebody renames or moves an object, and a position means nothing outside the one file. Comparing
two runs would therefore have reported any object that had been *moved* as one object deleted and a
different one created — a change the customer did not make, reported as a change they did.
Comparison is now the only way this product verifies anything, so that was not cosmetic. It
surfaced because a check forced me to revisit why we capture the object's permanent identifier in
the first place, and the reason turned out not to be served by the storage that was supposed to
serve it. Fixed, while nothing depended on it yet, which was the only cheap moment it had.

**One thing I deliberately did not decide.** How much free disk space a run demands before it
starts is still open. The shape of it is settled — no guessing, no estimate derived from an object
count — but the piece that actually protects correctness when a disk fills is the seal, and that is
what I built instead.

**Where this leaves us.** We can connect to a domain controller over the best protection it will
accept. We can read a partition whole. We can now write what we read into a sealed file and refuse
to open one that has been altered. What we still cannot do is run: nothing joins the reading to the
writing, and nothing starts either of them. That is one piece of work, it is named, and it is the
next one.

## 2026-08-12 — Where audits are kept, and telling the truth when we cannot compare

**What I set out to do.** Decide where a run bundle lives on disk. That sounds like filing and it is not. Whether the tool owns a folder of its own decides whether it can list what audits exist at all, and everything that needs a second audit to point at depends on that list: the baseline, drift, comparison, importing findings you already accepted.

**What we settled.** The tool owns one folder, and you choose where it is. The old version hardcoded a location into two places in the code, which for a product that writes several gigabytes of evidence means it can fill the wrong disk without asking. Runs go directly inside that folder and nowhere else. I turned down the more flexible option that also allowed capturing to any path you like, because it brings a state the others cannot reach: a list entry pointing at an audit that has been moved or deleted. A list of audits that are not there is worse than a shorter list.

**A baseline belongs to a forest.** You said this barely matters, and you are right that in practice there will be one forest per machine, because we offer no way to supply different credentials. I kept the key anyway. It costs nothing and it means that if somebody copies an audit onto the machine from somewhere else, it lands on its own rather than being quietly offered as last month for a forest it has nothing to do with.

**I was wrong once and you caught it.** I told you that with one forest there is effectively one profile, so the grouping collapses. That came from a summary rather than from the code, and the code says otherwise: the old product had two identities, not one. One says which forest was audited. The other says which domains the run declared it would read and which parts were excluded, and that second one is what already governs whether two audits can be compared. Your question about different domains was the right question and my answer was built on a wrong reading. I have corrected the document that carried it and said plainly that it was wrong, rather than quietly deleting the sentence.

**What reading the old code turned up.** Your exclusion dialog makes two promises, and I checked both. If somebody excludes a domain that is populated, the run cannot be used as a baseline afterwards, and that is genuinely enforced before anything is written. If somebody claims a domain holds nothing of value, the audit tests that claim against what the forest actually reported and records it as broken if it was. Both promises are kept. That matters more than it sounds, because it means the runs that are eligible to be a baseline are the ones that read the whole forest or excluded only domains that were verified empty, and those are safely comparable to each other. It is why the baseline needed no second grouping.

**And the thing I would want fixed first.** The home screen tells you what changed since last time. It is built from five numbers and reads nothing else. When the system refuses to compare two audits, the refusal comes back with all those numbers at zero, and the screen prints No changes since the previous audit and renders it as a clean pass. So the tool can tell somebody in the capture dialog that their run cannot be used as a baseline, and then show them an all-clear against that same baseline an hour later. That is the one thing an audit tool must never do, and it is not a slip in one place: the question of whether an audit may be used is answered in five separate spots in the old code, and they disagree with each other.

**So the theme you asked for is now written down as a rule.** One component answers whether two audits may be compared, and every screen asks it rather than deciding for itself. The answer is a fixed list of named outcomes, which means adding one later makes the compiler point at every screen that has not been updated. The drift card gets three shapes instead of one: a real result, a result with a plain statement of what was not looked at, and no result at all with the reason named. Only the first is ever allowed to say nothing changed.

**Where this leaves us.** Nothing new runs. This was a deciding session, not a building one, and I have written down what was decided, what I found in the old code, and one mistake I made in my own process along the way. The next piece of work is the one that builds the library and that single answer, and it is named.

---

## 2026-08-12 — The run's identity, and one answer to whether an audit may be used

**Two decisions we made this morning were built on something that had already been taken out.**
Both of yesterday's records leaned on the exclusion attestation — the rule that somebody excluding
part of the directory has to say whether it is populated or empty, and have that claim checked. That
mechanism was removed a week earlier, when we decided the audit reads the whole forest and there is
nothing to exclude. Neither record noticed, because that was a capture decision and the session was
about the library. I caught it before writing any code, which is the only reason it is a paragraph
here rather than a defect. Four of the eleven states on the drift card described things that could
never happen, and the test binding them would have passed while describing the impossible.

**So we re-derived it, and you made three calls.** Coverage can now only vary two ways: the audit
could not read a domain, or the forest itself changed shape — a domain decommissioned, an
acquisition finished. You ruled that a domain read only in part counts as failed, that an audit that
failed a domain cannot be a baseline, and that it cannot be compared either. That last one costs
something real: one flaky domain controller near the end of a long capture now costs the whole run
and it has to be done again. I think it is the right call. The alternative is a baseline with a hole
in it, which makes every later comparison understate what changed while looking perfectly confident.

**Then the same thing happened again, one level down, and you caught the shape of it.** I put six
words to you for describing what became of an audit — running, finished, failed, cancelled,
interrupted, damaged — without first checking what the product can actually see. It turns out a
failed audit, a cancelled one, one killed by a reboot and one still running all leave exactly the
same thing on disk. So four of my six words were unreachable, and I had asked you to approve a list
I had not checked. That is my error and it is written down as one.

**The fix is small and you chose it.** An audit that ends badly now leaves a short note saying which
of the two it was and why. Whether an audit is still running is answered by asking the file system
whether anything is still writing to it — which is free, and needs no tidying up after a crash,
unlike the usual tricks. All six words are now arrived at by looking at something rather than
assumed.

**What is built.** The product now knows which forest an audit belongs to, which domains it declared
it would read, which of them it actually managed to read, what became of the run, and — the one that
matters — whether an audit may be used, either as something to compare against or as the baseline
everything later is measured from. That last question was answered in five separate places in the
old code and they disagreed with each other. It is now answered once, and the list of answers is
fixed, so adding one later makes the compiler point at every screen that has not been updated.

**Three things this deliberately does not finish, all written down rather than left to look done.**
Nothing calls the new rule yet, because the library screen, the drift card and the compare window do
not exist. Nothing writes the end-of-run note yet, so until the part that runs an audit is built,
every bad ending reports as *stopped without saying why* — which is true, just less useful than it
will be. And reading an audit's recorded details out of its own database waits on the database being
rebuilt, so that piece is half done and says so.

**Two smaller things I found while checking rather than assuming.** The list of decisions was missing
two of them entirely — the two we made yesterday were never added to it. And the rule that decides
whether a folder holds a finished audit or a half-written one was sitting inside a record marked
*superseded*, even though the part that superseded it never mentioned that rule. Anyone reading it,
seeing the marker and moving on would have lost it. Both are fixed.

**The guards earned their keep three times today.** The one that stops the same question having two
different answers refused a helper I had named `Normalize`, because that word already belongs
somewhere else — correctly, since a second thing called normalisation is exactly how one question
ends up with two answers. The one that protects the ledger refused two rows I had written with a
column missing, rather than writing a damaged row, which is a thing that has happened four times
before. And deliberately breaking my own new checks, to see whether they notice, found one that was
doing nothing at all: a guard I had written to prevent the old baseline defect turned out to be
redundant, because the types already made that defect impossible. It is kept and labelled, and the
guard that is really doing the work now has a test of its own.

**You asked for a point-in-time review, and I have not done it.** You were right to ask. Two of
today's findings are precisely what such a review exists to catch, and neither the records nor any
test found them — I did, by chance, while reading for something else. I have written it down as owed
so it survives into the next session rather than depending on either of us remembering.


## 2026-08-12 - The point-in-time review, and a word we should not have been using

**I did the review you asked for.** Every decision record read against every other, and every claim
that mattered checked against the actual code rather than against a document describing it. The
result is a single document you can read in one sitting - what the product does today, what each of
the thirty decisions decided in one line, which have been overtaken and by what, and what is really
built as against what is merely agreed. It is at `docs/next/POINT-IN-TIME-REVIEW.md`, and what the
cross-reading turned up is at `docs/next/S-19-the-point-in-time-review.md`.

**It found the thing it was commissioned to find, and it was the serious kind.** Five of our accepted
decisions describe a bundle as *signed*. One of them is the sentence that says what this product is:
*a forest-wide security audit producing signed, point-in-time evidence*. But we decided two days
earlier that the seal is not a signature - there is no key anywhere in this product, so it proves the
bytes have not changed and proves nothing at all about who produced them. Two of our documents repeat
the claim in the same breath as saying a bundle gets forwarded to auditors and insurers. Those are
exactly the people who would read *signed* as proof of origin, and it is not.

**You withdrew the word, and I think that was right.** It is recorded as decision 30. Nothing else
changed - every decision in those five records still stands, and I did not touch their text, because
those records are dated accounts of what we thought at the time and rewriting one destroys the only
thing it was for. Each got a note on its status line instead, pointing at the correction. The two
documents that would have shown a customer the claim are corrected, and so is a test message that
repeated it.

**The one sentence that said it plainly was in a record marked superseded.** Decision 19 said *"It is
called a seal and not a signature, because it is not one"*, and 19 is the record a reader is told to
move past. That is the second time a good sentence has been lost behind a supersession marker - the
same thing happened last week with the rule about half-written audits. It is worth knowing that our
own filing system has a way of hiding things.

**Three problems I found and deliberately did not fix.** Decision 7 still says we refuse to compare
two audits taken in different modes, and the rebuilt product has no such thing as a mode - so either
our list of reasons to refuse a comparison is missing one, or that sentence is dead. It needs you.
Separately, a comment in the code argues that we cannot tell a running audit from an interrupted one,
which we decided two days later that we can, and the file next to it does exactly that. And the names
of a bundle's files are kept in two different places, which is the pattern one of our own guards
exists to stop. All three are changes to the product, and this session was not allowed to write any.

**A tidier note.** The list of decisions was missing the supersessions for three more records,
including the one that moved the whole rebuild to a new folder - so anyone reading that record alone
would have opened the wrong solution. Fixed. And an empty stray file had been committed into the
decisions folder by accident; it is gone, though three more are sitting untracked elsewhere and I
have named them rather than quietly deleting another session's work.

**What this exercise cannot do, said out loud.** I have bound the new document to the decisions with
a test, so it cannot quietly omit one or invent one, and so it cannot claim a decision still stands
whole when the record itself says otherwise. That would have caught the missing index entries from
last week. It would not have caught the *signed* problem. Nothing mechanical would. That one needed a
person to read thirty documents in a sitting and notice that two of them could not both be true - so
if this is worth having again, it is worth having as a session and not as a check.

**And I got two things wrong in my own method, both caught.** When testing whether my new guard
actually notices a broken document, I deleted a line and then confirmed the repair by searching for a
number that also appears elsewhere in the prose - so it told me the file was fixed when it was not.
Then, restoring a file from a backup, the copy kept its old date, so the build decided it had nothing
to do and ran the broken version three times while I read the failures as real. Both are the same
mistake: trusting a check without asking what it would say if the thing it measures were missing.

## 2026-08-12 - Reading the old storage code before rebuilding it, and stopping short

**This session was meant to write the new evidence schema and did not write it.** It did the reading
first, and the reading changed enough that writing would have been guessing. What came out is a
record of what was found and six questions for me, at `docs/next/S-20-what-a-bundle-stores.md`.

**The first pass overstated what it had read, and I pushed back.** It answered my questions from a
partial reading and presented conclusions with more confidence than the evidence carried. When it
went back and actually read the old capture code, two of the things it had told me turned out to be
wrong. That is worth recording as a method note: the correction came from being asked to look again,
not from anything mechanical.

**What the old code turned out to be doing.** The predecessor never stored the raw values from the
directory. It read an attribute, decided what it meant, and stored the decision - a bit in
`userAccountControl` became a row saying "Unconstrained", and the original security descriptor bytes
were parsed and then thrown away. So the database holds conclusions rather than observations, with
no line marking which is which. The consequence is the one that matters for an audit product: if one
of those conclusions was wrong, every capture ever taken is wrong and cannot be corrected without
reading the customer's forest again, which is the one thing that cannot be redone.

**But re-analysis worked, and the session had to withdraw a claim about that.** It first told me
re-analysis "only half-works". Reading `DerivedAnalysisPipeline` showed that is not so. There is a
list of eight tables that get deleted and rebuilt, and everything I ever used re-analysis for -
rules, the graph, escalation paths, tiering - sits in that list and rebuilds correctly. The
boundary the session wanted to introduce **already exists in my old product**; it just has no name
and nothing enforcing it. What genuinely cannot be recomputed is narrower: only the places where the
original value was binary and got digested at capture. The clearest is resource-based constrained
delegation, where the database records that it is configured and never records who can use it.

**Three silent holes found in the old write path**, all the same habit. An object whose GUID did not
arrive is dropped with no row and no error, and the run still reports success. A failed permissions
write is swallowed to a debug message that a release build does not even emit. And an object seen
twice keeps its first location, so something that moved appears never to have moved. None of these
are carelessness - they come from a loop that must not crash on nine million objects - but the
answer is to make them impossible rather than to be more careful.

**Something in my own plan could not be built as written.** The instruction for this row says to
carry over a "deleted" flag from the old product. The new capture never asks for that attribute, so
the column would be false on every row of every audit forever - a field that looks like an answer
and measures nothing. The session stopped on it rather than writing it, which is what I asked for.

**And the disk question is going to be settled with a number instead of an argument.** Whether we
keep the raw permission bytes comes down to storage cost, which is what killed this idea in the old
app. The session's contribution was to notice that most objects in a forest carry byte-identical
permissions, so storing them once and pointing at them may cost a fraction of storing one per
object. There is now a script that measures exactly that on a live forest. It needs a production
environment to be meaningful - a lab will make the answer look better than it is - so this waits
until I can get it somewhere real.

**Next is a review of the permission parser against Microsoft's published format**, prompted at
`docs/next/sessions/S-21-the-security-descriptor-parser.md`. I spent a long time on that parser and I
think it is right, but the session made a point I had not considered: the tests that guard it were
copied from the old implementation on purpose, so they prove the new code matches the old code. They
would not notice if the old code was wrong. Only reading the specification would.

## 2026-08-12 - Measuring instead of arguing, and finding the hole that bit me last time

**The storage decisions are settled, and one of them reverses something I did in March.** This
carries on from the earlier entry today, where the session stopped rather than write a schema it
could not justify. What changed is that we went and measured.

**The disk question turned out to be the opposite of what I assumed.** I have been carrying the idea
that keeping the raw permission bytes was too expensive. On a real domain, the raw bytes are
*smaller* than the rows you get from parsing them - about half - and if you store each distinct
permission set once instead of once per object, they cost roughly a tenth. Most objects in a forest
carry byte-identical permissions inherited from the same place, so storing them once and pointing at
them collapses the whole problem. Keeping the original bytes now costs about thirteen per cent on
top, which buys the ability to fix a parser bug later without asking a customer to let us read their
forest again.

**It also confirmed what I actually said the disk cost was.** It was never the permissions - it was
the derived analysis. The measurement backs that: the parsed entries alone are nearly five gigabytes
per hundred thousand objects before a single graph table exists, and the graph is built on top.

**Then the thing that mattered more than any of it.** I asked whether there was a record of why I
stopped storing inherited permissions, because I had a feeling it was tied to escalation paths. There
is - a commit from March saying it cut the database by eighty to ninety per cent, with a note that
control edges, findings and escalation paths only need explicit permissions. So we went and checked
whether that was true.

It is not. The graph never understood containment at all. If someone is given full control over an
organisational unit, every account inside it inherits that control - but the graph only ever recorded
one connection, to the unit itself, and none to the thousands of accounts underneath. So the question
this product exists to answer - who can take over this account - would come back with nothing, while
the dangerous permission that caused it sat in the report a page earlier. The tool saw the cause and
could not reason about the effect. That is what bit me when I got to escalation paths, and now I know
why.

**So inherited permissions come back, and for a reason I can defend** rather than because it feels
more complete. With each object carrying its own full picture, the connection falls out of the data
without any clever inheritance logic that could be wrong. The catch is recorded alongside it: every
object also inherits full control from Domain Admins and SYSTEM, so the analysis has to learn to
ignore the expected ones or the graph fills with noise. That is written down against the row that
will have to solve it, today, rather than being discovered later.

**One in five objects in a production domain would not give up its permissions at all.** They belong
to a single sign-on product - two per user, holding stored credentials - and an ordinary account
cannot read them, which is the vendor doing the right thing. We proved it is a permissions wall and
not a technical failure by asking for two hundred of them one at a time and getting nothing back.
What it exposed is that our idea of coverage has no word for this: the domain was read completely,
and a fifth of it gave us no permissions. The product will now record that plainly instead of storing
those objects as though they grant nothing. Whether an audit run by an ordinary user should count as
an audit at all is the one big question still open.

**And my own measuring tool was wrong three times before it was right**, which is worth writing down
because it is the same mistake in three costumes. It reported zeroes that looked like a fact about
the forest and were really a failed read - the exact thing this product exists to stop. Then two
theories about why, both published to me with more confidence than they deserved, and one of them
raised as a possible fault in the new capture code before being withdrawn. The actual cause was a
one-line mistake that a two-line test on the local machine would have found before anyone touched a
forest. The tool now refuses to report zero permissions across a whole domain, because that is not
something a directory can be.

## 2026-08-13 - Reading the half of the old product nobody had read

We finally read the analytical half of the old application - the part that takes the raw directory
data and turns it into findings, escalation paths and chokepoints, plus the comparison between two
runs. Everything we had said about that half until now came from reading the *shape of the tables it
writes*, not the code that writes them. That is a cheap way to be confident and wrong, and it had
already cost us once. **Nothing was changed. The session produced a document and stopped.**

**The most important thing it found is about the tier policy - the file where a customer names their
own crown jewels.** You write down that your certificate authority, or your finance server, matters
as much as a domain controller. It shows up correctly on the asset tier screen. And it never reaches
the escalation analysis at all, because the two run off different copies of the tier rules and only
one of them was given your file. So the question *who can reach our certificate authority* comes back
empty, and comes back empty confidently. The comment in the code even argues that these two must
never be allowed to disagree - and the wiring one file away makes them disagree. That is the exact
kind of fault we went looking for: a promise made in one place that nothing ever checked against the
place that had to keep it.

**Two more would have told a customer something false.** If the escalation stage crashes, the screen
shows an empty list and no warning, which reads as *nobody can reach anything* rather than *this did
not run* - and the old code does know it failed, it just tells only the exported report and not the
screen. And a domain whose permissions we deliberately skipped is counted as fully covered, so the
product claims a complete analysis of data it never collected. There is also a narrower one: a
"Deny" rule that names a group is invisible to the analysis, so we would report someone as having
control that Windows would actually refuse them - a false alarm, which costs trust as surely as a
miss.

**Three of your five design challenges moved, and one of them did not survive.** The challenge about
the tier definition needing a version is now the strongest of the five and is confirmed twice over.
The challenge about evidence being a blob is stronger than it was written - that blob is not just
something we show you, it is how two stages of the analysis hand data to each other, and its reader
silently drops anything it does not recognise. But **the challenge we were most confident about was
the one that was wrong.** It argued, as arithmetic rather than opinion, that the old product stores
an explosive all-pairs table of escalation routes. It does not. It already does the clever thing that
challenge proposed - searching backwards from the valuable accounts - and it already caps what it
keeps at twenty routes per account. The argument was sound and it was about a different program. I
have left the text alone for you to correct or drop, because it is your document.

**What I think that says about how we are working:** the two mistakes in this session and the one in
the last all have the same shape. Someone reasons carefully from a description of a thing instead of
the thing. It is faster, it feels the same from the inside, and the only reliable defence we have
found is to go and read the code every time a claim is doing real work. That is now the third
occasion, which is enough to call it a pattern rather than bad luck.

**Four questions are yours, not mine.** The biggest: when a customer changes their own tier policy
and re-runs the audit, every route result shifts - should we refuse to compare the two runs, or
compare them and warn? Today we do neither, and simply report the churn as though the forest had
changed underneath them.

## 2026-08-13 - Asking what the product needs, instead of what the rebuild has got

I went looking for what capture must read, and found two rules in your product that could not
answer their question at all.

**The thing that was wrong.** SecureAD asks a domain controller for a fixed list of attributes. That
list is the ceiling on everything the product can ever say, and it cannot be raised after the fact -
an attribute we did not ask for is not in the evidence, is in no report, and nobody can go back and
re-read last quarter. To stop the list growing without reason, every attribute on it has to name
something that reads it, and a test fails the build if one cannot.

That test was asking the wrong question. It accepted only a *rebuild component* as the answer, and
almost none of the rebuild is built. So the list was bounded by how far the rebuild had got, rather
than by what the product needs - and an attribute your rules require, but no finished component
reads, looked correct to leave out. A note from the previous session even said so in as many words.

**What it cost.** Two rules. **SEC-091** reports a computer missing its LAPS deployment, and
**SEC-092** reports a computer where LAPS has quietly stopped rotating the password. Both are
switched on. Neither had the data. A customer with no LAPS anywhere in the estate would have got a
report that said nothing about it - not *unknown*, nothing, which reads exactly like a clean result.
That is the one thing an audit tool must never do, and it is fixed: three attributes added, and both
rules now have what they need.

**The reassuring half.** I checked all sixty-two of your rules, one at a time, against what capture
asks for. The list was **three attributes short** - not thirty. Everything else the old product read
and the rebuild dropped is genuinely read by no rule: last logon, account expiry, descriptions, the
password-policy settings. Those drops were right.

**What it costs to hold them.** Nothing worth discussing. The three live on computers only and are
short. Measured against the storage numbers from two sessions ago, they add well under a megabyte in
a hundred-thousand-object forest, where the permissions alone cost between half a gigabyte and five.
Which settles a general point: storage is not the reason to refuse an attribute.

**Your decision about LAPS passwords is now a guard, not a promise.** You said we should never read
one. The attributes we now read sit one word away from the ones that hold the password itself, so a
future session could add one by accident in a single line. A test now fails the build if it happens.

**Two things I am handing you rather than fixing.** Six attributes we capture have no rule reading
them at all - including the one that records which keys can log on as an account without its
password, which is a real attack and a rule we do not have. That is a gap in the rule list, not in
capture, so the data should stay. And six rules read Group Policy files from SYSVOL, which we have
not built yet, so a tenth of the rule catalogue is inert. You said B14 and B15 will get to them;
I have written down the words a report should use in the meantime, for when there is a report to put
them in.

**Three things went wrong while I worked, all mine, all recorded.** I threw away an hour of my own
edits with a careless undo; I corrupted a document by writing it back with the wrong text encoding,
which the numbers-check caught; and a cancelled script left a deliberate break in place, which I
found only by re-reading the file. None reached the product. All three are the same shape as
mistakes this project has made before, so they are written into the document rather than tidied
away.

## 2026-08-13 - Checking the story against Microsoft, and finding a hole in how we connect

**I set out to build the database inside a bundle and did not get there.** Two of our own documents
described different databases, and before I could pick one I had to check what they both rested on.
That checking is what this session turned out to be. The schema itself is still owed.

**Your instinct about LAPS was right and mine was wrong.** I had accepted the brief's claim that the
LAPS timestamp we read can be hidden from us without warning. It cannot: Microsoft ships it readable,
and the one attribute that *is* protected is the password itself, which we already refuse to touch.
So the specific disaster the brief warned about - reporting "no LAPS" across an estate that has it -
needs a customer to have changed something Microsoft did not. Worth knowing, and much smaller than we
thought.

**But checking that turned up something bigger, and it is not hypothetical.** Windows Server 2025
changed a default. On those domain controllers, protected attributes are only handed over on an
encrypted connection - and if the connection is not encrypted, the controller quietly leaves them out
and says nothing. No error, no warning. We climb a ladder of four ways to connect, best first. The
worst rung already needs you to sign it off in advance, and on a 2025 controller it will not connect
at all. The problem is the rung above it: it is not encrypted, it needs nobody's permission, and it
is the only one that both works and misleads. We gated the loud failure and left the quiet one open.

**You decided two things about that.** Encryption becomes the line, so that middle rung now needs the
same sign-off as the worst one; and a bundle will record how each controller was actually read, so a
report can say "these were read over a weaker connection" instead of letting a reader assume we saw
everything. The first belongs to the connection work rather than to storage, so it is written into
that row rather than done here. **Until it is done, this is live** - a capture today can still take
that rung.

**A question that had been open for a week turned out to be a misreading of one word.** We had
recorded that Microsoft's rule for which attributes can be hidden contradicts itself, because they
ship an attribute carrying both marks at once. Reading the page rather than our note about the page:
the mark is *ignored* on that kind of attribute, not forbidden. Nothing ever contradicted anything.
The rule is one line long and it is now written down in the four places that had been waiting for it.

**I also settled which of the two documents to believe, and it is not the newer one.** The older
design justifies itself with a distinction it does not actually record - it stores a flag saying "this
did not come back", which turns out to mean exactly the same as "there is nothing here". The decision
that replaced it was right, but for a reason it never gave: when the directory leaves something out,
it does not say why, so nothing we store per object could tell you which it was. That is a better
argument than the one it had, and it is now recorded against it.

**One structural change.** The list of attributes we ask for lived in the capture project, and the
database that has to build a column for each of them cannot see it from there. I moved the list into
the shared project both sides can reach. Nothing about what it contains changed.

**Two things went wrong, both mine, both caught.** My editing tool silently replaced whole lines
instead of the phrases I gave it, and destroyed most of two rows in the tracking table - the tests
caught it within a minute and I rebuilt them by hand and checked the sizes. And I claimed a change
would silently disable three of our safety checks; when I tested that claim, it was false - the
checks fire loudly, because they are wired in both directions. I had already written the wrong claim
into four places before disproving it. Both are recorded in the session document rather than tidied
away, and the second one is the better lesson: I ran the test because the rule here says to, not
because I doubted myself, and the rule was right.

## 2026-08-13 - Making the documents agree with the product, and finding one that did not

This one was housekeeping that turned out to matter. Over the last few weeks we have written a lot
of documents, and every so often one of them was caught saying something the code had stopped
doing. That kept happening by accident, so this session went looking on purpose.

**Six disagreements. Five were the document, one was the tracking table, and none was the code.**
That is the good news: the product itself is doing what we think it is.

**The one worth your attention.** A few days ago I withdrew a claim from one document - it described
a feature we had decided not to build. I withdrew it in the two places I noticed and missed three
others, including a line filed under *things checked against the code and found correct*. So the
document said, in its most trustworthy section, that the product does something it has never done.
Nothing caught it, because nothing was reading that document. Anyone building on it next would have
inherited the mistake as fact.

**What I did about it, beyond fixing it.** Six documents now have tests that read them and fail the
build when they drift. I broke each one deliberately, from both sides - changed the document and
watched it fail, changed the code and watched it fail - so we know they actually work rather than
merely exist. Two of them caught mistakes I made during this very session, within minutes of my
writing them. One of those was me "correcting" a line in the tracking table from something true to
something false, because I had checked it carelessly. The test disagreed with me and was right.

**Two things are owed.** A decision we took last week has nobody assigned to carry it out - I have
recorded it against the nearest owner rather than letting it sit. And a review we wrote a brief for
was never actually run, and nothing anywhere said so. More on that next.

**What this does not fix.** Every problem found this session was found because a document and the
code disagreed. The nastier case - where a document and the code agree with each other and both
describe something we have since replaced - is still invisible to a test, and the one instance of it
I found was found by reading, in a particular order, by hand. I have not solved that. I have only
made it visible in more places.

## 2026-08-13 - Reading the permissions parser against Microsoft, not against ourselves

The brief for this one was written three days ago and then forgotten, which the previous session
noticed. It is the review I would least like to have skipped.

**Why it needed doing.** The component in question reads the raw permission data out of Active
Directory. Every single thing this product says about who can do what rests on it. If it misreads,
the product does not fall over - it reports a confident wrong answer, and the customer acts on it.

**And our own tests could not have told us.** They were built by recording what the old product
produced and checking the new one matches. That proves the two agree. It does not prove either is
right. A misreading we inherited passes every test we have. The only way to check is to read
Microsoft's published specification and compare it line by line, which is what this session did.

**The good news first, because there is a lot of it.** Eleven things came back correct, including
several I expected to find wrong - the fiddly bits where two halves of the same structure are stored
back-to-front from each other, and the table that translates "full control" into the specific
permissions it stands for, which matches Microsoft's own definition exactly. Whoever wrote this read
the specification properly.

**Two things I fixed.** Both were cases where Microsoft's document is unambiguous and we had simply
read a number the wrong way. One of them meant a corrupted or malicious record would crash the parse
instead of being logged as damaged - and the whole design of that component is that one bad object
must never spoil a whole audit. Neither fix changed any recorded value, so nothing we have measured
before has moved.

**Two things I did not fix, and they need you.**

The first: when we cannot read an object's permissions, we currently report it as an object that
**denies everybody**. In Windows those are two very different things, and we are reporting the
second when we mean the first. The practical effect is that an object we failed to read looks like
the most secure object in the estate. An auditor scanning for problems would skip straight past it.
Fixing it means adding a fourth possible answer - *we could not tell* - which touches the database
we have just finished building, so I have not done it unilaterally.

The second: Windows checks permissions in the order they are stored, and stops at the first one that
matches. We sort them into a tidy order before saving, which we need to do for comparison to work.
But we keep no record of the original order - so if someone deliberately arranges an object's
permissions in an unusual order to grant access that appears to be denied, we would report the
denial, and Windows would grant the access. We cannot currently see that this has happened. The
cheap version of the fix is a single yes/no flag per object saying whether the order was normal.

**One more, unowned.** There is a second permission list on every object which records what gets
audited, and we do not read it at all. That may well be the right call for this product, but it is
not written down as a decision anywhere, and one of our own descriptions promises we read it. I have
raised it rather than answered it.

**Something I got wrong, and one thing the brief did.** The brief told me to update two rows in the
tracking table; one of those rows is about something else entirely and I did not touch it, because a
session should not rewrite the status of work it has not looked at. And halfway through testing my
own fixes I nearly recorded a false result, because the build had quietly not rebuilt - the test was
reporting on old code. Both are written down.

## 2026-08-13 - Deciding the three questions the parser review raised, and building them

You took all three decisions the same day they were put to you, so this session is the work that
follows from them. Everything below is now in the product.

**When we cannot read an object's permissions, we now say so.** Before this, such an object was
recorded as one that *denies everybody* - the most locked-down answer there is - so the objects we
had failed to read looked like the safest things in the estate. They now carry a distinct state, and
anything that reports permissions has to handle it rather than quietly treating it as safe.

**There turned out to be a fourth case, worse than the one we discussed.** We talked about an object
whose permissions could not be read at all. The nastier one is an object where we read *some* of
them: it looks complete, and quietly under-reports. That object is genuinely present and correct in
every field, so no amount of new states fixes it - it needed its own answer to *did we get all of
this*, which every descriptor now carries.

**One of our own safety checks improved the design and caught a bug in it.** My first version stored
a plain number - how many permission entries the object claimed to have. A standing rule in this
codebase forbids a bare number that cannot say whether it was measured, and the check refused it
immediately. It was right, and not on a technicality: a record claiming zero entries and a record
too damaged to read would both have arrived as zero, which is precisely the confusion this whole
piece of work exists to remove. My first draft really did report a damaged record as an empty one. I
changed the number to a named answer and corrected the written decision to say that its own first
draft reproduced the fault it was written to fix.

**We can now see permissions stored in an unusual order.** Windows reads an object's permission list
top to bottom and stops at the first entry that applies, so a list arranged with an allow before a
deny grants access that a tidied-up view would show as denied. We tidy every list up in order to
compare objects between runs, and until now that tidying quietly erased the evidence. Each object
now records whether its list arrived tidy. On most estates the answer will be *yes* everywhere,
which is the boring and correct result; where it is not, that is likely the most interesting line in
the report.

**I withdrew one of my own recommendations while implementing it.** I had offered to record the
original position of every single permission entry. That was unnecessary: we already keep each
object's permissions exactly as the directory sent them, so the original order was never actually
lost - only hidden from easy querying. Storing it a second time would have been a duplicate of
something we hold, which is how this codebase acquired three different ways to answer one question
about names. One yes/no per object does the job.

**We do not collect audit settings, and now that is a decision rather than a habit.** The code has
always asked the directory for permissions only, and the reason written beside it is a good one: the
audit half requires a privilege, and not asking for it means this tool runs as an ordinary user and
nobody has to grant it special rights on their domain controllers before it will read anything. I
was unfair to that comment last session when I called the behaviour undocumented - the reasoning was
there, only the authority was missing. It is written down now, along with what it costs us: we will
not tell you that auditing has been switched off somewhere it matters.

**Cost of all this: three new columns**, on a database that is finished but has not yet had a single
real capture written into it. The same change in six months would have meant migrating every
customer's stored evidence.

## 2026-08-13 - Checking my own advice against Microsoft, and finding it wrong twice

A short follow-up, and the useful part is what it says about how I was reasoning rather than what
changed in the product.

**I told you one of our checks was too lax, and it was not.** I reported that an entry type we do
not recognise gets treated as harmless. Reading the code properly, the component that decides
whether a permission is dangerous already refuses to judge such entries and says so. I had implied a
risk that was never there.

**I then proposed a fix that would have recorded something twice.** My suggestion was to log these
entries as damage. But we already store them: the stored evidence keeps the raw type number for
anything we cannot name, so they are already findable with a single query. Worse, logging them as
damage would have put them in the table that means *this record could not be read*, which is not
what happened - the entry reads perfectly, we simply have no name for it. This is the same mistake I
caught myself making the day before with a different column, one day apart.

**And I gave you an argument that was backwards.** I said keeping the audit-entry vocabulary was
safer because such an entry would be *recognised and handled*. When I checked what handled meant, we
answer *not dangerous* about it - and since we stopped reading audit lists entirely, such an entry
can now only turn up somewhere it does not belong. I raised that as a defect for you to rule on.

**Then I read Microsoft's actual access-check algorithm, and the defect was not a defect.** An audit
entry takes no part in deciding access, wherever it sits, so answering *not dangerous* about one is
correct. What was wrong was only the sentence we attached to it, which explained the answer by
reference to something we no longer read. So: no behaviour changed, one comment corrected, and the
one thing genuinely worth doing - noticing that somebody wrote a malformed record into the directory
- is handed to the part of the product that reports findings, where it belongs.

**What I take from it.** Three of my four claims here came from reading our own code carefully and
not reading the specification at all. The specification settled it in minutes. I have written the
one inference the specification does *not* support into the record as well, because the tempting
next step - assuming anything the algorithm does not mention is harmless - is false, and somebody
will reach for it.
