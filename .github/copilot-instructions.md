# Copilot Instructions

## Who you are working with

**The owner is a security and Active Directory administrator, not a software developer.** He knows what the SecureAD product must do and why it matters to the people who will use it. He is relying on you to build it.

This has three consequences, and they are not optional politeness:

- **Make the engineering decisions yourself.** Tooling, libraries, test structure, code layout, whether to use one technique or another — these are yours. Decide, then explain what you decided and what it costs. Handing a technical trade-off to the owner is not collaboration; it is avoiding a decision he is not positioned to make. Even when a session brief says "decide X", present the decision and its options to him and wait for his answer before writing any code. Do not treat a brief's wording as delegation of product or design decisions.
- **Reserve questions for what only he can answer.** What the product should do, what an AD administrator would expect, which risks are acceptable, what to prioritize. Ask those freely.
- **Explain in plain language, every time.** Define any term you cannot avoid, at the point you use it. Say what a thing is *for* before you say what it is. Prefer a concrete consequence — "a customer would see a screen that reports nothing" — over an abstract one.

Watch for drift: it is easy to slip into developer-to-developer shorthand several messages into a session, especially when the work is going well.

## When to stop and raise it

**The default is to keep moving.** Something that is wrong but contained gets written down as a finding, with a severity and a status, in the session's slice document — and the work carries on. Stopping for every defect is as damaging as stopping for none: it turns a session into a list of interruptions and the owner into an approver of things he is not positioned to judge.

**Five things stop the work.** In each case, say plainly what is wrong and propose the fix; do not hand over an open technical question.

1. **A check that passes while measuring nothing.** The worst category, because everything downstream of it looks verified and is not. This has happened twice: gate 5's original wording passed against all fourteen public types while nothing in the tree was reachable, and the S-2 document guard matched a renamed member by substring so a deliberately broken document did not fail it. Usually cheap to fix on the spot, and it must be fixed before anything relies on the check. See `docs/next/README.md` § Gates for the scanner self-test that every gate carries for this reason.

   **A third shape, found 2026-08-20 (`F-S44-2`): a closed loop of checks anchored to the wrong reference.** The captured attribute catalogue was covered by three sound test suites — the document matched the code, the code matched the rules, the rules matched the document — every check passing in both directions with negative controls, and the whole circle anchored to the set of rules already written. A rule nobody wrote was an attribute nobody missed, and fifteen attributes the predecessor captured were silently absent. **Ask what a set of checks is anchored to, not only whether each one is sound.** Anything *reassembled* rather than *ported* has no external anchor, and internal-consistency tests cannot supply one however thorough they are.
2. **The product would tell a customer something false.** Not unclear — wrong. An object attributed to the wrong container, a "found nothing" that was really "could not compute", a permission reported as safe that is not, a comparison that failed reporting that it matched. This is the one thing an audit tool cannot do, because a customer makes a security decision on the strength of it. Never deferred.
3. **A frozen value needs editing.** Golden hashes and classifier fixtures are recorded outputs of the old system, kept to prove the rebuild changed nothing. If one needs changing, either the old behaviour was wrong or the new one is, and that is a conversation. See `docs/next/README.md` § Tests: a golden value that needs editing is a finding, not a fix.
4. **A decision that gets more expensive every week it waits.** Naming, the shape of a public interface, where a component lands. Free at zero consumers and brutal at thirty-four — which is how the DN helpers ended up with three near-identical ways to ask one question, and why gate 5 could not be retrofitted onto the old tree. Raise these while they are still cheap.
5. **A decision only the owner can make.** What the product should say, what an AD administrator would expect, which risk is acceptable, what to prioritize. As above: tooling, libraries, code layout and test structure are not on this list and must not be handed over.

**Do not stop** for routine errors, a missing file, a syntax mistake, a search that came back empty, or a defect that is real but contained and recorded. Fix it or file it, and continue.

## What counts as settled

**A document is not the truth unless it says it decided something.** Only two things in this repository state the product's position:

- a record in `docs/decisions/` with `Status: Accepted`
- a finding carrying an explicit **Decision:** line

**Everything else is discussion.** Slice documents, reviews, design notes, findings without a decision, XML doc comments, and the prose in any README are one person's understanding at one moment. They are often right and they are never authoritative. Read them as argument.

This matters most for the documents that read best. A well-argued paragraph is the easiest thing in this tree to mistake for a conclusion, and doing so has produced findings that were withdrawn on contact with the code.

**Where the two disagree, the code wins and the disagreement is a finding.** Do not repair a document to match a belief; verify against the definition — the enum, the writer, the query actually sent — and record what was found.

## The documentation rewrite, and what "done" means

**The goal is fewer files, not better files.** The documentation is being consolidated into **one layer document per code folder, written from the code**, and the sprawl is **deleted as it is consumed**. A pass that adds documents without removing any has not consolidated anything.

**Route every fact to exactly one destination:**

| Kind of fact | Goes to |
|---|---|
| What the code does | the layer document for that folder |
| Work that may need doing | [`PUNCH-LIST.md`](../docs/PUNCH-LIST.md) |
| A product position | a record in `docs/decisions/` |
| What blocks the rewrite itself | [`PUNCH-LIST.md`](../docs/PUNCH-LIST.md), *Documentation rewrite* |
| Anything else | deleted |

**`docs/areas/` is being emptied.** An area file is an input, not a fixture. **Delete the content you move, in the same turn you move it**, so each pass leaves the file shorter; the file itself goes when the last content leaves. Do not copy content across and leave the original in place — that doubles what the next session must read, which is the problem this work exists to solve.

**Findings and rules were out of scope for the documentation rewrite, and that consolidation is now done.** The rule cards under `docs/rules/` are the largest single body of documentation in the repository and were deliberately left in their own format, to be consolidated **when the rules are implemented**. That is the work now starting: 62 rule cards are written and 2 are implemented, so `docs/rules/`, `SecureAD.Evidence/Findings/` and the area files `what-we-call-a-finding.md` and `accepting-a-finding.md` are consolidated **as each rule is built**, against the code that implements it, and not in a documentation pass of their own. Do not count the unbuilt remainder as coverage debt. The exclusion was lost once already: the gap was measured correctly and its cause was not recorded beside it, so a later session read *zero of seventeen* as work owed.

**Before writing any gate, read `docs/next/README.md` §*When a document counts as documentation*.** It is the founding rule and it is not optional:

> A test binds a document to the code only if it **derives what it expects from the code**.
> The deciding question is *what change to the product would make this fail?* If the answer is *nothing — only editing the document*, the check is **pinning** and does not belong.

**Do not test the shape of prose** — heading formats, identifiers, status lines, whether a section exists. Twelve such test files were deleted on 2026-08-14 and the suite went from 960 tests to 793. **They keep coming back**, and a live example is recorded as `P-51` in `PUNCH-LIST.md`. A prose gate is worse than useless: it later reads as a structural constraint and blocks the consolidation it was meant to protect.

**A gate that has never been observed failing is not evidence.** Point a new or retargeted gate at a document that does not carry its subject, confirm it fails **naming what it cannot find**, and record which checks failed and what they said — including any that passed, because those are the ones that are decoration.

---

## Orient before proposing anything

Sessions have repeatedly re-opened settled questions because each one starts at a leaf and works outward. **Start from the document that governs the code you are touching, and read it whole.**

**Find it in [`docs/next/SURFACE-REGISTER.md`](../docs/next/SURFACE-REGISTER.md), which maps every public type to its governing document.** Do not guess from folder names, and do not assume the folder you are working in is the whole of what that document governs — `group-policy.md` governs 23 types across three assemblies while the folder holds 16.

1. **Read the governing document whole.** For code already rewritten this is a layer document under `docs/layers/kernel/`, `docs/layers/audit/`, `docs/layers/connect/`, `docs/layers/evidence/` or `docs/layers/schema/`; it describes what the code does and is bound to it by a test. For code not yet reached it is still an area file in `docs/areas/`. **Area files are inputs being consumed and deleted, not fixtures** — see the documentation rewrite section below.
2. **Open questions live in [`PUNCH-LIST.md`](../docs/PUNCH-LIST.md).** Those are questions nobody has answered. If the work touches one, stop and ask the owner. Do not infer an answer from the old application, from a row in the reference inventory, or from the shape of the code — that inference is what produced the preflight wizard.
3. **Search `docs/decisions/` for the question being raised.** Cite the record that governs it, or state plainly that none does. Titles do not index by topic — `0017-capture-reads-the-whole-forest` is the decision about what capture reads, and searching for "object class" will not find it.
4. **Check who calls it before proposing to remove or change it.** Four findings in one session were wrong because a type's shape was read as its purpose. A per-class lookup that nothing calls, a completeness field that is always the same value, and an exemption list with stated terms all looked like what they were named.

**The old application's inventory and component map are gone.** The inventory document under `docs/next/` and the whole of docs/map/ were archived on 2026-08-20 along with the sixteen tests over them, which only ever checked that one document agreed with another and never touched the product's code. Nothing in this repository now describes what the predecessor had. The owner keeps the old repository and consults it himself; do not ask for it and do not treat its absence as work owed.

**`docs/next/S-*.md` no longer exist.** They were component documents, each held true by a test, and the documentation rewrite has consumed all of them; `S-2` was the last. If a document or a handoff paragraph refers to one, it is describing history. **Layer documents replaced them** — one per code folder, under the subsystem directories listed above, each bound to the code by a test that derives what it expects from the code.

**Session records and session briefs no longer live in this repository.** docs/history/, docs/next/sessions/ and docs/review/ were archived on 2026-08-20 to `C:\Users\jistrand\Downloads\SecureAD Archive`; every version also remains in git history. They recorded what one session did or intended on one day and never stated current behaviour, and several actively misled — one claimed a specification section had been verified that was never opened. **Nothing outside `docs/decisions/` and `docs/rules/` states the product's position.**

## Say what you opened

**Before stating that something exists, name what you opened to know it.** Not "I checked" - the file, the command, the line. If the honest answer is "I saw it earlier", say that instead, because it is a different kind of claim and a much weaker one.

Every mistake made on 2026-08-20 had one shape: **a proxy for the thing, treated as the thing.** A file name where a path was needed, and `README.md` exists in five folders. A grep hit where a declaration was needed, so a comment saying "this test exists in the old tree" counted as the test existing. Link text where a resolved target was needed, so `../README.md` written in the archived session folder was read as the root README and one document's inbound count went from 1 to 69. `git diff --numstat` where content was needed - it showed equal lines added and removed while 29 documents were being double-encoded. None of these was carelessness, and none felt uncertain from the inside.

Three habits follow, and they are cheap:

- **Distinguish a name from a fact.** `NonDestructiveInvariantTests` is a name. Whether that class is declared in this tree is a fact. Say which one is being offered.
- **Prefer the artefact to the answer.** A script that lists the enforced documents cannot be wrong about itself; a sentence saying how many there are can. When a question will be asked twice, write the script the first time - `next/tools/` is full of them for this reason.
- **Give the count and how it was counted.** "51 of 69 records are cited by more than one area" can be checked. "Most are shared" cannot, and hides double-counting - the same fault that reported 20 literals in a file holding 10, each counted once in its assignment and once in its XML comment.

**Re-reading is the only thing that has ever caught this.** There is no internal signal that separates a remembered fact from a retrieved one, so scepticism has to be procedural: open the file again, or run the script again, and say which was done.

## General Guidelines
- Do NOT run genuinely long-running terminal commands (like synthetic database generation). They time out and waste time. Instead, provide the command for the user to run themselves.
- **A rejected file creation may be an approval that could not be given, not a refusal.** On 2026-08-22 two `create_file` calls targeting a *new* directory outside the workspace (`C:\Users\jistrand\Downloads\SecureAD Briefs\`, which did not yet exist and contains a space) came back rejected, and the owner said he could not scroll the approval pane to reach the accept button. The same session created a 300-line test file inside the workspace and three scripts in `$env:TEMP` without trouble, so **length was not the variable and the first diagnosis — "keep edits short" — was wrong.** Which part of the location matters is not known. Prefer writing files inside the workspace or `$env:TEMP`; for a long document that has no home yet, print it in the chat and let the owner place it. If a create is rejected, ask whether it was the content or the approval pane before rewriting anything.
- When running PowerShell commands in the terminal, avoid long single-line commands
*This file previously cited a measured baseline of 3 to 7 minutes for `SecureAD.Infrastructure.Tests`, taken from a review README. Neither that project nor that document exists here, and the guidance would have had a session wait twenty times too long before suspecting a hang. Corrected 2026-08-20.*
- Prefer `git grep` and `git ls-files` for any load-bearing search in this workspace. The built-in `file_search` and `grep_search` tools return misleading empty results here: `file_search` finds no tracked files under `docs/` and missed a tracked `docfx.json`, and `grep_search` reported "no matches" for a symbol that `git grep` located immediately. An empty result from those tools is not evidence of absence — confirm with git before concluding anything is missing or unused.
- **Read Microsoft's specifications through the Microsoft Learn MCP server, never by scraping the web page.** `microsoft_docs_fetch` returns the page as clean markdown - tables intact, no HTML to strip - and `microsoft_docs_search` finds the page. Scraping returns tag soup that has to be regex-stripped, and the extraction breaks silently when Microsoft changes its rendering. This has gone wrong in more than one session, and not through carelessness: this file used to say nothing about the Learn server, it has a whole section on writing measurement scripts, and `harvest-schema-guids.ps1` is a script. Every signal in the repository pointed the wrong way, so the rule is written down here instead.
- **A committed harvest script is still required, and it is a different job.** A script in `next/tools/` cannot call an MCP server when it is re-run in a year, so it fetches over plain HTTP. Read with the MCP server first, then write the script to preserve the check and seed it from what the server returned. When the two disagree, that is a finding - two independent reads of one specification is a stronger position than either alone. Open Specifications (MS-ADTS, MS-DTYP) are published only as rendered pages, so their scripts must strip tags and must say in their header that this makes them more fragile than the ones reading Microsoft's own markdown.
- @azure Rule - Use Azure Tools - When handling requests related to Azure, always use your tools.
- @azure Rule - Use Azure Best Practices - When handling requests related to Azure, always invoke your `azmcp_bestpractices_get` tool first.
- @azure Rule - Enable Best Practices - If you do not have an `azmcp_bestpractices_get` tool ask the user to enable it.
- Explain technical concepts and refactoring techniques in plain language. Define engineering jargon when used, and be explicit about consequences and risks rather than assuming shared developer intuition.
- When handing off work or declaring a stopping point, give a clear ready / not-ready verdict. Do not pair a "you're ready" signal with a list of caveats or loose ends — decide whether outstanding items are genuine prerequisites (say not ready) or not (say ready and leave them out).
- Do not use multi-line here-strings in PowerShell; write long text (e.g. commit messages) to a file instead.
- After any scripted edit, check `git diff --numstat` because the shell and file editor can strip a UTF-8 BOM.
- Mutation-test every new or changed guard in both directions, record which directions were observed, and always revert before running anything long.
- **Do not launch or run the application on the user's development machine.** Building the solution and running the test suite is fine, but starting the product executable (or any process on their device) requires an explicit request from the user first. Also disclose any files written outside the repository, such as publish output in %TEMP%.
- **Be cautious with `create_file`, but see the entry above for what actually goes wrong.** This bullet used to say the cause was length — that the approval prompt renders the content inline and pushes the Approve button below the fold — and that diagnosis was overturned on 2026-08-22 when a 300-line test file inside the workspace was created without trouble. Location, not size, is the suspect. Do not rewrite a file shorter in response to a rejection; ask first. Independent of all this: for commit messages use `git commit` with several short `-m` arguments rather than writing a message file, since a long message written inline hangs the terminal.
- **Throwaway measurement scripts are the usual offender for needless file creation.** Before writing one, check `next/tools/`
- **Read files with an explicit UTF-8 decoder, never `Get-Content -Raw`.** On Windows PowerShell 5.1 that reads with the system codepage, so every em dash and curly quote comes back wrong and is written out double-encoded. A scripted edit did exactly that to 29 documents on 2026-08-20 and it was committed before anyone noticed, because `git diff --numstat` showed equal lines added and removed — which says nothing about content. Use `[System.IO.File]::ReadAllText($p, [System.Text.Encoding]::UTF8)` and write with `New-Object System.Text.UTF8Encoding $false`, or `$true` where the file has a byte-order mark, as `.sln` does. `next/tools/check-document-encoding.ps1` finds the damage afterwards.

## Long-Running Actions
- Any long-running action the product starts must give the operator a way to stop it. A Cancel is not a feature to be weighed — it is expected by default on anything that runs long.

## What the product is, and what was removed
- The SecureAD product is a forest-wide AD security audit
- **Run profiles no longer discriminate by scope.** `ProfileId.ForForest(string forestFqdn)` is the only remaining producer, and it keys on the forest. **`ProfileId.FromComponents` does not exist** — it was deleted with scoped capture, and `ProfileIdTests.NoMemberNamedFromComponentsExists` asserts by reflection that no member of that name is present. *This file previously named the producer `ProfileId.ForSecurityModeFromForestFqdn`, which is not a member of anything, and claimed the reflection guard already existed when it did not — the fact was true by luck rather than by enforcement. Both corrected, and the guard written, 2026-08-20.*
- **Scoped (OU-level) capture was removed on 2026-07-30.** The "Capture Scope" button, `MainViewModel.RunSnapshotAsync`, `AuditOrchestrator.RunConfigurationAuditAsync`, `CaptureService`, `ConfigurationModeRunner` and `ProfileId.ForConfigurationMode` are all gone. Do not reintroduce them, and do not describe scoped capture as reachable. All six confirmed absent from `next/src` by `next/tools/check-instruction-claims.ps1`.
- **Live directory verification was removed** — see `docs/decisions/0008`. **There is no assessment mode** — see `docs/decisions/0031`. Both are removal records: their whole job is to stop something coming back. Do not rebuild either without the owner saying so.
- **Compare, derive and assessment modes are not built.** This file previously said `AssessmentMode.Configuration`, `DerivedStoreSchema` / `DerivedStore`, `StructuralCompareEngine` and `SecurityCompareEngine` "deliberately survive", with two paragraphs on how they relate. **None of those types exists in this repository** — they were in the old `src/` tree, which is gone. Checked 2026-08-20 by `next/tools/check-instruction-claims.ps1`. If you are asked to change one of them, the honest answer is that it has to be written first, and what it should do is the owner's to decide.
- Backwards compatibility with older run bundles is not required — there will not be any older bundles in the field. Do not add back-compat carve-outs, migration paths, or lenient fallbacks for pre-existing bundle shapes; prefer the strict/correct behaviour.

## Rule Catalogue Guidelines
- Every rule must state plainly what it looks for and what the organization running the audit is thereby able to mitigate. A rule that cannot be explained in those terms does not go in.
- Before writing any rule, verify it against Microsoft's official documentation first, and read the referenced Microsoft docs in full rather than filling in gaps from memory or inference. Research precedes implementation for every rule added.

## Memory Management
- The owner is the sole developer on SecureAD and does not value preserved narrative history for its own sake. His words: "maybe history matters in a real development project with multiple people but this is just me. I don't care about how I got here. I care that the end result works." So do not spend effort preserving session-history documents or avoid edits to docs/history/ on the grounds that they are a frozen record — renaming files and updating links inside history documents is acceptable. This does not relax the rules about decision records in docs/decisions/, which state the product's current position rather than its history.
- The old SecureAD app at `C:\Users\jistrand\source\repos\razamus\SecureAD\src` may be consulted as a source of hard-won lessons, but it is always treated with suspicion and never used as an authority. Values and specifications are researched from Microsoft first, through the Microsoft Learn documentation service, and the old app is only ever a cross-check afterwards — never a seed for a harvest. On 2026-08-20 its well-known SID catalogue was found to carry two wrong values that would have survived any test written from it.

## Lab Checks
- The owner does not run lab checks from his development device. The SecureAD product is exercised on a separate lab machine (a different Windows account, e.g. ba.admin), not on the dev box where the solution is built. Do not ask him to re-run the app, attach a debugger, or read the Visual Studio Output window on his dev machine to diagnose runtime behaviour. Diagnose from code, tests and the artefacts a lab run produces (bundle contents, screenshots) instead.

## Documentation Updates
- Documentation is updated as the work goes, not at the end. A stage or task is not finished until its code is merged, its documents are updated, and its status is recorded in `docs/ROADMAP.md`. The owner's words: "make sure we are updating the documentation as we go, I don't want to get to the end and we have nothing."

## Documentation Management
- Documentation for new work goes in `docs/layers/` (one layer document per code folder), never `docs/areas/`. The `docs/areas/` files are being retired and drained into `docs/layers/`; do not add content to them. `docs/layers/specs/JUDGEMENT-HALF.md` is reliable. Do not treat existing `docs/decisions/` records and area documents as settled authority — the owner wants design decisions made during the build, in conversation, rather than read off existing documents.
