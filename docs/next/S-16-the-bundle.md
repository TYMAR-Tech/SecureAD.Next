# S-16 — The bundle

What a bundle is, what is in it, and what stops a half-written one being read as a whole one.

Everything this product ever says, it says from a bundle. Nothing is said from a live directory.
That is what lets a finding be reproduced a year later on a machine that has never seen the
forest — and it is why this document exists before the screens that will read it.

Bound by `BundleDocumentationTests`, which compares the table list below against the tables the
code actually creates in a real database, in both directions. A table named here and absent from
the schema fails the build, and so does a table the schema creates and this document does not
name.

## What a bundle is on disk

A bundle is **one directory**, and where it lives is an argument the operator supplies. Nothing
picks a location on the operator's behalf, because a tool that decides for itself where several
gigabytes of evidence go is a tool that fills the wrong disk.

| File | What it is |
|---|---|
| `evidence.db` | The evidence. Present only on a bundle that finished |
| `evidence.db.seal` | The seal covering `evidence.db` |
| `annotations.db` | The customer's notes, acceptances and declared scope. Created empty at seal time |
| `evidence.db.partial` | A run that has not finished, or did not |

**The name is the mechanism.** A run writes `evidence.db.partial`. Renaming it to `evidence.db`
is the last act, after the write-ahead log is folded back in and after the seal is written. A
reader opens `evidence.db`, so a run that was interrupted has no file by that name to offer it.

This is the answer to *what stops a half-written bundle being opened and read as a whole one*, and
it is deliberately not a check. A check has to be remembered at every place a bundle is opened. A
name has to be remembered nowhere: the partial file is not called the thing readers ask for, and
that is true whether or not anybody thought about it.

**A crashed run and a running one are told apart, and the file system is what answers.** Both
present a `.partial` file and no `evidence.db`, so the files alone cannot say — but per
[`0029`](../decisions/0029-a-run-that-ends-badly-says-so.md) the question is whether anything still
holds the partial file open. Nothing does once the writing process ends, whatever ended it, because
the operating system releases handles when a process dies. `RunStateReader` performs that check. A
recorded heartbeat or a process identifier would need cleaning up after a crash, which is precisely
the moment nothing is running to clean it.

A run that ended badly also leaves `run-outcome.json` saying which ending it was. A missing outcome
file is not an error — it means the run stopped without being able to say why, which is reported as
*interrupted*.

> This section argued the opposite until 2026-08-13 — that the two are indistinguishable and that
> telling them apart would mean claiming to know something about a process that is not there to be
> asked. `0029` decided otherwise two days after that was written, and the argument was left
> standing here while `BundleLayout` recorded the correction.

**A failed run's `.partial` file is left where it is.** Nothing deletes it. Reclaiming disk on a
failure path destroys the only record of how far the run got, on a judgement made by the code that
has just failed, and the file has no name any reader asks for — so leaving it costs disk and never
a wrong answer.

**Why more than one file at all.** Write-ahead logging keeps recent changes in a `-wal` file
beside the database until a checkpoint folds them back
([copying a database](https://learn.microsoft.com/dotnet/maui/data-cloud/database-sqlite#advanced-configuration)),
so during a run the evidence is genuinely spread across several files. Write-ahead logging is on
because it is what the provider's guidance points to for throughput: SQLite has no asynchronous
I/O, and the async methods run synchronously
([async limitations](https://learn.microsoft.com/dotnet/standard/data/sqlite/async)). That is also
why every method on the writer is synchronous. An `async` surface here would await nothing and
mislead every caller about what it costs.

## The seal

The reasoning is `0019`. What matters at the
point of use:

**What it proves.** The bytes of `evidence.db` are the bytes that were there when the run declared
itself finished.

**What it does not prove.** It is not a signature and is deliberately not called one — there is no
key anywhere in this product, so anyone who can rewrite the evidence file can rewrite the seal
beside it. It catches corruption, truncation and casual editing, and not a determined party. It
says nothing about whether the capture was **complete**: that is a claim the bundle makes in its
own `bundle` and `partition_coverage` tables, and the seal only proves the claim has not been
edited since it was made. And it says nothing about whether the capture was correct.

**Verification has four outcomes**, and only the first opens a bundle.

| Outcome | What was observed |
|---|---|
| `Intact` | The seal is present, readable, and matches |
| `Absent` | There is no seal file. Unreachable for a bundle this product wrote, because sealing precedes the rename — so it means the directory was assembled by hand |
| `Unreadable` | A seal file exists and cannot be read. **Not** the same as `Absent`: the one thing that certainly happened is that something happened to the seal |
| `Mismatch` | The seal was read and the file does not match it |

Folding `Unreadable` into `Absent` would render a failure as a benign absence, which is the one
shape of defect an audit tool cannot have.

There is no cached verdict. Reopening a large bundle re-hashes it every time, which costs real
seconds on a bundle of some gigabytes. That cost is accepted, because a cache whose function is to
avoid performing an integrity check is a way for the check to silently never run.

## The tables

The rule every table below follows: per [`0002`](../decisions/0002-absent-view-means-degraded-run.md)
a missing answer is a fact about the capture and never about the forest. That question arrives
here one level down — an object with no permission rows either had no permissions or was never
read, and those are opposite findings that look identical if the only evidence is an empty result.

So **coverage is recorded positively, as rows, and never inferred from their absence.**

**An object is one row with typed columns**, per
[`0022`](../decisions/0022-objects-are-stored-as-typed-columns.md). Single-valued attributes are
columns on `captured_object`; each multi-valued attribute has a table to itself, holding its values
in the order the controller sent them. Both sets are derived from `CapturedAttributeCatalog` rather
than written out here, so the schema cannot ask for one set of attributes and store another.

**No column records why a value is missing**, and that is the one place the rule above is
deliberately not applied. It cannot be: Active Directory omits an absent attribute without saying
whether the caller was refused it, so *withheld* and *never set* arrive identically and a column
claiming to separate them would hold a guess rather than an observation. What a run could not see
is recorded where it *is* observable — per partition in `partition_coverage`, and by reference for
the things something pointed at and that were never seen.

<!-- TABLES:BEGIN -->

| Table | What one row is | What its absence means |
|---|---|---|
| `bundle` | The run's own account of itself: schema version, forest, when capture started and finished, the evidence identity of what it declared it would cover, and whether it covered it | A file that never reached the end of a run. It cannot be reached through `evidence.db`, because the row is written before the seal and the rename |
| `domain_coverage` | One domain the forest declared when the run started, and what became of it | Not reachable in a sealed bundle — every declared domain has a row. That is the point of the table: before it existed, a run that reached one domain of nine sealed a bundle in which the other eight were simply absent, and absence is what a reader cannot interpret |
| `forest_partition_coverage` | The configuration or schema partition, and what became of it | Not reachable in a sealed bundle — both are always reported. Held apart from `domain_coverage` because a run that could not read the schema partition has failed outright rather than found a domain with a problem |
| `partition_coverage` | One naming context, read from one controller, with what the pass consumed, the connection security it was read over, how many of its objects had unreadable descriptors, and whether referrals were suppressed | That naming context was never read. This is the row every other absence is interpreted against |
| `continuation_reference` | One referral a controller returned | No referrals were returned — which means *nothing lies below* only when the coverage row says referrals were not suppressed |
| `unread_partition` | One partition the forest declares that this product does not read — the application directory partitions, which in practice are the DNS zone partitions every forest has | The forest declared no such partition. Safe to read that way only because the rows are written before the first read and an incomplete run never seals, so an empty table cannot mean the run forgot to say |
| `excluded_domain` | One domain left out of this run, with the reason picked from the closed list, whatever the operator added in his own words, the account the run was made under, the name he gave as authorising it, and when he said so | No domain was excluded. It does **not** mean the attestation was not recorded. The `kind` column keeps a domain the operator took out apart from one the forest named no writable controller for — [`0063`](../decisions/0063-excluded-never-looks-like-unreachable.md) — and `authorised_by` is a typed string that nothing validated, so no reader may present it as a verified identity |
| `captured_object` | One object: the identity that survives a rename, where it sits in the tree, when it was read, and one typed column per single-valued attribute the catalogue asks for | The object was not read. Whether that is a fact about the forest depends on its partition's coverage row |
| `objectclass_value` | One class name from one object's `objectClass` | Not reachable for an object that was read at all — every object has a class, so an empty list here means the object's row should not be trusted |
| `description_value` | One line of an object's `description`, in the order the controller sent them | The object was never described, or the value was withheld. Multi-valued in the schema, which most tooling shows the first value of and calls the description |
| `member_value` | One member of one group, in the order the controller sent them | The group has no members, or membership was withheld. The two are one emptiness and the bundle does not claim to tell them apart |
| `memberof_value` | One group one object belongs to, as the directory reports it back-linked | The object is in no group other than its primary one, which is a column and not a row here |
| `sidhistory_value` | One security identifier an object carries from a migrated domain, as bytes | The object was never migrated, or its history was withheld. A row here is the finding; an absence is the ordinary case |
| `serviceprincipalname_value` | One service principal name registered on an account | The account runs no registered service — which is what makes an account with rows here worth looking at |
| `msds_allowedtodelegateto_value` | One service this account may delegate to | Constrained delegation is not configured on this account. Unconstrained delegation is a flag on `useraccountcontrol` and leaves nothing here |
| `msds_keycredentiallink_value` | One key credential registered against the account | No key credential is registered, or they were withheld. This is where a shadow-credential attack leaves its mark |
| `gpcmachineextensionnames_value` | One client-side extension a group policy object drives | The policy object drives no machine-side extension, or the value was withheld |
| `appliesto_value` | One class an extended right applies to | The right is not scoped to any class, which means it applies wherever its GUID appears rather than nowhere |
| `security_descriptor` | One **distinct** security descriptor, keyed on the SHA-256 of the bytes the controller sent, with those bytes, its owner, group, DACL state and the canonical hash of its whole entry set | No descriptor with those bytes was read anywhere in the forest. It is not a statement about any particular object — which objects carry it is `object_security_descriptor`'s question |
| `object_security_descriptor` | One object read together with the descriptor it was read with | Either no descriptor was read for that object, or none was attempted. Which of those it is depends on `unreadable_security_descriptor`: a row there means it was tried and failed, no row there means nothing was asked |
| `security_descriptor_error` | One reason a descriptor could not be fully parsed | That descriptor parsed cleanly. Without this table a descriptor that failed and an object granting nothing are the same thing: no rows in `ace` |
| `unreadable_security_descriptor` | One object whose security descriptor could not be read at all | Every object that was asked had its descriptor read. This table is the difference between *nobody knows what this object grants* and *this object grants nothing*, and on a production domain it was 19,927 objects in 100,000 |
| `unresolved_reference` | One thing an object pointed at — a group member, a permission trustee, a parent container, a primary group — that nothing in the run ever saw, and which of four reasons it was never seen for | Everything every object pointed at was also captured. An empty table is a strong claim, not a quiet one, and it is only trustworthy because the rows are written positively rather than inferred |
| `trustee` | One security identifier, once for the whole forest, and why it could not be resolved if it could not | That trustee appears in no entry anywhere |
| `ace` | One access control entry, already canonicalised, including inherited ones, belonging to a **descriptor** rather than to an object | That descriptor grants nothing — but only when it has no rows in `security_descriptor_error`. Which objects that applies to is reached through `object_security_descriptor` |
| `sysvol_gpo_coverage` | One Group Policy object the directory declared, with its display name and what became of its files: read, read in part, or not read, and why | The forest declares no Group Policy at all. This is the one table in the bundle where a failure is expected rather than fatal — per [`0044`](../decisions/0044-sysvol-coverage-is-recorded-beside-the-capture-units.md) a SYSVOL read that fails does not stop the run, so these rows are the only account of what was missed |
| `gpo_registry_setting` | One registry value a policy writes, with the raw type and bytes as the file held them, and whether it applies to the machine or the user | The policy configures no registry-backed settings — unless its row in `sysvol_gpo_coverage` says its files were not read, in which case nothing is known about what it configures |
| `gpo_security_setting` | One setting out of a policy's security template: the privileges it grants, the signing and channel-binding settings it can weaken | Same reading as above. SEC-064 and SEC-066 are answered from here |
| `gpo_restricted_group` | One principal a policy places into, or takes into, a privileged group on every machine it reaches, with which way round the membership goes | The policy imposes no group memberships. SEC-065 exists because this membership is invisible to every directory group rule |
| `gpo_stored_credential` | Where a policy stores a credential in its own files — the Group Policy Preferences defect of MS14-025 | No stored credential was found in the files that were read. **Presence only: neither the password nor the ciphertext is stored**, because the key protecting it is public and keeping it would rebuild the vulnerability inside the audit |
| `gpo_file_error` | One file inside a policy that was opened and could not be understood | Every file that was opened parsed cleanly. The same distinction `security_descriptor_error` draws: without it, a template that failed to parse and a policy that assigns no privileges are the same evidence |
| `sysvol_path_security_descriptor` | One path inside a policy's folder read together with its permissions, joined to the same descriptor and entry tables the directory's permissions use | Nothing under that policy was permission-read. How deep the read goes is set by [`0043`](../decisions/0043-a-gpos-file-permissions-are-read-below-the-root-folder.md): the policy folder, every folder beneath it, every file whose contents were read, and everything under `Machine\Scripts` and `User\Scripts` |
| `unreadable_sysvol_descriptor` | One path inside a policy whose permissions could not be read at all | Every path that was reached had its permissions read. The file-share counterpart of `unreadable_security_descriptor`, and it exists for the same reason: no rows in `ace` must not mean both *this path grants nothing* and *nobody could look* |
| `finding` | One thing a rule found, about one object: its rule, its subject, the object by `objectGUID`, the severity the rule fixed, and whether the evidence behind it was complete | No rule matched anything. It does not mean the rules were not run and it does not mean the forest is clean: a rule that could not read a declared input reaches no verdict under [`0083`](../decisions/0083-a-rule-declares-its-data-dependencies.md) and writes no row here, so a reader must consult the coverage tables before presenting an empty table as a clean forest |
| `finding_unconstrained_delegation` | What an unconstrained delegation finding rests on: the `userAccountControl` value, whether the object declared the computer class, and the three raw domain-controller signals | A defect rather than an absence with a meaning. Every finding SEC-010 or SEC-011 produces has exactly one row here, so a finding of that kind without one is a write that half happened |
| `evaluated_rule` | Which rules were run over this bundle, and at what version of their logic | The bundle was captured and never judged. This is what makes an empty `finding` table readable: no findings beside no rules means nobody looked, and no findings beside rules that ran means nothing matched. Presenting the first as a clean forest is the failure [`0002`](../decisions/0002-absent-view-means-degraded-run.md) forbids |

<!-- TABLES:END -->

### Descriptors are stored once, not once per object

A forest does not hold one security descriptor per object. It holds a few thousand distinct ones
repeated across millions of objects, mostly because they are inherited. Storing one row per object
measured **4.81 GB per 100,000 objects against 1.24 GB** for the same evidence stored once, and it
removed about three quarters of the parsing and inserting as well — the same descriptor was being
parsed, hashed and written again for every object that carried it.

So `security_descriptor` is keyed on the SHA-256 of the descriptor's bytes, `ace` hangs off the
descriptor rather than the object, and `object_security_descriptor` records which objects were read
with which. `captured_object.ace_count` still answers "how many entries does *this* object have",
because that is a question about the object even when the answer is shared.

**The hash is cryptographic, and not out of caution.** A collision here would not corrupt a row; it
would silently give one object another object's permissions, which is the one failure an audit tool
cannot have. The byte length is stored beside the hash so a collision would have to agree on two
things rather than one.

**The raw bytes are stored too**, at about 13% on top of the parsed entries — the raw form is
smaller than what parsing it produces. That is the difference between repairing a defect in the
parser by re-analysing bundles already captured, and repairing it by asking a customer to re-read
his entire forest.

### Three states, not two, for what an object grants

An object with no entries can mean three different things, and before this schema they looked
identical:

- It **grants nothing** — a row in `object_security_descriptor`, a descriptor whose DACL state is
  `Empty`, and no errors.
- Its descriptor **could not be parsed** — a row in `object_security_descriptor` and rows in
  `security_descriptor_error`.
- Its descriptor **could not be read at all** — a row in `unreadable_security_descriptor`, and
  `ace_count` left null rather than zero.

> **Corrected 2026-08-13 in `S-21`, as `F-S21-1`.** The
> second bullet was true about the error rows and wrong about the state beside them. A descriptor
> that could not be parsed still recorded `dacl_state = 'Empty'` — so the one field a reader
> consults to learn *what does this object grant* said **grants nothing**, which is the most
> locked-down answer there is, about an object nobody had managed to read. The error rows were
> beside it and nothing obliged anyone to look at them.
>
> [`0037`](../decisions/0037-an-unreadable-dacl-says-so.md) adds `Unreadable`, and it turns out
> there is a **fourth** case this section did not have either: a DACL that yielded *some* of what it
> declared. That one is genuinely `Present` — it is present, and saying otherwise would be a
> different lie — so the shortfall is carried by `dacl_completeness` instead, which is
> `Complete`, `Incomplete` or `Unknown`. A state answers *what is this*; the completeness answers
> *did we get all of it*, and putting the second into the first would have made the state a
> judgement rather than a fact.

The third is not a rare case. A production domain returned 19,927 of 100,000 objects with no
readable descriptor, and the predecessor's writer returned early on exactly that condition with its
only counter sitting below the return — so a fifth of a domain was unknown and no number anywhere
said so. The count is now kept per partition on `partition_coverage.unreadable_descriptors`, so a
reader can get from *this many were unreadable* to the controller they were unreadable on. The run
total is the sum of those rows and is not stored separately, because a stored total is a second fact
that can drift from the first.

### Whether the DACL arrived in the order the directory stored it
`security_descriptor.dacl_was_canonical` records one thing normalisation destroys.

Windows evaluates a DACL in stored order and stops at the first entry that matches, so an allow
placed before a deny grants what the canonical form denies. `AceNormalizer` sorts every DACL into
canonical order — which it must, or `ace_hash` and `ace_set_hash` would change every time the
directory returned entries in a different order — and after that nothing says the directory held it
differently.

Exact order is **not** stored. `raw_bytes` is already here, so re-parsing recovers it precisely, and
a per-entry ordinal would be a second copy of a fact the bundle already holds. What was missing was
a way to ask the question over a whole forest without re-parsing several million descriptors, and a
boolean with a partial index on the `0` rows answers it for nothing on a forest where the answer is
zero. Required by [`0038`](../decisions/0038-a-descriptor-records-whether-its-dacl-was-canonical.md).

**The flag describes the entries the product understood.** An entry whose type is not one of the ten
`AceType` names is skipped when the order is judged, because the alternative is to guess where it
belongs and let that guess decide the answer. That is honest only because such an entry is still
visible, which is the next section.

### `ace_type` holds a number when the product has no name for the type

`ace.ace_type` is `TEXT` and holds the member name — `AccessAllowed`, `AccessDeniedObject` — for the
ten types [security descriptors](../kernel/security-descriptors.md) names. For any other type byte **it holds the
number**: `0x12` is stored as `"18"`.

**That is deliberate, and it is the only reason anything else in this schema can afford to ignore an
unmodelled entry.** It makes *which entries did this product not understand* a query against
evidence already stored —

```sql
SELECT * FROM ace WHERE ace_type GLOB '[0-9]*'
```

— rather than a re-parse of every descriptor in the bundle, and it means such an entry is never
silently dropped, normalised into a neighbouring type, or recorded as damage it is not.

It began as an accident. The column holds `ace.AceType.ToString()`, and .NET renders an undefined
enum value as its number, so the behaviour was free and undocumented. `S-21` found the whole
treatment of unrecognised types resting on it, and `BundleWriterTests` now holds it in both
directions: casting to `(int)` or normalising unknowns to a placeholder each fail the build.

### What identifies an object

`object_guid`, and not the distinguished name and not the row identifier.
A distinguished name changes the moment somebody renames an object or moves it between
organisational units, and the row identifier is local to one file. Two bundles joined on either
would report a moved object as one object deleted and a different one created — a change the
customer did not make, reported as a change they did.

It is nullable, because an identity that did not arrive is not invented. An object with no
identity cannot take part in a comparison, and a reader has to be able to see that rather than be
handed a placeholder that quietly joins to nothing.

The writer also refuses a security descriptor whose own view of which object it belongs to
disagrees with the object it is being written against. There is no way to tell which side is
wrong, so the run ends rather than attributing one object's permissions to another.

### The hash of a whole entry set

Every descriptor carries `ace_set_hash`, computed by `AceSetHash` in the kernel and required by
[`0015`](../decisions/0015-a-bundle-names-a-pattern-it-never-explains-one-away.md).

It exists for comparison. Asking whether an object's permissions changed between two runs by
reading every entry of every object is the query that makes comparison too slow to use, and
comparison is the only verification path this product has left since
[`0008`](../decisions/0008-live-verification-is-removed.md) removed live checking. One value per
object turns that question into an equality test.

The canonicalisation version is inside the hash, so two values produced by different pipelines can
never compare equal by coincidence — a comparison reporting *unchanged* across a pipeline change
would be the product saying something false. An empty entry set has a hash like any other, so a
reader never has to decide what a missing value means; whether an empty set means *grants nothing*
or *grants everyone everything* is what the DACL state beside it answers.

### Three things stored that a smaller design would leave out
**The DACL state**, as its own value. A null DACL and an empty DACL mean opposite things — one
grants everyone everything, the other grants nobody anything — and both produce no rows in `ace`.
**Parse errors.** A descriptor that could not be read produces no entries in exactly the way an
object granting nothing does. Reporting the second as the first would tell a customer an object is
safe when nobody knows whether it is.

**Inherited entries.** Skipping them was a defensible size saving and it forces the read side to
reconstruct inheritance — recomputing what the directory already told us, and being wrong wherever
the reconstruction disagrees.

### What is not stored, and what replaced it

There is no materialised ACL payload column and no binary codec for one. Entries go in their own
table, and a trustee's security identifier goes in a shared one, so an entry carries an integer
where it would have carried a forty-character string. That squeezes the repetition **across the
whole forest** rather than within one object's list — a domain's administrators appear in access
control lists on hundreds of thousands of objects, and a table scoped to one payload could not
look past the object it was inside. The reasoning, and the fact that it is an argument rather than
a measurement, is in `S-15` and F-S15-1.

### Indexes

Indexes are created **after** the writing, not before. A forest is millions of objects, and an
index maintained during ingest is paid for on every insert and read by nobody until the run is
over.

Two passes over the whole table run immediately after the indexes are built, and the order is not
incidental — both join on a column those indexes have just created, and either would be a scan per
row if it ran first. One fills in each object's `parent_guid` by stripping the leading relative name
and matching what is left against `distinguished_name`; the other fills in each object's
`ace_count`. The parent pass writes its own failures: an object whose parent DN matches nothing is
an object whose container nobody captured, so the same query that resolves the edge records the gap
in `unresolved_reference`, and the two cannot disagree because they are one statement.

### The page size is set with the schema, and can never be set later

`page_size` is fixed by SQLite when the first table is created; after that only a full `VACUUM` can
change it, and a sealed bundle will never get one. So it is set before `CREATE TABLE` and before the
database enters write-ahead logging mode, which also locks it.

It is **8192**, against a 4096 default. Descriptors on a production domain averaged 31,742 bytes,
which no supported page size holds inline, so the only question is how long the overflow chain is —
and doubling the page halves it. It is not raised further because a bundle is not mostly
descriptors: `ace`, `trustee` and `captured_object` are small rows and there are millions of them,
and a 32 KB page would make every one of those reads fetch far more than it needs in order to serve
the minority that are large.

### Where an object sits, and when it was read

Five columns on `captured_object` are not derived from the attribute catalogue, because each answers
a question about the object's place in the forest rather than about one of its attributes.

`dn_reversed` turns "everything under this organisational unit" from a scan into an indexed range —
see [`S-2`](S-2-distinguished-name-manipulation.md). `parent_guid` is the containment edge, resolved
in one pass when writing finishes. `domain_fqdn` is on the row so a forest-wide question does not
have to parse a distinguished name. `captured_utc` is **per row**, because a capture of a large
forest is hours rather than an instant and two objects in one bundle can have been read far enough
apart for one to have changed after the other was seen; a single run-level timestamp would quietly
claim they were a snapshot. `ace_count` is null until a descriptor is written and stays null for an
object whose descriptor could not be read — which is a different thing from zero, and the
distinction the descriptor tables exist to keep.

**The deleted flag does not come across.** It was instructed until 2026-08-12, and capture never
reads `isDeleted`, so the column would have been false on every row of every bundle forever.

### No migrations

There is no schema migration path and no column added conditionally on open. Per
[`0001`](../decisions/0001-no-backward-compatibility.md) nothing is kept backward compatible and
per [`0013`](../decisions/0013-the-bundle-is-no-longer-a-two-way-contract.md) the bundle is not a
contract with anything, so a schema mismatch is a broken build rather than an old file. The schema
version is recorded so a reader can refuse a bundle it does not understand, not so it can adapt to
one.

## What is refused, and what is recorded

These are two different things and the difference is the most important sentence in this document.

**A value this product cannot represent ends the run.** Capture is fail-fast and there is no
partial bundle, so an object that cannot be written down is not logged and skipped. Four cases: an
attribute still part-way through a range retrieval, which has no spelling in the stored vocabulary
at all; a value that is neither text nor bytes, because a value coerced through `ToString` is not
an error that surfaces but a mangled string that looks like data; a value whose kind disagrees with
the kind the catalogue declares, which SQLite will otherwise store without complaint because a
column's declared type is an affinity and not a constraint; and an attribute the catalogue does not
name, which has no column and no table and would otherwise be dropped in silence.

The range-retrieval refusal used to happen twice — once in the vocabulary and once as a constraint
on a column that no longer exists. It now happens once. The remaining wall is the stronger of the
two, because a missing enum member cannot be forgotten in the way a check can, but the redundancy
is genuinely gone and is recorded as `F-S24-6` rather than left to be discovered.

**A fact about the customer's forest is recorded, however bad it is.** A security descriptor the
directory holds and this product could not parse is stored, with its errors. So is a partition read
with referrals suppressed. So is an object whose identity never arrived.

Conflating the two is how a real finding about a real domain gets thrown away as a bug in the
reader.

## One way in

There is one entry point and it takes the directory the bundle is written into. **Where that
directory comes from is not the caller's choice**: per
[`0025`](../decisions/0025-the-run-library-is-a-managed-root.md) the tool owns a configured root and
creates each run inside it, and capture to an arbitrary path is not offered. The writer sits below
that decision — it is handed a directory and writes there — and the component that turns the root
into this run's directory is inventory row `F11`, which is not built.

Re-analysis is a second way in and it **does** come across, per
[`0021`](../decisions/0021-re-analysis-produces-a-new-bundle.md): it derives into a new bundle from a
sealed one and never touches the original. This section previously said the opposite, on the grounds
that re-analysis destroyed the original capture's seal — a claim taken from the map and contradicted
by the code.

The writer knows nothing about a window. There is one way to start a capture and it runs unattended,
per [`0039`](../decisions/0039-one-way-to-start-a-capture.md); a window drives that same entry point
rather than being a second one.

