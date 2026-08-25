# What a bundle holds

**Code:** `next/src/SecureAD.Evidence/BundleSchema.cs`, `BundleWriter.cs`
**Layer:** Evidence — the shape of the only thing this product ever reads from.

Every table in a bundle, what one row of it is, and what its absence means. Everything this product
says, it says from here; nothing is said from a live directory. That is what lets a finding be
reproduced a year later on a machine that has never seen the forest.

Bound by `BundleDocumentationTests`, which creates the schema in a real database and compares the
table list below against `sqlite_master` in both directions. A table named here and absent from the
schema fails the build, and so does a table the schema creates and this page does not name. It also
fails a row whose *absence* column is under thirty characters, because a table whose emptiness
nobody has interpreted is the defect this schema is arranged to prevent.

---

## The rule the whole shape follows

Per [`0002`](../../decisions/0002-absent-view-means-degraded-run.md) a missing answer is a fact about
the capture and never about the forest. That question arrives here one level down: an object with no
permission rows either had no permissions or was never read, and those are opposite findings that
look identical if the only evidence is an empty result.

So **coverage is recorded positively, as rows, and never inferred from their absence.** What was
read has a `partition_coverage` row; what was not read has none. A descriptor that failed to parse
stores its errors, because zero entries with no errors means *this object grants nothing* while zero
with errors means *nobody knows what this object grants*.

**All schema lives in one file.** No writer creates its own table, so `CREATE TABLE` appears in one
place and a writer cannot quietly invent a column that nothing else knows to read.

**An object is one row with typed columns**, per
[`0022`](../../decisions/0022-objects-are-stored-as-typed-columns.md). Single-valued attributes are
columns on `captured_object`; each multi-valued attribute has a table to itself, holding its values
in the order the controller sent them. Both sets are derived from `CapturedAttributeCatalog` rather
than written out, so the schema cannot ask for one set of attributes and store another. A
hand-written list agrees with the catalogue on the day it is written and stops agreeing the first
time an attribute is added.

**No column records why a value is missing**, and that is the one place the rule above is
deliberately not applied. It cannot be: Active Directory omits an absent attribute without saying
whether the caller was refused it, so *withheld* and *never set* arrive identically and a column
claiming to separate them would hold a guess rather than an observation. What a run could not see is
recorded where it *is* observable — per partition in `partition_coverage`, and by reference for the
things something pointed at and never saw.

---

## The tables

<!-- TABLES:BEGIN -->

| Table | What one row is | What its absence means |
|---|---|---|
| `bundle` | The run's own account of itself: schema version, forest, when capture started and finished, the evidence identity of what it declared it would cover, and whether it covered it | A file that never reached the end of a run. It cannot be reached through `evidence.db`, because the row is written before the seal and the rename |
| `domain_coverage` | One domain the forest declared when the run started, and what became of it | Not reachable in a sealed bundle — every declared domain has a row. That is the point of the table: before it existed, a run that reached one domain of nine sealed a bundle in which the other eight were simply absent, and absence is what a reader cannot interpret |
| `forest_partition_coverage` | The configuration or schema partition, and what became of it | Not reachable in a sealed bundle — both are always reported. Held apart from `domain_coverage` because a run that could not read the schema partition has failed outright rather than found a domain with a problem |
| `partition_coverage` | One naming context, read from one controller, with what the pass consumed, the connection security it was read over, how many of its objects had unreadable descriptors, and whether referrals were suppressed | That naming context was never read. This is the row every other absence is interpreted against |
| `continuation_reference` | One referral a controller returned | No referrals were returned — which means *nothing lies below* only when the coverage row says referrals were not suppressed |
| `unread_partition` | One partition the forest declares that this product does not read — the application directory partitions, which in practice are the DNS zone partitions every forest has | The forest declared no such partition. Safe to read that way only because the rows are written before the first read and an incomplete run never seals, so an empty table cannot mean the run forgot to say |
| `excluded_domain` | One domain left out of this run, with the reason picked from the closed list, whatever the operator added in his own words, the account the run was made under, the name he gave as authorising it, and when he said so | No domain was excluded. It does **not** mean the attestation was not recorded. The `kind` column keeps a domain the operator took out apart from one the forest named no writable controller for — [`0063`](../../decisions/0063-excluded-never-looks-like-unreachable.md) — and `authorised_by` is a typed string that nothing validated, so no reader may present it as a verified identity |
| `captured_object` | One object: the identity that survives a rename, where it sits in the tree, when it was read, and one typed column per single-valued attribute the catalogue asks for | The object was not read. Whether that is a fact about the forest depends on its partition's coverage row |
| `objectclass_value` | One class name from one object's `objectClass` | Not reachable for an object that was read at all — every object has a class, so an empty list here means the object's row should not be trusted |
| `description_value` | One line of an object's `description`, in the order the controller sent them | The object was never described, or the value was withheld. Multi-valued in the schema, which most tooling shows the first value of and calls the description |
| `member_value` | One member of one group, in the order the controller sent them | The group has no members, or membership was withheld. The two are one emptiness and the bundle does not claim to tell them apart |
| `memberof_value` | One group one object belongs to, as the directory reports it back-linked | The object is in no group other than its primary one, which is a column and not a row here |
| `sidhistory_value` | One security identifier an object carries from a migrated domain, as bytes | The object was never migrated, or its history was withheld. A row here is the finding; an absence is the ordinary case |
| `msds_psoappliesto_value` | One user or group a fine-grained password policy applies to, as a distinguished name | The policy names nobody, or the list was withheld. The only multi-valued attribute of a policy settings object, so the only one that gets a table rather than a column |
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
| `sysvol_gpo_coverage` | One Group Policy object the directory declared, with its display name and what became of its files: read, read in part, or not read, and why | The forest declares no Group Policy at all. This is the one table in the bundle where a failure is expected rather than fatal — per [`0044`](../../decisions/0044-sysvol-coverage-is-recorded-beside-the-capture-units.md) a SYSVOL read that fails does not stop the run, so these rows are the only account of what was missed |
| `gpo_registry_setting` | One registry value a policy writes, with the raw type and bytes as the file held them, and whether it applies to the machine or the user | The policy configures no registry-backed settings — unless its row in `sysvol_gpo_coverage` says its files were not read, in which case nothing is known about what it configures |
| `gpo_security_setting` | One setting out of a policy's security template: the privileges it grants, the signing and channel-binding settings it can weaken | Same reading as above. SEC-064 and SEC-066 are answered from here |
| `gpo_restricted_group` | One principal a policy places into, or takes into, a privileged group on every machine it reaches, with which way round the membership goes | The policy imposes no group memberships. SEC-065 exists because this membership is invisible to every directory group rule |
| `gpo_stored_credential` | Where a policy stores a credential in its own files — the Group Policy Preferences defect of MS14-025 | No stored credential was found in the files that were read. **Presence only: neither the password nor the ciphertext is stored**, because the key protecting it is public and keeping it would rebuild the vulnerability inside the audit |
| `gpo_file_error` | One file inside a policy that was opened and could not be understood | Every file that was opened parsed cleanly. The same distinction `security_descriptor_error` draws: without it, a template that failed to parse and a policy that assigns no privileges are the same evidence |
| `sysvol_path_security_descriptor` | One path inside a policy's folder read together with its permissions, joined to the same descriptor and entry tables the directory's permissions use | Nothing under that policy was permission-read. How deep the read goes is set by [`0043`](../../decisions/0043-a-gpos-file-permissions-are-read-below-the-root-folder.md): the policy folder, every folder beneath it, every file whose contents were read, and everything under `Machine\Scripts` and `User\Scripts` |
| `unreadable_sysvol_descriptor` | One path inside a policy whose permissions could not be read at all | Every path that was reached had its permissions read. The file-share counterpart of `unreadable_security_descriptor`, and it exists for the same reason: no rows in `ace` must not mean both *this path grants nothing* and *nobody could look* |
| `finding` | One thing a rule found, about one object: its rule, its subject, the object by `objectGUID`, the severity the rule fixed, and whether the evidence behind it was complete | No rule matched anything. It does not mean the rules were not run and it does not mean the forest is clean: a rule that could not read a declared input reaches no verdict under [`0083`](../../decisions/0083-a-rule-declares-its-data-dependencies.md) and writes no row here, so a reader must consult the coverage tables before presenting an empty table as a clean forest |
| `finding_unconstrained_delegation` | What an unconstrained delegation finding rests on: the `userAccountControl` value, whether the object declared the computer class, and the three raw domain-controller signals | A defect rather than an absence with a meaning. Every finding SEC-010 or SEC-011 produces has exactly one row here, so a finding of that kind without one is a write that half happened |
| `evaluated_rule` | Which rules were run over this bundle, and at what version of their logic | The bundle was captured and never judged. This is what makes an empty `finding` table readable: no findings beside no rules means nobody looked, and no findings beside rules that ran means nothing matched. Presenting the first as a clean forest is the failure [`0002`](../../decisions/0002-absent-view-means-degraded-run.md) forbids |

<!-- TABLES:END -->

Twenty-six of these are fixed. The ten `_value` tables are derived, one per multi-valued attribute
in the catalogue, and appear or disappear with it.

---

## Descriptors are stored once, not once per object

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

**The writer refuses a descriptor whose own view of which object it belongs to disagrees with the
object it is being written against.** There is no way to tell which side is wrong, so the run ends
rather than attributing one object's permissions to another.

### Three states, not two, for what an object grants

An object with no entries can mean three different things, and before this schema they looked
identical:

- It **grants nothing** — a row in `object_security_descriptor`, a descriptor whose DACL state is
  `Empty`, and no errors.
- Its descriptor **could not be parsed** — a row in `object_security_descriptor`, rows in
  `security_descriptor_error`, and a DACL state of `Unreadable`.
- Its descriptor **could not be read at all** — a row in `unreadable_security_descriptor`, and
  `ace_count` left null rather than zero.

There is a fourth case that is not a fourth state. A DACL that yielded *some* of what it declared is
genuinely `Present` — it is present, and saying otherwise would be a different lie — so the
shortfall is carried by `dacl_completeness` instead, which is `Complete`, `Incomplete` or `Unknown`.
A state answers *what is this*; the completeness answers *did we get all of it*, and putting the
second into the first would make the state a judgement rather than a fact. Both are indexed
partially, on the rows that are not the healthy value, so the forest-wide question costs nothing on
a forest where the answer is none.

The third case is not rare. A production domain returned 19,927 of 100,000 objects with no readable
descriptor, and the predecessor's writer returned early on exactly that condition with its only
counter sitting below the return — so a fifth of a domain was unknown and no number anywhere said
so. The count is now kept per partition on `partition_coverage.unreadable_descriptors`, so a reader
can get from *this many were unreadable* to the controller they were unreadable on. The run total is
the sum of those rows and is not stored separately, because a stored total is a second fact that can
drift from the first.

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
zero. Required by [`0038`](../../decisions/0038-a-descriptor-records-whether-its-dacl-was-canonical.md).

**The flag describes the entries the product understood.** An entry whose type is not one of the ten
`AceType` names is skipped when the order is judged, because the alternative is to guess where it
belongs and let that guess decide the answer. That is honest only because such an entry is still
visible, which is the next section.

### `ace_type` holds a number when the product has no name for the type

`ace.ace_type` is `TEXT` and holds the member name — `AccessAllowed`, `AccessDeniedObject` — for the
ten types [security descriptors](../kernel/security-descriptors.md) names. For any other type byte
**it holds the number**: `0x12` is stored as `"18"`.

**That is deliberate, and it is the only reason anything else in this schema can afford to ignore an
unmodelled entry.** It makes *which entries did this product not understand* a query against
evidence already stored —

```sql
SELECT * FROM ace WHERE ace_type GLOB '[0-9]*'
```

— rather than a re-parse of every descriptor in the bundle, and it means such an entry is never
silently dropped, normalised into a neighbouring type, or recorded as damage it is not.

It began as an accident. The column holds `ace.AceType.ToString()`, and .NET renders an undefined
enum value as its number, so the behaviour was free and undocumented. The whole treatment of
unrecognised types was found resting on it, and `BundleWriterTests` now holds it in both directions:
casting to `(int)` or normalising unknowns to a placeholder each fail the build.

### The hash of a whole entry set

Every descriptor carries `ace_set_hash`, computed by `AceSetHash` in the kernel and required by
[`0015`](../../decisions/0015-a-bundle-names-a-pattern-it-never-explains-one-away.md).

It exists for comparison. Asking whether an object's permissions changed between two runs by reading
every entry of every object is the query that makes comparison too slow to use, and comparison is
the only verification path this product has left since
[`0008`](../../decisions/0008-live-verification-is-removed.md) removed live checking. One value per
object turns that question into an equality test.

The canonicalisation version is inside the hash, so two values produced by different pipelines can
never compare equal by coincidence — a comparison reporting *unchanged* across a pipeline change
would be the product saying something false. An empty entry set has a hash like any other, so a
reader never has to decide what a missing value means; whether an empty set means *grants nothing*
or *grants everyone everything* is what the DACL state beside it answers.

`security_descriptor.canonicalization_version` records the recipe separately, and it is not the same
number as `schema_version`: that one describes these table shapes, this one describes the kernel's
output, and a build can read every column here and still be unable to reproduce a single hash. What
that column is sourced from, and why that matters more than the number it currently holds, belongs
to the read side and is `P-3` on the punch list.

### What is not stored, and what replaced it

There is no materialised ACL payload column and no binary codec for one. Entries go in their own
table, and a trustee's security identifier goes in a shared one, so an entry carries an integer
where it would have carried a forty-character string. That squeezes the repetition **across the
whole forest** rather than within one object's list — a domain's administrators appear in access
control lists on hundreds of thousands of objects, and a table scoped to one payload could not look
past the object it was inside.

**Inherited entries are stored.** Skipping them was a defensible size saving — the predecessor
measured 80–90% — and it is reversed because it makes the graph provably wrong: containment is
modelled nowhere in derivation, so a principal holding control on a container produced no edges to
anything beneath it, and paths, chokepoint counts and Tier 0 reachability were all computed from a
graph missing most of its edges.

---

## Where an object sits, and when it was read

**Six columns on `captured_object` are not derived from the attribute catalogue**, because each
answers a question about the object's place in the forest rather than about one of its attributes.

| Column | What it answers |
|---|---|
| `dn_reversed` | Turns "everything under this organisational unit" from a scan into an indexed range — see [distinguished name manipulation](../kernel/naming.md) |
| `parent_dn` | The name of the container one level up, written as each object is stored |
| `parent_guid` | The containment edge it resolves to, filled in one pass when writing finishes |
| `domain_fqdn` | On the row so a forest-wide question does not have to parse a distinguished name |
| `captured_utc` | **Per row**, because a capture of a large forest is hours rather than an instant |
| `ace_count` | Null until a descriptor is written, and null for an object whose descriptor could not be read |

**`parent_dn` is a stored column rather than something SQL derives, and that is the interesting
one.** A distinguished name looks like a delimited list and is not one: `CN=Smith\, John` carries a
comma that separates nothing, and SQL has no way to tell it from one that does. The parent was cut
here on the first comma until that was found, which gave such an object a container that does not
exist and left it outside the containment tree inherited permissions travel down. `DnHelper.GetParentDn`
knows the difference, so the answer is computed once by something that does and written down.

The same fault had a second half. A naming context root has no parent inside the bundle and is not a
gap — and it was excluded by the *absence of a comma*, which holds only for a root of a single
label, and so reported the root domain of substantially every real forest as a container the run
failed to capture. It is now excluded by matching what capture recorded as a naming context, so a
partition this product has never heard of behaves correctly.

`captured_utc` is per row because two objects in one bundle can have been read far enough apart for
one to have changed after the other was seen; a single run-level timestamp would quietly claim they
were a snapshot. `ace_count` null against zero is the distinction the descriptor tables exist to
keep: null means *nobody knows*, zero means *this object grants nothing*.

**The deleted flag does not come across.** It was instructed until it was found that capture never
reads `isDeleted`, so the column would have been false on every row of every bundle for ever.

---

## The order writing happens in, and why each step is where it is

`Complete` is the whole design in one method.

1. **The per-partition tallies of unreadable descriptors** are written from memory, once. An
   `UPDATE` per unreadable descriptor would rewrite the same coverage row twenty thousand times on
   a domain like the one that produced the 19,927.
2. **The `bundle` row**, then **domain coverage**, **forest partition coverage** and **SYSVOL
   coverage**. All four are what *became of* the read and are not known until the read is over.
3. **The transaction commits.**
4. **The indexes are created** — after the writing, never before. A forest is millions of objects,
   and an index maintained during ingest is paid for on every insert and read by nobody until the
   run is over.
5. **Two set-based passes run, and the order is not incidental.** One fills in each object's
   `parent_guid` by matching `parent_dn` against `distinguished_name`; the other fills in each
   object's `ace_count`. Both join on a column the indexes have just created, and either would be a
   scan per row if it ran first. The parent pass writes its own failures: an object whose parent DN
   matches nothing is an object whose container nobody captured, so the same query that resolves the
   edge records the gap in `unresolved_reference`, and the two cannot disagree because they are one
   statement.
6. **The write-ahead log is folded back in**, before the hash. A hash taken while changes are still
   in the log covers a database that is not all there.
7. **The seal is written**, over the partial file.
8. **The annotations sidecar is created**, so that opening a bundle never writes to it.
9. **The rename happens last**, because it is the act that makes the bundle readable at all.

### The page size is set with the schema, and can never be set later

`page_size` is fixed by SQLite when the first table is created; after that only a full `VACUUM` can
change it, and a sealed bundle will never get one. So it is set before `CREATE TABLE` and before the
database enters write-ahead logging mode, which also locks it. Setting it afterwards would be a line
that reads as configuration and does nothing.

It is **8192**, against a 4096 default. Descriptors on a production domain averaged 31,742 bytes,
which no supported page size holds inline, so the only question is how long the overflow chain is —
and doubling the page halves it. It is not raised further because a bundle is not mostly
descriptors: `ace`, `trustee` and `captured_object` are small rows and there are millions of them,
and a 32 KB page would make every one of those reads fetch far more than it needs in order to serve
the minority that are large.

### Why write-ahead logging at all

It is what the provider's guidance points to for throughput, because SQLite has no asynchronous I/O
and the async methods run synchronously. That is also why every method on the writer is synchronous.
An `async` surface here would await nothing and mislead every caller about what it costs. It costs
the checkpoint in step 6.

### No migrations

There is no schema migration path and no column added conditionally on open. Per
[`0001`](../../decisions/0001-no-backward-compatibility.md) nothing is kept backward compatible and per
[`0013`](../../decisions/0013-the-bundle-is-no-longer-a-two-way-contract.md) the bundle is not a
contract with anything, so a schema mismatch is a broken build rather than an old file. The schema
version is recorded so a reader can refuse a bundle it does not understand, not so it can adapt to
one. It stands at **6**, raised when `finding` was added: a version 5 bundle has no findings table,
so a build that read one without refusing would report no findings and be telling the truth about
the table while lying about the forest.

---

## What is refused, and what is recorded

These are two different things and the difference is the most important sentence on this page.

**A value this product cannot represent ends the run.** Capture is fail-fast and there is no partial
bundle, so an object that cannot be written down is not logged and skipped.

| Refused | Why it cannot be stored and skipped |
|---|---|
| An attribute still part-way through a range retrieval | It has no spelling in the stored vocabulary at all |
| A value that is neither text nor bytes | A value coerced through `ToString` is not an error that surfaces, it is a mangled string that looks like data |
| A value whose kind disagrees with the kind the catalogue declares | SQLite stores it without complaint, because a column's declared type is an affinity and not a constraint — so the typed columns are only as honest as this check |
| An attribute the catalogue does not name | There is no column and no table, so it would otherwise be dropped in silence |
| More than one value for an attribute the catalogue calls single-valued | One column cannot hold them, and choosing one would discard evidence |
| An attribute offering values while stating it did not come back | Both cannot be true, and storing the values would let a reader treat withheld values as observed ones |
| A descriptor whose own object identity disagrees with the object it is written against | There is no way to tell which side is wrong, and a permission reported against the wrong object is the failure an audit tool cannot have |
| An object whose partition has no coverage row yet | Coverage is what an absence is interpreted against, so an object filed under the wrong partition silently changes what its neighbours' absence means |

**A fact about the customer's forest is recorded, however bad it is.** A security descriptor the
directory holds and this product could not parse is stored, with its errors. So is a partition read
with referrals suppressed. So is an object whose identity never arrived — `object_guid` is nullable,
because an identity that did not arrive is not invented, and an object with no identity cannot take
part in a comparison and a reader has to be able to see that rather than be handed a placeholder
that quietly joins to nothing.

Conflating the two is how a real finding about a real domain gets thrown away as a bug in the
reader.

---

## One way in

There is one entry point and it takes the directory the bundle is written into. **Where that
directory comes from is not the caller's choice**: per
[`0025`](../../decisions/0025-the-run-library-is-a-managed-root.md) the tool owns a configured root and
creates each run inside it, and capture to an arbitrary path is not offered. The writer sits below
that decision — it is handed a directory and writes there.

**A bundle is never written over.** An existing `evidence.db` in the target directory ends the call:
a bundle is sealed evidence of one forest at one moment, so a second capture goes to a new
directory.

Re-analysis is a second way in and it derives into a new bundle from a sealed one, never touching
the original, per [`0021`](../../decisions/0021-re-analysis-produces-a-new-bundle.md).

The writer knows nothing about a window. There is one way to start a capture and it runs unattended,
per [`0039`](../../decisions/0039-one-way-to-start-a-capture.md); a window drives that same entry point
rather than being a second one.

---

## What is built

Each capability names the test that proves it. **The test is the evidence; this table is only the
index.**

| An operator can… | Proven by | Confirmed in lab |
|---|---|---|
| be certain a bundle is never written over | `BundleWriterTests.ABundleIsNeverWrittenOver` |  |
| be certain nothing can be added after a bundle is sealed | `BundleWriterTests.NothingCanBeAddedAfterTheBundleIsSealed` |  |
| tell a descriptor that could not be parsed from an object that grants nothing | `BundleWriterTests.ADescriptorThatCouldNotBeParsedIsDistinguishableFromAnObjectThatGrantsNothing` |  |
| be certain the DACL state is stored rather than inferred from an empty entry list | `BundleWriterTests.TheDaclStateIsStoredRatherThanInferredFromAnEmptyEntryList` |  |
| find non-canonical descriptors without reading every entry | `BundleWriterTests.NonCanonicalDescriptorsCanBeFoundWithoutReadingEveryEntry` |  |
| find entries this product does not model, rather than losing them | `BundleWriterTests.EntriesThisProductDoesNotModelCanBeFoundByQueryingAceType` |  |
| tell an attribute that did not come back from one that has no values | `BundleWriterTests.AnAttributeWithNoValuesIsStoredTheSameWayAsOneThatDidNotComeBack` |  |
| be certain the writer refuses an attribute the catalogue does not name | `BundleWriterTests.TheWriterRefusesAnAttributeTheCatalogueDoesNotName` |  |
| be certain a descriptor belonging to a different object is refused | `BundleWriterTests.ADescriptorBelongingToADifferentObjectIsRefused` |  |
| see which partitions a run declined to read, stated in the evidence | `BundleWriterTests.APartitionTheRunDeclinedToReadIsStatedInTheEvidence` |  |
| find an object by an identity that survives a rename or a move | `BundleWriterTests.AnObjectIsStoredWithTheIdentityThatSurvivesARenameOrMove` |  |
| see the connection security a partition was read over | `BundleWriterTests.TheConnectionSecurityAPartitionWasReadOverIsRecorded` |  |
| be certain a container nobody captured is recorded as an unresolved reference | `BundleWriterTests.AContainerThatWasNeverCapturedIsRecordedAsAnUnresolvedReference` |  |
| be certain every catalogue attribute is stored somewhere | `BundleSchemaTests.EveryCatalogueAttributeIsStoredSomewhere` |  |
| be certain no two catalogue attributes collide on a column name | `BundleSchemaTests.NoTwoCatalogueAttributesShareAColumnName` |  |
| read the same account of the schema in this document and in a real database | `BundleDocumentationTests` |  |
