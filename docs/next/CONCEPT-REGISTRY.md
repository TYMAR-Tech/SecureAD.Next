# Concept registry

Every named concept in the rebuild, and the one type that owns it.

A **concept** is a question the product has to answer — *what does this GUID mean?*, *is this
permission dangerous?*, *what is this object's parent?* Each is answered in exactly one place, by
one type, and everything else asks that type.

## What this is for

The map found the same question answered three to six times, differently, in branches that could
not see each other's work. It is the defect that recurred most.

It is not theoretical. Two of the five kernel components rebuilt so far were instances of it:

- **K13 and K14** were two hand-maintained tables of the same Active Directory facts, in different
  folders. Neither referenced the other. Both carried correction comments about entries that had
  previously pointed at the wrong GUID. Exactly one file in the entire product touched both.
- **K16** was six separate answers to *"is this permission dangerous"*. Two of them powered the
  live and the stored effective-access panels — the two screens a customer opens precisely so that
  he can compare them against each other. They disagreed about `gPLink`, `scriptPath` and
  `userAccountControl`.

Both were found by a human reading the map carefully. There are 251 inventory rows left and that does
not scale, so the seventh duplicate has to fail the build instead of waiting for someone to notice
it.

For an audit tool the consequence is not untidiness. When two answers disagree, at least one screen
is telling a customer something false about who can take over his directory, and there is nothing
in the product that can tell him which.

## What it does not do

**It cannot tell you that two differently named members answer the same question.** It matches
member names against the shapes written down here. A genuinely new name for an old question gets
past it, and always will — that is a reader's job, and the reason each row says what the concept
*is* in words rather than only in patterns.

**It cannot see outside .NET.** The check reflects over the compiled rebuild assemblies, so a
duplicate written in SQL, in a report template or in a configuration file is out of its reach.
K16's sixth answer to the danger question lived in the rule SQL, so this limit is a known one
rather than a hypothetical.

**It is not a naming rule.** A type may declare anything it likes, so long as no other type has
already been made answerable for it.

## How a row is read

| Column | Meaning |
|---|---|
| **Concept** | The question, in words |
| **Owning type** | The one type allowed to answer it. Types nested inside it count as part of it |
| **Member shapes** | The member names that constitute an answer. `*` stands for the rest of a name and nothing else is a wildcard; the match is against the whole name, so `Classify` does not match `CannotClassify` |
| **Why it is a concept** | What went wrong, or would go wrong, without an owner |

The shapes are deliberately wider than the members that exist today. A shape naming only the
current members would fail on nothing but a verbatim copy, and the duplicates this exists for were
never verbatim copies — K14 asked K13's question under the names `GetGuid`, `TryGetGuid`, `ByGuid`
and `ByLdapName`. Those four names are claimed by the schema-lookup row below, and
`ConceptRegistryTests` asserts that the row still claims them, so a shape narrowed until it would
no longer have caught the original defect fails the build.

Globs rather than regular expressions, for two reasons. A regular expression's alternation
character, `|`, is the character a markdown table uses to separate its cells. And the owner of this
product is an Active Directory administrator rather than a developer: `GuidFor*` is readable and
`^(?:Guid(?:For|By))[A-Za-z]*$` is not.

The table below sits between the two markers around it, so the test parses only the rows.

<!-- CONCEPTS:BEGIN -->

| Concept | Owning type | Member shapes | Why it is a concept |
|---|---|---|---|
| Schema GUID lookup | SchemaGuidCatalog | `FindByGuid*`, `FindByLdapName*`, `GuidFor*`, `GetGuid*`, `TryGetGuid*`, `LookupGuid*`, `ByGuid`, `ByLdapName`, `WellKnownGuid*` | The defect this gate is named for. Two tables of the same facts, in `Catalogs/` and `Schema/`, both carrying corrections for entries that had been wrong. One attribute ended up recorded under three GUIDs, two of them wrong. `SchemaGuidSingleSourceGateTests` already forbids the literals; this forbids the second table |
| Dangerous-permission classification | DangerousPermissionClassifier | `Classify*`, `IsDangerous*`, `AreDangerous*`, `IsRisky*`, `AssessDanger*`, `EvaluateDanger*`, `ComputeDanger*`, `DangerousRights*`, `DangerousGuids*` | Six answers, two of which drove the pair of screens a customer opens to compare against each other, and they disagreed. `PermissionAssessment.Dangerous` is not a rival: it builds the answer the classifier has already decided, which is why the shapes are verb-shaped and `Dangerous` alone is not one of them |
| Distinguished-name manipulation | DnHelper | `GetParentDn*`, `ParentDn*`, `ExtractFirstRdn*`, `ExtractNameFromDn*`, `GetRdn*`, `SplitDn*`, `DnToFqdn*`, `ToFqdn*`, `NormalizeDn*` | The old product grew three near-identical ways to ask one question about a DN, because the cost of adding a fourth was never visible. A DN parsed two ways attributes an object to the wrong container, which is a customer reading a report about an OU that does not hold the object |
| Security descriptor parsing | SecurityDescriptorParser | `Parse`, `ParseBase64*`, `ParseSecurityDescriptor*`, `ParseSd*`, `TryParseSecurityDescriptor*` | Raw bytes are read once. A second reader is a second interpretation of an offset, and the two disagree silently: the ACEs come out looking plausible and are not the ones the directory holds |
| ACE canonicalisation | AceNormalizer | `Normalize*`, `Normalise*`, `Canonicalize*`, `Canonicalise*` | The canonical form is what stored hashes are computed over. A second normaliser makes two runs of the same directory compare as changed, so the product reports drift that did not happen |
| Generic-rights expansion | GenericRightsExpander | `Expand*`, `ExpandGenericRights*`, `HasGenericRights*` | Whether `GENERIC_ALL` becomes the specific rights it implies decides whether a Full Control entry is seen at all. Two expansions mean one screen sees it and another does not |
| Capture search request | CaptureSearchRequestFactory | `ForUnit*`, `BuildSearchRequest*`, `CreateSearchRequest*`, `NewSearchRequest*`, `SearchRequestFor*`, `ApplyReferralPolicy*` | A second place that builds a capture search is a second referral policy, and referral policy is the difference between reading a forest and reading its first page while being told nothing went wrong. The policy has two halves — a setting on the connection and a control on the request — so a second builder does not disagree loudly; it disagrees in whichever half its author forgot. `DirectorySearchGateTests` forbids the *construction* elsewhere; this forbids a second type being made answerable for the question |
| Directory failure response | RetryPolicy | `FailureFor*`, `IsTransient*`, `IsRetryable*`, `ShouldRetry*`, `RetryAfter*`, `WaitBefore*`, `BackoffFor*` | Whether a failed request is worth sending again is one question, and answering it in two places is how a controller that said "I am busy" gets asked again immediately by one caller and left alone by another. It also decides whether a paged read is resumed or restarted, and a second opinion on that is a partial capture reported as complete |
| Operation outcome | Result | `IsSuccess`, `IsFailure`, `Succeeded`, `Failed`, `IsOk` | Gate 1's own mechanism. A second outcome type is how "found nothing" and "could not compute" become indistinguishable again — the failure gate 4 exists for, arriving through the back door |
| What capture asks the directory for | CapturedAttributeCatalog | `AttributesFor*`, `RequestedAttributes*`, `AttributesForClass*`, `CaptureFilter*`, `CapturedAttributes*`, `IsRangeLiable*`, `RangeLiable*`, `MultiValuedAttributes*`, `BinaryAttributes*` | The previous product answered this in one place and then filtered the answer in four more, so which objects had their permissions read depended on which copy ran. It also kept a second, hand-maintained list of the attributes needing range retrieval, which is the shape that agrees on the day it is written and stops agreeing silently — a group past the server's value limit then reports as smaller than it is. The shapes claim the old names as well as the new ones, so a second answer under the old spelling fails too |
| What an entry's values mean | LdapEntryReader | `ForEntry*`, `ForValues*`, `ValuesOf*`, `ReadAttribute*`, `AsText*`, `AsBytes*`, `AsInteger*`, `AsGuid*`, `AsSid*`, `Continue*` | Two questions are decided when a directory value is read: whether it is text or bytes, and whether the values in hand are all of them. A second reader disagreeing on the first produces mangled text somebody notices; disagreeing on the second produces a group reported smaller than it is, which nobody notices. The previous product answered this in two files with interchangeable names, and two grab bags with interchangeable names is how a third one gets created |
| Where a block of values begins and ends | AttributeRange | `SpecifierFor*`, `TryReadSpecifier*`, `NextAfter*`, `FirstRound*`, `ValuesPerRound*` | A range specifier is how the values past a server's limit are asked for, and how a controller says which block it served. A second opinion about where a block ends does not fail loudly: both spellings look plausible, one of them fetches fewer values, and nothing says so. `RangeSpecifierGateTests` forbids the *text* elsewhere; this forbids a second type being made answerable for the question |
| Which forest a run assessed | ProfileId | `ForForest*`, `ForSecurityMode*`, `FromComponents*`, `ProfileFor*`, `ForestKey*` | The predecessor had two factories for this and nothing checked they agreed, so two callers could compute different values for one forest. Such a run matched nothing, sat in a group of one, was never offered as a compare partner, and said nothing about why. The dead names are claimed here as well as the live one, so the deleted second factory cannot come back under its old name |
| Which evidence a run is built from | CoverageId | `ForDomains*`, `FromDomains*`, `CoverageFor*`, `DeclaredCoverage*` | This decides whether two runs may be compared at all. A second way to compute it is a second answer to *did these audits look at the same thing*, and the two would disagree only for the runs where it matters - a forest that changed shape |
| What became of a run | RunStateNames | `Persist*`, `PersistedName*`, `ReadState*`, `ParseRunState*`, `ToRunState*` | The predecessor kept these strings private to the writer while four readers matched bare literals, so a rename changed what was written without changing what was read, and every sealed run vanished from every picker that filtered on sealed. Nothing failed; the runs simply stopped being there |
| Whether a run may be used | RunComparability | `Evaluate*`, `MayBeBaseline*`, `IsBaselineEligible*`, `CanCompare*`, `MayCompare*`, `IsComparable*`, `CompareCompatibility*`, `NoEarlierRun*`, `EarlierRunDeleted*` | The defect this registry exists for, in its largest instance. Five independent predicates in three files, and they disagreed rather than repeating each other: the drift path checked neither coverage nor eligibility, two compare commands checked only sealing, and the one that did check coverage refused every mismatch - including the case its own comparison core had been rewritten to permit. A sixth would not fail; it would quietly become the answer at one door |
| What a bundle's files are called | BundleLayout | `EvidenceFileName`, `PartialFileName`, `SealFileName`, `AnnotationsFileName`, `OutcomeFileName`, `EvidencePath*`, `PartialPath*`, `SealPath*`, `AnnotationsPath*`, `OutcomePath*`, `BundleFile*`, `BundlePath*` | Which files are present is how the product decides what became of a run, so a name is not cosmetic: a second spelling of `evidence.db` is a reader that finds no bundle where there is one, and a second spelling of the outcome file is a run that failed reporting as merely interrupted. The registry gained this row on 2026-08-12, after the point-in-time review found the outcome file's name declared on `RunOutcomeFile` while the other four lived here - two owners for one question, which this gate exists to prevent and could not see, because nothing had claimed the concept |
| What a userAccountControl bit means | UserAccountControlWording | `Documented`, `DocumentedFlags*`, `AccountControlFlags*`, `AccountStateFlags*`, `WordAccountControl*` | This bitfield decides whether an account can log on at all, whether its password ever expires, whether it can be attacked without Kerberos pre-authentication, and whether a service running as it can impersonate whoever calls it. Getting a bit wrong is the mistake nobody sees: it does not throw and it does not look odd, it renders as a confident *The account is disabled* beside an account that is enabled. A second table is a second set of those, disagreeing only for the accounts where it matters. This one is transcribed from Learn, asserted bit by bit, and carries out any set bit it has no wording for, so a partial reading cannot pass for a complete one |
| What a directory timestamp means | DirectoryTime | `WordTimestamp*`, `FromInterval*`, `FromGeneralizedTime*`, `TimestampFormatFor*`, `IsTimestampAttribute*` | Active Directory stores time two ways and neither is recognisable as time: an interval counted from 1601 and a string of digits. A generalized time parses perfectly well as an interval and lands in the seventeenth century, so a second reader guessing the syntax from the value does not fail loudly — it produces a plausible date. Worse, three of these attributes carry values that are not moments at all: `accountExpires` has two meaning *never*, and `pwdLastSet` of zero means the password must be set at next logon. A second reader that handles one sentinel and not the other renders *never expires* as an expiry in 1601, which reads as a lapsed account nobody revoked |

<!-- CONCEPTS:END -->

Twelve concepts against thirty-five public types. Seven were kernel ones, an eighth arrived on
2026-08-11 with inventory row B2, and four more on 2026-08-12 with the run identity and comparability
rows — the first that are about the product's own record-keeping rather than about Active
Directory. It is also the cheapest moment this file will ever be written: gate 5 could not
be retrofitted onto the old tree at all, and this would have been worse, because the duplicates it
forbids are already there.

The run-comparability row is the one to watch. It claims nine member shapes rather than the usual
four or five, because the question it owns was answered in five places in the predecessor under
five different names, and none of them looked like a duplicate of the others.

It has already earned its place. On the day it was written, gate 2 refused a private helper called
`DomainCoverage.Normalize`, because `Normalize*` belongs to `AceNormalizer` — correctly, since a
second thing called normalisation is how one question comes to have two answers. It was renamed to
`AsDomainFqdn`.

A concept is added when a question gets its first owner — that is, in the session that writes the
type answering it, not later. `ConceptRegistryTests` cannot make that happen. What it can do, and
does, is fail when an owner named here stops answering its own question, so a row cannot quietly
become decoration.
