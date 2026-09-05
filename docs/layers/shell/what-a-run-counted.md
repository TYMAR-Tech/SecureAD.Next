# What a run counted

The dashboard: how much of the forest a run read, and what it held. `DashboardViewModel` over
`ForestInventory`, written from the code on 2026-09-05.

**This is orientation, not authority.** Nothing here states the product's position; only a record in
[`decisions/`](../../decisions/) with `Status: Accepted` does that.

## What the screen is for

An operator opening a run lands in a tree of eight thousand objects with no sense of the forest's
size, how much of it was read, or whether the capture was complete. This screen answers *what am I
looking at* and nothing else.

It is the landing screen for a run opened from the library — `ShellViewModel.ShowOpenedRun`, the
owner's decision of 2026-09-05. A run that would not open never arrives here: it has no sealed
evidence to land in, and the library states what became of it instead.

## What it refuses to claim

**A count is never rendered for a domain that was not read.** This is the whole reason the stage
exists. A domain nobody could read produces no rows in the object table — and so does a domain that
was read and found empty. Rendering both as `0` tells an administrator his directory is clean, and
he stops looking. That is failure class 2 in `.github/copilot-instructions.md`: the product telling
a customer something false.

**The refusal is carried by the type, not by the screen.** `DomainInventory` holds its counts in a
field reachable only through `TryGetCounts`, which returns false for any outcome but
`DomainReadOutcome.Read`. Its factories refuse both contradictions at construction — `Counted` throws
for a domain that was not read, `NotCounted` throws for one that was. So there is no zero available
to render even if `DashboardView.xaml` were wrong. The markup is the second line of defence.

**A total is never presented as the forest unless it is.** `ForestInventory.CountedTotal` sums only
the domains that were read, and `AllDeclaredDomainsAreComplete` says whether that is everything.
The screen states what the total covers by naming the domains — not by counting them. *2 of 3* says
how many and not which, and which is what decides whether the total covers the domain being worried
about.

**No findings and no severities.** `ROADMAP.md` § Stage 2. The findings pane already counts them, and
a second count here would be two numbers about one judgement that eventually disagree.

**A domain excluded by choice never reads as one that could not be reached** — `0063`. Both draw a
row with no numbers, so the words are the only thing keeping them apart, and a domain the forest
named no writable controller for is raised above everything rather than listed with the exclusions.
It is not a decision the operator made.

## What it counts, and the trap in counting it

Users, computers, groups and organisational units, per domain, plus Group Policy objects.

**Each object is counted as its most specific class, which is the highest `objectClass` ordinal.**
`objectClass` is multi-valued and arrives least specific first — `top`, `person`,
`organizationalPerson`, `user` — so a computer account's chain contains `user`, and a group managed
service account's contains `computer`. A query matching any value in the chain would report every
workstation and every domain controller in the forest as a user account, in a figure that looks
entirely ordinary.

`InventoryReader` therefore applies the same rule `ObjectListing` already applies to the object
grid, stated once and read from the same table, so the dashboard and the tree cannot give two
answers about what a user is.

Objects of other kinds — containers, contacts, printers — are counted by nothing rather than folded
into the nearest named kind, which would make that kind's figure say something the directory does
not.

## Group Policy, and the one exact shortfall

Policies are stated as **read of declared**, the owner's ruling of 2026-09-05: where we can say how
many were read and how many were not, we say both.

This is the only place a sealed bundle can state an exact shortfall. The declaration comes from the
directory, which is read under fail-fast capture — a domain that could not be read ends the run
before the seal. The files come from SYSVOL, which `0044` allows to fail *without* failing the run.
So the denominator is trustworthy even when the numerator is short. A policy read only in part
counts as not read: part of a policy is not the policy.

## What a domain outcome can actually be

`DomainReadOutcome` has five members and the screen handles all of them, but two are unreachable in
a bundle a reader can open:

| Outcome | On this screen |
|---|---|
| `Read` | counted, including as zero |
| `PartiallyRead` | no count, explained |
| `NotRead` | unreachable — `BundleReader.ReadScope` refuses such a bundle outright |
| `ExcludedByChoice` | no count, explained as the operator's own decision |
| `ExcludedForWantOfCandidates` | no count, and raised above everything |

`NotRead` cannot arise from a run this product completed — capture is fail-fast per `0003`, and
`UnreadOutcomeIsUnreachableTests` holds that no production code records it. A bundle claiming it is
treated as written by something else or altered. The screen still words the case rather than
crashing on it, but nothing here should be read as evidence that it happens.

## The caveat that is not about the counts

`ConfidentialCaveat` appears where any counted domain was read over a connection that was not
encrypted. A Windows Server 2025 controller strips confidential attributes from such a search and
returns no error (`F-S24-1`).

It says explicitly that **the object counts are unaffected** — every object still arrived — and that
detail shown elsewhere for those domains may be incomplete. Wording it as *these numbers may be
wrong* would be its own falsehood, and over-warning erodes trust in warnings as surely as
under-warning does. It is placed last on the screen because it qualifies detail on other screens
rather than anything counted above it.

## Where the seal is verified

One `BundleAssetSource` serves both this screen and the assets tree. Verifying a seal re-reads every
byte of the evidence and is deliberately never cached, so two sources would re-hash gigabytes each
time an operator moved between the dashboard and the tree.

Unlike the assets screen, this one is not told whether a capture is running. The tree refuses a run
being written to because a half-written directory presented as a whole one is a lie; this screen
reads sealed coverage, and a run still capturing has none — so the evidence layer's own refusal is
already the accurate answer, and a second rule here would give one condition two accounts.

## How it was proved

Three mutations, each watched failing and reverted:

- `DomainInventory.NotCounted` made to carry `ObjectCounts.None` instead of null — the most natural
  way to simplify that type. Eight tests failed, including the suite's own self-test.
- `InventoryReader`'s class ordinal flipped from `DESC` to `ASC`. Three failed, including *a
  computer is not counted as a user*.
- A deliberately unbound property in `DashboardView.xaml`. `ViewBindingGateTests` named the file,
  line and property.

Every assertion of a silence is paired with one asserting the corresponding sound — read-and-empty
shows `0`, an excluded domain raises no warning, an encrypted run carries no caveat — so a screen
that went quiet everywhere would fail rather than pass.

## Types

| Type | What it is |
|---|---|
| `ObjectCounts` | the four kinds, for one domain or as a total |
| `DomainInventory` | one domain's coverage and, only where it was read, its counts |
| `ForestInventory` | every declared domain, the policy figures, and what the total covers |
| `InventoryReader` | the one grouped scan that produces them |
| `DashboardViewModel` | the screen's wording |
| `DomainInventoryRowViewModel` | one row: its figures, or what happened to it |
