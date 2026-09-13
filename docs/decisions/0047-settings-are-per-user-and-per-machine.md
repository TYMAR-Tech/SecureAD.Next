# 0047 - Settings are per-user and per-machine

Date: 2026-08-14
Status: Accepted

> **The title said "and there is one of them" until 2026-09-13.** The count moved into the record's
> own Decision section when the owner added a second setting, because a title carrying a number is a
> claim that goes stale silently - the index reprints it, and a reader who never opens the file
> believes it. The bar for adding a setting is unchanged and is stated where it can be read in
> context.

Settles where the operator's own choices are kept, and what may be one. Raised by the owner at the
close of `S-35`, which had built a settings store without deciding the question it implied.

## Context

`S-35` gave the shell a single persisted setting - the run library path - because
[`0025`](0025-the-run-library-is-a-managed-root.md) forbids the product choosing a default and the
owner ruled the operator sets it. The store was written to `%APPDATA%\SecureAD\shell-settings.json`
before anyone had decided that was right.

Two questions were open, and the second is not obvious.

**Whether configuration is per-user or machine-wide.** This product is copied onto an administrative
workstation, a jump host or a domain controller and run. Several administrators may share such a
machine.

**Whether configuration roams.** `%APPDATA%` follows a user between machines where roaming profiles
are in use, which is common in exactly the organisations this product audits. `%LOCALAPPDATA%` does
not.

The roaming question turns on what a run library path usually is. A path to a network share -
`\\fileserver\audits$` - means the same thing everywhere and should follow the operator. A path to a
local disk - `D:\audits` - means nothing on another machine. The owner's answer is that a run
library is expected to be a local disk.

## Decision

**Settings are kept per-user and per-machine, in `%LOCALAPPDATA%\SecureAD\shell-settings.json`.**

**Local rather than roaming, because a wrong answer is worse than no answer.** A roamed local path
produces a product that is confidently pointed somewhere that does not exist. It cannot distinguish
that from a library that has been moved or a drive that is not mounted, so the operator gets an
error where they should have got a question. An installation that has never been configured asks;
that is the behaviour `0025` requires and it should not be lost by a setting arriving from a machine
the operator is no longer using.

**Per-user, not machine-wide.** Two administrators sharing a jump host do not overwrite each other's
choice. It also needs no elevation, which matters for a tool that is copied onto a domain controller
and run by whoever is signed in.

**The run library path is the only thing the operator sets.** Not a preference among many with one
currently implemented - the only one. Consistent with
`0017` and
[`0042`](0042-dns-zones-and-records-are-out-of-scope.md): nothing a customer can switch makes a run
read more or less, and there is no setting that changes what the product looks at. A second setting
is added by overturning this sentence, not by adding a field.

> **Overturned 2026-09-13 by the owner: there is a second setting, and it is how many domains are
> read at once.** The sentence above required that this be done by overturning it rather than by
> adding a field, so it is being done that way. What is kept whole is the *test* the sentence was
> applying, because the clause after it is the reasoning and the clause before it is only the
> count: **nothing a customer can switch makes a run read more or less.** That still holds. The
> ceiling changes how long a capture takes and nothing about what it covers - every domain of the
> forest is read at every setting, and a bundle captured at one is indistinguishable from a bundle
> captured at another.
>
> **What makes it admissible is whose machine it governs**, and that is
> [`0041`](0041-capture-reads-domains-in-parallel.md)'s amendment of the same day rather than a new
> argument here. Reading domains at once does not make any one controller work harder than reading
> them in turn; what changes is the load on the machine running the audit, because every domain in
> flight writes a database of its own. A setting over the operator's own disk is a question he can
> actually answer. A setting over a server he does not own is not, which is why `0041` still
> refuses a rate limit and why this record still refuses anything that would narrow a run.
>
> **Lowering it makes a capture slower and never safer.** Any screen or help text presenting it as
> a politeness dial has misread it, and that constraint travels with the wording rather than being
> left to whoever writes the next one.
>
> **A third setting is added by overturning this amendment.** The bar is unchanged; only the count
> is. `DirectoryConnectionSettings.DefaultDomainsAtOnce` carries the same reasoning beside the
> constant, so a reader who never opens this file still meets it.

**The command line does not read this file.** It takes `--library` explicitly, so a scheduled task
running under a service account never depends on a profile that may not exist, and a capture started
without a window behaves identically to one started with it. This is the same separation
[`0039`](0039-one-way-to-start-a-capture.md) draws: the window is a caller, and its conveniences are
its own.

> **Unchanged by the amendment above, and it settles how the flag behaves.** `--concurrent` states
> the ceiling for that invocation. It neither reads the stored value nor writes it, so a scheduled
> capture does what its command line says rather than inheriting a number from the profile of
> whoever last used the window on that machine.

**Logs are not settled by this record.** The owner raised them and deferred them. What is decided
here is only that they would not belong beside this file: roaming a log means copying it across the
network at sign-out, and a capture that read a large forest does not produce a small one. The prior
question is what a log would carry that the sealed bundle does not already record.

## Consequences

**An operator who moves between machines is asked again on each.** That is the cost, and it is
accepted: being asked once per machine is a smaller harm than being pointed at a path that is not
there. An organisation keeping its libraries on a share pays this without benefit, which is the case
that would reopen this record.

**Nothing carries a setting from the predecessor.** It hardcoded `%LOCALAPPDATA%` as the run library
itself, which `0025` refuses. This record puts a *pointer* there and continues to refuse a default
for the thing pointed at; the two must not be confused by a future reader who sees the same folder
named in both.

**A machine-wide policy is not available.** An organisation wanting every administrator on a host to
share one library must say so in the path they each choose. If that becomes a real request, it is a
new record and not a second file quietly consulted first.
