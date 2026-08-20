# 0020 - The seal detects corruption, not tampering, and only an intact bundle opens

Date: 2026-08-12
Status: Accepted

Supersedes `0019`, which was written without the owner and
justified the seal partly as a defence against tampering.

## Context

`0019` established that the bundle is sealed with SHA-256 and
that the mechanism is what [`0003`](0003-refuse-to-reanalyse-an-incomplete-capture.md) rests on. It
also argued several points as tamper resistance. On review the owner rejected that framing, and was
right to:

> If someone can access the database to tamper with it they can make their modifications, re-hash,
> then change the hash where we store it. We are not using certificates to guarantee anything.

A hash stored beside the file it describes gives no protection against anyone with write access to
the folder. Designing around a threat the mechanism cannot address is theatre, and theatre in a
security tool is worse than nothing, because it invites trust it has not earned.

What the seal does catch is real and common: an interrupted copy, a network transfer that reported
success, a bad disk block, backup or antivirus software, and - the case that matters most - **a
capture truncated by a full disk**. A truncated bundle analysed silently produces findings that are
wrong in the reassuring direction.

## Decision

**The seal is a corruption control, not a tamper control**, and the product says so.

Verification happens **when a bundle is opened and again when evidence is exported**. The verdict is
held while the bundle stays open and the file handle is kept, so "unchanged since we checked" is
enforced rather than assumed; reopening a bundle verifies it again. There is no cached verdict on
disk.

**Only an intact bundle is opened.** The other three states - no seal, unreadable seal, mismatch -
are refused, naming which one was seen. A missing seal says plainly that a bundle is a folder and
the whole folder must travel together.

The limits are documented for the customer rather than engineered around: what the seal proves, what
it does not, and the recommendation to treat a bundle as sensitive evidence and restrict write
access to it.

## Consequences

Opening a large bundle costs a full read of it, and so does exporting. On the only bundle anyone has
measured - roughly 17 GB - that is seconds to tens of seconds, twice per working session rather than
per screen. **This must be measured in a production environment before it is treated as acceptable.**

The disk cache is still refused, on a corruption argument rather than a tampering one: silent bit rot
does not pass through the file system, so a cache keyed on size and last-write time would miss
exactly the damage this control exists to find.

The four verdict states remain, as **corruption diagnostics**. Distinguishing an unreadable seal from
an absent one tells an operator what kind of damage occurred.

Real signing with a certificate would change what can be claimed, and is deliberately left open. It
is not planned, and will not be built unless a customer asks. The naming is chosen so that adopting
it later does not require renaming anything.
