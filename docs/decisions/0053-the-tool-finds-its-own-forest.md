# 0053 - The tool finds its own forest, and a typed name is the fallback

Date: 2026-08-15
Status: Accepted

## Context

The rebuild's only entry into a capture is `CaptureSession.ValidateAsync`, which demands the
hostname of a domain controller. An operator running the tool on a domain-joined machine already
sits inside the forest being audited, and is being asked to supply a fact the machine holds. The
predecessor did not ask: it found its own forest and started.

A typed hostname is also the weakest input available. It is the one thing in the whole plan that
nothing verifies before use, it names a machine rather than a directory, and mistyping it is
indistinguishable from naming a controller that is down.

## Decision

**The tool determines its own forest.** It reads the machine's DNS domain suffix, falling back to
the NetBIOS domain name, and opens its first connection **to that domain name rather than to a
host**. The Windows domain controller locator turns a domain name into a nearby live controller.
That indirection is the whole mechanism: a domain name is something the machine already knows, and
a hostname is not. From the resulting connection it reads `rootDomainNamingContext` from the
RootDSE, which is the forest root as stated by the directory rather than as inferred from a name.

**This is the sanctioned use of DNS, not an exception to it.**
[`0050`](0050-the-candidate-list-comes-from-the-configuration-partition.md) states that DNS is used
to bootstrap and to resolve, never to enumerate. Locating one controller from a domain name is
bootstrapping. Nothing about *which* controllers exist comes from it.

**A typed name survives as a recovery path.** A machine that is not domain-joined, and an operator
auditing a forest that is not his own, both need it. It is offered when automatic bootstrap fails
and it is available on demand; it is not the ordinary route in.

## Consequences

The New Audit surface has no text box on its first screen, and a run can begin from a click.

Bootstrap acquires a failure mode the product must state plainly: a machine with no domain suffix
and no NetBIOS domain is not in a forest, and saying so is more use than an empty field.

The controller the first connection lands on is **not** the controller anything is captured from.
It answers one question - what forest is this - and selection under `0050` proceeds from the
configuration partition it yields. Nothing may treat the bootstrap controller as pinned.
