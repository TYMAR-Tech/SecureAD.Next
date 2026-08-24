# How a connection is opened

**Layer.** The one place in this product that opens a socket to a domain controller, what identity
it presents, and what the resulting channel will and will not do.

The code is [`LdapDirectoryChannelFactory`](../../../next/src/SecureAD.Audit/Connect/LdapDirectoryChannelFactory.cs),
[`LdapDirectoryChannel`](../../../next/src/SecureAD.Audit/Connect/LdapDirectoryChannel.cs),
[`DirectoryConnectionSettings`](../../../next/src/SecureAD.Audit/Connect/DirectoryConnectionSettings.cs)
and [`DirectoryCredential`](../../../next/src/SecureAD.Audit/Connect/DirectoryCredential.cs).

Which rung it lands on is [`the connection ladder`](the-connection-ladder.md). What the channel is
used for afterwards is [`how a controller is read`](../audit/how-a-controller-is-read.md).

---

## What this page owns

<!-- TYPES:BEGIN -->

| Type | What it is |
|---|---|
| `LdapDirectoryChannelFactory` | The one place in this product that opens a connection to a domain controller |
| `LdapDirectoryChannel` | A live connection to one controller: the implementation of the product's one seam onto a customer's forest |
| `DirectoryConnectionSettings` | Everything a run decides about how it connects, decided once before anything is read |
| `DirectoryCredential` | Who a capture binds to a controller as. Two answers and no third |

<!-- TYPES:END -->

This table is the page's claim of ownership, and it is bound in both directions against the public
types the four files above declare: one they declare and this table omits fails the build, and so
does a row naming something they do not.

`ConnectionSecurityLog` is named further down this page and is **not** owned here — it is claimed by
[`the connection ladder`](the-connection-ladder.md), beside the walk that fills it. This page writes
into it; that is a mention, not a claim.

---

## One owner, held by a build failure

`ConnectionSecurityGateTests` fails the build if an `LdapConnection` is constructed, or a
transport-security option assigned, anywhere else in the tree.

That is the same shape as the referral policy's guard and it exists for the same reason: **the
correctness is invisible at the point where it is lost.** A second place that opens a connection is
a second ladder, and the first sign the two disagree is a customer's evidence having crossed a
network unprotected with nothing saying so.

The gate holds four things:

- **One place opens a connection.**
- **One place decides how protected a channel is.** The level is reported and recorded afterwards,
  never adjusted.
- **Nothing binds with anything but Negotiate**, anywhere, including inside the factory.
- **The rung list and the level enumeration are the same set, in the same order.** A rung added to
  one and not the other would leave the product climbing one ladder and reporting another — and the
  reporting half is what a customer reads.

It was mutation-tested in four directions, each confirmed present in the source before the run was
believed, and each reverted.

| # | Mutation | Expected | Observed |
|---|---|---|---|
| 1 | A connection opened, a transport option set and a non-Negotiate bind added to a file that is not the factory | The three boundary checks fire | All three fired |
| 2 | The bottom rung deleted from the list | The ladder and the enumeration disagree | Both the list check and the scanner self-test fired |
| 3 | The factory stops setting `Sealing` | The self-test's floor on what the factory contains fires | Fired |
| 4 | The factory file renamed, so the exemption matches nothing | The self-test fires rather than the checks passing against an unguarded tree | The self-test fired, and both boundary checks fired with it |

---

## A factory, not a connection

Capture is handed the factory rather than an open channel, and that follows from one line of the
failure policy at [`limits-and-failures`](../audit/limits-and-failures.md): a failure that ends the
conversation with a controller takes the paging bookmark with it, and the answer is to read the
naming context again from its first page **on a fresh connection**. Something handed a connection
could not do that.

Both collaborators are required rather than defaulted. A factory that could be built without a
[`ConnectionSecurityLog`](../../../next/src/SecureAD.Audit/Connect/ConnectionSecurityLog.cs) would be a
product that sometimes did not know what its own evidence crossed.

## What opening one rung actually does

1. Build an `LdapDirectoryIdentifier` for the host at that rung's port, fully qualified.
2. Construct the `LdapConnection` with `AuthType.Negotiate` and the run's connect timeout.
3. Set `ProtocolVersion = 3`, then `SecureSocketLayer`, `Signing` and `Sealing` **from the rung** —
   never from a setting.
4. Apply the referral policy, which is `CaptureSearchRequestFactory`'s and not this file's.
5. Bind.
6. Read the RootDSE.
7. Hand back a channel carrying the level, the advertised controls and the naming contexts served.

**The RootDSE read is part of opening, not a later question.** A connection whose capability list
was never read cannot say whether the domain-scope control is worth sending, and a capture pass
refuses to run on one — so a channel that could exist without having asked would be a channel that
fails later for a reason decided here. A RootDSE that answers with no entry, or a non-success result
code, is raised as an `LdapException` and classified like any other rung failure.

**A failure is classified, never flattened.** What the directory said is the difference between
*"check your network"* and *"your password expired"*, and between a security finding about the
forest and a claim this run has no right to make. That classification, and its one known defect, are
[`the connection ladder`](the-connection-ladder.md)'s.

**This is the part no test reaches, and it is stated rather than glossed.** There is no domain
controller in a build agent, so nothing exercises the bind or the TLS handshake. The rest is a lab
obligation on inventory row B20.

---

## The channel

**It interprets nothing.** A result code that is not success is raised as an `LdapException`
carrying the controller's own code, because that is the shape the platform's client produces and
inventing a second one would mean translating twice. What that code means — retry, restart the
naming context, or stop — is the retry policy's, and a channel that quietly retried would be a
second failure policy.

**One request at a time.** Nothing here fans work out, and `SerializedDirectoryAccessGateTests`
fails the build if anything in this project both speaks to a directory and runs work in parallel.
That is not politeness: the state a controller keeps between the pages of a paged search comes out
of one per-controller budget which it relieves by discarding the oldest, so **two reads at one
server can truncate each other silently** — a report that is wrong rather than one that fails.

**A cancelled request is aborted, not abandoned.** A cancelled capture that left a request running
would leave a controller building a page nobody will read, and the connection would then be closed
under it.

**An answer that is not a search result is refused.** Reading it as an empty page would report a
partition as finished.

### The seam survived contact

`IDirectoryChannel` was written from the capture loop's side against a controller model, with
nothing real on the other end. This was the first thing to meet it from the other direction. It held,
unchanged — every member maps onto something a live connection actually has:

| What the seam asks for | Where it comes from |
|---|---|
| The referral policy in force | Read back off the live session options, never remembered from what was set |
| Whether the capability list was really read | Whether the RootDSE answered with any advertised control at all |
| The controls the controller advertises | `supportedControl` on the RootDSE |
| A page, in three states | Whether the response carried a paging control, and what was in it |

One thing was added rather than changed. `namingContexts` confirms a controller actually serves the
partition a unit names, so the channel exposes it. It arrives in the same round trip and costs
nothing extra.

**The request for it is built by the search-request factory**, not here — the one-place rule from
[`the search capture issues`](../audit/the-search-capture-issues.md) applying to a request nobody had
needed yet. It is the right answer rather than a formality: the RootDSE read happens on the same
connection as everything else, and a second builder would be a second referral policy.

---

## What a run decides about connecting

`DirectoryConnectionSettings` is short on purpose. **Every field is one something reads**; a setting
nothing consumes is dead weight that looks like a lever.

**What is deliberately not there.** A choice of transport, because that is the ladder's and the
ladder is not configurable — an operator who could pin the connection to one rung could pin it to
the bottom one without declaring anything. A choice of authentication, because it is Negotiate. A
referral setting, because there is one referral policy and the request factory owns it. And nothing
about which controller to use, which is the plan's.

**The connect timeout is short — ten seconds by default**, and it bounds one attempt at one rung.
Four rungs at thirty seconds each, against twelve controllers, is a preflight that takes a quarter of
an hour to discover a typo in a host name. A controller that has not completed a TCP connection and
a bind in ten seconds is not one a multi-hour capture should be reading from.

---

## What happens to a customer's credentials

Two answers and no third: the account the product is already running under, or an account an
operator typed in for this run. Authentication is Negotiate either way — the credential decides
*whose* identity is presented, never *how*.

**Nothing is remembered between runs.** The map records a file named `SavedCredential.cs` in the
previous product containing no such type — a folder and a filename left behind by a
credential-persistence feature that was designed and never built. That was the right call and it
stands. A tool that reads a directory and writes nothing to it has no business holding a customer's
administrative password from one week to the next.

**A password is not on this component's public surface.** The way a secret normally escapes is that
something prints the object holding it, so `DirectoryCredential` is deliberately **not a record** —
a record's compiler-generated `ToString` prints every member it has. Its `ToString` names neither the
password nor the account, and no public member hands either back. Both are asserted rather than
intended.

**The account name is withheld too**, which is a slightly stronger position than it needs to be and
is taken on purpose. A user name is not a secret, but it is half of one, and an audit tool's logs
travel: they go into support tickets and get pasted into chat. There is no operational question this
product answers better by naming the account.
