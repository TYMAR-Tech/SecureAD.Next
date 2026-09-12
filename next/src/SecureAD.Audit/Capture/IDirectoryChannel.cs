using System.DirectoryServices.Protocols;
using SecureAD.Evidence;
using SecureAD.Kernel;

namespace SecureAD.Audit.Capture;

/// <summary>
/// The one way this product speaks to a domain controller: send a request, get an answer.
/// </summary>
/// <remarks>
/// <para>
/// This is the seam between the product and a customer's forest. It exists as an interface for the
/// reason an interface is worth having - what is on the other side is not this product's code, and
/// there is no forest in a build agent. Everything above it can therefore be exercised against a
/// controller model that behaves the way Microsoft's documentation says a controller behaves, which
/// is the only way the rules in docs/layers/audit/how-a-controller-is-read.md can be checked at all.
/// </para>
/// <para>
/// <b>One request at a time.</b> A capture places one request on a controller and waits for the
/// answer before placing another - see docs/layers/audit/limits-and-failures.md, where that is the whole
/// of the product's politeness and also a correctness rule, because the state a controller keeps
/// between the pages of a paged search comes out of one per-controller budget which it relieves by
/// discarding the oldest. Nothing here enforces that; what enforces it is
/// <c>SerializedDirectoryAccessGateTests</c>, which fails the build if a fan-out shape appears
/// anywhere in this project.
/// </para>
/// <para>
/// <b>What a channel does not do.</b> It does not choose a controller or decide what to ask - both
/// belong to <c>SecureAD.Audit.Connect</c>, which is built. It does not retry: the failure policy is
/// one table, in
/// <see cref="RetryPolicy"/>, and a channel that quietly retried would be a second one. And it
/// never builds a request; only <see cref="CaptureSearchRequestFactory"/> does, because a request
/// carries the referral policy.
/// </para>
/// </remarks>
public interface IDirectoryChannel : IDisposable
{
    /// <summary>The controller on the other end. Compared against the unit being read.</summary>
    string DomainController { get; }

    /// <summary>
    /// How well protected this connection turned out to be, after the ladder finished walking.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Reported by the connection because only the connection knows it.</b> The rung reached is
    /// not a property of the request or of the partition; it is the outcome of a negotiation with
    /// one controller, and a capture pass has no other way to find out what it got.
    /// </para>
    /// <para>
    /// It is on this interface rather than logged beside it because it is recorded per partition in
    /// the bundle. A Windows Server 2025 controller strips confidential attributes from an
    /// unencrypted search and returns <i>no error to the client</i>, so a partition read over
    /// <see cref="ConnectionSecurityLevel.Signed"/> can be missing values with nothing else in the
    /// bundle recording their absence - and per <c>docs/decisions/0002</c> that silence must not be
    /// readable as a fact about the forest. See <c>F-S24-1</c>.
    /// </para>
    /// </remarks>
    ConnectionSecurityLevel SecurityLevel { get; }

    /// <summary>
    /// The referral policy actually in force on this connection.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>This is reported rather than assumed, and it is the most load-bearing member here.</b> A
    /// paged search ends when the controller says there is no more to send. A client that chases a
    /// subordinate referral mid-search has that answer overwritten inside the LDAP runtime and
    /// reads "no more to send" on the first page - and Microsoft's own account of the defect is
    /// that on the wire the controller <i>did</i> send more: <i>"the paged cookie it receives is
    /// empty and thus the application ends the query. In a network trace, you can verify that the
    /// paged query does return a non-empty cookie"</i>
    /// (<see href="https://learn.microsoft.com/troubleshoot/windows-server/active-directory/ldap-paged-queries-subordinate-referrals-not-chased">LDAP
    /// paged queries with subordinate referrals are not chased properly</see>). So nothing in any
    /// response distinguishes the two. The only defence is that chasing was off, and the only way a
    /// loop can know that is to be told by the connection.
    /// </para>
    /// </remarks>
    ReferralChasingOptions ReferralChasing { get; }

    /// <summary>
    /// The control OIDs the controller advertises in its RootDSE, which decide whether the
    /// domain-scope control is worth sending.
    /// </summary>
    IReadOnlyList<string> SupportedControls { get; }

    /// <summary>
    /// The naming contexts this controller says it serves, from the same RootDSE read that gave
    /// <see cref="SupportedControls"/>.
    /// </summary>
    /// <remarks>
    /// Carried on the channel because it is the only place the answer is real. Confirming that a
    /// controller serves the partition it was chosen for needs that controller's own list, and for
    /// every domain beyond the one the operator named, the first time the product holds that list
    /// is when a connection to it has been opened.
    /// </remarks>
    IReadOnlyList<string> NamingContextsServed { get; }

    /// <summary>
    /// Whether <see cref="SupportedControls"/> is what the controller advertises, rather than what
    /// could be seen.
    /// </summary>
    /// <remarks>
    /// An empty list means one of two things - this controller advertises no controls, which no
    /// real one does, or its RootDSE was never read. They are not the same, and the difference is
    /// not cosmetic: the domain-scope control is sent only where it is advertised, so an unread
    /// capability list quietly drops the second line of the referral defence and nothing says so.
    /// A capture pass refuses to run on a connection that cannot answer this.
    /// </remarks>
    bool IsComplete { get; }

    /// <summary>
    /// Sends one request and waits for the answer.
    /// </summary>
    /// <remarks>
    /// A failure is raised as an <see cref="LdapException"/> carrying the controller's result code,
    /// because that is the shape the platform's own client produces and inventing a second one
    /// would mean translating twice. A result code that is not success is a failure and is raised
    /// the same way. <see cref="RetryPolicy"/> is what interprets the code; this method interprets
    /// nothing.
    /// </remarks>
    /// <param name="request">The request, built by <see cref="CaptureSearchRequestFactory"/>.</param>
    /// <param name="cancellationToken">Cancellation for a capture an operator stopped.</param>
    Task<DirectoryPage> SendAsync(SearchRequest request, CancellationToken cancellationToken);
}

/// <summary>
/// Opens a connection to the controller a capture unit names.
/// </summary>
/// <remarks>
/// <para>
/// This exists because of one line of the failure policy. When a failure ends the conversation with
/// a controller the paging bookmark dies with it, and the answer is to read the naming context
/// again from its first page on a <i>fresh connection</i> - see
/// docs/layers/audit/limits-and-failures.md. A component handed a connection cannot do that, so it could
/// not implement the policy it is supposed to be applying: it would have to hand the decision
/// upwards, and the budget of one restart per naming context would then live nowhere.
/// </para>
/// <para>
/// Opening the connection - choosing the controller, binding, and applying the referral policy with
/// <see cref="CaptureSearchRequestFactory.ApplyReferralPolicy"/> - belongs to
/// <c>SecureAD.Audit.Connect</c>, where <c>LdapDirectoryChannelFactory</c> does it. This is the
/// shape of the hand-off.
/// </para>
/// </remarks>
public interface IDirectoryChannelFactory
{
    /// <summary>Opens a connection to the controller <paramref name="unit"/> names.</summary>
    /// <param name="unit">The unit about to be read.</param>
    Result<IDirectoryChannel> Connect(CaptureUnit unit);

    /// <summary>
    /// Opens a connection to a controller named on its own, before any partition is known.
    /// </summary>
    /// <remarks>
    /// A run starts by being pointed at one controller and asking it what the forest contains, and
    /// at that moment there is no unit to name: which partitions exist is the answer that read
    /// produces. Without this, a caller would have to invent a unit to carry a host name - a
    /// capture unit describing a partition nobody intends to read - and a value invented to satisfy
    /// a signature is the sort of thing a later reader takes for a fact.
    /// </remarks>
    /// <param name="domainController">The host to open a connection to.</param>
    Result<IDirectoryChannel> Connect(string domainController);
}
