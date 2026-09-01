using System.Globalization;
using SecureAD.Evidence;
using SecureAD.Kernel.Security;

namespace SecureAD.Derivation;

/// <summary>
/// What one pass over a bundle found out about nesting, ready to be written.
/// </summary>
/// <param name="Sids">The SID dictionary every other member names principals through.</param>
/// <param name="Identities">Which principal each SID identifies, current and historical.</param>
/// <param name="Principals">The per-principal facts a membership question needs.</param>
/// <param name="Edges">The direct nesting relationships, as dictionary id pairs.</param>
/// <param name="UnresolvedTrustees">
/// Names a group claimed as a member that no captured object answers to. Carried rather than
/// dropped: a member from a domain the run did not cover is a fact about the capture's coverage,
/// and a closure built over these edges is incomplete by exactly this much.
/// </param>
/// <param name="ObjectsWithoutSid">
/// How many captured objects carried no <c>objectSid</c>. Most are ordinary - a container has no
/// SID - but the count is kept because a principal missing one is invisible to every closure.
/// </param>
/// <param name="CollapsedStubs">
/// How many captured objects named a principal another object had already answered for. A universal
/// well-known SID is held once in the configuration partition and again as a stub in every domain,
/// and all of them are the same principal - so the extra objects are folded onto it. Counted rather
/// than passed over, because a fidelity loss nobody is told about is one nobody can check.
/// </param>
/// <param name="ForestHeuristics">
/// The forest's <c>dSHeuristics</c> value, an empty string where the object carries none, or null
/// where the bundle does not hold the object at all. Required rather than defaulted, per gate 1:
/// a default of null would make "nobody read it" the quiet answer, and that is precisely the state
/// a caller must decide about rather than inherit.
/// </param>
internal sealed record NestingFacts(
    SidInterner Sids,
    IReadOnlyList<SidIdentityRow> Identities,
    IReadOnlyList<PrincipalRow> Principals,
    IReadOnlyList<NestingEdge> Edges,
    IReadOnlyList<string> UnresolvedTrustees,
    int ObjectsWithoutSid,
    int CollapsedStubs,
    string? ForestHeuristics)
{
    /// <summary>The SID prefix of the forest-root domain, derived from sealed Evidence.</summary>
    public string? ForestRootDomainSid { get; init; }
}

/// <summary>
/// Reads a sealed bundle once and works out the directory's nesting: who is in what, what each
/// principal's other identities are, and which group each account names as its primary.
/// </summary>
/// <remarks>
/// <para>
/// <b>One pass, because the bundle is the expensive part.</b> A forest capture is hours of data,
/// and every phase that walks it again pays that cost again. Everything three different closures
/// need is collected here, once, and they are computed from the result rather than from the file.
/// </para>
/// <para>
/// <b>Edges cannot be resolved while reading, so they are resolved afterwards.</b> Membership is
/// written in distinguished names; the store holds SIDs. The object a name refers to may not have
/// been streamed yet, so names are interned as they go past and turned into SIDs once the pass has
/// seen everything it is going to see.
/// </para>
/// <para>
/// <b>It reads both <c>member</c> and <c>memberOf</c>, which describe the same relationships.</b>
/// Storing an edge twice costs nothing - the table ignores the duplicate - and reading only one
/// side would lose every relationship whose other half was not captured.
/// </para>
/// </remarks>
internal static class MembershipNestingPass
{
    /// <summary>The name this phase is recorded under.</summary>
    public const string PhaseName = "MembershipAndNesting";

    private const int GroupTypeSecurityEnabled = unchecked((int)0x80000000);

    /// <summary>
    /// Whether a group's flags say it can carry authorization.
    /// </summary>
    /// <remarks>
    /// Computed from the raw flags rather than stored beside them, so the answer cannot drift from
    /// what it was derived from. Null when the group's <c>groupType</c> was not captured, because
    /// a group whose type nobody knows is not a group known to be a distribution group.
    /// </remarks>
    /// <param name="groupType">The raw <c>groupType</c> flags word.</param>
    public static bool? IsSecurityEnabled(int? groupType) =>
        groupType is null ? null : (groupType.Value & GroupTypeSecurityEnabled) != 0;

    /// <summary>
    /// Reads every object in a bundle and returns the nesting facts.
    /// </summary>
    /// <param name="objects">The bundle's objects, streamed.</param>
    /// <param name="cancellationToken">Stops the pass between objects.</param>
    /// <returns>What the pass found.</returns>
    public static NestingFacts Read(
        IEnumerable<ObjectAttributes> objects,
        string forestFqdn,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(objects);
        ArgumentException.ThrowIfNullOrWhiteSpace(forestFqdn);

        var sids = new SidInterner();
        var names = new DistinguishedNameIndex();

        // Keyed by principal id rather than appended, because one principal can be captured more
        // than once and the store holds one row per principal. A universal well-known SID appears
        // in the WellKnown Security Principals container and again as a foreignSecurityPrincipal
        // stub in every domain - four objects for S-1-5-11 in a three-domain forest, all the same
        // principal. Appending a row each time is what ended the first multi-domain derivation:
        // UNIQUE constraint failed: sid_identity.sid_id.
        var identities = new Dictionary<int, Ranked<SidIdentityRow>>();
        var principals = new Dictionary<int, Ranked<PrincipalRow>>();

        // Held as name-id pairs until the pass is over, because the far side of an edge may not have
        // been streamed yet.
        var pendingEdges = new List<(int GroupNameId, int MemberNameId)>();
        var objectsWithoutSid = 0;
        var collapsedStubs = 0;

        // The forest's own settings, picked up from the object that carries them rather than by
        // reading the bundle a second time. There is one nTDSService object in a forest and this
        // pass already goes past every object, so noticing it here costs nothing - where a separate
        // read would open the evidence again for one string.
        //
        // Null until the object is seen, and that is the point: a bundle whose capture predates the
        // attribute carries no value because nobody asked, which is not the same as a forest that
        // set none. Only the first stays null.
        string? forestHeuristics = null;
        string? forestRootDomainSid = null;

        foreach (var subject in objects)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var ownNameId = names.IdOf(subject.DistinguishedName);
            var ownSid = SidTextOf(subject, "objectSid");

            // Before the no-SID branch below, because the object carrying this has no SID: it is a
            // settings object, not a principal, and the branch that skips such objects would skip
            // this with them.
            forestHeuristics ??= HeuristicsOf(subject);

            if (ownSid is null)
            {
                // Ordinary for a container or an organisational unit. Counted rather than ignored:
                // a principal with no SID takes part in no closure, and a reader should be able to
                // see how much of the directory that was.
                objectsWithoutSid++;
                CollectEdges(subject, ownNameId, names, pendingEdges);
                continue;
            }

            if (string.Equals(subject.DomainFqdn, forestFqdn, StringComparison.OrdinalIgnoreCase))
            {
                var candidate = DomainSidOf(ownSid);
                if (candidate is not null)
                {
                    if (forestRootDomainSid is not null
                        && !string.Equals(forestRootDomainSid, candidate, StringComparison.Ordinal))
                    {
                        throw new InvalidOperationException(
                            $"Forest root domain '{forestFqdn}' produced conflicting domain SIDs.");
                    }

                    forestRootDomainSid = candidate;
                }
            }

            var classes = ClassesOf(subject);

            // A stub stands in for a principal rather than being one. Where a real object and a
            // stub carry the same SID, the real object's facts are the ones worth keeping - its
            // objectClass, its groupType, its GUID. A stub has none of those to offer.
            var isStub = classes.Any(
                c => string.Equals(c, "foreignSecurityPrincipal", StringComparison.OrdinalIgnoreCase));

            var rank = isStub ? StubRank : PrincipalRank;

            var ownSidId = sids.Intern(ownSid, subject.DomainFqdn);
            names.BindSid(ownNameId, ownSidId);

            KeepBest(identities, ownSidId, rank, new SidIdentityRow(ownSidId, ownSidId, SidIdentityKind.Current));

            foreach (var historical in SidTextsOf(subject, "sIDHistory"))
            {
                // An ACE naming the old SID reaches this principal. It is another identity it
                // carries, not another group it is in, so it is never made into an edge.
                //
                // Ranked below any current identity: a SID that is somebody's current SID belongs
                // to that principal, whatever another object's history claims about it.
                var historicalId = sids.Intern(historical, subject.DomainFqdn);
                KeepBest(
                    identities,
                    historicalId,
                    HistoryRank,
                    new SidIdentityRow(historicalId, ownSidId, SidIdentityKind.History));
            }

            var isGroup = classes.Any(c => string.Equals(c, "group", StringComparison.OrdinalIgnoreCase));
            var groupType = SignedIntegerOf(subject, "groupType");
            var primaryGroupSidId = PrimaryGroupSidIdOf(subject, ownSid, sids, subject.DomainFqdn);

            // Counted here rather than beside the identity so one folded object counts once,
            // whichever of the two objects turned out to hold the better row.
            if (!KeepBest(
                principals,
                ownSidId,
                rank,
                new PrincipalRow(
                    ownSidId,
                    subject.ObjectGuid ?? Guid.Empty,
                    isGroup,
                    groupType,
                    primaryGroupSidId)))
            {
                collapsedStubs++;
            }

            CollectEdges(subject, ownNameId, names, pendingEdges);
        }

        var edges = new List<NestingEdge>(pendingEdges.Count);
        var unresolved = new List<string>();

        foreach (var (groupNameId, memberNameId) in pendingEdges)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (!names.TryResolve(groupNameId, out var groupSidId))
            {
                unresolved.Add(names.TextOf(groupNameId));
                continue;
            }

            if (!names.TryResolve(memberNameId, out var memberSidId))
            {
                unresolved.Add(names.TextOf(memberNameId));
                continue;
            }

            edges.Add(new NestingEdge(groupSidId, memberSidId));
        }

        return new NestingFacts(
            sids,
            [.. identities.Values.Select(r => r.Value)],
            [.. principals.Values.Select(r => r.Value)],
            edges,
            [.. unresolved.Distinct(StringComparer.OrdinalIgnoreCase)],
            objectsWithoutSid,
            collapsedStubs,
            forestHeuristics)
        {
            ForestRootDomainSid = forestRootDomainSid,
        };
    }

    private static string? DomainSidOf(string sid)
    {
        var parts = sid.Split('-');
        if (parts.Length != 8
            || !string.Equals(parts[0], "S", StringComparison.OrdinalIgnoreCase)
            || parts[1] != "1"
            || parts[2] != "5"
            || parts[3] != "21"
            || parts.Skip(4).Any(part => !uint.TryParse(part, out _)))
        {
            return null;
        }

        return string.Join('-', parts[..^1]);
    }

    /// <summary>
    /// Collects both halves of the relationships this object describes.
    /// </summary>
    private static void CollectEdges(
        ObjectAttributes subject,
        int ownNameId,
        DistinguishedNameIndex names,
        List<(int, int)> pendingEdges)
    {
        // This object is the group; each value names something inside it.
        foreach (var memberDn in TextsOf(subject, "member"))
            pendingEdges.Add((ownNameId, names.IdOf(memberDn)));

        // This object is the member; each value names a group it is in.
        foreach (var groupDn in TextsOf(subject, "memberOf"))
            pendingEdges.Add((names.IdOf(groupDn), ownNameId));
    }

    /// <summary>
    /// The SID named by <c>primaryGroupID</c>, which is a relative identifier rather than a SID.
    /// </summary>
    /// <remarks>
    /// <b>The group is in the account's own domain, so its SID is the account's with the last part
    /// replaced.</b> Microsoft's specifications state that <c>primaryGroupID</c> identifies a group
    /// the account is a member of, and that neither the account's <c>memberOf</c> nor the group's
    /// <c>member</c> carries the relationship - so a traversal that reads only those two is
    /// incomplete, and an account whose primary group is a privileged one would go unseen.
    /// </remarks>
    private static int? PrimaryGroupSidIdOf(
        ObjectAttributes subject,
        string ownSid,
        SidInterner sids,
        string? domainFqdn)
    {
        var rid = SignedIntegerOf(subject, "primaryGroupID");
        if (rid is null)
            return null;

        var lastSeparator = ownSid.LastIndexOf('-');
        if (lastSeparator <= 0)
            return null;

        var domainSid = ownSid[..lastSeparator];
        return sids.Intern(
            domainSid + "-" + rid.Value.ToString(CultureInfo.InvariantCulture),
            domainFqdn);
    }

    /// <summary>How good a claim one captured object has to be the row for a principal.</summary>
    /// <remarks>
    /// Lower wins. The order is the whole of the precedence: a real object beats a stub standing in
    /// for it, and any current identity beats a historical claim on the same SID.
    /// </remarks>
    private const int PrincipalRank = 0;

    /// <inheritdoc cref="PrincipalRank"/>
    private const int StubRank = 1;

    /// <inheritdoc cref="PrincipalRank"/>
    private const int HistoryRank = 2;

    /// <summary>One row and how strong a claim it has to its key.</summary>
    private readonly record struct Ranked<T>(T Value, int Rank);

    /// <summary>
    /// Keeps <paramref name="row"/> if nothing better is already held for <paramref name="key"/>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Ties go to what arrived first, which makes the result depend on nothing but the bundle.</b>
    /// Objects are streamed in <c>object_id</c> order, so two objects with equal claim resolve the
    /// same way on every derivation of the same evidence - and a derived fact that changed between
    /// two runs over one sealed bundle would be a fact about this product rather than the forest.
    /// </para>
    /// <para>
    /// <b>It answers whether the key was new, not whether this row won.</b> A stub captured before
    /// the principal it stands for is replaced rather than discarded, and both orders are the same
    /// event: two objects, one principal. Counting only the discards would report the collapse in
    /// one order and miss it in the other.
    /// </para>
    /// </remarks>
    /// <returns>Whether this was the first row seen for the key.</returns>
    private static bool KeepBest<T>(Dictionary<int, Ranked<T>> rows, int key, int rank, T row)
    {
        if (!rows.TryGetValue(key, out var held))
        {
            rows[key] = new Ranked<T>(row, rank);
            return true;
        }

        if (rank < held.Rank)
            rows[key] = new Ranked<T>(row, rank);

        return false;
    }

    private static string? SidTextOf(ObjectAttributes subject, string ldapDisplayName) =>
        SidTextsOf(subject, ldapDisplayName).FirstOrDefault();

    private static IEnumerable<string> SidTextsOf(ObjectAttributes subject, string ldapDisplayName) =>
        subject.Attributes
            .Where(a => string.Equals(a.LdapDisplayName, ldapDisplayName, StringComparison.OrdinalIgnoreCase))
            .SelectMany(a => a.Values)
            .Select(v => v.Bytes is null ? null : Sid.ToText(v.Bytes))
            .Where(s => s is not null)
            .Select(s => s!);

    private static IReadOnlyList<string> TextsOf(ObjectAttributes subject, string ldapDisplayName) =>
    [
        .. subject.Attributes
            .Where(a => string.Equals(a.LdapDisplayName, ldapDisplayName, StringComparison.OrdinalIgnoreCase))
            .SelectMany(a => a.Values)
            .Select(v => v.Text)
            .Where(t => !string.IsNullOrWhiteSpace(t))
            .Select(t => t!),
    ];

    private static IReadOnlyList<string> ClassesOf(ObjectAttributes subject) =>
        TextsOf(subject, "objectClass");

    /// <summary>
    /// The forest's <c>dSHeuristics</c>, if this object is the one that carries it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Recognised by class rather than by name.</b> The object's distinguished name ends in the
    /// forest root's own, so matching on a name would mean composing one out of a domain - the
    /// string surgery <c>a-domain-left-out-on-purpose.md</c> refuses. There is one
    /// <c>nTDSService</c> object per forest, so its class identifies it and nothing has to be
    /// assembled.
    /// </para>
    /// <para>
    /// <b>An empty string is returned where the object holds no value, and it is not null.</b> That
    /// distinction is the whole point: the object being present means the forest was asked, and
    /// MS-ADTS says an absent value means every character defaults. Null is reserved for never
    /// having looked.
    /// </para>
    /// </remarks>
    private static string? HeuristicsOf(ObjectAttributes subject)
    {
        if (!ClassesOf(subject).Any(
                c => string.Equals(c, "nTDSService", StringComparison.OrdinalIgnoreCase)))
        {
            return null;
        }

        return TextsOf(subject, "dSHeuristics").FirstOrDefault() ?? string.Empty;
    }

    private static int? SignedIntegerOf(ObjectAttributes subject, string ldapDisplayName) =>
        int.TryParse(
            TextsOf(subject, ldapDisplayName).FirstOrDefault(),
            NumberStyles.Integer,
            CultureInfo.InvariantCulture,
            out var value)
            ? value
            : null;
}
