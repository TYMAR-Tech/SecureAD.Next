using SecureAD.Evidence.Run;

namespace SecureAD.Evidence.Inventory;

/// <summary>
/// How many objects of each kind one domain held.
/// </summary>
/// <remarks>
/// <para>
/// <b>The kinds are the most specific class the controller sent, not any class in the chain.</b>
/// <c>objectClass</c> arrives least specific first - <c>top</c>, <c>person</c>,
/// <c>organizationalPerson</c>, <c>user</c> - so a computer's chain contains <c>user</c> and a
/// group managed service account's contains <c>computer</c>. Counting every object whose chain
/// contains <c>user</c> would report every workstation and every domain controller in the forest
/// as a user account, and the figure would look entirely plausible while being wrong. This is the
/// same rule <see cref="ObjectListing"/> applies for the object grid, so the dashboard and the
/// tree cannot disagree about what a user is.
/// </para>
/// <para>
/// <b>Zero is a claim here, and that is why this type is only ever handed out beside coverage.</b>
/// A domain read in full that holds no organisational units genuinely has none. A domain that was
/// never read holds an unknown number, and the two must not both render as <c>0</c>. See
/// <see cref="DomainInventory"/>, which is the only thing that constructs one.
/// </para>
/// </remarks>
/// <param name="Users">Accounts whose most specific class is <c>user</c>.</param>
/// <param name="Computers">Accounts whose most specific class is <c>computer</c>.</param>
/// <param name="Groups">Objects whose most specific class is <c>group</c>.</param>
/// <param name="OrganisationalUnits">
/// Containers whose most specific class is <c>organizationalUnit</c>.
/// </param>
public sealed record ObjectCounts(int Users, int Computers, int Groups, int OrganisationalUnits)
{
    /// <summary>A count of nothing, for a domain that was read and held none of these.</summary>
    public static ObjectCounts None { get; } = new(0, 0, 0, 0);

    /// <summary>Every object of the four counted kinds.</summary>
    /// <remarks>
    /// Not every object in the domain. The directory holds containers, contacts, printers and much
    /// else that this does not count, so presenting it as <i>objects in the domain</i> would
    /// overstate what was measured.
    /// </remarks>
    public int OfTheseKinds => Users + Computers + Groups + OrganisationalUnits;

    /// <summary>Adds two counts, for totalling the domains that were counted.</summary>
    /// <param name="left">One count.</param>
    /// <param name="right">The other.</param>
    public static ObjectCounts operator +(ObjectCounts left, ObjectCounts right)
    {
        ArgumentNullException.ThrowIfNull(left);
        ArgumentNullException.ThrowIfNull(right);

        return new ObjectCounts(
            left.Users + right.Users,
            left.Computers + right.Computers,
            left.Groups + right.Groups,
            left.OrganisationalUnits + right.OrganisationalUnits);
    }

    /// <summary>Named so the operator is available to callers that cannot use it.</summary>
    /// <param name="left">One count.</param>
    /// <param name="right">The other.</param>
    public static ObjectCounts Add(ObjectCounts left, ObjectCounts right) => left + right;
}

/// <summary>
/// What one declared domain contributed to the inventory, and whether it contributed anything at
/// all.
/// </summary>
/// <remarks>
/// <para>
/// <b>This type exists so that "could not read" has no number in it to render.</b> A dashboard is
/// the easiest screen in the product to make dishonest, because a count with no denominator always
/// looks like an answer - and the specific way it goes wrong is that a domain nobody could read
/// draws a <c>0</c>, which tells an administrator his directory is clean. Holding the counts in a
/// nullable field reached only through <see cref="TryGetCounts"/> means a caller cannot obtain a
/// number without having been told whether it means anything. That is
/// <c>docs/decisions/0002-absent-view-means-degraded-run.md</c> enforced by the type rather than by
/// everyone remembering to check a flag.
/// </para>
/// <para>
/// <b>The coverage travels with the counts rather than beside them.</b> Two parallel collections -
/// one of counts, one of outcomes - is an arrangement that is correct until somebody sorts,
/// filters or pages one of them, and the failure is silent when it comes.
/// </para>
/// </remarks>
public sealed record DomainInventory
{
    private readonly ObjectCounts? _counts;

    private DomainInventory(
        DomainCoverage coverage,
        ObjectCounts? counts,
        bool mayBeMissingConfidentialValues)
    {
        Coverage = coverage;
        _counts = counts;
        MayBeMissingConfidentialValues = mayBeMissingConfidentialValues;
    }

    /// <summary>What became of this domain during the run.</summary>
    public DomainCoverage Coverage { get; }

    /// <summary>The domain, lowercased.</summary>
    public string DomainFqdn => Coverage.DomainFqdn;

    /// <summary>Whether this domain has counts to show at all.</summary>
    /// <remarks>
    /// True only where <see cref="DomainCoverage.Outcome"/> is
    /// <see cref="DomainReadOutcome.Read"/>. Every other outcome - unread, partly read, excluded
    /// by choice, excluded for want of a controller - leaves the number unknown, and an unknown
    /// number is stated as unknown rather than guessed at.
    /// </remarks>
    public bool WasCounted => _counts is not null;

    /// <summary>
    /// Whether the connection this domain was read over could have had confidential attributes
    /// stripped from it without saying so.
    /// </summary>
    /// <remarks>
    /// A Windows Server 2025 controller removes confidential attributes from an unencrypted search
    /// and returns no error (<c>F-S24-1</c>). The object count itself is unaffected - an object
    /// still arrives - but a screen that shows a total from such a read without saying this has
    /// presented a figure more certain than the evidence supports.
    /// </remarks>
    public bool MayBeMissingConfidentialValues { get; }

    /// <summary>
    /// The counts, where this domain was read.
    /// </summary>
    /// <param name="counts">What was counted, when this returns true.</param>
    /// <returns>
    /// True where the domain was read in full and the counts mean what they say; false where
    /// nothing can be said, in which case <paramref name="counts"/> is null and there is no zero
    /// to mistake for an answer.
    /// </returns>
    public bool TryGetCounts(out ObjectCounts? counts)
    {
        counts = _counts;
        return _counts is not null;
    }

    /// <summary>Records a domain that was read in full, with what it held.</summary>
    /// <param name="coverage">Its coverage, which must be <see cref="DomainReadOutcome.Read"/>.</param>
    /// <param name="counts">What it held.</param>
    /// <param name="mayBeMissingConfidentialValues">
    /// Whether it was read over a connection that could have withheld confidential attributes.
    /// </param>
    /// <exception cref="ArgumentException">
    /// <paramref name="coverage"/> is not a domain that was read. Counting an unread domain is the
    /// defect this type exists to prevent, so it is refused at construction rather than checked by
    /// the screen.
    /// </exception>
    public static DomainInventory Counted(
        DomainCoverage coverage, ObjectCounts counts, bool mayBeMissingConfidentialValues)
    {
        ArgumentNullException.ThrowIfNull(coverage);
        ArgumentNullException.ThrowIfNull(counts);

        if (coverage.Outcome != DomainReadOutcome.Read)
        {
            throw new ArgumentException(
                $"'{coverage.DomainFqdn}' was {coverage.Outcome} and has no count to report.",
                nameof(coverage));
        }

        return new DomainInventory(coverage, counts, mayBeMissingConfidentialValues);
    }

    /// <summary>Records a domain that contributed no count, and why.</summary>
    /// <param name="coverage">
    /// Its coverage, which must be anything but <see cref="DomainReadOutcome.Read"/>.
    /// </param>
    /// <exception cref="ArgumentException">
    /// <paramref name="coverage"/> says the domain was read. A domain that was read has a count,
    /// and recording it as uncounted would hide a number the evidence holds.
    /// </exception>
    public static DomainInventory NotCounted(DomainCoverage coverage)
    {
        ArgumentNullException.ThrowIfNull(coverage);

        if (coverage.Outcome == DomainReadOutcome.Read)
        {
            throw new ArgumentException(
                $"'{coverage.DomainFqdn}' was read and its objects can be counted.",
                nameof(coverage));
        }

        return new DomainInventory(coverage, counts: null, mayBeMissingConfidentialValues: false);
    }
}

/// <summary>
/// What one run's evidence can say about the size of the forest it read.
/// </summary>
/// <remarks>
/// <para>
/// <b>Counted per domain and totalled afterwards, rather than counted forest-wide.</b> A single
/// forest-wide figure cannot show a hole: a run that read two domains of three produces a smaller
/// number, and a smaller number looks exactly like a smaller forest. Rows per domain make an
/// uncovered domain a visibly absent row, which is the owner's decision of 2026-09-05.
/// </para>
/// <para>
/// <b>The policy figures are read of declared, not a count on its own.</b>
/// <see cref="SysvolCoverage"/> knows both, so the exact numbers are stated rather than a
/// proportion or a warning - the owner's ruling of 2026-09-05: where we can say how many were read
/// and how many were not, we say both. This is the one genuine partial a sealed bundle can hold,
/// because <c>docs/decisions/0044</c> lets a SYSVOL failure through without failing the run.
/// </para>
/// </remarks>
public sealed record ForestInventory
{
    private ForestInventory(
        string forestFqdn,
        IReadOnlyList<DomainInventory> domains,
        int policiesDeclared,
        int policiesRead)
    {
        ForestFqdn = forestFqdn;
        Domains = domains;
        PoliciesDeclared = policiesDeclared;
        PoliciesRead = policiesRead;
    }

    /// <summary>The forest the run captured.</summary>
    public string ForestFqdn { get; }

    /// <summary>Every declared domain, counted or not, sorted by name.</summary>
    public IReadOnlyList<DomainInventory> Domains { get; }

    /// <summary>How many Group Policy objects the directory declared - the denominator.</summary>
    public int PoliciesDeclared { get; }

    /// <summary>How many of those had their files read in full.</summary>
    public int PoliciesRead { get; }

    /// <summary>How many policies could not be read in full.</summary>
    public int PoliciesNotRead => PoliciesDeclared - PoliciesRead;

    /// <summary>Whether every declared policy's files were read.</summary>
    public bool AllPoliciesRead => PoliciesNotRead == 0;

    /// <summary>How many domains the forest declared.</summary>
    public int DomainsDeclared => Domains.Count;

    /// <summary>How many of them were read and therefore counted.</summary>
    public int DomainsCounted => Domains.Count(d => d.WasCounted);

    /// <summary>
    /// Whether every declared domain was read, so the counts beside this are the whole forest.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>This is what vouches for <see cref="Domains"/> and <see cref="CountedTotal"/> under gate
    /// 4.</b> A caller holding the list can tell a complete inventory from a partial one without
    /// inspecting every row, so a total is never handed on as a fact about the forest when it is a
    /// fact about part of one.
    /// </para>
    /// <para>
    /// <b>Named to match <see cref="RunScope.AllDeclaredDomainsAreComplete"/> rather than something
    /// shorter.</b> It is the same statement one level up, and two words for one idea is how a
    /// reader comes to believe they are different questions.
    /// </para>
    /// </remarks>
    public bool AllDeclaredDomainsAreComplete => DomainsCounted == DomainsDeclared;

    /// <summary>
    /// The domains that contributed nothing, in the order they are declared.
    /// </summary>
    /// <remarks>
    /// Named rather than counted. <i>2 of 3</i> tells an operator how many and not which, and
    /// which is what decides whether the total covers the domain he is worried about.
    /// </remarks>
    public IReadOnlyList<DomainInventory> UncountedDomains =>
        [.. Domains.Where(d => !d.WasCounted)];

    /// <summary>
    /// Domains the forest named no writable controller for, so nothing was ever attempted.
    /// </summary>
    /// <remarks>
    /// Held out separately because it is not a decision the operator made. It is a trust,
    /// replication or decommissioning problem he may not know about, and
    /// <c>docs/decisions/0063</c> requires it never to read as an ordinary exclusion.
    /// </remarks>
    public IReadOnlyList<DomainInventory> DomainsWithNoController =>
        [.. Domains.Where(d =>
            d.Coverage.Outcome == DomainReadOutcome.ExcludedForWantOfCandidates)];

    /// <summary>Whether any counted domain was read over a connection that could withhold.</summary>
    public bool AnyDomainMayBeMissingConfidentialValues =>
        Domains.Any(d => d.WasCounted && d.MayBeMissingConfidentialValues);

    /// <summary>
    /// The counted domains added together.
    /// </summary>
    /// <remarks>
    /// <b>A total over what was counted, never over what was declared.</b> It is only the whole
    /// forest when <see cref="EveryDomainCounted"/> is true, and any screen showing it must say
    /// which domains it covers - which is why <see cref="UncountedDomains"/> names them.
    /// </remarks>
    public ObjectCounts CountedTotal =>
        Domains.Aggregate(
            ObjectCounts.None,
            (running, domain) => domain.TryGetCounts(out var counts)
                ? running + counts!
                : running);

    /// <summary>Records what a run's evidence can say about the forest's size.</summary>
    /// <param name="forestFqdn">The forest the run captured.</param>
    /// <param name="domains">Every declared domain, counted or not.</param>
    /// <param name="policiesDeclared">How many policies the directory declared.</param>
    /// <param name="policiesRead">How many of them were read in full.</param>
    public static ForestInventory Of(
        string forestFqdn,
        IEnumerable<DomainInventory> domains,
        int policiesDeclared,
        int policiesRead)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(forestFqdn);
        ArgumentNullException.ThrowIfNull(domains);
        ArgumentOutOfRangeException.ThrowIfNegative(policiesDeclared);
        ArgumentOutOfRangeException.ThrowIfNegative(policiesRead);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(policiesRead, policiesDeclared);

        var ordered = domains
            .Select(d => d ?? throw new ArgumentException("A domain was null.", nameof(domains)))
            .OrderBy(d => d.DomainFqdn, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        return new ForestInventory(forestFqdn, ordered, policiesDeclared, policiesRead);
    }
}
