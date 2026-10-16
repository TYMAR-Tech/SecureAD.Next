namespace SecureAD.Evidence.Run;

/// <summary>
/// How much of a forest one sealed run actually covered, read back out of its bundle.
/// </summary>
/// <remarks>
/// <para>
/// <b>This is the answer to "3 of 3 domains" on a screen.</b> A run listing says what became of a
/// run - finished, damaged, interrupted. Captured scope is also published in the compact capture
/// root, so the library can group runs without opening their databases.
/// </para>
/// <para>
/// <b>Every declared domain has a row, including the ones nobody read.</b> That is the property
/// <c>domain_coverage</c> exists for: a domain nobody looked at must not be indistinguishable from
/// one that held nothing. So the denominator here is the forest as the run found it, not the number
/// of domains the run managed to get to.
/// </para>
/// <para>
/// <b>Excluded is counted apart from unread</b>, per
/// <c>docs/decisions/0063-excluded-never-looks-like-unreachable.md</c>. An operator reading
/// <i>2 of 3</i> needs to know whether the third was a decision he made or a failure he has not
/// heard about, and those two have different remedies.
/// </para>
/// </remarks>
public sealed record RunScope
{
    private RunScope(string identity, IReadOnlyList<DomainCoverage> domains)
    {
        Identity = identity;
        Domains = domains;
    }

    /// <summary>
    /// Which group of like runs this one belongs to.
    /// </summary>
    /// <remarks>
    /// <b>This is <see cref="CoverageId"/>'s value, read back from the bundle, and not a second
    /// answer computed here.</b> <i>Same evidence</i> is a question <c>CoverageId</c> owns, and a
    /// grouping key worked out independently from the domain rows below would be a second answer to
    /// it - the defect the concept registry exists to prevent. Two runs share a group when this
    /// matches.
    /// </remarks>
    public string Identity { get; }

    /// <summary>
    /// Every domain the forest declared, with what became of it, sorted by name.
    /// </summary>
    /// <remarks>
    /// Sorted so two runs of one forest list their domains alike, and an operator comparing two
    /// screens is not made to do the matching himself.
    /// </remarks>
    public IReadOnlyList<DomainCoverage> Domains { get; }

    /// <summary>How many domains the forest declared. Never zero.</summary>
    public int DeclaredCount => Domains.Count;

    /// <summary>How many were read in full.</summary>
    /// <remarks>
    /// A partially read domain is not counted here. It is a hole of unknown shape, and counting it
    /// as read is the arithmetic <see cref="DomainCoverage"/> exists to refuse.
    /// </remarks>
    public int ReadCount => Domains.Count(d => d.Outcome == DomainReadOutcome.Read);

    /// <summary>How many the operator deliberately left out, of either kind.</summary>
    public int ExcludedCount => Domains.Count(IsExcluded);

    /// <summary>
    /// How many the run tried to read and could not, or read only in part.
    /// </summary>
    /// <remarks>
    /// This is the count that matters most and the one a screen must never merge into
    /// <see cref="ExcludedCount"/>: an operator already knows what he excluded, and this is the
    /// part he has not been told about.
    /// </remarks>
    public int ShortfallCount => Domains.Count(d =>
        d.Outcome is DomainReadOutcome.NotRead or DomainReadOutcome.PartiallyRead);

    /// <summary>
    /// Whether every declared domain was read in full.
    /// </summary>
    /// <remarks>
    /// Named to match <c>RunCoverage.AllDeclaredUnitsAreComplete</c> rather than something shorter,
    /// because it is the same statement one level down and two words for one idea is how a reader
    /// comes to believe they are different questions. It is also what makes the counts beside it
    /// readable: a number on its own cannot say whether it was reached, and this says it.
    /// </remarks>
    public bool AllDeclaredDomainsAreComplete => ReadCount == DeclaredCount;

    /// <summary>
    /// Records what a run covered.
    /// </summary>
    /// <remarks>
    /// <b>Gate 4 is satisfied by <see cref="AllDeclaredDomainsAreComplete"/>, not by hiding this.</b>
    /// This factory was internal for a while on the theory that reaching the counts only through a
    /// <c>Result</c> was what vouched for them. It is not: the gate asks whether the declaring type
    /// states its own completeness, and this one does, which is why the counts may be plain
    /// integers. Hiding the factory bought nothing and cost every caller outside the assembly the
    /// ability to describe a scope.
    /// </remarks>
    /// <param name="identity">The evidence identity the run recorded, from its bundle header.</param>
    /// <param name="domains">One entry per declared domain.</param>
    /// <returns>The scope.</returns>
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    /// <exception cref="ArgumentException">
    /// The identity is blank, no domain was given, or one domain appears twice. A run that declared
    /// no domain assessed nothing, and a scope built from an empty list would report <i>0 of 0
    /// domains read</i> - which reads as a measurement and is the shape of claim this product is
    /// being rebuilt to stop making.
    /// </exception>
    public static RunScope Of(string identity, IEnumerable<DomainCoverage> domains)
    {
        ArgumentNullException.ThrowIfNull(identity);
        ArgumentNullException.ThrowIfNull(domains);
        ArgumentException.ThrowIfNullOrWhiteSpace(identity);

        var sorted = domains
            .OrderBy(d => d.DomainFqdn, StringComparer.Ordinal)
            .ToArray();

        if (sorted.Length == 0)
        {
            throw new ArgumentException(
                "No domain was covered. Every bundle records one row per declared domain, so an "
                + "empty set means the coverage table was not read rather than that the forest has "
                + "no domains.",
                nameof(domains));
        }

        var repeated = sorted
            .GroupBy(d => d.DomainFqdn, StringComparer.Ordinal)
            .Where(g => g.Count() > 1)
            .Select(g => g.Key)
            .ToArray();

        if (repeated.Length > 0)
        {
            throw new ArgumentException(
                $"Covered {string.Join(", ", repeated)} more than once. A domain with two outcomes "
                + "has no single answer, and the counts drawn from it would exceed the number of "
                + "domains the forest has.",
                nameof(domains));
        }

        return new RunScope(identity, sorted);
    }

    /// <summary>Whether this outcome is one of the two exclusions.</summary>
    private static bool IsExcluded(DomainCoverage domain) =>
        domain.Outcome is DomainReadOutcome.ExcludedByChoice
            or DomainReadOutcome.ExcludedForWantOfCandidates;
}
