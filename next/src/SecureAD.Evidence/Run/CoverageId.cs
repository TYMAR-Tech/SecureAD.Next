namespace SecureAD.Evidence.Run;

/// <summary>
/// Identifies the evidence a run is built from: the domains the forest reported when it started.
/// </summary>
/// <remarks>
/// <para>
/// Two runs assessed the same evidence when their <see cref="ProfileId"/> matches <i>and</i> their
/// <see cref="CoverageId"/> matches. The profile answers <i>same forest</i> and keeps a forest's
/// history together; this answers <i>same evidence</i> and is what makes a comparison a like for
/// like one.
/// </para>
/// <para>
/// <b>Kept apart from the profile because the two are not recoverable the same way.</b> A profile
/// can be recomputed from the forest name alone, so a bundle missing its metadata can still be
/// grouped. A coverage identity can only be read back from where the run recorded it. A combined
/// type would force a half-populated value at exactly the sites that recompute the profile, and a
/// wrong key there silently groups runs that must not be compared.
/// </para>
/// <para>
/// <b>It hashes what the forest reported, not what the run managed to read.</b> A controller dying
/// at hour two must not give the run a private identity and strand it on a comparison island of
/// one. Whether the declaration was achieved is a different question, answered by
/// <see cref="RunCoverage"/> - and under
/// <c>docs/decisions/0027-coverage-varies-only-by-failure-or-by-the-forest-changing.md</c> a run
/// that failed to read a domain is refused a comparison outright, so the failure is reported
/// rather than hidden inside a key that no longer matches.
/// </para>
/// <para>
/// <b>Excluded domains are not accounted for here yet, and that is a known gap rather than a
/// design.</b> The predecessor hashed a list of operator-chosen organisational unit exclusions
/// alongside the domains. Those are gone for good:
/// <c>docs/decisions/0052-the-domain-is-the-only-unit-of-scope.md</c> reads everything below a
/// domain whole, so there is nothing smaller to exclude. But <c>0052</c> does let an operator leave
/// out a whole domain, and it requires this identity to account for the excluded set - so that a
/// run carrying an exclusion is never comparable with a whole-forest one and the difference cannot
/// be read as change in the directory. Nothing here does that, because nothing can yet produce an
/// exclusion. <b>When the exclusion type exists, this is the guardrail that has to be built with
/// it</b>; until then the only way coverage varies is a domain that could not be fully read, or a
/// forest that genuinely changed shape.
/// </para>
/// <para>
/// This paragraph previously stated that there are no exclusions at all and cited <c>0017</c> for
/// it. That was true when written and stopped being true at <c>0052</c>.
/// </para>
/// </remarks>
public sealed record CoverageId
{
    private CoverageId(string value, string forestFqdn, IReadOnlyList<string> declaredDomains)
    {
        Value = value;
        ForestFqdn = forestFqdn;
        DeclaredDomains = declaredDomains;
    }

    /// <summary>Sixteen lowercase hex characters identifying this evidence set.</summary>
    public string Value { get; }

    /// <summary>The forest the domains belong to, lowercased.</summary>
    public string ForestFqdn { get; }

    /// <summary>
    /// The domains that were hashed, lowercased, de-duplicated and sorted.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Kept so a refusal can name the domains that differ. Showing an operator two hashes that do
    /// not match tells him only that something is wrong, which is the shape of message this
    /// product is being rebuilt to stop producing.
    /// </para>
    /// <para>
    /// <b>Internal on purpose.</b> Gate 4 forbids a public member handing back a collection from a
    /// type that cannot say whether it looked, because an empty list and a failed query render as
    /// the same empty grid. This list can never be empty - <see cref="ForDomains"/> refuses a run
    /// that declared nothing - so the ambiguity cannot arise, but that is an argument for a fourth
    /// kind of exemption and the allowlist says plainly that a reason which is not <i>a compiled
    /// table that cannot fail</i> does not belong in it. Widening an allowlist is how a gate dies.
    /// </para>
    /// <para>
    /// So the list stays inside the assembly, where <see cref="RunCoverage"/> and
    /// <see cref="RunComparability"/> need it. Callers outside read the same domains from
    /// <see cref="RunCoverage.Domains"/>, which carries
    /// <see cref="RunCoverage.AllDeclaredUnitsAreComplete"/> beside
    /// them and is therefore able to say whether it looked.
    /// </para>
    /// </remarks>
    internal IReadOnlyList<string> DeclaredDomains { get; }

    /// <summary>
    /// Computes the evidence identity of a run over <paramref name="declaredDomains"/>.
    /// </summary>
    /// <param name="forestFqdn">
    /// The forest the domains belong to. Part of the identity as well as of the profile, because a
    /// bundle copied in by hand from another machine must not be offered as a comparison partner
    /// for a forest it does not belong to.
    /// </param>
    /// <param name="declaredDomains">
    /// Every domain the forest reported at the start of the run. Order is discarded, because the
    /// order discovery happened to return them in is not a fact about the forest; case is
    /// discarded and repeats collapse, for the same reason.
    /// </param>
    /// <returns>The evidence identity.</returns>
    /// <exception cref="ArgumentNullException">Either argument is null.</exception>
    /// <exception cref="ArgumentException">
    /// The forest name is blank, a domain is blank, or no domain was declared. A run that declared
    /// nothing assessed nothing, and giving it an identity would produce a key that quietly groups
    /// every such run together as mutually comparable.
    /// </exception>
    public static CoverageId ForDomains(string forestFqdn, IEnumerable<string> declaredDomains)
    {
        ArgumentNullException.ThrowIfNull(forestFqdn);
        ArgumentNullException.ThrowIfNull(declaredDomains);
        ArgumentException.ThrowIfNullOrWhiteSpace(forestFqdn);

        var forest = forestFqdn.Trim().ToLowerInvariant();

        var domains = new List<string>();
        foreach (var domain in declaredDomains)
        {
            if (string.IsNullOrWhiteSpace(domain))
            {
                throw new ArgumentException(
                    "A declared domain was blank. A coverage identity computed over a blank entry "
                    + "would differ from one computed without it, so two runs of the same forest "
                    + "would stop being comparable on nothing.",
                    nameof(declaredDomains));
            }

            domains.Add(domain.Trim().ToLowerInvariant());
        }

        if (domains.Count == 0)
        {
            throw new ArgumentException(
                "No domain was declared. A run that assessed no domain has no evidence to be "
                + "identified by.",
                nameof(declaredDomains));
        }

        var normalised = domains
            .Distinct(StringComparer.Ordinal)
            .OrderBy(d => d, StringComparer.Ordinal)
            .ToArray();

        var value = RunHash.Of($"forest|{forest}|domains|{string.Join(',', normalised)}");

        return new CoverageId(value, forest, normalised);
    }

    /// <summary>Returns <see cref="Value"/>.</summary>
    public override string ToString() => Value;
}
