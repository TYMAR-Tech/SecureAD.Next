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
/// <b>The excluded set is part of the identity, alongside the declared one.</b>
/// <c>docs/decisions/0052-the-domain-is-the-only-unit-of-scope.md</c> lets an operator leave out a
/// whole domain, and requires this identity to account for it so that a run carrying an exclusion
/// is never comparable with a whole-forest one and the difference cannot be read as change in the
/// directory. Until 2026-08-21 nothing here did that: two runs of an eight domain forest, one
/// leaving out domain three and one leaving out domain five, both declared all eight and therefore
/// hashed alike - so the product would have offered them as like for like and reported the
/// difference between two different domains as drift.
/// </para>
/// <para>
/// <b>Both sets are hashed, not the difference between them.</b> A forest that genuinely shrank
/// from eight domains to seven, and a run of an eight domain forest that left one out, have the
/// same covered set and are not the same evidence: one estate has seven domains and the other has
/// eight and did not look at one. Hashing only the remainder would merge them.
/// </para>
/// <para>
/// The predecessor also hashed a list of operator-chosen organisational unit exclusions. Those are
/// gone for good - <c>0052</c> reads everything below a domain whole, so there is nothing smaller
/// than a domain to exclude.
/// </para>
/// <para>
/// This remark previously stated that there are no exclusions at all and cited <c>0017</c> for it.
/// That was true when written and stopped being true at <c>0052</c>.
/// </para>
/// </remarks>
public sealed record CoverageId
{
    private CoverageId(
        string value,
        string forestFqdn,
        IReadOnlyList<string> declaredDomains,
        IReadOnlyList<string> excludedDomains)
    {
        Value = value;
        ForestFqdn = forestFqdn;
        DeclaredDomains = declaredDomains;
        ExcludedDomains = excludedDomains;
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
    /// The declared domains the run left out, lowercased, de-duplicated and sorted. Empty when the
    /// run took the whole forest.
    /// </summary>
    /// <remarks>
    /// Kept for the same reason as <see cref="DeclaredDomains"/>: a refusal names the domain rather
    /// than showing two hashes that differ. Internal for the same reason too - gate 4 forbids a
    /// public collection on a type that cannot say whether it looked, and this one can legitimately
    /// be empty, so the ambiguity that gate exists for is real here rather than merely arguable.
    /// </remarks>
    internal IReadOnlyList<string> ExcludedDomains { get; }

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
    public static CoverageId ForDomains(string forestFqdn, IEnumerable<string> declaredDomains) =>
        ForDomainsExcluding(forestFqdn, declaredDomains, []);

    /// <summary>
    /// Computes the evidence identity of a run that declared <paramref name="declaredDomains"/> and
    /// deliberately left <paramref name="excludedDomains"/> out.
    /// </summary>
    /// <param name="forestFqdn">The forest the domains belong to.</param>
    /// <param name="declaredDomains">
    /// Every domain the forest reported at the start of the run, including the excluded ones. This
    /// is the denominator, so a domain does not stop being declared by being left out.
    /// </param>
    /// <param name="excludedDomains">
    /// The domains the run deliberately did not read. Pass the DNS name the forest published -
    /// <c>AttestedExclusion.DomainFqdn</c> carries it for this purpose. Deriving it from a naming
    /// context by string surgery invents a name nobody published and is wrong in exactly the forest
    /// that renamed a domain.
    /// </param>
    /// <returns>The evidence identity.</returns>
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    /// <exception cref="ArgumentException">
    /// The forest name is blank, a domain is blank, no domain was declared, or an excluded domain
    /// was not among the declared ones. The last is refused rather than ignored: a run cannot leave
    /// out a domain the forest never reported, so the pairing is a mistake at the call site, and
    /// silently dropping it would produce an identity that groups runs of different scope.
    /// </exception>
    public static CoverageId ForDomainsExcluding(
        string forestFqdn,
        IEnumerable<string> declaredDomains,
        IEnumerable<string> excludedDomains)
    {
        ArgumentNullException.ThrowIfNull(forestFqdn);
        ArgumentNullException.ThrowIfNull(declaredDomains);
        ArgumentNullException.ThrowIfNull(excludedDomains);
        ArgumentException.ThrowIfNullOrWhiteSpace(forestFqdn);

        var forest = forestFqdn.Trim().ToLowerInvariant();

        var domains = AsSortedDomainSet(declaredDomains, nameof(declaredDomains));

        if (domains.Length == 0)
        {
            throw new ArgumentException(
                "No domain was declared. A run that assessed no domain has no evidence to be "
                + "identified by.",
                nameof(declaredDomains));
        }

        var excluded = AsSortedDomainSet(excludedDomains, nameof(excludedDomains));

        var undeclared = excluded.Except(domains, StringComparer.Ordinal).ToArray();
        if (undeclared.Length > 0)
        {
            throw new ArgumentException(
                $"Excluded {string.Join(", ", undeclared)}, which the forest did not declare. An "
                + "exclusion names a domain the run chose not to read, so one the forest never "
                + "reported is a mistake at the call site rather than a narrower scope.",
                nameof(excludedDomains));
        }

        var value = RunHash.Of(
            $"forest|{forest}"
            + $"|domains|{string.Join(',', domains)}"
            + $"|excluded|{string.Join(',', excluded)}");

        return new CoverageId(value, forest, domains, excluded);
    }

    /// <summary>
    /// Lowercases, trims, de-duplicates and sorts a domain list, refusing a blank entry.
    /// </summary>
    /// <remarks>
    /// Order is discarded because the order discovery happened to return them in is not a fact
    /// about the forest; case is discarded and repeats collapse, for the same reason.
    ///
    /// <para>
    /// Deliberately not called <c>Normalise</c>: <c>CONCEPT-REGISTRY.md</c> gives that word to
    /// <c>AceNormalizer</c>, which canonicalises access control entries, and a second member
    /// carrying it here would read as a second answer to that question.
    /// </para>
    /// </remarks>
    private static string[] AsSortedDomainSet(IEnumerable<string> domains, string parameterName)
    {
        var sorted = new List<string>();

        foreach (var domain in domains)
        {
            if (string.IsNullOrWhiteSpace(domain))
            {
                throw new ArgumentException(
                    "A domain was blank. A coverage identity computed over a blank entry would "
                    + "differ from one computed without it, so two runs of the same forest would "
                    + "stop being comparable on nothing.",
                    parameterName);
            }

            sorted.Add(domain.Trim().ToLowerInvariant());
        }

        return [.. sorted.Distinct(StringComparer.Ordinal).OrderBy(d => d, StringComparer.Ordinal)];
    }

    /// <summary>Returns <see cref="Value"/>.</summary>
    public override string ToString() => Value;
}
