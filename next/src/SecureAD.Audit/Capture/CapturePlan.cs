using SecureAD.Evidence;
using SecureAD.Kernel;

namespace SecureAD.Audit.Capture;

/// <summary>
/// Which naming contexts a run reads, in the order it reads them, and which of the ones the
/// controller published it is deliberately leaving alone.
/// </summary>
/// <remarks>
/// <para>
/// This is inventory row B6's other half, and docs/layers/audit/how-a-controller-is-read.md was the
/// document bound to it. A capture unit is one partition on one controller
/// (docs/layers/audit/the-search-capture-issues.md); this is the list of them.
/// </para>
/// <para>
/// <b>Nothing is discovered here.</b> The plan is built from what it is handed: the forest's domain
/// partitions with a controller for each, its configuration and schema partitions, and the list of
/// partitions the forest declares that this run does not read. Finding those out is branch A. The
/// reason to keep it that way is that a partition list alone cannot tell a domain from an
/// application partition - a name like <c>DC=DomainDnsZones,DC=example,DC=com</c> is spelled
/// exactly as a domain is - and the only reliable answer is in the configuration partition's
/// cross-references. A component that guessed from the name would be right on every forest anybody
/// builds to test it.
/// </para>
/// <para>
/// <b>What the run does not read is stated by the forest, not inferred here.</b> An earlier version
/// computed it by subtracting the units it planned from the partition list it had planned from,
/// which is empty by construction - so a run that saw one domain of nine reported nothing missing.
/// That is <c>F-S28-1</c>. The list now arrives from the forest's own cross-references, so it names
/// the application partitions this product does not read and nothing else.
/// </para>
/// <para>
/// <b>The forest's declaration is carried beside the units, and that is what makes completeness a
/// question with an answer.</b> This type once carried an <c>IsComplete</c> defined as "nothing was
/// left unread", computed by subtracting the units planned from the list they were planned from -
/// empty by construction, so the flag was true no matter what. <see cref="DeclaredDomains"/> comes
/// from the forest's cross-references rather than from anything this type built, so
/// <see cref="IsComplete"/> compares two independently sourced lists.
/// </para>
/// </remarks>
/// <param name="Units">The units to read, in order.</param>
/// <param name="NotRead">
/// Partitions the forest declares that this run does not read - the application directory
/// partitions, of which the DNS zone partitions are the ones every forest has. Recorded rather than
/// omitted, per <c>docs/decisions/0052-the-domain-is-the-only-unit-of-scope.md</c>: a part of the
/// directory the run left alone is stated, never silently absent.
/// </param>
/// <param name="DeclaredDomains">
/// The DNS name of every domain the forest declares it has. This is the denominator a run's
/// coverage is measured against, and it is what <c>CoverageId</c> records when the run starts.
/// </param>
/// <param name="ForestFqdn">
/// The DNS name of the forest, which is its root domain's. Carried here because it comes from the
/// same read as everything else in this type - the RootDSE names the root domain's partition and
/// the cross-references give its DNS name - and a run told the forest's name separately would have
/// a second source for one fact, which is what gate 2 exists to prevent.
/// </param>
public sealed record CapturePlan(
    IReadOnlyList<CaptureUnit> Units,
    IReadOnlyList<string> NotRead,
    IReadOnlyList<string> DeclaredDomains,
    string ForestFqdn)
{
    /// <summary>
    /// The DNS name the forest declared for each domain naming context.
    /// </summary>
    public IReadOnlyDictionary<string, string> DomainDnsNames { get; init; } =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Whether this plan reads every domain the forest declared.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>What it catches:</b> a domain the forest declared that no unit reads. That is
    /// <c>F-S28-1</c> - a forest of nine domains planned as one - and it is the failure that must
    /// never pass silently.
    /// </para>
    /// <para>
    /// <b>What it does not catch, said plainly:</b> it compares how many domains were declared
    /// against how many domain units were planned, not which. Two lists of the same length naming
    /// different domains would satisfy it. That cannot happen while every unit is built from the
    /// declaration in <c>For</c>, and the counts are compared rather than the names because a unit
    /// is identified by its naming context while a declaration is a DNS name - matching them would
    /// mean this type deciding that a controller's host name is a domain's DNS name, which is true
    /// only while controllers are reached through <c>dnsRoot</c> and would break silently the day a
    /// configuration file pins real controllers.
    /// </para>
    /// <para>
    /// Whether a run <i>achieved</i> its plan is <c>RunCoverage.AllDeclaredUnitsAreComplete</c>, which is a
    /// different question and is measured after the reading rather than before it.
    /// </para>
    /// </remarks>
    public bool IsComplete =>
        DeclaredDomains.Count == Units.Count(u => u.Kind == NamingContextKind.Domain);

    /// <summary>Validates that each exclusion identifies one domain exactly as the forest declared it.</summary>
    public AuditError? ValidateExclusions(
        IReadOnlyDictionary<string, AttestedExclusion> exclusions)
    {
        ArgumentNullException.ThrowIfNull(exclusions);

        foreach (var (key, exclusion) in exclusions)
        {
            if (!string.Equals(key, exclusion.NamingContext, StringComparison.OrdinalIgnoreCase))
            {
                return InvalidExclusion(
                    $"The exclusion dictionary names '{key}' while its attestation names "
                    + $"'{exclusion.NamingContext}'.");
            }

            if (!DomainDnsNames.TryGetValue(key, out var declaredDnsName))
            {
                return InvalidExclusion(
                    $"The exclusion names '{key}', which is not a domain naming context this "
                    + "forest declared.");
            }

            if (!string.Equals(
                    declaredDnsName, exclusion.DomainFqdn, StringComparison.OrdinalIgnoreCase))
            {
                return InvalidExclusion(
                    $"The forest pairs '{key}' with '{declaredDnsName}', while the attestation "
                    + $"pairs it with '{exclusion.DomainFqdn}'.");
            }
        }

        return null;
    }

    private static AuditError InvalidExclusion(string detail) => AuditError.Create(
        ErrorCategory.Capture,
        "ExclusionDoesNotMatchDeclaredDomain",
        ErrorSeverity.Failed,
        detail + " No run was created because an exclusion must identify exactly one domain as "
            + "the forest declared it.",
        context: null);

    /// <summary>
    /// The same plan with the named domain partitions taken out of it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>An attested exclusion has to reach the reading, not only the evidence.</b> Recording that
    /// a domain was left out while still reading it produces a bundle that contradicts itself: an
    /// attestation saying nobody looked, filed beside the objects that were captured when somebody
    /// did. An auditor cannot tell which half to believe, and the attestation is the half that
    /// looks authoritative.
    /// </para>
    /// <para>
    /// <b><see cref="DeclaredDomains"/> is deliberately untouched.</b> It is the denominator a
    /// run's coverage is measured against, and the forest still declares the domain that was left
    /// out. Trimming it here would make the run report full coverage of a forest it did not fully
    /// read - which is <c>F-S28-1</c> arriving by the front door. The plan becomes
    /// <see cref="IsComplete"/> false instead, which is true and is what the caller has an
    /// attestation for.
    /// </para>
    /// <para>
    /// <b>Matched on naming context, which is what a unit is identified by.</b> No DNS name is
    /// derived from a distinguished name here, for the reason <see cref="IsComplete"/> gives.
    /// </para>
    /// </remarks>
    /// <param name="namingContexts">
    /// The domain partitions to leave out. Names this plan does not carry are ignored: a caller
    /// holding an attestation for a domain that was never planned has nothing to remove, and that
    /// is not this method's failure to report.
    /// </param>
    public CapturePlan Excluding(IEnumerable<string> namingContexts)
    {
        ArgumentNullException.ThrowIfNull(namingContexts);

        var excluded = namingContexts.ToHashSet(StringComparer.OrdinalIgnoreCase);

        if (excluded.Count == 0)
        {
            return this;
        }

        return this with
        {
            Units =
            [
                .. Units.Where(u =>
                    u.Kind != NamingContextKind.Domain
                    || !excluded.Contains(u.NamingContext)),
            ],
        };
    }

    /// <summary>
    /// Builds the plan for one controller, refusing one that does not hold up.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The configuration and schema partitions are read first, and that ordering is a decision.</b>
    /// They are a few thousand objects once per forest, and they are what everything else is
    /// interpreted against - a permission naming a schema GUID means nothing until the schema
    /// partition has been read, per <c>docs/decisions/0014</c>. Capture is fail-fast, so a run that
    /// is going to fail on them should fail in its first minute rather than after three hours of a
    /// customer's domain.
    /// </para>
    /// <para>
    /// <b>Every unit that can be confirmed here is confirmed here.</b> Discovering at hour two
    /// that a controller was never going to answer for a partition costs the whole capture, and a
    /// forest is only readable as it stands today. The check is
    /// <see cref="CaptureUnit.ConfirmServedBy"/> and it costs nothing for the units read from
    /// <paramref name="domainController"/>, because that controller's published list is already in
    /// hand.
    /// </para>
    /// <para>
    /// <b>A domain read from another controller is not confirmed here, and that is stated rather
    /// than quietly skipped.</b> This method holds one controller's partition list, so a unit
    /// belonging to a different controller has nothing here to be checked against, and a check
    /// written anyway would pass for those units no matter what - which is the shape of
    /// <c>F-S28-2</c>. Those are confirmed by connecting to each domain's own controller before any
    /// reading begins, which is inventory row A8 and is what <c>--validate</c> performs on its own.
    /// </para>
    /// </remarks>
    /// <param name="domainController">
    /// The controller the operator named. The configuration and schema partitions are read from it.
    /// </param>
    /// <param name="configurationNamingContext">The forest's configuration partition.</param>
    /// <param name="schemaNamingContext">The forest's schema partition.</param>
    /// <param name="domains">
    /// The forest's domain partitions as branch A discovered them from the forest's
    /// cross-references: the partition's distinguished name, the domain's DNS name, and the
    /// controller this run reads it from. The DNS name is carried separately from the controller
    /// because they are the same string only while a domain is reached through its own DNS name,
    /// and a configuration file pinning real controllers would part them.
    /// </param>
    /// <param name="namingContextsPublished">
    /// The <c>namingContexts</c> <paramref name="domainController"/> reports in its RootDSE.
    /// </param>
    /// <param name="partitionsNotRead">
    /// Partitions the forest declares that this run does not read.
    /// </param>
    public static Result<CapturePlan> For(
        string domainController,
        string forestFqdn,
        string configurationNamingContext,
        string schemaNamingContext,
        IEnumerable<(string NamingContext, string DnsName, string DomainController)> domains,
        IEnumerable<string> namingContextsPublished,
        IEnumerable<string> partitionsNotRead)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(domainController);
        ArgumentException.ThrowIfNullOrWhiteSpace(forestFqdn);
        ArgumentNullException.ThrowIfNull(domains);
        ArgumentNullException.ThrowIfNull(namingContextsPublished);
        ArgumentNullException.ThrowIfNull(partitionsNotRead);

        var published = namingContextsPublished
            .Where(nc => !string.IsNullOrWhiteSpace(nc))
            .Select(nc => nc.Trim())
            .ToList();

        var forestDomains = domains.ToList();

        var wanted = new List<(string NamingContext, NamingContextKind Kind, string Controller)>
        {
            (configurationNamingContext, NamingContextKind.Configuration, domainController),
            (schemaNamingContext, NamingContextKind.Schema, domainController),
        };

        foreach (var (namingContext, _, controller) in forestDomains)
        {
            wanted.Add((namingContext, NamingContextKind.Domain, controller));
        }

        var units = new List<CaptureUnit>();

        foreach (var (namingContext, kind, controller) in wanted)
        {
            var created = CaptureUnit.Create(namingContext, kind, controller);
            if (!created.IsSuccess)
            {
                return created.Error!;
            }

            var unit = created.Value!;

            if (string.Equals(
                    unit.DomainController, domainController.Trim(), StringComparison.OrdinalIgnoreCase))
            {
                var confirmed = unit.ConfirmServedBy(published);
                if (!confirmed.IsSuccess)
                {
                    return confirmed.Error!;
                }

                unit = confirmed.Value!;
            }

            units.Add(unit);
        }

        if (!units.Any(u => u.Kind == NamingContextKind.Domain))
        {
            return AuditError.Create(
                ErrorCategory.Capture,
                "CapturePlanReadsNoDomain",
                ErrorSeverity.Failed,
                $"No domain partition was planned for {domainController}. Every forest has at "
                + "least one domain, and a run that reads only the configuration and schema "
                + "partitions would seal a bundle containing no principals, no permissions and "
                + "nothing to audit - while looking like a capture that worked.",
                context: null);
        }

        var declared = forestDomains
            .Select(d => d.DnsName)
            .Where(d => !string.IsNullOrWhiteSpace(d))
            .Select(d => d.Trim())
            .ToList();

        return new CapturePlan(
            units,
            partitionsNotRead
                .Where(nc => !string.IsNullOrWhiteSpace(nc))
                .Select(nc => nc.Trim())
                .ToList(),
            declared,
            forestFqdn.Trim())
        {
            DomainDnsNames = forestDomains.ToDictionary(
                domain => domain.NamingContext,
                domain => domain.DnsName,
                StringComparer.OrdinalIgnoreCase),
        };
    }
}
