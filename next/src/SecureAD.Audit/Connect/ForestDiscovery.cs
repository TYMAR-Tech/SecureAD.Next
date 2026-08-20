using System.Net;
using SecureAD.Audit.Capture;
using SecureAD.Kernel;
using SecureAD.Kernel.Capture;

namespace SecureAD.Audit.Connect;

/// <summary>
/// Asks a controller which partitions the forest has, and turns the answer into a capture plan.
/// </summary>
/// <remarks>
/// <para>
/// This is the join between connect and capture. <c>CapturePlan.For</c> has always required the
/// configuration, schema and domain naming contexts "as branch A discovered them", and nothing
/// discovered them - so a plan could be constructed in a test and never from a directory. The
/// request this issues was already built by <c>CaptureSearchRequestFactory.ForRootDse</c> and had
/// no caller.
/// </para>
/// <para>
/// <b>Everything here comes from the controller's own account of itself.</b> The two forest-wide
/// partitions are read from <c>configurationNamingContext</c> and <c>schemaNamingContext</c> rather
/// than recognised by the shape of a distinguished name.
/// </para>
/// <para>
/// <b>Which naming contexts are domains is the forest's answer, not this controller's.</b> An
/// earlier version of this class treated every published naming context that was not the
/// configuration or schema partition as a domain. That was wrong twice over. It over-read, because
/// an application partition is spelled exactly as a domain is. Far worse, it under-read: an
/// ordinary domain controller publishes only the partitions it holds, so in a forest of nine
/// domains the answer named one, and the run sealed a bundle covering a ninth of a forest with
/// nothing saying so. That is <c>F-S28-1</c>. <see cref="ForestPartitions"/> reads the
/// cross-references in the configuration partition instead, which every controller in the forest
/// holds and which name every partition the forest has.
/// </para>
/// <para>
/// <b>Each domain is read from its own DNS name.</b> A cross-reference carries the domain's
/// <c>dnsRoot</c>, which resolves to controllers holding that domain, so an operator names one
/// controller and the run reaches the rest of the forest without being told how. <b>This is a
/// lab-grade choice and is recorded as one</b>: it gives <i>a</i> controller in the domain rather
/// than a chosen one. Pinning controllers explicitly is the configuration file, deferred until a
/// graphical surface can generate one - hand-typing a list of controllers now would put typos into
/// the first real run.
/// </para>
/// </remarks>
public static class ForestDiscovery
{
    private static readonly CapturedAttribute NamingContexts =
        new("namingContexts", AttributeCardinality.MultiValued, AttributeStorage.Text);

    private static readonly CapturedAttribute ConfigurationNamingContext =
        new("configurationNamingContext", AttributeCardinality.SingleValued, AttributeStorage.Text);

    private static readonly CapturedAttribute SchemaNamingContext =
        new("schemaNamingContext", AttributeCardinality.SingleValued, AttributeStorage.Text);

    private static readonly CapturedAttribute RootDomainNamingContext =
        new("rootDomainNamingContext", AttributeCardinality.SingleValued, AttributeStorage.Text);

    /// <summary>
    /// Reads the controller's RootDSE, learns the forest's topology and roles from the same
    /// connection, and plans the run against a chosen controller per domain.
    /// </summary>
    /// <remarks>
    /// The connection this is given is the bootstrap connection and is never pinned, per
    /// <c>docs/decisions/0053-the-tool-finds-its-own-forest.md</c>. It answers the questions here,
    /// and every domain is then read from whichever controller
    /// <see cref="ControllerSelection"/> ranked first.
    /// </remarks>
    /// <param name="channel">The bootstrap connection. No second connection is opened.</param>
    /// <param name="localAddresses">
    /// This machine's own addresses, matched against the forest's subnets to find the operator's
    /// site. Passed in rather than read here, so that ranking is exercisable without a network.
    /// </param>
    /// <param name="overrides">
    /// Controllers an operator named, keyed by domain naming context. Empty when none were named.
    /// An override that is not an eligible candidate fails the whole plan rather than being
    /// substituted.
    /// </param>
    /// <param name="cancellationToken">Cancellation for a capture an operator stopped.</param>
    public static async Task<Result<ForestPlan>> PlanAsync(
        IDirectoryChannel channel,
        IEnumerable<IPAddress> localAddresses,
        IReadOnlyDictionary<string, string> overrides,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(channel);
        ArgumentNullException.ThrowIfNull(localAddresses);
        ArgumentNullException.ThrowIfNull(overrides);

        DirectoryPage page;

        try
        {
            page = await channel
                .SendAsync(CaptureSearchRequestFactory.ForRootDse(), cancellationToken)
                .ConfigureAwait(false);
        }
        catch (System.DirectoryServices.Protocols.LdapException exception)
        {
            return Result<ForestPlan>.Failure(AuditError.Create(
                ErrorCategory.Capture,
                "RootDseCouldNotBeRead",
                ErrorSeverity.Failed,
                $"The RootDSE of {channel.DomainController} could not be read: "
                + $"{exception.Message}. Nothing about the forest is known without it, so no run "
                + "is planned rather than one being planned against a guess.",
                channel.DomainController));
        }

        if (page.Entries.Count != 1)
        {
            return Result<ForestPlan>.Failure(AuditError.Create(
                ErrorCategory.Capture,
                "RootDseWasNotOneEntry",
                ErrorSeverity.Failed,
                $"{channel.DomainController} answered a base-scope read of its RootDSE with "
                + $"{page.Entries.Count} entries. Exactly one is the only answer that means "
                + "anything.",
                channel.DomainController));
        }

        var rootDse = page.Entries[0];

        var configurationRead = ForestPartitions.SingleTextValue(rootDse, ConfigurationNamingContext);
        if (!configurationRead.IsSuccess)
        {
            return Result<ForestPlan>.Failure(configurationRead.Error!);
        }

        if (configurationRead.Value is not { } configuration)
        {
            return Result<ForestPlan>.Failure(Missing(channel, "configurationNamingContext"));
        }

        var schemaRead = ForestPartitions.SingleTextValue(rootDse, SchemaNamingContext);
        if (!schemaRead.IsSuccess)
        {
            return Result<ForestPlan>.Failure(schemaRead.Error!);
        }

        if (schemaRead.Value is not { } schema)
        {
            return Result<ForestPlan>.Failure(Missing(channel, "schemaNamingContext"));
        }

        var published = rootDse.ValuesOf(NamingContexts);
        if (published.Completeness != AttributeCompleteness.Complete || published.Values.Count == 0)
        {
            return Result<ForestPlan>.Failure(Missing(channel, "namingContexts"));
        }

        var partitions = new List<string>();

        foreach (var value in published.Values)
        {
            var text = LdapEntryReader.AsText(value);
            if (!text.IsSuccess)
            {
                return Result<ForestPlan>.Failure(text.Error!);
            }

            partitions.Add(text.Value!);
        }

        var rootDomainRead = ForestPartitions.SingleTextValue(rootDse, RootDomainNamingContext);
        if (!rootDomainRead.IsSuccess)
        {
            return Result<ForestPlan>.Failure(rootDomainRead.Error!);
        }

        if (rootDomainRead.Value is not { } rootDomain)
        {
            return Result<ForestPlan>.Failure(Missing(channel, "rootDomainNamingContext"));
        }

        var forest = await ForestPartitions
            .ReadAsync(channel, configuration, schema, cancellationToken)
            .ConfigureAwait(false);

        if (!forest.IsSuccess)
        {
            return Result<ForestPlan>.Failure(forest.Error!);
        }

        // The forest is named by its root domain, and which domain that is comes from the RootDSE
        // rather than from the shape of the shortest name in the list.
        var forestRoot = forest.Value!.Domains.FirstOrDefault(
            d => string.Equals(d.NamingContext, rootDomain, StringComparison.OrdinalIgnoreCase));

        if (forestRoot is null)
        {
            return Result<ForestPlan>.Failure(AuditError.Create(
                ErrorCategory.Capture,
                "ForestRootDomainWasNotDeclared",
                ErrorSeverity.Failed,
                $"{channel.DomainController} names '{rootDomain}' as the forest root domain, and "
                + "the forest's own cross-references do not declare it as a domain. The two "
                + "disagree about what this forest is, and a run cannot choose between them - a "
                + "bundle named for the wrong forest would be offered as a comparison partner for "
                + "a forest it is not evidence of.",
                channel.DomainController));
        }

        var domainNamingContexts = forest.Value.Domains.Select(d => d.NamingContext).ToList();

        // The candidate list, the operator's site and the two forest-level roles, all from the
        // connection already open - 0050's claim that discovery contacts nobody, kept intact. Each
        // domain's PDC emulator is deliberately not asked about here; that is 0055, and it happens
        // at preflight over a connection that already exists.
        var topology = await ForestTopology
            .ReadAsync(channel, configuration, cancellationToken)
            .ConfigureAwait(false);

        if (!topology.IsSuccess)
        {
            return Result<ForestPlan>.Failure(topology.Error!);
        }

        var roles = await ForestRoles
            .ReadAsync(
                channel, configuration, schema, topology.Value!, domainNamingContexts,
                cancellationToken)
            .ConfigureAwait(false);

        if (!roles.IsSuccess)
        {
            return Result<ForestPlan>.Failure(roles.Error!);
        }

        var site = OperatorSite.For(topology.Value!.Subnets, localAddresses);

        // An override names a domain the way an operator says it - contoso.com - and selection keys
        // by naming context. The translation happens here because this is the first point that holds
        // both. A name matching no domain is refused rather than dropped: an override silently
        // ignored produces a run reading from a controller the operator asked it not to use, and
        // nothing anywhere saying so.
        var byDnsName = forest.Value.Domains.ToDictionary(
            d => d.DnsName, d => d.NamingContext, StringComparer.OrdinalIgnoreCase);

        var keyed = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        foreach (var (domain, host) in overrides)
        {
            if (!byDnsName.TryGetValue(domain, out var namingContext))
            {
                return Result<ForestPlan>.Failure(AuditError.Create(
                    ErrorCategory.Capture,
                    "OverriddenDomainIsNotInThisForest",
                    ErrorSeverity.Failed,
                    $"A controller was named for '{domain}', and this forest has no such domain. "
                    + $"The domains it declares are: {string.Join(", ", byDnsName.Keys)}. The run "
                    + "stops rather than proceeding without the instruction it was given.",
                    channel.DomainController));
            }

            keyed[namingContext] = host;
        }

        var selection = ControllerSelection.For(
            topology.Value!, roles.Value!, site, domainNamingContexts, keyed);

        if (!selection.IsSuccess)
        {
            return Result<ForestPlan>.Failure(selection.Error!);
        }

        // What this replaces: each domain's controller was set to the domain's own DNS name, so a
        // domain was read from whichever machine DNS happened to answer with. A domain with no
        // candidate controllers gets no entry here at all and is carried by
        // ControllerSelection.DomainsWithNoCandidates instead, which is what 0054 acts on.
        var pinned = selection.Value!.Domains.ToDictionary(
            d => d.NamingContext, d => d.PinnedController, StringComparer.OrdinalIgnoreCase);

        var domains = forest.Value.Domains
            .Where(d => pinned.ContainsKey(d.NamingContext))
            .Select(d => (d.NamingContext, d.DnsName, DomainController: pinned[d.NamingContext]))
            .ToList();

        var capture = CapturePlan.For(
            channel.DomainController,
            forestRoot.DnsName,
            configuration,
            schema,
            domains,
            partitions,
            forest.Value.PartitionsNotRead);

        if (!capture.IsSuccess)
        {
            return Result<ForestPlan>.Failure(capture.Error!);
        }

        // Every domain the forest declared, including the ones no controller was found for.
        // CapturePlan.For derives its declaration from the domains it was given, so leaving it to do
        // that here would shrink the declared count and the unit count together and CapturePlan
        // .IsComplete would report a plan missing a whole domain as complete - the exact failure
        // (F-S28-1) that property exists to catch.
        var declared = forest.Value.Domains
            .Select(d => d.DnsName)
            .Where(d => !string.IsNullOrWhiteSpace(d))
            .Select(d => d.Trim())
            .ToList();

        return Result<ForestPlan>.Success(new ForestPlan(
            capture.Value! with { DeclaredDomains = declared },
            topology.Value!,
            roles.Value!,
            selection.Value!));
    }

    private static AuditError Missing(IDirectoryChannel channel, string attribute) =>
        AuditError.Create(
            ErrorCategory.Capture,
            "RootDseDidNotStateThePartition",
            ErrorSeverity.Failed,
            $"{channel.DomainController} did not state {attribute} in its RootDSE. Every domain "
            + "controller publishes it, so a controller that does not is not one this run can plan "
            + "against - and inferring the partition from the shape of another name would be this "
            + "product deciding what the forest contains.",
            channel.DomainController);
}
