using SecureAD.Audit.Capture;
using SecureAD.Kernel;
using SecureAD.Kernel.Capture;
using SecureAD.Kernel.Naming;

namespace SecureAD.Audit.Connect;

/// <summary>
/// One domain controller the forest declares, and everything selection needs to know about it.
/// </summary>
/// <param name="HostName">
/// The controller's DNS host name, from the <c>server</c> object above its <c>nTDSDSA</c> object.
/// This is what a connection is opened to, and what an operator recognises.
/// </param>
/// <param name="Site">The site the controller sits in, from where its object sits in the tree.</param>
/// <param name="WritableNamingContexts">
/// The naming contexts this controller holds a <b>writable</b> replica of, exactly as
/// <c>msDS-hasMasterNCs</c> states them. A read-only controller declares its domains elsewhere, so
/// a domain absent from every controller's list here has no candidate that can be audited.
/// </param>
/// <param name="DirectoryServiceDn">
/// The distinguished name of the controller's own <c>nTDSDSA</c> object.
/// </param>
/// <remarks>
/// <see cref="DirectoryServiceDn"/> is carried because it is the only name an operations master
/// role is recorded under. A role is a single <c>fSMORoleOwner</c> attribute on the object the role
/// governs, and its value is the holder's <c>nTDSDSA</c> distinguished name - never a host name. A
/// controller without that name in hand cannot be told apart from the one holding the role, and
/// ranking would put a long read on the busiest machine in a domain with nothing able to say it had.
/// </remarks>
public sealed record ForestController(
    string HostName,
    string Site,
    IReadOnlyList<string> WritableNamingContexts,
    string DirectoryServiceDn);

/// <summary>
/// One address range the forest associates with a site.
/// </summary>
/// <param name="Prefix">
/// The range in CIDR form - <c>10.20.0.0/16</c> - which is the subnet object's own name.
/// </param>
/// <param name="Site">The site the range belongs to.</param>
public sealed record ForestSubnet(string Prefix, string Site);

/// <summary>
/// The physical shape of the forest - every controller, every site, every declared address range -
/// read from the configuration partition without contacting a second machine.
/// </summary>
/// <remarks>
/// <para>
/// This is the candidate list
/// <c>docs/decisions/0050-the-candidate-list-comes-from-the-configuration-partition.md</c> requires
/// and <c>docs/decisions/0040-a-failed-domain-is-read-again-from-another-controller.md</c> already
/// assumed existed. Before it, a domain was read from whichever machine DNS happened to return for
/// the domain's name, a retry resolved the same name and hoped for a different answer, and nothing
/// could tell a read-only controller from a writable one.
/// </para>
/// <para>
/// <b>Discovery contacts nobody.</b> Every controller in a forest holds a complete replica of the
/// configuration partition, so one connection - the one that answered the question <i>what forest
/// is this</i> - yields the topology of the whole forest. The predecessor's cost model was a DNS
/// enumeration and then a connection to every candidate before a single object was captured. This
/// is one read.
/// </para>
/// <para>
/// <b>A site is read from where an object sits, not from an attribute.</b> An <c>nTDSDSA</c> object
/// is named <c>CN=NTDS Settings,CN=&lt;server&gt;,CN=Servers,CN=&lt;site&gt;,CN=Sites,…</c>, so the
/// site is the great-grandparent container's name. There is no attribute on the controller stating
/// it. That makes the depth load-bearing: counting wrong yields a plausible-looking wrong site
/// rather than an error, which would rank a distant controller first and cost hours of a capture
/// with nothing reporting why.
/// </para>
/// <para>
/// <b>A controller that cannot be named is recorded, never dropped.</b> An <c>nTDSDSA</c> object
/// whose <c>server</c> parent carries no <c>dNSHostName</c> is a controller this product cannot open
/// a connection to. Silently omitting it would shorten a candidate list with nothing saying so, and
/// per <c>docs/decisions/0002-absent-view-means-degraded-run.md</c> an absence the product created
/// may not be presented as a fact about the forest.
/// </para>
/// </remarks>
public sealed class ForestTopology
{
    private static readonly CapturedAttribute DnsHostName =
        new("dNSHostName", AttributeCardinality.SingleValued, AttributeStorage.Text);

    private static readonly CapturedAttribute HasMasterNamingContexts =
        new("msDS-hasMasterNCs", AttributeCardinality.MultiValued, AttributeStorage.Text);

    private static readonly CapturedAttribute SiteObject =
        new("siteObject", AttributeCardinality.SingleValued, AttributeStorage.Text);

    /// <summary>
    /// A topology from values already in hand, rather than from a read.
    /// </summary>
    /// <remarks>
    /// <see cref="ReadAsync"/> is how a run obtains one. This exists because the type is published
    /// on <c>ForestPlan</c> and a caller holding one must be able to state it without opening a
    /// connection - the same separation that keeps <see cref="OperatorSite"/> apart from the
    /// directory so its rules can be exercised without one.
    /// </remarks>
    /// <param name="controllers">Every controller the forest names a host name for.</param>
    /// <param name="subnets">Every address range the forest associates with a site.</param>
    /// <param name="controllersWithNoHostName">
    /// Controllers the forest names and gives no host name for, which is why a candidate list may
    /// be shorter than the forest is.
    /// </param>
    public ForestTopology(
        IReadOnlyList<ForestController> controllers,
        IReadOnlyList<ForestSubnet> subnets,
        IReadOnlyList<string> controllersWithNoHostName)
    {
        ArgumentNullException.ThrowIfNull(controllers);
        ArgumentNullException.ThrowIfNull(subnets);
        ArgumentNullException.ThrowIfNull(controllersWithNoHostName);

        Controllers = controllers;
        Subnets = subnets;
        ControllersWithNoHostName = controllersWithNoHostName;
    }

    /// <summary>
    /// Every writable domain controller the forest declares, in the order the controller returned
    /// them. Ranking is applied later and separately, so this order carries no preference.
    /// </summary>
    public IReadOnlyList<ForestController> Controllers { get; }

    /// <summary>
    /// Every address range the forest associates with a site, used to work out which site the
    /// machine running the audit is in.
    /// </summary>
    public IReadOnlyList<ForestSubnet> Subnets { get; }

    /// <summary>
    /// The distinguished names of controllers the forest declares but does not give a host name
    /// for, so this product cannot connect to them.
    /// </summary>
    /// <remarks>
    /// Carried rather than discarded because a candidate list one controller short, with nothing
    /// recording why, is indistinguishable from a forest that really has one fewer controller.
    /// </remarks>
    public IReadOnlyList<string> ControllersWithNoHostName { get; }

    /// <summary>
    /// Whether every controller the forest declared could be named, and is therefore available as
    /// a candidate.
    /// </summary>
    /// <remarks>
    /// A caller holding this type is holding a read that succeeded - the read returns nothing at
    /// all when it fails. What it cannot otherwise tell is whether the candidate lists are the
    /// forest's full complement or short of it, and a short list is invisible at the point it
    /// matters: a domain with one usable controller and no failover reads exactly like a domain
    /// that only ever had one. False here means <see cref="ControllersWithNoHostName"/> names the
    /// difference.
    /// </remarks>
    public bool IsComplete => ControllersWithNoHostName.Count == 0;

    /// <summary>
    /// Asks the forest for its own physical topology.
    /// </summary>
    /// <param name="channel">A connection to any controller in the forest.</param>
    /// <param name="configurationNamingContext">
    /// The configuration partition, as the controller named it in its RootDSE.
    /// </param>
    /// <param name="cancellationToken">Cancellation for a capture an operator stopped.</param>
    public static async Task<Result<ForestTopology>> ReadAsync(
        IDirectoryChannel channel,
        string configurationNamingContext,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(channel);
        ArgumentException.ThrowIfNullOrWhiteSpace(configurationNamingContext);

        var sitesContainer = "CN=Sites," + configurationNamingContext;
        var subnetsContainer = "CN=Subnets," + sitesContainer;

        var topologyPages = await ReadAllPagesAsync(
            channel,
            cookie => CaptureSearchRequestFactory.ForSiteTopology(sitesContainer, cookie),
            sitesContainer,
            "SiteTopologyCouldNotBeRead",
            "It is the forest's own record of which controllers exist and which domains each one "
            + "holds, and without it a run cannot choose a controller at all - so no run is "
            + "planned rather than one being planned against whichever machine DNS happened to "
            + "return.",
            cancellationToken).ConfigureAwait(false);

        if (!topologyPages.IsSuccess)
        {
            return Result<ForestTopology>.Failure(topologyPages.Error!);
        }

        var subnetPages = await ReadAllPagesAsync(
            channel,
            cookie => CaptureSearchRequestFactory.ForSubnets(subnetsContainer, cookie),
            subnetsContainer,
            "SubnetsCouldNotBeRead",
            "They are how this run works out which site it is being run from, which is what puts "
            + "a nearby controller ahead of a distant one.",
            cancellationToken).ConfigureAwait(false);

        if (!subnetPages.IsSuccess)
        {
            return Result<ForestTopology>.Failure(subnetPages.Error!);
        }

        var controllers = BuildControllers(topologyPages.Value!, channel.DomainController);
        if (!controllers.IsSuccess)
        {
            return Result<ForestTopology>.Failure(controllers.Error!);
        }

        var subnets = BuildSubnets(subnetPages.Value!);
        if (!subnets.IsSuccess)
        {
            return Result<ForestTopology>.Failure(subnets.Error!);
        }

        var (named, unnamed) = controllers.Value!;

        return new ForestTopology(named, subnets.Value!, unnamed);
    }

    /// <summary>
    /// Turns the entries of one <c>CN=Sites</c> search into controllers, joining each
    /// <c>nTDSDSA</c> object to the <c>server</c> object directly above it.
    /// </summary>
    /// <remarks>
    /// The two classes arrive interleaved in one result set and are told apart by what they carry
    /// rather than by re-reading their object class: only an <c>nTDSDSA</c> object declares
    /// <c>msDS-hasMasterNCs</c>, and only a <c>server</c> object declares <c>dNSHostName</c>. A
    /// server object with no controller beneath it is a server that is not a domain controller, and
    /// is simply not a candidate.
    /// </remarks>
    private static Result<(IReadOnlyList<ForestController> Named, IReadOnlyList<string> Unnamed)>
        BuildControllers(IReadOnlyList<LdapEntryReader> entries, string readFrom)
    {
        var hostNames = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var settings = new List<(string Dn, IReadOnlyList<string> NamingContexts)>();

        foreach (var entry in entries)
        {
            var hostNameRead = ForestPartitions.SingleTextValue(entry, DnsHostName);
            if (!hostNameRead.IsSuccess)
            {
                return Result<(IReadOnlyList<ForestController>, IReadOnlyList<string>)>
                    .Failure(hostNameRead.Error!);
            }

            if (hostNameRead.Value is { } hostName)
            {
                hostNames[entry.DistinguishedName] = hostName;
                continue;
            }

            var namingContexts = entry.ValuesOf(HasMasterNamingContexts);
            if (namingContexts.Completeness != AttributeCompleteness.Complete
                || namingContexts.Values.Count == 0)
            {
                // Either a server object that is not a domain controller, or a read-only
                // controller, which declares its replicas in msDS-hasFullReplicaNCs instead.
                // Neither is a candidate, and neither is a fault.
                continue;
            }

            var held = new List<string>();

            foreach (var value in namingContexts.Values)
            {
                var text = LdapEntryReader.AsText(value);
                if (!text.IsSuccess)
                {
                    return Result<(IReadOnlyList<ForestController>, IReadOnlyList<string>)>
                        .Failure(text.Error!);
                }

                held.Add(text.Value!);
            }

            settings.Add((entry.DistinguishedName, held));
        }

        var named = new List<ForestController>();
        var unnamed = new List<string>();

        foreach (var (dn, namingContexts) in settings)
        {
            var serverDn = DnHelper.GetParentDn(dn);
            var site = SiteOf(dn);

            if (serverDn is null || site is null || !hostNames.TryGetValue(serverDn, out var host))
            {
                unnamed.Add(dn);
                continue;
            }

            named.Add(new ForestController(host, site, namingContexts, dn));
        }

        if (named.Count == 0 && unnamed.Count == 0)
        {
            return Result<(IReadOnlyList<ForestController>, IReadOnlyList<string>)>.Failure(
                AuditError.Create(
                    ErrorCategory.Capture,
                    "ForestDeclaredNoDomainControllers",
                    ErrorSeverity.Failed,
                    $"{readFrom} returned a sites container naming no writable domain controller "
                    + "at all - not even the controller that answered. Every forest has at least "
                    + "one, so this is an answer that cannot be right, and planning a run against "
                    + "it would produce a bundle covering nothing.",
                    readFrom));
        }

        return (named, (IReadOnlyList<string>)unnamed);
    }

    /// <summary>
    /// The site a controller sits in, which is the great-grandparent of its <c>nTDSDSA</c> object.
    /// </summary>
    /// <remarks>
    /// Null where the name is too shallow to have one. A distinguished name that does not have
    /// three containers above it is not a controller object wherever it came from, and inventing a
    /// site for it would put a controller in a site the forest never placed it in.
    /// </remarks>
    private static string? SiteOf(string domainControllerSettingsDn)
    {
        var server = DnHelper.GetParentDn(domainControllerSettingsDn);
        var servers = server is null ? null : DnHelper.GetParentDn(server);
        var site = servers is null ? null : DnHelper.GetParentDn(servers);

        return site is null ? null : DnHelper.ExtractNameFromDn(site);
    }

    /// <summary>
    /// Turns the entries of one subnets search into ranges and the sites they belong to.
    /// </summary>
    /// <remarks>
    /// A subnet with no <c>siteObject</c> is declared and unassigned, which a forest is entitled to
    /// contain. It cannot contribute a site preference, so it is left out rather than treated as a
    /// fault of the run.
    /// </remarks>
    private static Result<IReadOnlyList<ForestSubnet>> BuildSubnets(
        IReadOnlyList<LdapEntryReader> entries)
    {
        var subnets = new List<ForestSubnet>();

        foreach (var entry in entries)
        {
            var siteRead = ForestPartitions.SingleTextValue(entry, SiteObject);
            if (!siteRead.IsSuccess)
            {
                return Result<IReadOnlyList<ForestSubnet>>.Failure(siteRead.Error!);
            }

            if (siteRead.Value is not { } siteDn)
            {
                continue;
            }

            subnets.Add(new ForestSubnet(
                DnHelper.ExtractNameFromDn(entry.DistinguishedName),
                DnHelper.ExtractNameFromDn(siteDn)));
        }

        return Result<IReadOnlyList<ForestSubnet>>.Success(subnets);
    }

    /// <summary>
    /// Runs a paged search to its end and returns every entry it produced.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>A page that cannot say it was the last one is not the last one.</b> The loop ends only on
    /// <see cref="PageCompleteness.LastPage"/>. A response carrying no paging control at all means
    /// the controller did not answer the question, and treating that as completion is how part of a
    /// forest gets reported as the whole of it.
    /// </para>
    /// <para>
    /// One request is in flight at a time, which is <c>docs/next/S-10-politeness.md</c> and is also
    /// what makes a paged search correct: the state a controller keeps between pages comes out of
    /// one budget it relieves by discarding the oldest.
    /// </para>
    /// </remarks>
    private static async Task<Result<IReadOnlyList<LdapEntryReader>>> ReadAllPagesAsync(
        IDirectoryChannel channel,
        Func<byte[], System.DirectoryServices.Protocols.SearchRequest> request,
        string container,
        string errorCode,
        string whyItMatters,
        CancellationToken cancellationToken)
    {
        var entries = new List<LdapEntryReader>();
        var cookie = Array.Empty<byte>();

        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();

            DirectoryPage page;

            try
            {
                page = await channel
                    .SendAsync(request(cookie), cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (System.DirectoryServices.Protocols.LdapException exception)
            {
                return Result<IReadOnlyList<LdapEntryReader>>.Failure(AuditError.Create(
                    ErrorCategory.Capture,
                    errorCode,
                    ErrorSeverity.Failed,
                    $"'{container}' could not be read from {channel.DomainController}: "
                    + $"{exception.Message}. {whyItMatters}",
                    channel.DomainController));
            }

            entries.AddRange(page.Entries);

            if (page.Completeness == PageCompleteness.LastPage)
            {
                return Result<IReadOnlyList<LdapEntryReader>>.Success(entries);
            }

            if (page.Completeness == PageCompleteness.NotPaged)
            {
                return Result<IReadOnlyList<LdapEntryReader>>.Failure(AuditError.Create(
                    ErrorCategory.Capture,
                    errorCode,
                    ErrorSeverity.Failed,
                    $"{channel.DomainController} answered a paged search of '{container}' without "
                    + "saying whether there was more to send. What came back cannot be shown to be "
                    + "the whole of it, and reading part of a forest's topology as all of it would "
                    + $"leave controllers out of the candidate list silently. {whyItMatters}",
                    channel.DomainController));
            }

            cookie = page.PagingCookie;
        }
    }
}
