using System.DirectoryServices.Protocols;
using SecureAD.Evidence;
using SecureAD.Kernel.Capture;

namespace SecureAD.Audit.Capture;

/// <summary>
/// Builds the one search request capture issues, and holds the referral policy that makes it safe.
/// </summary>
/// <remarks>
/// <para>
/// This is inventory row B4's mechanism, and <c>docs/audit/the-search-capture-issues.md</c> is the document
/// bound to it. Everything a search does about referrals is decided here, in one place, and that
/// is the point rather than a convenience. The policy has two halves - a setting on the connection
/// and a control on the request - and a policy expressed in two places can be half-removed. Half
/// of this one still reads a forest correctly right up until the forest has a child domain.
/// </para>
/// <para>
/// <b>Referral chasing is set rather than left alone.</b> Microsoft's own guidance on the paging
/// defect says "as referrals are chased by default, use ldap_set_option with flag
/// LDAP_OPT_REFERRALS to turn off referral chasing"
/// (<see href="https://learn.microsoft.com/troubleshoot/windows-server/active-directory/ldap-paged-queries-subordinate-referrals-not-chased">LDAP
/// paged queries with subordinate referrals are not chased properly</see>). A policy that happens
/// to be safe is not a policy.
/// </para>
/// <para>
/// <b>Nothing else in the product may build a search request.</b> That is not a convention, it is
/// a build failure: <c>DirectorySearchGateTests</c> fails if a <c>SearchRequest</c> is constructed
/// or a referral option is assigned anywhere but in this file. It is the shape of gate 1 - a
/// correct mechanism with a boundary obliging its use - and it exists because the correctness here
/// is invisible at the point where it is lost. A second place that builds a search is a second
/// referral policy, and the first sign that the two disagree is a customer's report covering a
/// fraction of their forest and saying nothing about it.
/// </para>
/// </remarks>
public static class CaptureSearchRequestFactory
{
    /// <summary>
    /// The only referral policy capture ever uses. Chasing a subordinate referral during a paged
    /// search overwrites the paged cookie inside the LDAP runtime, so the application sees an empty
    /// cookie and stops after the first page believing it read everything.
    /// </summary>
    public const ReferralChasingOptions RequiredReferralChasing = ReferralChasingOptions.None;

    /// <summary>
    /// <c>LDAP_SERVER_DOMAIN_SCOPE_OID</c>: the control that tells a controller not to generate
    /// continuation referrals when searching a domain root. Checked for in a controller's RootDSE
    /// <c>supportedControl</c> before it is sent.
    /// </summary>
    public const string DomainScopeControlOid = "1.2.840.113556.1.4.1339";

    /// <summary>
    /// The filter capture searches with: every object, except the classes the catalogue names as
    /// unread.
    /// </summary>
    /// <remarks>
    /// Built from <see cref="CapturedAttributeCatalog.UnreadObjectClasses"/> rather than written
    /// out, so the DNS scope decision is stated once. It is an exclusion and not an inclusion: a
    /// dangerous permission on an object class nobody anticipated is still read.
    /// </remarks>
    public static string Filter { get; } = BuildFilter();

    /// <summary>
    /// The search request for the first page of one capture unit.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Every search is based at the root of one naming context, subtree scope, paged. The base is
    /// the partition root and not a container beneath it: searching below the root loses the
    /// objects sitting directly in it, and anything in a container the caller did not think to
    /// enumerate, without saying that it has.
    /// </para>
    /// <para>
    /// The whole attribute catalogue is requested on every unit rather than a per-unit subset. An
    /// attribute an object does not have is simply absent from the entry, so a superset costs
    /// nothing on the wire, and a per-unit list is a second thing to keep in step with the
    /// catalogue.
    /// </para>
    /// </remarks>
    /// <param name="unit">The naming context and controller being read.</param>
    /// <param name="supportedControls">
    /// The control OIDs the chosen controller advertises in its RootDSE. The domain-scope control
    /// is sent only if it appears here.
    /// </param>
    public static SearchRequest ForUnit(CaptureUnit unit, IEnumerable<string> supportedControls) =>
        Build(unit, supportedControls, EmptyCookie);

    /// <summary>
    /// The search request for the next page of a unit already part-read.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A paged search is not one request. It is a request per page, each carrying the opaque
    /// bookmark - the <i>cookie</i> - the controller returned with the page before, which is how
    /// the controller knows where the reader had got to. Without a way to pass that back, only the
    /// first page of any partition can ever be asked for.
    /// </para>
    /// <para>
    /// <b>The cookie is where this whole component's correctness shows up or fails to.</b> A paging
    /// loop ends when the controller returns an empty cookie, meaning there is no more to send. A
    /// client that chases a referral mid-search has that cookie overwritten and reads an empty one
    /// on the first page, so the loop ends immediately and the caller cannot tell that from a
    /// partition that really did fit in one page. That is why the referral policy and the paging
    /// live in the same place: they are one mechanism, and separating them is what makes the
    /// failure invisible.
    /// </para>
    /// <para>
    /// Reading the cookie back off a response belongs to the component running the loop, which is
    /// inventory row B6. What it must not do is treat an empty cookie as proof of completeness
    /// without knowing that nothing was chased.
    /// </para>
    /// </remarks>
    /// <param name="unit">The naming context and controller being read.</param>
    /// <param name="supportedControls">The controller's advertised control OIDs.</param>
    /// <param name="pagingCookie">
    /// The cookie from the previous page's response. Never empty - an empty cookie means the
    /// previous page was the last, and asking for another page is a defect rather than an outcome.
    /// </param>
    public static SearchRequest ForNextPage(
        CaptureUnit unit, IEnumerable<string> supportedControls, byte[] pagingCookie)
    {
        ArgumentNullException.ThrowIfNull(pagingCookie);

        if (pagingCookie.Length == 0)
        {
            throw new ArgumentException(
                "An empty paging cookie means the controller has no more pages to send. Asking "
                + "for another page with it would restart the search from the beginning and read "
                + "the partition twice.",
                nameof(pagingCookie));
        }

        return Build(unit, supportedControls, pagingCookie);
    }

    private static readonly byte[] EmptyCookie = [];

    private static SearchRequest Build(
        CaptureUnit unit, IEnumerable<string> supportedControls, byte[] pagingCookie)
    {
        ArgumentNullException.ThrowIfNull(unit);
        ArgumentNullException.ThrowIfNull(supportedControls);

        var request = new SearchRequest
        {
            DistinguishedName = unit.NamingContext,
            Filter = Filter,
            Scope = SearchScope.Subtree,

            // Zero means "no client-imposed limit". Stated rather than left at its default,
            // because a size limit and a page size are easy to confuse and one of them silently
            // truncates a capture.
            SizeLimit = 0,
            TimeLimit = ServerLimits.QueryDuration,
        };

        foreach (var attribute in CapturedAttributeCatalog.All)
        {
            request.Attributes.Add(attribute.LdapDisplayName);
        }

        request.Controls.Add(new PageResultRequestControl(ServerLimits.PageSize)
        {
            Cookie = pagingCookie,
        });

        request.Controls.Add(SecurityDescriptorFlags());

        if (ShouldSendDomainScopeControl(unit, supportedControls))
        {
            // Non-critical: a controller that does not recognise the control answers anyway
            // instead of failing the search. Correctness rests on referral chasing being off;
            // this is a second line.
            request.Controls.Add(new DomainScopeControl { IsCritical = false });
        }

        return request;
    }

    /// <summary>
    /// Whether the domain-scope control is sent for this unit.
    /// </summary>
    /// <remarks>
    /// Only for a domain partition, because it is domain roots that generate continuation
    /// referrals, and only where the controller advertises the OID.
    /// </remarks>
    /// <param name="unit">The unit being read.</param>
    /// <param name="supportedControls">The controller's advertised control OIDs.</param>
    public static bool ShouldSendDomainScopeControl(
        CaptureUnit unit, IEnumerable<string> supportedControls)
    {
        ArgumentNullException.ThrowIfNull(unit);
        ArgumentNullException.ThrowIfNull(supportedControls);

        return unit.Kind == NamingContextKind.Domain
               && supportedControls.Contains(DomainScopeControlOid, StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Applies the referral policy to a connection's session options.
    /// </summary>
    /// <remarks>
    /// The one place in the product where a referral option is assigned. It cannot be exercised
    /// without a directory, so no test here proves it was called; what proves that is the guard
    /// forbidding the assignment anywhere else, and gate 5b once inventory row B6 gives the rebuild
    /// something that runs.
    /// </remarks>
    /// <param name="sessionOptions">The session options of the connection about to be searched.</param>
    public static void ApplyReferralPolicy(LdapSessionOptions sessionOptions)
    {
        ArgumentNullException.ThrowIfNull(sessionOptions);

        sessionOptions.ReferralChasing = RequiredReferralChasing;
    }

    /// <summary>
    /// The request for one block of one attribute of one object: a range retrieval.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Why this lives here.</b> It is a search request, and there is one place that builds a
    /// search request. A second builder would be a second referral policy, and this request is
    /// issued on the same connection as a paged search that is halfway through a partition.
    /// </para>
    /// <para>
    /// <b>It is not paged, and that is the point.</b> A base-scope search of one object returns
    /// one entry, so there is nothing to page, and it therefore creates no paging state of its own
    /// on the controller and cannot compete with the paged search already in flight for the
    /// controller's intermediate-result budget.
    /// </para>
    /// <para>
    /// <b>The domain-scope control is not sent.</b> That control asks a controller not to generate
    /// continuation referrals below a domain root, and a base-scope search of a single object has
    /// nothing below it. Referral chasing is off on the connection either way, which is where the
    /// correctness lives.
    /// </para>
    /// </remarks>
    /// <param name="distinguishedName">The object whose attribute is being continued.</param>
    /// <param name="rangedAttributeName">
    /// The attribute name with the range option after it, as
    /// <see cref="AttributeRange.SpecifierFor"/> spells it. Nothing else in the product spells one.
    /// </param>
    public static SearchRequest ForAttributeBlock(
        string distinguishedName, string rangedAttributeName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(distinguishedName);
        ArgumentException.ThrowIfNullOrWhiteSpace(rangedAttributeName);

        var request = new SearchRequest
        {
            DistinguishedName = distinguishedName,
            Filter = "(objectClass=*)",
            Scope = SearchScope.Base,
            SizeLimit = 0,
            TimeLimit = ServerLimits.QueryDuration,
        };

        request.Attributes.Add(rangedAttributeName);
        request.Controls.Add(SecurityDescriptorFlags());

        return request;
    }

    /// <summary>
    /// The request that asks a controller about itself: a base-scope read of the RootDSE.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The RootDSE is the one entry every LDAP server publishes without being asked about anything
    /// else, and it is read by searching with an empty base at base scope. Four of its attributes
    /// decide things capture cannot proceed without: <c>supportedControl</c>, which says whether
    /// the domain-scope control is worth sending; <c>namingContexts</c>, which says which
    /// partitions this controller actually serves; and <c>configurationNamingContext</c> and
    /// <c>schemaNamingContext</c>, which name the two forest-wide partitions by their own account
    /// rather than by a reader recognising a prefix.
    /// </para>
    /// <para>
    /// <b>Why the last two are asked for rather than derived.</b> Both are identifiable from
    /// <c>namingContexts</c> by their distinguished names, and doing that would be this product
    /// deciding what a partition is from the shape of its name. The controller states both, so it
    /// is asked.
    /// </para>
    /// <para>
    /// <b>Why it is built here.</b> Because it is a search request, and there is one place that
    /// builds a search request. It carries no paging control - there is exactly one entry - and no
    /// domain-scope control, which asks a controller not to generate referrals below a domain root
    /// and has nothing to apply to an entry that is not in a partition at all.
    /// </para>
    /// </remarks>
    public static SearchRequest ForRootDse()
    {
        var request = new SearchRequest
        {
            DistinguishedName = string.Empty,
            Filter = "(objectClass=*)",
            Scope = SearchScope.Base,
            SizeLimit = 0,
            TimeLimit = ServerLimits.QueryDuration,
        };

        request.Attributes.Add("supportedControl");
        request.Attributes.Add("namingContexts");
        request.Attributes.Add("configurationNamingContext");
        request.Attributes.Add("schemaNamingContext");
        request.Attributes.Add("rootDomainNamingContext");

        return request;
    }

    /// <summary>
    /// The request that asks the forest what partitions it has: the cross-references in the
    /// Partitions container.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>This is the only authoritative answer to "which naming contexts are domains".</b> A
    /// controller's <c>namingContexts</c> lists what that one controller holds, which in a forest
    /// of several domains is its own domain and no other. And a partition list alone cannot tell a
    /// domain from an application partition, because
    /// <c>DC=DomainDnsZones,DC=example,DC=com</c> is spelled exactly as a domain is. The forest
    /// records the answer itself, one <c>crossRef</c> object per partition, and this asks for it.
    /// </para>
    /// <para>
    /// <b>Three attributes, and each is load-bearing.</b> <c>nCName</c> is the partition's
    /// distinguished name. <c>systemFlags</c> carries the bit that says whether the partition is a
    /// domain. <c>dnsRoot</c> is the DNS name of the domain, which is a name that resolves to
    /// controllers holding it - so it is both an identifier a person recognises and somewhere a
    /// run can connect.
    /// </para>
    /// <para>
    /// <b>It is one-level scope, not subtree.</b> Cross-references are direct children of the
    /// Partitions container. A subtree search would descend into the site and licensing objects
    /// beneath it for nothing.
    /// </para>
    /// <para>
    /// <b>It is not paged, and nothing here has to notice that.</b> A forest has one cross-reference
    /// per partition, so this is tens of entries and paging state on the controller is not worth
    /// creating for it. An unpaged search that exceeds the server's page size answers
    /// <c>sizeLimitExceeded</c> with a truncated entry list, and a caller reading only the entries
    /// would take the truncation for the whole answer - which is the same failure this request
    /// exists to fix, reached from the other side. <c>LdapDirectoryChannel</c> throws on any result
    /// code that is not success, so a truncated answer never reaches a reader as a page.
    /// </para>
    /// </remarks>
    /// <param name="partitionsContainerDn">
    /// The Partitions container, which is <c>CN=Partitions</c> beneath the configuration partition
    /// the controller named in its RootDSE. Composed by the caller rather than here, so that nothing
    /// in this file has to know the shape of a configuration partition's name.
    /// </param>
    public static SearchRequest ForCrossReferences(string partitionsContainerDn)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(partitionsContainerDn);

        var request = new SearchRequest
        {
            DistinguishedName = partitionsContainerDn,
            Filter = "(objectClass=crossRef)",
            Scope = SearchScope.OneLevel,
            SizeLimit = 0,
            TimeLimit = ServerLimits.QueryDuration,
        };

        request.Attributes.Add("nCName");
        request.Attributes.Add("dnsRoot");
        request.Attributes.Add("systemFlags");

        return request;
    }

    /// <summary>
    /// The request that asks the forest for its physical topology: every domain controller in it,
    /// which domains each holds a writable replica of, and which site each sits in.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>One read describes the whole forest.</b> Every controller holds a complete replica of the
    /// configuration partition, so the sites container answers for sixty controllers as readily as
    /// for one, without a single further connection being opened. That is
    /// <c>docs/decisions/0050-the-candidate-list-comes-from-the-configuration-partition.md</c>, and
    /// the reasoning for preferring it to DNS enumeration is there rather than repeated here.
    /// </para>
    /// <para>
    /// <b>Two object classes in one search, because the answer is split across two objects.</b> An
    /// <c>nTDSDSA</c> object carries <c>msDS-hasMasterNCs</c> - the naming contexts that controller
    /// holds a <i>writable</i> replica of - but not a host name. The <c>server</c> object directly
    /// above it carries <c>dNSHostName</c>, which is what a connection is opened to. Asking for
    /// both in one subtree search costs one round trip instead of two and cannot return a
    /// half-consistent pair from two moments.
    /// </para>
    /// <para>
    /// <b>A read-only controller is excluded by what it does not say.</b> An RODC lists a domain in
    /// <c>msDS-hasFullReplicaNCs</c> rather than in <c>msDS-hasMasterNCs</c>, so a candidate list
    /// built from the latter can never contain one. That attribute is deliberately not requested:
    /// asking for it would invite a reader to filter on it, which is the capability probe <c>0050</c>
    /// exists to avoid, and a refusal expressed in two places can be half-removed.
    /// </para>
    /// <para>
    /// <b>It is paged.</b> A forest with more controllers or subnets than the server's page size
    /// answers an unpaged search with <c>sizeLimitExceeded</c> and a truncated entry list;
    /// <c>LdapDirectoryChannel</c> turns that into a failure rather than a page, so nothing is read
    /// as complete when it is not - but the result is a run that cannot plan itself at all in a
    /// large forest. Paging makes the large forest work rather than merely fail honestly.
    /// </para>
    /// </remarks>
    /// <param name="sitesContainerDn">
    /// The sites container, which is <c>CN=Sites</c> beneath the configuration partition. Composed
    /// by the caller rather than here, for the reason <see cref="ForCrossReferences"/> gives.
    /// </param>
    /// <param name="pagingCookie">
    /// The bookmark from the previous page, or an empty array for the first page.
    /// </param>
    public static SearchRequest ForSiteTopology(string sitesContainerDn, byte[] pagingCookie)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sitesContainerDn);
        ArgumentNullException.ThrowIfNull(pagingCookie);

        var request = new SearchRequest
        {
            DistinguishedName = sitesContainerDn,
            Filter = "(|(objectClass=nTDSDSA)(objectClass=server))",
            Scope = SearchScope.Subtree,
            SizeLimit = 0,
            TimeLimit = ServerLimits.QueryDuration,
        };

        request.Attributes.Add("distinguishedName");
        request.Attributes.Add("dNSHostName");
        request.Attributes.Add("msDS-hasMasterNCs");

        request.Controls.Add(new PageResultRequestControl(ServerLimits.PageSize)
        {
            Cookie = pagingCookie,
        });

        return request;
    }

    /// <summary>
    /// The request that asks the forest which address ranges belong to which site.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>What this is for.</b> Ranking a domain's controllers puts the ones in the operator's own
    /// site first, and the only way to know which site that is - from a machine that may not even be
    /// joined to the forest being audited - is to match the machine's own addresses against the
    /// subnets the forest declares, taking the longest prefix. That is what Netlogon does
    /// internally; here it is computed from data already read.
    /// </para>
    /// <para>
    /// <b>The prefix is the object's name.</b> A <c>subnet</c> object is named for the range it
    /// describes - <c>CN=10.20.0.0/16</c> - and <c>siteObject</c> is the site it belongs to. There
    /// is no separate attribute holding the range, so the name is the datum rather than a label for
    /// it.
    /// </para>
    /// <para>
    /// <b>One level, and paged.</b> Subnet objects are direct children of the subnets container, and
    /// a large organisation declares thousands of them - comfortably past a server page size, which
    /// is why this is paged where <see cref="ForCrossReferences"/> is not.
    /// </para>
    /// </remarks>
    /// <param name="subnetsContainerDn">
    /// The subnets container, which is <c>CN=Subnets,CN=Sites</c> beneath the configuration
    /// partition. Composed by the caller, for the reason <see cref="ForCrossReferences"/> gives.
    /// </param>
    /// <param name="pagingCookie">
    /// The bookmark from the previous page, or an empty array for the first page.
    /// </param>
    public static SearchRequest ForSubnets(string subnetsContainerDn, byte[] pagingCookie)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(subnetsContainerDn);
        ArgumentNullException.ThrowIfNull(pagingCookie);

        var request = new SearchRequest
        {
            DistinguishedName = subnetsContainerDn,
            Filter = "(objectClass=subnet)",
            Scope = SearchScope.OneLevel,
            SizeLimit = 0,
            TimeLimit = ServerLimits.QueryDuration,
        };

        request.Attributes.Add("distinguishedName");
        request.Attributes.Add("siteObject");

        request.Controls.Add(new PageResultRequestControl(ServerLimits.PageSize)
        {
            Cookie = pagingCookie,
        });

        return request;
    }

    /// <summary>
    /// The request preflight uses to find out whether the Password Settings Container can be read:
    /// a base-scope read of one container per domain.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Why this question is asked at all.</b> <c>msDS-PasswordSettings</c> objects carry a
    /// restrictive default access control list, and an account without access reads the container
    /// as <i>empty</i> rather than as <i>denied</i>. A run made by such an account would report
    /// that a domain has no fine-grained password policy when it has several. That is the fourth
    /// question of <c>docs/decisions/0048-preflight-proves-a-controller-before-a-run-commits.md</c>
    /// and the reasoning is there rather than repeated here.
    /// </para>
    /// <para>
    /// <b>Base scope on the container itself, not a search of its children.</b> Reading the
    /// container proves the access; enumerating what is inside it is capture's work and would cost
    /// a second answer to a question capture already answers. Nothing is asked for beyond the
    /// container's own name, because what is being measured is whether the read succeeds.
    /// </para>
    /// <para>
    /// <b>What a failure here does and does not mean.</b> Active Directory answers a caller who
    /// lacks list access with <i>no such object</i>, the same code an absent container would
    /// produce. So this request can establish that the container was read, and cannot distinguish
    /// denied from absent - which is why what preflight records is <i>could not be read</i>,
    /// carrying the controller's own words, rather than a claim about why.
    /// </para>
    /// </remarks>
    /// <param name="passwordSettingsContainerDn">
    /// The container, which is <c>CN=Password Settings Container,CN=System</c> beneath a domain's
    /// naming context. Composed by the caller rather than here, for the reason
    /// <see cref="ForCrossReferences"/> gives.
    /// </param>
    public static SearchRequest ForPasswordSettingsContainer(string passwordSettingsContainerDn)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(passwordSettingsContainerDn);

        var request = new SearchRequest
        {
            DistinguishedName = passwordSettingsContainerDn,
            Filter = "(objectClass=*)",
            Scope = SearchScope.Base,
            SizeLimit = 0,
            TimeLimit = ServerLimits.QueryDuration,
        };

        request.Attributes.Add("distinguishedName");

        return request;
    }

    /// <summary>
    /// The request that asks one object which controller holds the operations master role kept on
    /// it: a base-scope read of that object's <c>fSMORoleOwner</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>What this is for.</b> Ranking a domain's controllers puts the ones holding no operations
    /// master role last, the PDC emulator above all. It is the busiest machine in any domain - time
    /// sync, password chaining, account lockout, Group Policy edits - and pointing a multi-hour
    /// forest-wide read at it is the one clearly bad choice available. That is
    /// <c>docs/decisions/0050-the-candidate-list-comes-from-the-configuration-partition.md</c>.
    /// </para>
    /// <para>
    /// <b>The role is recorded on an object, not on the controller.</b> There is no attribute on a
    /// controller listing the roles it holds. Each role is a single attribute on the object the role
    /// governs - the schema head, the Partitions container, a domain's naming context head - naming
    /// its holder by the distinguished name of that controller's <c>nTDSDSA</c> object. So a role is
    /// found by reading the object and then matching the answer against the candidate list, rather
    /// than by asking a controller what it is.
    /// </para>
    /// <para>
    /// <b>Which of these reads are free, and which are not.</b> The forest-level roles live in the
    /// configuration and schema partitions, which every controller in the forest holds a full
    /// replica of, so both are answered by the connection discovery already has open. A domain's PDC
    /// emulator sits on that domain's naming context head, which a controller of another domain does
    /// not hold - and referral chasing is off, so asking it produces a failure rather than an answer
    /// from elsewhere. Learning a foreign domain's PDC therefore costs a connection to that domain,
    /// which is why it is read during preflight, where a connection to each domain already exists,
    /// rather than during discovery.
    /// </para>
    /// </remarks>
    /// <param name="roleObjectDn">
    /// The object the role is recorded on. Composed by the caller rather than here, for the reason
    /// <see cref="ForCrossReferences"/> gives.
    /// </param>
    public static SearchRequest ForRoleOwner(string roleObjectDn)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(roleObjectDn);

        var request = new SearchRequest
        {
            DistinguishedName = roleObjectDn,
            Filter = "(objectClass=*)",
            Scope = SearchScope.Base,
            SizeLimit = 0,
            TimeLimit = ServerLimits.QueryDuration,
        };

        request.Attributes.Add("distinguishedName");
        request.Attributes.Add("fSMORoleOwner");

        return request;
    }

    /// <summary>
    /// The security-descriptor parts capture asks for: owner, group
    /// </summary>
    /// <remarks>
    /// <para>
    /// <c>nTSecurityDescriptor</c> is requested on every object, and without this control the
    /// server decides which parts of it to return. The SACL - the audit half of a descriptor - is
    /// privileged: retrieving it is one of the operations Microsoft lists as failing with
    /// insufficient access rights for a caller without the privilege behind it
    /// (<see href="https://learn.microsoft.com/windows/win32/api/winldap/nf-winldap-ldap_bind_s#remarks">ldap_bind_s</see>).
    /// </para>
    /// <para>
    /// <b>What that buys a customer.</b> A capture runs as an ordinary authenticated user. Nobody
    /// has to grant an audit tool a privilege on their domain controllers before it will read
    /// anything, and the product never holds the audit configuration of a forest it was asked only
    /// to inspect permissions on. The control is <c>LDAP_SERVER_SD_FLAGS_OID</c>,
    /// <c>1.2.840.113556.1.4.801</c>.
    /// </para>
    /// </remarks>
    public static SecurityDescriptorFlagControl SecurityDescriptorFlags() =>
        new(SecurityMasks.Owner | SecurityMasks.Group | SecurityMasks.Dacl);

    private static string BuildFilter()
    {
        var exclusions = string.Concat(
            CapturedAttributeCatalog.UnreadObjectClasses.Select(c => $"(!(objectClass={c}))"));

        return "(&(objectClass=*)" + exclusions + ")";
    }
}
