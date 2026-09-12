using System.DirectoryServices.Protocols;
using System.Text;
using SecureAD.Audit.Capture;
using SecureAD.Evidence;
using SecureAD.Kernel;

namespace SecureAD.Next.Tests.Capture;

/// <summary>
/// One <c>crossRef</c> object: the forest's own record of one of its partitions.
/// </summary>
/// <remarks>
/// <para>
/// <b>The flag values are Microsoft's and are written here as the constants they are.</b> A
/// cross-reference representing a domain carries both <c>ADS_SYSTEMFLAG_CR_NTDS_NC</c> (<c>0x1</c>)
/// and <c>ADS_SYSTEMFLAG_CR_NTDS_DOMAIN</c> (<c>0x2</c>); an application directory partition, and
/// the configuration and schema partitions, carry the first and not the second.
/// </para>
/// <para>
/// <b>An application partition is given a DNS name too, and that is deliberate.</b> Real ones have
/// one - <c>DomainDnsZones.example.com</c> - so a model that omitted it would let an implementation
/// pass by classifying on "has a dnsRoot" rather than on the flag that actually decides.
/// </para>
/// <para>
/// Every field is nullable so that a controller answering incompletely can be modelled. A
/// cross-reference with no readable <c>systemFlags</c> is the case where a run must refuse rather
/// than guess.
/// </para>
/// </remarks>
/// <param name="NamingContext">The partition's distinguished name, or null to omit <c>nCName</c>.</param>
/// <param name="DnsRoot">The partition's DNS name, or null to omit <c>dnsRoot</c>.</param>
/// <param name="SystemFlags">The flags as text, or null to omit <c>systemFlags</c>.</param>
internal sealed record CrossReference(string? NamingContext, string? DnsRoot, string? SystemFlags)
{
    /// <summary><c>ADS_SYSTEMFLAG_CR_NTDS_NC</c>: the naming context is held in Active Directory.</summary>
    private const int NamingContextIsInDirectory = 0x1;

    /// <summary><c>ADS_SYSTEMFLAG_CR_NTDS_DOMAIN</c>: the naming context is a domain.</summary>
    private const int NamingContextIsADomain = 0x2;

    /// <summary>A domain: both flags set, and a DNS name a run can connect to.</summary>
    public static CrossReference Domain(string namingContext, string dnsRoot) =>
        new(namingContext, dnsRoot, $"{NamingContextIsInDirectory | NamingContextIsADomain}");

    /// <summary>
    /// An application directory partition - the DNS zone partitions are the ones every forest has.
    /// </summary>
    public static CrossReference ApplicationPartition(string namingContext, string dnsRoot) =>
        new(namingContext, dnsRoot, $"{NamingContextIsInDirectory}");

    /// <summary>
    /// The configuration or schema partition. It carries the same flags as an application
    /// partition, which is why a run recognises those two by the names the RootDSE gave it rather
    /// than by anything here.
    /// </summary>
    public static CrossReference ForestPartition(string namingContext) =>
        new(namingContext, DnsRoot: null, $"{NamingContextIsInDirectory}");

    /// <summary>The name of the cross-reference object itself. Nothing reads meaning from it.</summary>
    public string Name => (NamingContext ?? "external").Replace('=', '-').Replace(',', '-');

    /// <summary>The attributes as the controller returns them, omitting any that is not set.</summary>
    public IEnumerable<KeyValuePair<string, IReadOnlyList<object>>> Attributes()
    {
        if (NamingContext is { } namingContext)
            yield return new("nCName", [namingContext]);

        if (DnsRoot is { } dnsRoot)
            yield return new("dnsRoot", [dnsRoot]);

        if (SystemFlags is { } systemFlags)
            yield return new("systemFlags", [systemFlags]);
    }
}

/// <summary>
/// A domain controller, modelled from the documentation, so that the capture loop can be run
/// against something without a forest.
///
/// <para>
/// It behaves the way Microsoft's articles say a controller behaves: it serves at most a page of
/// objects at a time and returns a bookmark while there is more, returns no bookmark on the last
/// page, will not put more than <c>MaxValRange</c> values of one attribute in one response, answers
/// a range retrieval under the ranged name it actually served, and marks the final block of one
/// with the wildcard.
/// </para>
/// <para>
/// <b>This proves the rule and not the wire.</b> Every behaviour above is taken from an article
/// rather than from a controller, which is finding F-S7-37 and is owed to the lab session. Saying
/// so is the point: a test that looked like proof of something it never touched is the failure this
/// repository has committed more than once.
/// </para>
/// </summary>
internal sealed class ControllerModel
{
    private readonly List<(string Dn, Dictionary<string, List<object>> Attributes)> _objects = [];

    public ControllerModel(string domainController = "dc01.example.com")
    {
        DomainController = domainController;
    }

    public string DomainController { get; }

    /// <summary>
    /// The names that reach this controller, beyond its own host name.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A domain's DNS name resolves to controllers holding that domain, so connecting to
    /// <c>example.com</c> genuinely arrives at <c>dc01.example.com</c> and the channel reports the
    /// name that was asked for. That is how a run given one controller reaches the rest of a
    /// forest, and a model that could not express it would make every domain unit look like a
    /// connection to the wrong host.
    /// </para>
    /// <para>
    /// It is opt-in, and deliberately so. <c>PartitionCaptureTests</c> refuses a channel opened
    /// against a different controller, and it proves that by handing out a model whose host name is
    /// not the one the unit asked for. A model that answered to every name would make that check
    /// impossible to fail.
    /// </para>
    /// </remarks>
    public List<string> AnswersTo { get; } = [];

    /// <summary>The referral policy the connections this model hands out will report.</summary>
    public ReferralChasingOptions ReferralChasing { get; set; } = ReferralChasingOptions.None;

    /// <summary>
    /// The controls this model advertises, which decide what capture is able to ask for.
    /// </summary>
    /// <remarks>
    /// <c>1.2.840.113556.1.4.319</c> is paged results and <c>1.2.840.113556.1.4.1339</c> is the
    /// domain-scope control, which asks a controller to generate no continuation references. Until
    /// <c>F-S30-3</c> only paging was advertised, so capture never suppressed referrals against this
    /// model while it always does against a real controller - and the end-to-end test therefore
    /// asserted the opposite of what the product does in the field.
    /// </remarks>
    public List<string> SupportedControls { get; } =
        ["1.2.840.113556.1.4.319", "1.2.840.113556.1.4.1339"];

    /// <summary>Whether the controller's advertised capabilities were read at all.</summary>
    public bool CapabilitiesWereRead { get; set; } = true;

    /// <summary>
    /// The rung the connection to this controller landed on. Defaults to the one most real captures
    /// reach, so a test that says nothing about connection security gets the ordinary case.
    /// </summary>
    public ConnectionSecurityLevel SecurityLevel { get; set; } =
        ConnectionSecurityLevel.SignedAndSealed;

    /// <summary>The most values of one attribute this controller will put in one response.</summary>
    public int MaxValRange { get; set; } = 1500;

    /// <summary>Continuation references the controller mentions on its first page.</summary>
    public List<string> References { get; } = [];

    /// <summary>
    /// The partitions this controller publishes in its RootDSE.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The DNS application partition is here on purpose, and it is what makes the coverage
    /// assertion mean something.</b> A controller publishes every partition it holds, and every
    /// forest has the two DNS zone partitions. Without one in this list there is nothing a correct
    /// implementation would decline to read, so <c>NotRead</c> is empty for the trivial reason and
    /// an assertion about it holds no matter what the code under it does. That is <c>F-S28-2</c>.
    /// </para>
    /// <para>
    /// It is also spelled exactly as a domain is - <c>DC=DomainDnsZones,DC=example,DC=com</c> -
    /// which is the whole reason a partition list cannot be classified by the shape of a name and
    /// the cross-references below have to be read.
    /// </para>
    /// </remarks>
    public List<string> NamingContexts { get; } =
    [
        "DC=example,DC=com",
        "CN=Configuration,DC=example,DC=com",
        "CN=Schema,CN=Configuration,DC=example,DC=com",
        "DC=DomainDnsZones,DC=example,DC=com",
    ];

    /// <summary>The configuration partition, as the RootDSE states it.</summary>
    public string? ConfigurationNamingContext { get; set; } = "CN=Configuration,DC=example,DC=com";

    /// <summary>The schema partition, as the RootDSE states it.</summary>
    public string? SchemaNamingContext { get; set; } = "CN=Schema,CN=Configuration,DC=example,DC=com";

    /// <summary>
    /// The forest root domain's partition, as the RootDSE states it.
    /// </summary>
    /// <remarks>
    /// Every controller in a forest publishes this, and it is how a run learns which of the domains
    /// it discovered is the forest itself - a fact it would otherwise have to infer from the shape
    /// of a name, which is the guessing this session removed.
    /// </remarks>
    public string? RootDomainNamingContext { get; set; } = "DC=example,DC=com";

    /// <summary>
    /// The forest's own account of its partitions: one <c>crossRef</c> per partition, answered to a
    /// one-level search of the Partitions container.
    /// </summary>
    /// <remarks>
    /// Held separately from <see cref="NamingContexts"/> rather than derived from it, because the
    /// two genuinely differ and the difference is the point. A controller's RootDSE lists what that
    /// controller holds; the cross-references list what the <i>forest</i> has. In a forest of nine
    /// domains the first names one and the second names nine, and a model that computed one from
    /// the other could not express the case that is <c>F-S28-1</c>.
    /// </remarks>
    public List<CrossReference> CrossReferences { get; } =
    [
        CrossReference.Domain("DC=example,DC=com", "example.com"),
        CrossReference.ForestPartition("CN=Configuration,DC=example,DC=com"),
        CrossReference.ForestPartition("CN=Schema,CN=Configuration,DC=example,DC=com"),
        CrossReference.ApplicationPartition(
            "DC=DomainDnsZones,DC=example,DC=com", "DomainDnsZones.example.com"),
    ];

    /// <summary>
    /// The base the cross-reference search was issued against, or null if it was never issued.
    /// </summary>
    /// <remarks>
    /// Recorded so a test can assert the Partitions container was composed correctly, rather than
    /// only that some answer came back. A search of the wrong container returning nothing and a
    /// forest genuinely having no cross-references are different failures.
    /// </remarks>
    public string? CrossReferenceSearchBase { get; private set; }

    /// <summary>
    /// Distinguished names this controller will not serve, however they are asked for.
    /// </summary>
    /// <remarks>
    /// <para>
    /// It answers <c>noSuchObject</c> rather than <c>insufficientAccessRights</c>, because that is
    /// what Active Directory does: a caller without list access on an object is told the object is
    /// not there. A model that answered "access denied" would let a caller distinguish denied from
    /// absent, which no real caller can - and preflight's fourth question exists precisely because
    /// the two are indistinguishable.
    /// </para>
    /// </remarks>
    public List<string> RefusesToRead { get; } = [];

    /// <summary>Omit the paging control from every response, as though paging never happened.</summary>
    public bool AnswerWithoutThePagingControl { get; set; }


    /// <summary>Hand back the same bookmark that was sent, forever.</summary>
    public bool RepeatTheCookie { get; set; }

    /// <summary>Return one empty page, with a fresh bookmark, before the real first page.</summary>
    public bool BeginWithAnEmptyPage { get; set; }

    /// <summary>
    /// Report the search finished on the first page while holding more. This is what the client
    /// sees when a subordinate referral was chased: the bookmark is wiped inside the LDAP runtime
    /// and the application is told there is nothing more.
    /// </summary>
    public bool ClaimToBeFinishedAfterOnePage { get; set; }

    /// <summary>Fail this many times with <see cref="FailWithCode"/> before answering.</summary>
    public int FailuresBeforeAnswering { get; set; }

    /// <summary>
    /// Fail the request with this one-based number. Null leaves request-position failure disabled.
    /// </summary>
    public int? FailRequestNumber { get; set; }

    public int FailWithCode { get; set; } = 51;

    /// <summary>
    /// Raise the failure the way a controller's own answer arrives, rather than the way the client
    /// library reports a failure that never reached one.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The two are different types and only one of them was ever modelled here.</b> A result
    /// code the controller itself returned comes back from <c>EndSendRequest</c> as a
    /// <c>DirectoryOperationException</c>, which does not derive from <c>LdapException</c>. Busy
    /// and Unavailable - the two failures the retry policy exists for - are exactly that kind, so
    /// a model that only ever threw <c>LdapException</c> proved the retry against the one shape it
    /// never has to handle.
    /// </para>
    /// <para>
    /// It is opt-in rather than the default because the client-library failures this model also
    /// serves - <c>ServerDown</c> at 81, <c>Timeout</c> at 85 - genuinely do arrive as
    /// <c>LdapException</c>, and collapsing the two would trade one blind spot for another.
    /// </para>
    /// </remarks>
    public bool FailsAsServerResult { get; set; }

    /// <summary>
    /// The exception a failing request raises, in whichever of the two shapes
    /// <see cref="FailsAsServerResult"/> asks for.
    /// </summary>
    public DirectoryException Failure() =>
        FailsAsServerResult
            ? ServerResultFailure.AnsweredWith(
                (ResultCode)FailWithCode,
                $"The controller answered with result code {FailWithCode}.")
            : new LdapException(FailWithCode);

    /// <summary>How many connections this model has been asked for.</summary>
    public int ConnectionsOpened { get; private set; }

    /// <summary>How many requests have reached it, across all connections.</summary>
    public int RequestsReceived { get; private set; }

    /// <summary>
    /// Whether text values are served as bytes, which is what a directory actually sends.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>True by default, because false is a world no controller lives in.</b> This model served
    /// text as .NET strings until a lab run failed on 2026-08-14 with a message saying the
    /// controller had not published <c>configurationNamingContext</c>. It had. The readers were
    /// filtering values with <c>OfType&lt;string&gt;()</c> and finding none, because a live response
    /// carries bytes - and no test could catch it, since every test handed the reader strings.
    /// </para>
    /// <para>
    /// The switch exists so a test can say plainly that it is about the other shape, not so that a
    /// test can opt out of reality.
    /// </para>
    /// </remarks>
    public bool ServesTextAsBytes { get; set; } = true;

    /// <summary>
    /// Serve <c>configurationNamingContext</c> as bytes that are not valid text.
    /// </summary>
    /// <remarks>
    /// The attribute is present and its value cannot be read. That is a third state, distinct from
    /// both a controller that published it and one that did not, and the product must not collapse
    /// it into either.
    /// </remarks>
    public bool ServesAnUnreadableConfigurationNamingContext { get; set; }

    /// <summary>One attribute value, in the shape this controller serves it.</summary>
    private object OnTheWire(object value) =>
        ServesTextAsBytes && value is string text ? Encoding.UTF8.GetBytes(text) : value;

    private IReadOnlyList<object> OnTheWire(IEnumerable<object> values) =>
        values.Select(OnTheWire).ToList();

    public void AddObject(string dn, params (string Attribute, object[] Values)[] attributes)
    {
        var byName = new Dictionary<string, List<object>>(StringComparer.OrdinalIgnoreCase);
        foreach (var (attribute, values) in attributes)
        {
            byName[attribute] = [.. values];
        }

        _objects.Add((dn, byName));
    }

    public void AddObjects(int count, string suffix)
    {
        for (var i = 0; i < count; i++)
        {
            AddObject($"CN=object{i},{suffix}", ("objectClass", ["top"]));
        }
    }

    public IDirectoryChannelFactory Connections() => new Factory(this);

    private sealed class Factory(ControllerModel model) : IDirectoryChannelFactory
    {
        public Result<IDirectoryChannel> Connect(CaptureUnit unit)
        {
            model.ConnectionsOpened++;
            return new Channel(model, unit.DomainController);
        }

        public Result<IDirectoryChannel> Connect(string domainController)
        {
            model.ConnectionsOpened++;
            return new Channel(model, domainController);
        }
    }

    private sealed class Channel(ControllerModel model, string requested) : IDirectoryChannel
    {
        private bool _emptyPageServed;

        /// <summary>
        /// The controller this channel reports being connected to.
        /// </summary>
        /// <remarks>
        /// The name that was asked for, when this controller answers to it - which is what the real
        /// factory does, since it builds the channel from the host it was told to open. Otherwise
        /// the model's own name, so that a channel handed out for the wrong controller is visibly
        /// the wrong controller.
        /// </remarks>
        public string DomainController =>
            model.AnswersTo.Contains(requested, StringComparer.OrdinalIgnoreCase)
                ? requested
                : model.DomainController;

        public ConnectionSecurityLevel SecurityLevel => model.SecurityLevel;

        public ReferralChasingOptions ReferralChasing => model.ReferralChasing;

        public IReadOnlyList<string> SupportedControls => model.SupportedControls;

        public IReadOnlyList<string> NamingContextsServed => model.NamingContexts;

        public bool IsComplete => model.CapabilitiesWereRead;

        public void Dispose()
        {
        }

        public Task<DirectoryPage> SendAsync(
            SearchRequest request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            model.RequestsReceived++;

            if (model.FailRequestNumber == model.RequestsReceived)
                throw model.Failure();

            if (model.FailuresBeforeAnswering > 0)
            {
                model.FailuresBeforeAnswering--;
                throw model.Failure();
            }

            if (model.RefusesToRead.Contains(
                    request.DistinguishedName, StringComparer.OrdinalIgnoreCase))
            {
                // 32 is noSuchObject. See RefusesToRead for why this rather than a denial.
                throw new LdapException(32, "The object does not exist.");
            }

            return Task.FromResult(
                IsCrossReferenceSearch(request) ? CrossReferences(request)
                : request.Scope != SearchScope.Base ? Page(request)
                : request.DistinguishedName.Length == 0 ? RootDse()
                : IsRangeRetrieval(request) ? AttributeBlock(request)
                : BaseEntry(request));
        }

        /// <summary>
        /// Whether a base-scope read is asking for one attribute's values a block at a time, rather
        /// than for the entry itself.
        /// </summary>
        /// <remarks>
        /// Told apart by the range option on the attribute name, which is the only thing that
        /// distinguishes them on the wire. Before preflight read the Password Settings Container,
        /// every base-scope read this model saw was a range retrieval and the two paths were one -
        /// which would have made an ordinary base read crash the model rather than answer it.
        /// </remarks>
        private static bool IsRangeRetrieval(SearchRequest request) =>
            request.Attributes.Count > 0
            && request.Attributes[0]!.ToString()!
                .Contains(";range=", StringComparison.OrdinalIgnoreCase);

        /// <summary>
        /// One entry, read at base scope.
        /// </summary>
        /// <remarks>
        /// An object this controller does not hold answers <c>noSuchObject</c>, which is what a
        /// real one does - and is the same answer it gives a caller who holds the object but lacks
        /// list access on it. Returning an empty page instead would let a read of something that
        /// is not there look like a read that succeeded.
        /// </remarks>
        private DirectoryPage BaseEntry(SearchRequest request)
        {
            var found = model._objects
                .FirstOrDefault(o => string.Equals(
                    o.Dn, request.DistinguishedName, StringComparison.OrdinalIgnoreCase));

            if (found.Attributes is null)
            {
                throw new LdapException(32, "The object does not exist.");
            }

            return DirectoryPage.From(
                [LdapEntryReader.ForValues(found.Dn, Serve(found.Attributes))],
                cookie: null,
                continuationReferences: []);
        }

        /// <summary>
        /// Whether this is the forest's own account of its partitions being asked for.
        /// </summary>
        /// <remarks>
        /// Recognised by the filter rather than by the base, so a request aimed at the wrong
        /// container still reaches <see cref="CrossReferences"/> and is recorded there. A model
        /// that matched on the base would answer nothing to a misaddressed search, and the caller
        /// would see an empty forest rather than a mistake.
        /// </remarks>
        private static bool IsCrossReferenceSearch(SearchRequest request) =>
            string.Equals(request.Filter as string, "(objectClass=crossRef)", StringComparison.Ordinal);

        /// <summary>
        /// The cross-reference objects, as a one-level search of the Partitions container returns
        /// them.
        /// </summary>
        private DirectoryPage CrossReferences(SearchRequest request)
        {
            model.CrossReferenceSearchBase = request.DistinguishedName;

            var entries = model.CrossReferences
                .Select(c => LdapEntryReader.ForValues(
                    "CN=" + c.Name + "," + request.DistinguishedName,
                    c.Attributes().Select(a =>
                        new KeyValuePair<string, IReadOnlyList<object>>(
                            a.Key, model.OnTheWire(a.Value)))))
                .ToList();

            return DirectoryPage.From(entries, cookie: null, continuationReferences: []);
        }

        /// <summary>
        /// The entry every LDAP server publishes: read with an empty base at base scope.
        /// </summary>
        private DirectoryPage RootDse()
        {
            var attributes = new List<KeyValuePair<string, IReadOnlyList<object>>>
            {
                new("supportedControl", model.OnTheWire(model.SupportedControls.Cast<object>())),
                new("namingContexts", model.OnTheWire(model.NamingContexts.Cast<object>())),
            };

            if (model.ConfigurationNamingContext is { } configuration)
            {
                attributes.Add(new(
                    "configurationNamingContext",
                    model.ServesAnUnreadableConfigurationNamingContext
                        ? [new byte[] { 0xFF, 0xFE, 0xFD }]
                        : [model.OnTheWire(configuration)]));
            }

            if (model.SchemaNamingContext is { } schema)
                attributes.Add(new("schemaNamingContext", [model.OnTheWire(schema)]));

            if (model.RootDomainNamingContext is { } rootDomain)
                attributes.Add(new("rootDomainNamingContext", [model.OnTheWire(rootDomain)]));

            // The RootDSE has no distinguished name. It is given one here only because the reader
            // needs something to report an attribute against, and nothing reads it back.
            return DirectoryPage.From(
                [LdapEntryReader.ForValues("RootDSE", attributes)],
                cookie: null,
                continuationReferences: []);
        }

        private DirectoryPage Page(SearchRequest request)
        {
            var sentCookie = CookieOf(request);

            if (model.BeginWithAnEmptyPage && !_emptyPageServed)
            {
                _emptyPageServed = true;
                return DirectoryPage.From([], Bookmark(0), []);
            }

            // Only what is below the base being searched. A controller serving every object it
            // holds whatever it was asked for would let a run over three partitions store each
            // object three times and no test would notice.
            var matching = model._objects
                .Where(o => o.Dn.EndsWith(request.DistinguishedName, StringComparison.OrdinalIgnoreCase))
                .ToList();

            var from = sentCookie.Length == 0 ? 0 : int.Parse(Encoding.UTF8.GetString(sentCookie));
            var take = Math.Min(ServerLimits.PageSize, matching.Count - from);

            var entries = new List<LdapEntryReader>();
            for (var i = from; i < from + take; i++)
            {
                var (dn, attributes) = matching[i];
                entries.Add(LdapEntryReader.ForValues(dn, Serve(attributes)));
            }

            var references = from == 0 ? model.References.ToList() : [];
            var next = from + take;

            byte[]? cookie =
                model.AnswerWithoutThePagingControl ? null
                : model.RepeatTheCookie ? (sentCookie.Length == 0 ? Bookmark(take) : sentCookie)
                : model.ClaimToBeFinishedAfterOnePage ? []
                : next >= matching.Count ? []
                : Bookmark(next);

            return DirectoryPage.From(entries, cookie, references);
        }

        /// <summary>
        /// The values of one attribute, truncated to what the controller will serve at once and
        /// named with the range it actually served.
        /// </summary>
        private IEnumerable<KeyValuePair<string, IReadOnlyList<object>>> Serve(
            Dictionary<string, List<object>> attributes)
        {
            foreach (var (name, values) in attributes)
            {
                if (values.Count <= model.MaxValRange)
                {
                    yield return new(name, model.OnTheWire(values));
                    continue;
                }

                var served = Math.Min(model.MaxValRange, AttributeRange.ValuesPerRound);
                yield return new(
                    $"{name};range=0-{served - 1}",
                    model.OnTheWire(values.Take(served)));
            }
        }

        private DirectoryPage AttributeBlock(SearchRequest request)
        {
            var asked = request.Attributes[0]!.ToString()!;
            var marker = asked.IndexOf(";range=", StringComparison.OrdinalIgnoreCase);
            var name = asked[..marker];
            var low = int.Parse(asked[(marker + 7)..].Split('-')[0]);

            var found = model._objects
                .FirstOrDefault(o => string.Equals(
                    o.Dn, request.DistinguishedName, StringComparison.OrdinalIgnoreCase));

            if (found.Attributes is null || !found.Attributes.TryGetValue(name, out var all))
            {
                return DirectoryPage.From([], [], []);
            }

            var served = Math.Min(
                Math.Min(model.MaxValRange, AttributeRange.ValuesPerRound), all.Count - low);
            var last = low + served >= all.Count;

            var returnedName = last ? $"{name};range={low}-*" : $"{name};range={low}-{low + served - 1}";

            return DirectoryPage.From(
                [
                    LdapEntryReader.ForValues(
                        found.Dn,
                        [new(returnedName, model.OnTheWire(all.Skip(low).Take(served)))])
                ],
                [],
                []);
        }

        private static byte[] Bookmark(int index) => Encoding.UTF8.GetBytes(index.ToString());

        private static byte[] CookieOf(SearchRequest request)
        {
            foreach (DirectoryControl control in request.Controls)
            {
                if (control is PageResultRequestControl paging)
                    return paging.Cookie ?? [];
            }

            return [];
        }
    }
}

/// <summary>Collects what the loop hands on, so a test can count it and look at it.</summary>
internal sealed class RecordingSink : ICapturedObjectSink
{
    private int? _receivedCheckpoint;

    public List<CapturedObject> Received { get; } = [];

    /// <summary>The partitions the loop announced, in the order it announced them.</summary>
    public List<(CaptureUnit Unit, ConnectionSecurityLevel Security, bool ReferralsSuppressed)> Opened { get; } = [];

    /// <summary>The coverage the loop reported for each partition it finished.</summary>
    public List<PartitionCoverage> Completed { get; } = [];

    public void BeginPartition(
        CaptureUnit unit, ConnectionSecurityLevel connectionSecurity, bool referralsSuppressed)
    {
        _receivedCheckpoint = Received.Count;
        Opened.Add((unit, connectionSecurity, referralsSuppressed));
    }

    public void Receive(CapturedObject capturedObject) => Received.Add(capturedObject);

    public void AbortPartition()
    {
        Opened.RemoveAt(Opened.Count - 1);
        Received.RemoveRange(_receivedCheckpoint!.Value, Received.Count - _receivedCheckpoint.Value);
        _receivedCheckpoint = null;
    }

    public void CompletePartition(PartitionCoverage coverage)
    {
        Completed.Add(coverage);
        _receivedCheckpoint = null;
    }
}
