using System.Collections;
using System.Runtime.CompilerServices;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Kernel.Capture;
using SecureAD.Kernel.Security;
using Xunit;
using static SecureAD.Next.Tests.Judgement.JudgingStatusTests;

namespace SecureAD.Next.Tests.Judgement;

public sealed class RequesterReuseTests
{
    [Fact]
    public void WorkCountersObserveEnumerationWithoutAnObserverCallback()
    {
        var values = new CountingList<int>([3, 5]);
        Assert.Equal(8, values.Sum());
        Assert.Equal(2, values.Visits);
        Assert.Equal(3, values[0]);
        Assert.Equal(3, values.Visits);
    }

    [Theory]
    [InlineData(1, 1, 1)]
    [InlineData(12, 8, 3)]
    public void SelectionRetainsEveryQuestionWitnessFingerprintAndLimitation(int members, int targets, int duplicates)
    {
        var fixture = new SelectionFixture(members, targets, duplicates);
        var expected = fixture.Reference();
        var actual = fixture.Select();

        Assert.NotEmpty(expected.Candidates);
        Assert.Contains(expected.Candidates, value => value.Family == PathRequesterFamily.MembershipDacl);
        Assert.Equal(Tier0PathCalculation.Fingerprint(expected), Tier0PathCalculation.Fingerprint(actual));
        Assert.All(actual.Candidates, candidate => Assert.Equal(candidate.Witnesses.Count, candidate.Witnesses.Distinct().Count()));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(64)]
    public void SelectionEnumeratesIdentityNodesOnceNotOncePerQuestion(int members)
    {
        var fixture = new SelectionFixture(members, 8, 2);
        var actual = fixture.Select();
        Assert.Equal(members * (8 + 1 + 8), actual.Candidates.Count);
        Assert.Equal((1, fixture.Nodes.Count), (fixture.Nodes.Passes, fixture.Nodes.Visits));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(64)]
    public void SelectionVisitsTargetEntriesFiveTimesIndependentOfMembers(int members)
    {
        var fixture = new SelectionFixture(members, 8, 2);
        var actual = fixture.Select();
        Assert.NotEmpty(actual.Candidates);
        // Index, selection, holder fingerprint, serialized entries and serialized OWNER RIGHTS presence.
        Assert.All(fixture.TargetEntries, entries => Assert.Equal(5 * entries.Count, entries.Visits));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(64)]
    public void SelectionFingerprintsEachRequesterOnceDespiteManyWitnesses(int duplicates)
    {
        var fixture = new SelectionFixture(8, 3, duplicates);
        var actual = fixture.Select();
        Assert.Equal(8 * (3 + 1 + 3), actual.Candidates.Count);
        // One fingerprint serializes Values and the same attribute's OnlyValue.
        Assert.All(fixture.Probes, values => Assert.Equal(2, values.Visits));
        Assert.All(actual.Candidates.Where(candidate => candidate.Family == PathRequesterFamily.MembershipDacl),
            candidate => Assert.Equal(duplicates + 1, candidate.Witnesses.Count));
    }

    [Theory]
    [InlineData("duplicate")]
    [InlineData("cross-domain")]
    [InlineData("missing")]
    [InlineData("broad")]
    [InlineData("case")]
    public void SelectionLookupPreservesIdentityScopeAndExplicitLimitations(string variant)
    {
        var fixture = new SelectionFixture(2, 2, 2);
        fixture.Change(variant);
        var expected = fixture.Reference();
        var actual = fixture.Select();
        Assert.Equal(Tier0PathCalculation.Fingerprint(expected), Tier0PathCalculation.Fingerprint(actual));
        if (variant != "case")
            Assert.Contains(actual.Limitations, value => value.Reason is PathRequesterSelectionReason.IdentityUnresolved
                or PathRequesterSelectionReason.ResourceContextUnsupported or PathRequesterSelectionReason.BroadIdentityNotExpanded);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ScopedBuiltinIdentityCollisionsDoNotCrossDomains(bool sameScope)
    {
        var fixture = new SelectionFixture(1, 1, 1);
        fixture.AddScopedIdentity(sameScope);
        var actual = fixture.Select();
        Assert.Equal(Tier0PathCalculation.Fingerprint(fixture.Reference()), Tier0PathCalculation.Fingerprint(actual));
        Assert.Equal(sameScope, actual.Candidates.Count == 0);
    }

    [Fact]
    public void SelectionStopsWhenCancellationArrivesDuringIdentityIndexing()
    {
        var fixture = new SelectionFixture(64, 8, 2);
        using var stopping = new CancellationTokenSource();
        fixture.Nodes.OnVisit = visited => { if (visited == 3) stopping.Cancel(); };
        Assert.Throws<OperationCanceledException>(() => fixture.Select(stopping.Token));
        Assert.InRange(fixture.Nodes.Visits, 3, 4);
        Assert.All(fixture.TargetEntries, entries => Assert.Equal(0, entries.Visits));
    }

    [Fact]
    public void SelectionDiagnosticsCountRealWorkWithoutRecordingIdentities()
    {
        var fixture = new SelectionFixture(4, 3, 2);
        var log = new StatusLog();
        var clock = new TimerClock();
        using var status = new JudgingStatus(log, JudgingRun.NobodyIsWatching, clock, () => new(1, 2, 3, 4, 5, 6, 7, "available"));
        PathRequesterSelection selected;
        using (var diagnostic = status.BeginPostPass("Selecting account checks", fixture.Inputs.JudgementGenerationId))
        {
            fixture.Nodes.OnVisit = visited => { if (visited == 1) clock.Advance(TimeSpan.FromMinutes(1)); };
            selected = fixture.Select(diagnostic: diagnostic);
            diagnostic.Complete();
        }
        var running = Assert.Single(log.Lines, line => line.Message == "post-pass status" && line.Value("outcome") == "running");
        Assert.Equal(("indexing-identities", "execution-only"), (running.Value("activePart"), running.Value("kind")));
        var complete = Assert.Single(log.Lines, line => line.Message == "post-pass status" && line.Value("outcome") == "completed");
        Assert.Equal((fixture.Nodes.Count.ToString(), selected.Sources.Count.ToString(), selected.Candidates.Count.ToString(), "4"),
            (complete.Value("identityNodesIndexed"), complete.Value("resourcesProcessed"), complete.Value("distinctQuestions"), complete.Value("accountsFingerprinted")));
        var text = System.Text.Json.JsonSerializer.Serialize(log.Lines);
        Assert.Contains("identityNodesIndexed", text);
        Assert.DoesNotContain("CN=", text);
        Assert.DoesNotContain("S-1-5-", text);
    }

    [Fact]
    public void StreamedSelectorReleasesResourceAttributeAndPermissionSnapshots()
    {
        var fixture = new SelectionFixture(8, 6, 2);
        var sink = new RequesterSelectionEvaluation.Collector();
        var attributes = new List<WeakReference>();
        var permissions = new List<WeakReference>();
        var selector = fixture.Producer(sink, value => Detached(value, attributes), value => Detached(value, permissions));

        var scan = selector.Select();
        Assert.NotEmpty(sink.Finish(scan).Candidates);
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();

        Assert.NotEmpty(attributes);
        Assert.NotEmpty(permissions);
        Assert.All(attributes, value => Assert.False(value.IsAlive));
        Assert.All(permissions, value => Assert.False(value.IsAlive));
        GC.KeepAlive(selector);
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static ObjectAttributes Detached(ObjectAttributes value, List<WeakReference> seen)
    {
        var snapshot = value with { };
        seen.Add(new(snapshot));
        return snapshot;
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static ObjectPermissions Detached(ObjectPermissions value, List<WeakReference> seen)
    {
        var snapshot = value with { };
        seen.Add(new(snapshot));
        return snapshot;
    }

    internal sealed class CountingList<T>(IReadOnlyList<T> values) : IReadOnlyList<T>
    {
        internal int Visits { get; private set; }
        internal Action<int>? OnVisit { get; set; }
        public int Count => values.Count;
        public T this[int index]
        {
            get { Visits++; OnVisit?.Invoke(Visits); return values[index]; }
        }
        public IEnumerator<T> GetEnumerator()
        {
            for (var index = 0; index < Count; index++) yield return this[index];
        }
        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
        internal void Reset() => Visits = 0;
    }

    internal sealed class CountingNodes(Dictionary<string, Tier0PathNode> values) : IReadOnlyDictionary<string, Tier0PathNode>
    {
        internal int Passes { get; private set; }
        internal int Visits { get; private set; }
        internal Action<int>? OnVisit { get; set; }
        internal Dictionary<string, Tier0PathNode> Inner => values;
        public int Count => values.Count;
        public IEnumerable<string> Keys => values.Keys;
        public IEnumerable<Tier0PathNode> Values => Enumerate();
        public Tier0PathNode this[string key] => values[key];
        public bool ContainsKey(string key) => values.ContainsKey(key);
        public bool TryGetValue(string key, out Tier0PathNode value) => values.TryGetValue(key, out value!);
        public IEnumerator<KeyValuePair<string, Tier0PathNode>> GetEnumerator() => values.GetEnumerator();
        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
        private IEnumerable<Tier0PathNode> Enumerate()
        {
            Passes++;
            foreach (var value in values.Values) { Visits++; OnVisit?.Invoke(Visits); yield return value; }
        }
    }

    private sealed class SelectionFixture
    {
        private const string Domain = "DC=contoso,DC=com";
        private const string Group = "CN=Obtainable," + Domain;
        private const string Holder = "CN=Holder," + Domain;
        private readonly Dictionary<string, ObjectAttributes> _attributes = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, ObjectPermissions> _permissions = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, NamingContextKind> _contexts = new(StringComparer.OrdinalIgnoreCase) { [Domain] = NamingContextKind.Domain };
        internal CountingNodes Nodes { get; } = new(new(StringComparer.OrdinalIgnoreCase));
        internal PathInputs Inputs { get; private set; }
        internal List<CountingList<PermissionEntry>> TargetEntries { get; } = [];
        internal List<CountingList<AttributeValue>> Probes { get; } = [];
        private readonly string[] _users;

        internal SelectionFixture(int members, int targets, int duplicates)
        {
            _users = Enumerable.Range(0, members).Select(index => $"CN=User{index},{Domain}").ToArray();
            for (var index = 0; index < members; index++)
            {
                var probe = new CountingList<AttributeValue>([new(0, "fingerprint-only", null)]);
                Probes.Add(probe);
                Add(_users[index], $"S-1-5-21-1-2-3-{1100 + index}", "user", [],
                    [new("description", AttributeCardinality.SingleValued, probe)]);
            }
            Add(Holder, "S-1-5-21-1-2-3-2001", "group",
                [Attribute("groupType", "-2147483646"), Attribute("member", _users)], []);
            var holder = new PermissionTrustee("S-1-5-21-1-2-3-2001", "Holder", Holder, "contoso.com", null, null, null);
            Add(Group, "S-1-5-21-1-2-3-2002", "group", [Attribute("groupType", "-2147483646")], []);
            Nodes.Inner[Group] = Nodes.Inner[Group] with { MembershipDistance = 1 };
            _permissions[Group] = Permissions(Group, Enumerable.Range(0, duplicates).Select(ordinal =>
                new PermissionEntry(ordinal, "AccessAllowed", holder, 0x08, null, null, false, 0, 0, false, false, [])).ToArray());
            var fixedTargets = new List<Tier0Target>();
            for (var index = 0; index < targets; index++)
            {
                var dn = $"CN=Tier0{index},{Domain}";
                Add(dn, $"S-1-5-21-1-2-3-{3000 + index}", "group", [Attribute("groupType", "-2147483646")], []);
                var entries = new CountingList<PermissionEntry>(
                [
                    new(0, "AccessAllowed", holder, 0x40000, null, null, false, 0, 0, false, false, []),
                    new(1, "AccessDenied", new("S-1-5-21-1-2-3-2002", "Obtainable", Group, "contoso.com", null, null, null),
                        0x40000, null, null, false, 0, 0, false, false, []),
                ]);
                TargetEntries.Add(entries);
                _permissions[dn] = Permissions(dn, entries);
                Nodes.Inner[dn] = Nodes.Inner[dn] with { MembershipDistance = 0 };
                fixedTargets.Add(Nodes[dn].Subject);
            }
            Inputs = new(Guid.NewGuid(), PathInputAvailability.Recorded, null,
                new(true, false, true, Tier0Limitations.None), fixedTargets, [], [], [], [], null);
        }

        internal PathRequesterSelection Select(CancellationToken token = default, PostPassDiagnostics? diagnostic = null) =>
            RequesterSelectionEvaluation.Select(dn => _attributes.GetValueOrDefault(dn), dn => _permissions.GetValueOrDefault(dn),
                Inputs, Nodes, _contexts, token, diagnostic, null);

        internal PathRequesterSelector Producer(IPathRequesterSelectionSink sink,
            Func<ObjectAttributes, ObjectAttributes> attributes, Func<ObjectPermissions, ObjectPermissions> permissions) =>
            new(dn => _attributes.GetValueOrDefault(dn) is { } value ? attributes(value) : null,
                dn => _permissions.GetValueOrDefault(dn) is { } value ? permissions(value) : null,
                Inputs, Nodes, _contexts, CancellationToken.None, null, sink);

        internal PathRequesterSelection Reference() =>
            new RequesterSelectionReference(dn => _attributes.GetValueOrDefault(dn), dn => _permissions.GetValueOrDefault(dn),
                Inputs, Nodes.Inner, _contexts, CancellationToken.None).Select() with { Version = PathRequesterSelector.Version };

        internal void Change(string variant)
        {
            if (variant == "duplicate") Add("CN=Duplicate," + Domain, Nodes[_users[0]].Subject.Sid!, "user", [], []);
            else if (variant == "missing") _attributes.Remove(_users[0]);
            else if (variant == "cross-domain")
            {
                var value = _attributes[_users[0]] with { DomainFqdn = "other.contoso.com" };
                _attributes[_users[0]] = value;
                Nodes.Inner[_users[0]] = Nodes[_users[0]] with { Subject = Tier0Target.From(value, Domain) };
            }
            else if (variant == "broad")
            {
                var permission = _permissions[Group];
                _permissions[Group] = permission with { Entries = permission.Entries.Select(entry =>
                    entry with { Trustee = new("S-1-5-11", "Authenticated Users", null, null, null, null, null) }).ToArray() };
            }
            else
            {
                var first = Inputs.FixedTargets[0].DistinguishedName;
                _permissions[first] = _permissions[first] with { Entries = _permissions[first].Entries.Select(entry =>
                    entry with { Trustee = entry.Trustee with { DistinguishedName = entry.Trustee.DistinguishedName?.ToUpperInvariant() } }).ToArray() };
            }
        }

        internal void AddScopedIdentity(bool sameScope)
        {
            var user = _attributes[_users[0]];
            user = user with { Attributes = user.Attributes.Select(attribute => attribute.LdapDisplayName == "objectSid"
                ? Attribute("objectSid", "S-1-5-32-544") : attribute).ToArray() };
            _attributes[_users[0]] = user;
            Nodes.Inner[_users[0]] = Nodes[_users[0]] with { Subject = Tier0Target.From(user, Domain) };
            var domain = sameScope ? Domain : "DC=other,DC=contoso,DC=com";
            Add("CN=Duplicate," + domain, "S-1-5-32-544", "user", [], [], domain);
        }

        private void Add(string dn, string sid, string kind, ObjectAttribute[] extra, ObjectAttribute[] other, string domain = Domain)
        {
            var value = new ObjectAttributes(dn, Guid.NewGuid(), DateTimeOffset.UnixEpoch, EvidenceCompleteness.Complete,
                [Attribute("objectClass", kind == "user" ? ["top", "person", "user"] : ["top", kind]), Attribute("objectSid", sid), .. extra, .. other],
                DomainFqdn: SecureAD.Kernel.Naming.DnHelper.DnToFqdn(domain));
            _attributes.Add(dn, value);
            Nodes.Inner.Add(dn, new(Tier0Target.From(value, domain), null, null, null, null));
            _permissions.Add(dn, Permissions(dn, []));
        }

        private static ObjectAttribute Attribute(string name, params string[] values) =>
            new(name, AttributeCardinality.MultiValued, values.Select((value, index) => new AttributeValue(index, value, null)).ToArray());
        private static ObjectPermissions Permissions(string dn, IReadOnlyList<PermissionEntry> entries) =>
            new(dn, DescriptorAvailability.Read, null, null, DaclState.Present, DaclCompleteness.Complete, true, false, entries, []);
    }
}
