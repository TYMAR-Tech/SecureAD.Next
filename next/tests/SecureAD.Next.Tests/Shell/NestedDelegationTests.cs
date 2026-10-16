using System.Globalization;
using System.Security.Cryptography;
using Microsoft.Data.Sqlite;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using SecureAD.Kernel;
using SecureAD.Kernel.Capture;
using SecureAD.Kernel.Security;
using SecureAD.Next.Tests.Kernel.Security;
using SecureAD.Shell.Services;
using SecureAD.Shell.ViewModels;
using Xunit;

namespace SecureAD.Next.Tests.Shell;

public sealed class NestedDelegationTests
{
    private const string Alice = "S-1-5-21-1-2-3-1100";
    private const string Helpdesk = "S-1-5-21-1-2-3-2100";
    private const string Operators = "S-1-5-21-1-2-3-2200";
    private const int SecurityGroup = unchecked((int)0x80000002);

    [Fact]
    public async Task SavedMembershipGuidsMustMatchTheCapturedHolderIdentity()
    {
        using var fixture = new Fixture();
        var alice = fixture.Principal("Alice", Alice);
        fixture.Principal("Helpdesk", Helpdesk, groupType: SecurityGroup, members: [alice]);
        fixture.Target("People", [Ace(Helpdesk)]);
        fixture.Open(wrongHolderIdentity: true);

        var read = await fixture.Read(await fixture.Query());

        Assert.False(read.IsSuccess);
        Assert.Contains("does not match", read.Error.Description);
    }

    [Fact]
    public async Task ANewMembershipGenerationRefusesTheOldPageInsteadOfMixingResults()
    {
        using var fixture = new Fixture();
        var alice = fixture.Principal("Alice", Alice);
        fixture.Principal("Helpdesk", Helpdesk, groupType: SecurityGroup, members: [alice]);
        fixture.Target("People", Enumerable.Repeat(Ace(Helpdesk), 102).ToArray());
        fixture.Open();
        var query = await fixture.Query();
        var first = await fixture.Search(query);
        Assert.NotNull(first.Next);
        fixture.DeriveAgain();

        var read = await fixture.Read(query, first.Next);

        Assert.False(read.IsSuccess);
        Assert.Contains("changed", read.Error.Description, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("Failed")]
    [InlineData("DidNotRun")]
    public async Task UnperformedNestingCannotBeReadAsNoContainingGroups(string outcome)
    {
        using var fixture = new Fixture();
        var alice = fixture.Principal("Alice", Alice);
        fixture.Principal("Helpdesk", Helpdesk, groupType: SecurityGroup, members: [alice]);
        fixture.Target("People", [Ace(Helpdesk)]);
        fixture.Open(nestingOutcome: outcome);

        var read = await fixture.Read(await fixture.Query());

        Assert.False(read.IsSuccess);
        Assert.Contains("nesting is unavailable", read.Error.Description);
    }

    [Fact]
    public async Task SidHistoryIsNotSilentlyFollowedAsANestingLink()
    {
        using var fixture = new Fixture();
        const string historical = "S-1-5-21-9-8-7-1100";
        var alice = fixture.Principal("Alice", Alice, history: historical);
        fixture.Principal("Helpdesk", Helpdesk, groupType: SecurityGroup, members: [alice]);
        fixture.Target("People", [Ace(historical), Ace(Helpdesk)]);
        fixture.Open();
        var question = await fixture.Query(historical);

        var grouped = await fixture.Read(question);
        var direct = await fixture.Read(question with { IncludeGroupHeldPermissions = false });

        Assert.False(grouped.IsSuccess);
        Assert.Contains("SID history is not group nesting", grouped.Error.Description);
        Assert.Equal(historical, Assert.Single(direct.Value.Entries).Entry.Trustee.Sid);
    }

    [Fact]
    public async Task OriginalOccurrencesAppearOnceAcrossDiamondRoutesAndCycles()
    {
        using var fixture = new Fixture();
        var alice = fixture.Principal("Alice", Alice);
        var helpdesk = fixture.Principal("Helpdesk", Helpdesk, groupType: SecurityGroup, members: [alice]);
        var alternate = fixture.Principal("Alternate", "S-1-5-21-1-2-3-2101", groupType: SecurityGroup, members: [alice]);
        var operators = fixture.Principal("Operators", Operators, groupType: SecurityGroup, members: [helpdesk, alternate, fixture.Dn("Cycle")]);
        fixture.Principal("Cycle", "S-1-5-21-1-2-3-2300", groupType: SecurityGroup, members: [operators]);
        fixture.Target("People", [Ace(Alice), Ace(Operators), Ace(Operators)]);
        fixture.Open();

        var page = await fixture.Search();

        Assert.Equal([0, 1, 2], page.Entries.Select(entry => entry.Entry.Ordinal));
        Assert.Null(page.Entries[0].HolderMembershipId);
        Assert.NotNull(page.Entries[1].HolderMembershipId);
        Assert.Equal(2, page.Entries.Count(entry => entry.Entry.Trustee.Sid == Operators));
        Assert.Equal(6, page.Membership!.Links.Count);
        Assert.Null(page.Next);
        var row = new DelegationRowViewModel(page.Entries[1], PermissionVocabulary.Shipped, new(page.Membership));
        Assert.Contains("Operators", row.PermissionHeldBy);
        Assert.Contains("Alice", row.Detail);
        Assert.Contains("Helpdesk", row.Detail);
        Assert.Contains("Alternate", row.Detail);
        Assert.Contains("Cycle", row.Detail);
        Assert.Contains("not an effective access check", row.Detail);
    }

    [Fact]
    public async Task PrimaryGroupMembershipIsIncludedAndNamed()
    {
        using var fixture = new Fixture();
        fixture.Principal("Alice", Alice, primaryGroup: 513);
        var primary = fixture.Principal("Primary", "S-1-5-21-1-2-3-513", groupType: SecurityGroup);
        fixture.Principal("Operators", Operators, groupType: SecurityGroup, members: [primary]);
        fixture.Target("People", [Ace(Operators)]);
        fixture.Open();

        var page = await fixture.Search();

        var entry = Assert.Single(page.Entries);
        Assert.Single(page.Membership!.Links, link => link.IsPrimaryGroup);
        var detail = new DelegationRowViewModel(entry, PermissionVocabulary.Shipped, new(page.Membership)).Detail;
        Assert.Contains("primary group", detail);
        Assert.Contains("Primary", detail);
        Assert.Contains("Operators", detail);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task DistributionLinksAreNotPresentedAsSecurityGroupRoutes(bool distributionIsSelected)
    {
        using var fixture = new Fixture();
        var alice = fixture.Principal("Alice", Alice);
        var distribution = fixture.Principal("Distribution", Helpdesk, groupType: 2, members: [alice]);
        fixture.Principal("Operators", Operators, groupType: SecurityGroup, members: [distribution]);
        fixture.Target("People", [Ace(Operators), Ace(Helpdesk)]);
        fixture.Open();
        var query = await fixture.Query(distributionIsSelected ? Helpdesk : Alice);

        var page = await fixture.Search(query);

        Assert.DoesNotContain(page.Entries, entry => entry.Entry.Trustee.Sid == Operators);
        Assert.Equal(distributionIsSelected ? 1 : 0, page.Entries.Count);
        Assert.Contains(page.Membership!.Warnings, warning => warning.Contains("distribution", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task UnknownGroupTypesRemainPossibleWithVisibleQualifications()
    {
        using var fixture = new Fixture();
        var alice = fixture.Principal("Alice", Alice);
        var unknown = fixture.Principal("UnknownGroup", Helpdesk, isGroup: true, members: [alice]);
        fixture.Principal("Operators", Operators, groupType: SecurityGroup, members: [unknown]);
        fixture.Target("People", [Ace(Operators)]);
        fixture.Open();

        var page = await fixture.Search();

        Assert.Single(page.Entries);
        Assert.Contains(page.Membership!.Warnings, warning => warning.Contains("uncertain", StringComparison.Ordinal));
        var detail = new DelegationRowViewModel(page.Entries[0], PermissionVocabulary.Shipped, new(page.Membership)).Detail;
        Assert.Contains("group type not established", detail);
    }

    [Fact]
    public async Task MissingContainingGroupsAndCaptureGapsCannotBecomeACompleteNegative()
    {
        using var fixture = new Fixture();
        fixture.Principal("Alice", Alice, memberOf: ["CN=MissingGroup,DC=uncaptured,DC=example"]);
        fixture.Open(partial: true);

        var page = await fixture.Search();

        Assert.Empty(page.Entries);
        Assert.Contains(page.Membership!.Warnings, warning => warning.Contains("MissingGroup", StringComparison.Ordinal));
        Assert.Contains(page.Membership.Warnings, warning => warning.Contains("did not cover", StringComparison.Ordinal));
        Assert.False(page.Coverage.DeclaredScopeWasRead);
    }

    [Fact]
    public async Task BuiltinPermissionHoldersKeepTheirResourceDomains()
    {
        using var fixture = new Fixture();
        var alice = fixture.Principal("Alice", Alice);
        const string builtin = "S-1-5-32-544";
        fixture.Principal("Administrators", builtin, groupType: SecurityGroup, members: [alice]);
        fixture.Principal("Administrators", builtin, groupType: SecurityGroup, members: [alice], domain: "child.contoso.com");
        fixture.Target("RootResource", [Ace(builtin)]);
        fixture.Target("ChildResource", [Ace(builtin)], "child.contoso.com");
        fixture.Open();

        var page = await fixture.Search();

        Assert.Equal(2, page.Entries.Count);
        Assert.Equal(2, page.Entries.Select(entry => entry.HolderMembershipId).Distinct().Count());
        Assert.All(page.Entries, entry => Assert.Equal(entry.DomainFqdn, entry.Entry.Trustee.DomainFqdn));
    }

    [Fact]
    public async Task PagingCrossesHoldersAndAnEmptyRemainderWithoutDroppingOccurrences()
    {
        using var fixture = new Fixture();
        var alice = fixture.Principal("Alice", Alice);
        fixture.Principal("Helpdesk", Helpdesk, groupType: SecurityGroup, members: [alice]);
        fixture.Principal("Operators", Operators, groupType: SecurityGroup, members: [alice]);
        fixture.Principal("NoPermissions", "S-1-5-21-1-2-3-2400", groupType: SecurityGroup, members: [alice]);
        fixture.Target("People", [.. Enumerable.Repeat(Ace(Alice), 60), .. Enumerable.Repeat(Ace(Helpdesk), 90),
            .. Enumerable.Repeat(Ace(Operators), 50)]);
        fixture.Open();
        var query = await fixture.Query();
        var first = await fixture.Search(query);
        var second = await fixture.Search(query, first.Next);

        Assert.Equal(100, first.Entries.Count);
        Assert.Equal(100, second.Entries.Count);
        Assert.NotNull(first.Next);
        Assert.Null(second.Next);
        Assert.Equal(200, first.Entries.Concat(second.Entries).Select(entry => (entry.ObjectId, entry.Entry.Ordinal)).Distinct().Count());
        Assert.Equal(first.Membership!.GenerationId, first.Next!.MembershipGenerationId);
        Assert.Equal(first.Membership.EvidenceFingerprint, first.Next.EvidenceFingerprint);
    }

    [Theory]
    [InlineData("generation")]
    [InlineData("evidence")]
    [InlineData("holder")]
    [InlineData("question")]
    public async Task AContinuationCannotBorrowAnotherMembershipGenerationOrQuestion(string change)
    {
        using var fixture = new Fixture();
        var alice = fixture.Principal("Alice", Alice);
        fixture.Principal("Helpdesk", Helpdesk, groupType: SecurityGroup, members: [alice]);
        fixture.Target("People", Enumerable.Repeat(Ace(Helpdesk), 102).ToArray());
        fixture.Open();
        var query = await fixture.Query();
        var first = await fixture.Search(query);
        var mark = Assert.IsType<DelegationPageMark>(first.Next);
        mark = change switch
        {
            "generation" => mark with { MembershipGenerationId = Guid.NewGuid() },
            "evidence" => mark with { EvidenceFingerprint = new string('0', 64) },
            "holder" => mark with { HolderMembershipId = int.MaxValue },
            _ => mark with { Query = mark.Query with { IncludeInherited = true } },
        };

        var read = await fixture.Read(query, mark);

        Assert.False(read.IsSuccess);
        Assert.Contains("changed", read.Error.Description, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task MissingMembershipIsRefusedButTheSameCaptureStillSupportsDirectLookup()
    {
        using var fixture = new Fixture();
        fixture.Principal("Alice", Alice);
        fixture.Target("People", [Ace(Alice)]);
        fixture.Open(derive: false);
        var query = await fixture.Query();

        var grouped = await fixture.Read(query);
        var direct = await fixture.Read(query with { IncludeGroupHeldPermissions = false });

        Assert.False(grouped.IsSuccess);
        Assert.Contains("Uncheck Include group-held permissions", grouped.Error.Description);
        Assert.True(direct.IsSuccess);
        Assert.Null(direct.Value.Membership);
        Assert.Single(direct.Value.Entries);
    }

    [Fact]
    public async Task GroupLookupIsReadOnlyAndNeedsNoJudgement()
    {
        using var fixture = new Fixture();
        var alice = fixture.Principal("Alice", Alice);
        fixture.Principal("Helpdesk", Helpdesk, groupType: SecurityGroup, members: [alice]);
        fixture.Target("People", [Ace(Helpdesk)]);
        fixture.Open();
        var before = fixture.Files();

        var page = await fixture.Search();

        Assert.Single(page.Entries);
        Assert.Equal(before, fixture.Files());
        Assert.DoesNotContain(before, file => file.Contains("judgement", StringComparison.OrdinalIgnoreCase));
    }

    private static byte[] Ace(string sid) => SdBytes.AllowAce(Sid.ToBytes(sid)!, 0x100);

    internal sealed class Fixture : IDisposable
    {
        private static readonly DateTimeOffset Started = new(2026, 10, 5, 0, 0, 0, TimeSpan.Zero);
        private readonly string _directory = Path.Combine(Path.GetTempPath(), "nd-" + Guid.NewGuid().ToString("N"));
        private readonly BundleWriter _writer;
        private readonly HashSet<string> _domains = [];
        private readonly BundleAssetSource _source = new();
        internal Fixture() => _writer = BundleWriter.Create(_directory, Started);
        internal string Dn(string name, string domain = "contoso.com") => $"CN={name},DC=" + domain.Replace(".", ",DC=", StringComparison.Ordinal);
        private PartitionCoverage Coverage(string domain)
        {
            var coverage = new PartitionCoverage("DC=" + domain.Replace(".", ",DC=", StringComparison.Ordinal),
                NamingContextKind.Domain, "dc." + domain, ConnectionSecurityLevel.SignedAndSealed, 12, 4200, 3, [], false);
            if (_domains.Add(domain)) _writer.WriteCoverage(coverage);
            return coverage;
        }
        internal string Principal(string name, string sid, int? groupType = null, bool isGroup = false,
            string[]? members = null, string[]? memberOf = null, int? primaryGroup = null, string domain = "contoso.com",
            string? history = null)
        {
            var attributes = new List<EvidenceAttribute>
            {
                Text("objectClass", "top", groupType.HasValue || isGroup ? "group" : "user"),
                Text("sAMAccountName", name),
                new("objectSid", StoredAttributeCompleteness.Complete, [EvidenceValue.OfBytes(Sid.ToBytes(sid)!)]),
            };
            if (groupType is { } type) attributes.Add(Text("groupType", type.ToString(CultureInfo.InvariantCulture)));
            if (members is not null) attributes.Add(Text("member", members));
            if (memberOf is not null) attributes.Add(Text("memberOf", memberOf));
            if (primaryGroup is { } primary) attributes.Add(Text("primaryGroupID", primary.ToString(CultureInfo.InvariantCulture)));
            if (history is not null) attributes.Add(new("sIDHistory", StoredAttributeCompleteness.Complete, [EvidenceValue.OfBytes(Sid.ToBytes(history)!)]));
            var dn = Dn(name, domain);
            _writer.WriteObject(new(Coverage(domain), dn, Guid.NewGuid(), attributes, Started));
            return dn;
        }
        internal void Target(string name, byte[][] aces, string domain = "contoso.com")
        {
            var id = _writer.WriteObject(new(Coverage(domain), Dn(name, domain), Guid.NewGuid(),
                [Text("objectClass", "top", "organizationalUnit")], Started));
            var bytes = SdBytes.SelfRelativeSd(null, null, aces);
            _writer.WriteSecurityDescriptor(id, bytes, AceNormalizer.Normalize(Guid.Empty, SecurityDescriptorParser.Parse(bytes)));
        }
        internal void Open(bool derive = true, bool partial = false, string? nestingOutcome = null, bool wrongHolderIdentity = false)
        {
            _writer.Complete(RunCoverage.Of(CoverageId.ForDomains("contoso.com", _domains),
                _domains.Select(domain => partial ? DomainCoverage.PartiallyRead(domain, "synthetic gap") : DomainCoverage.Read(domain)).ToArray(),
                [ForestPartitionCoverage.Read("CN=Configuration,DC=contoso,DC=com", NamingContextKind.Configuration),
                 ForestPartitionCoverage.Read("CN=Schema,CN=Configuration,DC=contoso,DC=com", NamingContextKind.Schema)],
                SysvolCoverage.Of([])), Started.AddMinutes(1));
            _writer.Dispose();
            if (derive)
            {
                DeriveAgain();
                if (nestingOutcome is not null || wrongHolderIdentity)
                {
                    var generation = AnalysisStoreLifecycle.Resolve(_directory, AnalysisStoreKind.Derivation).Value;
                    var path = BundleLayout.AnalysisSegmentDataPath(_directory, generation, StoreSegmentRole.Membership);
                    using (var connection = new SqliteConnection($"Data Source={path};Pooling=False"))
                    {
                        connection.Open();
                        using var command = connection.CreateCommand();
                        if (wrongHolderIdentity)
                        {
                            command.CommandText = "UPDATE principal SET object_guid=$guid WHERE sid_id=(SELECT sid_id FROM sid WHERE sid=$sid AND scope='')";
                            command.Parameters.AddWithValue("$guid", Guid.NewGuid().ToString("D"));
                            command.Parameters.AddWithValue("$sid", Helpdesk);
                        }
                        else
                        {
                            command.CommandText = "UPDATE derivation_phase SET outcome=$outcome WHERE phase='MembershipAndNesting'";
                            command.Parameters.AddWithValue("$outcome", nestingOutcome!);
                        }
                        Assert.Equal(1, command.ExecuteNonQuery());
                    }
                    TestSealing.ResealAnalysis(_directory, generation);
                }
            }
            _source.SelectRun(_directory);
        }
        internal void DeriveAgain()
        {
            var result = Stage2aRun.Derive(_directory, ExpansionBudget.Bulk, Started.AddMinutes(2),
                Stage2aRun.Unwatched, RunLog.Discarded, CancellationToken.None);
            Assert.True(result.IsSuccess, result.IsSuccess ? "" : result.Error.Description);
        }
        internal async Task<DelegationQuery> Query(string sid = Alice)
        {
            var principals = await _source.ReadAsync(_directory,
                (reader, _) => reader.FindDelegationPrincipals(_directory, sid, null), CancellationToken.None);
            Assert.True(principals.IsSuccess, principals.IsSuccess ? "" : principals.Error.Description);
            return new(Assert.Single(principals.Value.Principals), DelegationPermission.All, false) { IncludeGroupHeldPermissions = true };
        }
        internal Task<Result<DelegationPage>> Read(DelegationQuery query, DelegationPageMark? after = null) =>
            _source.ReadAsync(_directory, (reader, _) => reader.ReadDelegations(_directory, query, after), CancellationToken.None);
        internal async Task<DelegationPage> Search(DelegationQuery? query = null, DelegationPageMark? after = null)
        {
            var result = await Read(query ?? await Query(), after);
            Assert.True(result.IsSuccess, result.IsSuccess ? "" : result.Error.Description);
            return result.Value;
        }
        internal string[] Files() => Directory.GetFiles(_directory, "*", SearchOption.AllDirectories).Order(StringComparer.Ordinal)
            .Select(file => Path.GetRelativePath(_directory, file) + ":" + Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(file)))).ToArray();
        private static EvidenceAttribute Text(string name, params string[] values) =>
            new(name, StoredAttributeCompleteness.Complete, values.Select(EvidenceValue.OfText).ToArray());
        public void Dispose()
        {
            _source.Dispose();
            _writer.Dispose();
            if (Directory.Exists(_directory)) Directory.Delete(_directory, true);
        }
    }
}
