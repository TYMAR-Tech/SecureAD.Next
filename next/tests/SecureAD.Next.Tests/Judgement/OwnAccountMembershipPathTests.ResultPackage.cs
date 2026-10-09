using Microsoft.Data.Sqlite;
using SecureAD.Derivation;
using SecureAD.Judgement;
using Xunit;
using static SecureAD.Next.Tests.Judgement.SelfMembershipDiscoveryTests;

namespace SecureAD.Next.Tests.Judgement;

public sealed partial class OwnAccountMembershipPathTests
{
    [Fact]
    public void ResultPackageStreamsSavedQuestionsAndAnswersWithoutOneQueryPerAnswer()
    {
        using var fixture = PrerequisiteFixtureFor("both-permissions", 83);
        using var trace = new JudgingInputReuseTests.Statements(fixture.Connection);
        using var counts = new PathResultPackageTests.Counts(fixture.Description.GenerationId);
        RewriteRequesterWork(fixture);
        var queries = trace.Sql.ToArray();
        Assert.Single(queries.Where(query => query.Contains("LEFT JOIN path_requester_work w ON w.id=a.id", StringComparison.Ordinal)));
        Assert.DoesNotContain(queries, query => query.StartsWith(
            "SELECT id,family,requester,target,group_dn,permission_kind,question_key,fingerprint FROM path_requester_work WHERE id=", StringComparison.Ordinal));
        Assert.Equal(1L, counts.Indexes);
        var manifest = PathCalculationStorage.Read(fixture.Connection, fixture.Description, CancellationToken.None)!;
        Assert.Equal((665, 1, 498, 166), (manifest.Work.Count, manifest.RequesterCount, manifest.OwnAccountCount, manifest.MembershipDaclCount));
        PathCalculationStorage.RequirePublishable(fixture.Connection, fixture.Description, CancellationToken.None);
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("fingerprint")]
    [InlineData("key")]
    [InlineData("family")]
    [InlineData("requester")]
    [InlineData("target")]
    [InlineData("group")]
    [InlineData("kind")]
    public void JoinedCompletionStillRefusesChangedQuestionsBeforeCommittingAnswers(string changed)
    {
        using var fixture = changed == "kind" ? new PrerequisiteFixture(ObtainedPrepared("nested"), CancellationToken.None)
            : PrerequisiteFixtureFor("both-permissions");
        Assert.Throws<InvalidDataException>(() => RewriteRequesterWork(fixture, phase =>
        {
            if (phase != PathRequesterWorkPhase.WritingProofs) return;
            using var query = fixture.Connection.CreateCommand();
            query.CommandText = "SELECT id,requester,target,group_dn,permission_kind FROM path_requester_work WHERE family='MembershipDacl' ORDER BY id LIMIT 1";
            PathRequesterWorkPlan.Question question;
            using (var row = query.ExecuteReader())
            {
                Assert.True(row.Read());
                question = new(row.GetInt64(0), PathRequesterFamily.MembershipDacl, row.GetString(1), row.GetString(2),
                    row.GetString(3), Enum.Parse<OwnAccountMembershipPermissionKind>(row.GetString(4)));
            }
            var altered = changed switch
            {
                "family" => question with { Family = PathRequesterFamily.OwnAccountMembership, GroupDn = null },
                "requester" => question with { RequesterDn = "CN=NotSelectedRequester,DC=contoso,DC=com" },
                "target" => question with { TargetDn = OtherGroupDn },
                "group" => question with { GroupDn = OtherGroupDn },
                "kind" => question with { PermissionKind = question.PermissionKind == OwnAccountMembershipPermissionKind.SelfMembership
                    ? OwnAccountMembershipPermissionKind.WriteMembers : OwnAccountMembershipPermissionKind.SelfMembership },
                _ => question,
            };
            PathRequesterWorkPlan.Validate(altered);
            var fingerprint = Convert.FromHexString(Tier0PathCalculation.Fingerprint(
                new { Version = 1, fixture.Description.GenerationId, Question = altered }));
            using var corrupt = fixture.Connection.CreateCommand();
            corrupt.CommandText = changed == "missing" ? "DELETE FROM path_requester_work WHERE id=$id"
                : """
                  UPDATE path_requester_work SET family=$family,requester=$requester,target=$target,group_dn=$group,
                      permission_kind=$kind,question_key=$key,fingerprint=$fingerprint WHERE id=$id
                  """;
            corrupt.Parameters.AddWithValue("$id", question.Id);
            if (changed != "missing")
            {
                corrupt.Parameters.AddWithValue("$family", altered.Family.ToString());
                corrupt.Parameters.AddWithValue("$requester", altered.RequesterDn);
                corrupt.Parameters.AddWithValue("$target", altered.TargetDn);
                corrupt.Parameters.AddWithValue("$group", (object?)altered.GroupDn ?? DBNull.Value);
                corrupt.Parameters.AddWithValue("$kind", altered.PermissionKind!.Value.ToString());
                corrupt.Parameters.AddWithValue("$key", changed == "key" ? "invalid-question-key" : altered.Key);
                corrupt.Parameters.AddWithValue("$fingerprint", changed == "fingerprint" ? new byte[32] : fingerprint);
            }
            Assert.Equal(1, corrupt.ExecuteNonQuery());
        }));
        using var check = fixture.Connection.CreateCommand();
        check.CommandText = "SELECT COUNT(*) FROM path_requester_risk";
        Assert.Equal(0L, check.ExecuteScalar());
    }

    [Fact]
    public void PublishedDistancesUseTheRequesterRoutesMatchedAfterEvaluation()
    {
        using var fixture = PrerequisiteFixtureFor("both-permissions",
            coreDescriptor: $"O:SYG:SYD:(A;;WD;;;{TargetSid})");
        RewriteRequesterWork(fixture);
        var node = Tier0PathStorage.ReadNode(fixture.Connection, UserDn, CancellationToken.None)!;
        Assert.True(node.OwnAccountRoute is not null || node.MembershipDaclRoute is not null);
        var distance = Tier0DistanceStorage.ReadObject(fixture.Connection, fixture.Description, UserDn, CancellationToken.None)!;
        Assert.Equal((Tier0DistanceVerdict.SupportedRoute, 2), (distance.Facts.Verdict, distance.Facts.SupportedDistance));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void DistancePublicationConsumesTheUpdatedNodeIndexAndRefusesMissingRows(bool missing)
    {
        using var fixture = PrerequisiteFixtureFor("both-permissions");
        var proofs = PathRequesterRiskStorage.ReadProofs(fixture.Connection, fixture.Description, CancellationToken.None);
        var routes = new PathRequesterRouteIndex();
        routes.AddRequesters(proofs.Requesters, CancellationToken.None, null);
        routes.AddOwnAccounts(proofs.OwnAccounts, CancellationToken.None, null);
        routes.AddMembershipDacls(proofs.MembershipDacls, CancellationToken.None, null);
        var summary = Tier0DistanceStorage.ReadSummary(fixture.Connection, fixture.Description, CancellationToken.None)!;
        var dictionary = new Dictionary<string, Tier0PathNode>(fixture.Nodes, StringComparer.OrdinalIgnoreCase);
        if (missing)
        {
            var original = dictionary[UserDn];
            dictionary.Remove(UserDn);
            dictionary.Add("CN=NotTheRecordedKey,DC=contoso,DC=com", original);
        }
        var nodes = new IndexedNodes(dictionary);
        using var transaction = fixture.Connection.BeginTransaction();
        using var clear = fixture.Connection.CreateCommand();
        clear.Transaction = transaction;
        clear.CommandText = "DELETE FROM tier0_distance; DELETE FROM tier0_distance_product";
        clear.ExecuteNonQuery();
        var recorded = OwnershipAuditStorage.Targets(fixture.Connection);
        if (missing) recorded = recorded.OrderBy(row => row.Identity.DistinguishedName == UserDn ? 0 : 1).ToArray();
        void Write() => Tier0DistanceStorage.Write(fixture.Connection, transaction, fixture.Description, fixture.Inputs,
                summary.CalculationFingerprint, recorded, nodes, routes, null,
                proofs.Requesters.Select(value => value.Assessment.Request.RequesterDn), CancellationToken.None);
        if (missing)
        {
            Assert.Throws<InvalidDataException>(Write);
            using var check = fixture.Connection.CreateCommand();
            check.Transaction = transaction;
            check.CommandText = "SELECT COUNT(*) FROM tier0_distance";
            Assert.Equal(0L, check.ExecuteScalar());
        }
        else Write();
        Assert.Equal(0, nodes.Enumerations);
    }

    private sealed class IndexedNodes(IReadOnlyDictionary<string, Tier0PathNode> nodes) : IReadOnlyDictionary<string, Tier0PathNode>
    {
        internal int Enumerations { get; private set; }
        public int Count => nodes.Count;
        public IEnumerable<string> Keys => nodes.Keys;
        public IEnumerable<Tier0PathNode> Values => nodes.Values;
        public Tier0PathNode this[string key] => nodes[key];
        public bool ContainsKey(string key) => nodes.ContainsKey(key);
        public bool TryGetValue(string key, out Tier0PathNode value) => nodes.TryGetValue(key, out value!);
        public IEnumerator<KeyValuePair<string, Tier0PathNode>> GetEnumerator()
        {
            Enumerations++;
            return nodes.GetEnumerator();
        }
        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();
    }
}
