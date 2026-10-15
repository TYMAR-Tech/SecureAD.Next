using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Next.Tests.Judgement;
using SecureAD.Shell.Services;
using Xunit;
using static SecureAD.Next.Tests.Judgement.SelfMembershipDiscoveryTests;

namespace SecureAD.Next.Tests.Shell;

public sealed partial class OpenedRunResultsTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public void ControlReadbackRefusesCorruptionBeforeReturningSavedAnswers(int list)
    {
        var directory = CreateControlRun();
        var generation = AnalysisStoreLifecycle.Resolve(directory, AnalysisStoreKind.Judgement).Value.GenerationId;
        File.AppendAllText(BundleLayout.AnalysisGenerationDataPath(directory, AnalysisStoreKind.Judgement, generation), "corruption");
        using var source = new BundleAssetSource();

        Assert.Equal("Evidence.ProtectedStoreMismatch", ReadControlList(source, directory, list).Error?.Code);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public void ControlReadbackSharesProtectedFilesAcrossRepeatedLists(int list)
    {
        var directory = CreateControlRun();
        using var counts = new ReadbackCounts(directory);
        using var source = new BundleAssetSource();
        ReadControlList(source, directory, list);
        ReadControlList(source, directory, list);

        Assert.Equal((1L, 1L, 1L, 0L), (counts.EvidenceVerifications, counts.DerivationVerifications,
            counts.JudgementVerifications, counts.AnalyticalReads));
        Assert.Equal((list == 1 ? 0L : 1L, list == 1 ? 1L : 0L, 0L),
            (counts.PermissionProofVerifications, counts.PathProofVerifications, counts.FactsVerifications));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public void ControlReadbackRefusesAClosedRun(int list)
    {
        var directory = CreateControlRun();
        using var source = new BundleAssetSource();
        ReadControlList(source, directory, list);
        source.CloseRun();

        Assert.Equal("Shell.SavedResultsGenerationChanged", ReadControlList(source, directory, list).Error?.Code);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public void ControlReadbackCannotCrossAnUnpublishedAttempt(int list)
    {
        var directory = CreateControlRun();
        using var source = new BundleAssetSource();
        ReadControlList(source, directory, list);
        using var attempt = JudgementWriter.Create(directory, BundleSealing.ReadSeal(BundleLayout.SealPath(directory))!.Hash,
            AnalysisStoreLifecycle.Resolve(directory, AnalysisStoreKind.Derivation).Value.GenerationId, Started, Started);

        Assert.Equal("Shell.SavedResultsUnfinished", ReadControlList(source, directory, list).Error?.Code);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public void ControlReadbackCannotCrossAReplacementGeneration(int list)
    {
        var directory = CreateControlRun();
        using var source = new BundleAssetSource();
        ReadControlList(source, directory, list);
        var result = JudgingRun.JudgeWithMemberAttribution(directory, [], new(100, 100, 1000, TimeSpan.FromMinutes(1)),
            Started, Started, JudgingRun.NobodyIsWatching, RunLog.Discarded, CancellationToken.None);
        Assert.True(result.IsSuccess, result.Error?.Description);

        Assert.Equal("Shell.SavedResultsGenerationChanged", ReadControlList(source, directory, list).Error?.Code);
    }

    [Fact]
    public void ControlReadbackRetainsEverySavedConclusionAndSupport()
    {
        var directory = CreateControlRun();
        using var reader = FullControlStorageTests.Open(directory);
        var expected = JsonSerializer.Serialize(ControlProofVerification.ReadPage(reader, UserDn, null, null, true, 0));
        using var source = new BundleAssetSource();

        var actual = source.ReadControlEdges(directory, UserDn, null, null, true, 0);

        Assert.Equal(expected, JsonSerializer.Serialize(actual.Value));
    }

    [Fact]
    public void ControlReadbackUsesTheSavedFullControlConclusionWithoutReplaying()
    {
        var directory = CreateControlRun();
        // A resealed test-only sentinel distinguishes reading a published answer from deriving it again.
        MutateControlRun(directory, "UPDATE full_control_assessment SET proof=json_set(proof,'$.HasIndependentGrantRoutes',json('true'))");
        using var source = new BundleAssetSource();

        var page = source.ReadControlEdges(directory, UserDn, null, null, true, 0).Value;

        Assert.True(page.FullControlAssessments.Single(value => value.Source.Holder.Sid == TargetSid).HasIndependentGrantRoutes);
    }

    [Fact]
    public void ControlReadbackDoesNotDecodeOffPageFullControlProof()
    {
        var directory = CreateControlRun();
        MutateControlRun(directory, "UPDATE full_control_assessment SET proof='not json'");
        using var source = new BundleAssetSource();

        var page = source.ReadControlEdges(directory, UserDn, null, null, true, long.MaxValue);

        Assert.True(page.IsSuccess, page.Error?.Description);
    }

    [Fact]
    public void ControlReadbackKeepsHolderCountsIndependentOfMemberReads()
    {
        var directory = CreateControlRun();
        using var source = new BundleAssetSource();
        var before = source.ReadControlEdges(directory, UserDn, null, null, true, 0).Value;
        source.ReadMemberAttribution(directory, TargetSid, null, UserDn);
        source.ReadPermissionsThroughMembership(directory, UserSid, null, true, 0);
        var after = source.ReadControlEdges(directory, UserDn, null, null, true, 0).Value;

        Assert.Equal((before.ExpectedCount, before.UnknownCount, before.UnexpectedCount, before.FullControlSupports.Count),
            (after.ExpectedCount, after.UnknownCount, after.UnexpectedCount, after.FullControlSupports.Count));
    }

    [Fact]
    public void ControlReadbackRetainsForwardMembershipEvidence()
    {
        var directory = CreateControlRun();
        using var reader = FullControlStorageTests.Open(directory);
        var expected = JsonSerializer.Serialize(reader.ReadMemberAttribution(TargetSid, null, UserDn));
        using var source = new BundleAssetSource();

        Assert.Equal(expected, JsonSerializer.Serialize(source.ReadMemberAttribution(directory, TargetSid, null, UserDn).Value));
    }

    [Fact]
    public void ControlReadbackRetainsReverseMembershipReferences()
    {
        var directory = CreateControlRun();
        using var reader = FullControlStorageTests.Open(directory);
        var expected = JsonSerializer.Serialize(reader.ReadPermissionsThroughMembership(UserSid, null, true, 0));
        using var source = new BundleAssetSource();

        Assert.Equal(expected, JsonSerializer.Serialize(source.ReadPermissionsThroughMembership(directory, UserSid, null, true, 0).Value));
    }

    [Fact]
    public void ControlReadbackRetainsUnselectedIncompleteMembership()
    {
        var directory = CreateControlRun();
        using var source = new BundleAssetSource();

        var page = source.ReadPermissionsThroughMembership(directory, "S-1-5-21-1-2-3-9999", null, true, 0).Value;

        Assert.False(page.IsComplete);
    }

    [Fact]
    public void ControlReadbackDoesNotDecodeUnselectedMembershipProof()
    {
        var directory = CreateControlRun();
        MutateControlRun(directory, "UPDATE member_attribution_root SET proof=json_set(proof,'$.Holder',json('{}'))");
        using var source = new BundleAssetSource();

        var page = source.ReadPermissionsThroughMembership(directory, "S-1-5-21-1-2-3-9999", null, true, 0);

        Assert.True(page.IsSuccess, page.Error?.Description);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ControlReadbackRejectsSelectedMembershipSourceGenerationMismatch(bool reverse)
    {
        var directory = CreateControlRun();
        MutateControlRun(directory, "UPDATE control_edge SET generation='99999999-9999-9999-9999-999999999999'; UPDATE full_control_assessment SET generation='99999999-9999-9999-9999-999999999999'");
        using var source = new BundleAssetSource();

        var result = ReadControlList(source, directory, reverse ? 3 : 2);

        Assert.False(result.IsSuccess);
    }

    [Fact]
    public void ControlReadbackRetainsSavedSelfMembershipAnswers()
    {
        var directory = Bundle();
        Derive(directory);
        var judged = JudgingRun.Judge(directory, [], [new(UserDn, TargetDn, SelfMembershipOperation.Add, null)], SelfMembershipBudget.Default,
            Started, Started, JudgingRun.NobodyIsWatching, RunLog.Discarded, CancellationToken.None);
        Assert.True(judged.IsSuccess, judged.Error?.Description);
        using var reader = FullControlStorageTests.Open(directory);
        var expected = JsonSerializer.Serialize(Assert.Single(reader.ReadSelfMembershipAssessments(TargetDn, UserDn).Assessments));
        using var source = new BundleAssetSource();

        var read = source.ReadSelfMembershipAssessments(directory, TargetDn, UserDn);

        Assert.Equal(expected, JsonSerializer.Serialize(Assert.Single(read.Value.Assessments)));
    }

    private static string CreateControlRun()
    {
        var directory = Bundle(userDescriptor: $"O:{UserSid}G:SYD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;{TargetSid})",
            members: [UserDn, "CN=Missing,DC=foreign,DC=example"], tier0Route: true);
        using var prepared = MemberAttributionTests.Prepare(directory);
        return directory;
    }

    private static Result<object> ReadControlList(BundleAssetSource source, string directory, int list) => list switch
    {
        0 => Box(source.ReadControlEdges(directory, UserDn, null, null, true, 0)),
        1 => Box(source.ReadSelfMembershipAssessments(directory, TargetDn, UserDn)),
        2 => Box(source.ReadMemberAttribution(directory, TargetSid, null, UserDn)),
        3 => Box(source.ReadPermissionsThroughMembership(directory, UserSid, null, true, 0)),
        _ => throw new ArgumentOutOfRangeException(nameof(list)),
    };

    private static Result<object> Box<T>(Result<T> result) where T : class =>
        result.IsSuccess ? Result<object>.Success(result.Value) : Result<object>.Failure(result.Error);

    private static void MutateControlRun(string directory, string sql) => SelfMembershipCoverageTests.Mutate(directory, connection =>
    {
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        command.ExecuteNonQuery();
    });

    /// <summary>
    /// Restores every shared reading's digest after a deliberate change to its payload.
    /// </summary>
    /// <remarks>
    /// Format 42 stores each distinct reading once under a digest, so a test that plants recorded
    /// wording has to restore the digest or the reader refuses the record and the case proves
    /// nothing about whether the words were read rather than recomputed.
    /// </remarks>
    private static void RepairReadingFingerprints(string directory) => SelfMembershipCoverageTests.Mutate(directory, connection =>
    {
        var payloads = new Dictionary<long, string>();
        using (var read = connection.CreateCommand())
        {
            read.CommandText = "SELECT id,payload FROM permission_classification_reading";
            using var rows = read.ExecuteReader();
            while (rows.Read()) payloads[rows.GetInt64(0)] = rows.GetString(1);
        }

        foreach (var (id, payload) in payloads)
        {
            using var update = connection.CreateCommand();
            update.CommandText = "UPDATE permission_classification_reading SET fingerprint=$fingerprint WHERE id=$id";
            update.Parameters.AddWithValue("$fingerprint", System.Security.Cryptography.SHA256.HashData(
                System.Text.Encoding.UTF8.GetBytes(payload)));
            update.Parameters.AddWithValue("$id", id);
            update.ExecuteNonQuery();
        }

        RebindValues(connection);
    });

    /// <summary>
    /// Rebinds every entry's interpretation to the reading it points at, after that reading has
    /// been rewritten.
    /// </summary>
    /// <remarks>
    /// <b>Needed since <c>P-283</c>, and moved by <c>P-280</c>.</b> The digest of the reading is
    /// folded into the binding that covers a <c>reading_id</c>, so that pointer cannot be repointed
    /// at another valid reading — which is how an allow <c>WRITE_DAC</c> could be made to read as
    /// <i>"A deny entry grants no access"</i>. The consequence here is that restoring the reading's
    /// own digest is not enough to make a deliberately rewritten store readable: the rows bound to
    /// it move too.
    /// <para>
    /// That binding used to sit on each occurrence and now sits on the one row per distinct entry,
    /// because that is where a single wrong association would otherwise reach every occurrence of
    /// the entry at once. So this repairs <c>permission_classification_value</c>, and the
    /// occurrence rows need no repair at all — they carry no fingerprint, and the list fingerprint
    /// over a descriptor covers the entries rather than their interpretations.
    /// </para>
    /// <para>
    /// The new value comes from <c>SharedPermissionStorage.ValueFingerprint</c>, which is the
    /// writer's own key. A repair that computed it here instead could agree with itself and
    /// disagree with the product, and the test above would then be proving nothing.
    /// </para>
    /// </remarks>
    private static void RebindValues(SqliteConnection connection)
    {
        Guid generation;
        using (var read = connection.CreateCommand())
        {
            read.CommandText = "SELECT generation FROM permission_classification_product";
            generation = Guid.Parse((string)read.ExecuteScalar()!);
        }

        var repaired = new List<(long EntryId, byte[] Fingerprint)>();
        using (var command = connection.CreateCommand())
        {
            // The reader's own projection, so the ordinal sits where ReadShared expects it, with
            // the interpretation's own columns appended after it.
            command.CommandText = "SELECT " + SharedPermissionStorage.Projection
                + ",0 AS ordinal,c.entry_id,c.right_count,c.object_schema,c.inherited_schema,r.fingerprint"
                + " FROM permission_classification_value c LEFT JOIN permission_entry p ON p.id=c.entry_id"
                + " LEFT JOIN permission_classification_reading r ON r.id=c.reading_id"
                + SharedPermissionStorage.MeaningJoin;
            const int offset = SharedPermissionStorage.ProjectionColumns + 1;
            using var rows = command.ExecuteReader();
            while (rows.Read())
            {
                var entry = SharedPermissionStorage.ReadShared(rows, generation);
                repaired.Add((rows.GetInt64(offset), SharedPermissionStorage.ValueFingerprint(
                    generation, entry, (byte[])rows.GetValue(offset + 4), rows.GetInt32(offset + 1),
                    rows.IsDBNull(offset + 2) ? null : rows.GetString(offset + 2),
                    rows.IsDBNull(offset + 3) ? null : rows.GetString(offset + 3))));
            }
        }

        foreach (var (entryId, fingerprint) in repaired)
        {
            using var update = connection.CreateCommand();
            update.CommandText = "UPDATE permission_classification_value SET fingerprint=$fingerprint WHERE entry_id=$entry";
            update.Parameters.AddWithValue("$fingerprint", fingerprint);
            update.Parameters.AddWithValue("$entry", entryId);
            update.ExecuteNonQuery();
        }
    }
}
