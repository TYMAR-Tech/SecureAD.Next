using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Kernel.Security;
using Xunit;

namespace SecureAD.Next.Tests.Evidence;

/// <summary>
/// Folding one parallel reader's database into the bundle being assembled.
/// </summary>
/// <remarks>
/// <para>
/// <b>These are the first tests this code has ever had, and the reason it had none is worth
/// stating.</b> <c>BundleMerge</c> was written on 2026-09-13 and could not be exercised: nothing
/// could produce a shard, because the only way to finish a writer was <c>Complete</c>, which writes
/// run-level rows the merge refuses by design. <c>P-195</c> recorded it as blocked. It is unblocked
/// by <c>BundleWriter.CompleteShard</c>, and these run against shards written by the real writer
/// rather than by hand - a merge tested against hand-built tables would be testing the test's idea
/// of the schema.
/// </para>
/// <para>
/// <b>What is actually at stake here.</b> Every keyed table in the schema counts from 1, so two
/// shards each hand out identifier 1 to different things. A merge that got this wrong would attach
/// one domain's access control entries to another domain's principal - a permission reported
/// against the wrong account, in a bundle that looks perfectly healthy. That is the failure the
/// whole shard scheme exists to prevent, and it is what the collapse tests below are really about.
/// </para>
/// </remarks>
public sealed class BundleMergeTests : IDisposable
{
    private readonly string _directory =
        Path.Combine(Path.GetTempPath(), "securead-merge-" + Guid.NewGuid().ToString("N"));

    private static readonly DateTimeOffset Started = new(2026, 9, 13, 9, 0, 0, TimeSpan.Zero);

    private static readonly Guid AliceGuid = Guid.Parse("11111111-2222-3333-4444-555555555555");

    // ---------------------------------------------------------------------------------------
    // A shard is not a bundle
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void AShardIsWrittenToItsOwnFile()
    {
        using (var writer = BundleWriter.Create(_directory, Started, BundleShard.Number(1)))
            writer.WriteCoverage(SomeCoverage("DC=contoso,DC=com"));

        Assert.True(File.Exists(BundleLayout.ShardPath(_directory, BundleShard.Number(1))));
    }

    /// <summary>
    /// Two shards never share a file. Sharing it would be the identifier collision arriving one
    /// layer earlier: nine writers queueing for the single write lock SQLite hands out.
    /// </summary>
    [Fact]
    public void TwoShardsWriteToDifferentFiles()
    {
        using (var first = BundleWriter.Create(_directory, Started, BundleShard.Number(1)))
            first.WriteCoverage(SomeCoverage("DC=contoso,DC=com"));

        using (var second = BundleWriter.Create(_directory, Started, BundleShard.Number(2)))
            second.WriteCoverage(SomeCoverage("DC=fabrikam,DC=com"));

        Assert.True(File.Exists(BundleLayout.ShardPath(_directory, BundleShard.Number(1))));
        Assert.True(File.Exists(BundleLayout.ShardPath(_directory, BundleShard.Number(2))));
    }

    [Fact]
    public void AnUnshardedRunStillWritesThePartialFile()
    {
        using (var writer = BundleWriter.Create(_directory, Started))
            writer.WriteCoverage(SomeCoverage("DC=contoso,DC=com"));

        Assert.True(File.Exists(BundleLayout.PartialPath(_directory)));
    }

    /// <summary>
    /// A shard is never sealed and never gets the name a reader asks for, because it is scaffolding
    /// that is deleted once its rows are in the bundle.
    /// </summary>
    [Fact]
    public void FinishingAShardLeavesNoEvidenceFile()
    {
        WriteShard(1, w => w.WriteCoverage(SomeCoverage("DC=contoso,DC=com")));

        Assert.False(File.Exists(BundleLayout.EvidencePath(_directory)));
        Assert.False(File.Exists(BundleLayout.SealPath(_directory)));
    }

    [Fact]
    public void FinishingAShardLeavesItsOwnFile()
    {
        WriteShard(1, w => w.WriteCoverage(SomeCoverage("DC=contoso,DC=com")));

        var shard = BundleLayout.ShardPath(_directory, BundleShard.Number(1));

        Assert.True(new FileInfo(shard).Length > 0);
    }

    /// <summary>
    /// The write-ahead log is folded back in, so the merge opens one self-contained file rather
    /// than depending on a sidecar being found beside it.
    /// </summary>
    [Fact]
    public void FinishingAShardFoldsInTheWriteAheadLog()
    {
        WriteShard(1, w => w.WriteCoverage(SomeCoverage("DC=contoso,DC=com")));

        var shard = BundleLayout.ShardPath(_directory, BundleShard.Number(1));

        Assert.False(File.Exists(shard + "-wal"));
    }

    [Fact]
    public void TheWholeBundleCannotBeFinishedAsAShard()
    {
        using var writer = BundleWriter.Create(_directory, Started);

        var error = Assert.Throws<InvalidOperationException>(() => writer.CompleteShard());

        Assert.Contains("not a shard of one", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void TheWholeBundleHasNoShardFile()
    {
        Assert.Throws<ArgumentOutOfRangeException>(
            () => BundleLayout.ShardPath(_directory, BundleShard.Whole));
    }

    // ---------------------------------------------------------------------------------------
    // What a shard contributes
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void AShardsObjectsArriveInTheBundle()
    {
        WriteShard(1, w =>
        {
            var coverage = w.WriteCoverage(SomeCoverage("DC=contoso,DC=com"));
            w.WriteObject(ObjectAt(coverage, "CN=Alice,DC=contoso,DC=com", AliceGuid));
        });

        using var bundle = OpenBundle();
        Absorb(bundle, 1);

        Assert.Equal(1, ScalarLong(bundle, "SELECT COUNT(*) FROM captured_object"));
    }

    [Fact]
    public void TwoShardsObjectsBothArrive()
    {
        WriteShard(1, w =>
        {
            var coverage = w.WriteCoverage(SomeCoverage("DC=contoso,DC=com"));
            w.WriteObject(ObjectAt(coverage, "CN=Alice,DC=contoso,DC=com", GuidNumbered(1)));
        });

        WriteShard(2, w =>
        {
            var coverage = w.WriteCoverage(SomeCoverage("DC=fabrikam,DC=com"));
            w.WriteObject(ObjectAt(coverage, "CN=Bob,DC=fabrikam,DC=com", GuidNumbered(2)));
        });

        using var bundle = OpenBundle();
        Absorb(bundle, 1);
        Absorb(bundle, 2);

        Assert.Equal(2, ScalarLong(bundle, "SELECT COUNT(*) FROM captured_object"));
    }

    /// <summary>
    /// The identifiers stay disjoint through the merge, which is the property the whole scheme
    /// rests on.
    /// </summary>
    [Fact]
    public void TwoShardsObjectsKeepDistinctIdentifiers()
    {
        WriteShard(1, w =>
        {
            var coverage = w.WriteCoverage(SomeCoverage("DC=contoso,DC=com"));
            w.WriteObject(ObjectAt(coverage, "CN=Alice,DC=contoso,DC=com", GuidNumbered(1)));
        });

        WriteShard(2, w =>
        {
            var coverage = w.WriteCoverage(SomeCoverage("DC=fabrikam,DC=com"));
            w.WriteObject(ObjectAt(coverage, "CN=Bob,DC=fabrikam,DC=com", GuidNumbered(2)));
        });

        using var bundle = OpenBundle();
        Absorb(bundle, 1);
        Absorb(bundle, 2);

        Assert.Equal(
            2, ScalarLong(bundle, "SELECT COUNT(DISTINCT object_id) FROM captured_object"));
    }

    // ---------------------------------------------------------------------------------------
    // Trustees: the same principal in two domains is one row
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// A trustee is genuinely shared between domains - Domain Admins appears in every shard that
    /// saw an entry granting it something - so the merge matches on the SID and keeps one row.
    /// </summary>
    [Fact]
    public void OneSidSeenByTwoShardsBecomesOneTrustee()
    {
        WriteShardGranting(1, "DC=contoso,DC=com", GuidNumbered(1), "S-1-5-32-544");
        WriteShardGranting(2, "DC=fabrikam,DC=com", GuidNumbered(2), "S-1-5-32-544");

        using var bundle = OpenBundle();
        Absorb(bundle, 1);
        Absorb(bundle, 2);

        Assert.Equal(1, ScalarLong(bundle, "SELECT COUNT(*) FROM trustee"));
    }

    /// <summary>
    /// The negative control, and the one that matters most. If the collapse above were happening
    /// for the wrong reason - collapsing everything rather than matching SIDs - this would also
    /// return one, and the bundle would be attributing two domains' permissions to one account.
    /// </summary>
    [Fact]
    public void TwoDifferentSidsStayTwoTrustees()
    {
        WriteShardGranting(1, "DC=contoso,DC=com", GuidNumbered(1), "S-1-5-21-1-1");
        WriteShardGranting(2, "DC=fabrikam,DC=com", GuidNumbered(2), "S-1-5-21-2-2");

        using var bundle = OpenBundle();
        Absorb(bundle, 1);
        Absorb(bundle, 2);

        Assert.Equal(2, ScalarLong(bundle, "SELECT COUNT(*) FROM trustee"));
    }

    /// <summary>
    /// Collapsing two trustees into one must not lose either shard's entries.
    /// </summary>
    /// <remarks>
    /// <b>The two shards grant the same principal different access, and that detail is the test.</b>
    /// Granting identical access would produce byte-identical descriptors, which correctly collapse
    /// to a single descriptor carrying a single entry - so the assertion would be measuring
    /// deduplication rather than the trustee remap, and
    /// <see cref="ASharedDescriptorKeepsExactlyOneSetOfEntries"/> already covers that. Differing
    /// masks keep the descriptors distinct while the SID stays shared, which isolates the one thing
    /// under test: both shards' entries survive, and both point at the surviving trustee.
    /// </remarks>
    [Fact]
    public void CollapsingATrusteeKeepsBothShardsEntries()
    {
        WriteShardGranting(1, "DC=contoso,DC=com", GuidNumbered(1), "S-1-5-32-544", mask: 0x20000);
        WriteShardGranting(2, "DC=fabrikam,DC=com", GuidNumbered(2), "S-1-5-32-544", mask: 0x40000);

        using var bundle = OpenBundle();
        Absorb(bundle, 1);
        Absorb(bundle, 2);

        Assert.Equal(
            2,
            ScalarLong(
                bundle,
                """
                SELECT COUNT(*) FROM ace
                JOIN trustee ON trustee.trustee_id = ace.trustee_id
                WHERE trustee.sid = 'S-1-5-32-544'
                """));
    }

    /// <summary>
    /// Both of those entries point at the one surviving trustee row, rather than one of them
    /// pointing at an identifier the merge left behind.
    /// </summary>
    [Fact]
    public void CollapsingATrusteePointsBothShardsEntriesAtOneRow()
    {
        WriteShardGranting(1, "DC=contoso,DC=com", GuidNumbered(1), "S-1-5-32-544", mask: 0x20000);
        WriteShardGranting(2, "DC=fabrikam,DC=com", GuidNumbered(2), "S-1-5-32-544", mask: 0x40000);

        using var bundle = OpenBundle();
        Absorb(bundle, 1);
        Absorb(bundle, 2);

        Assert.Equal(1, ScalarLong(bundle, "SELECT COUNT(DISTINCT trustee_id) FROM ace"));
    }

    /// <summary>
    /// Every entry points at a trustee that exists. A remap that missed a row would leave an entry
    /// pointing at an identifier from the shard's own numbering, which after the merge belongs to
    /// nobody - or worse, to somebody else.
    /// </summary>
    [Fact]
    public void EveryEntryPointsAtATrusteeThatExists()
    {
        WriteShardGranting(1, "DC=contoso,DC=com", GuidNumbered(1), "S-1-5-32-544");
        WriteShardGranting(2, "DC=fabrikam,DC=com", GuidNumbered(2), "S-1-5-21-2-2");

        using var bundle = OpenBundle();
        Absorb(bundle, 1);
        Absorb(bundle, 2);

        Assert.Equal(
            0,
            ScalarLong(
                bundle,
                """
                SELECT COUNT(*) FROM ace
                WHERE trustee_id NOT IN (SELECT trustee_id FROM trustee)
                """));
    }

    // ---------------------------------------------------------------------------------------
    // Descriptors: identical bytes in two domains are one row
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// Two objects in different domains can carry byte-identical descriptors, and the bundle stores
    /// one copy. The merge matches on the hash for the same reason the writer does.
    /// </summary>
    [Fact]
    public void AnIdenticalDescriptorSeenByTwoShardsBecomesOneRow()
    {
        WriteShardGranting(1, "DC=contoso,DC=com", GuidNumbered(1), "S-1-5-32-544");
        WriteShardGranting(2, "DC=fabrikam,DC=com", GuidNumbered(2), "S-1-5-32-544");

        using var bundle = OpenBundle();
        Absorb(bundle, 1);
        Absorb(bundle, 2);

        Assert.Equal(1, ScalarLong(bundle, "SELECT COUNT(*) FROM security_descriptor"));
    }

    [Fact]
    public void TwoDifferentDescriptorsStayTwoRows()
    {
        WriteShardGranting(1, "DC=contoso,DC=com", GuidNumbered(1), "S-1-5-21-1-1");
        WriteShardGranting(2, "DC=fabrikam,DC=com", GuidNumbered(2), "S-1-5-21-2-2");

        using var bundle = OpenBundle();
        Absorb(bundle, 1);
        Absorb(bundle, 2);

        Assert.Equal(2, ScalarLong(bundle, "SELECT COUNT(*) FROM security_descriptor"));
    }

    /// <summary>
    /// A descriptor already in the bundle brings no entries with it, and must not.
    /// </summary>
    /// <remarks>
    /// <c>ace</c> is unique on (descriptor, ordinal), so copying the second shard's entries for a
    /// descriptor that is already present would violate that constraint - and equal hashes mean
    /// equal bytes mean the same entries, so there is nothing to add. This asserts the count rather
    /// than merely that the merge did not throw, because a merge that skipped the entries for the
    /// wrong reason would pass a does-not-throw test.
    /// </remarks>
    [Fact]
    public void ASharedDescriptorKeepsExactlyOneSetOfEntries()
    {
        WriteShardGranting(1, "DC=contoso,DC=com", GuidNumbered(1), "S-1-5-32-544");
        WriteShardGranting(2, "DC=fabrikam,DC=com", GuidNumbered(2), "S-1-5-32-544");

        using var bundle = OpenBundle();
        Absorb(bundle, 1);
        Absorb(bundle, 2);

        Assert.Equal(1, ScalarLong(bundle, "SELECT COUNT(*) FROM ace"));
    }

    /// <summary>
    /// Both objects still reach the descriptor they were captured with, even though only one copy
    /// of it is stored. Deduplication that lost an object's link would report an object as having
    /// no descriptor - which the schema reads as "nobody knows", not "grants nothing".
    /// </summary>
    [Fact]
    public void BothObjectsStillReachTheSharedDescriptor()
    {
        WriteShardGranting(1, "DC=contoso,DC=com", GuidNumbered(1), "S-1-5-32-544");
        WriteShardGranting(2, "DC=fabrikam,DC=com", GuidNumbered(2), "S-1-5-32-544");

        using var bundle = OpenBundle();
        Absorb(bundle, 1);
        Absorb(bundle, 2);

        Assert.Equal(2, ScalarLong(bundle, "SELECT COUNT(*) FROM object_security_descriptor"));
    }

    [Fact]
    public void EveryObjectDescriptorLinkPointsAtADescriptorThatExists()
    {
        WriteShardGranting(1, "DC=contoso,DC=com", GuidNumbered(1), "S-1-5-32-544");
        WriteShardGranting(2, "DC=fabrikam,DC=com", GuidNumbered(2), "S-1-5-21-2-2");

        using var bundle = OpenBundle();
        Absorb(bundle, 1);
        Absorb(bundle, 2);

        Assert.Equal(
            0,
            ScalarLong(
                bundle,
                """
                SELECT COUNT(*) FROM object_security_descriptor
                WHERE descriptor_id NOT IN (SELECT descriptor_id FROM security_descriptor)
                """));
    }

    // ---------------------------------------------------------------------------------------
    // What the merge refuses
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// A shard carrying run-level rows is refused. Nine shards each with their own account of one
    /// run would give the merged bundle nine contradictory answers about what the run covered.
    /// </summary>
    [Fact]
    public void AShardCarryingRunLevelRowsIsRefused()
    {
        WriteShard(1, w => w.WriteCoverage(SomeCoverage("DC=contoso,DC=com")));

        var shardPath = BundleLayout.ShardPath(_directory, BundleShard.Number(1));

        using (var shard = OpenForWriting(shardPath))
        {
            using var command = shard.CreateCommand();
            command.CommandText =
                "INSERT INTO domain_coverage (domain_fqdn, outcome, reason) "
                + "VALUES ('contoso.com', 'Read', NULL)";
            command.ExecuteNonQuery();
        }

        using var bundle = OpenBundle();

        var error = Assert.Throws<InvalidOperationException>(() => Absorb(bundle, 1));

        Assert.Contains("domain_coverage", error.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// A shard whose rows carry another shard's identifiers has already gone wrong, and the merge
    /// is the last moment that is still a crash rather than a wrong answer.
    /// </summary>
    [Fact]
    public void AShardCarryingAnotherShardsIdentifiersIsRefused()
    {
        WriteShard(1, w =>
        {
            var coverage = w.WriteCoverage(SomeCoverage("DC=contoso,DC=com"));
            w.WriteObject(ObjectAt(coverage, "CN=Alice,DC=contoso,DC=com", GuidNumbered(1)));
        });

        using var bundle = OpenBundle();

        // Read as though it were shard 2, which owns a different range entirely.
        Assert.Throws<InvalidOperationException>(
            () => BundleMerge.Absorb(
                bundle,
                BundleLayout.ShardPath(_directory, BundleShard.Number(1)),
                BundleShard.Number(2)));
    }

    [Fact]
    public void AMissingShardIsRefused()
    {
        using var bundle = OpenBundle();

        Assert.Throws<FileNotFoundException>(
            () => BundleMerge.Absorb(
                bundle,
                Path.Combine(_directory, "evidence.shard-7.db.partial"),
                BundleShard.Number(7)));
    }

    // ---------------------------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------------------------

    /// <summary>Writes one shard and finishes it, so the merge has something real to read.</summary>
    private void WriteShard(int index, Action<BundleWriter> write)
    {
        using var writer = BundleWriter.Create(_directory, Started, BundleShard.Number(index));
        write(writer);
        writer.CompleteShard();
    }

    /// <summary>
    /// A shard holding one object whose descriptor grants <paramref name="sid"/> something.
    /// </summary>
    /// <remarks>
    /// The descriptor's bytes are derived from what it parsed to, so two shards granting the same
    /// SID the same access produce byte-identical descriptors, and granting different access does
    /// not - which is the distinction the deduplication and remap tests here rest on.
    /// </remarks>
    private void WriteShardGranting(
        int index, string namingContext, Guid objectGuid, string sid, int mask = 0x20000) =>
        WriteShard(index, w =>
        {
            var coverage = w.WriteCoverage(SomeCoverage(namingContext));
            var objectId = w.WriteObject(ObjectAt(coverage, $"CN=x,{namingContext}", objectGuid));

            var descriptor = new AceNormalizationResult(
                objectGuid,
                "S-1-5-21-1",
                "S-1-5-21-2",
                DaclState.Present,
                false,
                [Ace(objectGuid, sid, mask)],
                [],
                DaclCompleteness.Complete,
                true);

            w.WriteSecurityDescriptor(objectId, DescriptorBytes(descriptor), descriptor);
        });

    private static CanonicalAce Ace(Guid objectGuid, string trustee, int mask) => new(
        objectGuid,
        AceType.AccessAllowed, trustee, mask, null, null, false, 0, 0,
        $"hash-{trustee}-{mask}", AceCanonicalization.Version);

    /// <summary>
    /// Stand-in raw bytes derived from what the descriptor parsed to, so that identical content
    /// hashes identically and different content does not - the property deduplication turns on.
    /// </summary>
    private static byte[] DescriptorBytes(AceNormalizationResult descriptor) =>
        System.Text.Encoding.UTF8.GetBytes(string.Join(
            "|",
            descriptor.OwnerSid,
            descriptor.GroupSid,
            descriptor.DaclState,
            descriptor.IsDaclProtected,
            string.Join(",", descriptor.Aces.Select(a => a.AceHash)),
            string.Join(",", descriptor.Errors)));

    /// <summary>
    /// The bundle the shards are merged into: a writer's own database, opened directly.
    /// </summary>
    /// <remarks>
    /// The real run driver will merge into the writer it is already holding. These tests open the
    /// file instead, because what is under test is the merge rather than the run driver, and
    /// building the destination through the writer keeps the schema honest - a hand-built
    /// destination would be testing the test's idea of the schema.
    /// </remarks>
    private SqliteConnection OpenBundle()
    {
        var path = Path.Combine(_directory, "destination.db");

        if (!File.Exists(path))
        {
            using var writer = BundleWriter.Create(
                Path.Combine(_directory, "seed"), Started, BundleShard.Number(9));
            writer.CompleteShard();

            File.Move(BundleLayout.ShardPath(Path.Combine(_directory, "seed"), BundleShard.Number(9)), path);
        }

        return OpenForWriting(path);
    }

    private void Absorb(SqliteConnection bundle, int index) =>
        BundleMerge.Absorb(
            bundle,
            BundleLayout.ShardPath(_directory, BundleShard.Number(index)),
            BundleShard.Number(index));

    private static PartitionCoverage SomeCoverage(string namingContextDn) => new(
        namingContextDn,
        NamingContextKind.Domain,
        "dc01.contoso.com",
        ConnectionSecurityLevel.SignedAndSealed,
        12,
        4200,
        3,
        [],
        false);

    private static EvidenceObject ObjectAt(long coverageId, string dn, Guid guid) =>
        new(SomeCoverage(DomainOf(dn)), dn, guid, [TextAttribute("cn", "x")], Started);

    private static string DomainOf(string dn) =>
        dn[(dn.IndexOf("DC=", StringComparison.Ordinal))..];

    private static EvidenceAttribute TextAttribute(string name, string value) =>
        new(name, StoredAttributeCompleteness.Complete, [EvidenceValue.OfText(value)]);

    private static Guid GuidNumbered(int n) =>
        Guid.Parse($"00000000-0000-0000-0000-{n:D12}");

    private static SqliteConnection OpenForWriting(string path)
    {
        var connection = new SqliteConnection(
            new SqliteConnectionStringBuilder
            {
                DataSource = path,
                Mode = SqliteOpenMode.ReadWrite,
                Pooling = false,
                ForeignKeys = true,
            }.ToString());

        connection.Open();
        return connection;
    }

    private static long ScalarLong(SqliteConnection connection, string sql)
    {
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        return Convert.ToInt64(command.ExecuteScalar());
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();

        if (Directory.Exists(_directory))
            Directory.Delete(_directory, recursive: true);
    }
}
