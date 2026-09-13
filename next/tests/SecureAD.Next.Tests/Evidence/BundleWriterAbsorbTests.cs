using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using SecureAD.Kernel.Naming;
using SecureAD.Kernel.Security;
using Xunit;

namespace SecureAD.Next.Tests.Evidence;

/// <summary>
/// Folding a shard into the writer that is still assembling the bundle, which is what the run
/// driver does and what <c>BundleMergeTests</c> deliberately does not.
/// </summary>
/// <remarks>
/// <para>
/// <b>The merge itself is tested elsewhere; what is held here is everything around it.</b>
/// <c>BundleMergeTests</c> merges into a plain connection, because what is under test there is the
/// remapping of trustees and descriptors. The real run merges into a live
/// <see cref="BundleWriter"/> and then <i>keeps writing</i> - SYSVOL is read after the directory,
/// per <c>docs/decisions/0044</c>, through that same writer. That ordering is the whole reason
/// this class exists.
/// </para>
/// <para>
/// <b>The failure it holds is not one a reader would guess from the merge.</b>
/// <see cref="BundleWriter"/> keeps trustees by SID and descriptors by hash in memory so that a
/// repeated principal costs a dictionary lookup rather than a query. Rows the merge brings in are
/// not in those caches. A policy folder on SYSVOL granting <c>BUILTIN\Administrators</c> - which is
/// every policy folder - would then try to insert a SID a domain shard had already placed, against
/// <c>UNIQUE(sid)</c>. It fails loudly rather than silently, which is the only thing to be said for
/// it, and it would fail on every real forest at the end of a capture that had already run for
/// hours.
/// </para>
/// </remarks>
public sealed class BundleWriterAbsorbTests : IDisposable
{
    private readonly string _directory =
        Path.Combine(Path.GetTempPath(), "securead-absorb-" + Guid.NewGuid().ToString("N"));

    private static readonly DateTimeOffset Started =
        new(2026, 9, 13, 11, 0, 0, TimeSpan.Zero);

    private static readonly DateTimeOffset Finished =
        new(2026, 9, 13, 12, 0, 0, TimeSpan.Zero);

    /// <summary>
    /// <c>BUILTIN\Administrators</c>. Named rather than invented because it is the principal that
    /// makes this failure certain rather than possible: it is on the access control list of every
    /// policy folder and of most of the directory.
    /// </summary>
    private const string Administrators = "S-1-5-32-544";

    private const string Domain = "DC=contoso,DC=com";

    private static readonly Guid PolicyGuid =
        Guid.Parse("31b2f340-016d-11d2-945f-00c04fb984f9");

    // ---------------------------------------------------------------------------------------
    // Writing on after a merge
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// A principal a merged domain already named can be named again by SYSVOL, and is one row.
    /// </summary>
    /// <remarks>
    /// The fire test for the trustee cache. Without the refresh in
    /// <see cref="BundleWriter.Absorb"/> this throws on <c>UNIQUE(sid)</c>.
    /// </remarks>
    [Fact]
    public void SysvolMayNameAPrincipalAMergedDomainAlreadyNamed()
    {
        Seal(bundle =>
        {
            WriteShardGranting(1, Administrators, mask: 0x20000);
            bundle.Absorb(ShardPath(1), BundleShard.Number(1));

            bundle.WriteSysvolSecurityDescriptor(
                PolicyGuid, string.Empty, Bytes("sysvol"), Granting(Administrators, 0x1F01FF));
        });

        Assert.Equal(1, Scalar($"SELECT COUNT(*) FROM trustee WHERE sid = '{Administrators}'"));
    }

    /// <summary>
    /// A descriptor a merged domain already held is recognised rather than stored a second time.
    /// </summary>
    /// <remarks>
    /// The fire test for the descriptor cache, which is the other half of the same staleness. Two
    /// rows for one hash are refused by <c>UNIQUE(sha256)</c>, so without the refresh this throws.
    /// </remarks>
    [Fact]
    public void SysvolMayCarryADescriptorAMergedDomainAlreadyHeld()
    {
        Seal(bundle =>
        {
            var shared = Granting(Administrators, 0x1F01FF);

            WriteShard(1, w =>
            {
                var coverage = w.WriteCoverage(DomainCoverageOf(Domain));
                var objectId = w.WriteObject(ObjectAt(Domain, $"CN=x,{Domain}"));

                w.WriteSecurityDescriptor(objectId, Bytes("shared"), shared);
            });

            bundle.Absorb(ShardPath(1), BundleShard.Number(1));

            bundle.WriteSysvolSecurityDescriptor(PolicyGuid, string.Empty, Bytes("shared"), shared);
        });

        Assert.Equal(1, Scalar("SELECT COUNT(*) FROM security_descriptor"));
    }

    /// <summary>
    /// The rows the shard carried really are in the bundle.
    /// </summary>
    /// <remarks>
    /// The negative control for the two above. Without it they would also pass against an
    /// <see cref="BundleWriter.Absorb"/> that quietly did nothing - which is the one state in which
    /// no cache could ever go stale, and in which a domain would vanish from the evidence.
    /// </remarks>
    [Fact]
    public void AnAbsorbedShardsObjectsAreInTheBundle()
    {
        Seal(bundle =>
        {
            WriteShardGranting(1, Administrators, mask: 0x20000);
            bundle.Absorb(ShardPath(1), BundleShard.Number(1));
        });

        Assert.Equal(1, Scalar("SELECT COUNT(*) FROM captured_object"));
    }

    /// <summary>
    /// The bundle is still being written after a merge, rather than left with its transaction
    /// closed behind it.
    /// </summary>
    /// <remarks>
    /// <see cref="BundleWriter.Absorb"/> has to commit, because SQLite refuses <c>ATTACH</c> inside
    /// a transaction. What follows the merge has to land in a transaction of its own, and under the
    /// fan-out what follows is every remaining shard and the whole of SYSVOL.
    /// </remarks>
    [Fact]
    public void TheBundleIsStillWritableAfterAMerge()
    {
        Seal(bundle =>
        {
            WriteShardGranting(1, Administrators, mask: 0x20000);
            bundle.Absorb(ShardPath(1), BundleShard.Number(1));

            bundle.WriteCoverage(ConfigurationCoverage());
            bundle.WriteObject(
                ObjectAt(
                    "CN=Configuration,DC=contoso,DC=com",
                    "CN=y,CN=Configuration,DC=contoso,DC=com"));
        });

        Assert.Equal(2, Scalar("SELECT COUNT(*) FROM captured_object"));
    }

    // ---------------------------------------------------------------------------------------
    // What is refused
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// A shard cannot absorb another shard.
    /// </summary>
    /// <remarks>
    /// It would carry both domains' rows into the merge that later folds it in, and the second
    /// domain would be counted twice.
    /// </remarks>
    [Fact]
    public void AShardCannotAbsorbAnotherShard()
    {
        using var shard = BundleWriter.Create(_directory, Started, BundleShard.Number(5));

        WriteShardGranting(1, Administrators, mask: 0x20000);

        var refusal = Assert.Throws<InvalidOperationException>(
            () => shard.Absorb(ShardPath(1), BundleShard.Number(1)));

        Assert.Contains(
            "not the bundle being assembled", refusal.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// A merge is refused while a partition attempt is open.
    /// </summary>
    /// <remarks>
    /// The merge commits, and a commit puts the open attempt's rows beyond the reach of the
    /// savepoint that exists to discard them - so a restart of that partition would leave a partial
    /// read in the bundle, which <c>docs/decisions/0040</c> forbids.
    /// </remarks>
    [Fact]
    public void AMergeIsRefusedWhileAPartitionIsOpen()
    {
        using var bundle = BundleWriter.Create(_directory, Started);

        WriteShardGranting(1, Administrators, mask: 0x20000);

        bundle.BeginPartition(
            "DC=fabrikam,DC=com",
            NamingContextKind.Domain,
            "dc01.fabrikam.com",
            ConnectionSecurityLevel.SignedAndSealed);

        var refusal = Assert.Throws<InvalidOperationException>(
            () => bundle.Absorb(ShardPath(1), BundleShard.Number(1)));

        Assert.Contains("partition attempt is open", refusal.Message, StringComparison.Ordinal);
    }

    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// Runs <paramref name="write"/> against a bundle and seals it, so the assertions read finished
    /// evidence rather than a writer's own uncommitted view of itself.
    /// </summary>
    private void Seal(Action<BundleWriter> write)
    {
        using var bundle = BundleWriter.Create(_directory, Started);

        write(bundle);

        bundle.Complete(OneDomainRead(), Finished);
    }

    private string ShardPath(int index) =>
        BundleLayout.ShardPath(_directory, BundleShard.Number(index));

    private void WriteShard(int index, Action<BundleWriter> write)
    {
        using var writer = BundleWriter.Create(_directory, Started, BundleShard.Number(index));
        write(writer);
        writer.CompleteShard();
    }

    private void WriteShardGranting(int index, string sid, int mask) =>
        WriteShard(index, w =>
        {
            var coverage = w.WriteCoverage(DomainCoverageOf(Domain));
            var objectId = w.WriteObject(ObjectAt(Domain, $"CN=x,{Domain}"));

            w.WriteSecurityDescriptor(objectId, Bytes(Domain), Granting(sid, mask));
        });

    private static AceNormalizationResult Granting(string sid, int mask) =>
        new(
            Guid.Empty,
            "S-1-5-21-1",
            "S-1-5-21-2",
            DaclState.Present,
            false,
            [
                new CanonicalAce(
                    Guid.Empty,
                    AceType.AccessAllowed,
                    sid,
                    mask,
                    null,
                    null,
                    false,
                    0,
                    0,
                    $"hash-{sid}-{mask}",
                    AceCanonicalization.Version),
            ],
            [],
            DaclCompleteness.Complete,
            true);

    private static byte[] Bytes(string seed) => System.Text.Encoding.UTF8.GetBytes(seed);

    private static PartitionCoverage DomainCoverageOf(string namingContextDn) => new(
        namingContextDn,
        NamingContextKind.Domain,
        "dc01.contoso.com",
        ConnectionSecurityLevel.SignedAndSealed,
        PagesRead: 1,
        ObjectsRead: 1,
        AttributeBlocksFetched: 0,
        ContinuationReferences: [],
        ReferralsSuppressed: false);

    private static PartitionCoverage ConfigurationCoverage() => new(
        "CN=Configuration,DC=contoso,DC=com",
        NamingContextKind.Configuration,
        "dc01.contoso.com",
        ConnectionSecurityLevel.SignedAndSealed,
        PagesRead: 1,
        ObjectsRead: 1,
        AttributeBlocksFetched: 0,
        ContinuationReferences: [],
        ReferralsSuppressed: false);

    private static EvidenceObject ObjectAt(string namingContextDn, string dn) =>
        new(
            namingContextDn.StartsWith("CN=", StringComparison.Ordinal)
                ? ConfigurationCoverage()
                : DomainCoverageOf(namingContextDn),
            dn,
            Guid.NewGuid(),
            [
                new EvidenceAttribute(
                    "cn", StoredAttributeCompleteness.Complete, [EvidenceValue.OfText("x")]),
            ],
            Started);

    /// <summary>
    /// The smallest coverage a sealed bundle can honestly carry.
    /// </summary>
    private static RunCoverage OneDomainRead() =>
        RunCoverage.Of(
            CoverageId.ForDomains("contoso.com", ["contoso.com"]),
            [DomainCoverage.Read("contoso.com")],
            [
                ForestPartitionCoverage.Read(
                    "CN=Configuration,DC=contoso,DC=com", NamingContextKind.Configuration),
                ForestPartitionCoverage.Read(
                    "CN=Schema,CN=Configuration,DC=contoso,DC=com", NamingContextKind.Schema),
            ],
            SysvolCoverage.Of([]));

    private long Scalar(string sql)
    {
        using var connection = new SqliteConnection(
            new SqliteConnectionStringBuilder
            {
                DataSource = BundleLayout.EvidencePath(_directory),
                Mode = SqliteOpenMode.ReadOnly,
                Pooling = false,
            }.ToString());

        connection.Open();

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
