using System.Collections.Concurrent;
using System.Diagnostics.Metrics;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Inventory;
using SecureAD.Evidence.Run;
using SecureAD.Kernel;
using SecureAD.Kernel.Capture;
using SecureAD.Shell.Services;
using SecureAD.Shell.ViewModels;
using Xunit;

namespace SecureAD.Next.Tests.Evidence;

public sealed class DashboardOverviewTests
{
    private const string Domain = "contoso.com";
    private const string Root = "DC=contoso,DC=com";
    private static readonly DateTimeOffset When = DateTimeOffset.UnixEpoch;
    private static readonly string[] OverviewTables = ["class_exclusion", "domain_inventory", "overview_product"];

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void SavedOverviewPreservesPerDomainCountsScopeAndCoverage(bool includeEnatel)
    {
        var directory = Capture(includeEnatel: includeEnatel);
        using var evidence = BundleReader.Open(directory).Value;
        var original = evidence.ReadInventory().Value;
        var saved = ReadOverview(directory);
        Assert.True(saved.IsSuccess, saved.Error?.Description);
        Assert.Equal(InventorySnapshot(original), InventorySnapshot(saved.Value));
        Assert.Equal(new ObjectCounts(1, 1, 1, 1), saved.Value.CountedTotal);
        Assert.Equal(5, saved.Value.DomainsDeclared);
        Assert.Equal(2, saved.Value.DomainsCounted);
        Assert.True(saved.Value.Domains.Single(domain => domain.DomainFqdn == Domain).MayBeMissingConfidentialValues);
        var empty = saved.Value.Domains.Single(domain => domain.DomainFqdn == "empty.contoso.com");
        Assert.True(empty.TryGetCounts(out var emptyCounts));
        Assert.Equal(ObjectCounts.None, emptyCounts);
        Assert.All(saved.Value.UncountedDomains, domain =>
        {
            Assert.False(domain.TryGetCounts(out var counts));
            Assert.Null(counts);
            Assert.False(domain.MayBeMissingConfidentialValues);
        });
        Assert.Equal(3, saved.Value.PoliciesDeclared);
        Assert.Equal(1, saved.Value.PoliciesRead);
        Assert.Equal(CaptureObjectScope.For(includeEnatel).ExcludedClasses.Order(StringComparer.Ordinal),
            saved.Value.ExcludedObjectClasses.Order(StringComparer.Ordinal));

        var root = Selected(directory);
        using var connection = OpenDatabase(BundleLayout.OverviewPath(directory, root.GenerationId), readOnly: true);
        using var tables = connection.CreateCommand();
        tables.CommandText = "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name";
        var names = new List<string>();
        using var rows = tables.ExecuteReader();
        while (rows.Read()) names.Add(rows.GetString(0));
        Assert.Equal(OverviewTables, names);
    }

    [Theory]
    [InlineData("not-derived", "Group membership has not been worked out yet")]
    [InlineData("zero", "No unidentified group members reported")]
    [InlineData("gap", "2 groups have unidentified members")]
    [InlineData("missing", "Saved membership results could not be read.")]
    [InlineData("foreign", "Saved membership results could not be read.")]
    [InlineData("zero-policy", "No unidentified group members reported")]
    public async Task CompleteDashboardFirstShowRevisitAndReopenUseOnlySmallSavedProducts(string membership, string heading)
    {
        var directory = Capture(policies: membership != "zero-policy");
        if (membership != "missing") PublishDerivation(directory, membership);
        if (membership == "foreign")
        {
            var path = AnalysisStoreLifecycle.ManifestPath(directory, AnalysisStoreKind.Derivation);
            var root = JsonSerializer.Deserialize<StoreRootManifest>(File.ReadAllText(path))!;
            root = root with { DerivationSummary = root.DerivationSummary! with { EvidenceSeal = new string('a', 64) } };
            File.WriteAllText(path, JsonSerializer.Serialize(root with { Hash = root.ComputeHash() }));
        }
        using var verifications = new Verifications(directory);
        using var locks = new HeavyStoreLocks(directory);
        using var source = new BundleAssetSource();
        var model = new DashboardViewModel(source);
        model.Show(directory);
        await model.ReadCompletion;
        Assert.True(model.HasRun);
        Assert.Null(model.Refusal);
        Assert.False(model.IsLoading);
        Assert.Equal("1", model.TotalUsers);
        Assert.Equal("1", model.TotalComputers);
        Assert.Equal("1", model.TotalGroups);
        Assert.Equal("1", model.TotalOrganisationalUnits);
        Assert.Equal("2 of 5 declared domains read", model.DomainCoverageSummary);
        Assert.Equal(heading, model.MembershipSummary);
        Assert.Equal(membership == "zero-policy" ? 0 : 3, model.PoliciesDeclaredCount);
        Assert.Equal(membership == "zero-policy" ? 0 : 1, model.PoliciesReadCount);
        Assert.Equal(membership != "zero-policy", model.HasDeclaredPolicies);
        Assert.NotNull(model.ConfidentialCaveat);
        Assert.NotNull(model.Warning);
        Assert.Equal("0", model.Domains.Single(domain => domain.DomainFqdn == "empty.contoso.com").Users);
        Assert.All(model.Domains.Where(domain => !domain.CountsAreShown), domain => Assert.Null(domain.Users));
        var first = DashboardSnapshot(model);
        Assert.Equal(1, verifications.For("overview"));
        AssertNoHeavyVerification(verifications);

        model.Show(directory);
        await model.ReadCompletion;
        Assert.Equal(first, DashboardSnapshot(model));
        Assert.Equal(1, verifications.For("overview"));
        AssertNoHeavyVerification(verifications);

        source.CloseRun();
        model.Show(directory);
        await model.ReadCompletion;
        Assert.Equal(first, DashboardSnapshot(model));
        Assert.Equal(2, verifications.For("overview"));
        AssertNoHeavyVerification(verifications);
    }

    [Theory]
    [InlineData("bytes")]
    [InlineData("missing")]
    [InlineData("seal")]
    [InlineData("generation")]
    [InlineData("schema")]
    [InlineData("objects")]
    [InlineData("attributes")]
    [InlineData("domains")]
    [InlineData("exclusions")]
    [InlineData("counts")]
    [InlineData("uncounted")]
    [InlineData("withhold")]
    [InlineData("policies")]
    [InlineData("outcome")]
    public void InvalidOrIncompleteOverviewNeverProducesAnInventory(string defect)
    {
        var directory = Capture();
        var root = Selected(directory);
        var path = BundleLayout.OverviewPath(directory, root.GenerationId);
        if (defect == "missing") File.Delete(path);
        else if (defect == "seal") File.Delete(path + ".seal");
        else
        {
            using (var connection = OpenDatabase(path))
            {
                using var edit = connection.CreateCommand();
                edit.CommandText = "PRAGMA ignore_check_constraints=ON;" + (defect switch
                {
                    "bytes" => "UPDATE domain_inventory SET users=2 WHERE domain_fqdn='contoso.com'",
                    "generation" => "UPDATE overview_product SET capture_generation='" + Guid.NewGuid().ToString("D") + "'",
                    "schema" => "UPDATE overview_product SET schema_version=999",
                    "objects" => "UPDATE overview_product SET captured_objects=captured_objects+1",
                    "attributes" => "UPDATE overview_product SET captured_attribute_catalog_version=999",
                    "domains" => "DELETE FROM domain_inventory WHERE domain_fqdn='empty.contoso.com'",
                    "exclusions" => "DELETE FROM class_exclusion",
                    "counts" => "UPDATE domain_inventory SET users=-1 WHERE domain_fqdn='contoso.com'",
                    "uncounted" => "UPDATE domain_inventory SET users=0,computers=0,groups=0,organisational_units=0 WHERE domain_fqdn='partial.contoso.com'",
                    "withhold" => "UPDATE domain_inventory SET may_withhold=2 WHERE domain_fqdn='contoso.com'",
                    "policies" => "UPDATE overview_product SET policies_read=policies_declared+1",
                    "outcome" => "UPDATE domain_inventory SET outcome='Unknown' WHERE domain_fqdn='partial.contoso.com'",
                    _ => throw new ArgumentOutOfRangeException(nameof(defect)),
                });
                edit.ExecuteNonQuery();
                edit.CommandText = "PRAGMA wal_checkpoint(TRUNCATE)";
                edit.ExecuteNonQuery();
            }
            if (defect != "bytes") ResealOverview(directory);
        }
        var read = ReadOverview(directory);
        Assert.False(read.IsSuccess);
        Assert.NotNull(read.Error);
        if (defect is "missing" or "seal") Assert.Equal("Evidence.CaptureManifestUnreadable", read.Error.Code);
    }

    [Fact]
    public void AValidOverviewSealFromAnotherCaptureCannotRebindItsGeneration()
    {
        var directory = Capture();
        var other = Capture();
        var path = BundleLayout.OverviewPath(directory, Selected(directory).GenerationId);
        var foreign = BundleLayout.OverviewPath(other, Selected(other).GenerationId);
        File.Copy(foreign, path, overwrite: true);
        File.Copy(foreign + ".seal", path + ".seal", overwrite: true);
        ResealOverview(directory);
        Assert.False(ReadOverview(directory).IsSuccess);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void OverviewSealingFailureOrCancellationCannotPublishACompleteCapture(bool cancel)
    {
        var directory = TempDirectories.Create("overview-failure");
        using var writer = BundleWriter.Create(directory, When);
        writer.WriteCoverage(Partition(Root));
        using var stopping = new CancellationTokenSource();
        var reached = false;
        var error = Record.Exception(() => writer.Complete(Coverage(), When.AddMinutes(1),
            ContinuationReconciliation.NotPerformed, CaptureObjectScope.Default, stopping.Token, (data, seal, token) =>
            {
                BundleSealing.Seal(data, seal, token);
                if (data != BundleLayout.OverviewPartialPath(directory)) return;
                reached = true;
                if (cancel) stopping.Cancel();
                else throw new IOException("Injected overview sealing failure.");
            }));
        Assert.True(reached);
        if (cancel) Assert.IsType<OperationCanceledException>(error);
        else Assert.IsType<IOException>(error);
        Assert.False(File.Exists(BundleLayout.CaptureManifestPath(directory)));
        Assert.False(AnalysisStoreLifecycle.ResolveCapture(directory).IsSuccess);
        Assert.False(ReadOverview(directory).IsSuccess);
        Assert.False(BundleReader.Open(directory).IsSuccess);
    }

    [Theory]
    [InlineData("capture")]
    [InlineData("derivation")]
    [InlineData("pending")]
    public void OverviewSelectionCannotVouchForChangedOrUnfinishedGenerations(string change)
    {
        var directory = Capture();
        PublishDerivation(directory, "zero");
        using var source = new BundleAssetSource();
        Assert.True(source.ReadInventory(directory).IsSuccess);
        Assert.Equal(0, source.ReadGroupsWithUnidentifiedMembers(directory).Value);
        var valid = source.CaptureReadValidity();
        Assert.True(valid());
        if (change == "capture")
        {
            var root = Selected(directory);
            root = root with { CapturedObjects = root.CapturedObjects + 1 };
            File.WriteAllText(BundleLayout.CaptureManifestPath(directory), JsonSerializer.Serialize(root with { Hash = root.ComputeHash() }));
        }
        else if (change == "derivation") PublishDerivation(directory, "gap");
        else AnalysisStoreLifecycle.BeginAttempt(directory, AnalysisStoreKind.Derivation);
        Assert.False(valid());
        Assert.False(source.ReadGroupsWithUnidentifiedMembers(directory).IsSuccess);
        if (change == "capture") Assert.False(source.ReadInventory(directory).IsSuccess);
    }

    [Fact]
    public void OverviewProtectionOutlivesItsOwnerUntilTheReaderReleasesIt()
    {
        var directory = Capture();
        var path = BundleLayout.OverviewPath(directory, Selected(directory).GenerationId);
        using var store = ProtectedStoreFile.OpenOverview(directory).Value;
        using var reader = DashboardOverviewReader.Open(store).Value;
        store.Dispose();
        Assert.Equal(new ObjectCounts(1, 1, 1, 1), reader.ReadInventory().CountedTotal);
        Assert.Throws<IOException>(() =>
        {
            using var write = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite);
        });
        reader.Dispose();
        Assert.Throws<ObjectDisposedException>(() => reader.ReadInventory());
        using var released = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite);
    }

    [Fact]
    public void OverviewIgnoresUnsealedWalEvenWhenOrdinarySqliteReadsIt()
    {
        var directory = Capture();
        var path = BundleLayout.OverviewPath(directory, Selected(directory).GenerationId);
        var scratch = Path.Combine(directory, "overview-writer.db");
        File.Copy(path, scratch);
        using var writer = OpenDatabase(scratch);
        using var write = writer.CreateCommand();
        write.CommandText = "PRAGMA journal_mode=WAL; PRAGMA wal_checkpoint(TRUNCATE)";
        write.ExecuteNonQuery();
        using (var shared = new FileStream(scratch, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
        using (var bytes = new MemoryStream())
        {
            shared.CopyTo(bytes);
            Assert.Equal(File.ReadAllBytes(path), bytes.ToArray());
        }
        write.CommandText = "UPDATE domain_inventory SET users=99 WHERE domain_fqdn='contoso.com'";
        write.ExecuteNonQuery();
        File.Copy(scratch + "-wal", path + "-wal");
        using (var ordinary = OpenDatabase(path, readOnly: true))
        {
            using var query = ordinary.CreateCommand();
            query.CommandText = "SELECT users FROM domain_inventory WHERE domain_fqdn='contoso.com'";
            Assert.Equal(99L, query.ExecuteScalar());
        }
        var saved = ReadOverview(directory);
        Assert.True(saved.IsSuccess, saved.Error?.Description);
        Assert.Equal(1, saved.Value.CountedTotal.Users);
    }

    private static Result<ForestInventory> ReadOverview(string directory)
    {
        var protectedFile = ProtectedStoreFile.OpenOverview(directory);
        if (!protectedFile.IsSuccess) return Result<ForestInventory>.Failure(protectedFile.Error);
        using var store = protectedFile.Value;
        var opened = DashboardOverviewReader.Open(store);
        if (!opened.IsSuccess) return Result<ForestInventory>.Failure(opened.Error);
        using var reader = opened.Value;
        return Result<ForestInventory>.Success(reader.ReadInventory());
    }

    private static string InventorySnapshot(ForestInventory inventory) => JsonSerializer.Serialize(new
    {
        inventory.ForestFqdn, inventory.ExcludedObjectClasses, inventory.PoliciesDeclared, inventory.PoliciesRead,
        Domains = inventory.Domains.Select(domain => new
        {
            domain.Coverage, domain.MayBeMissingConfidentialValues,
            Counts = domain.TryGetCounts(out var counts) ? counts : null,
        }),
    });

    private static string DashboardSnapshot(DashboardViewModel model) => JsonSerializer.Serialize(new
    {
        model.HasRun, model.HasNoRun, model.IsLoading, model.Refusal, model.HasWarning, model.Warning,
        model.ForestFqdn, model.DomainCoverageSummary, model.CoverageHeadline, model.ObjectClassScopeStatement,
        model.HasCoverageLimitations, model.HasTotals, model.TotalsCover,
        model.TotalUsers, model.TotalComputers, model.TotalGroups, model.TotalOrganisationalUnits,
        model.PolicyCoverageSummary, model.Policies, model.PoliciesDeclaredCount, model.PoliciesReadCount,
        model.HasDeclaredPolicies, model.SomePoliciesWereNotRead, model.MembershipSummary, model.MembershipDetail,
        model.MembershipNotice, model.HasMembershipNotice, model.ConfidentialCaveat, model.HasConfidentialCaveat,
        Domains = model.Domains.Select(domain => new
        {
            domain.DomainFqdn, domain.CaptureStatus, domain.CountsAreShown, domain.ExplanationIsShown,
            domain.Explanation, domain.Users, domain.Computers, domain.Groups, domain.OrganisationalUnits,
        }),
    });

    private static void AssertNoHeavyVerification(Verifications verifications)
    {
        Assert.Equal(0, verifications.For("navigation"));
        Assert.Equal(0, verifications.For("evidence"));
        Assert.Equal(0, verifications.For("derivation"));
        Assert.Equal(0, verifications.For("judgement"));
    }

    private static void ResealOverview(string directory)
    {
        var root = Selected(directory);
        var path = BundleLayout.OverviewPath(directory, root.GenerationId);
        BundleSealing.Seal(path, path + ".seal");
        root = root with
        {
            Segments = root.Segments.Select(segment => segment.Role == StoreSegmentRole.Overview
                ? segment with { Hash = BundleSealing.HashFile(path), ByteLength = new FileInfo(path).Length } : segment).ToArray(),
        };
        File.WriteAllText(BundleLayout.CaptureManifestPath(directory), JsonSerializer.Serialize(root with { Hash = root.ComputeHash() }));
    }

    private static void PublishDerivation(string directory, string membership)
    {
        using var writer = DerivationWriter.Create(directory, Selected(directory).EvidenceSeal, When);
        if (membership == "gap")
        {
            writer.WriteSids(["S-1-5-21-1-2-3-1000", "S-1-5-21-1-2-3-1001"], [null, null]);
            writer.WriteUnresolvedNestingLinks(
            [
                new(0, NestingLinkDirection.Member, "CN=A," + Root),
                new(0, NestingLinkDirection.Member, "CN=B," + Root),
                new(1, NestingLinkDirection.Member, "CN=C," + Root),
                new(1, NestingLinkDirection.ContainingGroup, "CN=D," + Root),
            ]);
            writer.RecordPhase(MembershipNestingPass.PhaseName, DerivationPhaseOutcome.Degraded, null);
        }
        else if (membership != "not-derived")
            writer.RecordPhase(MembershipNestingPass.PhaseName, DerivationPhaseOutcome.Succeeded, null);
        writer.Complete(When.AddMinutes(1));
    }

    private static string Capture(bool includeEnatel = false, bool policies = true)
    {
        var directory = TempDirectories.Create("dashboard-overview");
        using var writer = BundleWriter.Create(directory, When);
        var partition = Partition(Root, ConnectionSecurityLevel.Signed);
        writer.WriteCoverage(partition);
        void Write(string name, params string[] classes) => writer.WriteObject(new(partition, name, Guid.NewGuid(),
            classes.Length == 0 ? [] : [new("objectClass", StoredAttributeCompleteness.Complete, classes.Select(EvidenceValue.OfText).ToArray())], When));
        Write(Root, "top", "domainDNS");
        Write("CN=Alice," + Root, "top", "user");
        Write("CN=Computer," + Root, "top", "user", "computer");
        Write("CN=Group," + Root, "top", "group");
        Write("OU=People," + Root, "top", "organizationalUnit");
        Write("CN=Managed," + Root, "top", "user", "computer", "msDS-GroupManagedServiceAccount");
        Write("CN=Unknown," + Root);
        var partial = Partition("DC=partial," + Root, ConnectionSecurityLevel.Signed);
        writer.WriteCoverage(partial);
        writer.WriteObject(new(partial, "CN=Partial,DC=partial," + Root, Guid.NewGuid(),
            [new("objectClass", StoredAttributeCompleteness.Complete, [EvidenceValue.OfText("user")])], When));
        writer.Complete(Coverage(policies), When.AddMinutes(1), ContinuationReconciliation.NotPerformed,
            CaptureObjectScope.For(includeEnatel));
        return directory;
    }

    private static PartitionCoverage Partition(string dn, ConnectionSecurityLevel security = ConnectionSecurityLevel.SignedAndSealed) =>
        new(dn, NamingContextKind.Domain, "dc.contoso.com", security, 1, 8, 1, [], false);

    private static RunCoverage Coverage(bool policies = true) => RunCoverage.Of(
        CoverageId.ForDomainsExcluding(Domain,
            [Domain, "empty.contoso.com", "partial.contoso.com", "excluded.contoso.com", "missing.contoso.com"],
            ["excluded.contoso.com"]),
        [
            DomainCoverage.Read(Domain), DomainCoverage.Read("empty.contoso.com"),
            DomainCoverage.PartiallyRead("partial.contoso.com", "A recorded continuation was unavailable."),
            DomainCoverage.Excluded("excluded.contoso.com", ExclusionKind.ByChoice, "A recorded operator exclusion."),
            DomainCoverage.Excluded("missing.contoso.com", ExclusionKind.ForWantOfCandidates, "No writable controller was named."),
        ],
        [
            ForestPartitionCoverage.Read("CN=Configuration," + Root, NamingContextKind.Configuration),
            ForestPartitionCoverage.Read("CN=Schema,CN=Configuration," + Root, NamingContextKind.Schema),
        ],
        SysvolCoverage.Of(policies ?
        [
            GpoCoverage.Read(new Guid(1, 0, 0, new byte[8]), "Read policy", @"\\contoso.com\sysvol\1"),
            GpoCoverage.PartiallyRead(new Guid(2, 0, 0, new byte[8]), "Partial policy", @"\\contoso.com\sysvol\2", "Scripts were unavailable."),
            GpoCoverage.Unreadable(new Guid(3, 0, 0, new byte[8]), "Unread policy", @"\\contoso.com\sysvol\3", "The files were unavailable."),
        ] : []));

    private static StoreRootManifest Selected(string directory)
    {
        var selected = AnalysisStoreLifecycle.ResolveCapture(directory);
        Assert.True(selected.IsSuccess, selected.Error?.Description);
        return selected.Value;
    }

    private static SqliteConnection OpenDatabase(string path, bool readOnly = false)
    {
        var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = path, Mode = readOnly ? SqliteOpenMode.ReadOnly : SqliteOpenMode.ReadWrite, Pooling = false,
        }.ToString());
        connection.Open();
        return connection;
    }

    private sealed class HeavyStoreLocks : IDisposable
    {
        private readonly List<FileStream> _files = [];
        internal HeavyStoreLocks(string directory)
        {
            foreach (var path in Directory.EnumerateFiles(directory).Where(path =>
                Path.GetFileName(path).StartsWith("evidence.db", StringComparison.Ordinal)
                || Path.GetFileName(path).StartsWith("navigation.", StringComparison.Ordinal)
                || Path.GetFileName(path).StartsWith("derivation.", StringComparison.Ordinal)
                || Path.GetFileName(path).StartsWith("judgement.", StringComparison.Ordinal)))
            {
                if (path.EndsWith(".db", StringComparison.Ordinal) || path.EndsWith(".seal", StringComparison.Ordinal))
                    _files.Add(new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.None));
            }
        }
        public void Dispose() { foreach (var file in _files) file.Dispose(); }
    }

    private sealed class Verifications : IDisposable
    {
        private readonly MeterListener _listener = new();
        private readonly ConcurrentDictionary<string, long> _counts = new();
        internal Verifications(string directory)
        {
            _listener.InstrumentPublished = (instrument, listener) =>
            {
                if (instrument.Name == "store.verifications") listener.EnableMeasurementEvents(instrument);
            };
            _listener.SetMeasurementEventCallback<long>((_, value, tags, _) =>
            {
                foreach (var tag in tags)
                    if (tag.Value is string path && path.StartsWith(directory, StringComparison.OrdinalIgnoreCase))
                        _counts.AddOrUpdate(Path.GetFileName(path).Split('.')[0], value, (_, previous) => previous + value);
            });
            _listener.Start();
        }
        internal long For(string role) => _counts.GetValueOrDefault(role);
        public void Dispose() => _listener.Dispose();
    }
}
