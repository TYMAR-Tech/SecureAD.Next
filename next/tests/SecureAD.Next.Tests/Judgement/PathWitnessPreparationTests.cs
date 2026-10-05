using System.Reflection;
using System.Security.AccessControl;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Kernel.Security;
using Xunit;
using static SecureAD.Next.Tests.Judgement.SelfMembershipDiscoveryTests;

namespace SecureAD.Next.Tests.Judgement;

public sealed class PathWitnessPreparationTests
{
    private const string Domain = "DC=contoso,DC=com";
    private const string First = "CN=First," + Domain;
    private const string Second = "CN=Second," + Domain;
    private const string Descriptor = "O:SYG:SYD:(A;;WD;;;WD)(A;;WD;;;S-1-3-0)(A;;WD;;;WD)";

    [Theory]
    [InlineData("entries")]
    [InlineData("owner")]
    [InlineData("null-dacl")]
    [InlineData("null-dacl-broad-trustee")]
    [InlineData("missing-descriptor")]
    [InlineData("missing-identity")]
    [InlineData("forest-gap")]
    public void GroupedWitnessValidationPreservesEverySupportedSourceDistinction(string variant)
    {
        using var fixture = new Source(variant is "null-dacl" or "null-dacl-broad-trustee" ? "O:SYG:SY"
            : variant == "missing-descriptor" ? null : Descriptor,
            missingIdentity: variant == "missing-identity", incompleteCapture: variant == "forest-gap");
        var source = variant switch
        {
            "entries" => new Tier0DiscoveryLimitation(Tier0DiscoveryReason.BroadTrustee, First, 2, "S-1-1-0"),
            "owner" => new(Tier0DiscoveryReason.UnsupportedRoute, First, null, "S-1-5-18"),
            "null-dacl" => new(Tier0DiscoveryReason.NullDacl, First, null, null),
            "null-dacl-broad-trustee" => new(Tier0DiscoveryReason.BroadTrustee, First, null, "S-1-1-0"),
            "missing-descriptor" => new(Tier0DiscoveryReason.DescriptorUnavailable, First, null, null),
            "missing-identity" => new(Tier0DiscoveryReason.MissingIdentity, First, null, null),
            "forest-gap" => new(Tier0DiscoveryReason.CaptureIncomplete, null, null, null),
            _ => throw new ArgumentOutOfRangeException(nameof(variant)),
        };
        var region = TargetPermissionReference.Region(source, source.TargetDn is null ? null : fixture.Target(First));
        PathUncertaintyRegion[] regions = [region, region, region];
        var before = fixture.Hash;
        TargetPermissionReference.ValidateWitnesses(fixture.Bundle, fixture.Contexts, regions, CancellationToken.None);

        var error = Record.Exception(() => PathInputStorage.ValidateWitnesses(fixture.Bundle, fixture.Contexts, regions, CancellationToken.None));

        Assert.Null(error);
        Assert.Equal(3, regions.Length);
        Assert.Equal(before, fixture.Hash);
    }

    [Theory]
    [InlineData("last-ordinal")]
    [InlineData("wrong-pair")]
    [InlineData("sid-case")]
    [InlineData("other-target")]
    [InlineData("owner")]
    [InlineData("wrong-null")]
    [InlineData("wrong-unavailable")]
    [InlineData("wrong-incomplete")]
    [InlineData("valid-identity")]
    [InlineData("capture-complete")]
    [InlineData("capture-target")]
    [InlineData("cause")]
    [InlineData("subjects")]
    [InlineData("resource")]
    [InlineData("scope")]
    public void GroupedWitnessValidationStillRefusesTheLastContradictoryWitness(string defect)
    {
        using var fixture = new Source(incompleteCapture: defect == "capture-target");
        var valid = TargetPermissionReference.Region(new(Tier0DiscoveryReason.BroadTrustee, First, 0, "S-1-1-0"), fixture.Target(First));
        var wrongSource = defect switch
        {
            "last-ordinal" => valid.Source with { PermissionOrdinal = 99 },
            "wrong-pair" => valid.Source with { PermissionOrdinal = 1 },
            "sid-case" => valid.Source with { TrusteeSid = "s-1-1-0" },
            "other-target" => valid.Source with { TargetDn = Second },
            "owner" => new(Tier0DiscoveryReason.UnsupportedRoute, First, null, UserSid),
            "wrong-null" => new(Tier0DiscoveryReason.NullDacl, First, null, null),
            "wrong-unavailable" => new(Tier0DiscoveryReason.DescriptorUnavailable, First, null, null),
            "wrong-incomplete" => new(Tier0DiscoveryReason.DescriptorIncomplete, First, null, null),
            "valid-identity" => new(Tier0DiscoveryReason.MissingIdentity, First, null, null),
            "capture-complete" => new(Tier0DiscoveryReason.CaptureIncomplete, null, null, null),
            "capture-target" => new(Tier0DiscoveryReason.CaptureIncomplete, First, null, null),
            _ => valid.Source,
        };
        var wrong = TargetPermissionReference.Region(wrongSource,
            wrongSource.TargetDn is { } dn ? fixture.Target(dn) : null);
        wrong = defect switch
        {
            "cause" => wrong with { Cause = PathUncertaintyCause.CapturedEvidenceIncomplete },
            "subjects" => wrong with { Subjects = PathSubjectScope.UnknownWithinForest },
            "resource" => wrong with { RecordedResource = wrong.RecordedResource! with { ObjectGuid = Guid.NewGuid() } },
            "scope" => wrong with { Targets = PathTargetScope.Forest },
            _ => wrong,
        };
        PathUncertaintyRegion[] regions = [.. Enumerable.Repeat(valid, 32), wrong];
        Assert.Throws<InvalidDataException>(() =>
            TargetPermissionReference.ValidateWitnesses(fixture.Bundle, fixture.Contexts, regions, CancellationToken.None));

        Assert.Throws<InvalidDataException>(() =>
            PathInputStorage.ValidateWitnesses(fixture.Bundle, fixture.Contexts, regions, CancellationToken.None));
    }

    [Theory]
    [InlineData(2)]
    [InlineData(2000)]
    public void GroupedWitnessValidationReadsEachSourceOnceWithoutChangingOccurrences(int repetitions)
    {
        using var fixture = new Source();
        var first = TargetPermissionReference.Region(new(Tier0DiscoveryReason.BroadTrustee, First, 2, "S-1-1-0"), fixture.Target(First));
        var second = TargetPermissionReference.Region(new(Tier0DiscoveryReason.UnsupportedRoute, Second, 0, UserSid), fixture.Target(Second));
        var regions = Enumerable.Range(0, repetitions).SelectMany(_ => new[] { first, second }).ToArray();
        var original = JsonSerializer.Serialize(regions, ProofSerialization.Options);
        TargetPermissionReference.ValidateWitnesses(fixture.Bundle, fixture.Contexts, [first, second], CancellationToken.None);
        using var trace = new JudgingInputReuseTests.Statements(Connection(fixture.Bundle));
        trace.Sql.Clear();

        PathInputStorage.ValidateWitnesses(fixture.Bundle, fixture.Contexts, regions, CancellationToken.None);

        Assert.Equal(2, trace.Sql.Count(sql => sql.StartsWith("SELECT s.descriptor_id,", StringComparison.Ordinal)));
        Assert.Equal(2, trace.Sql.Count(sql => sql.StartsWith("SELECT o.object_id, o.distinguished_name,", StringComparison.Ordinal)));
        Assert.Equal(original, JsonSerializer.Serialize(regions, ProofSerialization.Options));
        Assert.Equal(repetitions * 2, regions.Length);
    }

    [Fact]
    public void GroupedWitnessValidationDoesNotKeepAWholeRunSourceCache()
    {
        using var fixture = new Source();
        var region = TargetPermissionReference.Region(new(Tier0DiscoveryReason.BroadTrustee, First, 2, "S-1-1-0"), fixture.Target(First));
        PathInputStorage.ValidateWitnesses(fixture.Bundle, fixture.Contexts, [region], CancellationToken.None);
        using var trace = new JudgingInputReuseTests.Statements(Connection(fixture.Bundle));
        trace.Sql.Clear();

        PathInputStorage.ValidateWitnesses(fixture.Bundle, fixture.Contexts, [region], CancellationToken.None);

        Assert.Single(trace.Sql.Where(sql => sql.StartsWith("SELECT s.descriptor_id,", StringComparison.Ordinal)));
        Assert.Single(trace.Sql.Where(sql => sql.StartsWith("SELECT o.object_id, o.distinguished_name,", StringComparison.Ordinal)));
    }

    [Fact]
    public void EmptyWitnessValidationDoesNotReadSources()
    {
        using var fixture = new Source();
        using var trace = new JudgingInputReuseTests.Statements(Connection(fixture.Bundle));
        trace.Sql.Clear();

        PathInputStorage.ValidateWitnesses(fixture.Bundle, fixture.Contexts, [], CancellationToken.None);

        Assert.Empty(trace.Sql);
    }

    [Fact]
    public void GroupedWitnessValidationPropagatesCancellationBeforeReading()
    {
        using var fixture = new Source();
        var region = TargetPermissionReference.Region(new(Tier0DiscoveryReason.BroadTrustee, First, 2, "S-1-1-0"), fixture.Target(First));
        using var stopping = new CancellationTokenSource();
        stopping.Cancel();
        using var trace = new JudgingInputReuseTests.Statements(Connection(fixture.Bundle));
        trace.Sql.Clear();

        Assert.Throws<OperationCanceledException>(() =>
            PathInputStorage.ValidateWitnesses(fixture.Bundle, fixture.Contexts, [region], stopping.Token));
        Assert.Empty(trace.Sql);
    }

    [Fact]
    public void GroupedWitnessValidationCanCancelWhileGroupingSources()
    {
        using var fixture = new Source();
        using var stopping = new CancellationTokenSource();
        var region = TargetPermissionReference.Region(new(Tier0DiscoveryReason.BroadTrustee, First, 2, "S-1-1-0"), fixture.Target(First));
        var regions = new TargetPermissionReference.CancellingList<PathUncertaintyRegion>(region, stopping);

        Assert.Throws<OperationCanceledException>(() =>
            PathInputStorage.ValidateWitnesses(fixture.Bundle, fixture.Contexts, regions, stopping.Token));
        Assert.Equal(2, regions.Visits);
    }

    private static SqliteConnection Connection(BundleReader bundle) => Assert.IsType<SqliteConnection>(
        typeof(BundleReader).GetField("_connection", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(bundle));

    private sealed class Source : IDisposable
    {
        private readonly string _directory;
        internal BundleReader Bundle { get; }
        internal IReadOnlyDictionary<string, NamingContextKind> Contexts { get; }
        internal string Hash => BundleSealing.HashFile(BundleLayout.EvidencePath(_directory));

        internal Source(string? descriptor = Descriptor, bool missingIdentity = false, bool incompleteCapture = false)
        {
            _directory = TempDirectories.Create("target-witness-preparation");
            var coverage = new PartitionCoverage(Domain, NamingContextKind.Domain, "dc01.contoso.com",
                ConnectionSecurityLevel.SignedAndSealed, 3, 100, 1, [], false);
            using (var writer = BundleWriter.Create(_directory, Started))
            {
                writer.WriteCoverage(coverage);
                Write(Domain, "domainDNS", "S-1-5-21-1-2-3", "O:SYG:SYD:", Guid.NewGuid());
                Write(First, "group", "S-1-5-21-1-2-3-1200", descriptor, missingIdentity ? Guid.Empty : Guid.NewGuid());
                Write(Second, "group", "S-1-5-21-1-2-3-1300", $"O:SYG:SYD:(A;;WD;;;{UserSid})", Guid.NewGuid());
                var domains = incompleteCapture ? new[] { "contoso.com", "child.contoso.com" } : ["contoso.com"];
                writer.Complete(RunCoverage.Of(CoverageId.ForDomains("contoso.com", domains),
                    domains.Select(domain => domain == "contoso.com" ? DomainCoverage.Read(domain)
                        : DomainCoverage.Excluded(domain, ExclusionKind.ByChoice, "Synthetic source gap")).ToArray(),
                    [ForestPartitionCoverage.Read("CN=Configuration," + Domain, NamingContextKind.Configuration),
                        ForestPartitionCoverage.Read("CN=Schema,CN=Configuration," + Domain, NamingContextKind.Schema)], SysvolCoverage.Of([])),
                    Started.AddMinutes(1));

                void Write(string dn, string objectClass, string sid, string? sddl, Guid? guid)
                {
                    var id = writer.WriteObject(new(coverage, dn, guid,
                        [new("objectClass", StoredAttributeCompleteness.Complete, [EvidenceValue.OfText("top"), EvidenceValue.OfText(objectClass)]),
                            new("objectSid", StoredAttributeCompleteness.Complete, [EvidenceValue.OfBytes(Sid.ToBytes(sid)!)]),
                            new("groupType", StoredAttributeCompleteness.Complete, [EvidenceValue.OfText("-2147483646")])], Started));
                    if (sddl is null) return;
                    var raw = new RawSecurityDescriptor(sddl);
                    var bytes = new byte[raw.BinaryLength];
                    raw.GetBinaryForm(bytes, 0);
                    writer.WriteSecurityDescriptor(id, bytes, AceNormalizer.Normalize(guid ?? Guid.Empty, SecurityDescriptorParser.Parse(bytes)));
                }
            }
            var opened = BundleReader.Open(_directory);
            Assert.True(opened.IsSuccess, opened.Error?.Description);
            Bundle = opened.Value;
            Contexts = Bundle.ReadNamingContexts().Value;
        }

        internal Tier0Target Target(string dn) => OwnershipAuditRun.Target(Bundle.ReadObjectAttributes(dn)!, Contexts);
        public void Dispose() => Bundle.Dispose();
    }
}
