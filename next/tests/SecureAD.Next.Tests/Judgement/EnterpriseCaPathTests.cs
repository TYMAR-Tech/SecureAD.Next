using System.Security.AccessControl;
using System.Security.Cryptography;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Kernel.Capture;
using SecureAD.Kernel.Security;
using Xunit;
using Xunit.Abstractions;
using static SecureAD.Next.Tests.Derivation.EnterpriseCaTestEvidence;
using static SecureAD.Next.Tests.Judgement.SelfMembershipDiscoveryTests;

namespace SecureAD.Next.Tests.Judgement;

public sealed class EnterpriseCaPathTests(ITestOutputHelper output)
{
    [Theory]
    [InlineData(RegistrationDn, "pKIEnrollmentService")]
    [InlineData(HostDn, "computer")]
    public void DerivationRetainsTheRegistrationAndHostEvidence(string dn, string objectClass)
    {
        var directory = Capture();
        Derive(directory);
        using var reader = DerivationReader.Open(directory).Value;

        Assert.Contains(reader.ReadMembershipInput().Objects, subject => subject.DistinguishedName == dn
            && subject.Find("objectClass")?.Values.Any(value => value.Text == objectClass) == true
            && subject.Find("dNSHostName")?.Values.SingleOrDefault()?.Text == HostName);
    }

    [Theory]
    [InlineData(RegistrationDn)]
    [InlineData(HostDn)]
    public void QualifiedCaAssetsAreSavedAsFixedTargets(string dn)
    {
        var directory = Judged();
        using var reader = Open(directory);

        Assert.Contains(reader.ReadPathInputs().FixedTargets, target => target.DistinguishedName == dn);
    }

    [Theory]
    [InlineData(RegistrationDn)]
    [InlineData(HostDn)]
    public void EachCaAssetHasItsOwnZeroDistanceWithoutAnInventedHop(string dn)
    {
        using var reader = Open(Judged());
        var path = reader.ReadTier0Path(dn);

        Assert.Equal((Tier0Reachability.Reachable, (int?)0, 0), (path.Reachability, path.ShortestProvenDistance, path.Steps.Count));
    }

    [Fact]
    public void TheNewSourceSemanticsCarryTheirOwnVersionsAndConfigurationContext()
    {
        using var reader = Open(Judged());
        var binding = reader.ReadPathInputs().Input;

        Assert.Equal((8, 15, 47, (int?)2, (int?)2, ConfigurationDn),
            (CapturedAttributeCatalog.Version, DerivationSchema.Version, JudgementSchema.Version,
             binding?.PolicyVersion, binding?.ContractVersion, binding?.ConfigurationNamingContext));
    }

    [Fact]
    public void ExistingWriteDaclProofTerminatesOnTheHostNotItsRegistration()
    {
        using var reader = Open(Judged());
        var path = reader.ReadTier0Path(UserDn);
        var grants = reader.ReadControlEdges(HostDn, null, null, true, 0).Edges
            .Where(edge => edge.Capability == ControlCapability.CanWriteDacl && edge.IsCounted).ToArray();

        Assert.Equal((Tier0Reachability.Reachable, (int?)1, HostDn, 1),
            (path.Reachability, path.ShortestProvenDistance, path.Steps.SingleOrDefault()?.To.DistinguishedName, grants.Length));
    }

    [Fact]
    public void SeveralRegistrationsDoNotMultiplyHostTargetsOrGroupHeldPermissions()
    {
        using var reader = Open(Judged(twoRegistrations: true, groupHeld: true));
        var inputs = reader.ReadPathInputs();
        var grants = reader.ReadControlEdges(HostDn, null, null, true, 0).Edges
            .Count(edge => edge.Capability == ControlCapability.CanWriteDacl && edge.IsCounted);

        Assert.Equal((1, 1, 2), (inputs.FixedTargets.Count(target => target.DistinguishedName == HostDn), grants,
            inputs.Classifications.Single(item => item.Target.DistinguishedName == HostDn).Supports
                .Count(support => support.Basis == Tier0Basis.EnterpriseCaHost)));
    }

    [Fact]
    public void MissingHostEvidenceRemainsIndependentOfTheRegistrationTarget()
    {
        using var reader = Open(Judged(hostNamed: false));
        var inputs = reader.ReadPathInputs();

        Assert.Equal((true, false, true), (inputs.FixedTargets.Any(target => target.DistinguishedName == RegistrationDn),
            inputs.FixedTargets.Any(target => target.DistinguishedName == HostDn),
            inputs.Coverage.Limitations.HasFlag(Tier0Limitations.AssetHostEvidenceMissing)));
    }

    [Fact]
    public void PassiveCaReadbackDoesNotWriteOrPublishAnalysis()
    {
        var directory = Judged();
        var before = Snapshot(directory);
        using (var reader = Open(directory)) reader.ReadTier0Path(HostDn);

        Assert.Equal(before, Snapshot(directory));
    }

    [Fact]
    public void AnOpenReaderRefusesCaInputsAfterTheDerivationChanges()
    {
        var directory = Judged();
        using var reader = Open(directory);
        reader.ReadPathInputs();
        Derive(directory);

        Assert.Throws<InvalidOperationException>(() => reader.ReadPathInputs());
    }

    [Fact]
    public void CancelledCaJudgingKeepsThePreviousGenerationSelected()
    {
        var directory = Judged();
        var before = AnalysisStoreLifecycle.Resolve(directory, AnalysisStoreKind.Judgement).Value.GenerationId;
        using var stopping = new CancellationTokenSource();
        Assert.Throws<OperationCanceledException>(() => JudgingRun.JudgeWithTier0Discovery(directory, [], Started, Started,
            new CancellingProgress(stopping), RunLog.Discarded, stopping.Token, selfMembershipDiscoveryBudget: null));

        Assert.Equal(before, AnalysisStoreLifecycle.Resolve(directory, AnalysisStoreKind.Judgement).Value.GenerationId);
    }

    [Fact]
    public void CoverageKeepsCaHostQuestionsSeparateFromConfigurationRegistrationLimits()
    {
        var directory = Capture();
        Derive(directory);
        Assert.True(JudgingRun.JudgeAudit(directory, [], PathRequesterPolicy.SupportedCapturedQuestions, Started, Started,
            JudgingRun.NobodyIsWatching, RunLog.Discarded, CancellationToken.None, null).IsSuccess);
        using var reader = Open(directory);
        var coverage = reader.ReadPathRequesterCoverage();

        Assert.Equal((true, true), (reader.ReadTier0Path(UserDn).RequesterAssessments.Any(value => value.Request.TargetDn == HostDn),
            coverage.Limitations.Any(value => value.ResourceDn == RegistrationDn
                && value.Reason == PathRequesterSelectionReason.ResourceContextUnsupported)));
    }

    private string Judged(bool hostNamed = true, bool twoRegistrations = false, bool groupHeld = false)
    {
        var directory = Capture(hostNamed, twoRegistrations, groupHeld);
        Derive(directory);
        var result = JudgingRun.JudgeWithTier0Discovery(directory, [], Started, Started,
            JudgingRun.NobodyIsWatching, RunLog.Discarded, CancellationToken.None, selfMembershipDiscoveryBudget: null);
        Assert.True(result.IsSuccess, result.Error?.Description);
        return directory;
    }

    private string Capture(bool hostNamed = true, bool twoRegistrations = false, bool groupHeld = false)
    {
        var directory = Bundle(writeAdditional: (writer, domainCoverage) =>
        {
            var configurationCoverage = new PartitionCoverage(ConfigurationDn, NamingContextKind.Configuration,
                "dc01.contoso.com", ConnectionSecurityLevel.SignedAndSealed, 3, 100, 1, [], false);
            writer.WriteCoverage(configurationCoverage);
            Write(writer, configurationCoverage, ConfigurationDn, "configuration", null, null, "O:SYG:SYD:");
            Write(writer, configurationCoverage, RegistrationDn, "pKIEnrollmentService", null,
                hostNamed ? HostName : null, "O:SYG:SYD:");
            if (twoRegistrations)
                Write(writer, configurationCoverage, RegistrationDn.Replace("Contoso Issuing CA", "Second CA", StringComparison.Ordinal),
                    "pKIEnrollmentService", null, HostName, "O:SYG:SYD:");
            Write(writer, domainCoverage, HostDn, "computer", HostSid, HostName,
                $"O:SYG:SYD:(A;;WD;;;{(groupHeld ? TargetSid : UserSid)})");
        });
        output.WriteLine(directory);
        return directory;
    }

    private static void Write(BundleWriter writer, PartitionCoverage coverage, string dn, string objectClass,
        string? sid, string? hostName, string sddl)
    {
        var guid = Guid.NewGuid();
        var attributes = new List<EvidenceAttribute>
        {
            new("objectClass", StoredAttributeCompleteness.Complete, [EvidenceValue.OfText("top"), EvidenceValue.OfText(objectClass)]),
            new("dNSHostName", hostName is null ? StoredAttributeCompleteness.NotReturned : StoredAttributeCompleteness.Complete,
                hostName is null ? [] : [EvidenceValue.OfText(hostName)]),
        };
        if (sid is not null) attributes.Add(new("objectSid", StoredAttributeCompleteness.Complete, [EvidenceValue.OfBytes(Sid.ToBytes(sid) ?? throw new InvalidOperationException())]));
        var id = writer.WriteObject(new(coverage, dn, guid, attributes, Started));
        var descriptor = new RawSecurityDescriptor(sddl);
        var bytes = new byte[descriptor.BinaryLength];
        descriptor.GetBinaryForm(bytes, 0);
        writer.WriteSecurityDescriptor(id, bytes, AceNormalizer.Normalize(guid, SecurityDescriptorParser.Parse(bytes)));
    }

    private static JudgementReader Open(string directory)
    {
        var result = JudgementReader.Open(directory);
        Assert.True(result.IsSuccess, result.Error?.Description);
        return result.Value;
    }

    private static string[] Snapshot(string directory) => Directory.GetFiles(directory, "*", SearchOption.AllDirectories)
        .Where(path => !path.EndsWith(".db-shm", StringComparison.Ordinal)
            && (!path.EndsWith(".db-wal", StringComparison.Ordinal) || new FileInfo(path).Length != 0))
        .Order(StringComparer.Ordinal).Select(path => path + ":" + Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)))).ToArray();

    private sealed class CancellingProgress(CancellationTokenSource stopping) : IProgress<JudgingRun.JudgingProgress>
    {
        public void Report(JudgingRun.JudgingProgress value)
        {
            if (value.Phase == JudgingPhase.SelectingOwnershipScope) stopping.Cancel();
        }
    }
}
