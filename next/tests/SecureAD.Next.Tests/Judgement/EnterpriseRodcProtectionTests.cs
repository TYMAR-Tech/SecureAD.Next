using System.Security.AccessControl;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Evidence.Run;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Kernel.Security;
using Xunit;
using static SecureAD.Next.Tests.Judgement.SelfMembershipDiscoveryTests;

namespace SecureAD.Next.Tests.Judgement;

public sealed class EnterpriseRodcProtectionTests
{
    private const string SubjectDn = "CN=Renamed forest group,DC=contoso,DC=com";
    private const string SubjectSid = "S-1-5-21-1-2-3-498";

    [Theory]
    [InlineData(false, "SEC-031", Severity.Low)]
    [InlineData(true, "SEC-032", Severity.Medium)]
    public void OwnershipRulesConsumeTheSavedRid498Answer(bool memberOfDomainAdmins, string expectedRule, Severity expectedSeverity)
    {
        var directory = Capture(memberOfDomainAdmins);
        var evidenceHash = Hash(directory);
        Derive(directory);
        Guid derivationGeneration;
        using (var derived = DerivationReader.Open(directory).Value)
        {
            var protection = derived.Read().ProtectedPrincipals.Value!;
            derivationGeneration = derived.Description.GenerationId;
            Assert.True(protection.IsComplete);
            Assert.Equal(4, protection.CatalogueVersion);
            var entry = Assert.Single(protection.Catalogue, value => value.Rid == 498);
            Assert.Equal("EstablishedNo", entry.PrincipalStatus);
            Assert.Equal("ProtocolSpecification", entry.PrincipalProvenance);
            Assert.Equal("MS-ADTS-3.1.1.6.1.2-P88-2026-10", entry.PrincipalSourceId);
            Assert.Equal("Unverified", entry.PropagationStatus);
            var fact = Assert.IsType<StoredProtectedPrincipalFact>(protection.Lookup(SubjectSid, null));
            Assert.Equal(memberOfDomainAdmins ? ProtectedPrincipalEvaluation.Protected : ProtectedPrincipalEvaluation.NotProtected,
                fact.Evaluation);
            Assert.Equal(ProtectionUnknownReason.None, fact.UnknownReasons);
        }

        var judged = JudgingRun.Judge(directory, [new ObjectOwnedByNonAdministrator(), new ProtectedObjectOwnedByNonAdministrator()],
            Started, Started, JudgingRun.NobodyIsWatching, RunLog.Discarded, CancellationToken.None);
        Assert.True(judged.IsSuccess, judged.Error?.Description);
        using var reader = JudgementReader.Open(directory).Value;
        var stored = reader.Read();

        var finding = Assert.Single(stored.Findings, value => value.DistinguishedName == SubjectDn);
        Assert.Equal((expectedRule, expectedSeverity), (finding.RuleId, finding.Severity));
        Assert.All(stored.RulesRun, rule => Assert.Empty(rule.MissingInputs));
        Assert.Equal(derivationGeneration, reader.Description.DerivationGenerationId);
        Assert.Equal(evidenceHash, Hash(directory));
    }

    private static string Capture(bool memberOfDomainAdmins) => Bundle(membership: false, writeAdditional: (writer, domain) =>
    {
        WriteGroup(writer, domain, SubjectDn, SubjectSid, "-2147483640", [],
            $"O:{UserSid}G:SYD:(A;;RP;;;AU)");
        WriteGroup(writer, domain, CoreDn, "S-1-5-21-1-2-3-512", "-2147483646",
            memberOfDomainAdmins ? [SubjectDn] : [], "O:SYG:SYD:");
        var configuration = new PartitionCoverage("CN=Configuration,DC=contoso,DC=com", NamingContextKind.Configuration,
            "dc01.contoso.com", ConnectionSecurityLevel.SignedAndSealed, 1, 100, 1, [], false);
        writer.WriteCoverage(configuration);
        var guid = Guid.NewGuid();
        var id = writer.WriteObject(new(configuration,
            "CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,DC=contoso,DC=com",
            guid, [Text("objectClass", ["top", "nTDSService"]), Text("dSHeuristics", ["0"])], Started));
        WriteDescriptor(writer, id, guid, "O:SYG:SYD:");
    });

    private static void WriteGroup(BundleWriter writer, PartitionCoverage domain, string dn, string sid,
        string groupType, string[] members, string sddl)
    {
        var guid = Guid.NewGuid();
        var id = writer.WriteObject(new(domain, dn, guid,
        [
            Text("objectClass", ["top", "group"]),
            new("objectSid", StoredAttributeCompleteness.Complete, [EvidenceValue.OfBytes(Sid.ToBytes(sid)!)]),
            Text("groupType", [groupType]), Text("member", members),
        ], Started));
        WriteDescriptor(writer, id, guid, sddl);
    }

    private static void WriteDescriptor(BundleWriter writer, long id, Guid guid, string sddl)
    {
        var descriptor = new RawSecurityDescriptor(sddl);
        var bytes = new byte[descriptor.BinaryLength];
        descriptor.GetBinaryForm(bytes, 0);
        writer.WriteSecurityDescriptor(id, bytes, AceNormalizer.Normalize(guid, SecurityDescriptorParser.Parse(bytes)));
    }

    private static EvidenceAttribute Text(string name, string[] values) =>
        new(name, StoredAttributeCompleteness.Complete, values.Select(EvidenceValue.OfText).ToArray());
}
