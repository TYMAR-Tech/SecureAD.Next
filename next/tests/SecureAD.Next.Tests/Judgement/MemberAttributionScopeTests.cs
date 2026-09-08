using System.Security.AccessControl;
using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using SecureAD.Judgement;
using SecureAD.Kernel.Security;
using Xunit;
using static SecureAD.Next.Tests.Judgement.SelfMembershipDiscoveryTests;

namespace SecureAD.Next.Tests.Judgement;

public sealed class MemberAttributionScopeTests
{
    private const string ChildTarget = "CN=Resource,DC=child,DC=contoso,DC=com";
    private const string AppRoot = "CN=Configuration,DC=contoso,DC=com";
    private const string AppTarget = "CN=Resource," + AppRoot;

    [Theory]
    [InlineData(-2147483646L, MemberAttributionState.Established)]
    [InlineData(-2147483644L, MemberAttributionState.NotEstablished)]
    [InlineData(-2147483640L, MemberAttributionState.Established)]
    public void MembershipDoesNotChangeWhenResourceDomainChanges(long type, MemberAttributionState applicability)
    {
        using var reader = MemberAttributionTests.Prepare(Forest(type, false));
        var detail = reader.ReadMemberAttribution(TargetSid, null, ChildTarget);
        Assert.Equal((1, applicability), (detail.Expansion!.ResolvedMemberCount, Assert.Single(detail.ResourceMembers).State));
    }

    [Fact]
    public void ConfigurationPartitionWithoutServingContextRemainsUnknownNotOutOfScope()
    {
        using var reader = MemberAttributionTests.Prepare(Forest(-2147483644, false));
        Assert.Equal(MemberAttributionState.Unknown,
            Assert.Single(reader.ReadMemberAttribution(TargetSid, null, AppTarget).ResourceMembers).State);
    }

    [Fact]
    public void EqualBuiltinSidsKeepTheirDomainObjectsAndMembersSeparate()
    {
        using var reader = MemberAttributionTests.Prepare(Forest(-2147483644, true));
        var parent = reader.ReadMemberAttribution("S-1-5-32-544", "contoso.com", UserDn).Expansion!;
        var child = reader.ReadMemberAttribution("S-1-5-32-544", "child.contoso.com", ChildTarget).Expansion!;
        Assert.Equal((UserDn, ChildTarget), (Assert.Single(parent.Members).Identity, Assert.Single(child.Members).Identity));
    }

    [Fact]
    public void HiddenExpectedSourceCountIsIndependentOfTheReverseFilter()
    {
        using var reader = MemberAttributionTests.Prepare(Forest(-2147483644, true));
        var hidden = reader.ReadPermissionsThroughMembership(UserSid, null, false, 0);
        var shown = reader.ReadPermissionsThroughMembership(UserSid, null, true, 0);
        Assert.Equal((1L, 1L), (hidden.ExpectedCount, shown.ExpectedCount));
    }

    private static string Forest(long groupType, bool builtin)
    {
        var directory = TempDirectories.Create("member-attribution-scope");
        var parent = Coverage("DC=contoso,DC=com", NamingContextKind.Domain);
        var child = Coverage("DC=child,DC=contoso,DC=com", NamingContextKind.Domain);
        var app = Coverage(AppRoot, NamingContextKind.Configuration);
        using var writer = BundleWriter.Create(directory, Started);
        writer.WriteCoverage(parent);
        writer.WriteCoverage(child);
        writer.WriteCoverage(app);
        Write(parent, "DC=contoso,DC=com", "S-1-5-21-1-2-3", "domainDNS", [], "O:SYG:SYD:");
        Write(child, "DC=child,DC=contoso,DC=com", "S-1-5-21-4-5-6", "domainDNS", [], "O:SYG:SYD:");
        var sid = builtin ? "S-1-5-32-544" : TargetSid;
        Write(parent, TargetDn, sid, "group",
        [
            Text("groupType", groupType.ToString(System.Globalization.CultureInfo.InvariantCulture)),
            Text("member", UserDn),
        ], "O:SYG:SYD:");
        if (builtin)
            Write(child, "CN=Administrators,DC=child,DC=contoso,DC=com", sid, "group",
                [Text("groupType", "-2147483644"), Text("member", ChildTarget)], "O:SYG:SYD:");
        Write(parent, UserDn, UserSid, "user", [Text("primaryGroupID", "513")], $"O:SYG:SYD:(A;;WD;;;{sid})");
        Write(child, ChildTarget, "S-1-5-21-4-5-6-1100", "user", [Text("primaryGroupID", "513")], $"O:SYG:SYD:(A;;WD;;;{sid})");
        Write(app, AppTarget, null, "container", [], $"O:SYG:SYD:(A;;WD;;;{sid})");
        writer.Complete(RunCoverage.Of(CoverageId.ForDomains("contoso.com", ["contoso.com", "child.contoso.com"]),
            [DomainCoverage.Read("contoso.com"), DomainCoverage.Read("child.contoso.com")],
            [ForestPartitionCoverage.Read(AppRoot, NamingContextKind.Configuration),
             ForestPartitionCoverage.Read("CN=Schema,CN=Configuration,DC=contoso,DC=com", NamingContextKind.Schema)],
            SysvolCoverage.Of([])), Started.AddMinutes(1));
        return directory;

        void Write(PartitionCoverage coverage, string dn, string? objectSid, string kind, EvidenceAttribute[] extra, string descriptor)
        {
            var guid = Guid.NewGuid();
            var attributes = new List<EvidenceAttribute> { Text("objectClass", kind) };
            if (objectSid is not null) attributes.Add(new("objectSid", StoredAttributeCompleteness.Complete, [EvidenceValue.OfBytes(Sid.ToBytes(objectSid)!)]));
            attributes.AddRange(extra);
            var id = writer.WriteObject(new(coverage, dn, guid, attributes, Started));
            var raw = new RawSecurityDescriptor(descriptor);
            var bytes = new byte[raw.BinaryLength];
            raw.GetBinaryForm(bytes, 0);
            writer.WriteSecurityDescriptor(id, bytes, AceNormalizer.Normalize(guid, SecurityDescriptorParser.Parse(bytes)));
        }
    }

    private static PartitionCoverage Coverage(string dn, NamingContextKind kind) => new(dn, kind, "dc01.contoso.com",
        ConnectionSecurityLevel.SignedAndSealed, 3, 100, 1, [], false);
    private static EvidenceAttribute Text(string name, string value) => new(name, StoredAttributeCompleteness.Complete, [EvidenceValue.OfText(value)]);
}
