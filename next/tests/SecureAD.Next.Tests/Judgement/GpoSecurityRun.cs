using System.Security.AccessControl;
using System.Security.Principal;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using SecureAD.Kernel;
using SecureAD.Kernel.Schema;
using SecureAD.Kernel.Security;
using SecureAD.Kernel.GroupPolicy;
using Xunit;

namespace SecureAD.Next.Tests.Judgement;

internal static class GpoSecurityRun
{
    internal const string Parent = "DC=example,DC=test";
    internal const string Child = "DC=child," + Parent;
    internal const string ParentSid = "S-1-5-21-1-2-3";
    internal const string ChildSid = "S-1-5-21-4-5-6";
    internal const string Computer = "CN=Computer," + Parent;
    internal const string Policy = "CN={11111111-1111-1111-1111-111111111111},CN=Policies,CN=System," + Parent;
    internal const string ComputerSid = ParentSid + "-1100";
    internal const string ApplyGuid = "edacfd8f-ffb3-11d1-b41d-00a0c968f939";
    internal const int Read = 0x20010;
    internal const int Apply = 0x100;
    internal const long Global = -2147483646;
    internal const long Universal = -2147483640;
    internal const long Local = -2147483644;
    internal static readonly DateTimeOffset Captured = new(2026, 9, 3, 9, 0, 0, TimeSpan.Zero);
    internal static readonly Guid ComputerGuid = Guid.Parse("22222222-2222-2222-2222-222222222222");
    internal static readonly Guid PolicyGuid = Guid.Parse("11111111-1111-1111-1111-111111111111");

    internal sealed record Entry(string Sid, int Mask, bool Deny = false, string? Scope = null,
        bool Callback = false, AceFlags Flags = AceFlags.None);
    internal sealed record Group(string Name, uint Rid, long Type, bool ChildDomain,
        IReadOnlyList<string> Members, IReadOnlyList<string> History)
    {
        internal string Dn => "CN=" + Name + "," + (ChildDomain ? Child : Parent);
        internal string Sid => (ChildDomain ? ChildSid : ParentSid) + "-" + Rid;
    }

    internal sealed record OtherObject(string Dn, Guid Guid, IReadOnlyList<EvidenceAttribute> Attributes,
        bool PolicyPermissions = false);

    internal sealed record Options
    {
        internal IReadOnlyList<Entry> Entries { get; init; } =
            [new("S-1-5-11", Read), new("S-1-5-11", Apply, Scope: ApplyGuid)];
        internal IReadOnlyList<Group> Groups { get; init; } = [];
        internal IReadOnlyList<string> ComputerHistory { get; init; } = [];
        internal bool Derive { get; init; } = true;
        internal uint? PrimaryGroup { get; init; } = 515;
        internal uint AccountControl { get; init; } = 4096;
        internal string ComputerClass { get; init; } = "computer";
        internal string PolicyClass { get; init; } = "groupPolicyContainer";
        internal string? CapturedComputerSid { get; init; } = ComputerSid;
        internal string Owner { get; init; } = "S-1-5-18";
        internal bool NoDescriptor { get; init; }
        internal bool NullDacl { get; init; }
        internal bool ShortDacl { get; init; }
        internal IReadOnlyList<string> Backlinks { get; init; } = [];
        internal IReadOnlyList<string> OtherUsers { get; init; } = [];
        internal string? DomainLinks { get; init; }
        internal IReadOnlyList<EvidenceAttribute> PolicyAttributes { get; init; } = [];
        internal IReadOnlyList<EvidenceAttribute> ComputerAttributes { get; init; } = [];
        internal (string Path, GpoTemplateVersionObservation Observation)? TemplateVersion { get; init; }
        internal IReadOnlyList<OtherObject> OtherObjects { get; init; } = [];
        internal IReadOnlyList<(Guid Guid, string Path, GpoRegistrySettings Settings)> RegistryPolicies { get; init; } = [];
    }

    internal static string Build(Options options)
    {
        var directory = TempDirectories.Create("gpo-security-filter");
        var groups = new[] { new Group("Primary computers", 515, Global, false, [], []) }
            .Concat(options.Groups.Where(group => group.Rid != 515 || group.ChildDomain)).ToArray();
        var parentCount = 3 + groups.Count(group => !group.ChildDomain) + options.OtherUsers.Count
            + options.OtherObjects.Count(row => !InChild(row.Dn));
        var parent = new PartitionCoverage(Parent, NamingContextKind.Domain, "dc.example.test",
            ConnectionSecurityLevel.SignedAndSealed, parentCount, 1, 0, [], false);
        var child = new PartitionCoverage(Child, NamingContextKind.Domain, "dc.child.example.test",
            ConnectionSecurityLevel.SignedAndSealed,
            1 + groups.Count(group => group.ChildDomain) + options.OtherObjects.Count(row => InChild(row.Dn)), 1, 0, [], false);
        using (var writer = BundleWriter.Create(directory, Captured))
        {
            writer.WriteCoverage(parent);
            writer.WriteCoverage(child);
            writer.WriteObject(new(parent, Parent, Guid.NewGuid(),
                [Text("objectClass", "domainDNS"), Sid("objectSid", ParentSid),
                    .. options.DomainLinks is { } links ? new[] { Text("gPLink", links) } : []], Captured));
            writer.WriteObject(new(child, Child, Guid.NewGuid(), [Text("objectClass", "domainDNS"), Sid("objectSid", ChildSid)], Captured));
            var computer = new List<EvidenceAttribute>
            {
                Text("objectClass", "top", "person", "organizationalPerson", "user", options.ComputerClass),
                Text("userAccountControl", options.AccountControl.ToString(System.Globalization.CultureInfo.InvariantCulture)),
            };
            if (options.CapturedComputerSid is { } sid) computer.Add(Sid("objectSid", sid));
            if (options.PrimaryGroup is { } primary) computer.Add(Text("primaryGroupID", primary.ToString(System.Globalization.CultureInfo.InvariantCulture)));
            if (options.ComputerHistory.Count > 0) computer.Add(Sids("sIDHistory", options.ComputerHistory));
            if (options.Backlinks.Count > 0) computer.Add(Text("memberOf", options.Backlinks.ToArray()));
            computer.AddRange(options.ComputerAttributes);
            writer.WriteObject(new(parent, Computer, ComputerGuid, computer, Captured));
            for (var index = 0; index < options.OtherUsers.Count; index++)
                writer.WriteObject(new(parent, $"CN=Other user {index},{Parent}", Guid.NewGuid(),
                    [Text("objectClass", "top", "person", "organizationalPerson", "user"),
                        Sid("objectSid", options.OtherUsers[index])], Captured));
            foreach (var group in groups)
            {
                var attributes = new List<EvidenceAttribute>
                {
                    Text("objectClass", "top", "group"), Sid("objectSid", group.Sid),
                    Text("groupType", group.Type.ToString(System.Globalization.CultureInfo.InvariantCulture)),
                };
                if (group.Members.Count > 0) attributes.Add(Text("member", group.Members.ToArray()));
                if (group.History.Count > 0) attributes.Add(Sids("sIDHistory", group.History));
                writer.WriteObject(new(group.ChildDomain ? child : parent, group.Dn, Guid.NewGuid(), attributes, Captured));
            }
            var policyId = writer.WriteObject(new(parent, Policy, PolicyGuid,
                [Text("objectClass", "top", "container", options.PolicyClass), .. options.PolicyAttributes], Captured));
            if (options.TemplateVersion is { } template)
                writer.WriteGpoTemplateVersion(PolicyGuid, template.Path, template.Observation);
            WritePermissions(writer, policyId, PolicyGuid, options);
            foreach (var row in options.OtherObjects)
            {
                var id = writer.WriteObject(new(InChild(row.Dn) ? child : parent, row.Dn, row.Guid, row.Attributes, Captured));
                if (row.PolicyPermissions) WritePermissions(writer, id, row.Guid, options);
            }
            var policyCoverage = new List<GpoCoverage>();
            foreach (var (guid, path, registry) in options.RegistryPolicies)
            {
                for (var index = 0; index < registry.Settings.Count; index++)
                {
                    var setting = registry.Settings[index];
                    writer.WriteGpoRegistrySetting(guid, index, GpoSettingScope.Machine,
                        setting.KeyPath, setting.ValueName, setting.RegistryType, setting.Data);
                }
                for (var index = 0; index < registry.ParseErrors.Count; index++)
                    writer.WriteGpoFileError(guid, index, @"Machine\Registry.pol", registry.ParseErrors[index]);
                if (registry.Outcome == GpoSettingsOutcome.Read)
                    policyCoverage.Add(GpoCoverage.Read(guid, "Synthetic policy", path));
                else if (registry.Outcome == GpoSettingsOutcome.PartiallyRead)
                    policyCoverage.Add(GpoCoverage.PartiallyRead(guid, "Synthetic policy", path, registry.Reason!));
                else if (registry.Outcome == GpoSettingsOutcome.Unreadable)
                    policyCoverage.Add(GpoCoverage.Unreadable(guid, "Synthetic policy", path, registry.Reason!));
            }
            writer.Complete(RunCoverage.Of(CoverageId.ForDomains("example.test", ["example.test", "child.example.test"]),
                [DomainCoverage.Read("example.test"), DomainCoverage.Read("child.example.test")],
                [
                    ForestPartitionCoverage.Read("CN=Configuration," + Parent, NamingContextKind.Configuration),
                    ForestPartitionCoverage.Read("CN=Schema,CN=Configuration," + Parent, NamingContextKind.Schema),
                ], SysvolCoverage.Of(policyCoverage)), Captured.AddMinutes(1));
        }
        if (options.Derive) Derive(directory);
        return directory;
    }

    private static void WritePermissions(BundleWriter writer, long policyId, Guid policyGuid, Options options)
    {
        if (options.NoDescriptor) return;
        var acl = options.NullDacl ? null : new RawAcl(GenericAcl.AclRevisionDS, options.Entries.Count);
        foreach (var entry in options.NullDacl ? [] : options.Entries)
        {
            var qualifier = entry.Deny ? AceQualifier.AccessDenied : AceQualifier.AccessAllowed;
            var trusteeSid = new SecurityIdentifier(entry.Sid);
            GenericAce ace = entry.Scope is { } scope
                ? new ObjectAce(entry.Flags, qualifier, entry.Mask, trusteeSid, ObjectAceFlags.ObjectAceTypePresent,
                    Guid.Parse(scope), Guid.Empty, entry.Callback, entry.Callback ? new byte[4] : null)
                : new CommonAce(entry.Flags, qualifier, entry.Mask, trusteeSid, entry.Callback, entry.Callback ? new byte[4] : null);
            acl!.InsertAce(acl.Count, ace);
        }
        var descriptor = new RawSecurityDescriptor(ControlFlags.DiscretionaryAclPresent | ControlFlags.SelfRelative,
            new(options.Owner), new("S-1-5-18"), null, acl);
        var bytes = new byte[descriptor.BinaryLength];
        descriptor.GetBinaryForm(bytes, 0);
        if (options.ShortDacl)
        {
            var offset = System.Buffers.Binary.BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(16, 4));
            var count = System.Buffers.Binary.BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(offset + 4, 2));
            System.Buffers.Binary.BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(offset + 4, 2), checked((ushort)(count + 1)));
        }
        writer.WriteSecurityDescriptor(policyId, bytes, AceNormalizer.Normalize(policyGuid, SecurityDescriptorParser.Parse(bytes)));
    }

    internal static void Derive(string directory)
    {
        var result = Stage2aRun.Derive(directory, ExpansionBudget.Bulk, Captured.AddMinutes(2),
            Stage2aRun.Unwatched, RunLog.Discarded, CancellationToken.None);
        Assert.True(result.IsSuccess);
    }

    private static EvidenceAttribute Text(string name, params string[] values) =>
        new(name, StoredAttributeCompleteness.Complete, values.Select(EvidenceValue.OfText).ToArray());
    private static EvidenceAttribute Sid(string name, string value) =>
        new(name, StoredAttributeCompleteness.Complete, [EvidenceValue.OfBytes(SecureAD.Kernel.Security.Sid.ToBytes(value)!)]);
    private static EvidenceAttribute Sids(string name, IReadOnlyList<string> values) =>
        new(name, StoredAttributeCompleteness.Complete, values.Select(value => EvidenceValue.OfBytes(SecureAD.Kernel.Security.Sid.ToBytes(value)!)).ToArray());
    private static bool InChild(string dn) => dn.EndsWith(Child, StringComparison.OrdinalIgnoreCase);
}
