using System.Buffers.Binary;
using System.Globalization;
using System.Security.AccessControl;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Evidence.Run;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Kernel.Capture;
using SecureAD.Kernel.Security;
using Xunit;

namespace SecureAD.Next.Tests.Judgement;

internal sealed record Scout09LapsRun(string Directory, Guid TargetGuid)
{
    internal const string Root = "DC=ad,DC=lab";
    internal const string Target = "CN=Scout09,OU=Servers," + Root;
    internal const string SetGuid = "11111111-2222-3333-4444-555555555555";
    internal const string ComputerGuid = "bf967a86-0de6-11d0-a285-00aa003049e2";
    internal const string PasswordGuid = "53c5be7e-5403-4013-a04b-b22e05d0e3c1";
    internal const string EncryptedGuid = "f3531ec6-6330-4f8e-8d39-7a671fbac605";
    internal static readonly DateTimeOffset When = DateTimeOffset.UnixEpoch;

    internal static Scout09LapsRun Create(int holders = 0, int searchFlags = 128, int systemFlags = 0,
        int mask = 0x110, uint? control = 4096, string attribute = "msLAPS-Password",
        string scope = "attribute", bool shortDescriptor = false, bool captureBroadPrincipal = true)
    {
        var directory = TempDirectories.Create("scout09-laps-read");
        const string schemaRoot = "CN=Schema,CN=Configuration," + Root;
        const string configurationRoot = "CN=Configuration," + Root;
        const string foreignDn = "CN=S-1-5-11,CN=ForeignSecurityPrincipals," + Root;
        var domain = Coverage(Root, NamingContextKind.Domain);
        var schema = Coverage(schemaRoot, NamingContextKind.Schema);
        var configuration = Coverage(configurationRoot, NamingContextKind.Configuration);
        var guid = Guid.NewGuid();
        var attributes = new List<EvidenceAttribute>
        {
            Multi("objectClass", "top", "person", "organizationalPerson", "user", "computer"),
            Text("sAMAccountName", "Scout09$"),
            Bytes("objectSid", Sid.ToBytes("S-1-5-21-1-2-3-1100")!),
            Text("primaryGroupID", "515"), Multi("memberOf"),
        };
        if (control.HasValue) attributes.Add(Text("userAccountControl", control.Value.ToString(CultureInfo.InvariantCulture)));
        var attributeGuid = attribute == "msLAPS-EncryptedPassword" ? EncryptedGuid : PasswordGuid;
        var objectGuid = scope switch { "property-set" => SetGuid, "class" => ComputerGuid, _ => attributeGuid };
        using (var writer = BundleWriter.Create(directory, When))
        {
            writer.WriteCoverage(domain);
            writer.WriteCoverage(schema);
            writer.WriteCoverage(configuration);
            writer.WriteObject(new(domain, Root, Guid.NewGuid(),
                [Multi("objectClass", "top", "domainDNS"), Bytes("objectSid", Sid.ToBytes("S-1-5-21-1-2-3")!)], When));
            if (captureBroadPrincipal || holders > 0)
            {
                writer.WriteObject(new(domain, foreignDn, Guid.NewGuid(),
                    [Multi("objectClass", "top", "foreignSecurityPrincipal"), Bytes("objectSid", Sid.ToBytes("S-1-5-11")!),
                        Multi("memberOf")], When));
            }
            if (holders > 0)
            {
                for (var index = 0; index < holders; index++)
                    writer.WriteObject(new(domain, $"CN=Holder{index:D3},OU=Groups,{Root}", Guid.NewGuid(),
                        [Multi("objectClass", "top", "group"), Text("sAMAccountName", $"Holder{index:D3}"),
                            Bytes("objectSid", Sid.ToBytes($"S-1-5-21-1-2-3-{2000 + index}")!),
                            Text("groupType", "-2147483644"), Multi("member", foreignDn), Multi("memberOf")], When));
            }
            var id = writer.WriteObject(new(domain, Target, guid, attributes, When));
            var trustees = holders == 0 ? new[] { "S-1-5-11" }
                : Enumerable.Range(0, holders).Select(index => $"S-1-5-21-1-2-3-{2000 + index}").ToArray();
            var aces = string.Concat(trustees.Select(sid => scope is "property-set" or "class"
                ? $"(OA;;RP;{objectGuid};;{sid})(A;;CR;;;{sid})"
                : $"(OA;;0x{mask:X};{objectGuid};;{sid})"));
            var descriptor = new RawSecurityDescriptor("O:SYG:SYD:" + aces);
            var bytes = new byte[descriptor.BinaryLength];
            descriptor.GetBinaryForm(bytes, 0);
            if (shortDescriptor)
            {
                var offset = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(16, 4));
                BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(offset + 4, 2),
                    checked((ushort)(descriptor.DiscretionaryAcl!.Count + 1)));
            }
            var parsed = SecurityDescriptorParser.Parse(bytes);
            writer.WriteSecurityDescriptor(id, bytes, AceNormalizer.Normalize(guid, parsed));
            foreach (var (name, identity) in new[]
            {
                ("msLAPS-Password", PasswordGuid), ("msLAPS-EncryptedPassword", EncryptedGuid),
                ("ms-Mcs-AdmPwd", "2e0e4a88-f5fa-11df-b3af-001fc000a000"),
            })
            {
                var definition = new List<EvidenceAttribute>
                {
                    Multi("objectClass", "top", "attributeSchema"), Text("lDAPDisplayName", name), Text("cn", name),
                    Bytes("schemaIDGUID", Guid.Parse(identity).ToByteArray()), Text("isSingleValued", "TRUE"),
                    Text("searchFlags", searchFlags.ToString(CultureInfo.InvariantCulture)),
                    Text("systemFlags", systemFlags.ToString(CultureInfo.InvariantCulture)),
                };
                if (scope == "property-set" && name == attribute)
                    definition.Add(Bytes("attributeSecurityGUID", Guid.Parse(SetGuid).ToByteArray()));
                writer.WriteObject(new(schema, $"CN={name},{schemaRoot}", Guid.NewGuid(), definition, When));
            }
            writer.WriteObject(new(schema, "CN=Computer," + schemaRoot, Guid.NewGuid(),
                [Multi("objectClass", "top", "classSchema"), Text("lDAPDisplayName", "computer"), Text("cn", "Computer"),
                    Bytes("schemaIDGUID", Guid.Parse(ComputerGuid).ToByteArray())], When));
            writer.WriteObject(new(configuration, "CN=Synthetic-LAPS-Set,CN=Extended-Rights," + configurationRoot,
                Guid.NewGuid(), [Multi("objectClass", "top", "controlAccessRight"), Text("cn", "Synthetic-LAPS-Set"),
                    Text("rightsGuid", SetGuid), Text("validAccesses", "48")], When));
            writer.Complete(RunCoverage.Of(CoverageId.ForDomains("ad.lab", ["ad.lab"]),
                [DomainCoverage.Read("ad.lab")],
                [ForestPartitionCoverage.Read(configurationRoot, NamingContextKind.Configuration),
                    ForestPartitionCoverage.Read(schemaRoot, NamingContextKind.Schema)],
                SysvolCoverage.Of([])), When.AddMinutes(1));
        }
        var derived = Stage2aRun.Derive(directory, ExpansionBudget.Bulk, When,
            Stage2aRun.Unwatched, RunLog.Discarded, CancellationToken.None);
        Assert.True(derived.IsSuccess, derived.Error?.Description);
        var judged = JudgingRun.Judge(directory, [new LapsPasswordReadAccess()], When, When,
            JudgingRun.NobodyIsWatching, RunLog.Discarded, CancellationToken.None);
        Assert.True(judged.IsSuccess, judged.Error?.Description);
        return new(directory, guid);
    }

    internal static void Mutate(string directory, string sql) => SelfMembershipCoverageTests.Mutate(directory, connection =>
    {
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        command.ExecuteNonQuery();
    });

    private static PartitionCoverage Coverage(string dn, NamingContextKind kind) =>
        new(dn, kind, "dc.ad.lab", ConnectionSecurityLevel.SignedAndSealed, 1, 200, 1, [], false);
    private static EvidenceAttribute Text(string name, string value) =>
        new(name, StoredAttributeCompleteness.Complete, [EvidenceValue.OfText(value)]);
    private static EvidenceAttribute Bytes(string name, byte[] value) =>
        new(name, StoredAttributeCompleteness.Complete, [EvidenceValue.OfBytes(value)]);
    private static EvidenceAttribute Multi(string name, params string[] values) =>
        new(name, StoredAttributeCompleteness.Complete, values.Select(EvidenceValue.OfText).ToArray());
}
