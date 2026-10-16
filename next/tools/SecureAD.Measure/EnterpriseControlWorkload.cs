using System.Globalization;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Text;
using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using SecureAD.Kernel.Capture;
using SecureAD.Kernel.Security;

namespace SecureAD.Measure;

internal static class EnterpriseControlWorkload
{
    internal static readonly DateTimeOffset When = new(2026, 10, 10, 0, 0, 0, TimeSpan.Zero);
    internal const int Domains = 3;
    internal const int GroupsPerDomain = 53;
    internal const int ComputersPerDomain = 53;
    internal const int Objects = 343;
    internal const int MemberOccurrences = 795;
    internal const string Root = "DC=resp01,DC=invalid";
    private const string MemberGuid = "bf9679c0-0de6-11d0-a285-00aa003049e2";
    private const string DefaultDescriptor = "O:SYG:SYD:(A;;RP;;;S-1-5-11)";

    internal static string Domain(int index) => index == 0 ? Root : $"DC=d{index},{Root}";
    internal static string DomainName(int index) => index == 0 ? "resp01.invalid" : $"d{index}.resp01.invalid";
    internal static string DomainSid(int index) => $"S-1-5-21-20261015-{100 + index}-75";
    internal static string Accounts(int domain) => "OU=Accounts," + Domain(domain);
    internal static string User(int domain, int index) => $"CN=User-{index:000}," + Accounts(domain);
    internal static string Group(int domain, int index) => $"CN=Group-{index:000}," + Accounts(domain);
    internal static string Computer(int domain, int index) => $"CN=Computer-{index:000}," + Accounts(domain);
    private static int GroupRid(int index) => index switch { 0 => 512, 1 => 513, 2 => 515, _ => 6000 + index };

    internal static BundleSealTimings Write(string directory, CancellationToken token)
    {
        using var writer = BundleWriter.Create(directory, When);
        for (var domain = 0; domain < Domains; domain++)
        {
            token.ThrowIfCancellationRequested();
            var coverage = Coverage(Domain(domain), NamingContextKind.Domain, domain, 112);
            writer.WriteCoverage(coverage);
            WriteObject(coverage, Domain(domain), "domainDNS", DomainSid(domain), [], DefaultDescriptor);
            WriteObject(coverage, Accounts(domain), "organizationalUnit", null, [], DefaultDescriptor);
            for (var index = 0; index < 4; index++)
            {
                var attributes = new List<EvidenceAttribute>
                {
                    Text("sAMAccountName", $"User-{index:000}"),
                    Text("userAccountControl", index switch { 0 => "544", 1 => "4194816", _ => "512" }),
                    Text("primaryGroupID", "513"),
                    Text("pwdLastSet", When.AddDays(-60).ToFileTime().ToString(CultureInfo.InvariantCulture)),
                };
                if (index >= 2) attributes.Add(Text("servicePrincipalName", "HTTP/synthetic.resp01.invalid"));
                WriteObject(coverage, User(domain, index), "user", DomainSid(domain) + $"-{1100 + index}",
                    attributes.ToArray(), DefaultDescriptor);
            }
            for (var index = 0; index < GroupsPerDomain; index++)
            {
                var members = index == 2
                    ? Enumerable.Range(0, ComputersPerDomain).Select(computer => Computer(domain, computer)).ToList()
                    : Enumerable.Range(0, 4).Select(user => User(domain, user)).ToList();
                if (index == 0) members.Add(User(domain, 0));
                if (index == 3) { members.Add(Group(domain, 3)); members.Add(Group(domain, 4)); }
                if (index == 4) members.Add(Group(domain, 3));
                var descriptor = index switch
                {
                    0 => $"O:{DomainSid(domain)}-1100G:SYD:(A;;WD;;;{DomainSid(domain)}-6003)",
                    3 => $"O:SYG:SYD:(OA;;WP;{MemberGuid};;{DomainSid(domain)}-1101)",
                    _ => DefaultDescriptor,
                };
                WriteObject(coverage, Group(domain, index), "group", DomainSid(domain) + $"-{GroupRid(index)}",
                    [Text("sAMAccountName", $"Group-{index:000}"),
                        Text("groupType", index > 4 && index % 5 == 0 ? "8" : "-2147483646"),
                        Text("member", members.ToArray())], descriptor);
            }
            for (var index = 0; index < ComputersPerDomain; index++)
            {
                var attributes = new List<EvidenceAttribute>
                {
                    Text("sAMAccountName", $"Computer-{index:000}$"),
                    Text("userAccountControl", "4096"), Text("primaryGroupID", "515"),
                    Text("operatingSystem", "Windows Server 2022"),
                    Text("operatingSystemVersion", "10.0 (20348)"),
                };
                var expiry = When.AddDays(index % 2 == 0 ? -1 : 1).ToFileTime().ToString(CultureInfo.InvariantCulture);
                if (index % 3 == 0) attributes.Add(Text("msLAPS-PasswordExpirationTime", expiry));
                if (index % 3 == 1) attributes.Add(Text("ms-Mcs-AdmPwdExpirationTime", expiry));
                WriteObject(coverage, Computer(domain, index), "computer", DomainSid(domain) + $"-{10000 + index}",
                    attributes.ToArray(), DefaultDescriptor);
            }
        }

        var configuration = "CN=Configuration," + Root;
        var schemaDn = "CN=Schema," + configuration;
        var configurationCoverage = Coverage(configuration, NamingContextKind.Configuration, 0, 1);
        var schemaCoverage = Coverage(schemaDn, NamingContextKind.Schema, 0, 6);
        writer.WriteCoverage(configurationCoverage);
        writer.WriteCoverage(schemaCoverage);
        WriteObject(configurationCoverage, configuration, "configuration", null, [], DefaultDescriptor);
        WriteObject(schemaCoverage, schemaDn, "dMD", null, [], DefaultDescriptor);
        Schema("member", "attributeSchema", Guid.Parse(MemberGuid));
        Schema("user", "classSchema", Guid.Parse("bf967aba-0de6-11d0-a285-00aa003049e2"));
        Schema("group", "classSchema", Guid.Parse("bf967a9c-0de6-11d0-a285-00aa003049e2"));
        Schema("msLAPS-PasswordExpirationTime", "attributeSchema", Identity("schema/windows-laps-expiry"));
        Schema("ms-Mcs-AdmPwdExpirationTime", "attributeSchema", Identity("schema/legacy-laps-expiry"));
        return writer.Complete(RunCoverage.Of(
            CoverageId.ForDomains("resp01.invalid", Enumerable.Range(0, Domains).Select(DomainName).ToArray()),
            Enumerable.Range(0, Domains).Select(index => DomainCoverage.Read(DomainName(index))).ToArray(),
            [ForestPartitionCoverage.Read(configuration, NamingContextKind.Configuration),
                ForestPartitionCoverage.Read(schemaDn, NamingContextKind.Schema)],
            SysvolCoverage.Of([])), When.AddMinutes(1), ContinuationReconciliation.NotPerformed,
            CaptureObjectScope.Default, token);

        void Schema(string name, string kind, Guid guid) =>
            WriteObject(schemaCoverage, "CN=" + name + "," + schemaDn, kind, null,
                [Text("lDAPDisplayName", name),
                    new("schemaIDGUID", StoredAttributeCompleteness.Complete, [EvidenceValue.OfBytes(guid.ToByteArray())]),
                    Text("isSingleValued", name == "member" ? "FALSE" : "TRUE"),
                    Text("systemFlags", "16"), Text("searchFlags", "0")], DefaultDescriptor);

        void WriteObject(PartitionCoverage coverage, string dn, string kind, string? sid,
            EvidenceAttribute[] attributes, string descriptor)
        {
            token.ThrowIfCancellationRequested();
            var guid = Identity(dn);
            var identity = sid is null ? Array.Empty<EvidenceAttribute>()
                : [new("objectSid", StoredAttributeCompleteness.Complete, [EvidenceValue.OfBytes(
                    Sid.ToBytes(sid) ?? throw new InvalidDataException("Invalid synthetic SID."))])];
            var id = writer.WriteObject(new(coverage, dn, guid,
                [Text("objectClass", "top", kind), .. identity, .. attributes], When));
            var raw = new RawSecurityDescriptor(descriptor);
            var bytes = new byte[raw.BinaryLength];
            raw.GetBinaryForm(bytes, 0);
            writer.WriteSecurityDescriptor(id, bytes, AceNormalizer.Normalize(guid, SecurityDescriptorParser.Parse(bytes)));
        }
    }

    private static PartitionCoverage Coverage(string dn, NamingContextKind kind, int domain, int count) =>
        new(dn, kind, "dc01." + DomainName(domain), ConnectionSecurityLevel.SignedAndSealed, 1, count, 1, [], false);

    private static EvidenceAttribute Text(string name, params string[] values) =>
        new(name, StoredAttributeCompleteness.Complete, values.Select(EvidenceValue.OfText).ToArray());

    private static Guid Identity(string value) =>
        new(SHA256.HashData(Encoding.UTF8.GetBytes("0x20261015/" + value)).AsSpan(0, 16));
}
