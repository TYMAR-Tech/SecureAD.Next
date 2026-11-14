using System.Globalization;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Text;
using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using SecureAD.Kernel.Capture;
using SecureAD.Kernel.GroupPolicy;
using SecureAD.Kernel.Security;

namespace SecureAD.Measure;

internal enum ConfiguredLapsWorkloadProfile { AllWindowsLaps, MixedLegacyWindows }

internal sealed record ConfiguredLapsShape(int Computers, int PoliciesPerDomain, int GroupDepth, int FillerObjects)
{
    internal const int Domains = 9;
    public ConfiguredLapsWorkloadProfile Profile { get; init; }
    internal long Objects => checked(9L * (8 + GroupDepth + PoliciesPerDomain) + Computers + FillerObjects + 2);
    internal int LinkedPoliciesPerDomain => Profile == ConfiguredLapsWorkloadProfile.MixedLegacyWindows
        ? 2 + (PoliciesPerDomain - 1) / 2 : PoliciesPerDomain;
    internal bool IsLinked(int policy) => Profile == ConfiguredLapsWorkloadProfile.AllWindowsLaps || policy < 2 || policy % 2 == 0;

    internal void Validate()
    {
        if (Computers < Domains || Computers % Domains != 0 || FillerObjects < 0 || FillerObjects % Domains != 0
            || PoliciesPerDomain < 2 || GroupDepth < 1 || !Enum.IsDefined(Profile))
            throw new ArgumentException("Computers and filler must divide across nine domains; at least two policies and one nested group per domain are required.");
        _ = Objects;
    }
}

internal static class ConfiguredLapsWorkload
{
    internal static readonly DateTimeOffset When = new(2026, 11, 12, 0, 0, 0, TimeSpan.Zero);
    internal const string RegistryKey = @"Software\Microsoft\Windows\CurrentVersion\Policies\LAPS";
    internal const string LegacyRegistryKey = @"Software\Policies\Microsoft Services\AdmPwd";
    internal const string UnrelatedRegistryKey = @"Software\Policies\SyntheticUnrelated";
    private const string Apply = "edacfd8f-ffb3-11d1-b41d-00a0c968f939";
    private const string RegistryExtensions = "[{35378eac-683f-11d2-a89a-00c04fbbcfa2}{00000000-0000-0000-0000-000000000001}]";
    private const string Descriptor = "O:SYG:SYD:(A;;RP;;;S-1-5-11)";
    internal static string Domain(int index) => index == 0 ? "DC=laps,DC=invalid" : $"DC=d{index},DC=laps,DC=invalid";
    internal static string DomainName(int index) => index == 0 ? "laps.invalid" : $"d{index}.laps.invalid";
    internal static string DomainSid(int index) => $"S-1-5-21-20261112-{100 + index}-84";
    internal static Guid Identity(string value) => new(SHA256.HashData(Encoding.UTF8.GetBytes("laps-measure/" + value)).AsSpan(0, 16));

    internal static void Write(string directory, ConfiguredLapsShape shape, CancellationToken token)
    {
        shape.Validate();
        using var writer = BundleWriter.Create(directory, When);
        var sysvol = new List<GpoCoverage>();
        var computersPerDomain = shape.Computers / ConfiguredLapsShape.Domains;
        var fillerPerDomain = shape.FillerObjects / ConfiguredLapsShape.Domains;
        for (var domain = 0; domain < ConfiguredLapsShape.Domains; domain++)
        {
            token.ThrowIfCancellationRequested();
            var root = Domain(domain);
            var name = DomainName(domain);
            var sid = DomainSid(domain);
            var ou = "OU=Computers," + root;
            string Computer(int index) => $"CN=Computer-{index:D6}," + ou;
            string Group(int depth) => $"CN=PolicyReaders-{depth:D3}," + root;
            var holder = sid + $"-{2000 + shape.GroupDepth - 1}";
            var coverage = Coverage(root, NamingContextKind.Domain, name,
                8 + shape.GroupDepth + shape.PoliciesPerDomain + computersPerDomain + fillerPerDomain);
            writer.WriteCoverage(coverage);
            var policyDns = Enumerable.Range(0, shape.PoliciesPerDomain)
                .Select(index => "CN=" + Identity($"folder/{domain}/{index}").ToString("B") + ",CN=Policies,CN=System," + root).ToArray();
            var links = string.Concat(policyDns.Select((dn, index) => (Dn: dn, Index: index))
                .Where(policy => shape.IsLinked(policy.Index)).Reverse().Select(policy => "[LDAP://" + policy.Dn + ";0]"));
            WriteObject(coverage, root, ["top", "domainDNS"], sid, [Text("gPLink", links)]);
            WriteObject(coverage, ou, ["top", "organizationalUnit"], null, []);
            WriteObject(coverage, "CN=Domain Admins," + root, ["top", "group"], sid + "-512",
                [Text("groupType", "-2147483646"), Text("member")]);
            WriteObject(coverage, "CN=Domain Users," + root, ["top", "group"], sid + "-513",
                [Text("groupType", "-2147483646"), Text("member")]);
            WriteObject(coverage, "CN=Domain Computers," + root, ["top", "group"], sid + "-515",
                [Text("groupType", "-2147483646"), Text("member")]);
            WriteObject(coverage, "CN=Domain Controllers," + root, ["top", "group"], sid + "-516",
                [Text("groupType", "-2147483646"), Text("member")]);
            for (var depth = 0; depth < shape.GroupDepth; depth++)
                WriteObject(coverage, Group(depth), ["top", "group"], sid + $"-{2000 + depth}",
                    [Text("groupType", "-2147483646"), Text("member", depth == 0
                        ? Enumerable.Range(0, computersPerDomain).Select(Computer).ToArray() : [Group(depth - 1)])]);
            for (var index = 0; index < computersPerDomain; index++)
            {
                var dc = index % 11 == 0;
                var flags = (dc ? 8192 : 4096) | (index % 17 == 0 ? 2 : 0);
                var attributes = new List<EvidenceAttribute>
                {
                    Text("sAMAccountName", $"Computer-{index:D6}$"),
                    Text("userAccountControl", flags.ToString(CultureInfo.InvariantCulture)),
                    Text("primaryGroupID", dc ? "516" : "515"),
                };
                if (index % 13 != 0)
                {
                    attributes.Add(Text("operatingSystem", index % 5 == 0 ? "Windows Server 2016" : "Windows Server 2022"));
                    attributes.Add(Text("operatingSystemVersion", index % 5 == 0 ? "10.0 (14393)" : "10.0 (20348)"));
                }
                WriteObject(coverage, Computer(index), ["top", "person", "organizationalPerson", "user", "computer"],
                    sid + $"-{10000 + index}", attributes.ToArray());
            }
            for (var index = 0; index < fillerPerDomain; index++)
                WriteObject(coverage, $"CN=Filler-{index:D6}," + root, ["top", "person", "organizationalPerson", "user"],
                    sid + $"-{1000000 + index}", [Text("userAccountControl", "512"), Text("primaryGroupID", "513")]);
            for (var filter = 0; filter < 2; filter++)
            {
                var logical = Identity($"logical-filter/{domain}/{filter}").ToString("B");
                var queries = shape.Profile == ConfiguredLapsWorkloadProfile.MixedLegacyWindows
                    ? new[] { filter == 0 ? "SELECT * FROM Win32_OperatingSystem WHERE Version < '10.0.17763'"
                        : "SELECT * FROM Win32_OperatingSystem WHERE Version >= '10.0.17763'" }
                    : filter == 0
                    ? new[] { "SELECT * FROM Win32_OperatingSystem WHERE ProductType = '3'" }
                    : ["SELECT * FROM Win32_OperatingSystem WHERE Version >= '10.0.17763'",
                        "SELECT * FROM Win32_OperatingSystem WHERE ProductType = '3'"];
                var framed = queries.Length.ToString(CultureInfo.InvariantCulture) + ";"
                    + string.Concat(queries.Select(query => $"3;10;{query.Length};WQL;root\\CIMv2;{query};"));
                WriteObject(coverage, "CN=" + logical + ",CN=SOM,CN=WMIPolicy,CN=System," + root,
                    ["top", "msWMI-Som"], null, [Text("msWMI-ID", logical), Text("msWMI-Parm2", framed)]);
            }
            for (var policy = 0; policy < shape.PoliciesPerDomain; policy++)
            {
                var dn = policyDns[policy];
                var objectGuid = Identity(dn);
                var folder = Identity($"folder/{domain}/{policy}").ToString("B");
                var path = @"\\" + name + @"\SYSVOL\" + name + @"\Policies\" + folder;
                var logical = Identity($"logical-filter/{domain}/{policy % 2}").ToString("B");
                WriteObject(coverage, dn, ["top", "container", "groupPolicyContainer"], null,
                    [Text("gPCFileSysPath", path), Text("gPCFunctionalityVersion", "2"), Text("versionNumber", "1"),
                        Text("flags", "0"), Text("gPCMachineExtensionNames", RegistryExtensions),
                        Text("gPCWQLFilter", "[" + name + ";" + logical + ";0]")],
                    $"O:SYG:SYD:(A;;RCRP;;;{holder})(OA;;CR;{Apply};;{holder})");
                writer.WriteGpoTemplateVersion(objectGuid, path, new(GpoTemplateVersionOutcome.Read,
                    Encoding.ASCII.GetBytes("[General]\r\nVersion=1\r\n"), "1", 1, null));
                var settings = new RegistryPolicyEntry[]
                {
                    Number("BackupDirectory", 2), Number("ADPasswordEncryptionEnabled", 1),
                    new(RegistryKey, "ADPasswordEncryptionPrincipal", (uint)RegistryValueType.String, Encoding.Unicode.GetBytes(holder + "\0")),
                    Number("ADBackupDSRMPassword", 1),
                };
                if (shape.Profile == ConfiguredLapsWorkloadProfile.MixedLegacyWindows && policy == 0)
                    settings = [new(LegacyRegistryKey, "AdmPwdEnabled", (uint)RegistryValueType.Dword, BitConverter.GetBytes(1u)),
                        new(LegacyRegistryKey, "PasswordLength", (uint)RegistryValueType.Dword, BitConverter.GetBytes(14u))];
                else if (shape.Profile == ConfiguredLapsWorkloadProfile.MixedLegacyWindows && policy >= 2)
                    settings = [new(UnrelatedRegistryKey, "Setting", (uint)RegistryValueType.Dword, BitConverter.GetBytes((uint)policy))];
                for (var index = 0; index < settings.Length; index++)
                {
                    var setting = settings[index];
                    writer.WriteGpoRegistrySetting(objectGuid, index, GpoSettingScope.Machine,
                        setting.KeyPath, setting.ValueName, setting.RegistryType, setting.Data);
                }
                sysvol.Add(GpoCoverage.Read(objectGuid, "Synthetic policy", path));
            }
        }
        var configuration = "CN=Configuration," + Domain(0);
        var schema = "CN=Schema," + configuration;
        var configurationCoverage = Coverage(configuration, NamingContextKind.Configuration, DomainName(0), 1);
        var schemaCoverage = Coverage(schema, NamingContextKind.Schema, DomainName(0), 1);
        writer.WriteCoverage(configurationCoverage);
        writer.WriteCoverage(schemaCoverage);
        WriteObject(configurationCoverage, configuration, ["top", "configuration"], null, []);
        WriteObject(schemaCoverage, schema, ["top", "dMD"], null, []);
        writer.Complete(RunCoverage.Of(
            CoverageId.ForDomains(DomainName(0), Enumerable.Range(0, ConfiguredLapsShape.Domains).Select(DomainName).ToArray()),
            Enumerable.Range(0, ConfiguredLapsShape.Domains).Select(index => DomainCoverage.Read(DomainName(index))).ToArray(),
            [ForestPartitionCoverage.Read(configuration, NamingContextKind.Configuration),
                ForestPartitionCoverage.Read(schema, NamingContextKind.Schema)], SysvolCoverage.Of(sysvol)),
            When.AddMinutes(1), ContinuationReconciliation.NotPerformed, CaptureObjectScope.Default, token);

        void WriteObject(PartitionCoverage coverage, string dn, string[] classes, string? sid,
            EvidenceAttribute[] attributes, string descriptor = Descriptor)
        {
            token.ThrowIfCancellationRequested();
            var guid = Identity(dn);
            var identity = sid is null ? Array.Empty<EvidenceAttribute>()
                : [new EvidenceAttribute("objectSid", StoredAttributeCompleteness.Complete,
                    [EvidenceValue.OfBytes(Sid.ToBytes(sid) ?? throw new InvalidDataException("Invalid synthetic SID."))])];
            var id = writer.WriteObject(new(coverage, dn, guid,
                [Text("objectClass", classes), .. identity, .. attributes], When));
            var raw = new RawSecurityDescriptor(descriptor);
            var bytes = new byte[raw.BinaryLength];
            raw.GetBinaryForm(bytes, 0);
            writer.WriteSecurityDescriptor(id, bytes, AceNormalizer.Normalize(guid, SecurityDescriptorParser.Parse(bytes)));
        }
    }

    private static RegistryPolicyEntry Number(string name, uint value) =>
        new(RegistryKey, name, (uint)RegistryValueType.Dword, BitConverter.GetBytes(value));
    private static EvidenceAttribute Text(string name, params string[] values) =>
        new(name, StoredAttributeCompleteness.Complete, values.Select(EvidenceValue.OfText).ToArray());
    private static PartitionCoverage Coverage(string dn, NamingContextKind kind, string domain, int count) =>
        new(dn, kind, "dc." + domain, ConnectionSecurityLevel.SignedAndSealed, count, 1, 0, [], false);
}
