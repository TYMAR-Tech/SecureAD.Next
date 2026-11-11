using System.Globalization;
using System.Text;
using SecureAD.Evidence;
using SecureAD.Kernel.GroupPolicy;
using static SecureAD.Next.Tests.Judgement.GpoSecurityRun;

namespace SecureAD.Next.Tests.Judgement;

internal static class LapsPrecedenceRun
{
    internal const string Key = @"Software\Microsoft\Windows\CurrentVersion\Policies\LAPS";
    internal const string Principal = "ADPasswordEncryptionPrincipal";
    internal const string GroupA = "S-1-5-21-1-2-3-1200";
    internal const string GroupB = "S-1-5-21-1-2-3-1201";
    internal static readonly string RegistryCse =
        "[" + GpoClientSideExtensionCatalog.RegistryCse.ToString("B") + "{00000000-0000-0000-0000-000000000001}]";
    internal sealed record Policy(int Id, IReadOnlyList<RegistryPolicyEntry> Entries,
        int Filter = 1, string Flags = "0", string LinkOptions = "0",
        GpoSettingsOutcome Outcome = GpoSettingsOutcome.Read, IReadOnlyList<string>? ParseErrors = null,
        string? Extensions = null, bool NoFilterReference = false, bool ChildDomain = false);

    internal static Guid PolicyGuid(int id) => id == 1 ? GpoSecurityRun.PolicyGuid
        : Guid.Parse($"{id:D8}-aaaa-bbbb-cccc-111111111111");
    internal static string PolicyDn(Policy policy) => policy.Id == 1 ? GpoSecurityRun.Policy
        : $"CN={{{policy.Id:D8}-1111-2222-3333-444444444444}},CN=Policies,CN=System," + (policy.ChildDomain ? Child : Parent);
    internal static string PathOf(Policy policy) =>
        @"\\" + (policy.ChildDomain ? "child.example.test" : "example.test") + @"\SYSVOL\Policies\" + policy.Id;
    internal static string FilterId(int id) => $"{{{id:D8}-1111-2222-3333-555555555555}}";

    internal static string Build(IReadOnlyList<Policy> policies, string? links = null)
    {
        var first = policies.Single(policy => policy.Id == 1);
        var options = new Options
        {
            Derive = false,
            DomainLinks = links ?? string.Concat(policies.Reverse().Select(policy =>
                "[LDAP://" + PolicyDn(policy) + ";" + policy.LinkOptions + "]")),
            PolicyAttributes = Attributes(first),
            RegistryPolicies = policies.Select(policy => (PolicyGuid(policy.Id), PathOf(policy),
                new GpoRegistrySettings(policy.Entries, policy.Outcome,
                    policy.Outcome == GpoSettingsOutcome.Read ? null : "Recorded incomplete registry acquisition.")
                    { ParseErrors = policy.ParseErrors ?? [] })).ToArray(),
        };
        var others = new List<OtherObject>();
        foreach (var policy in policies.Where(policy => policy.Id != 1))
            others.Add(new(PolicyDn(policy), PolicyGuid(policy.Id),
                [Text("objectClass", "top", "container", "groupPolicyContainer"), .. Attributes(policy)], true));
        const string query = "SELECT * FROM Win32_OperatingSystem WHERE ProductType = 3";
        var wrapper = FormattableString.Invariant($"1;3;10;{query.Length};WQL;root\\CIMv2;{query};");
        foreach (var id in policies.Select(policy => policy.Filter).Distinct())
            others.Add(new("CN=" + FilterId(id) + ",CN=SOM,CN=WMIPolicy,CN=System," + Parent,
                Guid.Parse($"{id:D8}-aaaa-bbbb-cccc-555555555555"),
                [Text("objectClass", "top", "msWMI-Som"), Text("msWMI-ID", FilterId(id)),
                    Text("msWMI-Parm2", wrapper)]));
        return GpoSecurityRun.Build(options with { OtherObjects = others });
    }

    private static IReadOnlyList<EvidenceAttribute> Attributes(Policy policy) =>
        [Text("gPCFileSysPath", PathOf(policy)), Text("gPCFunctionalityVersion", "2"),
            Text("versionNumber", "1"), Text("flags", policy.Flags),
            Text("gPCMachineExtensionNames", policy.Extensions ?? RegistryCse),
            .. policy.NoFilterReference ? Array.Empty<EvidenceAttribute>()
                : [Text("gPCWQLFilter", "[example.test;" + FilterId(policy.Filter) + ";0]")]];
    internal static RegistryPolicyEntry Number(string name, uint value) =>
        new(Key, name, (uint)RegistryValueType.Dword, BitConverter.GetBytes(value));
    internal static RegistryPolicyEntry TextValue(string name, string value, string? key = null) =>
        new(key ?? Key, name, (uint)RegistryValueType.String, Encoding.Unicode.GetBytes(value + "\0"));
    private static EvidenceAttribute Text(string name, params string[] values) =>
        new(name, StoredAttributeCompleteness.Complete, values.Select(EvidenceValue.OfText).ToArray());
}
