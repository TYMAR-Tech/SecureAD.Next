using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using SecureAD.Kernel;
using Xunit;
using static SecureAD.Next.Tests.Judgement.GpoSecurityRun;

namespace SecureAD.Next.Tests.Judgement;

internal static class GpoHierarchyRun
{
    internal const string ParentOu = "OU=Parent," + Parent;
    internal const string LeafOu = "OU=Leaf," + ParentOu;
    internal const string Subject = "CN=Computer," + LeafOu;
    internal sealed record Container(string Dn, string? Links = null, string? Inheritance = null,
        string Class = "organizationalUnit", bool NoGuid = false);
    internal sealed record PolicyRow(int Id, bool ChildDomain = false, string Class = "groupPolicyContainer");
    internal sealed record Options
    {
        internal IReadOnlyList<Container> Containers { get; init; } =
            [new(LeafOu), new(ParentOu), new(Parent, Class: "domainDNS")];
        internal IReadOnlyList<PolicyRow> Policies { get; init; } = Enumerable.Range(1, 6).Select(id => new PolicyRow(id)).ToArray();
        internal string ComputerDn { get; init; } = Subject;
        internal string ComputerClass { get; init; } = "computer";
        internal bool ComputerNoGuid { get; init; }
    }
    internal static string PolicyDn(int id, bool child = false) =>
        $"CN={{{id:D8}-1111-2222-3333-444444444444}},CN=Policies,CN=System," + (child ? Child : Parent);
    internal static string Link(int id, string options = "0", bool child = false) =>
        "[LDAP://" + PolicyDn(id, child) + ";" + options + "]";
    internal static Options Links(string? leaf = null, string? parent = null, string? domain = null,
        string? leafOptions = null, string? parentOptions = null) => new()
        {
            Containers = [new(LeafOu, leaf, leafOptions), new(ParentOu, parent, parentOptions),
                new(Parent, domain, Class: "domainDNS")],
        };

    internal static string Build(Options options)
    {
        var directory = TempDirectories.Create("gpo-hierarchy");
        var parentCount = options.Containers.Count(row => !InChild(row.Dn))
            + options.Policies.Count(row => !row.ChildDomain) + (InChild(options.ComputerDn) ? 0 : 1);
        var childCount = 1 + options.Containers.Count(row => InChild(row.Dn))
            + options.Policies.Count(row => row.ChildDomain) + (InChild(options.ComputerDn) ? 1 : 0);
        var parent = new PartitionCoverage(Parent, NamingContextKind.Domain, "dc.example.test",
            ConnectionSecurityLevel.SignedAndSealed, parentCount, 1, 0, [], false);
        var child = new PartitionCoverage(Child, NamingContextKind.Domain, "dc.child.example.test",
            ConnectionSecurityLevel.SignedAndSealed, childCount, 1, 0, [], false);
        using var writer = BundleWriter.Create(directory, Captured);
        writer.WriteCoverage(parent);
        writer.WriteCoverage(child);
        writer.WriteObject(new(child, Child, Guid.NewGuid(), [Text("objectClass", "top", "domainDNS")], Captured));
        foreach (var row in options.Containers)
        {
            var attributes = new List<EvidenceAttribute> { Text("objectClass", "top", row.Class) };
            if (row.Links is not null) attributes.Add(Text("gPLink", row.Links));
            if (row.Inheritance is not null) attributes.Add(Text("gPOptions", row.Inheritance));
            writer.WriteObject(new(InChild(row.Dn) ? child : parent, row.Dn, row.NoGuid ? null : Guid.NewGuid(), attributes, Captured));
        }
        writer.WriteObject(new(InChild(options.ComputerDn) ? child : parent, options.ComputerDn,
            options.ComputerNoGuid ? null : ComputerGuid,
            [Text("objectClass", "top", "person", "organizationalPerson", "user", options.ComputerClass)], Captured));
        foreach (var row in options.Policies)
            writer.WriteObject(new(row.ChildDomain ? child : parent, PolicyDn(row.Id, row.ChildDomain), Guid.NewGuid(),
                [Text("objectClass", "top", "container", row.Class)], Captured));
        writer.Complete(RunCoverage.Of(CoverageId.ForDomains("example.test", ["example.test", "child.example.test"]),
            [DomainCoverage.Read("example.test"), DomainCoverage.Read("child.example.test")],
            [
                ForestPartitionCoverage.Read("CN=Configuration," + Parent, NamingContextKind.Configuration),
                ForestPartitionCoverage.Read("CN=Schema,CN=Configuration," + Parent, NamingContextKind.Schema),
            ], SysvolCoverage.Of([])), Captured.AddMinutes(1));
        return directory;
    }

    private static bool InChild(string dn) => dn.EndsWith(Child, StringComparison.OrdinalIgnoreCase);
    private static EvidenceAttribute Text(string name, params string[] values) =>
        new(name, StoredAttributeCompleteness.Complete, values.Select(EvidenceValue.OfText).ToArray());
}
