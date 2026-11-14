using SecureAD.Audit.Capture;
using SecureAD.Audit.Sysvol;
using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using SecureAD.Kernel;

namespace SecureAD.Next.Tests.Sysvol;

internal static class GpoProtocolRun
{
    internal static readonly Guid PolicyGuid = new("11111111-2222-3333-4444-555555555555");
    internal const string Parent = "DC=example,DC=test";
    internal const string PolicyDn = "CN={aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee},CN=Policies,CN=System," + Parent;
    internal const string PolicyPath = @"\\example.test\SYSVOL\example.test\Policies\{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}";
    internal static readonly DateTimeOffset Captured = new(2026, 9, 3, 9, 0, 0, TimeSpan.Zero);
    internal static byte[] Descriptor =>
    [
        0x01, 0x00, 0x04, 0x80, 0x14, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x2C, 0x00, 0x00, 0x00,
        0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x12, 0x00, 0x00, 0x00,
        0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x12, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    internal static void WritePolicy(BundleWriter writer, string functionality = "2", string flags = "0",
        string directoryVersion = "65537", bool duplicate = false)
    {
        var coverage = new PartitionCoverage(Parent, NamingContextKind.Domain, "dc.example.test",
            ConnectionSecurityLevel.SignedAndSealed, duplicate ? 3 : 2, 1, 0, [], false);
        writer.WriteCoverage(coverage);
        writer.WriteObject(new(coverage, Parent, Guid.NewGuid(), [Text("objectClass", "top", "domainDNS")], Captured));
        writer.WriteObject(new(coverage, PolicyDn, PolicyGuid,
        [
            Text("objectClass", "top", "container", "groupPolicyContainer"), Text("gPCFileSysPath", PolicyPath),
            Text("gPCFunctionalityVersion", functionality), Text("flags", flags), Text("versionNumber", directoryVersion),
        ], Captured));
        if (duplicate) writer.WriteObject(new(coverage, "CN=Duplicate policy,CN=System," + Parent, PolicyGuid,
            [Text("objectClass", "top", "container", "groupPolicyContainer"), Text("gPCFileSysPath", PolicyPath)], Captured));
    }

    internal static RunCoverage Coverage(SysvolCoverage sysvol) => RunCoverage.Of(
        CoverageId.ForDomains("example.test", ["example.test"]), [DomainCoverage.Read("example.test")],
        [
            ForestPartitionCoverage.Read("CN=Configuration," + Parent, NamingContextKind.Configuration),
            ForestPartitionCoverage.Read("CN=Schema,CN=Configuration," + Parent, NamingContextKind.Schema),
        ], sysvol);

    internal static GpoInventory Inventory()
    {
        var inventory = new GpoInventory();
        inventory.Observe(CapturedObject.Create(PolicyDn,
        [
            new("objectClass", ["top", "container", "groupPolicyContainer"], AttributeCompleteness.Complete, null),
            new("displayName", ["Captured policy"], AttributeCompleteness.Complete, null),
            new("gPCFileSysPath", [PolicyPath], AttributeCompleteness.Complete, null),
        ]), PolicyGuid);
        return inventory;
    }

    internal static async Task<(string Directory, SysvolCoverage Coverage)> CaptureAsync(ISysvolFileReader reader, CancellationToken token = default)
    {
        var directory = TempDirectories.Create("gpo-protocol-inputs");
        using var writer = BundleWriter.Create(directory, Captured);
        WritePolicy(writer);
        var coverage = await new SysvolCapture(reader, writer, RunLog.Discarded, TimeProvider.System).ReadAsync(Inventory(), token);
        writer.Complete(Coverage(coverage), Captured.AddMinutes(1));
        return (directory, coverage);
    }

    internal static string Build(GpoTemplateVersionObservation? observation, string? resource = null, bool duplicate = false)
    {
        var directory = TempDirectories.Create("gpo-protocol-stored");
        using var writer = BundleWriter.Create(directory, Captured);
        WritePolicy(writer, duplicate: duplicate);
        if (observation is not null) writer.WriteGpoTemplateVersion(PolicyGuid, resource ?? PolicyPath, observation);
        writer.Complete(Coverage(SysvolCoverage.Of([])), Captured.AddMinutes(1));
        return directory;
    }

    private static EvidenceAttribute Text(string name, params string[] values) =>
        new(name, StoredAttributeCompleteness.Complete, values.Select(EvidenceValue.OfText).ToArray());
}
