using System.Security.AccessControl;
using System.Text.Json;
using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using SecureAD.Kernel.Capture;
using SecureAD.Kernel.Security;
using Xunit;

namespace SecureAD.Next.Tests.Evidence;

public sealed class BulkObjectLookupTests
{
    private const string Domain = "DC=lookup,DC=test";
    private const string Alice = "CN=Alice," + Domain;
    private const string Bob = "CN=Bob," + Domain;
    private static readonly DateTimeOffset When = new(2026, 9, 17, 0, 0, 0, TimeSpan.Zero);

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void RowIdentityPreservesWholeAttributesAndRawPermissions(bool duplicateGuid)
    {
        var guid = Guid.NewGuid();
        var directory = Write([(Alice, duplicateGuid ? guid : null, 16), (Bob, guid, 32)]);
        using var reference = Open(directory);
        using var bulk = Open(directory);
        bulk.PrepareBulkObjectLookup();
        foreach (var name in new[] { Alice, Bob }) AssertSame(reference, bulk, name);
        Assert.Equal(16, Assert.Single(bulk.ReadPermissions(Alice)!.Entries).AccessMask);
        Assert.Equal(32, Assert.Single(bulk.ReadPermissions(Bob)!.Entries).AccessMask);
        Assert.NotEqual(JsonSerializer.Serialize(bulk.ReadObjectAttributes(Alice)), JsonSerializer.Serialize(bulk.ReadObjectAttributes(Bob)));
    }

    [Theory]
    [InlineData("same-spelling")]
    [InlineData("case-ambiguous")]
    [InlineData("unicode")]
    [InlineData("escaped")]
    public void NameResolutionRetainsTheOriginalSqliteSelection(string scenario)
    {
        string[] names = scenario switch
        {
            "same-spelling" => [Alice, Alice],
            "case-ambiguous" => [Alice.ToLowerInvariant(), Alice],
            "unicode" => ["CN=Älice," + Domain, "CN=älice," + Domain],
            _ => [@"CN=Smith\, Jane," + Domain, @"CN=Smith\, John," + Domain],
        };
        var directory = Write([(names[0], Guid.NewGuid(), 16), (names[1], Guid.NewGuid(), 32)]);
        using var reference = Open(directory);
        using var bulk = Open(directory);
        bulk.PrepareBulkObjectLookup();
        foreach (var name in names)
        {
            AssertSame(reference, bulk, name);
            AssertSame(reference, bulk, name.Replace("CN=", "cn=", StringComparison.Ordinal));
            AssertSame(reference, bulk, name.ToUpperInvariant());
        }
    }

    [Fact]
    public void MissingObjectsAndMissingDescriptorsRemainDifferent()
    {
        var directory = Write([(Alice, null, 0)]);
        using var reference = Open(directory);
        using var bulk = Open(directory);
        bulk.PrepareBulkObjectLookup();
        AssertSame(reference, bulk, Alice);
        Assert.NotNull(bulk.ReadObjectAttributes(Alice));
        Assert.NotNull(bulk.ReadPermissions(Alice));
        Assert.Null(bulk.ReadObjectAttributes(Bob));
        Assert.Null(bulk.ReadPermissions(Bob));
    }

    [Fact]
    public void LookupBelongsToItsReaderAndRejectsUseAfterDisposal()
    {
        var first = Write([(Alice, null, 16), (Bob, null, 32)]);
        var second = Write([(Bob, null, 64), (Alice, null, 128)]);
        using var reader1 = Open(first);
        using var reader2 = Open(second);
        using var reference2 = Open(second);
        reader1.PrepareBulkObjectLookup();
        reader2.PrepareBulkObjectLookup();
        Assert.Equal(16, Assert.Single(reader1.ReadPermissions(Alice)!.Entries).AccessMask);
        Assert.Equal(128, Assert.Single(reader2.ReadPermissions(Alice)!.Entries).AccessMask);
        AssertSame(reference2, reader2, Alice);
        reader1.Dispose();
        Assert.Throws<ObjectDisposedException>(() => reader1.PrepareBulkObjectLookup());
        Assert.Throws<ObjectDisposedException>(() => reader1.ReadPermissions(Alice));
        Assert.Throws<ObjectDisposedException>(() => reader1.ReadObjectAttributes(Alice));
        AssertSame(reference2, reader2, Bob);
    }

    [Fact]
    public void RepeatedPreparationIsPassiveAndKeepsFreshEvidenceValues()
    {
        var directory = Write([(Alice, null, 16), (Bob, null, 32)]);
        var before = BundleSealing.HashFile(BundleLayout.EvidencePath(directory));
        using var reference = Open(directory);
        using var bulk = Open(directory);
        bulk.PrepareBulkObjectLookup();
        var first = bulk.ReadObjectAttributes(Alice);
        bulk.PrepareBulkObjectLookup();
        Assert.NotSame(first, bulk.ReadObjectAttributes(Alice));
        AssertSame(reference, bulk, Alice);
        AssertSame(reference, bulk, Bob);
        Assert.Equal(before, BundleSealing.HashFile(BundleLayout.EvidencePath(directory)));
    }

    private static void AssertSame(BundleReader reference, BundleReader bulk, string name)
    {
        Assert.Equal(JsonSerializer.Serialize(reference.ReadObjectAttributes(name)), JsonSerializer.Serialize(bulk.ReadObjectAttributes(name)));
        Assert.Equal(JsonSerializer.Serialize(reference.ReadPermissions(name)), JsonSerializer.Serialize(bulk.ReadPermissions(name)));
    }

    private static BundleReader Open(string directory)
    {
        var opened = BundleReader.Open(directory);
        Assert.True(opened.IsSuccess, opened.Error?.Description);
        return opened.Value;
    }

    private static string Write((string Dn, Guid? Guid, int Mask)[] objects)
    {
        var directory = Path.Combine(AppContext.BaseDirectory, "p242-lookup-checks", Guid.NewGuid().ToString("N"));
        using var writer = BundleWriter.Create(directory, When);
        for (var i = 0; i < objects.Length; i++)
        {
            var item = objects[i];
            var coverage = new PartitionCoverage(Domain, NamingContextKind.Domain, $"dc{i}.lookup.test",
                i == 0 ? ConnectionSecurityLevel.SignedAndSealed : ConnectionSecurityLevel.Signed, 1, 1, 1, [], false);
            writer.WriteCoverage(coverage);
            var id = writer.WriteObject(new(coverage, item.Dn, item.Guid,
                [Text("objectClass", "top", "user"), Text("sAMAccountName", $"user{i}"), Text("description", "one", "two"),
                 new("objectSid", StoredAttributeCompleteness.Complete, [EvidenceValue.OfBytes(Sid.ToBytes($"S-1-5-21-10-20-30-{1000 + i}")!)])], When));
            if (item.Mask == 0) continue;
            var raw = new RawSecurityDescriptor($"O:SYG:SYD:(A;;0x{item.Mask:X};;;AU)");
            var bytes = new byte[raw.BinaryLength];
            raw.GetBinaryForm(bytes, 0);
            writer.WriteSecurityDescriptor(id, bytes, AceNormalizer.Normalize(item.Guid ?? Guid.Empty, SecurityDescriptorParser.Parse(bytes)));
        }
        writer.Complete(RunCoverage.Of(CoverageId.ForDomains("lookup.test", ["lookup.test"]), [DomainCoverage.Read("lookup.test")],
            [ForestPartitionCoverage.Read("CN=Configuration," + Domain, NamingContextKind.Configuration),
             ForestPartitionCoverage.Read("CN=Schema,CN=Configuration," + Domain, NamingContextKind.Schema)], SysvolCoverage.Of([])), When.AddMinutes(1));
        return directory;
    }

    private static EvidenceAttribute Text(string name, params string[] values) =>
        new(name, StoredAttributeCompleteness.Complete, values.Select(EvidenceValue.OfText).ToArray());
}
