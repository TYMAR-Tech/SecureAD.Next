using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using SecureAD.Kernel.Capture;
using Xunit;
using Xunit.Abstractions;

namespace SecureAD.Next.Tests.Evidence;

public sealed class CaptureObjectScopeStorageTests(ITestOutputHelper output)
{
    [Theory]
    [InlineData(false, "dnsNode,dnsZone,enatelSSOAccount,enatelSSOAccountParameter,enatelSSOStorage,enatelUserManagedAuth")]
    [InlineData(true, "dnsNode,dnsZone")]
    public void ASealedBundleRecordsTheScopeActuallySelected(bool includeEnatelSso, string expected)
    {
        var directory = WriteBundle(CaptureObjectScope.For(includeEnatelSso));

        using var reader = BundleReader.Open(directory).Value;

        Assert.Equal(expected, string.Join(",", reader.Description.ExcludedObjectClasses));
    }

    [Fact]
    public void TheDefaultWriterRecordsTheDefaultClassScope()
    {
        var directory = NewDirectory();
        using (var writer = BundleWriter.Create(directory, DateTimeOffset.UnixEpoch))
            writer.Complete(Coverage(), DateTimeOffset.UnixEpoch);

        using var reader = BundleReader.Open(directory).Value;

        Assert.Equal("dnsNode,dnsZone,enatelSSOAccount,enatelSSOAccountParameter,enatelSSOStorage,enatelUserManagedAuth",
            string.Join(",", reader.Description.ExcludedObjectClasses));
        Assert.Equal(16, reader.Description.SchemaVersion);
    }

    [Fact]
    public void MissingScopeDoesNotMeanThatAllClassesWereCaptured()
    {
        var directory = WriteBundle(CaptureObjectScope.Default);
        ModifyAndSeal(directory, "DELETE FROM capture_object_class_exclusion");

        var error = OpenError(directory);

        Assert.Equal("Evidence.EvidenceUnreadable", error);
    }

    [Fact]
    public void AnOlderFormatIsRefusedBeforeReadingTheNewScopeTable()
    {
        var directory = WriteBundle(CaptureObjectScope.WithEnatelSso);
        ModifyAndSeal(directory,
            "DROP TABLE capture_object_class_exclusion; UPDATE bundle SET schema_version = 11;");

        var error = OpenError(directory);

        Assert.Equal("Evidence.SchemaVersionUnsupported", error);
    }

    [Fact]
    public void ThePreviousStorageScopeIsRefusedByFormatRatherThanRelabelled()
    {
        var directory = WriteBundle(CaptureObjectScope.Default);
        ModifyAndSeal(directory,
            "UPDATE bundle SET schema_version=14; "
            + "DELETE FROM capture_object_class_exclusion WHERE class_name='enatelSSOAccount'; "
            + "UPDATE capture_object_class_exclusion SET class_name='enatelSSOStorageV3' "
            + "WHERE class_name='enatelSSOStorage';");

        Assert.Equal("Evidence.SchemaVersionUnsupported", OpenError(directory));
    }

    [Fact]
    public void TheObsoleteStorageNameCannotClaimTheCorrectedFormat()
    {
        var directory = WriteBundle(CaptureObjectScope.Default);
        ModifyAndSeal(directory,
            "UPDATE capture_object_class_exclusion SET class_name='enatelSSOStorageV3' "
            + "WHERE class_name='enatelSSOStorage';");

        Assert.Equal("Evidence.EvidenceUnreadable", OpenError(directory));
    }

    [Fact]
    public void TheStorageOnlyFormatIsRefusedRatherThanRelabelled()
    {
        var directory = WriteBundle(CaptureObjectScope.Default);
        ModifyAndSeal(directory,
            "UPDATE bundle SET schema_version=15; "
            + "DELETE FROM capture_object_class_exclusion WHERE class_name='enatelSSOAccount';");

        Assert.Equal("Evidence.SchemaVersionUnsupported", OpenError(directory));
    }

    [Fact]
    public void TheStorageOnlyScopeCannotClaimTheAccountExcludingFormat()
    {
        var directory = WriteBundle(CaptureObjectScope.Default);
        ModifyAndSeal(directory,
            "DELETE FROM capture_object_class_exclusion WHERE class_name='enatelSSOAccount';");

        Assert.Equal("Evidence.EvidenceUnreadable", OpenError(directory));
    }

    private string WriteBundle(CaptureObjectScope scope)
    {
        var directory = NewDirectory();
        using var writer = BundleWriter.Create(directory, DateTimeOffset.UnixEpoch);
        writer.Complete(Coverage(), DateTimeOffset.UnixEpoch, ContinuationReconciliation.NotPerformed, scope);
        return directory;
    }

    private string NewDirectory()
    {
        var directory = Path.Combine(Path.GetTempPath(), "securead-p224-" + Guid.NewGuid().ToString("N"));
        output.WriteLine(directory);
        return directory;
    }

    private static RunCoverage Coverage() => RunCoverage.Of(
        CoverageId.ForDomains("example.com", ["example.com"]),
        [DomainCoverage.Read("example.com")],
        [ForestPartitionCoverage.Read("CN=Configuration,DC=example,DC=com", NamingContextKind.Configuration),
         ForestPartitionCoverage.Read("CN=Schema,CN=Configuration,DC=example,DC=com", NamingContextKind.Schema)],
        SysvolCoverage.Of([]));

    private static void ModifyAndSeal(string directory, string sql)
    {
        using (var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = BundleLayout.EvidencePath(directory), Mode = SqliteOpenMode.ReadWrite, Pooling = false,
        }.ToString()))
        {
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = sql;
            command.ExecuteNonQuery();
        }
        BundleSealing.Seal(BundleLayout.EvidencePath(directory), BundleLayout.SealPath(directory));
    }

    private static string? OpenError(string directory)
    {
        var result = BundleReader.Open(directory);
        if (!result.IsSuccess)
            return result.Error.Code;
        result.Value.Dispose();
        return null;
    }
}
