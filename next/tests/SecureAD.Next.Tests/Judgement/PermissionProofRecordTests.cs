using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Judgement;
using Xunit;

namespace SecureAD.Next.Tests.Judgement;

public sealed class PermissionProofRecordTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void SharedPermissionRecordsKeepLargeTextNulsAndEveryOriginalCallbackByte(bool large)
    {
        var name = (large ? new string('x', 3 * 65536 - 1) : "Exact") + "\U0001f512\0\uFEFF";
        var data = Enumerable.Range(0, large ? 2 * 65536 + 17 : 7).Select(value => (byte)value).ToArray();
        var first = FullControlEvaluatorTests.Allow(0) with
        {
            Trustee = FullControlEvaluatorTests.Allow(0).Trustee with { Name = name },
            ApplicationData = data,
        };
        var second = first with { Ordinal = 7, ApplicationData = data.ToArray() };
        var directory = FullControlStorageTests.Store([FullControlStorageTests.Evaluation(first, second)]);
        using var reader = FullControlStorageTests.Open(directory);
        var page = reader.ReadControlEdges(null, null, null, true, 0);
        var assessment = Assert.Single(page.FullControlAssessments);
        Assert.Equal(new[] { 0, 7 }, assessment.Source.Entries.Select(entry => entry.Ordinal));
        Assert.All(assessment.Source.Entries, entry =>
        {
            Assert.Equal(name, entry.Trustee.Name);
            Assert.Equal(data, entry.ApplicationData);
        });
        var selected = AnalysisStoreLifecycle.Resolve(directory, AnalysisStoreKind.Judgement).Value;
        using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = BundleLayout.AnalysisSegmentDataPath(directory, selected, StoreSegmentRole.PermissionProof),
            Mode = SqliteOpenMode.ReadOnly, Pooling = false,
        }.ToString());
        connection.Open();
        using var query = connection.CreateCommand();
        query.CommandText = "SELECT COUNT(*) FROM permission_entry";
        Assert.Equal(1L, query.ExecuteScalar());
        query.CommandText = "SELECT CAST(name AS BLOB),application_data FROM permission_entry";
        using (var read = query.ExecuteReader())
        {
            Assert.True(read.Read());
            Assert.Equal(Encoding.UTF8.GetBytes(name), (byte[])read.GetValue(0));
            Assert.Equal(SHA256.HashData(data), SHA256.HashData((byte[])read.GetValue(1)));
        }
        query.CommandText = "SELECT COUNT(*) FROM sqlite_schema WHERE name LIKE 'requested_detail_record%'";
        Assert.Equal(0L, query.ExecuteScalar());
    }
}
