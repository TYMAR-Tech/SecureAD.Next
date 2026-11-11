using System.Text;
using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Next.Tests.Sysvol;
using Xunit;
using static SecureAD.Next.Tests.Sysvol.GpoProtocolRun;

namespace SecureAD.Next.Tests.Evidence;

public sealed class GpoProtocolInputTests
{
    [Fact]
    public void GpoProtocolDirectoryValuesAndZeroTemplateVersionRemainOriginalInputs()
    {
        var bytes = Encoding.ASCII.GetBytes("[General]\r\nVersion= 0000 \r\n");
        var directory = Build(new(GpoTemplateVersionOutcome.Read, bytes, " 0000 ", 0, null));
        using var reader = BundleReader.Open(directory).Value;
        var before = BundleSealing.HashFile(BundleLayout.EvidencePath(directory));
        var selected = reader.ReadObjectIdentity(PolicyDn)!;
        var value = reader.ReadGpoProtocolInputs(selected with { ObjectClass = "user", DomainFqdn = "wrong.test" }, CancellationToken.None).Value;
        Assert.Equal(selected, value.Policy);
        Assert.Equal("2", value.PolicyValues.Find("gPCFunctionalityVersion")!.OnlyValue!.Text);
        Assert.Equal("0", value.PolicyValues.Find("flags")!.OnlyValue!.Text);
        Assert.Equal("65537", value.PolicyValues.Find("versionNumber")!.OnlyValue!.Text);
        Assert.Equal(0u, value.TemplateVersion.Version);
        Assert.Equal(" 0000 ", value.TemplateVersion.OriginalVersion);
        Assert.Equal(bytes, value.TemplateVersion.OriginalBytes!.Value.ToArray());
        Assert.Equal(selected.CaptureGenerationId, value.CaptureGenerationId);
        Assert.Equal(before, BundleSealing.HashFile(BundleLayout.EvidencePath(directory)));
    }

    [Theory]
    [InlineData(GpoTemplateVersionOutcome.Unavailable)]
    [InlineData(GpoTemplateVersionOutcome.Missing)]
    [InlineData(GpoTemplateVersionOutcome.Unreadable)]
    [InlineData(GpoTemplateVersionOutcome.Invalid)]
    public void GpoProtocolSavedNonReadAnswersDoNotBecomeZeroOrNoFile(GpoTemplateVersionOutcome outcome)
    {
        var directory = Build(new(outcome, outcome == GpoTemplateVersionOutcome.Invalid ? Encoding.ASCII.GetBytes("unusable") : null,
            null, null, "Captured reason"));
        using var reader = BundleReader.Open(directory).Value;
        var version = reader.ReadGpoProtocolInputs(reader.ReadObjectIdentity(PolicyDn)!, CancellationToken.None).Value.TemplateVersion;
        Assert.Equal(outcome, version.Outcome);
        Assert.Null(version.Version);
        Assert.Equal("Captured reason", version.Reason);
        Assert.NotNull(version.Error);
    }

    [Fact]
    public void GpoProtocolNoAcquisitionRecordIsExplicitlyNotCaptured()
    {
        using var reader = BundleReader.Open(Build(null)).Value;
        var version = reader.ReadGpoProtocolInputs(reader.ReadObjectIdentity(PolicyDn)!, CancellationToken.None).Value.TemplateVersion;
        Assert.Equal(GpoTemplateVersionOutcome.NotCaptured, version.Outcome);
        Assert.Null(version.Version);
        Assert.Equal("Evidence.GpoTemplateVersionNotCaptured", version.Error!.Code);
    }

    [Fact]
    public void GpoProtocolTemplateObservationCannotBindToAnotherResourcePath()
    {
        var directory = Build(new(GpoTemplateVersionOutcome.Read, Encoding.ASCII.GetBytes("[General]\r\nVersion=1\r\n"), "1", 1, null),
            @"\\another.test\SYSVOL\another.test\Policies\{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}");
        using var reader = BundleReader.Open(directory).Value;
        var result = reader.ReadGpoProtocolInputs(reader.ReadObjectIdentity(PolicyDn)!, CancellationToken.None);
        Assert.False(result.IsSuccess);
        Assert.Equal("Evidence.GpoTemplateVersionResourceMismatch", result.Error.Code);
    }

    [Fact]
    public void GpoProtocolDuplicatePolicyGuidCannotBindAnArbitraryVersionObservation()
    {
        using var reader = BundleReader.Open(Build(new(GpoTemplateVersionOutcome.Read,
            Encoding.ASCII.GetBytes("[General]\r\nVersion=1\r\n"), "1", 1, null), duplicate: true)).Value;
        var result = reader.ReadGpoProtocolInputs(reader.ReadObjectIdentity(PolicyDn)!, CancellationToken.None);
        Assert.False(result.IsSuccess);
        Assert.Equal("Evidence.GpoProtocolPolicyAmbiguous", result.Error.Code);
    }

    [Fact]
    public void GpoProtocolUnreturnedFunctionalityValueIsNotReplacedBySupportedVersionTwo()
    {
        var directory = Build(null);
        using (var connection = new SqliteConnection("Data Source=" + BundleLayout.EvidencePath(directory) + ";Pooling=False"))
        {
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = "UPDATE captured_object SET " + BundleSchema.ColumnNameFor("gPCFunctionalityVersion")
                + "=NULL WHERE distinguished_name=$dn";
            command.Parameters.AddWithValue("$dn", PolicyDn);
            Assert.Equal(1, command.ExecuteNonQuery());
            command.CommandText = "PRAGMA wal_checkpoint(TRUNCATE)";
            command.ExecuteNonQuery();
        }
        TestSealing.ResealCapture(directory);
        using var reader = BundleReader.Open(directory).Value;
        var value = reader.ReadGpoProtocolInputs(reader.ReadObjectIdentity(PolicyDn)!, CancellationToken.None).Value;
        Assert.False(value.PolicyValues.Find("gPCFunctionalityVersion")!.HasValue);
    }

    [Theory]
    [InlineData("no-bytes")]
    [InlineData("nonread-value")]
    [InlineData("wrong-original")]
    public void GpoProtocolWriterRejectsInconsistentObservationsRatherThanSavingSuccess(string defect)
    {
        var bytes = Encoding.ASCII.GetBytes("[General]\r\nVersion=1\r\n");
        var observation = defect switch
        {
            "no-bytes" => new GpoTemplateVersionObservation(GpoTemplateVersionOutcome.Read, null, "1", 1, null),
            "nonread-value" => new(GpoTemplateVersionOutcome.Missing, null, null, 0, "missing"),
            "wrong-original" => new(GpoTemplateVersionOutcome.Read, bytes, "2", 1, null),
            _ => throw new ArgumentOutOfRangeException(nameof(defect)),
        };
        Assert.Throws<ArgumentException>(() => Build(observation));
    }

    [Fact]
    public void GpoProtocolSelectedIdentityCannotCrossCaptureAndCancellationIsHonored()
    {
        using var first = BundleReader.Open(Build(null)).Value;
        using var second = BundleReader.Open(Build(null)).Value;
        var selected = first.ReadObjectIdentity(PolicyDn)!;
        Assert.Throws<InvalidDataException>(() => second.ReadGpoProtocolInputs(selected, CancellationToken.None));
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();
        Assert.Throws<OperationCanceledException>(() => first.ReadGpoProtocolInputs(selected, cancelled.Token));
    }

    [Fact]
    public void GpoProtocolOlderCaptureFormatIsRefusedWithoutMigration()
    {
        var directory = Build(null);
        using (var connection = new SqliteConnection("Data Source=" + BundleLayout.EvidencePath(directory) + ";Pooling=False"))
        {
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = "UPDATE bundle SET schema_version=17";
            Assert.Equal(1, command.ExecuteNonQuery());
            command.CommandText = "PRAGMA wal_checkpoint(TRUNCATE)";
            command.ExecuteNonQuery();
        }
        TestSealing.ResealCapture(directory);
        var result = BundleReader.Open(directory);
        Assert.False(result.IsSuccess);
        Assert.Contains("SchemaVersion", result.Error.Code, StringComparison.Ordinal);
    }

    [Fact]
    public void GpoProtocolInconsistentSavedReadIsNotReturnedAsAValidVersion()
    {
        var directory = Build(new(GpoTemplateVersionOutcome.Read, Encoding.ASCII.GetBytes("[General]\r\nVersion=1\r\n"), "1", 1, null));
        using (var connection = new SqliteConnection("Data Source=" + BundleLayout.EvidencePath(directory) + ";Pooling=False"))
        {
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = "PRAGMA ignore_check_constraints=ON; UPDATE gpo_template_version SET version=NULL";
            Assert.Equal(1, command.ExecuteNonQuery());
            command.CommandText = "PRAGMA wal_checkpoint(TRUNCATE)";
            command.ExecuteNonQuery();
        }
        TestSealing.ResealCapture(directory);
        using var reader = BundleReader.Open(directory).Value;
        Assert.Throws<InvalidDataException>(() => reader.ReadGpoProtocolInputs(reader.ReadObjectIdentity(PolicyDn)!, CancellationToken.None));
    }
}
