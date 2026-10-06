using System.Reflection;
using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Judgement;
using Xunit;
using static SecureAD.Next.Tests.Judgement.SelfMembershipDiscoveryTests;

namespace SecureAD.Next.Tests.Judgement;

public sealed partial class PathInputTests
{
    [Fact]
    public void CompletePathSourceValidationUsesTheGroupedWitnessReading()
    {
        var directory = Captured("O:SYG:SYD:(A;;WD;;;WD)(A;;WD;;;WD)");
        Derive(directory);
        Judge(directory);
        using var fixture = new ValidationFixture(directory);
        Assert.NotEmpty(fixture.Inputs.UncertaintyRegions);
        fixture.Validate(fixture.Inputs);
        using var trace = new JudgingInputReuseTests.Statements(fixture.EvidenceConnection);
        trace.Sql.Clear();
        fixture.Validate(fixture.Inputs);
        var single = trace.Sql.Count(sql => sql.StartsWith("SELECT s.descriptor_id,", StringComparison.Ordinal));
        trace.Sql.Clear();

        fixture.Validate(fixture.Inputs with
        { UncertaintyRegions = [.. Enumerable.Range(0, 8).SelectMany(_ => fixture.Inputs.UncertaintyRegions)] });

        Assert.True(single > 0);
        Assert.Equal(single, trace.Sql.Count(sql => sql.StartsWith("SELECT s.descriptor_id,", StringComparison.Ordinal)));
    }

    [Fact]
    public void CompletePathSourceValidationDoesNotSkipContradictoryWitnesses()
    {
        var directory = Captured("O:SYG:SYD:(A;;WD;;;WD)");
        Derive(directory);
        Judge(directory);
        using var fixture = new ValidationFixture(directory);
        var original = fixture.Inputs.UncertaintyRegions.First(region => region.Source.TargetDn == CoreDn && region.Source.PermissionOrdinal.HasValue);
        var wrong = original with { Source = original.Source with { PermissionOrdinal = 99 } };
        var inputs = fixture.Inputs with { UncertaintyRegions = [.. fixture.Inputs.UncertaintyRegions, wrong] };

        Assert.Throws<InvalidDataException>(() => fixture.Validate(inputs));
    }

    private sealed class ValidationFixture : IDisposable
    {
        private readonly JudgementReader _reader;
        private readonly SqliteConnection _connection;
        private readonly JudgingInputs _sources;
        private readonly OwnershipAuditStorage.Snapshot? _ownership;
        internal PathInputs Inputs { get; }
        internal SqliteConnection EvidenceConnection => Assert.IsType<SqliteConnection>(
            typeof(BundleReader).GetField("_connection", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(_sources.Bundle));

        internal ValidationFixture(string directory)
        {
            _reader = Open(directory);
            _connection = new SqliteConnection(new SqliteConnectionStringBuilder
            {
                DataSource = BundleLayout.AnalysisGenerationDataPath(directory, AnalysisStoreKind.Judgement, _reader.Description.GenerationId),
                Mode = SqliteOpenMode.ReadOnly, Pooling = false,
            }.ToString());
            _connection.Open();
            _sources = ControlProofVerification.OpenSources(_reader);
            Inputs = PathInputStorage.Read(_connection, _reader.Description, out _ownership, CancellationToken.None);
        }

        internal void Validate(PathInputs inputs) =>
            PathInputStorage.ValidateSources(_connection, _reader.Description, _sources, _ownership, inputs, CancellationToken.None);

        public void Dispose()
        {
            _sources.Dispose();
            _connection.Dispose();
            _reader.Dispose();
        }
    }
}
