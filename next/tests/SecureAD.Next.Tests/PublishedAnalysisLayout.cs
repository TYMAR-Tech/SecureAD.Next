using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Judgement;
using Xunit;

namespace SecureAD.Next.Tests;

internal sealed class PublishedAnalysisLayout
{
    private const string EvidenceSeal = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private static readonly Guid DerivedGeneration = new("11111111-2222-3333-4444-555555555555");
    private readonly string _directory;
    private readonly AnalysisStoreKind _kind;
    private readonly Guid _generation;

    private PublishedAnalysisLayout(string directory, AnalysisStoreKind kind, Guid generation)
    {
        _directory = directory;
        _kind = kind;
        _generation = generation;
    }

    internal IReadOnlyList<StoreSegmentRole> Roles => _kind == AnalysisStoreKind.Derivation
        ? [StoreSegmentRole.Derivation, StoreSegmentRole.Membership]
        : [StoreSegmentRole.Judgement, StoreSegmentRole.PermissionProof, StoreSegmentRole.PathProof, StoreSegmentRole.JudgementFacts];

    private int Version => _kind == AnalysisStoreKind.Derivation ? DerivationSchema.Version : JudgementSchema.Version;
    private string RootPath => Path.Combine(_directory, _kind == AnalysisStoreKind.Derivation
        ? "derivation.current.json" : "judgement.current.json");
    private StoreRootManifest Root => Assert.IsType<StoreRootManifest>(
        JsonSerializer.Deserialize<StoreRootManifest>(File.ReadAllText(RootPath)));

    internal static PublishedAnalysisLayout Create(AnalysisStoreKind kind)
    {
        var directory = TempDirectories.Create("native-layout");
        if (kind == AnalysisStoreKind.Derivation)
        {
            using var writer = DerivationWriter.Create(directory, EvidenceSeal, DateTimeOffset.UnixEpoch);
            writer.WriteSids([], []);
            writer.WriteMembershipInput([], captureComplete: true);
            writer.RecordPhase("MembershipAndNesting", DerivationPhaseOutcome.Succeeded, error: null);
            writer.Complete(DateTimeOffset.UnixEpoch);
            return new(directory, kind, writer.GenerationId);
        }
        Assert.Equal(AnalysisStoreKind.Judgement, kind);
        using var judgement = JudgementWriter.Create(directory, EvidenceSeal, DerivedGeneration,
            DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch);
        judgement.Complete(DateTimeOffset.UnixEpoch);
        return new(directory, kind, judgement.GenerationId);
    }

    internal string Read()
    {
        // Binding values are checked directly; only persisted definitions enter the layout checkpoint.
        CheckDeclarations();
        var layout = new StringBuilder().Append("root ").Append(Root.Version).Append('\n');
        foreach (var role in Roles)
        {
            using (var connection = Open(role, writable: false))
                CheckHeader(connection, role);
            layout.Append(role).Append('\n').Append(Version).Append('\n');
            foreach (var definition in Definitions(role))
                layout.Append(definition);
        }
        return layout.ToString();
    }

    internal void CheckDeclarations()
    {
        var root = Root;
        Binding(root.Version == 4, "root version");
        Binding(root.GenerationId == _generation, "root generation");
        Binding(root.EvidenceSeal == EvidenceSeal, "root evidence");
        Binding(root.Segments.Select(segment => segment.Role).SequenceEqual(Roles), "exact product roles");
        var summary = _kind == AnalysisStoreKind.Derivation
            ? new DerivationBrowseSummary(1, EvidenceSeal, _generation, true, 0) : null;
        Binding(root.DerivationSummary == summary, "derivation summary");
        foreach (var segment in root.Segments)
        {
            Binding(segment.SchemaVersion == Version, "product version");
            Binding(segment.GenerationId == _generation, "product generation");
            Binding(segment.FileName == FileName(segment.Role), "product file");
        }
    }

    internal IReadOnlyList<string> Definitions(StoreSegmentRole role)
    {
        using var connection = Open(role, writable: false);
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT type,name,tbl_name,sql FROM sqlite_schema WHERE sql IS NOT NULL ORDER BY type,name";
        using var reader = command.ExecuteReader();
        var definitions = new List<string>();
        while (reader.Read())
        {
            var definition = new StringBuilder();
            for (var column = 0; column < reader.FieldCount; column++)
                definition.Append(reader.GetString(column).Replace("\r\n", "\n", StringComparison.Ordinal)).Append('\n');
            definitions.Add(definition.ToString());
        }
        return definitions;
    }

    internal int Execute(StoreSegmentRole role, string sql)
    {
        using var connection = Open(role, writable: true);
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        return command.ExecuteNonQuery();
    }

    internal void ChangeDeclaration(string change)
    {
        var root = Root;
        var part = root.Segments[^1];
        StoreRootManifest ChangedPart(SealedStoreSegment replacement) =>
            root with { Segments = root.Segments.Select(segment => segment == part ? replacement : segment).ToArray() };
        var changed = change switch
        {
            "root-version" => root with { Version = root.Version + 1 },
            "root-generation" => root with { GenerationId = Guid.Empty },
            "root-evidence" => root with { EvidenceSeal = "foreign evidence" },
            "missing-role" => root with { Segments = root.Segments.SkipLast(1).ToArray() },
            "duplicate-role" => root with { Segments = root.Segments.Append(part).ToArray() },
            "product-version" => ChangedPart(part with { SchemaVersion = 0 }),
            "product-generation" => ChangedPart(part with { GenerationId = Guid.Empty }),
            "product-file" => ChangedPart(part with { FileName = "foreign.db" }),
            "summary" => root with { DerivationSummary = new(1, EvidenceSeal, Guid.Empty, true, 0) },
            _ => throw new ArgumentOutOfRangeException(nameof(change)),
        };
        File.WriteAllText(RootPath, JsonSerializer.Serialize(changed with { Hash = changed.ComputeHash() }));
    }

    internal void MoveTable(StoreSegmentRole source, StoreSegmentRole destination, string table) =>
        Move(source, destination, table, "TABLE");

    internal void MoveIndex(StoreSegmentRole source, StoreSegmentRole destination, string index) =>
        Move(source, destination, index, "INDEX");

    private void Move(StoreSegmentRole source, StoreSegmentRole destination, string name, string type)
    {
        using var connection = Open(source, writable: true);
        using var command = connection.CreateCommand();
        command.CommandText = type == "TABLE"
            ? "SELECT sql FROM sqlite_schema WHERE tbl_name=$name AND sql IS NOT NULL ORDER BY type DESC,name"
            : "SELECT sql FROM sqlite_schema WHERE type='index' AND name=$name AND sql IS NOT NULL";
        command.Parameters.AddWithValue("$name", name);
        var statements = new List<string>();
        using (var reader = command.ExecuteReader())
            while (reader.Read()) statements.Add(reader.GetString(0));
        Assert.NotEmpty(statements);
        command.Parameters.Clear();
        command.CommandText = "ATTACH DATABASE $path AS destination";
        command.Parameters.AddWithValue("$path", Path.Combine(_directory, FileName(destination)));
        command.ExecuteNonQuery();
        command.Parameters.Clear();
        foreach (var statement in statements)
        {
            var keyword = statement.StartsWith("CREATE TABLE ", StringComparison.Ordinal) ? "TABLE " : "INDEX ";
            command.CommandText = statement.Insert(statement.IndexOf(keyword, StringComparison.Ordinal) + keyword.Length, "destination.");
            command.ExecuteNonQuery();
        }
        command.CommandText = $"DROP {type} main.\"{name}\"";
        command.ExecuteNonQuery();
    }

    private void CheckHeader(SqliteConnection connection, StoreSegmentRole role)
    {
        using var command = connection.CreateCommand();
        command.CommandText = role switch
        {
            StoreSegmentRole.Derivation or StoreSegmentRole.Membership =>
                "SELECT schema_version,evidence_seal,derivation_generation_id FROM derivation",
            StoreSegmentRole.Judgement =>
                "SELECT schema_version,evidence_seal,judgement_generation_id,derivation_generation_id FROM judgement",
            _ => "SELECT schema_version,evidence_seal,generation,derivation_generation,role FROM judgement_part",
        };
        using var reader = command.ExecuteReader();
        Binding(reader.Read(), "missing product header");
        Binding(reader.GetInt64(0) == Version, "header version");
        Binding(reader.GetString(1) == EvidenceSeal, "header evidence");
        Binding(reader.GetString(2) == _generation.ToString("D"), "header generation");
        if (_kind == AnalysisStoreKind.Judgement)
        {
            Binding(!reader.IsDBNull(3) && reader.GetString(3) == DerivedGeneration.ToString("D"), "header derivation");
            if (role != StoreSegmentRole.Judgement)
                Binding(reader.GetString(4) == role.ToString(), "header role");
        }
        Binding(!reader.Read(), "duplicate product header");
    }

    private string FileName(StoreSegmentRole role) => role switch
    {
        StoreSegmentRole.Derivation => $"derivation.{_generation:N}.db",
        StoreSegmentRole.Membership => $"derivation.{_generation:N}.membership.db",
        StoreSegmentRole.Judgement => $"judgement.{_generation:N}.db",
        StoreSegmentRole.PermissionProof => $"judgement.{_generation:N}.permission-proof.db",
        StoreSegmentRole.PathProof => $"judgement.{_generation:N}.path-proof.db",
        StoreSegmentRole.JudgementFacts => $"judgement.{_generation:N}.facts.db",
        _ => throw new ArgumentOutOfRangeException(nameof(role)),
    };

    private SqliteConnection Open(StoreSegmentRole role, bool writable)
    {
        var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = Path.Combine(_directory, FileName(role)),
            Mode = writable ? SqliteOpenMode.ReadWrite : SqliteOpenMode.ReadOnly,
            Pooling = false,
            ForeignKeys = false,
        }.ToString());
        connection.Open();
        return connection;
    }

    private static void Binding(bool matches, string field) =>
        Assert.True(matches, $"Published layout binding changed: {field}.");
}
