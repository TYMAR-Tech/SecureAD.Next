using Microsoft.Data.Sqlite;
using SecureAD.Derivation;
using SecureAD.Evidence;

namespace SecureAD.Judgement;

internal static class PathCalculationStorage
{
    internal sealed record RecordSet(int Count, string Fingerprint);
    internal sealed record Selection(int Version, Guid JudgementGenerationId, string InputFingerprint, bool InputScanCompleted,
        RecordSet Candidates, RecordSet Sources, RecordSet Limitations);
    internal sealed record Inputs(Guid JudgementGenerationId, PathInputAvailability Availability, Tier0InputBinding? Input,
        Tier0Coverage Coverage, RecordSet FixedTargets, RecordSet UncertaintyRegions, SelfMembershipSummary? RequesterDiscovery,
        string SourceFingerprint);
    internal sealed record Manifest(int Version, Guid Generation, string InputFingerprint, int NodeCount,
        int RequesterCount, int OwnAccountCount, int MembershipDaclCount, string ProofFingerprint,
        bool OfflineSelection, Selection? Selection, Inputs Inputs, IReadOnlyList<PathRequesterFamilyCoverage> Families,
        RecordSet Work);
    internal sealed record Preparation(string InputFingerprint, Selection? Selection, Inputs Inputs);

    internal static void CreateTables(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            CREATE TABLE path_calculation_record (
                calculation INTEGER NOT NULL DEFAULT 1 REFERENCES tier0_path_calculation(id) ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED,
                kind TEXT NOT NULL CHECK(kind IN ('Candidates','Sources','Limitations','FixedTargets')),
                ordinal INTEGER NOT NULL CHECK(ordinal>=0),
                proof INTEGER NOT NULL REFERENCES path_proof(id),
                fingerprint BLOB NOT NULL CHECK(length(fingerprint)=32),
                question_key TEXT NULL, requester TEXT NULL COLLATE NOCASE,
                PRIMARY KEY(kind,ordinal), UNIQUE(kind,question_key));
            CREATE INDEX ix_path_calculation_requester ON path_calculation_record(kind,requester,ordinal);
            """;
        command.ExecuteNonQuery();
    }

    internal static Preparation Prepare(SqliteConnection connection, SqliteTransaction transaction,
        JudgementDescription description, PathInputs inputs, Selection? selection,
        PathSharedProofStorage shared, CancellationToken token)
    {
        if (selection is not null && (selection.Version != PathRequesterSelector.Version
            || selection.JudgementGenerationId != description.GenerationId
            || selection.InputScanCompleted != (inputs.Availability == PathInputAvailability.Recorded)
            || selection.InputFingerprint is not { Length: 64 })) throw Tier0PathStorage.InvalidProof();
        var inputFingerprint = selection?.InputFingerprint ?? Tier0PathCalculation.Fingerprint(inputs);
        var savedInputs = new Inputs(description.GenerationId, inputs.Availability, inputs.Input, inputs.Coverage,
            WriteRecords(connection, transaction, "FixedTargets", inputs.FixedTargets, shared, token),
            UncertaintySet(connection, token), inputs.RequesterDiscovery, InputFingerprint(connection));
        return new(inputFingerprint, selection, savedInputs);
    }

    internal static PathProofStorage.Reference Write(JudgementDescription description, Preparation prepared, int nodes,
        IReadOnlyList<PathRequesterFamilyCoverage> families, PathCalculationStorage.RecordSet work,
        IEnumerable<PathProofStorage.Reference> sources, PathProofStorage.Writer proofs)
    {
        int Count(PathRequesterFamily family) => families.Single(value => value.Family == family).StoredAssessments;
        var manifest = new Manifest(Tier0PathCalculation.Version, description.GenerationId, prepared.InputFingerprint, nodes,
            Count(PathRequesterFamily.RequesterDacl), Count(PathRequesterFamily.OwnAccountMembership),
            Count(PathRequesterFamily.MembershipDacl), Tier0PathCalculation.Fingerprint(sources),
            prepared.Selection is not null, prepared.Selection, prepared.Inputs, families, work);
        return proofs.Write(manifest);
    }

    private static RecordSet WriteRecords<T>(SqliteConnection connection, SqliteTransaction transaction, string kind,
        IReadOnlyList<T> values, PathSharedProofStorage shared, CancellationToken token)
    {
        using var insert = connection.CreateCommand();
        insert.Transaction = transaction;
        insert.CommandText = """
            INSERT INTO path_calculation_record(kind,ordinal,proof,fingerprint,question_key,requester)
            VALUES ($kind,$ordinal,$proof,$fingerprint,$key,$requester)
            """;
        insert.Parameters.AddWithValue("$kind", kind);
        insert.Parameters.Add("$ordinal", SqliteType.Integer);
        insert.Parameters.Add("$proof", SqliteType.Integer);
        insert.Parameters.Add("$fingerprint", SqliteType.Blob);
        insert.Parameters.Add("$key", SqliteType.Text);
        insert.Parameters.Add("$requester", SqliteType.Text);
        insert.Prepare();
        var count = 0;
        var fingerprint = Tier0PathCalculation.Fingerprint(Write());
        if (count != values.Count) throw Tier0PathStorage.InvalidProof();
        return new(count, fingerprint);

        IEnumerable<PathProofStorage.Reference> Write()
        {
            foreach (var value in values)
            {
                token.ThrowIfCancellationRequested();
                var proof = shared.Write(value);
                insert.Parameters["$ordinal"].Value = count++;
                insert.Parameters["$proof"].Value = proof.Id;
                insert.Parameters["$fingerprint"].Value = proof.Fingerprint;
                insert.Parameters["$key"].Value = DBNull.Value;
                insert.Parameters["$requester"].Value = DBNull.Value;
                if (insert.ExecuteNonQuery() != 1) throw Tier0PathStorage.InvalidProof();
                yield return proof;
            }
        }
    }

    internal static Manifest? Read(SqliteConnection connection, JudgementDescription description, CancellationToken token)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT proof,fingerprint FROM tier0_path_calculation WHERE id=1";
        Manifest value;
        using (var read = command.ExecuteReader())
        {
            if (!read.Read()) return null;
            value = PathProofStorage.Read<Manifest>(connection, read.GetInt64(0),
                Convert.ToHexString((byte[])read.GetValue(1)), token);
        }
        if (value.Version != Tier0PathCalculation.Version || value.Generation != description.GenerationId
            || value.InputFingerprint is not { Length: 64 } || value.ProofFingerprint is not { Length: 64 }
            || value.NodeCount < 0 || value.RequesterCount < 0 || value.OwnAccountCount < 0 || value.MembershipDaclCount < 0
            || value.OfflineSelection != (value.Selection is not null)
            || value.Inputs is not { } inputs || inputs.JudgementGenerationId != description.GenerationId
            || !Enum.IsDefined(inputs.Availability) || inputs.Coverage is null
            || inputs.SourceFingerprint != InputFingerprint(connection)
            || inputs.Input is { } binding && (binding.EvidenceSeal != description.EvidenceSeal
                || binding.DerivationGenerationId != description.DerivationGenerationId)
            || value.Families is not { Count: 3 } || value.Families.Any(family => family is null)
            || !value.Families.Select(family => family.Family).SequenceEqual(Enum.GetValues<PathRequesterFamily>())
            || !value.Families.Select(family => family.StoredAssessments)
                .SequenceEqual(new[] { value.RequesterCount, value.OwnAccountCount, value.MembershipDaclCount })
            || value.Families.Any(family => family.SelectedQuestions < 0 || family.StoredAssessments < 0
                || family.UnresolvedResults < 0 || family.UnresolvedResults > family.StoredAssessments
                || family.UnknownCurrentMembership < 0 || family.UnknownCurrentMembership > family.StoredAssessments
                || family.UnknownOperationReadiness < 0 || family.UnknownOperationReadiness > family.StoredAssessments))
            throw Tier0PathStorage.InvalidProof();
        RequireSet(inputs.FixedTargets);
        RequireSet(inputs.UncertaintyRegions);
        RequireSet(value.Work);
        if ((long)value.RequesterCount + value.OwnAccountCount + value.MembershipDaclCount != value.Work.Count)
            throw Tier0PathStorage.InvalidProof();
        PathInputStorage.RequireProjection(connection, description, inputs);
        if (value.Selection is { } selection)
        {
            if (selection.Version != PathRequesterSelector.Version || selection.JudgementGenerationId != value.Generation
                || selection.InputFingerprint != value.InputFingerprint
                || selection.InputScanCompleted != (inputs.Availability == PathInputAvailability.Recorded)
                || value.Families.Any(family => family.SelectedQuestions != family.StoredAssessments))
                throw Tier0PathStorage.InvalidProof();
            RequireSet(selection.Candidates);
            RequireSet(selection.Sources);
            RequireSet(selection.Limitations);
            if (value.Families.Sum(family => (long)family.SelectedQuestions) != selection.Candidates.Count)
                throw Tier0PathStorage.InvalidProof();
        }
        else if (value.Families.Any(family => family.SelectedQuestions != 0)) throw Tier0PathStorage.InvalidProof();
        return value;
    }

    internal static SavedPathInputs ReadInputs(SqliteConnection connection, JudgementDescription description,
        Manifest manifest, CancellationToken token)
    {
        var inputs = manifest.Inputs;
        var targets = ReadRecords<Tier0Target>(connection, description, "FixedTargets", inputs.FixedTargets, token);
        var regions = PathInputStorage.ReadRegions(connection, token);
        if (regions.Count != inputs.UncertaintyRegions.Count || UncertaintySet(connection, token) != inputs.UncertaintyRegions)
            throw Tier0PathStorage.InvalidProof();
        return new(inputs.JudgementGenerationId, inputs.Availability, inputs.Input, inputs.Coverage,
            targets, regions, inputs.RequesterDiscovery);
    }

    internal static PathRequesterSelection? ReadSelection(SqliteConnection connection, JudgementDescription description,
        Manifest manifest, CancellationToken token)
    {
        if (manifest.Selection is not { } selection) return null;
        var candidates = ReadRecords<PathRequesterCandidate>(connection, description, "Candidates", selection.Candidates, token);
        var sources = ReadRecords<PathRequesterSelectionSource>(connection, description, "Sources", selection.Sources, token);
        var limitations = ReadRecords<PathRequesterSelectionLimitation>(connection, description, "Limitations", selection.Limitations, token);
        if (candidates.Any(value => value is null || !Enum.IsDefined(value.Family)
                || string.IsNullOrWhiteSpace(value.RequesterDn) || string.IsNullOrWhiteSpace(value.TargetDn)
                || value.RequesterFingerprint is not { Length: 64 } || value.Witnesses is not { Count: > 0 }
                || value.Witnesses.Any(witness => witness is null))
            || sources.Any(value => value is null || string.IsNullOrWhiteSpace(value.ResourceDn) || value.Fingerprint is not { Length: 64 })
            || limitations.Any(value => value is null || !Enum.IsDefined(value.Reason))) throw Tier0PathStorage.InvalidProof();
        return new(selection.Version, selection.JudgementGenerationId, selection.InputFingerprint,
            selection.InputScanCompleted, candidates, sources, limitations);
    }

    internal static IReadOnlyList<T> ReadRecords<T>(SqliteConnection connection, JudgementDescription description,
        string kind, RecordSet expected, CancellationToken token)
    {
        ValidateRecords(connection, kind, expected, token);
        var shared = new PathSharedProofStorage(connection, description, token);
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT proof,fingerprint,question_key,requester FROM path_calculation_record WHERE kind=$kind ORDER BY ordinal";
        command.Parameters.AddWithValue("$kind", kind);
        using var read = command.ExecuteReader();
        var values = new List<T>();
        while (read.Read())
        {
            token.ThrowIfCancellationRequested();
            var value = shared.Read<T>(read.GetInt64(0), Convert.ToHexString((byte[])read.GetValue(1)));
            if (value is PathRequesterCandidate candidate && (PathRequesterSelector.Key(candidate) != read.GetString(2)
                || candidate.RequesterDn != read.GetString(3))) throw Tier0PathStorage.InvalidProof();
            values.Add(value);
        }
        return values;
    }

    internal static PathRequesterSummary Summary(JudgementDescription description, Manifest manifest) =>
        new(description.EvidenceSeal, description.DerivationGenerationId, description.GenerationId, manifest.Inputs.Availability,
            manifest.Selection?.Version, manifest.Selection?.InputScanCompleted ?? false, manifest.Families,
            manifest.Inputs.UncertaintyRegions.Count, manifest.Selection?.Limitations.Count ?? 0);

    internal static void RequirePublishable(SqliteConnection connection, JudgementDescription? description, CancellationToken token)
    {
        if (description is null)
        {
            using var check = connection.CreateCommand();
            check.CommandText = "SELECT COUNT(*) FROM tier0_path_calculation";
            if ((long)check.ExecuteScalar()! != 0) throw Tier0PathStorage.InvalidProof();
            return;
        }
        var manifest = Read(connection, description, token);
        if (manifest is null) return;
        PathSharedProofStorage.RequirePublishable(connection, description);
        PathRequesterWorkPlan.RequirePublishable(connection, description, manifest.Work, token);
        if (manifest.Selection is not null) PathRequesterWorkPlan.RequireSelectionMatchesWork(connection);
        if (Tier0PathCalculation.Fingerprint(SourceReferences(connection, token)) != manifest.ProofFingerprint
            || UncertaintySet(connection, token) != manifest.Inputs.UncertaintyRegions) throw Tier0PathStorage.InvalidProof();
        ValidateRecords(connection, "FixedTargets", manifest.Inputs.FixedTargets, token);
        if (manifest.Selection is { } selection)
        {
            ValidateRecords(connection, "Candidates", selection.Candidates, token);
            ValidateRecords(connection, "Sources", selection.Sources, token);
            ValidateRecords(connection, "Limitations", selection.Limitations, token);
        }
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT (SELECT COUNT(*) FROM tier0_path_node),
                (SELECT COUNT(*) FROM path_requester_risk),
                (SELECT COUNT(*) FROM path_calculation_record WHERE kind='Candidates'),
                (SELECT COUNT(*) FROM path_calculation_record c
                    LEFT JOIN path_requester_risk r ON r.question_key=c.question_key
                    WHERE c.kind='Candidates' AND (r.id IS NULL OR r.requester<>c.requester)),
                (SELECT COUNT(*) FROM path_requester_work w LEFT JOIN path_requester_risk r ON r.id=w.id
                    WHERE r.id IS NULL OR r.question_key<>w.question_key OR r.requester<>w.requester)
            """;
        using var read = command.ExecuteReader();
        if (!read.Read() || read.GetInt64(0) != manifest.NodeCount
            || read.GetInt64(1) != (long)manifest.RequesterCount + manifest.OwnAccountCount + manifest.MembershipDaclCount
            || read.GetInt64(2) != (manifest.Selection?.Candidates.Count ?? 0) || read.GetInt64(3) != 0 || read.GetInt64(4) != 0)
            throw Tier0PathStorage.InvalidProof();
    }

    internal static IEnumerable<PathProofStorage.Reference> SourceReferences(SqliteConnection connection, CancellationToken token)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT source_proof,source_fingerprint FROM path_requester_risk ORDER BY id";
        using var read = command.ExecuteReader();
        while (read.Read())
        {
            token.ThrowIfCancellationRequested();
            yield return new(read.GetInt64(0), (byte[])read.GetValue(1));
        }
    }

    private static RecordSet UncertaintySet(SqliteConnection connection, CancellationToken token)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT id,fingerprint FROM path_uncertainty ORDER BY id";
        using var read = command.ExecuteReader();
        var count = 0;
        var fingerprint = Tier0PathCalculation.Fingerprint(Rows());
        return new(count, fingerprint);
        IEnumerable<PathProofStorage.Reference> Rows()
        {
            while (read.Read())
            {
                token.ThrowIfCancellationRequested();
                count = checked(count + 1);
                yield return new(read.GetInt64(0), (byte[])read.GetValue(1));
            }
        }
    }

    private static void ValidateRecords(SqliteConnection connection, string kind, RecordSet expected, CancellationToken token)
    {
        RequireSet(expected);
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT ordinal,proof,fingerprint FROM path_calculation_record WHERE kind=$kind ORDER BY ordinal";
        command.Parameters.AddWithValue("$kind", kind);
        using var read = command.ExecuteReader();
        var count = 0;
        if (Tier0PathCalculation.Fingerprint(Rows()) != expected.Fingerprint || count != expected.Count)
            throw Tier0PathStorage.InvalidProof();
        IEnumerable<PathProofStorage.Reference> Rows()
        {
            while (read.Read())
            {
                token.ThrowIfCancellationRequested();
                if (read.GetInt64(0) != count++) throw Tier0PathStorage.InvalidProof();
                yield return new(read.GetInt64(1), (byte[])read.GetValue(2));
            }
        }
    }

    private static void RequireSet(RecordSet value)
    {
        if (value is null || value.Count < 0 || value.Fingerprint is not { Length: 64 }) throw Tier0PathStorage.InvalidProof();
    }

    private static string InputFingerprint(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT hex(fingerprint) FROM path_input WHERE id=1";
        return command.ExecuteScalar() as string ?? throw Tier0PathStorage.InvalidProof();
    }
}
