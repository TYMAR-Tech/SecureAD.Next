using Microsoft.Data.Sqlite;

namespace SecureAD.Evidence.Findings;

/// <summary>
/// Reads the findings a sealed bundle carries.
/// </summary>
/// <remarks>
/// <para>
/// <b>An empty result means no rule matched, and never means the forest is clean.</b> A rule that
/// could not read a declared input reaches no verdict under <c>docs/decisions/0083</c>, so it writes
/// no finding - and a caller that renders an empty list as "nothing wrong" has made the claim
/// <c>docs/decisions/0002</c> forbids. The coverage tables are what answer that question; this type
/// deliberately does not, because a reader that quietly supplied a reassuring default would be the
/// same defect one layer down.
/// </para>
/// <para>
/// <b>Evidence is rebuilt from its own table, and a finding without one is refused.</b> The two
/// derived answers on <see cref="DomainControllerSignals"/> are recomputed from the three stored
/// signals rather than read, because a stored copy of a derived value can disagree with the values
/// it was derived from and nothing would say which was right.
/// </para>
/// </remarks>
public static class FindingReader
{
    private const string Query = """
        SELECT f.finding_id, f.rule_id, f.rule_version, f.subject_kind, f.subject_key,
               f.object_guid, f.severity, f.distinguished_name, f.detail, f.coverage,
               d.user_account_control, d.is_computer, d.server_trust_account_bit,
               d.primary_group_is_domain_controller, d.under_domain_controllers_ou
        FROM finding f
        LEFT JOIN finding_unconstrained_delegation d ON d.finding_id = f.finding_id
        ORDER BY f.finding_id
        """;

    /// <summary>
    /// The findings in the bundle, beside the rules that were run to produce them.
    /// </summary>
    /// <param name="connection">An open connection to the evidence database.</param>
    /// <exception cref="InvalidOperationException">
    /// A finding is stored with no evidence row, so what it rests on has been lost.
    /// </exception>
    public static StoredFindings Read(SqliteConnection connection)
    {
        ArgumentNullException.ThrowIfNull(connection);

        return new StoredFindings(ReadFindings(connection), ReadEvaluatedRules(connection));
    }

    /// <summary>
    /// The rules that were run over this bundle. No rows means it was never judged.
    /// </summary>
    private static IReadOnlyList<EvaluatedRule> ReadEvaluatedRules(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT rule_id, rule_version FROM evaluated_rule ORDER BY rule_id";

        var rules = new List<EvaluatedRule>();
        using var reader = command.ExecuteReader();

        while (reader.Read())
            rules.Add(new EvaluatedRule(reader.GetString(0), reader.GetInt32(1)));

        return rules;
    }

    private static IReadOnlyList<Finding> ReadFindings(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = Query;

        var findings = new List<Finding>();
        using var reader = command.ExecuteReader();

        while (reader.Read())
        {
            var findingId = reader.GetInt64(0);

            if (reader.IsDBNull(10))
            {
                throw new InvalidOperationException(
                    $"Finding {findingId} ({reader.GetString(1)}) is stored with no evidence row, "
                    + "so what it rests on has been lost. A finding that cannot say what it rests "
                    + "on must not be presented as one.");
            }

            var evidence = new UnconstrainedDelegationEvidence(
                (uint)reader.GetInt64(10),
                reader.GetInt64(11) != 0,
                new DomainControllerSignals(
                    reader.GetInt64(12) != 0,
                    reader.GetInt64(13) != 0,
                    reader.GetInt64(14) != 0));

            findings.Add(new Finding(
                reader.GetString(1),
                reader.GetInt32(2),
                Enum.Parse<Severity>(reader.GetString(6)),
                new FindingSubject(
                    Enum.Parse<FindingSubjectKind>(reader.GetString(3)),
                    reader.GetString(4)),
                Guid.Parse(reader.GetString(5)),
                reader.GetString(7),
                reader.GetString(8),
                Enum.Parse<EvidenceCompleteness>(reader.GetString(9)),
                evidence));
        }

        return findings;
    }
}
