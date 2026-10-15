using Microsoft.Data.Sqlite;
using SecureAD.Evidence.Run;
using SecureAD.Kernel;

namespace SecureAD.Evidence.Inventory;

/// <summary>
/// Counts what a sealed bundle holds, per domain, for the dashboard.
/// </summary>
/// <remarks>
/// <para>
/// <b>One grouped pass rather than a query per kind per domain.</b> Four kinds across a forest of
/// several domains is a dozen scans of the object table for an answer one scan already contains,
/// and a dozen queries is a dozen places for the class rule below to be written differently.
/// </para>
/// <para>
/// <b>It counts by the most specific class, which is the highest ordinal.</b> <c>objectClass</c>
/// arrives least specific first and is stored in that order, so a computer's chain contains
/// <c>user</c> and a group managed service account's contains <c>computer</c>. Taking any value in
/// the chain would report every workstation in the forest as a user account. This is the rule
/// <see cref="ObjectListing"/> already applies to the object grid, stated the same way here so the
/// dashboard and the tree cannot give an administrator two different answers about one forest.
/// </para>
/// <para>
/// <b>A domain with no rows is not the same as a domain with no coverage.</b> This reader counts
/// only what the object table holds; whether a domain may be counted at all is
/// <see cref="DomainInventory"/>'s decision, taken from the coverage rather than from the presence
/// of rows. A domain nobody could read has no rows either, and the two must never render alike.
/// </para>
/// </remarks>
internal static class InventoryReader
{
    private const string UserClass = "user";
    private const string ComputerClass = "computer";
    private const string GroupClass = "group";
    private const string OrganisationalUnitClass = "organizationalUnit";

    /// <summary>
    /// The connection security rungs on which a controller may withhold confidential attributes
    /// without saying so.
    /// </summary>
    /// <remarks>
    /// The negation of <see cref="ReadCoverage"/>'s complete rungs, expressed in the words the
    /// <c>partition_coverage</c> check constraint stores.
    /// </remarks>
    private static readonly string[] MayWithhold = ["Signed", "Unprotected"];

    /// <summary>
    /// Counts the forest, or says why the run's coverage could not be established.
    /// </summary>
    /// <param name="connection">The open evidence database.</param>
    /// <param name="description">What the run recorded about itself.</param>
    public static Result<ForestInventory> Read(
        SqliteConnection connection, BundleDescription description, Result<RunScope> scope, bool navigation = false)
    {
        if (!scope.IsSuccess)
            return Result<ForestInventory>.Failure(scope.Error);

        var counts = CountsByDomain(connection, navigation);
        var withholding = DomainsReadOverAWithholdingConnection(connection);
        var policies = PolicyCoverage(connection);

        var domains = scope.Value.Domains.Select(coverage =>
            coverage.Outcome == DomainReadOutcome.Read
                ? DomainInventory.Counted(
                    coverage,
                    counts.GetValueOrDefault(coverage.DomainFqdn, ObjectCounts.None),
                    withholding.Contains(coverage.DomainFqdn))
                : DomainInventory.NotCounted(coverage));

        return Result<ForestInventory>.Success(ForestInventory.Of(
            description.ForestFqdn, domains, policies.Declared, policies.Read, description.ExcludedObjectClasses));
    }

    /// <summary>
    /// Every domain's counts, keyed by domain, from one grouped scan.
    /// </summary>
    /// <remarks>
    /// A domain absent from this is a domain the object table holds nothing for. The caller decides
    /// what that means, because this cannot: it is <i>read and empty</i> for one domain and
    /// <i>never read</i> for another, and only the coverage says which.
    /// </remarks>
    internal static Dictionary<string, ObjectCounts> CountsByDomain(
        SqliteConnection connection, bool navigation, bool attachedNavigation = false, CancellationToken token = default)
    {
        using var command = connection.CreateCommand();
        var prefix = attachedNavigation ? "navigation." : "";

        command.CommandText = navigation
            ? $"SELECT domain_fqdn,most_specific_class,COUNT(*) FROM {prefix}captured_object GROUP BY domain_fqdn,most_specific_class" :
            """
            SELECT o.domain_fqdn,
                   (SELECT v.value
                    FROM objectclass_value AS v
                    WHERE v.object_id = o.object_id
                    ORDER BY v.ordinal DESC
                    LIMIT 1) AS most_specific_class,
                   COUNT(*)
            FROM captured_object AS o
            GROUP BY o.domain_fqdn, most_specific_class
            """;

        var counts = new Dictionary<string, ObjectCounts>(StringComparer.OrdinalIgnoreCase);

        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            token.ThrowIfCancellationRequested();
            var domain = reader.GetString(0);
            var mostSpecific = reader.IsDBNull(1) ? null : reader.GetString(1);
            var howMany = reader.GetInt32(2);

            var running = counts.GetValueOrDefault(domain, ObjectCounts.None);

            counts[domain] = mostSpecific switch
            {
                UserClass => running with { Users = running.Users + howMany },
                ComputerClass => running with { Computers = running.Computers + howMany },
                GroupClass => running with { Groups = running.Groups + howMany },
                OrganisationalUnitClass => running with
                {
                    OrganisationalUnits = running.OrganisationalUnits + howMany,
                },

                // Every other class - containers, contacts, printers, the schema's own definitions.
                // Counted by nothing here on purpose: the dashboard names four kinds and must not
                // fold the rest into one of them.
                _ => running,
            };
        }

        return counts;
    }

    /// <summary>
    /// The domains at least one of whose partitions was read over a connection a controller may
    /// have stripped confidential attributes from.
    /// </summary>
    /// <remarks>
    /// Taken from the partitions the objects were actually read over rather than from the run's
    /// intent, because <c>connection_security</c> is recorded per partition and varies by
    /// controller (<c>F-S24-1</c>).
    /// </remarks>
    internal static HashSet<string> DomainsReadOverAWithholdingConnection(
        SqliteConnection connection, bool attachedNavigation = false, CancellationToken token = default)
    {
        using var command = connection.CreateCommand();
        var prefix = attachedNavigation ? "navigation." : "";

        command.CommandText =
            $"""
            SELECT DISTINCT o.domain_fqdn
            FROM {prefix}captured_object AS o
            JOIN {prefix}partition_coverage AS p ON p.coverage_id = o.coverage_id
            WHERE p.connection_security IN ($signed, $unprotected)
            """;

        command.Parameters.AddWithValue("$signed", MayWithhold[0]);
        command.Parameters.AddWithValue("$unprotected", MayWithhold[1]);

        var domains = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            token.ThrowIfCancellationRequested();
            domains.Add(reader.GetString(0));
        }

        return domains;
    }

    /// <summary>
    /// How many Group Policy objects the directory declared, and how many had their files read.
    /// </summary>
    /// <remarks>
    /// <b>The denominator is trustworthy even when the numerator is short.</b> The declaration
    /// comes from the directory, which is read under fail-fast capture, while the files come from
    /// SYSVOL, which <c>docs/decisions/0044</c> allows to fail without failing the run. So this is
    /// the one place a sealed bundle can state an exact shortfall.
    /// </remarks>
    internal static (int Declared, int Read) PolicyCoverage(SqliteConnection connection, bool attachedNavigation = false)
    {
        using var command = connection.CreateCommand();
        var prefix = attachedNavigation ? "navigation." : "";

        command.CommandText =
            $"""
            SELECT COUNT(*), COALESCE(SUM(CASE WHEN outcome = 'Read' THEN 1 ELSE 0 END), 0)
            FROM {prefix}sysvol_gpo_coverage
            """;

        using var reader = command.ExecuteReader();

        return reader.Read()
            ? (reader.GetInt32(0), reader.GetInt32(1))
            : (0, 0);
    }
}
