using Microsoft.Data.Sqlite;
using SecureAD.Evidence.Findings;

namespace SecureAD.Storage;

// Compiled into both disposable stores. One relational encoding prevents derivation and finding
// evidence from quietly keeping different parts of the same explanation.
internal static class MembershipRouteStorage
{
    public static void CreateTables(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            CREATE TABLE membership_route_summary (
                subject_id TEXT NOT NULL PRIMARY KEY,
                incomplete_reasons INTEGER NOT NULL
            );
            CREATE TABLE membership_route (
                subject_id TEXT NOT NULL REFERENCES membership_route_summary(subject_id),
                membership_ordinal INTEGER NOT NULL,
                route_ordinal INTEGER NOT NULL,
                catalogue_entry_id INTEGER NOT NULL,
                root_name TEXT NOT NULL,
                authorization TEXT NOT NULL,
                establishes_protection INTEGER NOT NULL CHECK (establishes_protection IN (0, 1)),
                PRIMARY KEY (subject_id, membership_ordinal, route_ordinal)
            );
            CREATE TABLE membership_route_step (
                subject_id TEXT NOT NULL,
                membership_ordinal INTEGER NOT NULL,
                route_ordinal INTEGER NOT NULL,
                step_ordinal INTEGER NOT NULL,
                sid TEXT NOT NULL,
                scope TEXT NULL,
                distinguished_name TEXT NULL,
                is_primary_group INTEGER NOT NULL CHECK (is_primary_group IN (0, 1)),
                PRIMARY KEY (subject_id, membership_ordinal, route_ordinal, step_ordinal),
                FOREIGN KEY (subject_id, membership_ordinal, route_ordinal)
                    REFERENCES membership_route(subject_id, membership_ordinal, route_ordinal)
            );
            """;
        command.ExecuteNonQuery();
    }

    public static void Write(SqliteConnection connection, SqliteTransaction transaction, string subjectId, MembershipRouteSummary summary)
    {
        Validate(summary);
        using var header = connection.CreateCommand();
        header.Transaction = transaction;
        header.CommandText = "INSERT INTO membership_route_summary VALUES ($subject, $reasons)";
        header.Parameters.AddWithValue("$subject", subjectId);
        header.Parameters.AddWithValue("$reasons", (int)summary.IncompleteReasons);
        header.ExecuteNonQuery();
        using var route = connection.CreateCommand();
        route.Transaction = transaction;
        route.CommandText = "INSERT INTO membership_route VALUES ($subject, $membership, $route, $entry, $name, $authorization, $protection)";
        using var step = connection.CreateCommand();
        step.Transaction = transaction;
        step.CommandText = "INSERT INTO membership_route_step VALUES ($subject, $membership, $route, $step, $sid, $scope, $dn, $primary)";
        for (var groupIndex = 0; groupIndex < summary.Memberships.Count; groupIndex++)
        {
            var group = summary.Memberships[groupIndex];
            for (var routeIndex = 0; routeIndex < group.Routes.Count; routeIndex++)
            {
                var path = group.Routes[routeIndex];
                route.Parameters.Clear();
                route.Parameters.AddWithValue("$subject", subjectId);
                route.Parameters.AddWithValue("$membership", groupIndex);
                route.Parameters.AddWithValue("$route", routeIndex);
                route.Parameters.AddWithValue("$entry", path.CatalogueEntryId);
                route.Parameters.AddWithValue("$name", path.RootName);
                route.Parameters.AddWithValue("$authorization", path.Authorization.ToString());
                route.Parameters.AddWithValue("$protection", path.EstablishesProtection ? 1 : 0);
                route.ExecuteNonQuery();
                for (var ordinal = 0; ordinal < path.Steps.Count; ordinal++)
                {
                    var item = path.Steps[ordinal];
                    step.Parameters.Clear();
                    step.Parameters.AddWithValue("$subject", subjectId);
                    step.Parameters.AddWithValue("$membership", groupIndex);
                    step.Parameters.AddWithValue("$route", routeIndex);
                    step.Parameters.AddWithValue("$step", ordinal);
                    step.Parameters.AddWithValue("$sid", item.Principal.Sid);
                    step.Parameters.AddWithValue("$scope", (object?)item.Principal.Scope ?? DBNull.Value);
                    step.Parameters.AddWithValue("$dn", (object?)item.Principal.DistinguishedName ?? DBNull.Value);
                    step.Parameters.AddWithValue("$primary", item.IsPrimaryGroup ? 1 : 0);
                    step.ExecuteNonQuery();
                }
            }
        }
    }

    public static Dictionary<string, MembershipRouteSummary> Read(SqliteConnection connection, string? subjectId)
    {
        var headers = new Dictionary<string, MembershipRouteIncompleteReason>(StringComparer.Ordinal);
        var paths = new Dictionary<(string Subject, int Group, int Route), List<MembershipRouteStep>>();
        var groups = new Dictionary<string, SortedDictionary<int, List<MembershipRoute>>>(StringComparer.Ordinal);
        var where = subjectId is null ? string.Empty : " WHERE subject_id = $subject";
        using var command = connection.CreateCommand();
        if (subjectId is not null)
            command.Parameters.AddWithValue("$subject", subjectId);
        command.CommandText = "SELECT subject_id, incomplete_reasons FROM membership_route_summary" + where;
        using (var reader = command.ExecuteReader())
            while (reader.Read())
                headers.Add(reader.GetString(0), (MembershipRouteIncompleteReason)reader.GetInt32(1));

        command.CommandText = "SELECT subject_id, membership_ordinal, route_ordinal, step_ordinal, sid, scope, distinguished_name, is_primary_group "
            + "FROM membership_route_step" + where + " ORDER BY subject_id, membership_ordinal, route_ordinal, step_ordinal";
        using (var reader = command.ExecuteReader())
        {
            while (reader.Read())
            {
                var key = (reader.GetString(0), reader.GetInt32(1), reader.GetInt32(2));
                if (!paths.TryGetValue(key, out var list))
                    paths.Add(key, list = []);
                if (reader.GetInt32(3) != list.Count)
                    throw new InvalidOperationException("Membership route steps are missing or out of order.");
                list.Add(new MembershipRouteStep(new MembershipRoutePrincipal(reader.GetString(4),
                    reader.IsDBNull(5) ? null : reader.GetString(5), reader.IsDBNull(6) ? null : reader.GetString(6)), reader.GetInt32(7) != 0));
            }
        }

        command.CommandText = "SELECT subject_id, membership_ordinal, route_ordinal, catalogue_entry_id, root_name, authorization, establishes_protection "
            + "FROM membership_route" + where + " ORDER BY subject_id, membership_ordinal, route_ordinal";
        using (var reader = command.ExecuteReader())
        {
            while (reader.Read())
            {
                var subject = reader.GetString(0);
                var groupIndex = reader.GetInt32(1);
                var routeIndex = reader.GetInt32(2);
                if (!headers.ContainsKey(subject))
                    throw new InvalidOperationException("Membership routes have no completeness record.");
                if (!groups.TryGetValue(subject, out var memberships))
                    groups.Add(subject, memberships = []);
                if (!memberships.TryGetValue(groupIndex, out var routes))
                {
                    if (groupIndex != memberships.Count)
                        throw new InvalidOperationException("Initial memberships are missing or out of order.");
                    memberships.Add(groupIndex, routes = []);
                }
                if (routeIndex != routes.Count || !paths.Remove((subject, groupIndex, routeIndex), out var steps))
                    throw new InvalidOperationException("A membership route has missing supporting evidence.");
                routes.Add(new MembershipRoute(reader.GetInt32(3), reader.GetString(4),
                    Enum.Parse<MembershipRouteAuthorization>(reader.GetString(5)), reader.GetInt32(6) != 0, steps));
            }
        }
        if (paths.Count != 0)
            throw new InvalidOperationException("Membership steps have no route.");

        var result = new Dictionary<string, MembershipRouteSummary>(StringComparer.Ordinal);
        foreach (var (subject, reasons) in headers)
        {
            var memberships = new List<InitialMembershipRoutes>();
            if (groups.TryGetValue(subject, out var stored))
                foreach (var routes in stored.Values)
                {
                    if (routes[0].Steps.Count < 2)
                        throw new InvalidOperationException("A membership route has no initial membership.");
                    memberships.Add(new InitialMembershipRoutes(routes[0].Steps[1].Principal, routes, reasons));
                }
            var summary = new MembershipRouteSummary(memberships, reasons);
            Validate(summary);
            result.Add(subject, summary);
        }
        return result;
    }

    private static void Validate(MembershipRouteSummary summary)
    {
        var knownReasons = Enum.GetValues<MembershipRouteIncompleteReason>().Aggregate(0, (a, b) => a | (int)b);
        if (((int)summary.IncompleteReasons & ~knownReasons) != 0)
            throw new InvalidOperationException("Membership completeness contains an unknown reason.");
        foreach (var group in summary.Memberships)
        {
            if (group.Completeness != summary.IncompleteReasons)
                throw new InvalidOperationException("Initial membership completeness disagrees with its summary.");
            if (group.Routes.Count == 0)
                throw new InvalidOperationException("An initial membership has no supporting route.");
            foreach (var route in group.Routes)
            {
                if (route.Steps.Count < 2 || route.Steps[1].Principal != group.InitialMembership
                    || route.Steps[0].IsPrimaryGroup || !Enum.IsDefined(route.Authorization)
                    || (route.EstablishesProtection && route.Steps.Any(s => s.IsPrimaryGroup)))
                    throw new InvalidOperationException("Membership route evidence is inconsistent.");
            }
        }
    }
}
