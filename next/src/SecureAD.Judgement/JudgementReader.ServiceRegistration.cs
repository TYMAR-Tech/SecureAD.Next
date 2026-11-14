using System.Globalization;
using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

public sealed partial class JudgementReader
{
    public Result<SavedServiceRegistrations> ReadServiceRegistrations(FindingReference reference, ServiceNameMark? after)
    {
        var saved = ReadServiceContext(reference);
        if (!saved.IsSuccess) return Result<SavedServiceRegistrations>.Failure(saved.Error);
        var context = saved.Value;
        if (after is { } mark && !ServiceMark(context, mark.GenerationId, mark.FindingId, mark.AccountGuid)) throw ServiceInvalid();
        var start = ServiceStart(after?.Ordinal, context.ServiceNameCount);
        using var command = ServiceCommand(context, """
            SELECT ordinal,service_principal_name FROM finding_kerberoastable_account_spn
            WHERE finding_id=$id AND ordinal>$after ORDER BY ordinal LIMIT $limit
            """, after: after?.Ordinal ?? -1);
        var values = new List<SavedServiceName>();
        using (var row = command.ExecuteReader())
            while (row.Read())
            {
                _readCancellation.ThrowIfCancellationRequested();
                if (row.GetValue(0) is not long ordinal || ordinal != start + values.Count
                    || row.GetValue(1) is not string value || string.IsNullOrWhiteSpace(value)) throw ServiceInvalid();
                values.Add(new(checked((int)ordinal), value));
            }
        ServiceSlice(values.Count, start, context.ServiceNameCount);
        ServiceNameMark? next = start + values.Count < context.ServiceNameCount
            ? new(reference.GenerationId, reference.FindingId, context.Account.ObjectGuid, values[^1].Ordinal) : null;
        return Result<SavedServiceRegistrations>.Success(new(context, values, next));
    }

    public Result<SavedInitialMemberships> ReadInitialMemberships(FindingReference reference, InitialMembershipMark? after)
    {
        var saved = ReadServiceContext(reference);
        if (!saved.IsSuccess) return Result<SavedInitialMemberships>.Failure(saved.Error);
        var context = saved.Value;
        if (after is { } mark && !ServiceMark(context, mark.GenerationId, mark.FindingId, mark.AccountGuid)) throw ServiceInvalid();
        var start = ServiceStart(after?.Ordinal, context.InitialMembershipCount);
        using var command = ServiceCommand(context, """
            SELECT r.membership_ordinal,s.sid,s.scope,s.distinguished_name,s.is_primary_group,
                   (SELECT COUNT(*) FROM membership_route x WHERE x.subject_id=r.subject_id AND x.membership_ordinal=r.membership_ordinal)
            FROM membership_route r JOIN membership_route_step s
              ON s.subject_id=r.subject_id AND s.membership_ordinal=r.membership_ordinal
              AND s.route_ordinal=0 AND s.step_ordinal=1
            WHERE r.subject_id=$subject AND r.route_ordinal=0 AND r.membership_ordinal>$after
            ORDER BY r.membership_ordinal LIMIT $limit
            """, after: after?.Ordinal ?? -1);
        var groups = new List<SavedInitialMembership>();
        using (var row = command.ExecuteReader())
            while (row.Read())
            {
                _readCancellation.ThrowIfCancellationRequested();
                if (row.GetValue(0) is not long ordinal || ordinal != start + groups.Count
                    || row.GetValue(5) is not long count || count is < 1 or > int.MaxValue) throw ServiceInvalid();
                groups.Add(new(checked((int)ordinal), ServicePrincipal(row, 1), ServiceBit(row, 4), count));
            }
        ServiceSlice(groups.Count, start, context.InitialMembershipCount);
        InitialMembershipMark? next = start + groups.Count < context.InitialMembershipCount
            ? new(reference.GenerationId, reference.FindingId, context.Account.ObjectGuid, groups[^1].Ordinal) : null;
        return Result<SavedInitialMemberships>.Success(new(context, groups, next));
    }

    public Result<SavedMembershipRoutes> ReadMembershipRoutes(FindingReference reference, int membershipOrdinal, MembershipRouteMark? after)
    {
        var saved = ReadServiceContext(reference);
        if (!saved.IsSuccess) return Result<SavedMembershipRoutes>.Failure(saved.Error);
        var context = saved.Value;
        var group = ReadServiceMembership(context, membershipOrdinal);
        if (after is { } mark && (!ServiceMark(context, mark.GenerationId, mark.FindingId, mark.AccountGuid)
            || mark.MembershipOrdinal != membershipOrdinal)) throw ServiceInvalid();
        var start = ServiceStart(after?.Ordinal, group.RouteCount);
        using var command = ServiceCommand(context, RouteHeaderSql + """
            WHERE r.subject_id=$subject AND r.membership_ordinal=$membership AND r.route_ordinal>$after
            ORDER BY r.route_ordinal LIMIT $limit
            """, membershipOrdinal, after: after?.Ordinal ?? -1);
        var routes = new List<SavedMembershipRoute>();
        using (var row = command.ExecuteReader())
            while (row.Read())
            {
                _readCancellation.ThrowIfCancellationRequested();
                var route = ServiceRoute(row, context, group);
                if (route.Ordinal != start + routes.Count) throw ServiceInvalid();
                routes.Add(route);
            }
        ServiceSlice(routes.Count, start, group.RouteCount);
        MembershipRouteMark? next = start + routes.Count < group.RouteCount
            ? new(reference.GenerationId, reference.FindingId, context.Account.ObjectGuid, membershipOrdinal, routes[^1].Ordinal) : null;
        return Result<SavedMembershipRoutes>.Success(new(context, group, routes, next));
    }

    public Result<SavedMembershipSteps> ReadMembershipSteps(FindingReference reference, int membershipOrdinal, int routeOrdinal,
        MembershipStepMark? after)
    {
        var saved = ReadServiceContext(reference);
        if (!saved.IsSuccess) return Result<SavedMembershipSteps>.Failure(saved.Error);
        var context = saved.Value;
        var group = ReadServiceMembership(context, membershipOrdinal);
        if (routeOrdinal < 0 || routeOrdinal >= group.RouteCount || after is { } mark
            && (!ServiceMark(context, mark.GenerationId, mark.FindingId, mark.AccountGuid)
                || mark.MembershipOrdinal != membershipOrdinal || mark.RouteOrdinal != routeOrdinal)) throw ServiceInvalid();
        SavedMembershipRoute route;
        using (var command = ServiceCommand(context, RouteHeaderSql + """
            WHERE r.subject_id=$subject AND r.membership_ordinal=$membership AND r.route_ordinal=$route
            """, membershipOrdinal, routeOrdinal))
        using (var row = command.ExecuteReader())
        {
            if (!row.Read()) throw ServiceInvalid();
            route = ServiceRoute(row, context, group);
        }
        var start = ServiceStart(after?.Ordinal, route.StepCount);
        using var stepsCommand = ServiceCommand(context, """
            SELECT step_ordinal,sid,scope,distinguished_name,is_primary_group FROM membership_route_step
            WHERE subject_id=$subject AND membership_ordinal=$membership AND route_ordinal=$route AND step_ordinal>$after
            ORDER BY step_ordinal LIMIT $limit
            """, membershipOrdinal, routeOrdinal, after?.Ordinal ?? -1);
        var steps = new List<SavedMembershipStep>();
        using (var row = stepsCommand.ExecuteReader())
            while (row.Read())
            {
                _readCancellation.ThrowIfCancellationRequested();
                if (row.GetValue(0) is not long ordinal || ordinal != start + steps.Count) throw ServiceInvalid();
                var primary = ServiceBit(row, 4);
                if (ordinal == 0 && primary || route.EstablishesProtection && primary) throw ServiceInvalid();
                steps.Add(new(checked((int)ordinal), ServicePrincipal(row, 1), primary));
            }
        ServiceSlice(steps.Count, start, route.StepCount);
        MembershipStepMark? next = start + steps.Count < route.StepCount
            ? new(reference.GenerationId, reference.FindingId, context.Account.ObjectGuid, membershipOrdinal, routeOrdinal, steps[^1].Ordinal) : null;
        return Result<SavedMembershipSteps>.Success(new(context, group, route, steps, next));
    }

    private Result<ServiceRegistrationContext> ReadServiceContext(FindingReference reference)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        _readCancellation.ThrowIfCancellationRequested();
        var selected = ReadSelectedFinding(reference);
        if (!selected.IsSuccess) return Result<ServiceRegistrationContext>.Failure(selected.Error);
        var finding = selected.Value;
        if (finding.RuleId != "SEC-021") throw ServiceInvalid();
        OpenPart(StoreSegmentRole.PermissionProof);
        using var command = _connection.CreateCommand();
        command.CommandText = """
            SELECT k.object_sid,k.user_account_control,k.unreadable_service_names,k.protection_catalogue_version,
                   k.direct_protection_entry_id,k.direct_protection_name,m.incomplete_reasons,
                   (SELECT COUNT(*) FROM finding_kerberoastable_account_spn s WHERE s.finding_id=k.finding_id),
                   (SELECT COUNT(DISTINCT r.membership_ordinal) FROM membership_route r WHERE r.subject_id=CAST(k.finding_id AS TEXT)),
                   f.protection_catalogue_version,f.direct_protection_entry_id,f.direct_protection_name
            FROM finding_kerberoastable_account k JOIN finding f ON f.finding_id=k.finding_id
            JOIN membership_route_summary m ON m.subject_id=CAST(k.finding_id AS TEXT) WHERE k.finding_id=$id
            """;
        command.Parameters.AddWithValue("$id", reference.FindingId);
        using var row = command.ExecuteReader();
        if (!row.Read() || row.GetValue(0) is not string sid || row.GetValue(1) is not long control || control is < 0 or > uint.MaxValue
            || row.GetValue(2) is not long unreadable || unreadable is < 0 or > int.MaxValue
            || row.GetValue(3) is not long catalogue || catalogue is < 1 or > int.MaxValue
            || row.GetValue(6) is not long reasons || reasons is < 0 or > int.MaxValue
            || row.GetValue(7) is not long names || row.GetValue(8) is not long groups
            || !Equals(row.GetValue(3), row.GetValue(9)) || !Equals(row.GetValue(4), row.GetValue(10))
            || !Equals(row.GetValue(5), row.GetValue(11))) throw ServiceInvalid();
        int? direct = row.IsDBNull(4) ? null : row.GetValue(4) is long id && id is >= 0 and <= int.MaxValue ? (int)id : throw ServiceInvalid();
        var context = new ServiceRegistrationContext(reference, finding.Subject,
            new(finding.ObjectGuid, finding.DistinguishedName, finding.DomainFqdn, finding.ObjectClass), finding.PrincipalName,
            sid, (uint)control, (int)unreadable, (int)catalogue, direct, row.IsDBNull(5) ? null : row.GetString(5),
            (MembershipRouteIncompleteReason)reasons, names, groups, finding.Coverage);
        if (!context.Matches(finding)) throw ServiceInvalid();
        return Result<ServiceRegistrationContext>.Success(context);
    }

    private SavedInitialMembership ReadServiceMembership(ServiceRegistrationContext context, int ordinal)
    {
        if (ordinal < 0 || ordinal >= context.InitialMembershipCount) throw ServiceInvalid();
        using var command = ServiceCommand(context, """
            SELECT s.sid,s.scope,s.distinguished_name,s.is_primary_group,
                   (SELECT COUNT(*) FROM membership_route x WHERE x.subject_id=r.subject_id AND x.membership_ordinal=r.membership_ordinal)
            FROM membership_route r JOIN membership_route_step s
              ON s.subject_id=r.subject_id AND s.membership_ordinal=r.membership_ordinal AND s.route_ordinal=0 AND s.step_ordinal=1
            WHERE r.subject_id=$subject AND r.membership_ordinal=$membership AND r.route_ordinal=0
            """, ordinal);
        using var row = command.ExecuteReader();
        if (!row.Read() || row.GetValue(4) is not long count || count is < 1 or > int.MaxValue) throw ServiceInvalid();
        return new(ordinal, ServicePrincipal(row, 0), ServiceBit(row, 3), count);
    }

    private const string RouteHeaderSql = """
        SELECT r.route_ordinal,r.catalogue_entry_id,r.root_name,r.authorization,r.establishes_protection,
               (SELECT COUNT(*) FROM membership_route_step x WHERE x.subject_id=r.subject_id AND x.membership_ordinal=r.membership_ordinal AND x.route_ordinal=r.route_ordinal),
               a.sid,a.is_primary_group,b.sid,b.scope,b.distinguished_name,b.is_primary_group,
               z.sid,z.scope,z.distinguished_name
        FROM membership_route r JOIN membership_route_step a
          ON a.subject_id=r.subject_id AND a.membership_ordinal=r.membership_ordinal AND a.route_ordinal=r.route_ordinal AND a.step_ordinal=0
        JOIN membership_route_step b
          ON b.subject_id=r.subject_id AND b.membership_ordinal=r.membership_ordinal AND b.route_ordinal=r.route_ordinal AND b.step_ordinal=1
        JOIN membership_route_step z
          ON z.subject_id=r.subject_id AND z.membership_ordinal=r.membership_ordinal AND z.route_ordinal=r.route_ordinal
          AND z.step_ordinal=(SELECT MAX(t.step_ordinal) FROM membership_route_step t
              WHERE t.subject_id=r.subject_id AND t.membership_ordinal=r.membership_ordinal AND t.route_ordinal=r.route_ordinal)

        """;

    private static SavedMembershipRoute ServiceRoute(SqliteDataReader row, ServiceRegistrationContext context, SavedInitialMembership group)
    {
        if (row.GetValue(0) is not long ordinal || ordinal is < 0 or > int.MaxValue
            || row.GetValue(1) is not long catalogue || catalogue is < 0 or > int.MaxValue || string.IsNullOrWhiteSpace(row.GetString(2))
            || !Enum.TryParse<MembershipRouteAuthorization>(row.GetString(3), out var authorization) || !Enum.IsDefined(authorization)
            || row.GetValue(5) is not long count || count is < 2 or > int.MaxValue
            || row.GetString(6) != context.Sid || ServiceBit(row, 7)
            || ServicePrincipal(row, 8) != group.Principal || ServiceBit(row, 11) != group.IsPrimaryGroup) throw ServiceInvalid();
        var protection = ServiceBit(row, 4);
        if (protection && group.IsPrimaryGroup) throw ServiceInvalid();
        return new((int)ordinal, (int)catalogue, row.GetString(2), authorization, protection, count)
            { RootPrincipal = ServicePrincipal(row, 12) };
    }

    private SqliteCommand ServiceCommand(ServiceRegistrationContext context, string sql, int membership = -1, int route = -1, int after = -1)
    {
        var command = _connection.CreateCommand();
        command.CommandText = sql;
        command.Parameters.AddWithValue("$id", context.Reference.FindingId);
        command.Parameters.AddWithValue("$subject", context.Reference.FindingId.ToString(CultureInfo.InvariantCulture));
        command.Parameters.AddWithValue("$membership", membership);
        command.Parameters.AddWithValue("$route", route);
        command.Parameters.AddWithValue("$after", after);
        command.Parameters.AddWithValue("$limit", SavedServiceRegistrations.PageSize);
        return command;
    }

    private static int ServiceStart(int? after, long count)
    {
        if (count < 0 || count > int.MaxValue) throw ServiceInvalid();
        if (after is not { } ordinal) return 0;
        if (ordinal < 0 || ordinal >= count - 1 || (ordinal + 1) % SavedServiceRegistrations.PageSize != 0) throw ServiceInvalid();
        return checked(ordinal + 1);
    }
    private static void ServiceSlice(int count, int start, long total)
    {
        if (count != Math.Min(SavedServiceRegistrations.PageSize, total - start)) throw ServiceInvalid();
    }
    private static MembershipRoutePrincipal ServicePrincipal(SqliteDataReader row, int column)
    {
        if (row.GetValue(column) is not string sid || Sid.ToBytes(sid) is null
            || !row.IsDBNull(column + 1) && string.IsNullOrWhiteSpace(row.GetString(column + 1))
            || !row.IsDBNull(column + 2) && string.IsNullOrWhiteSpace(row.GetString(column + 2))) throw ServiceInvalid();
        return new(sid, row.IsDBNull(column + 1) ? null : row.GetString(column + 1), row.IsDBNull(column + 2) ? null : row.GetString(column + 2));
    }
    private static bool ServiceBit(SqliteDataReader row, int column) =>
        row.GetValue(column) is long value && value is 0 or 1 ? value == 1 : throw ServiceInvalid();
    private static bool ServiceMark(ServiceRegistrationContext context, Guid generation, long finding, Guid account) =>
        generation == context.Reference.GenerationId && finding == context.Reference.FindingId && account == context.Account.ObjectGuid;
    private static InvalidDataException ServiceInvalid() => new(SavedServiceRegistrations.InvalidDetails);
}
