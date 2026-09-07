using System.Text.Json;
using Microsoft.Data.Sqlite;

namespace SecureAD.Judgement;

internal static class SelfMembershipCoverageStorage
{
    private static readonly JsonSerializerOptions ReadOptions = new()
    {
        RespectRequiredConstructorParameters = true,
        RespectNullableAnnotations = true,
    };

    internal static SelfMembershipSummary? Read(SqliteConnection connection, JudgementDescription description)
    {
        using var product = connection.CreateCommand();
        product.CommandText = "SELECT evaluator_version,completed FROM self_membership_product WHERE id=1";
        using var status = product.ExecuteReader();
        if (!status.Read())
        {
            using var orphaned = connection.CreateCommand();
            orphaned.CommandText = "SELECT EXISTS(SELECT 1 FROM self_membership_assessment) OR EXISTS(SELECT 1 FROM self_membership_discovery)";
            Require((long)orphaned.ExecuteScalar()! == 0, "requester product is absent but rows remain");
            return null;
        }
        Require(status.GetValue(0) is long version && version == 1 && status.GetValue(1) is long completed && completed == 1,
            "requester product is incomplete or its evaluator version is unsupported");
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT coverage_json FROM self_membership_discovery WHERE id=1";
        var encoded = command.ExecuteScalar();
        Require(encoded is string, "discovery record is missing");
        SelfMembershipDiscoveryCoverage coverage;
        try
        {
            coverage = JsonSerializer.Deserialize<SelfMembershipDiscoveryCoverage>((string)encoded!, ReadOptions)
                ?? throw new InvalidDataException("Self-Membership coverage is null.");
        }
        catch (JsonException error)
        {
            throw new InvalidDataException("Self-Membership coverage could not be decoded.", error);
        }
        Validate(coverage);
        command.CommandText = "SELECT COUNT(*),COALESCE(SUM(authorization='Unknown'),0),COALESCE(SUM(readiness='Unknown'),0) FROM self_membership_assessment";
        using var counts = command.ExecuteReader();
        Require(counts.Read(), "assessment counts are unavailable");
        var stored = counts.GetInt64(0);
        if (coverage.Mode == SelfMembershipDiscoveryMode.Automatic)
        {
            Require(stored == 2L * coverage.PairsDiscovered, "automatic pair and assessment counts disagree");
            using var pairs = connection.CreateCommand();
            pairs.CommandText = """
                SELECT EXISTS(SELECT 1 FROM self_membership_assessment
                GROUP BY requester_dn COLLATE NOCASE,target_dn COLLATE NOCASE
                HAVING COUNT(*)<>2 OR SUM(operation='Add')<>1 OR SUM(operation='Remove')<>1 OR COUNT(member_dn)<>0)
                """;
            Require((long)pairs.ExecuteScalar()! == 0, "automatic questions are not complete own-account Add/Remove pairs");
        }
        return new(description.GenerationId, description.EvidenceSeal, 1, stored, counts.GetInt64(1), counts.GetInt64(2), coverage);
    }

    internal static void Validate(SelfMembershipDiscoveryCoverage value)
    {
        Require(value.Version == 1, "unsupported discovery version");
        Require(Enum.IsDefined(value.Mode), "invalid discovery mode");
        Require(value.ObjectsVisited >= 0 && value.PermissionEntriesVisited >= 0 && value.MembershipValuesVisited >= 0
            && value.PairsDiscovered >= 0, "negative work counter");
        Require(value.Limitations is not null, "limitations are missing");
        foreach (var item in value.Limitations!)
        {
            Require(item is not null && Enum.IsDefined(item.Reason), "invalid limitation");
            Require(item!.PermissionOrdinal is null or >= 0, "negative permission ordinal");
            Require(item.TargetDn is null || !string.IsNullOrWhiteSpace(item.TargetDn), "blank target identity");
            Require(item.TrusteeSid is null || !string.IsNullOrWhiteSpace(item.TrusteeSid), "blank trustee identity");
            Require(item.MemberDn is null || !string.IsNullOrWhiteSpace(item.MemberDn), "blank member reference");
            Require(item.PermissionOrdinal is null || item.TargetDn is not null, "permission has no target reference");
        }
        Require(value.Limitations.Distinct().Count() == value.Limitations.Count, "duplicate limitations");
        var stopped = value.Limitations.Count(item => item.IsProcessingStop);
        var unconfigured = value.Limitations.Count(item => item.Reason == SelfMembershipDiscoveryReason.ProductionBudgetNotConfigured);
        if (value.Mode == SelfMembershipDiscoveryMode.ExplicitRequests)
        {
            Require(!value.InputScanCompleted && value.Budget is null && value.ObjectsVisited == 0
                && value.PermissionEntriesVisited == 0 && value.MembershipValuesVisited == 0 && value.PairsDiscovered == 0
                && value.Limitations.Count == 0, "explicit requests cannot claim discovery work");
            return;
        }
        Require(value.CaptureIsComplete || value.Limitations.Any(item => item.Reason == SelfMembershipDiscoveryReason.CaptureIncomplete),
            "incomplete capture lacks its limitation");
        if (value.Budget is null)
        {
            Require(!value.InputScanCompleted && unconfigured == 1 && stopped == 0 && value.ObjectsVisited == 0
                && value.PermissionEntriesVisited == 0 && value.MembershipValuesVisited == 0 && value.PairsDiscovered == 0,
                "unconfigured discovery cannot claim work or a processing stop");
            return;
        }
        var budget = value.Budget;
        Require(budget.Objects >= 0 && budget.PermissionEntries >= 0 && budget.MembershipValues >= 0 && budget.Pairs >= 0,
            "negative configured budget");
        Require(value.ObjectsVisited <= budget.Objects && value.PermissionEntriesVisited <= budget.PermissionEntries
            && value.MembershipValuesVisited <= budget.MembershipValues && value.PairsDiscovered <= budget.Pairs,
            "work counters exceed the recorded budget");
        Require(unconfigured == 0 && (value.InputScanCompleted ? stopped == 0 : stopped == 1),
            "scan completion and processing stop disagree");
        foreach (var item in value.Limitations.Where(item => item.IsProcessingStop))
            Require(item.Reason switch
            {
                SelfMembershipDiscoveryReason.ObjectsBudgetExceeded => value.ObjectsVisited == budget.Objects,
                SelfMembershipDiscoveryReason.PermissionBudgetExceeded => value.PermissionEntriesVisited == budget.PermissionEntries,
                SelfMembershipDiscoveryReason.MembershipBudgetExceeded => value.MembershipValuesVisited == budget.MembershipValues,
                SelfMembershipDiscoveryReason.PairBudgetExceeded => value.PairsDiscovered == budget.Pairs,
                _ => false,
            }, "stop reason does not match consumed work");
    }

    private static void Require(bool condition, string detail)
    {
        if (!condition) throw new InvalidDataException("Self-Membership coverage is invalid: " + detail + ".");
    }
}
