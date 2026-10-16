using Microsoft.Data.Sqlite;
using SecureAD.Evidence.Run;
using SecureAD.Kernel;
using SecureAD.Kernel.Capture;
using SecureAD.Kernel.Schema;
using SecureAD.Kernel.Security;

namespace SecureAD.Evidence.Inventory;

internal static class DashboardOverviewStorage
{
    internal const int Version = 1;

    internal static CapturedLibraryHeader Write(SqliteConnection connection, string directory, long objects, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        var path = BundleLayout.OverviewPartialPath(directory);
        if (File.Exists(path)) throw new IOException("An unfinished Dashboard overview already exists.");
        var counts = InventoryReader.CountsByDomain(connection, navigation: true, attachedNavigation: true, token: token);
        var withholding = InventoryReader.DomainsReadOverAWithholdingConnection(connection, attachedNavigation: true, token: token);
        var policies = InventoryReader.PolicyCoverage(connection, attachedNavigation: true);
        token.ThrowIfCancellationRequested();
        using var command = connection.CreateCommand();
        command.CommandText = "ATTACH DATABASE $path AS overview";
        command.Parameters.AddWithValue("$path", path);
        command.ExecuteNonQuery();
        command.Parameters.Clear();
        command.CommandText = "PRAGMA overview.journal_mode=WAL; PRAGMA overview.synchronous=NORMAL; PRAGMA overview.cache_size=-2048";
        command.ExecuteNonQuery();
        using var transaction = connection.BeginTransaction();
        command.Transaction = transaction;
        command.CommandText = """
            CREATE TABLE overview.overview_product (
                id INTEGER PRIMARY KEY CHECK(id=1), schema_version INTEGER NOT NULL,
                capture_generation TEXT NOT NULL, captured_objects INTEGER NOT NULL CHECK(captured_objects>=0),
                evidence_schema_version INTEGER NOT NULL, captured_attribute_catalog_version INTEGER NOT NULL,
                schema_guid_catalog_version INTEGER NOT NULL, security_descriptor_parser_version INTEGER NOT NULL,
                forest_fqdn TEXT NOT NULL, coverage_id TEXT NOT NULL,
                declared_domains INTEGER NOT NULL CHECK(declared_domains>=0),
                excluded_classes INTEGER NOT NULL CHECK(excluded_classes>=0),
                policies_declared INTEGER NOT NULL CHECK(policies_declared>=0),
                policies_read INTEGER NOT NULL CHECK(policies_read BETWEEN 0 AND policies_declared));
            CREATE TABLE overview.domain_inventory (
                domain_fqdn TEXT PRIMARY KEY COLLATE NOCASE, outcome TEXT NOT NULL, reason TEXT NULL,
                users INTEGER NULL CHECK(users>=0), computers INTEGER NULL CHECK(computers>=0),
                groups INTEGER NULL CHECK(groups>=0), organisational_units INTEGER NULL CHECK(organisational_units>=0),
                may_withhold INTEGER NOT NULL CHECK(may_withhold IN (0,1)),
                CHECK((outcome='Read' AND users IS NOT NULL AND computers IS NOT NULL
                    AND groups IS NOT NULL AND organisational_units IS NOT NULL)
                    OR (outcome<>'Read' AND users IS NULL AND computers IS NULL
                        AND groups IS NULL AND organisational_units IS NULL AND may_withhold=0)));
            CREATE TABLE overview.class_exclusion (class_name TEXT PRIMARY KEY);
            INSERT INTO overview.class_exclusion SELECT class_name FROM main.capture_object_class_exclusion;
            INSERT INTO overview.overview_product
            SELECT 1,$version,capture_generation_id,$objects,schema_version,captured_attribute_catalog_version,
                schema_guid_catalog_version,security_descriptor_parser_version,forest_fqdn,coverage_id,
                (SELECT COUNT(*) FROM main.domain_coverage),
                (SELECT COUNT(*) FROM main.capture_object_class_exclusion),$declared,$read
            FROM main.bundle;
            """;
        command.Parameters.AddWithValue("$version", Version);
        command.Parameters.AddWithValue("$objects", objects);
        command.Parameters.AddWithValue("$declared", policies.Declared);
        command.Parameters.AddWithValue("$read", policies.Read);
        command.ExecuteNonQuery();
        command.Parameters.Clear();
        command.CommandText = "SELECT domain_fqdn,outcome,reason FROM main.domain_coverage ORDER BY domain_fqdn";
        var domains = new List<(string Name, string Outcome, string? Reason)>();
        using (var rows = command.ExecuteReader())
            while (rows.Read())
            {
                token.ThrowIfCancellationRequested();
                domains.Add((rows.GetString(0), rows.GetString(1), rows.IsDBNull(2) ? null : rows.GetString(2)));
            }
        command.CommandText = """
            INSERT INTO overview.domain_inventory
            VALUES($domain,$outcome,$reason,$users,$computers,$groups,$units,$withhold)
            """;
        var domain = command.Parameters.Add("$domain", SqliteType.Text);
        var outcome = command.Parameters.Add("$outcome", SqliteType.Text);
        var reason = command.Parameters.Add("$reason", SqliteType.Text);
        var users = command.Parameters.Add("$users", SqliteType.Integer);
        var computers = command.Parameters.Add("$computers", SqliteType.Integer);
        var groups = command.Parameters.Add("$groups", SqliteType.Integer);
        var units = command.Parameters.Add("$units", SqliteType.Integer);
        var withhold = command.Parameters.Add("$withhold", SqliteType.Integer);
        command.Prepare();
        foreach (var row in domains)
        {
            token.ThrowIfCancellationRequested();
            var wasRead = row.Outcome == "Read";
            var counted = counts.GetValueOrDefault(row.Name, ObjectCounts.None);
            domain.Value = row.Name;
            outcome.Value = row.Outcome;
            reason.Value = (object?)row.Reason ?? DBNull.Value;
            users.Value = wasRead ? counted.Users : DBNull.Value;
            computers.Value = wasRead ? counted.Computers : DBNull.Value;
            groups.Value = wasRead ? counted.Groups : DBNull.Value;
            units.Value = wasRead ? counted.OrganisationalUnits : DBNull.Value;
            withhold.Value = wasRead && withholding.Contains(row.Name) ? 1 : 0;
            command.ExecuteNonQuery();
        }
        token.ThrowIfCancellationRequested();
        transaction.Commit();
        command.Transaction = null;
        command.Parameters.Clear();
        command.CommandText = "SELECT coverage_id FROM main.bundle";
        var coverageId = command.ExecuteScalar() as string
            ?? throw new InvalidDataException("The captured library identity is absent.");
        return new(coverageId, domains.Select(row => new CapturedDomainHeader(row.Name, row.Outcome, row.Reason)).ToArray());
    }

    internal static Result<ForestInventory> Read(
        SqliteConnection connection, StoreRootManifest root, string directory, CancellationToken token)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT id,schema_version,capture_generation,captured_objects,evidence_schema_version,
                captured_attribute_catalog_version,schema_guid_catalog_version,security_descriptor_parser_version,
                forest_fqdn,coverage_id,declared_domains,excluded_classes,policies_declared,policies_read
            FROM overview_product ORDER BY id
            """;
        string forest;
        string coverageId;
        int declaredDomains, excludedClasses, declaredPolicies, readPolicies;
        using (var row = command.ExecuteReader())
        {
            if (!row.Read() || row.GetInt32(0) != 1 || row.GetInt32(1) != Version
                || root.Segment(StoreSegmentRole.Overview).SchemaVersion != Version
                || row.GetString(2) != root.GenerationId.ToString("D") || row.GetInt64(3) != root.CapturedObjects
                || row.GetInt32(4) != BundleSchema.Version
                || root.Segment(StoreSegmentRole.Evidence).SchemaVersion != BundleSchema.Version
                || row.GetInt32(5) != CapturedAttributeCatalog.Version
                || row.GetInt32(6) != SchemaGuidCatalog.Version
                || row.GetInt32(7) != SecurityDescriptorParser.Version)
                throw new InvalidDataException("The saved Dashboard overview contradicts its capture root or this build.");
            forest = row.GetString(8);
            coverageId = row.GetString(9);
            declaredDomains = row.GetInt32(10);
            excludedClasses = row.GetInt32(11);
            declaredPolicies = row.GetInt32(12);
            readPolicies = row.GetInt32(13);
            if (declaredDomains < 0 || excludedClasses < 0 || row.Read())
                throw new InvalidDataException("The saved Dashboard overview has invalid declarations.");
        }
        command.CommandText = """
            SELECT domain_fqdn,outcome,reason,users,computers,groups,organisational_units,may_withhold
            FROM domain_inventory ORDER BY domain_fqdn
            """;
        var domains = new List<DomainInventory>();
        using (var rows = command.ExecuteReader())
            while (rows.Read())
            {
                token.ThrowIfCancellationRequested();
                var coverage = DomainCoverageReading.Read(
                    rows.GetString(0), rows.GetString(1), rows.IsDBNull(2) ? null : rows.GetString(2), directory);
                if (!coverage.IsSuccess) return Result<ForestInventory>.Failure(coverage.Error);
                var withhold = rows.GetInt32(7);
                if (withhold is not (0 or 1))
                    throw new InvalidDataException("The saved Dashboard confidentiality qualification is invalid.");
                var hasCounts = Enumerable.Range(3, 4).All(index => !rows.IsDBNull(index));
                var hasNoCounts = Enumerable.Range(3, 4).All(rows.IsDBNull);
                if (coverage.Value.Outcome == DomainReadOutcome.Read)
                {
                    if (!hasCounts) throw new InvalidDataException("A counted domain has missing Dashboard counts.");
                    var counts = new ObjectCounts(rows.GetInt32(3), rows.GetInt32(4), rows.GetInt32(5), rows.GetInt32(6));
                    if (counts.Users < 0 || counts.Computers < 0 || counts.Groups < 0 || counts.OrganisationalUnits < 0)
                        throw new InvalidDataException("A counted domain has invalid Dashboard counts.");
                    domains.Add(DomainInventory.Counted(coverage.Value, counts, withhold == 1));
                }
                else
                {
                    if (!hasNoCounts || withhold != 0)
                        throw new InvalidDataException("An uncounted domain carries Dashboard numbers or qualifications.");
                    domains.Add(DomainInventory.NotCounted(coverage.Value));
                }
            }
        if (domains.Count == 0)
            return Result<ForestInventory>.Failure(AuditError.Create(ErrorCategory.Evidence, "CoverageAbsent",
                ErrorSeverity.Failed, "This run records no domain at all. Every bundle carries one row per declared "
                + "domain, so an empty table means the run's coverage was never written rather "
                + "than that the forest has no domains.", directory));
        if (domains.Count != declaredDomains
            || domains.Select(domain => domain.DomainFqdn).Distinct(StringComparer.OrdinalIgnoreCase).Count() != declaredDomains)
            throw new InvalidDataException("The saved Dashboard overview is missing declared domains or repeats one.");
        RunScope.Of(coverageId, domains.Select(domain => domain.Coverage));
        command.CommandText = "SELECT class_name FROM class_exclusion ORDER BY class_name";
        var exclusions = new List<string>();
        using (var rows = command.ExecuteReader())
            while (rows.Read())
            {
                token.ThrowIfCancellationRequested();
                exclusions.Add(rows.GetString(0));
            }
        if (exclusions.Count != excludedClasses)
            throw new InvalidDataException("The saved Dashboard overview is missing recorded class exclusions.");
        token.ThrowIfCancellationRequested();
        return Result<ForestInventory>.Success(ForestInventory.Of(forest, domains, declaredPolicies, readPolicies, exclusions));
    }
}
