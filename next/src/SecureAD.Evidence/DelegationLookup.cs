using Microsoft.Data.Sqlite;
using SecureAD.Kernel.Naming;
using SecureAD.Kernel.Schema;
using SecureAD.Kernel.Security;

namespace SecureAD.Evidence;

/// <summary>Recorded rights to look for, not operations proved available to a requester.</summary>
public enum DelegationPermission
{
    /// <summary>Every original entry naming the selected SID.</summary>
    All,
    /// <summary>Password-reset entries, including broader recorded rights.</summary>
    ResetPassword,
    /// <summary>Entries naming creation of user objects or any child class.</summary>
    CreateUser,
    /// <summary>Property-write entries with recorded or unresolved user scope.</summary>
    WriteUserProperties,
}

/// <summary>A captured identity, or an explicitly unresolved SID supplied by the operator.</summary>
public sealed record DelegationPrincipal(long? ObjectId, string Sid, string Name,
    string? DistinguishedName, string? DomainFqdn);

/// <summary>A principal-search continuation bound to the exact evidence and search text.</summary>
public sealed record DelegationPrincipalMark(string EvidenceFingerprint, string Search, long ObjectId);

/// <summary>A bounded identity page; a continuation is not a statement about capture completeness.</summary>
public sealed record DelegationPrincipalPage(IReadOnlyList<DelegationPrincipal> Principals,
    DelegationPrincipalMark? Next, bool CaptureWasComplete);

/// <summary>The complete question that a permission-result continuation belongs to.</summary>
public sealed record DelegationQuery(DelegationPrincipal Principal, DelegationPermission Permission, bool IncludeInherited)
{
    /// <summary>Joins saved containing-group membership, rather than only the named SID.</summary>
    public bool IncludeGroupHeldPermissions { get; init; }
}

/// <summary>A position in the original descriptor/object/entry sequence, not the normalized index.</summary>
public sealed record DelegationPageMark(string EvidenceFingerprint, DelegationQuery Query,
    long DescriptorId, long ObjectId, int Ordinal)
{
    /// <summary>The exact saved membership generation, absent for a direct-only question.</summary>
    public Guid? MembershipGenerationId { get; init; }
    /// <summary>The permission holder in that generation; null denotes the selected principal's own entries.</summary>
    public int? HolderMembershipId { get; init; }
}

/// <summary>An original captured occurrence with its resource and capture qualifications.</summary>
public sealed record DelegationEntry(string DistinguishedName, string DomainFqdn, long DescriptorId,
    PermissionEntry Entry, DaclCompleteness DaclCompleteness, string? ScopeQualification)
{
    /// <summary>The original resource identity within the sealed evidence.</summary>
    public long ObjectId { get; init; }
    /// <summary>The saved group holding this occurrence, independent of how many membership routes reach it.</summary>
    public int? HolderMembershipId { get; init; }
}

/// <summary>Whole-capture limitations, counted independently of loaded result pages.</summary>
public sealed record DelegationCoverage(bool DeclaredScopeWasRead, IReadOnlyList<string> ExcludedObjectClasses,
    long UnreadableDescriptors, long UnattemptedDescriptors, long IncompleteDescriptors, long DescriptorErrors)
{
    /// <summary>All declared scope was read, with no excluded classes or recorded permission gaps.</summary>
    public bool IsComplete => DeclaredScopeWasRead && ExcludedObjectClasses.Count == 0 &&
        UnreadableDescriptors == 0 && UnattemptedDescriptors == 0 && IncompleteDescriptors == 0 && DescriptorErrors == 0;
}

/// <summary>A bounded page of recorded entries, with no effective-access verdict or inferred total.</summary>
public sealed record DelegationPage(IReadOnlyList<DelegationEntry> Entries, DelegationPageMark? Next,
    DelegationCoverage Coverage)
{
    /// <summary>The existing display-page size, not a limit on the number of matches.</summary>
    public const int PageSize = ObjectListingReader.PageSize;
    /// <summary>Saved membership supporting a group-inclusive question; absent only for direct-only reads.</summary>
    public DelegationMembership? Membership { get; init; }
}

internal static class DelegationLookup
{
    internal const int PageSize = DelegationPage.PageSize;
    private const int ControlAccess = 0x100;
    private const int CreateChild = 0x1;
    private const int WriteProperty = 0x20;

    internal static DelegationPrincipalPage FindPrincipals(SqliteConnection connection, string fingerprint,
        BundleDescription description, string search, DelegationPrincipalMark? after, CancellationToken token,
        bool serving = false)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(search);
        search = search.Trim();
        if (after is not null && (after.EvidenceFingerprint != fingerprint || after.Search != search || after.ObjectId < 0))
            throw new ArgumentException("The principal-search page belongs to different evidence or a different search.", nameof(after));
        token.ThrowIfCancellationRequested();
        var sid = Sid.ToBytes(search);
        if (sid is null && search.StartsWith("S-1-", StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("The supplied SID is not valid.", nameof(search));
        var principalClass = serving ? "(o.delegation_is_user=1 OR o.delegation_is_group=1)" : $"""
            EXISTS (SELECT 1 FROM {BundleSchema.ValueTableNameFor("objectClass")} AS c
                    WHERE c.object_id=o.object_id AND c.value COLLATE NOCASE IN ('user','group'))
            """;
        var identity = sid is not null ? "o.objectsid = $sid" : $"""
            (instr(lower(o.distinguished_name), lower($search)) > 0
             OR instr(lower(o.samaccountname), lower($search)) > 0)
            AND {principalClass}
            """;
        using var command = connection.CreateCommand();
        command.CommandText = $"""
            SELECT o.object_id, o.objectsid, o.distinguished_name, o.domain_fqdn
            FROM captured_object AS o
            WHERE o.object_id > $after AND o.objectsid IS NOT NULL
              AND {identity}
            ORDER BY o.object_id LIMIT $limit
            """;
        command.Parameters.AddWithValue("$after", after?.ObjectId ?? 0);
        command.Parameters.AddWithValue("$limit", PageSize + 1);
        if (sid is not null) command.Parameters.Add("$sid", SqliteType.Blob).Value = sid;
        else command.Parameters.AddWithValue("$search", search);
        var principals = new List<DelegationPrincipal>();
        using (var read = command.ExecuteReader())
        {
            while (read.Read())
            {
                token.ThrowIfCancellationRequested();
                var textSid = Sid.ToText((byte[])read[1])
                    ?? throw new InvalidDataException("A captured principal has an unreadable SID.");
                var dn = read.GetString(2);
                principals.Add(new(read.GetInt64(0), textSid, DnHelper.ExtractFirstRdn(dn), dn, read.GetString(3)));
            }
        }
        DelegationPrincipalMark? next = null;
        if (principals.Count > PageSize)
        {
            principals.RemoveAt(PageSize);
            next = new(fingerprint, search, principals[^1].ObjectId!.Value);
        }
        if (sid is not null && principals.Count == 0 && after is null)
        {
            var textSid = Sid.ToText(sid) ?? throw new ArgumentException("The SID could not be read.", nameof(search));
            principals.Add(new(null, textSid, WellKnownSidCatalog.FindBySid(textSid)?.DisplayName ?? textSid, null, null));
        }
        return new(principals, next, description.EveryDeclaredUnitRecordedAsRead);
    }

    // The comparison index sorts, expands generic rights and removes duplicates. It identifies
    // candidate descriptors only; displayed occurrences always come from the original bytes.
    internal static string CandidateSql => """
        SELECT DISTINCT d.descriptor_id
        FROM trustee AS t
        CROSS JOIN access_entry AS a INDEXED BY ix_access_entry_trustee ON a.trustee_id=t.trustee_id
        CROSS JOIN descriptor_entry AS d INDEXED BY ix_descriptor_entry_entry ON d.entry_id=a.entry_id
        WHERE t.sid=$sid AND d.descriptor_id >= $after
          AND ($mask=0 OR (a.access_mask & $mask)<>0)
          AND ($inherited=1 OR a.is_inherited=0)
          AND EXISTS (SELECT 1 FROM object_security_descriptor AS resource WHERE resource.descriptor_id=d.descriptor_id)
        ORDER BY d.descriptor_id
        """;

    internal static DelegationPage Read(SqliteConnection connection, string fingerprint, BundleDescription description,
        SchemaGuidCatalog schema, DelegationQuery query, DelegationPageMark? after, CancellationToken token, int pageSize = PageSize)
        => Read(connection, fingerprint, ReadCoverage(connection, description), schema, query, after, token, pageSize);

    internal static DelegationPage Read(SqliteConnection connection, string fingerprint, DelegationCoverage coverage,
        SchemaGuidCatalog schema, DelegationQuery query, DelegationPageMark? after, CancellationToken token, int pageSize,
        bool serving = false)
    {
        ArgumentNullException.ThrowIfNull(query);
        ArgumentNullException.ThrowIfNull(query.Principal);
        ArgumentOutOfRangeException.ThrowIfLessThan(pageSize, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(pageSize, PageSize + 1);
        if (query.IncludeGroupHeldPermissions || after?.MembershipGenerationId is not null || after?.HolderMembershipId is not null)
            throw new ArgumentException("Group-held permissions require the bound saved-membership reader.", nameof(query));
        if (!Enum.IsDefined(query.Permission)) throw new ArgumentOutOfRangeException(nameof(query));
        var sidBytes = Sid.ToBytes(query.Principal.Sid)
            ?? throw new ArgumentException("Select a principal with a valid SID.", nameof(query));
        if (Sid.ToText(sidBytes) != query.Principal.Sid)
            throw new ArgumentException("Select the canonical SID returned by the principal search.", nameof(query));
        if (after is not null && (after.EvidenceFingerprint != fingerprint || after.Query != query ||
            after.DescriptorId <= 0 || after.ObjectId <= 0 || after.Ordinal < 0))
            throw new ArgumentException("The delegation page belongs to different evidence or a different question.", nameof(after));
        token.ThrowIfCancellationRequested();
        ValidatePrincipal(connection, query.Principal, sidBytes);
        var requiredGuid = query.Permission switch
        {
            DelegationPermission.ResetPassword => SchemaGuid(schema, "User-Force-Change-Password", SchemaGuidKind.ExtendedRight),
            DelegationPermission.CreateUser or DelegationPermission.WriteUserProperties => SchemaGuid(schema, "user", SchemaGuidKind.ObjectClass),
            _ => null,
        };
        using var candidates = connection.CreateCommand();
        candidates.CommandText = serving ? CapturedDelegationStorage.CandidateSql : CandidateSql;
        candidates.Parameters.AddWithValue("$sid", query.Principal.Sid);
        candidates.Parameters.AddWithValue("$after", after?.DescriptorId ?? 0);
        candidates.Parameters.AddWithValue("$mask", query.Permission switch
        {
            DelegationPermission.ResetPassword => ControlAccess,
            DelegationPermission.CreateUser => CreateChild,
            DelegationPermission.WriteUserProperties => WriteProperty,
            _ => 0,
        });
        candidates.Parameters.AddWithValue("$inherited", query.IncludeInherited ? 1 : 0);
        var rows = new List<DelegationEntry>();
        var marks = new List<DelegationPageMark>();
        using var descriptors = candidates.ExecuteReader();
        while (descriptors.Read())
        {
            token.ThrowIfCancellationRequested();
            var descriptorId = descriptors.GetInt64(0);
            var (parsed, completeness) = ReadDescriptor(connection, descriptorId);
            var namedEntries = parsed.DaclAces.Where(ace => ace.TrusteeSid == query.Principal.Sid).ToArray();
            if (namedEntries.Length == 0)
                throw new InvalidDataException("The permission index cannot be reproduced from the original captured descriptor.");
            var entries = namedEntries.Where(ace => MatchesRight(ace, query, requiredGuid)).OrderBy(ace => ace.Ordinal).ToArray();
            if (entries.Length == 0) continue;
            using var objects = connection.CreateCommand();
            var isUser = serving ? "o.delegation_is_user" : $"""
                EXISTS(SELECT 1 FROM {BundleSchema.ValueTableNameFor("objectClass")} c WHERE c.object_id=o.object_id AND c.value='user' COLLATE NOCASE)
                """;
            var classWasRead = serving ? "o.delegation_class_was_read" : $"""
                EXISTS(SELECT 1 FROM {BundleSchema.ValueTableNameFor("objectClass")} c WHERE c.object_id=o.object_id)
                """;
            objects.CommandText = $"""
                SELECT o.object_id, o.distinguished_name, o.domain_fqdn,
                       {isUser}, {classWasRead}
                FROM object_security_descriptor AS link INDEXED BY ix_object_security_descriptor
                CROSS JOIN captured_object AS o ON o.object_id=link.object_id
                WHERE link.descriptor_id=$descriptor AND o.object_id >= $after
                  AND ($domain IS NULL OR o.domain_fqdn=$domain COLLATE NOCASE)
                ORDER BY link.object_id
                """;
            objects.Parameters.AddWithValue("$descriptor", descriptorId);
            objects.Parameters.AddWithValue("$after", after?.DescriptorId == descriptorId ? after.ObjectId : 0);
            objects.Parameters.AddWithValue("$domain",
                Sid.IsBuiltinDomain(query.Principal.Sid) ? (object?)query.Principal.DomainFqdn ?? DBNull.Value : DBNull.Value);
            using var targets = objects.ExecuteReader();
            while (targets.Read())
            {
                token.ThrowIfCancellationRequested();
                var objectId = targets.GetInt64(0);
                foreach (var ace in entries)
                {
                    token.ThrowIfCancellationRequested();
                    if (after is not null && descriptorId == after.DescriptorId && objectId == after.ObjectId && ace.Ordinal <= after.Ordinal)
                        continue;
                    var qualification = UserScope(ace, query.Permission, requiredGuid, targets.GetBoolean(3), targets.GetBoolean(4));
                    if (qualification == UserScopeMismatch) continue;
                    var principal = query.Principal;
                    var trustee = new PermissionTrustee(principal.Sid, principal.DistinguishedName is null ? null : principal.Name,
                        principal.DistinguishedName, principal.DomainFqdn, null, null, null);
                    var entry = new PermissionEntry(ace.Ordinal, ace.AceType.ToString(), trustee, ace.AccessMask,
                        ace.ObjectTypeGuid, ace.InheritedObjectTypeGuid, ace.IsInherited, ace.InheritanceFlags,
                        ace.PropagationFlags, ace.HasObjectType, ace.HasInheritedObjectType, ace.ApplicationData);
                    rows.Add(new(targets.GetString(1), targets.GetString(2), descriptorId, entry, completeness, qualification) { ObjectId = objectId });
                    marks.Add(new(fingerprint, query, descriptorId, objectId, ace.Ordinal));
                    if (rows.Count > pageSize)
                        return new(rows.Take(pageSize).ToArray(), marks[pageSize - 1], coverage);
                }
            }
        }
        return new(rows, null, coverage);
    }

    private static string SchemaGuid(SchemaGuidCatalog schema, string name, SchemaGuidKind kind) =>
        schema.FindUnambiguousByLdapName(name) is { } entry && entry.Kind == kind ? entry.Guid
        : throw new InvalidDataException($"The schema does not unambiguously name '{name}' as {kind}; use All recorded permissions.");

    private static bool MatchesRight(ParsedAce ace, DelegationQuery query, string? guid)
    {
        if (!query.IncludeInherited && ace.IsInherited) return false;
        var mask = GenericRightsExpander.Expand(ace.AccessMask);
        var unscoped = !ace.HasObjectType;
        return query.Permission switch
        {
            DelegationPermission.All => true,
            DelegationPermission.ResetPassword => (mask & ControlAccess) != 0 &&
                (unscoped || string.Equals(ace.ObjectTypeGuid, guid, StringComparison.OrdinalIgnoreCase)),
            DelegationPermission.CreateUser => (mask & CreateChild) != 0 &&
                (unscoped || string.Equals(ace.ObjectTypeGuid, guid, StringComparison.OrdinalIgnoreCase)),
            DelegationPermission.WriteUserProperties => (mask & WriteProperty) != 0,
            _ => throw new ArgumentOutOfRangeException(nameof(query)),
        };
    }

    private const string UserScopeMismatch = "Not user scope";

    private static string? UserScope(ParsedAce ace, DelegationPermission permission, string? userGuid,
        bool isUser, bool classWasRead)
    {
        if (permission != DelegationPermission.WriteUserProperties) return null;
        if ((ace.PropagationFlags & 8) == 0 && isUser) return null;
        if ((ace.InheritanceFlags & 3) != 0)
        {
            if (!ace.HasInheritedObjectType ||
                string.Equals(ace.InheritedObjectTypeGuid, userGuid, StringComparison.OrdinalIgnoreCase)) return null;
            // Capture has class GUIDs, not the schema subclass hierarchy. A class-specific entry
            // might reach a user subclass; keep it visible as unresolved instead of a false absence.
            return "User scope is not established for this descendant class; review Applies to.";
        }
        return classWasRead ? UserScopeMismatch : "The target's class was not captured; user scope is not established.";
    }

    private static (ParsedSecurityDescriptor Parsed, DaclCompleteness Completeness) ReadDescriptor(
        SqliteConnection connection, long descriptorId)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT raw_bytes, dacl_completeness FROM security_descriptor WHERE descriptor_id=$id";
        command.Parameters.AddWithValue("$id", descriptorId);
        using var read = command.ExecuteReader();
        if (!read.Read()) throw new InvalidDataException("The indexed permission descriptor is missing.");
        var parsed = SecurityDescriptorParser.Parse((byte[])read[0]);
        var completeness = Enum.Parse<DaclCompleteness>(read.GetString(1));
        if (completeness == DaclCompleteness.Complete &&
            (parsed.Errors.Count != 0 || parsed.DaclCompleteness != DaclCompleteness.Complete))
            completeness = parsed.DaclCompleteness == DaclCompleteness.Unknown ? DaclCompleteness.Unknown : DaclCompleteness.Incomplete;
        return (parsed, completeness);
    }

    private static void ValidatePrincipal(SqliteConnection connection, DelegationPrincipal principal, byte[] sid)
    {
        if (principal.ObjectId is not { } id)
        {
            if (principal.DistinguishedName is not null || principal.DomainFqdn is not null)
                throw new ArgumentException("An unresolved SID cannot claim a captured identity.", nameof(principal));
            return;
        }
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT EXISTS(SELECT 1 FROM captured_object WHERE object_id=$id AND objectsid=$sid
                AND distinguished_name=$dn COLLATE BINARY AND domain_fqdn=$domain COLLATE BINARY)
            """;
        command.Parameters.AddWithValue("$id", id);
        command.Parameters.Add("$sid", SqliteType.Blob).Value = sid;
        command.Parameters.AddWithValue("$dn", (object?)principal.DistinguishedName ?? DBNull.Value);
        command.Parameters.AddWithValue("$domain", (object?)principal.DomainFqdn ?? DBNull.Value);
        if ((long)command.ExecuteScalar()! != 1)
            throw new InvalidDataException("The selected principal does not belong to this captured evidence.");
    }

    internal static DelegationCoverage ReadCoverage(SqliteConnection connection, BundleDescription description)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT (SELECT count(*) FROM unreadable_security_descriptor),
                   (SELECT count(*) FROM captured_object) - (SELECT count(*) FROM object_security_descriptor)
                     - (SELECT count(*) FROM unreadable_security_descriptor),
                   (SELECT count(*) FROM security_descriptor AS descriptor WHERE dacl_completeness <> 'Complete'
                    AND EXISTS (SELECT 1 FROM object_security_descriptor AS resource WHERE resource.descriptor_id=descriptor.descriptor_id)),
                   (SELECT count(*) FROM security_descriptor_error AS error
                    WHERE EXISTS (SELECT 1 FROM object_security_descriptor AS resource WHERE resource.descriptor_id=error.descriptor_id))
            """;
        using var read = command.ExecuteReader();
        if (!read.Read()) throw new InvalidDataException("Delegation capture coverage could not be read.");
        return new(description.EveryDeclaredUnitRecordedAsRead, description.ExcludedObjectClasses,
            read.GetInt64(0), read.GetInt64(1), read.GetInt64(2), read.GetInt64(3));
    }
}
