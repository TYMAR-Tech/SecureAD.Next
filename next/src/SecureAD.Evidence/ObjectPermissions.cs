using Microsoft.Data.Sqlite;
using SecureAD.Kernel.Naming;
using SecureAD.Kernel.Security;

namespace SecureAD.Evidence;

/// <summary>
/// Whether this bundle holds the object's security descriptor at all.
/// </summary>
/// <remarks>
/// <para>
/// <b>Three states, because all three produce no entries and only one of them is a fact about the
/// forest.</b> A run that never asked for a descriptor, a run that asked and was refused, and an
/// object that genuinely grants nothing are the same emptiness to a viewer that does not keep them
/// apart - and a production domain returned 19,927 of 100,000 objects with no readable descriptor.
/// Reporting those as objects granting nothing would tell a reader an object is safe when nobody
/// knows whether it is.
/// </para>
/// <para>
/// This is a different question from <see cref="DaclState"/>. This says whether the descriptor
/// arrived; that says what the descriptor, having arrived, contained.
/// </para>
/// </remarks>
public enum DescriptorAvailability
{
    /// <summary>The descriptor was read and is in this bundle.</summary>
    Read,

    /// <summary>The object has a descriptor and this run could not get it.</summary>
    Unreadable,

    /// <summary>Nothing was attempted - no descriptor was read and no failure was recorded.</summary>
    NotAttempted,
}

/// <summary>
/// The principal an entry names, and what this bundle knows about it.
/// </summary>
/// <remarks>
/// <para>
/// <b><see cref="DistinguishedName"/> is null far more often than it looks like it should be.</b>
/// A trustee is a SID, and a SID is only a name if the object holding it was captured by this run.
/// Well-known identities, principals from another domain, and identifiers left behind by a deleted
/// object all stay bare - the predecessor showed those as an unexplained
/// <c>S-1-5-21-…-25601</c> holding Full Control, and an operator had no way to tell which of those
/// three it was.
/// </para>
/// </remarks>
/// <param name="Sid">The identifier the entry names, as the directory stores it.</param>
/// <param name="Name">
/// The first relative name of the captured object holding this SID, or null when nothing in this
/// bundle holds it.
/// </param>
/// <param name="DistinguishedName">That object's name, or null for the same reason.</param>
/// <param name="DomainFqdn">The domain it was captured from, or null for the same reason.</param>
/// <param name="UnresolvedReason">
/// Why the SID names nothing in this bundle, when the run recorded a reason. Null both for a
/// trustee that resolved and for one whose failure to resolve was never classified.
/// </param>
public sealed record PermissionTrustee(
    string Sid,
    string? Name,
    string? DistinguishedName,
    string? DomainFqdn,
    UnresolvedReferenceReason? UnresolvedReason);

/// <summary>
/// One access control entry, as the bundle stored it.
/// </summary>
/// <remarks>
/// <b>Nothing here is worded and nothing here is judged.</b> The mask is the mask and the flags are
/// the flags. <see cref="PermissionWordingWriter"/> turns a mask into words and
/// <see cref="DangerousPermissionClassifier"/> decides whether it matters, both separately and both
/// on the reader's terms.
/// </remarks>
/// <param name="Ordinal">Where the entry sits in the canonicalised DACL, counting from zero.</param>
/// <param name="AceType">
/// The entry's type as stored - <c>AccessAllowed</c>, <c>AccessDenied</c> and the object variants.
/// Kept as the stored text rather than parsed to <see cref="Kernel.Security.AceType"/>, so a value
/// this build has no member for reaches a reader instead of being dropped.
/// </param>
/// <param name="Trustee">Who the entry names.</param>
/// <param name="AccessMask">The mask, with generic rights already expanded.</param>
/// <param name="ObjectTypeGuid">What the entry is limited to, or null when it applies to all.</param>
/// <param name="InheritedObjectTypeGuid">
/// The class of descendant the entry is inherited by, or null when it is inherited by all.
/// </param>
/// <param name="IsInherited">Whether the entry came from a container above this object.</param>
/// <param name="InheritanceFlags">The entry's inheritance flags, as the directory stores them.</param>
/// <param name="PropagationFlags">The entry's propagation flags, as the directory stores them.</param>
/// <param name="HasObjectType">
/// Whether the entry actually carried an <c>ObjectType</c> GUID, from
/// <c>ACE_OBJECT_TYPE_PRESENT</c> rather than from whether
/// <paramref name="ObjectTypeGuid"/> is null. Those are different questions: an object ACE
/// carrying no GUID narrows nothing and has the same reach as its plain counterpart, whereas a
/// GUID that is present names what the entry is scoped to. Required by <c>S-56</c> R1.
/// </param>
/// <param name="HasInheritedObjectType">
/// The same, for <c>InheritedObjectType</c>.
/// </param>
/// <param name="ApplicationData">
/// The bytes a callback ACE carries after the trustee SID, which are what make a conditional ACE
/// conditional. Empty for every other ACE type. Without it an entry that may not apply at all is
/// indistinguishable from one that always does, and a caller can say <i>this entry is
/// conditional</i> and never <i>this is the condition</i> - which is <c>F-S58-10</c>.
/// <b>It makes value equality unreliable on this record</b>, for the reason <c>ParsedAce</c> gives:
/// an array is compared by reference, so two entries with identical bytes are unequal.
/// </param>
public sealed record PermissionEntry(
    int Ordinal,
    string AceType,
    PermissionTrustee Trustee,
    int AccessMask,
    string? ObjectTypeGuid,
    string? InheritedObjectTypeGuid,
    bool IsInherited,
    byte InheritanceFlags,
    byte PropagationFlags,
    bool HasObjectType,
    bool HasInheritedObjectType,
    byte[] ApplicationData);

/// <summary>
/// Everything a bundle holds about one object's permissions.
/// </summary>
/// <remarks>
/// <para>
/// <b>The four statements beside <see cref="Entries"/> are why this is a type and not a list.</b>
/// A short entry list is indistinguishable from a permissive object unless the reader is told which
/// it is: <see cref="DaclState"/> separates a DACL granting everyone everything from one granting
/// nobody anything, <see cref="DaclCompleteness"/> says whether every declared entry arrived,
/// <see cref="DaclWasCanonical"/> says whether Windows evaluates them in the order they read in,
/// and <see cref="IsDaclProtected"/> explains an ACL that looks surprisingly short. Hand back a
/// bare collection and every one of those becomes something a reader has to already know to ask
/// for.
/// </para>
/// <para>
/// <b><see cref="Entries"/> is the stored DACL, not the canonical projection.</b> It is parsed
/// back out of the descriptor's bytes in the order the directory holds them, with nothing
/// deduplicated, so an entry the projection collapses is present here and
/// <see cref="PermissionEntry.Ordinal"/> is the position the directory stored. The <c>ace</c> table
/// remains the projection and remains what <c>ace_set_hash</c> compares runs by; per <c>S-57</c>,
/// the defect was having only one representation and not having that one.
/// </para>
/// </remarks>
/// <param name="DistinguishedName">The object, as the controller named it.</param>
/// <param name="Availability">Whether the descriptor is in this bundle at all.</param>
/// <param name="UnreadableReason">
/// What the controller or the client said when the descriptor could not be read, or null when
/// <see cref="Availability"/> is not <see cref="DescriptorAvailability.Unreadable"/>.
/// </param>
/// <param name="Owner">
/// Who owns the object - which is not an entry, and grants the ability to rewrite every entry
/// below. Null when no descriptor was read, or when the descriptor carried no owner.
/// </param>
/// <param name="DaclState">What the DACL was: present, null, empty, or unreadable.</param>
/// <param name="DaclCompleteness">Whether the DACL yielded every entry its header declared.</param>
/// <param name="DaclWasCanonical">
/// Whether the entries arrived in canonical order. False means Windows will not evaluate them in
/// the order they are listed here: AD accumulates granted and denied masks across the whole DACL
/// and adds a deny only for rights it has not already granted, so an allow read first keeps a later
/// deny from taking effect and the object is more open than its entries read.
/// <see cref="Entries"/> shows the stored order, so this says whether that order is the canonical
/// one - not, as it did while entries came from the canonical projection, whether the list is
/// hiding a reordering.
/// </param>
/// <param name="IsDaclProtected">Whether the object refuses inheritance from its containers.</param>
/// <param name="Entries">
/// The entries in the order the directory stored them, with nothing deduplicated. Read from the
/// descriptor's own bytes rather than from the <c>ace</c> table, because that table is the
/// canonical projection and <c>S-57</c> upheld that a projection cannot stand in for the stored
/// DACL.
/// </param>
/// <param name="Errors">
/// What went wrong parsing the descriptor. Empty when nothing did - and it is what tells a
/// descriptor nobody could read from an object that grants nothing, both of which have no entries.
/// Named as <see cref="AceNormalizationResult.Errors"/> is, so the collection and the statement
/// about it cannot be read apart.
/// </param>
public sealed record ObjectPermissions(
    string DistinguishedName,
    DescriptorAvailability Availability,
    string? UnreadableReason,
    PermissionTrustee? Owner,
    DaclState DaclState,
    DaclCompleteness DaclCompleteness,
    bool DaclWasCanonical,
    bool IsDaclProtected,
    IReadOnlyList<PermissionEntry> Entries,
    IReadOnlyList<string> Errors);

/// <summary>
/// Reads one object's security descriptor out of a bundle.
/// </summary>
/// <remarks>
/// <para>
/// <b>The first thing in this product to read the descriptor half of the schema.</b> The parsing,
/// canonicalisation, wording and classification were all built and tested against constructed
/// bytes; nothing had yet read them back out of a bundle.
/// </para>
/// <para>
/// <b>Trustees are resolved against the objects this run captured, and nowhere else.</b> There is
/// no lookup against a live directory: a bundle is read on a machine that may never have seen the
/// forest, and a name fetched at read time would be the name today rather than the name the
/// evidence was sealed with. A SID that matches nothing captured stays a SID.
/// </para>
/// </remarks>
internal static class ObjectPermissionsReader
{
    /// <summary>
    /// Reads the permissions on <paramref name="distinguishedName"/>.
    /// </summary>
    /// <param name="connection">The open evidence database.</param>
    /// <param name="distinguishedName">The object the operator selected.</param>
    /// <returns>
    /// What the bundle holds, or null when it captured no object by that name - which is a
    /// different answer from an object with no permissions and is kept apart from it.
    /// </returns>
    public static ObjectPermissions? Read(SqliteConnection connection, string distinguishedName)
    {
        ArgumentNullException.ThrowIfNull(connection);
        ArgumentException.ThrowIfNullOrWhiteSpace(distinguishedName);

        var found = ObjectOf(connection, distinguishedName);
        if (found is not (var objectId, var dn))
            return null;

        var descriptor = DescriptorOf(connection, objectId);
        if (descriptor is null)
            return Absent(connection, objectId, dn);

        var stored = SecurityDescriptorParser.Parse(descriptor.RawBytes);
        var entries = EntriesOf(stored);
        var trustees = ResolveTrustees(connection, descriptor, entries);

        return new ObjectPermissions(
            dn,
            DescriptorAvailability.Read,
            UnreadableReason: null,
            descriptor.OwnerSid is null ? null : trustees[descriptor.OwnerSid],
            descriptor.DaclState,
            descriptor.DaclCompleteness,
            descriptor.DaclWasCanonical,
            descriptor.IsDaclProtected,
            [.. entries.Select(e => e.WithTrustee(trustees[e.TrusteeSid]))],
            ErrorsOf(connection, descriptor.DescriptorId, stored));
    }

    /// <summary>The stored descriptor, before its SIDs have been given names.</summary>
    /// <param name="RawBytes">
    /// The descriptor exactly as it arrived from the directory. This is what the entries are read
    /// from, rather than the <c>ace</c> table, because that table is the canonical projection and
    /// <c>S-57</c> upheld that a projection cannot stand in for the stored DACL.
    /// </param>
    private sealed record StoredDescriptor(
        long DescriptorId,
        string? OwnerSid,
        DaclState DaclState,
        DaclCompleteness DaclCompleteness,
        bool DaclWasCanonical,
        bool IsDaclProtected,
        byte[] RawBytes);

    /// <summary>One stored entry, before its trustee has been given a name.</summary>
    private sealed record StoredEntry(
        int Ordinal,
        string AceType,
        string TrusteeSid,
        int AccessMask,
        string? ObjectTypeGuid,
        string? InheritedObjectTypeGuid,
        bool IsInherited,
        byte InheritanceFlags,
        byte PropagationFlags,
        bool HasObjectType,
        bool HasInheritedObjectType,
        byte[] ApplicationData)
    {
        public PermissionEntry WithTrustee(PermissionTrustee trustee) => new(
            Ordinal,
            AceType,
            trustee,
            AccessMask,
            ObjectTypeGuid,
            InheritedObjectTypeGuid,
            IsInherited,
            InheritanceFlags,
            PropagationFlags,
            HasObjectType,
            HasInheritedObjectType,
            ApplicationData);
    }

    private static (long ObjectId, string Dn)? ObjectOf(
        SqliteConnection connection, string distinguishedName)
    {
        using var command = connection.CreateCommand();
        command.CommandText =
            "SELECT object_id, distinguished_name FROM captured_object "
            + "WHERE distinguished_name = $dn COLLATE NOCASE LIMIT 1";
        command.Parameters.AddWithValue("$dn", distinguishedName);

        using var reader = command.ExecuteReader();
        return reader.Read() ? (reader.GetInt64(0), reader.GetString(1)) : null;
    }

    private static StoredDescriptor? DescriptorOf(SqliteConnection connection, long objectId)
    {
        using var command = connection.CreateCommand();
        command.CommandText =
            """
            SELECT s.descriptor_id, s.owner_sid, s.dacl_state, s.dacl_completeness,
                   s.dacl_was_canonical, s.is_dacl_protected, s.raw_bytes
            FROM object_security_descriptor AS o
            JOIN security_descriptor AS s ON s.descriptor_id = o.descriptor_id
            WHERE o.object_id = $object
            """;
        command.Parameters.AddWithValue("$object", objectId);

        using var reader = command.ExecuteReader();
        if (!reader.Read())
            return null;

        return new StoredDescriptor(
            reader.GetInt64(0),
            reader.IsDBNull(1) ? null : reader.GetString(1),
            Enum.Parse<DaclState>(reader.GetString(2)),
            Enum.Parse<DaclCompleteness>(reader.GetString(3)),
            reader.GetInt32(4) != 0,
            reader.GetInt32(5) != 0,
            (byte[])reader[6]);
    }

    /// <summary>
    /// What to say about an object with no stored descriptor.
    /// </summary>
    /// <remarks>
    /// The DACL state is <see cref="DaclState.Unreadable"/> in both cases, and that is the accurate
    /// word rather than a convenient one: nothing here knows what the object grants, and
    /// <see cref="ObjectPermissions.Availability"/> is where the two cases are told apart.
    /// </remarks>
    private static ObjectPermissions Absent(
        SqliteConnection connection, long objectId, string distinguishedName)
    {
        using var command = connection.CreateCommand();
        command.CommandText =
            "SELECT reason FROM unreadable_security_descriptor WHERE object_id = $object";
        command.Parameters.AddWithValue("$object", objectId);

        var reason = command.ExecuteScalar() as string;

        return new ObjectPermissions(
            distinguishedName,
            reason is null ? DescriptorAvailability.NotAttempted : DescriptorAvailability.Unreadable,
            reason,
            Owner: null,
            DaclState.Unreadable,
            DaclCompleteness.Unknown,
            DaclWasCanonical: false,
            IsDaclProtected: false,
            [],
            []);
    }

    /// <summary>
    /// The entries the directory stored, read back out of the descriptor's own bytes.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Not from the <c>ace</c> table, and that is the whole point.</b> That table holds the
    /// canonical projection: sorted into evaluation order and deduplicated by <c>ace_hash</c>. Both
    /// are correct for what it is for - <c>ace_set_hash</c> is how two runs are compared without
    /// reading every entry of every object - and neither is correct for showing an operator what
    /// the directory holds. <c>S-57</c> upheld <c>#2</c>/<c>#3</c> on exactly that: a single
    /// canonical projection cannot stand in for the stored DACL, and the defect was having only one
    /// representation. So comparison keeps the projection and display reads the evidence.
    /// </para>
    /// <para>
    /// <b>Nothing is dropped and nothing is reordered.</b> Two entries the projection collapses are
    /// two entries here, because a DACL carrying the same grant twice is what the directory holds
    /// and a reader deciding it meant once is editing evidence. Measured on lab bundle
    /// <c>ad.lab-20260819-232425</c>: 12,603 stored against 12,600 projected, so three entries on
    /// three objects were being discarded before anyone could see them.
    /// </para>
    /// <para>
    /// <b>GUID presence now comes from the flag rather than from nullity.</b> The projection has
    /// only the GUID columns, so a reader of it has to infer presence from whether they are null.
    /// That happens to be right in every bundle measured - the parser populates a GUID only when
    /// <c>ACE_OBJECT_TYPE_PRESENT</c> is set, so the two cannot currently disagree - but it is
    /// right by coincidence of implementation rather than by contract, and <c>S-56</c> R1 asks for
    /// the flag. Reading the bytes gives it directly.
    /// </para>
    /// </remarks>
    private static List<StoredEntry> EntriesOf(ParsedSecurityDescriptor parsed)
    {
        return
        [
            .. parsed.DaclAces
                .OrderBy(ace => ace.Ordinal)
                .Select(ace => new StoredEntry(
                    ace.Ordinal,
                    ace.AceType.ToString(),
                    ace.TrusteeSid,
                    GenericRightsExpander.Expand(ace.AccessMask),
                    ace.ObjectTypeGuid,
                    ace.InheritedObjectTypeGuid,
                    ace.IsInherited,
                    ace.InheritanceFlags,
                    ace.PropagationFlags,
                    ace.HasObjectType,
                    ace.HasInheritedObjectType,
                    ace.ApplicationData)),
        ];
    }

    /// <summary>
    /// What went wrong with this descriptor: what the run recorded, and what re-reading its bytes
    /// found now.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Re-parsing is a second reading of the same bytes, and the two can disagree.</b> The run
    /// recorded its errors at capture time; this build parses the sealed bytes again to show the
    /// stored DACL. The bytes cannot have changed - the seal covers them - so a disagreement means
    /// the parser changed between the build that captured and the build that is reading, which
    /// <c>canonicalization_version</c> does not detect because the parser is not the hash.
    /// </para>
    /// <para>
    /// <b>So a fresh error is reported rather than swallowed.</b> Silently returning fewer entries
    /// than the run stored would be the failure <c>#4</c> was raised for, one layer further on: a
    /// reader cannot tell a descriptor this build could not re-read from an object that grants
    /// little. Duplicates of what the run already recorded are dropped, because saying it twice
    /// tells an operator nothing.
    /// </para>
    /// </remarks>
    private static List<string> ErrorsOf(
        SqliteConnection connection, long descriptorId, ParsedSecurityDescriptor stored)
    {
        var errors = new List<string>();

        using var command = connection.CreateCommand();
        command.CommandText =
            "SELECT message FROM security_descriptor_error WHERE descriptor_id = $descriptor "
            + "ORDER BY ordinal";
        command.Parameters.AddWithValue("$descriptor", descriptorId);

        using var reader = command.ExecuteReader();
        while (reader.Read())
            errors.Add(reader.GetString(0));

        foreach (var error in stored.Errors)
        {
            if (!errors.Contains(error, StringComparer.Ordinal))
                errors.Add($"Re-reading the stored descriptor reported: {error}");
        }

        return errors;
    }

    /// <summary>
    /// Puts a name against every SID this descriptor mentions, once per distinct SID.
    /// </summary>
    /// <remarks>
    /// Once per SID rather than once per entry, because a domain's administrators appear in most
    /// of the entries on most objects, and a lookup per entry would ask the same question of the
    /// same table a hundred times for one screen.
    /// </remarks>
    private static Dictionary<string, PermissionTrustee> ResolveTrustees(
        SqliteConnection connection, StoredDescriptor descriptor, List<StoredEntry> entries)
    {
        var sids = new HashSet<string>(StringComparer.Ordinal);

        if (descriptor.OwnerSid is not null)
            sids.Add(descriptor.OwnerSid);

        foreach (var entry in entries)
            sids.Add(entry.TrusteeSid);

        var reasons = UnresolvedReasonsFor(connection, sids);
        var resolved = new Dictionary<string, PermissionTrustee>(StringComparer.Ordinal);

        using var command = connection.CreateCommand();
        command.CommandText =
            "SELECT distinguished_name, domain_fqdn FROM captured_object "
            + "WHERE objectsid = $sid LIMIT 1";
        var parameter = command.Parameters.Add("$sid", SqliteType.Blob);

        foreach (var sid in sids)
            resolved[sid] = Lookup(command, parameter, sid, reasons.GetValueOrDefault(sid));

        return resolved;
    }

    /// <summary>
    /// Why each SID names nothing in this bundle, as the run recorded it.
    /// </summary>
    /// <remarks>
    /// <b>Keyed on the SID rather than reached through the entry.</b> The reason used to arrive on
    /// the join from <c>ace</c> to <c>trustee</c>, and the entries no longer come from <c>ace</c>.
    /// <c>trustee.sid</c> is declared <c>UNIQUE</c>, so the SID is as good a key as the identity
    /// was - and it is the better one, because the same fact is recorded once for a SID however
    /// many entries name it.
    /// </remarks>
    private static Dictionary<string, string?> UnresolvedReasonsFor(
        SqliteConnection connection, HashSet<string> sids)
    {
        var reasons = new Dictionary<string, string?>(StringComparer.Ordinal);

        using var command = connection.CreateCommand();
        command.CommandText = "SELECT unresolved_reason FROM trustee WHERE sid = $sid";
        var parameter = command.Parameters.Add("$sid", SqliteType.Text);

        foreach (var sid in sids)
        {
            parameter.Value = sid;
            reasons[sid] = command.ExecuteScalar() as string;
        }

        return reasons;
    }

    private static PermissionTrustee Lookup(
        SqliteCommand command, SqliteParameter parameter, string sid, string? unresolvedReason)
    {
        var reason = unresolvedReason is null
            ? (UnresolvedReferenceReason?)null
            : Enum.Parse<UnresolvedReferenceReason>(unresolvedReason);

        var bytes = Sid.ToBytes(sid);
        if (bytes is null)
            return new PermissionTrustee(sid, null, null, null, reason);

        parameter.Value = bytes;

        using var reader = command.ExecuteReader();
        if (!reader.Read())
            return new PermissionTrustee(sid, null, null, null, reason);

        var dn = reader.GetString(0);
        return new PermissionTrustee(
            sid, DnHelper.ExtractFirstRdn(dn), dn, reader.GetString(1), reason);
    }
}
