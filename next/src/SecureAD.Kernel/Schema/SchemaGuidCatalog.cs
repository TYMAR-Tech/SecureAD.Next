using System.Collections.Frozen;

namespace SecureAD.Kernel.Schema;

/// <summary>
/// The directory's schema GUIDs, and what each one is called.
/// </summary>
/// <remarks>
/// <para>
/// An access control entry in Active Directory scopes a permission by GUID: this principal may
/// write <i>this attribute</i>, or exercise <i>this extended right</i>. The GUID carries no
/// meaning of its own, so without a table an audit tool can report only that somebody has a
/// permission over something opaque. This is that table.
/// </para>
/// <para>
/// <b>One table, two indexes.</b> The previous implementation kept two: one mapping GUID to
/// meaning and one mapping name to GUID, in separate folders, with separate entry records and
/// separate category enums, and only one file in the product touched both. They overlapped in
/// content, disagreed in coverage - the two LAPS password attributes a rule reads were in one and
/// not the other - and both carried correction comments about entries that had pointed at the
/// wrong GUID. Two tables of the same facts is two places to be wrong and two places to fix.
/// </para>
/// <para>
/// <b>Looking up by GUID returns a set.</b> One GUID can name several things: <c>bf9679c0</c> is
/// both the <c>Self-Membership</c> validated write and the <c>member</c> attribute, and an ACE
/// distinguishes them by its type. Both previous tables returned whichever entry happened to be
/// declared first and said nothing about the other, which answers a question that was not asked.
/// </para>
/// <para>
/// <b>It cannot be changed once built.</b> Its predecessor was a static mutable singleton into
/// which a schema capture merged entries, so the same GUID could resolve differently depending on
/// what had already run in the process, and the shipped answer became unobtainable. For a product
/// whose output is meant to be reproducible and comparable between runs, that is a provenance
/// hazard. A catalogue captured from a live schema is a second instance, not an edit to this one.
/// </para>
/// <para>
/// <b>Nothing here says whether a right is dangerous.</b> That is a judgement about a permission
/// rather than a fact about the directory, it depends on the access mask and the ACE type as well
/// as the GUID, and it belongs to the classifier. See
/// <c>docs/decisions/0010-the-rule-catalogue-is-data-the-rule-logic-is-code.md</c>.
/// </para>
/// <para>
/// <b>This is the shipped layer, not the whole answer.</b> Every forest carries schema extensions
/// whose GUIDs this table cannot contain, some of them generated at creation and unique to that
/// forest. Capture reads them from the schema partition, per
/// <c>docs/decisions/0014-capture-reads-the-schema-partition.md</c>, and every entry states which
/// layer it came from so that evidence can tell a published fact from an observed one.
/// </para>
/// </remarks>
public sealed class SchemaGuidCatalog
{
    /// <summary>
    /// The catalogue's version. Increment when entries are added, removed or corrected, so a
    /// bundle can record which table produced its GUID names.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Moved to 2 when eleven entries were corrected against Microsoft and
    /// <c>DS-Replication-Monitor-Topology</c> was added under its real GUID. See
    /// <c>SchemaGuidCatalogMicrosoftAnchorTests</c>.
    /// </para>
    /// <para>
    /// <b>Nothing yet records it.</b> The summary above says a bundle can state which table named
    /// its GUIDs, but no writer puts this value in one and no reader looks for it, unlike
    /// <c>canonicalization_version</c>, which <c>BundleReader.Open</c> does refuse a mismatch on.
    /// So a bundle written before this correction and one written after are indistinguishable, and
    /// the names in the older one cannot be known to be the wrong ones. That is a gap in evidence
    /// provenance rather than in this constant.
    /// </para>
    /// </remarks>
    public const int Version = 2;

    private readonly FrozenDictionary<string, IReadOnlyList<SchemaGuidEntry>> _byGuid;
    private readonly FrozenDictionary<string, SchemaGuidEntry> _byLdapName;
    private readonly FrozenDictionary<string, IReadOnlyList<string>> _propertySetMembers;
    private FrozenSet<string> AmbiguousNames { get; init; } = Array.Empty<string>().ToFrozenSet(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Builds a catalogue over the given entries.
    /// </summary>
    /// <param name="entries">The rows. Copied, so the caller cannot alter the catalogue afterwards.</param>
    public SchemaGuidCatalog(IEnumerable<SchemaGuidEntry> entries)
        : this(entries, new Dictionary<string, IReadOnlyList<string>>(StringComparer.OrdinalIgnoreCase))
    {
    }

    /// <summary>
    /// Builds a catalogue over the given entries, knowing what each property set contains.
    /// </summary>
    /// <param name="entries">The rows. Copied, so the caller cannot alter the catalogue afterwards.</param>
    /// <param name="propertySetMembers">
    /// The LDAP names of the attributes in each property set, keyed by the set's GUID. Empty when
    /// no forest schema was read, which is <i>not assessed</i> rather than <i>contains nothing</i>.
    /// </param>
    public SchemaGuidCatalog(
        IEnumerable<SchemaGuidEntry> entries,
        IReadOnlyDictionary<string, IReadOnlyList<string>> propertySetMembers)
    {
        ArgumentNullException.ThrowIfNull(entries);
        ArgumentNullException.ThrowIfNull(propertySetMembers);

        Entries = entries.ToArray();

        _propertySetMembers = propertySetMembers.ToFrozenDictionary(
            p => p.Key, p => p.Value, StringComparer.OrdinalIgnoreCase);

        _byGuid = Entries
            .GroupBy(e => e.Guid, StringComparer.OrdinalIgnoreCase)
            .ToFrozenDictionary(
                g => g.Key,
                g => (IReadOnlyList<SchemaGuidEntry>)g.ToArray(),
                StringComparer.OrdinalIgnoreCase);

        _byLdapName = Entries.ToFrozenDictionary(e => e.LdapName, StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>
    /// The catalogue shipped with the product. Available without a directory, a network or a
    /// capture, which is what lets a bundle be re-read anywhere.
    /// </summary>
    public static SchemaGuidCatalog Embedded { get; } = new(EmbeddedEntries());

    /// <summary>
    /// A catalogue that answers from a forest's own schema first and falls back to the shipped
    /// table, which is the two-layer lookup
    /// <c>docs/decisions/0014-capture-reads-the-schema-partition.md</c> specifies.
    /// </summary>
    /// <param name="captured">
    /// What the run read from the forest's schema partition and extended-rights container. Empty
    /// when the run did not read them, in which case this is the shipped table and nothing else.
    /// </param>
    /// <param name="shipped">The catalogue to fall back to, normally <see cref="Embedded"/>.</param>
    /// <remarks>
    /// <para>
    /// <b>The forest wins, and that is the point of capturing it.</b> A shipped name is a general
    /// claim about Active Directory; a captured one is a fact about the forest under audit on the
    /// day it was read. Where they disagree the second is the one an administrator can act on.
    /// </para>
    /// <para>
    /// <b>Where they disagree about a base-schema GUID, that is itself a finding</b> - <c>0014</c>
    /// says so. This method resolves the display question and does not report it; nothing computes
    /// that finding yet, and this is where the evidence for it would come from.
    /// </para>
    /// <para>
    /// <b>Deduplicated rather than concatenated.</b> Names index uniquely, so the two layers
    /// naming <c>userAccountControl</c> - which they both certainly do - would otherwise throw on
    /// construction. A GUID already answered for by the captured layer, under the same kind or the
    /// same name, does not gain a second shipped answer behind it.
    /// </para>
    /// <para>
    /// <b>The forest wins except when it says nothing.</b>
    /// <see cref="SchemaGuidKind.Unclassified"/> is not an answer that beats a shipped one - it is
    /// the absence of one. Without this, a well-known extended right whose forest row carries no
    /// readable <c>validAccesses</c> would be captured as unclassified, take the name under the
    /// rule above, and suppress the shipped entry that classifies it correctly, turning a
    /// <c>Dangerous</c> verdict into <c>CannotClassify</c>. That is a false negative created by a
    /// fix meant to remove a false positive, which is <c>F-S54-2</c> exactly, so an unclassified
    /// entry yields to any entry of any layer that classifies the same GUID.
    /// </para>
    /// </remarks>
    public static SchemaGuidCatalog CapturedOver(
        IEnumerable<SchemaGuidEntry> captured,
        SchemaGuidCatalog shipped,
        IReadOnlyDictionary<string, IReadOnlyList<string>> propertySetMembers)
    {
        ArgumentNullException.ThrowIfNull(captured);
        ArgumentNullException.ThrowIfNull(shipped);
        ArgumentNullException.ThrowIfNull(propertySetMembers);

        var byGuidAndKind = new HashSet<(string, SchemaGuidKind)>();
        var byName = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var combined = new List<SchemaGuidEntry>();

        var capturedEntries = captured.ToArray();
        var ordered = capturedEntries.Concat(shipped.Entries).ToList();

        var classified = ordered
            .Where(e => e.Kind != SchemaGuidKind.Unclassified)
            .Select(e => e.Guid.ToLowerInvariant())
            .ToHashSet();

        foreach (var entry in ordered)
        {
            if (entry.Kind == SchemaGuidKind.Unclassified
                && classified.Contains(entry.Guid.ToLowerInvariant()))
            {
                continue;
            }

            if (!byGuidAndKind.Add((entry.Guid.ToLowerInvariant(), entry.Kind)))
                continue;

            if (!byName.Add(entry.LdapName))
                continue;

            combined.Add(entry);
        }

        // Membership is only ever the forest's. There is no shipped answer to fall back to, and
        // inventing one would say a property set was harmless while the directory disagreed.
        return new SchemaGuidCatalog(combined, propertySetMembers)
        {
            // Display precedence must not hide conflicting identities from authorization.
            AmbiguousNames = capturedEntries.GroupBy(entry => entry.LdapName, StringComparer.OrdinalIgnoreCase)
                .Where(group => group.DistinctBy(entry => (entry.Guid.ToUpperInvariant(), entry.Kind)).Skip(1).Any())
                .Select(group => group.Key).ToFrozenSet(StringComparer.OrdinalIgnoreCase),
        };
    }

    /// <summary>
    /// Whether any of this catalogue's answers came from a forest rather than from the shipped
    /// table.
    /// </summary>
    /// <remarks>
    /// A screen showing names has to be able to say which of the two kinds of claim it is making,
    /// and a run that was refused the schema partition resolves only what Microsoft publishes -
    /// which is a smaller answer, and one an operator should not mistake for a complete one.
    /// </remarks>
    public bool HasCapturedEntries => Entries.Any(e => e.Source == SchemaGuidSource.Captured);

    /// <summary>Every row, in declaration order.</summary>
    public IReadOnlyList<SchemaGuidEntry> Entries { get; }

    /// <summary>
    /// The attributes a property set contains, or <c>null</c> when this catalogue does not know.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Null and empty are different answers and both occur.</b> Null means no forest schema was
    /// read, so what the set grants is unknown. A caller must not read that as a set containing
    /// nothing dangerous - the classifier's whole contract is that an unassessed permission is
    /// never reported as safe.
    /// </para>
    /// <para>
    /// <b>Why this cannot be shipped in a table.</b> A property set names none of its members; each
    /// attribute points back at the set. A forest can therefore put its own attribute into a
    /// Microsoft-defined set, and a shipped list would say the set was harmless while the directory
    /// disagreed.
    /// </para>
    /// </remarks>
    /// <param name="propertySetGuid">The set's GUID, as an access control entry names it.</param>
    public IReadOnlyList<string>? MembersOfPropertySet(string propertySetGuid)
    {
        ArgumentNullException.ThrowIfNull(propertySetGuid);

        return _propertySetMembers.GetValueOrDefault(propertySetGuid);
    }

    /// <summary>
    /// Whether an attribute's captured assignment places it in this property set. Null means
    /// the assignment is unavailable or contradictory, not that the attribute is outside the set.
    /// </summary>
    /// <remarks>
    /// Observing other members of a set does not prove its member list complete. Only a positive
    /// assignment of this attribute can establish membership or exclusion from a different set.
    /// An absent assignment cannot distinguish an unassigned attribute from an unread one.
    /// </remarks>
    /// <param name="attributeName">The attribute's LDAP name.</param>
    /// <param name="propertySetGuid">The property-set GUID named by the permission entry.</param>
    public bool? AttributeBelongsToPropertySet(string attributeName, string propertySetGuid)
    {
        ArgumentNullException.ThrowIfNull(attributeName);
        ArgumentNullException.ThrowIfNull(propertySetGuid);

        string? assignedSet = null;
        foreach (var set in _propertySetMembers)
        {
            if (!set.Value.Contains(attributeName, StringComparer.OrdinalIgnoreCase)) continue;
            if (assignedSet is not null || !Guid.TryParse(set.Key, out _)) return null;
            assignedSet = set.Key;
        }
        return assignedSet is null || !Guid.TryParse(propertySetGuid, out _)
            ? null : string.Equals(assignedSet, propertySetGuid, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Every meaning of a GUID. Empty when the catalogue does not know it, which is an ordinary
    /// answer: a forest carries schema extensions this table cannot have heard of.
    /// </summary>
    public IReadOnlyList<SchemaGuidEntry> FindByGuid(string guid)
    {
        ArgumentNullException.ThrowIfNull(guid);
        return _byGuid.TryGetValue(guid, out var found) ? found : [];
    }

    /// <summary>
    /// The entry with this LDAP name, or <c>null</c> if there is none. Names are unique, so this
    /// answer is never a choice between candidates.
    /// </summary>
    public SchemaGuidEntry? FindByLdapName(string ldapName)
    {
        ArgumentNullException.ThrowIfNull(ldapName);
        return _byLdapName.GetValueOrDefault(ldapName);
    }

    /// <summary>
    /// Resolves a name without allowing display precedence to conceal conflicting captured GUIDs
    /// or schema kinds. Callers must still validate the returned identity and kind for their operation.
    /// </summary>
    public SchemaGuidEntry? FindUnambiguousByLdapName(string ldapName)
    {
        ArgumentNullException.ThrowIfNull(ldapName);
        return AmbiguousNames.Contains(ldapName) ? null : FindByLdapName(ldapName);
    }

    /// <summary>
    /// The GUID for an LDAP name, or <c>null</c> if the name is unknown. Exists so a rule can name
    /// the attribute it is about rather than carrying a GUID literal - which is how the same
    /// attribute came to be written down under three different GUIDs, two of them wrong.
    /// </summary>
    public string? GuidFor(string ldapName) => FindByLdapName(ldapName)?.Guid;

    private static SchemaGuidEntry ExtendedRight(string guid, string ldapName) =>
        new(guid, ldapName, SchemaGuidKind.ExtendedRight, SchemaGuidSource.Embedded);

    private static SchemaGuidEntry ValidatedWrite(string guid, string ldapName) =>
        new(guid, ldapName, SchemaGuidKind.ValidatedWrite, SchemaGuidSource.Embedded);

    private static SchemaGuidEntry PropertySet(string guid, string ldapName) =>
        new(guid, ldapName, SchemaGuidKind.PropertySet, SchemaGuidSource.Embedded);

    private static SchemaGuidEntry Attribute(string guid, string ldapName) =>
        new(guid, ldapName, SchemaGuidKind.Attribute, SchemaGuidSource.Embedded);

    private static SchemaGuidEntry ObjectClass(string guid, string ldapName) =>
        new(guid, ldapName, SchemaGuidKind.ObjectClass, SchemaGuidSource.Embedded);

    /// <summary>
    /// The shipped rows. Names are the CN Microsoft's AD schema reference gives, so an entry can
    /// be checked against <c>learn.microsoft.com/windows/win32/adschema</c> one line at a time.
    /// </summary>
    private static SchemaGuidEntry[] EmbeddedEntries() =>
    [
        // === Control access rights (r-<name>) ===
        ExtendedRight("00299570-246d-11d0-a768-00aa006e0529", "User-Force-Change-Password"),
        ExtendedRight("ab721a53-1e2f-11d0-9819-00aa0040529b", "User-Change-Password"),
        ExtendedRight("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2", "DS-Replication-Get-Changes"),
        ExtendedRight("1131f6ad-9c07-11d1-f79f-00c04fc2dcd2", "DS-Replication-Get-Changes-All"),
        ExtendedRight("89e95b76-444d-4c62-991a-0facbeda640c", "DS-Replication-Get-Changes-In-Filtered-Set"),
        // fec364e0 is Do-Garbage-Collection. It shipped as "DS-Replication-Get-Changes-All-Extended",
        // which is not an extended right at all - it is absent from Microsoft's Extended Rights
        // index. Checked rather than assumed: DangerousExtendedRights and ReplicationRights match
        // names exactly and neither held the invented one, so no verdict turned on it. The cost was
        // a fabricated name on screen where Do-Garbage-Collection belonged.
        ExtendedRight("fec364e0-0a98-11d1-adbb-00c04fd8d5cd", "Do-Garbage-Collection"),
        ExtendedRight("1131f6ab-9c07-11d1-f79f-00c04fc2dcd2", "DS-Replication-Synchronize"),
        // Manage-Topology is 1131f6ac. The neighbouring 1131f6ab is Synchronize, and shipping the
        // one for the other missed every DCShadow grant while reporting benign ones - SEC-124 §13.
        ExtendedRight("1131f6ac-9c07-11d1-f79f-00c04fc2dcd2", "DS-Replication-Manage-Topology"),
        // ee914b82 is Abandon-Replication, and DS-Replication-Monitor-Topology is f98340fb. The
        // catalogue published the first GUID under the second name and did not hold the second
        // GUID at all, so a real monitor-topology grant resolved to nothing.
        ExtendedRight("ee914b82-0a98-11d1-adbb-00c04fd8d5cd", "Abandon-Replication"),
        ExtendedRight("f98340fb-7c5b-4cdb-a00b-2ebdfa115a96", "DS-Replication-Monitor-Topology"),
        ExtendedRight("9923a32a-3607-11d2-b9be-0000f87a36b2", "DS-Install-Replica"),
        ExtendedRight("69ae6200-7f46-11d2-b9ad-00c04f79f805", "DS-Check-Stale-Phantoms"),
        ExtendedRight("4ecc03fe-ffc0-4947-b630-eb672a8a9dbc", "DS-Query-Self-Quota"),
        ExtendedRight("3e0f7e18-2c7a-4c10-ba82-4d926db99a3e", "DS-Clone-Domain-Controller"),
        ExtendedRight("9b026da6-0d3c-465c-8bee-5199d7165cba", "DS-Validated-Write-Computer"),
        ExtendedRight("ab721a52-1e2f-11d0-9819-00aa0040529b", "Domain-Administer-Server"),
        ExtendedRight("ab721a54-1e2f-11d0-9819-00aa0040529b", "Send-As"),
        ExtendedRight("ab721a55-1e2f-11d0-9819-00aa0040529b", "Send-To"),
        ExtendedRight("ab721a56-1e2f-11d0-9819-00aa0040529b", "Receive-As"),
        ExtendedRight("ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501", "Unexpire-Password"),
        ExtendedRight("280f369c-67c7-438e-ae98-1d46f3c6f541", "Update-Password-Not-Required-Bit"),
        ExtendedRight("05c74c5e-4deb-43b4-bd9f-86664c2a7fd5", "Enable-Per-User-Reversibly-Encrypted-Password"),
        ExtendedRight("ba33815a-4f93-4c76-87f3-57574bff8109", "Migrate-SID-History"),
        ExtendedRight("b7b1b3dd-ab09-4242-9e30-9980e5d322f7", "Generate-RSoP-Planning"),
        ExtendedRight("b7b1b3de-ab09-4242-9e30-9980e5d322f7", "Generate-RSoP-Logging"),
        ExtendedRight("cc17b1fb-33d9-11d2-97d4-00c04fd8d5cd", "Change-Infrastructure-Master"),
        ExtendedRight("e2a36dc9-ae17-47c3-b58b-be34c55ba633", "Create-Inbound-Forest-Trust"),
        ExtendedRight("0e10c968-78fb-11d2-90d4-00c04f79dc55", "Certificate-Enrollment"),
        ExtendedRight("a05b8cc2-17bc-4802-a710-e7c15ab866a2", "Certificate-AutoEnrollment"),
        // These two shipped with each other's GUID. Neither name is dangerous, so nothing anchored
        // them until this catalogue was pinned to Microsoft entry by entry.
        ExtendedRight("0bc1554e-0a99-11d1-adbb-00c04fd8d5cd", "Recalculate-Hierarchy"),
        ExtendedRight("62dd28a8-7f46-11d2-b9ad-00c04f79f805", "Recalculate-Security-Inheritance"),
        ExtendedRight("1abd7cf8-0a99-11d1-adbb-00c04fd8d5cd", "Allocate-Rids"),
        ExtendedRight("440820ad-65b4-11d1-a3da-0000f875ae0d", "Add-GUID"),
        ExtendedRight("91d67418-0135-4acc-8d79-c08e857cfbec", "SAM-Enumerate-Entire-Domain"),
        ExtendedRight("edacfd8f-ffb3-11d1-b41d-00a0c968f939", "Apply-Group-Policy"),
        ExtendedRight("68b1d179-0d15-4d4f-ab71-46152e79a7bc", "Allowed-To-Authenticate"),
        ExtendedRight("7726b9d5-a4b4-4288-a6b2-dce952e80a7f", "Run-Protect-Admin-Groups-Task"),
        ExtendedRight("7c0e2a7c-a419-48e4-a995-10180aad54dd", "Manage-Optional-Features"),

        // === Validated writes ===
        // Each shares its GUID with the attribute it validates, which is why a lookup by GUID
        // returns a set: the ACE's type says which of the two is meant.
        ValidatedWrite("bf9679c0-0de6-11d0-a285-00aa003049e2", "Self-Membership"),
        ValidatedWrite("f3a64788-5306-11d1-a9c5-0000f80367c1", "Validated-SPN"),
        ValidatedWrite("72e39547-7b18-11d1-adef-00c04fd8d5cd", "Validated-DNS-Host-Name"),
        // A second transposed pair, found the same way.
        ValidatedWrite("d31a8757-2447-4545-8081-3bb610cacbf2", "Validated-MS-DS-Behavior-Version"),
        ValidatedWrite("80863791-dbe9-4eb8-837e-7f0ab55d9ac7", "Validated-MS-DS-Additional-DNS-Host-Name"),

        // === Property sets (r-<name>) ===
        // Property sets and extended rights are distinct kinds of control access right, and the
        // effective-access pipeline must not flatten them.
        PropertySet("c7407360-20bf-11d0-a768-00aa006e0529", "Domain-Password"),
        PropertySet("b8119fd0-04f6-4762-ab7a-4986c76b3f9a", "Domain-Other-Parameters"),
        PropertySet("72e39547-7b18-11d1-adef-00c04fd8d5cd", "DNS-Host-Name-Attributes"),
        PropertySet("e45795b2-9455-11d1-aebd-0000f80367c1", "Email-Information"),
        PropertySet("59ba2f42-79a2-11d0-9020-00c04fc2d3cf", "General-Information"),
        PropertySet("bc0ac240-79a9-11d0-9020-00c04fc2d4cf", "Membership"),
        PropertySet("ffa6f046-ca4b-4feb-b40d-04dfee722543", "MS-TS-GatewayAccess"),
        PropertySet("77b5b886-944a-11d1-aebd-0000f80367c1", "Personal-Information"),
        PropertySet("91e647de-d96f-4b70-9557-d63ff4f3ccd8", "Private-Information"),
        PropertySet("e48d0154-bcf8-11d1-8702-00c04fb96050", "Public-Information"),
        PropertySet("037088f8-0ae1-11d2-b422-00a0c968f939", "RAS-Information"),
        PropertySet("5805bc62-bdc9-4428-a5e2-856a0f4c185e", "Terminal-Server-License-Server"),
        PropertySet("4c164200-20c0-11d0-a768-00aa006e0529", "User-Account-Restrictions"),
        PropertySet("5f202010-79a5-11d0-9020-00c04fc2d4cf", "User-Logon"),
        PropertySet("e45795b3-9455-11d1-aebd-0000f80367c1", "Web-Information"),

        // === Attributes (a-<name>) ===
        // A whole class of shipped defect was an attribute pointing at an object-class or
        // property-set GUID from the same bf967xxx namespace. Object classes are declared below
        // and their GUIDs are not reused here.
        Attribute("bf9679c0-0de6-11d0-a285-00aa003049e2", "member"),
        Attribute("bf967991-0de6-11d0-a285-00aa003049e2", "memberOf"),
        Attribute("bf967a68-0de6-11d0-a285-00aa003049e2", "userAccountControl"),
        Attribute("bf9679e1-0de6-11d0-a285-00aa003049e2", "unicodePwd"),
        Attribute("f3a64788-5306-11d1-a9c5-0000f80367c1", "servicePrincipalName"),
        Attribute("800d94d7-b7a1-42a1-b14d-7cae1423d07f", "msDS-AllowedToDelegateTo"),
        Attribute("3f78c3e5-f79a-46bd-a0b8-9d18116ddc79", "msDS-AllowedToActOnBehalfOfOtherIdentity"),
        Attribute("5b47d60f-6090-40b2-9f37-2a4de88f3063", "msDS-KeyCredentialLink"),
        Attribute("b77ea093-88d0-4780-9a98-911f8e8b1dca", "msDS-ResultantPSO"),
        Attribute("bf967a0a-0de6-11d0-a285-00aa003049e2", "pwdLastSet"),
        Attribute("bf967950-0de6-11d0-a285-00aa003049e2", "description"),
        Attribute("bf967953-0de6-11d0-a285-00aa003049e2", "displayName"),
        Attribute("3e0abfd0-126a-11d0-a060-00aa006c33ed", "sAMAccountName"),
        Attribute("28630ebb-41d5-11d1-a9c1-0000f80367c1", "userPrincipalName"),
        // sIDHistory is 17eb4278. It shipped twice as something else: bf967a6d is userParameters
        // and 9a9a0220 is userSharedFolderOther - SEC-123 §13.
        Attribute("17eb4278-d167-11d0-b002-0000f80367c1", "sIDHistory"),
        Attribute("bf967918-0de6-11d0-a285-00aa003049e2", "adminCount"),
        Attribute("72e39547-7b18-11d1-adef-00c04fd8d5cd", "dNSHostName"),
        Attribute("28630ebf-41d5-11d1-a9c1-0000f80367c1", "lockoutTime"),
        Attribute("bf9679a8-0de6-11d0-a285-00aa003049e2", "scriptPath"),
        Attribute("bf967985-0de6-11d0-a285-00aa003049e2", "homeDirectory"),
        Attribute("bf967986-0de6-11d0-a285-00aa003049e2", "homeDrive"),
        Attribute("bf9679e3-0de6-11d0-a285-00aa003049e2", "nTSecurityDescriptor"),
        Attribute("bf9679e4-0de6-11d0-a285-00aa003049e2", "distinguishedName"),
        Attribute("bf9679e5-0de6-11d0-a285-00aa003049e2", "objectClass"),
        Attribute("bf9679e7-0de6-11d0-a285-00aa003049e2", "objectGUID"),
        Attribute("bf9679e8-0de6-11d0-a285-00aa003049e2", "objectSid"),
        Attribute("f30e3bbe-9ff0-11d1-b603-0000f80367c1", "gPLink"),
        Attribute("c0e20a04-0e5a-4ff3-9482-5efeaecd7060", "lastLogonTimestamp"),
        // The two LAPS password attributes SEC-090 reads.
        Attribute("2e0e4a88-f5fa-11df-b3af-001fc000a000", "ms-Mcs-AdmPwd"),
        Attribute("53c5be7e-5403-4013-a04b-b22e05d0e3c1", "msLAPS-Password"),

        // === Object classes (c-<name>) ===
        ObjectClass("bf967aba-0de6-11d0-a285-00aa003049e2", "user"),
        ObjectClass("bf967a86-0de6-11d0-a285-00aa003049e2", "computer"),
        ObjectClass("bf967a9c-0de6-11d0-a285-00aa003049e2", "group"),
        ObjectClass("bf967aa5-0de6-11d0-a285-00aa003049e2", "organizationalUnit"),
        ObjectClass("bf967a8b-0de6-11d0-a285-00aa003049e2", "container"),
        ObjectClass("19195a5a-6da0-11d0-afd3-00c04fd930c9", "domain"),
        // f30e3bc2, not f30e3bc1. The neighbouring value is the gPLink attribute, declared above,
        // which is the same one-digit slip that put an attribute on an object-class GUID before.
        ObjectClass("f30e3bc2-9ff0-11d1-b603-0000f80367c1", "groupPolicyContainer"),
        ObjectClass("5cb41ed0-0e4c-11d0-a286-00aa003049e2", "contact"),
        ObjectClass("bf967aa8-0de6-11d0-a285-00aa003049e2", "printQueue"),
        ObjectClass("ce206244-5827-4a86-ba1c-1c0c386c1b64", "msDS-ManagedServiceAccount"),
        ObjectClass("7b8b558a-93a5-4af7-adca-c017e67f1057", "msDS-GroupManagedServiceAccount"),
        ObjectClass("e5209ca2-3bba-11d2-90cc-00c04fd91ab1", "pKICertificateTemplate"),
        ObjectClass("f0f8ffab-1191-11d0-a060-00aa006c33ed", "nTDSDSA"),
    ];
}
