using SecureAD.Kernel.Schema;

namespace SecureAD.Kernel.Security;

/// <summary>
/// One access control entry said in words an administrator reads, rather than in the bits and
/// GUIDs the directory stores.
/// </summary>
/// <remarks>
/// <para>
/// <b><see cref="RightsAreComplete"/> is why this is a type and not a string.</b> An access mask is a
/// set of bits, and this names the ones it knows. A viewer that silently dropped the rest would
/// hide access an administrator is looking straight at - the one thing an audit tool cannot do. So
/// anything unnamed is counted, said in <see cref="Summary"/>, and this reads false.
/// </para>
/// </remarks>
/// <param name="Summary">
/// The whole entry in one line, for a list. Never empty.
/// </param>
/// <param name="Rights">Each right the mask grants, named, with the bits that named it.</param>
/// <param name="RightsAreComplete">
/// Whether every bit of the mask was named. False means the mask carries rights this build has no
/// word for, and <see cref="Summary"/> says so.
/// </param>
public sealed record PermissionWording(
    string Summary,
    IReadOnlyList<PermissionRight> Rights,
    bool RightsAreComplete);

/// <summary>
/// One right an access control entry grants, in words, with the mask bits that produced those
/// words.
/// </summary>
/// <remarks>
/// <para>
/// <b><see cref="Bits"/> exists so a verdict can attach to a right rather than to the entry.</b>
/// An <c>ACCESS_MASK</c> is a set of bits that Windows evaluates independently, and
/// <see cref="DangerousPermissionClassifier"/> judges them differently by construction - so an
/// entry granting several rights has several answers, and one mark on the row cannot say which
/// right earned it. Carrying the bits lets a caller ask the classifier about each right on its
/// own. This type states which bits made the phrase; it does not judge them.
/// </para>
/// <para>
/// <b>The bits are not always one bit.</b> <i>Full control</i> is the whole mask said in two
/// words, and it is one grant rather than fifteen, so it is one right carrying every bit.
/// </para>
/// </remarks>
/// <param name="Name">
/// What an administrator reads. Microsoft's word for the right, and where the entry names a GUID,
/// what the schema catalogue calls it.
/// </param>
/// <param name="Bits">The bits of the access mask this phrase accounts for. Never zero.</param>
/// <param name="IsNamed">
/// Whether this build has a word for what the bits grant. False only for the item that counts what
/// was left over, whose bits this build cannot name and therefore must not have judged: a verdict
/// of <see cref="PermissionVerdict.NotDangerous"/> on an unread bit would report access nobody
/// examined as safe.
/// </param>
public sealed record PermissionRight(string Name, int Bits, bool IsNamed);

/// <summary>
/// Turns an access control entry into words.
/// </summary>
/// <remarks>
/// <para>
/// <b>This is the difference between a tool an administrator trusts and one he ignores.</b> The
/// directory stores <c>0x000F01FF</c> and <c>00299570-246d-11d0-a768-00aa006e0529</c>; what he
/// needs to read is <i>Full control</i> and <i>Reset password</i>. The predecessor showed neither -
/// its findings named raw identifiers, and a reader had to know the GUID.
/// </para>
/// <para>
/// <b>It states rights, and makes no judgement.</b> Whether a right is dangerous is
/// <see cref="DangerousPermissionClassifier"/>'s question, asked separately and only when the
/// operator asks for it.
/// </para>
/// <para>
/// The bit values are the directory's own, and are repeated here rather than shared with the
/// classifier deliberately: that type decides what is dangerous and this one decides what to call
/// things, and a change to either must not silently alter the other. <c>PermissionWordingTests</c>
/// asserts the two agree on the values they share.
/// </para>
/// </remarks>
public sealed class PermissionWordingWriter
{
    private const int CreateChild = 0x00000001;
    private const int DeleteChild = 0x00000002;
    private const int ListChildren = 0x00000004;
    private const int Self = 0x00000008;
    private const int ReadProperty = 0x00000010;
    private const int WriteProperty = 0x00000020;
    private const int DeleteTree = 0x00000040;
    private const int ListObject = 0x00000080;
    private const int ControlAccess = 0x00000100;
    private const int Delete = 0x00010000;
    private const int ReadControl = 0x00020000;
    private const int WriteDac = 0x00040000;
    private const int WriteOwner = 0x00080000;
    private const int Synchronize = 0x00100000;
    private const int AccessSystemSecurity = 0x01000000;

    // THE SHORTHAND BITS, WHICH A STORED ENTRY IS NOT SUPPOSED TO STILL CARRY.
    private const int GenericAll = 0x10000000;
    private const int GenericExecute = 0x20000000;
    private const int GenericWrite = 0x40000000;
    private const int GenericRead = unchecked((int)0x80000000);

    /// <summary>Every right this type has a word for, so anything else can be counted.</summary>
    private const int Named =
        CreateChild | DeleteChild | ListChildren | Self | ReadProperty | WriteProperty
        | DeleteTree | ListObject | ControlAccess | Delete | ReadControl | WriteDac | WriteOwner
        | Synchronize | AccessSystemSecurity
        | GenericAll | GenericExecute | GenericWrite | GenericRead;

    /// <summary>
    /// Full control over a directory object: every standard right and every directory-specific
    /// one. The same value <see cref="GenericRightsExpander"/> expands <c>GENERIC_ALL</c> to.
    /// </summary>
    private const int FullControl = 0x000F01FF;

    private readonly SchemaGuidCatalog _catalog;

    /// <summary>Creates a writer that names GUIDs from <paramref name="catalog"/>.</summary>
    /// <param name="catalog">The schema catalogue, for extended rights and attributes.</param>
    public PermissionWordingWriter(SchemaGuidCatalog catalog)
    {
        ArgumentNullException.ThrowIfNull(catalog);

        _catalog = catalog;
    }

    /// <summary>
    /// Says what one entry grants or denies.
    /// </summary>
    /// <param name="accessMask">The mask, with generic rights already expanded.</param>
    /// <param name="objectTypeGuid">
    /// What the entry is limited to - an extended right, an attribute, a property set or a class -
    /// or null when it applies to everything.
    /// </param>
    public PermissionWording Describe(int accessMask, string? objectTypeGuid)
    {
        var rights = new List<PermissionRight>();

        // FULL CONTROL IS ONE RIGHT AND CARRIES THE WHOLE MASK. It is one grant an administrator
        // removes in one action, not fifteen findings, so it earns one verdict.
        //
        // BUT ONLY THE BITS IT ACTUALLY ACCOUNTS FOR. This used to be a subset test that returned
        // immediately: any mask CONTAINING full control's bits was rendered as those two words,
        // whatever else it carried, and the rest was dropped while RightsAreComplete still said
        // true. That hid the one bit most worth seeing - ACCESS_SYSTEM_SECURITY must not appear in
        // a DACL at all, so an entry carrying it is malformed or hostile evidence, and it was being
        // concealed behind the two most reassuring words this product prints. See docs/next/S-58
        // findings 9 and 10.
        //
        // Scoped entries take the long road deliberately. Full control limited to one object type
        // is not full control over the object, and the shortcut ignored the GUID entirely.
        var isUnscoped = string.IsNullOrWhiteSpace(objectTypeGuid);
        var accountedFor = 0;

        if (isUnscoped && (accessMask & FullControl) == FullControl)
        {
            rights.Add(new PermissionRight("Full control", FullControl, IsNamed: true));
            accountedFor = FullControl;
        }

        // Everything below names what full control did not already speak for, so no bit is counted
        // twice and none is silently dropped.
        var remaining = accessMask & ~accountedFor;

        // THE SHORTHAND IS NAMED, NOT TRANSLATED. Windows lets a permission be written using a
        // shorthand bit, and the domain controller normally replaces it with the specific rights it
        // stands for at the moment the permission is written. Microsoft states that a shorthand bit
        // still present in an entry already attached to an object is NOT translated during the
        // access check, and might produce unintended results.
        //
        // So this says what the shorthand was plainly meant to convey, and says in the same breath
        // that it may not be enforced. It must not be quietly rendered as the rights it stands for:
        // that reports a permission the directory may not honour as though it were ordinary. Nor
        // may it fall through to "other rights", because an unnamed right is refused classification
        // and the row would go silent about what is probably full control. See docs/next/S-56 R2.
        AddPlain(rights, remaining, GenericAll, "Full control (shorthand - may not be enforced)");
        AddPlain(rights, remaining, GenericWrite, "Write (shorthand - may not be enforced)");
        AddPlain(rights, remaining, GenericRead, "Read (shorthand - may not be enforced)");
        AddPlain(rights, remaining, GenericExecute, "List contents (shorthand - may not be enforced)");

        // A GENUINE EXTENDED RIGHT KEEPS ITS BARE NAME, because that is what the ACL editor shows
        // and the rule above applies: an administrator comparing the two screens must not find two
        // words for one right.
        //
        // A GUID THAT TURNS OUT TO BE SOMETHING ELSE DOES NOT. Property sets are stored in the
        // extended-rights container but declare `validAccesses: 48`, which is read and write
        // property rather than control access - so an entry naming one with this bit is not naming
        // an extended right, and rendering it as a bare noun produced rows reading
        // "Private-Information, Write Private-Information, Read Private-Information", where the
        // first item looked like a fragment. `Control access` is Microsoft's own name for the bit.
        Add(rights, remaining, ControlAccess, objectTypeGuid, "All extended rights",
            SchemaGuidKind.ExtendedRight, (w, isExpectedKind) => isExpectedKind ? w : "Control access to " + w);
        Add(rights, remaining, WriteProperty, objectTypeGuid, "Write all properties",
            SchemaGuidKind.Attribute, (w, _) => "Write " + w);
        Add(rights, remaining, ReadProperty, objectTypeGuid, "Read all properties",
            SchemaGuidKind.Attribute, (w, _) => "Read " + w);
        Add(rights, remaining, Self, objectTypeGuid, "All validated writes",
            SchemaGuidKind.ValidatedWrite, (w, _) => "Validated write to " + w);
        Add(rights, remaining, CreateChild, objectTypeGuid, "Create any child object",
            SchemaGuidKind.ObjectClass, (w, _) => "Create " + w + " objects");
        Add(rights, remaining, DeleteChild, objectTypeGuid, "Delete any child object",
            SchemaGuidKind.ObjectClass, (w, _) => "Delete " + w + " objects");

        // THE WORDS ARE MICROSOFT'S, NOT THIS PRODUCT'S. They are the labels ADSI Edit and the ACL
        // editor show for the same bits, taken from the mapping published on Microsoft Learn. An
        // administrator comparing this screen against ADUC must not find two different words for
        // one right.
        //
        // 'Modify owner' was 'Take ownership' until 2026-08-18. That is the FILE SYSTEM's label for
        // WRITE_OWNER; the directory's is 'Modify Owner', and the two tools sit side by side on the
        // same administrator's screen.
        AddPlain(rights, remaining, WriteDac, "Modify permissions");
        AddPlain(rights, remaining, WriteOwner, "Modify owner");
        AddPlain(rights, remaining, Delete, "Delete");
        AddPlain(rights, remaining, DeleteTree, "Delete subtree");
        AddPlain(rights, remaining, ReadControl, "Read permissions");
        AddPlain(rights, remaining, ListChildren, "List contents");
        AddPlain(rights, remaining, ListObject, "List object");
        AddPlain(rights, remaining, Synchronize, "Synchronize");

        // NOT A GRANTED RIGHT. Microsoft: this bit MUST NOT be set in an ACE that is part of a
        // DACL, because a DACL does not control access to a SACL. So its presence is evidence that
        // something is wrong with the entry, not a permission somebody holds, and it is worded as
        // the anomaly it is rather than as one more item in a list of grants.
        AddPlain(rights, remaining, AccessSystemSecurity,
            "Access system security (not valid in a DACL - anomalous)");

        var unnamed = remaining & ~Named;
        var everythingIsNamed = unnamed == 0;

        // COUNTED, AND MARKED AS UNNAMED. It is still access an administrator is looking at, so it
        // is shown; but this build has no word for it, so nothing may judge it either way.
        if (!everythingIsNamed)
            rights.Add(new PermissionRight($"other rights (0x{unnamed:X8})", unnamed, IsNamed: false));

        if (rights.Count == 0)
        {
            // A mask of nothing grants nothing, and saying so plainly beats an empty line that
            // reads as though the row failed to load.
            return new PermissionWording("No rights", [], RightsAreComplete: true);
        }

        return new PermissionWording(
            string.Join(", ", rights.Select(r => r.Name)), rights, everythingIsNamed);
    }

    /// <summary>
    /// Adds a right that may be limited to one GUID.
    /// </summary>
    /// <remarks>
    /// A GUID the catalogue does not know is shown as the GUID rather than dropped or guessed at.
    /// An unrecognised extended right is still a right, and hiding it would hide access.
    /// </remarks>
    private void Add(
        List<PermissionRight> rights,
        int mask,
        int bit,
        string? objectTypeGuid,
        string whenEverything,
        SchemaGuidKind names,
        Func<string, bool, string> whenLimited)
    {
        if ((mask & bit) == 0)
            return;

        if (objectTypeGuid is null)
        {
            rights.Add(new PermissionRight(whenEverything, bit, IsNamed: true));
            return;
        }

        var (name, isExpectedKind) = Resolve(objectTypeGuid, names);
        rights.Add(new PermissionRight(whenLimited(name, isExpectedKind), bit, IsNamed: true));
    }

    private static void AddPlain(List<PermissionRight> rights, int mask, int bit, string word)
    {
        if ((mask & bit) != 0)
            rights.Add(new PermissionRight(word, bit, IsNamed: true));
    }

    /// <summary>
    /// What the catalogue calls a GUID, chosen by the right it qualifies.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>One GUID can name more than one thing, and the right decides which.</b>
    /// <c>bf9679c0-0de6-11d0-a285-00aa003049e2</c> is both the <c>member</c> attribute and the
    /// <i>Self-Membership</i> validated write - Active Directory gives them the same value. So
    /// <c>WriteProperty</c> with that GUID is <i>Write member</i>, which lets a principal add
    /// anybody to a group, while <c>Self</c> with the same GUID is <i>Self-Membership</i>, which
    /// lets them add only themselves. Taking whichever entry came first named one as the other.
    /// Found by a test, 2026-08-18.
    /// </para>
    /// <para>
    /// When the catalogue knows the GUID but not under the expected kind, the name it does have is
    /// used rather than none: a name of the wrong kind is still more use than a raw GUID, and the
    /// alternative is hiding what the entry is about.
    /// </para>
    /// </remarks>
    private (string Name, bool IsExpectedKind) Resolve(string guid, SchemaGuidKind names)
    {
        var found = _catalog.FindByGuid(guid);

        if (found.Count == 0)
            return (guid, false);

        var expected = found.FirstOrDefault(e => e.Kind == names);

        return expected is not null ? (expected.LdapName, true) : (found[0].LdapName, false);
    }
}
