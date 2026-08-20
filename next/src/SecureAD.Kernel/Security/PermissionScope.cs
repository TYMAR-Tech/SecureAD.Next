using SecureAD.Kernel.Schema;

namespace SecureAD.Kernel.Security;

/// <summary>
/// How far one access control entry reaches, said in words an administrator reads.
/// </summary>
/// <remarks>
/// <b>Two answers rather than one string</b>, because they answer different questions and a reader
/// scans them in different columns. <see cref="AppliesTo"/> is what the entry governs;
/// <see cref="Inheritance"/> is where it came from.
/// </remarks>
/// <param name="AppliesTo">
/// What the entry governs - this object, its descendants, or descendants of one class.
/// </param>
/// <param name="Inheritance">
/// Whether the entry was set on this object or came down from a container above it.
/// </param>
public sealed record PermissionScope(string AppliesTo, string Inheritance);

/// <summary>
/// Turns an entry's inheritance flags into the words the ACL editor puts in its
/// <i>Applies to</i> box.
/// </summary>
/// <remarks>
/// <para>
/// <b>Every value and every rule here was confirmed against Microsoft Learn on 2026-08-18</b>,
/// which is what <c>S-50</c> recorded as owed and <c>F-S44-2</c> asks for: tests prove the code
/// does what the test says, and only Learn proves the words and the values are the directory's.
/// </para>
/// <para>
/// <b>Confirmed</b>, from <i>ACE_HEADER structure</i> and <i>ACE Inheritance Rules</i>:
/// <c>OBJECT_INHERIT_ACE</c> is <c>0x1</c> and is inherited by non-container children;
/// <c>CONTAINER_INHERIT_ACE</c> is <c>0x2</c> and is inherited by container children as an
/// effective entry; <c>NO_PROPAGATE_INHERIT_ACE</c> is <c>0x4</c> and makes the system clear both
/// inherit flags as it passes the entry down, so the entry reaches one generation and stops;
/// <c>INHERIT_ONLY_ACE</c> is <c>0x8</c> and means the entry does not control access to the object
/// it is attached to. From <i>Object-specific ACEs</i>: <c>InheritedObjectType</c> names the class
/// of child that can inherit the entry.
/// </para>
/// <para>
/// <b>The one thing that changes the reading, and it is the reason this could not be guessed at.</b>
/// <i>ACE Inheritance Rules</i> states that <b>the directory service treats all object types as
/// containers</b>. So in Active Directory <c>CONTAINER_INHERIT_ACE</c> is the flag that carries a
/// permission down, and the file system's distinction between a folder and a file - which is what
/// <c>OBJECT_INHERIT_ACE</c> is for - does not divide the directory. Wording these two as the file
/// system does would have produced <i>subfolders</i> and <i>files</i> against a forest, which is
/// the same class of error <c>WRITE_OWNER</c>'s label already was.
/// </para>
/// <para>
/// <b>Not confirmed and therefore not said:</b> nothing here claims what an entry
/// <i>effectively grants</i> anywhere. That is a computation over the whole DACL of every object
/// beneath this one, and it is not what this product has read. These are the words for one entry's
/// declared reach.
/// </para>
/// </remarks>
public sealed class PermissionScopeWriter
{
    /// <summary>Non-container children inherit the entry. In the directory, all objects are containers.</summary>
    private const byte ObjectInherit = 0x01;

    /// <summary>Container children inherit the entry as an effective entry.</summary>
    private const byte ContainerInherit = 0x02;

    /// <summary>The inherit flags are cleared as the entry passes down, so it reaches one generation.</summary>
    private const byte NoPropagateInherit = 0x04;

    /// <summary>The entry does not control access to the object it is attached to.</summary>
    private const byte InheritOnly = 0x08;

    private readonly SchemaGuidCatalog _catalog;

    /// <summary>Creates a writer that names class GUIDs from <paramref name="catalog"/>.</summary>
    /// <param name="catalog">The schema catalogue, for the class an entry is limited to.</param>
    public PermissionScopeWriter(SchemaGuidCatalog catalog)
    {
        ArgumentNullException.ThrowIfNull(catalog);

        _catalog = catalog;
    }

    /// <summary>
    /// Says how far one entry reaches.
    /// </summary>
    /// <param name="inheritanceFlags">
    /// The entry's <c>OBJECT_INHERIT_ACE</c> and <c>CONTAINER_INHERIT_ACE</c> bits.
    /// </param>
    /// <param name="propagationFlags">
    /// The entry's <c>NO_PROPAGATE_INHERIT_ACE</c> and <c>INHERIT_ONLY_ACE</c> bits.
    /// </param>
    /// <param name="isInherited">Whether the directory marked the entry as inherited.</param>
    /// <param name="inheritedObjectTypeGuid">
    /// The class of descendant the entry is inherited by, or null when it is inherited by all.
    /// </param>
    public PermissionScope Describe(
        byte inheritanceFlags,
        byte propagationFlags,
        bool isInherited,
        string? inheritedObjectTypeGuid)
    {
        return new PermissionScope(
            AppliesTo(inheritanceFlags, propagationFlags, inheritedObjectTypeGuid),
            isInherited ? "Inherited" : "Set on this object");
    }

    private string AppliesTo(
        byte inheritanceFlags, byte propagationFlags, string? inheritedObjectTypeGuid)
    {
        var reachesDown = (inheritanceFlags & (ContainerInherit | ObjectInherit)) != 0;
        var here = (propagationFlags & InheritOnly) == 0;

        // An entry with no inherit flags governs the object it is attached to and nothing else -
        // and an entry with neither an inherit flag nor an effect here governs nothing at all,
        // which is a real thing to find in a DACL and is said rather than left blank.
        if (!reachesDown)
            return here ? "This object only" : "Nothing";

        // NO_PROPAGATE_INHERIT_ACE clears the inherit flags in the copy the child receives, so the
        // entry reaches the immediate generation and no further. 'Child' and 'descendant' are the
        // ACL editor's own two words for exactly this difference.
        var generation = (propagationFlags & NoPropagateInherit) != 0 ? "child" : "descendant";

        var limitedTo = inheritedObjectTypeGuid is null ? null : NameOf(inheritedObjectTypeGuid);

        var beneath = limitedTo is null
            ? $"all {generation} objects"
            : $"{generation} {limitedTo} objects";

        return here ? $"This object and {beneath}" : Capitalised(beneath);
    }

    /// <summary>
    /// What the catalogue calls a class GUID, or the GUID itself when it does not know it.
    /// </summary>
    /// <remarks>
    /// The GUID rather than nothing, for the reason <see cref="PermissionWordingWriter"/> gives:
    /// every forest carries schema extensions this table cannot have heard of, and an entry limited
    /// to one this build cannot name is still an entry an operator must be able to see.
    /// </remarks>
    private string NameOf(string guid)
    {
        var found = _catalog.FindByGuid(guid);

        if (found.Count == 0)
            return guid;

        return (found.FirstOrDefault(e => e.Kind == SchemaGuidKind.ObjectClass) ?? found[0])
            .LdapName;
    }

    private static string Capitalised(string words) =>
        char.ToUpperInvariant(words[0]) + words[1..];
}
