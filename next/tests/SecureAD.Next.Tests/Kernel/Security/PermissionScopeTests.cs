using SecureAD.Kernel.Schema;
using SecureAD.Kernel.Security;
using Xunit;

namespace SecureAD.Next.Tests.Kernel.Security;

/// <summary>
/// How far an entry reaches, said in the ACL editor's words.
/// </summary>
/// <remarks>
/// The flag values and their meanings were confirmed against Microsoft Learn on 2026-08-18 -
/// <i>ACE_HEADER structure</i>, <i>ACE Inheritance Rules</i> and <i>Object-specific ACEs</i>. These
/// tests hold the wording against those rules; they cannot and do not prove the rules.
/// </remarks>
public sealed class PermissionScopeTests
{
    private static readonly PermissionScopeWriter Writer = new(SchemaGuidCatalog.Embedded);

    private const byte ObjectInherit = 0x01;
    private const byte ContainerInherit = 0x02;
    private const byte NoPropagateInherit = 0x04;
    private const byte InheritOnly = 0x08;

    /// <summary>The GUID of the user class, which an entry may be limited to inheriting.</summary>
    private const string UserClass = "bf967aba-0de6-11d0-a285-00aa003049e2";

    // ---------------------------------------------------------------------------------------
    // What the entry governs
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void AnEntryWithNoInheritFlagsGovernsTheObjectItIsOn()
    {
        Assert.Equal("This object only", AppliesTo(0, 0));
    }

    [Fact]
    public void AnEntryInheritedByContainersGovernsTheObjectAndEverythingBeneathIt()
    {
        Assert.Equal(
            "This object and all descendant objects", AppliesTo(ContainerInherit, 0));
    }

    /// <summary>
    /// <c>INHERIT_ONLY_ACE</c> means the entry does not control access to the object it is attached
    /// to. Saying "this object and…" of one would claim access it does not grant.
    /// </summary>
    [Fact]
    public void AnInheritOnlyEntryDoesNotGovernTheObjectItIsOn()
    {
        Assert.Equal(
            "All descendant objects", AppliesTo(ContainerInherit, InheritOnly));
    }

    /// <summary>
    /// <c>NO_PROPAGATE_INHERIT_ACE</c> makes the system clear both inherit flags in the copy a
    /// child receives, so the entry reaches one generation and stops. <i>Child</i> and
    /// <i>descendant</i> are the ACL editor's own two words for that difference, and using one for
    /// the other would overstate the reach of every entry carrying this flag.
    /// </summary>
    [Fact]
    public void AnEntryThatDoesNotPropagateReachesOneGenerationOnly()
    {
        Assert.Equal(
            "This object and all child objects",
            AppliesTo(ContainerInherit, NoPropagateInherit));
    }

    [Fact]
    public void AnInheritOnlyEntryThatDoesNotPropagateGovernsTheChildrenAlone()
    {
        Assert.Equal(
            "All child objects",
            AppliesTo(ContainerInherit, NoPropagateInherit | InheritOnly));
    }

    // ---------------------------------------------------------------------------------------
    // Limited to one class
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// The difference between a principal who can reset every password in an organisational unit
    /// and one who can reset the passwords of its users.
    /// </summary>
    [Fact]
    public void AnEntryLimitedToOneClassNamesThatClass()
    {
        Assert.Equal(
            "Descendant user objects",
            AppliesTo(ContainerInherit, InheritOnly, UserClass));
    }

    [Fact]
    public void AnEntryLimitedToOneClassAndEffectiveHereSaysBoth()
    {
        Assert.Equal(
            "This object and descendant user objects",
            AppliesTo(ContainerInherit, 0, UserClass));
    }

    /// <summary>
    /// Every forest carries schema extensions the shipped catalogue cannot have heard of. An entry
    /// limited to one is still an entry an operator must be able to see.
    /// </summary>
    [Fact]
    public void AnEntryLimitedToAClassThisBuildCannotNameShowsTheGuid()
    {
        const string Unknown = "11111111-2222-3333-4444-555555555555";

        Assert.Equal(
            $"Descendant {Unknown} objects",
            AppliesTo(ContainerInherit, InheritOnly, Unknown));
    }

    // ---------------------------------------------------------------------------------------
    // The directory is not the file system
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// <i>ACE Inheritance Rules</i>: the directory service treats all object types as containers.
    /// So <c>OBJECT_INHERIT_ACE</c> reaches the same objects <c>CONTAINER_INHERIT_ACE</c> does, and
    /// the file system's split between folders and files - which is what that flag is for - does
    /// not divide the directory. Wording them apart would put <i>files</i> on a forest.
    /// </summary>
    [Fact]
    public void ObjectInheritIsWordedTheSameWayContainerInheritIs()
    {
        Assert.Equal(AppliesTo(ContainerInherit, 0), AppliesTo(ObjectInherit, 0));
    }

    /// <summary>
    /// An entry that governs neither the object it is on nor anything beneath it governs nothing.
    /// It is a real thing to find in a DACL, and a blank cell would read as an entry the product
    /// failed to describe.
    /// </summary>
    [Fact]
    public void AnEntryThatReachesNothingSaysSo()
    {
        Assert.Equal("Nothing", AppliesTo(0, InheritOnly));
    }

    // ---------------------------------------------------------------------------------------
    // Where the entry came from
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void AnEntryTheDirectoryMarkedInheritedSaysSo()
    {
        Assert.Equal("Inherited", Writer.Describe(0, 0, isInherited: true, null).Inheritance);
    }

    /// <summary>
    /// An entry set here is the one an administrator can change on this object, and the difference
    /// is what tells them where to go and fix it.
    /// </summary>
    [Fact]
    public void AnEntrySetOnTheObjectSaysSo()
    {
        Assert.Equal(
            "Set on this object", Writer.Describe(0, 0, isInherited: false, null).Inheritance);
    }

    // ---------------------------------------------------------------------------------------

    private static string AppliesTo(
        byte inheritanceFlags, byte propagationFlags, string? inheritedObjectTypeGuid = null) =>
        Writer.Describe(
            inheritanceFlags, propagationFlags, isInherited: false, inheritedObjectTypeGuid)
            .AppliesTo;
}
