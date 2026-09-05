using SecureAD.Evidence;
using SecureAD.Kernel.Security;
using Xunit;

namespace SecureAD.Next.Tests.Evidence;

/// <summary>
/// Working out what a trustee actually holds, from a list that does not say so directly.
/// </summary>
/// <remarks>
/// <para>
/// <b>Every case here is a way a permission list lies to somebody reading it entry by entry.</b> An
/// entry can be sitting on an object only to be copied to the objects beneath it; a deny can be
/// cancelled by an allow that happens to come first; an entry can be limited to one attribute while
/// looking like a grant over the object. Each of those, read naively, produces a sentence about a
/// customer's directory that is not true.
/// </para>
/// <para>
/// <b>These are anchored to MS-ADTS 6.1.3 and MS-DTYP 2.4.4.1</b>, not to the behaviour of the code
/// they cover. Per <c>F-S44-2</c>, a fixture built from the same assumption as the code proves only
/// that the two agree.
/// </para>
/// </remarks>
public sealed class EffectiveAccessCalculatorTests
{
    private const string ObjectDn = "CN=Thing,DC=contoso,DC=com";
    private const string DomainDn = "DC=contoso,DC=com";
    private const string Broad = "S-1-1-0";

    private const int ReadProperty = 0x00000010;
    private const int WriteDacl = 0x00040000;
    private const int WriteOwner = 0x00080000;

    private const string SomeAttribute = "aaaaaaaa-1111-2222-3333-444444444444";
    private const string OtherAttribute = "bbbbbbbb-1111-2222-3333-444444444444";

    /// <summary>A plain allow entry is what it looks like.</summary>
    [Fact]
    public void AnAllowEntryGrantsWhatItSays()
    {
        var access = Holders(
            Permissions(Allowing(Broad, WriteDacl)));

        Assert.Equal(WriteDacl, Assert.Single(access).Mask);
    }

    /// <summary>
    /// An inherit-only entry grants nothing on the object carrying it.
    /// </summary>
    /// <remarks>
    /// <b>This is the negative control the whole lift was made for.</b> MS-ADTS 6.1.3: the
    /// <c>INHERIT_ONLY_ACE</c> flag <i>"identifies an ineffective ACE, which does not control
    /// access to the object to which it is attached"</i>. An organizational unit that hands
    /// <i>Everyone</i> control of the objects beneath it must not be reported as handing anybody
    /// control of the organizational unit - the grant is real and it lands somewhere else.
    /// </remarks>
    [Fact]
    public void AnInheritOnlyEntryGrantsNothingOnTheObjectCarryingIt()
    {
        var access = Holders(
            Permissions(InheritOnly(Broad, WriteDacl)));

        Assert.Empty(access);
    }

    /// <summary>
    /// An inherit-only entry does not quietly cancel a real one beside it either.
    /// </summary>
    /// <remarks>
    /// The complement of the case above, and the one a careless fix would break: skipping the entry
    /// must not skip the trustee.
    /// </remarks>
    [Fact]
    public void AnInheritOnlyEntryDoesNotHideAnEffectiveOneForTheSameTrustee()
    {
        var access = Holders(
            Permissions(InheritOnly(Broad, WriteOwner), Allowing(Broad, WriteDacl)));

        Assert.Equal(WriteDacl, Assert.Single(access).Mask);
    }

    /// <summary>
    /// A deny that comes first removes the right.
    /// </summary>
    [Fact]
    public void ADenyBeforeAnAllowTakesEffect()
    {
        var access = Holders(
            Permissions(Denying(Broad, WriteDacl), Allowing(Broad, WriteDacl)));

        Assert.Empty(access);
    }

    /// <summary>
    /// An allow that comes first survives a later deny, which is what the platform does.
    /// </summary>
    /// <remarks>
    /// <b>This is the case that makes a non-canonical list more open than it reads</b>, and the
    /// reason <c>DaclWasCanonical</c> is carried on the evidence. Active Directory accumulates
    /// granted and denied masks across the list and adds a deny only for rights not already
    /// granted. Sorting the entries before evaluating them - the obvious-looking simplification -
    /// would report this object as safe when it is not.
    /// </remarks>
    [Fact]
    public void AnAllowBeforeADenySurvivesIt()
    {
        var access = Holders(
            Permissions(Allowing(Broad, WriteDacl), Denying(Broad, WriteDacl)));

        Assert.Equal(WriteDacl, Assert.Single(access).Mask);
    }

    /// <summary>
    /// A deny removes only the rights it names, leaving the rest.
    /// </summary>
    [Fact]
    public void ADenyRemovesOnlyTheRightsItNames()
    {
        var access = Holders(
            Permissions(Denying(Broad, WriteOwner), Allowing(Broad, WriteDacl | WriteOwner)));

        Assert.Equal(WriteDacl, Assert.Single(access).Mask);
    }

    /// <summary>
    /// A trustee left holding nothing is not reported as holding nothing - it is not reported.
    /// </summary>
    [Fact]
    public void ATrusteeDeniedEverythingItWasGrantedIsAbsent()
    {
        var access = Holders(
            Permissions(Denying(Broad, WriteDacl), Allowing(Broad, WriteDacl)));

        Assert.Empty(access);
    }

    /// <summary>
    /// An entry scoped to one attribute does not answer a question about the object as a whole.
    /// </summary>
    /// <remarks>
    /// A delegation letting somebody write one attribute is not control of the object, and
    /// reporting it as such would put a finding in front of a customer that cannot be justified.
    /// </remarks>
    [Fact]
    public void AScopedEntryDoesNotAnswerTheWholeObjectQuestion()
    {
        var access = Holders(
            Permissions(Scoped(Broad, WriteDacl, SomeAttribute)));

        Assert.Empty(access);
    }

    /// <summary>An entry scoped to the attribute asked about does answer.</summary>
    [Fact]
    public void AScopedEntryAnswersForItsOwnObjectType()
    {
        var access = Holders(
            Permissions(Scoped(Broad, ReadProperty, SomeAttribute)), SomeAttribute);

        Assert.Equal(ReadProperty, Assert.Single(access).Mask);
    }

    /// <summary>An entry scoped to a different attribute does not.</summary>
    [Fact]
    public void AScopedEntryDoesNotAnswerForAnotherObjectType()
    {
        var access = Holders(
            Permissions(Scoped(Broad, ReadProperty, OtherAttribute)), SomeAttribute);

        Assert.Empty(access);
    }

    /// <summary>
    /// An unscoped entry reaches every attribute, and that is read from the flag rather than the
    /// GUID.
    /// </summary>
    /// <remarks>
    /// <b>An object entry carrying no GUID narrows nothing.</b> Deciding scope from whether the
    /// GUID is null rather than from <c>ACE_OBJECT_TYPE_PRESENT</c> is the defect <c>S-56</c> R1
    /// records; it would drop a grant that reaches everything.
    /// </remarks>
    [Fact]
    public void AnObjectEntryCarryingNoGuidNarrowsNothing()
    {
        var entry = Ace(nameof(AceType.AccessAllowedObject), Broad, ReadProperty, null);

        var access = Holders(Permissions(entry), SomeAttribute);

        Assert.Equal(ReadProperty, Assert.Single(access).Mask);
    }

    /// <summary>
    /// A placeholder trustee is not a principal and holds nothing.
    /// </summary>
    /// <remarks>
    /// <c>CREATOR OWNER</c> and <c>OWNER RIGHTS</c> stand for whoever the owner turns out to be
    /// rather than naming anybody, and one lab bundle credited 1,708 entries to two of them.
    /// </remarks>
    [Fact]
    public void APlaceholderTrusteeHoldsNothing()
    {
        var access = Holders(
            Permissions(OwnerRightsEntry(WriteDacl)));

        Assert.Empty(access);
    }

    /// <summary>
    /// The entry reported as the cause is the one that first granted, not the last to mention it.
    /// </summary>
    /// <remarks>
    /// It is the entry an operator would go and change; a later, wider entry names a scope that is
    /// not the cause.
    /// </remarks>
    [Fact]
    public void TheCauseIsTheEntryThatFirstGranted()
    {
        var first = Allowing(Broad, WriteDacl) with { Ordinal = 3 };
        var second = Allowing(Broad, WriteOwner) with { Ordinal = 9 };

        var access = Holders(Permissions(first, second));

        Assert.Equal(3, Assert.Single(access).FirstGrantingEntry.Ordinal);
    }

    /// <summary>
    /// A descriptor nobody read is not an object that grants nothing.
    /// </summary>
    /// <remarks>
    /// <b>The one thing an audit tool must not do.</b> A production domain returned 19,927 of
    /// 100,000 objects with no readable descriptor. Handing back an empty list for those would let
    /// a caller report every one of them as safe.
    /// </remarks>
    [Fact]
    public void AnUnreadDescriptorIsNotAnAnswer()
    {
        var result = EffectiveAccessCalculator.Over(Permissions(DescriptorAvailability.Unreadable, DaclState.Present), objectTypeGuid: null);

        Assert.Equal(EffectiveAccessOutcome.DescriptorNotRead, result.Outcome);
        Assert.False(result.IsComplete);
        Assert.Empty(result.Holders);
    }

    /// <summary>
    /// A null DACL grants everyone everything, and must never read as an empty answer.
    /// </summary>
    /// <remarks>
    /// This is the most open state an object can be in, and a list of holders cannot express it.
    /// Reported as an empty list it would look like the safest object in the directory.
    /// </remarks>
    [Fact]
    public void ANullDaclIsReportedAsGrantingEveryoneEverything()
    {
        var result = EffectiveAccessCalculator.Over(Permissions(DescriptorAvailability.Read, DaclState.Null), objectTypeGuid: null);

        Assert.Equal(EffectiveAccessOutcome.GrantsEveryoneEverything, result.Outcome);
        Assert.False(result.IsComplete);
    }

    /// <summary>
    /// A DACL that declared entries and parsed none of them is unknown, not empty.
    /// </summary>
    [Fact]
    public void AnUnparsedDaclIsNotAnAnswer()
    {
        var result = EffectiveAccessCalculator.Over(Permissions(DescriptorAvailability.Read, DaclState.Unreadable), objectTypeGuid: null);

        Assert.Equal(EffectiveAccessOutcome.EntriesUnparsed, result.Outcome);
        Assert.False(result.IsComplete);
    }

    /// <summary>
    /// A DACL that lost some of its declared entries answers, but not completely.
    /// </summary>
    /// <remarks>
    /// A right nobody could parse may still be granted, so the holders below are a floor rather
    /// than the whole truth - and the caller has to be able to tell.
    /// </remarks>
    [Fact]
    public void AnIncompleteDaclComputesButDoesNotVouchForItself()
    {
        var result = EffectiveAccessCalculator.Over(Permissions(
            DescriptorAvailability.Read,
            DaclState.Present,
            DaclCompleteness.Incomplete,
            Allowing(Broad, WriteDacl)), objectTypeGuid: null);

        Assert.Equal(EffectiveAccessOutcome.Computed, result.Outcome);
        Assert.Single(result.Holders);
        Assert.False(result.IsComplete);
    }

    /// <summary>A read, complete, present DACL vouches for its own answer.</summary>
    [Fact]
    public void AReadAndCompleteDaclVouchesForItsAnswer()
    {
        var result = EffectiveAccessCalculator.Over(Permissions(Allowing(Broad, WriteDacl)), objectTypeGuid: null);

        Assert.True(result.IsComplete);
    }

    private static IReadOnlyList<EffectiveAccess> Holders(
        ObjectPermissions permissions, string? objectTypeGuid = null) =>
        EffectiveAccessCalculator.Over(permissions, objectTypeGuid).Holders;

    private static ObjectPermissions Permissions(params PermissionEntry[] entries) =>
        Permissions(
            DescriptorAvailability.Read, DaclState.Present, DaclCompleteness.Complete, entries);

    private static ObjectPermissions Permissions(
        DescriptorAvailability availability,
        DaclState daclState,
        DaclCompleteness completeness = DaclCompleteness.Complete,
        params PermissionEntry[] entries) => new(
        ObjectDn,
        availability,
        UnreadableReason: null,
        Owner: null,
        daclState,
        completeness,
        DaclWasCanonical: true,
        IsDaclProtected: false,
        entries,
        []);

    private static PermissionEntry Allowing(string sid, int mask) =>
        Ace(nameof(AceType.AccessAllowed), sid, mask, null);

    private static PermissionEntry Denying(string sid, int mask) =>
        Ace(nameof(AceType.AccessDenied), sid, mask, null);

    private static PermissionEntry Scoped(string sid, int mask, string objectTypeGuid) =>
        Ace(nameof(AceType.AccessAllowedObject), sid, mask, objectTypeGuid);

    /// <summary>
    /// An entry carrying <c>INHERIT_ONLY_ACE</c> (<c>0x08</c>) alongside the container-inherit bit
    /// that every real inherit-only entry also carries.
    /// </summary>
    private static PermissionEntry InheritOnly(string sid, int mask) => new(
        Ordinal: 0,
        nameof(AceType.AccessAllowed),
        Trustee(sid),
        mask,
        ObjectTypeGuid: null,
        InheritedObjectTypeGuid: null,
        IsInherited: false,
        InheritanceFlags: 0x02,
        PropagationFlags: 0x08,
        HasObjectType: false,
        HasInheritedObjectType: false,
        ApplicationData: []);

    private static PermissionEntry OwnerRightsEntry(int mask) => new(
        Ordinal: 0,
        nameof(AceType.AccessAllowed),
        new PermissionTrustee(
            "S-1-3-4", "OWNER RIGHTS", null, null, null,
            WellKnownSidRole.OwnerRightsQualifier, Meaning: null),
        mask,
        ObjectTypeGuid: null,
        InheritedObjectTypeGuid: null,
        IsInherited: false,
        InheritanceFlags: 0,
        PropagationFlags: 0,
        HasObjectType: false,
        HasInheritedObjectType: false,
        ApplicationData: []);

    private static PermissionEntry Ace(
        string type, string sid, int mask, string? objectTypeGuid) => new(
        Ordinal: 0,
        type,
        Trustee(sid),
        mask,
        objectTypeGuid,
        InheritedObjectTypeGuid: null,
        IsInherited: false,
        InheritanceFlags: 0,
        PropagationFlags: 0,
        HasObjectType: objectTypeGuid is not null,
        HasInheritedObjectType: false,
        ApplicationData: []);

    private static PermissionTrustee Trustee(string sid) =>
        new(sid, $"Principal {sid}", $"CN=Principal,{DomainDn}", "contoso.com", null,
            WellKnownRole: null, Meaning: null);
}
