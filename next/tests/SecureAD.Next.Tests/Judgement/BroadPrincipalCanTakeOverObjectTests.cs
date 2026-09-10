using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using SecureAD.Kernel.Capture;
using SecureAD.Kernel.Security;
using Xunit;

namespace SecureAD.Next.Tests.Judgement;

/// <summary>
/// SEC-060 - a principal broad in every organisation can take control of an object.
/// </summary>
/// <remarks>
/// <para>
/// <b>Every case here is a way the rule could tell a customer something false.</b> The rule says a
/// principal can rewrite an object's permissions. That sentence is wrong if the entry granting it
/// does not apply to the object, if a deny cancels it, if the right is scoped to one attribute, or
/// if the route runs through ownership the platform has taken away. Each of those has a test, and
/// each was watched failing.
/// </para>
/// <para>
/// <b>The access mask values are Microsoft's, not the code's.</b> Per <c>F-S44-2</c>, a fixture
/// built from the same assumption as the code proves only that the two agree.
/// </para>
/// </remarks>
public sealed class BroadPrincipalCanTakeOverObjectTests
{
    private const string Forest = "contoso.com";
    private const string Target = "OU=Applications,DC=contoso,DC=com";

    private const string Everyone = "S-1-1-0";
    private const string DomainUsers = "S-1-5-21-1004336348-1177238915-682003330-513";
    private const string Delegated = "S-1-5-21-1004336348-1177238915-682003330-1201";
    private const string Nested = "S-1-5-21-1004336348-1177238915-682003330-1202";
    private const string OwnerRights = "S-1-3-4";

    // MS-ADTS 6.1.3, transcribed from the access rights the generic mapping names.
    private const int WriteDacl = 0x00040000;
    private const int WriteOwner = 0x00080000;
    private const int ReadProperty = 0x00000010;
    private const int FullControl = 0x000F01FF;

    // GENERIC_WRITE_MAPPING = READ_CONTROL | WRITE_PROPERTY | WRITE_PROPERTY_EXTENDED. Nothing
    // else, which is why SEC-060 excludes it.
    private const int GenericWriteExpanded = 0x00020000 | 0x00000020 | 0x00000008;

    private static readonly DateTimeOffset Started =
        new(2026, 9, 5, 9, 0, 0, TimeSpan.Zero);

    /// <summary>A direct grant of Write DACL to a broad principal is the plainest finding.</summary>
    [Fact]
    public void ADirectWriteDaclGrantToABroadPrincipalIsReported()
    {
        var verdict = Judge(Container(), Allow(Everyone, WriteDacl));

        var finding = Assert.Single(verdict.Findings);
        var evidence = Assert.IsType<ObjectTakeoverEvidence>(finding.Evidence);

        Assert.Equal(Everyone, evidence.BroadPrincipalSid);
        Assert.Equal(ObjectTakeoverRight.WriteDacl, evidence.Right);
        Assert.Equal(0, evidence.NestingDepth);
        Assert.Equal(Severity.High, finding.Severity);
    }

    /// <summary>Full Control is reported as Full Control and not as Write DACL.</summary>
    /// <remarks>
    /// The mask arrives already expanded, so the rule cannot look for a <c>GENERIC_ALL</c> bit and
    /// find one. It compares against the mapping MS-ADTS publishes.
    /// </remarks>
    [Fact]
    public void FullControlIsNamedAsFullControl()
    {
        var verdict = Judge(Container(), Allow(Everyone, FullControl));

        var evidence = Assert.IsType<ObjectTakeoverEvidence>(
            Assert.Single(verdict.Findings).Evidence);

        Assert.Equal(ObjectTakeoverRight.GenericAll, evidence.Right);
    }

    /// <summary>A broad principal reached through nesting is reported with the whole route.</summary>
    /// <remarks>
    /// <b>The path is the finding.</b> Naming <i>Domain Users</i> without saying which link brought
    /// it in leaves an operator to reproduce the expansion by hand.
    /// </remarks>
    [Fact]
    public void ABroadPrincipalReachedThroughNestingIsReportedWithItsPath()
    {
        var verdict = Judge(
            Container(),
            [Allow(Delegated, WriteDacl)],
            Expands(Delegated, [Nested, DomainUsers]));

        var evidence = Assert.IsType<ObjectTakeoverEvidence>(
            Assert.Single(verdict.Findings).Evidence);

        Assert.Equal(DomainUsers, evidence.BroadPrincipalSid);
        Assert.Equal(3, evidence.MembershipPath.Count);
        Assert.Equal(Delegated, evidence.MembershipPath[0].Sid);
        Assert.Equal(2, evidence.NestingDepth);
    }

    /// <summary>
    /// GenericWrite alone is not takeover-class, and that is provable rather than a judgement.
    /// </summary>
    /// <remarks>
    /// <c>GENERIC_WRITE_MAPPING</c> contains neither <c>WRITE_DAC</c> nor <c>WRITE_OWNER</c>, so it
    /// cannot yield control of the access control list.
    /// </remarks>
    [Fact]
    public void GenericWriteAloneIsNotReported()
    {
        var verdict = Judge(Container(), Allow(Everyone, GenericWriteExpanded));

        Assert.Empty(verdict.Findings);
        Assert.True(verdict.IsComplete);
    }

    /// <summary>A read-only right is not takeover-class.</summary>
    [Fact]
    public void AReadOnlyRightIsNotReported()
    {
        var verdict = Judge(Container(), Allow(Everyone, ReadProperty));

        Assert.Empty(verdict.Findings);
    }

    /// <summary>A narrow delegation to named administrators is silent.</summary>
    [Fact]
    public void ANarrowDelegationToNamedAdministratorsIsSilent()
    {
        var verdict = Judge(
            Container(),
            [Allow(Delegated, WriteDacl)],
            Expands(Delegated, [Nested]));

        Assert.Empty(verdict.Findings);
        Assert.True(verdict.IsComplete);
    }

    /// <summary>A deny that comes first cancels the grant.</summary>
    [Fact]
    public void AGrantCancelledByAPrecedingDenyIsNotReported()
    {
        var verdict = Judge(
            Container(), Deny(Everyone, WriteDacl), Allow(Everyone, WriteDacl));

        Assert.Empty(verdict.Findings);
    }

    /// <summary>
    /// An allow that comes first survives a later deny, and the object is still reported.
    /// </summary>
    /// <remarks>
    /// <b>The negative control the earlier wording would have failed.</b> The specification said
    /// only that "a grant cancelled by a preceding deny is not a grant", which is true and
    /// incomplete: a non-canonical list is <i>more open</i> than it reads, and a rule that sorted
    /// the entries before evaluating them would report this object as safe when it is not.
    /// </remarks>
    [Fact]
    public void AGrantAheadOfADenyIsStillReported()
    {
        var verdict = Judge(
            Container(), Allow(Everyone, WriteDacl), Deny(Everyone, WriteDacl));

        Assert.Single(verdict.Findings);
    }

    /// <summary>
    /// An inherit-only entry grants nothing on the object carrying it.
    /// </summary>
    /// <remarks>
    /// <b>An organizational unit that delegates control of everything beneath it must not be
    /// reported as handing anybody control of the organizational unit itself.</b> MS-ADTS 6.1.3
    /// calls such an entry ineffective on the object it is attached to.
    /// </remarks>
    [Fact]
    public void AnInheritOnlyGrantIsNotReportedOnTheObjectCarryingIt()
    {
        var verdict = Judge(Container(), InheritOnly(Everyone, WriteDacl));

        Assert.Empty(verdict.Findings);
        Assert.True(verdict.IsComplete);
    }

    /// <summary>
    /// An entry scoped to one attribute is not control of the object.
    /// </summary>
    [Fact]
    public void AnEntryScopedToAnAttributeIsNotReported()
    {
        var verdict = Judge(
            Container(),
            Scoped(Everyone, WriteDacl, "aaaaaaaa-1111-2222-3333-444444444444"));

        Assert.Empty(verdict.Findings);
    }

    /// <summary>
    /// Take Ownership is takeover-class on an ordinary object, because an owner keeps the right to
    /// rewrite the list.
    /// </summary>
    [Fact]
    public void TakeOwnershipIsReportedWhereAnOwnerWouldKeepTheRight()
    {
        var verdict = Judge(Container(), Allow(Everyone, WriteOwner));

        var evidence = Assert.IsType<ObjectTakeoverEvidence>(
            Assert.Single(verdict.Findings).Evidence);

        Assert.Equal(ObjectTakeoverRight.WriteOwner, evidence.Right);
        Assert.True(evidence.ThroughOwnership);
    }

    /// <summary>
    /// Take Ownership is not takeover-class where an <c>OWNER RIGHTS</c> entry has switched the
    /// owner's implicit rights off.
    /// </summary>
    /// <remarks>
    /// <b>Invisible unless deliberately tested.</b> The rule looks entirely correct without this,
    /// and reports a principal as able to rewrite permissions it cannot rewrite.
    /// </remarks>
    [Fact]
    public void TakeOwnershipIsNotReportedWhereOwnerRightsSwitchesItOff()
    {
        var verdict = Judge(
            Container(), Allow(Everyone, WriteOwner), Allow(OwnerRights, ReadProperty));

        Assert.Empty(verdict.Findings);
    }

    /// <summary>
    /// Take Ownership is not takeover-class on a computer object in a forest that has blocked
    /// implicit owner rights.
    /// </summary>
    /// <remarks>
    /// This is the condition <c>P-138</c> was raised for. Reporting it would tell a customer a
    /// principal can rewrite permissions the platform prevents them from rewriting.
    /// </remarks>
    [Fact]
    public void TakeOwnershipOnAComputerWithoutAServerBaselineIsUnanswered()
    {
        var verdict = Judge(
            Computer(), [Allow(Everyone, WriteOwner)], NoMembers, Hardened());

        Assert.Empty(verdict.Findings);
        Assert.Contains(verdict.Unresolved, input => input.Reason == UnresolvedReason.OwnerServerBehaviorNotRecorded);
    }

    /// <summary>
    /// The same forest, the same grant, on an object that is not a computer - and here it <b>is</b>
    /// reported.
    /// </summary>
    /// <remarks>
    /// <b>The control that stops the hardening being read as a general switch.</b> MS-ADTS 6.1.3.4
    /// scopes the block to computer objects. A rule that dropped that condition would go silent
    /// across every organizational unit, group, user and certificate template in a hardened forest,
    /// hiding real exposure behind a setting that never applied to them.
    /// </remarks>
    [Fact]
    public void TakeOwnershipIsStillReportedOnANonComputerInAHardenedForest()
    {
        var verdict = Judge(
            Container(), [Allow(Everyone, WriteOwner)], NoMembers, Hardened());

        Assert.Single(verdict.Findings);
    }

    /// <summary>
    /// Write DACL is unaffected by the hardening, because it grants control directly rather than
    /// through ownership.
    /// </summary>
    [Fact]
    public void WriteDaclIsStillReportedOnAComputerInAHardenedForest()
    {
        var verdict = Judge(
            Computer(), [Allow(Everyone, WriteDacl)], NoMembers, Hardened());

        Assert.Single(verdict.Findings);
    }

    /// <summary>
    /// A computer object whose forest setting was never read is refused rather than answered.
    /// </summary>
    /// <remarks>
    /// Reporting would risk a false finding; staying silent would hide a real one. Refusing is the
    /// only honest answer, and it is confined to the objects the setting could apply to.
    /// </remarks>
    [Fact]
    public void AComputerIsRefusedWhereTheForestSettingWasNeverRead()
    {
        var verdict = JudgeWithoutForestSetting(Computer(), Allow(Everyone, WriteOwner));

        Assert.Empty(verdict.Findings);
        Assert.False(verdict.IsComplete);
        Assert.Contains(
            verdict.Unresolved, u => u.Reason == UnresolvedReason.OwnerHeuristicNotRead);
    }

    /// <summary>
    /// A non-computer object is answered even when the forest setting was never read.
    /// </summary>
    /// <remarks>
    /// The setting can never apply to it, so the unread value is not a doubt about anything. Without
    /// this the rule would refuse most of the directory whenever the configuration partition was
    /// missed.
    /// </remarks>
    [Fact]
    public void ANonComputerIsAnsweredEvenWithoutTheForestSetting()
    {
        var verdict = JudgeWithoutForestSetting(Container(), Allow(Everyone, WriteDacl));

        Assert.Single(verdict.Findings);
        Assert.True(verdict.IsComplete);
    }

    /// <summary>An object whose descriptor was unreadable must not report clean.</summary>
    [Fact]
    public void AnUnreadableDescriptorIsRefused()
    {
        var verdict = new BroadPrincipalCanTakeOverObject().Judge(
            Container(),
            JudgingContext.At(Started) with
            {
                Permissions = _ => Permissions(DescriptorAvailability.Unreadable, []),
                MembersOfPrincipal = NoMembers,
                OwnerImplicitRights = Unhardened(),
            });

        Assert.Empty(verdict.Findings);
        Assert.False(verdict.IsComplete);
    }

    /// <summary>
    /// A truncated expansion that found no broad principal must not report clean.
    /// </summary>
    [Fact]
    public void ATruncatedExpansionFindingNothingIsNotReportedAsClean()
    {
        var verdict = Judge(
            Container(),
            [Allow(Delegated, WriteDacl)],
            (_, _) => new PrincipalExpansion(
                Delegated, PrincipalExpansionOutcome.StoppedAtBudget, []));

        Assert.Empty(verdict.Findings);
        Assert.False(verdict.IsComplete);
    }

    /// <summary>
    /// A trustee that resolves to a principal which does not exist is judged silently.
    /// </summary>
    /// <remarks>
    /// <b>The opposite of SEC-031's handling, and deliberately so.</b> A grant to a deleted account
    /// reaches nobody, so there is nothing to report. An object <i>owned</i> by a deleted account is
    /// orphaned, which is a real problem - that is SEC-031's case, not this one. <c>P-134</c>.
    /// </remarks>
    [Fact]
    public void AGrantToAPrincipalThatDoesNotExistIsJudgedSilently()
    {
        var verdict = Judge(
            Container(),
            [Allow(Delegated, WriteDacl)],
            (_, _) => new PrincipalExpansion(
                Delegated, PrincipalExpansionOutcome.PrincipalDoesNotExist, null));

        Assert.Empty(verdict.Findings);
        Assert.True(verdict.IsComplete);
    }

    /// <summary>
    /// Where a principal holds both, the stronger right is the one reported.
    /// </summary>
    /// <remarks>
    /// An operator shown <i>Take Ownership</i> where the same principal also holds <i>Write
    /// DACL</i> would be told the weaker of two true things, and might conclude that hardening the
    /// forest would protect them.
    /// </remarks>
    [Fact]
    public void TheStrongestRightIsTheOneReported()
    {
        var verdict = Judge(
            Container(), Allow(Everyone, WriteOwner), Allow(Everyone, WriteDacl));

        var evidence = Assert.IsType<ObjectTakeoverEvidence>(
            Assert.Single(verdict.Findings).Evidence);

        Assert.Equal(ObjectTakeoverRight.WriteDacl, evidence.Right);
    }

    /// <summary>
    /// Finding nothing in an entry list that came back short is a refusal, not a clean object.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b><c>P-159</c>.</b> The rule already refuses an unreadable descriptor and a null DACL,
    /// because a production domain returned 19,927 of 100,000 objects with no readable descriptor
    /// and calling those safe would have been the worst thing it could say. What it did not refuse
    /// was a descriptor that <i>was</i> read and whose declared entries did not all arrive: the
    /// incompleteness was folded into <c>objectIsComplete</c>, which only ever reached the findings,
    /// so an object with a short list and nothing in it came back judged and clean.
    /// </para>
    /// <para>
    /// The entries that did not arrive are exactly the ones that might have granted takeover, which
    /// is why silence over them cannot be a statement about the object.
    /// </para>
    /// </remarks>
    [Fact]
    public void NothingFoundInAShortEntryListIsRefused()
    {
        var verdict = JudgeWithShortEntryList(Container(), Allow(Everyone, ReadProperty));

        Assert.Empty(verdict.Findings);
        Assert.False(verdict.IsComplete);
    }

    /// <summary>
    /// A whole entry list with nothing dangerous in it is still a clean object, so the refusal is
    /// not a blanket one.
    /// </summary>
    /// <remarks>
    /// Without this the change above would pass just as well if the rule had stopped reaching a
    /// verdict at all, which is the scanner self-test failure wearing different clothes.
    /// </remarks>
    [Fact]
    public void NothingFoundInAWholeEntryListIsStillClean()
    {
        var verdict = Judge(Container(), Allow(Everyone, ReadProperty));

        Assert.Empty(verdict.Findings);
        Assert.True(verdict.IsComplete);
    }

    // ---- fixtures ----

    private static RuleVerdict Judge(
        ObjectAttributes subject, params PermissionEntry[] entries) =>
        Judge(subject, entries, NoMembers);

    private static RuleVerdict Judge(
        ObjectAttributes subject,
        PermissionEntry[] entries,
        Func<string, string, PrincipalExpansion> expand,
        OwnerImplicitRightsSetting? ownerRights = null) =>
        new BroadPrincipalCanTakeOverObject().Judge(
            subject,
            JudgingContext.At(Started) with
            {
                Permissions = _ => Permissions(DescriptorAvailability.Read, entries),
                MembersOfPrincipal = expand,
                OwnerImplicitRights = ownerRights ?? Unhardened(),
            });

    /// <summary>
    /// A judging whose forest setting was never read.
    /// </summary>
    /// <remarks>
    /// <b>Its own helper rather than a null argument to the one above.</b> That helper defaults an
    /// omitted setting to an unhardened forest, so passing null through it would silently test the
    /// permissive case and the refusal control would pass while measuring nothing. Caught by this
    /// test failing when it was written that way.
    /// </remarks>
    private static RuleVerdict JudgeWithoutForestSetting(
        ObjectAttributes subject, params PermissionEntry[] entries) =>
        new BroadPrincipalCanTakeOverObject().Judge(
            subject,
            JudgingContext.At(Started) with
            {
                Permissions = _ => Permissions(DescriptorAvailability.Read, entries),
                MembersOfPrincipal = NoMembers,
                OwnerImplicitRights = null,
            });

    /// <summary>A forest that has never set the attribute, which is most forests.</summary>
    private static OwnerImplicitRightsSetting Unhardened() =>
        DirectoryHeuristics.OwnerImplicitRights(string.Empty);

    /// <summary>A forest with character 29 set to 1, which blocks.</summary>
    private static OwnerImplicitRightsSetting Hardened() =>
        DirectoryHeuristics.OwnerImplicitRights(
            new string('0', 9) + "1" + new string('0', 9) + "2" + new string('0', 8) + "1");

    private static PrincipalExpansion NoMembers(string sid, string scope) =>
        new(sid, PrincipalExpansionOutcome.Expanded, []);

    private static Func<string, string, PrincipalExpansion> Expands(
        string root, IReadOnlyList<string> members) =>
        (sid, _) => sid == root
            ? new PrincipalExpansion(
                root,
                PrincipalExpansionOutcome.Expanded,
                [
                    .. members.Select((m, i) => new ExpandedPrincipal(
                        m, Forest, [root, .. members.Take(i + 1)], true)),
                ])
            : new PrincipalExpansion(sid, PrincipalExpansionOutcome.Expanded, []);

    private static ObjectPermissions Permissions(
        DescriptorAvailability availability, IReadOnlyList<PermissionEntry> entries) =>
        Permissions(availability, entries, DaclCompleteness.Complete);

    private static ObjectPermissions Permissions(
        DescriptorAvailability availability,
        IReadOnlyList<PermissionEntry> entries,
        DaclCompleteness completeness) => new(
        Target,
        availability,
        availability is DescriptorAvailability.Unreadable ? "access denied" : null,
        Owner: null,
        availability is DescriptorAvailability.Read ? DaclState.Present : DaclState.Unreadable,
        completeness,
        DaclWasCanonical: true,
        IsDaclProtected: false,
        entries,
        Errors: []);

    /// <summary>A judging of an object whose descriptor was read and came back short.</summary>
    private static RuleVerdict JudgeWithShortEntryList(
        ObjectAttributes subject, params PermissionEntry[] entries) =>
        new BroadPrincipalCanTakeOverObject().Judge(
            subject,
            JudgingContext.At(Started) with
            {
                Permissions = _ => Permissions(
                    DescriptorAvailability.Read, entries, DaclCompleteness.Unknown),
                MembersOfPrincipal = NoMembers,
                OwnerImplicitRights = Unhardened(),
            });

    private static int _ordinal;

    private static PermissionEntry Allow(string sid, int mask) =>
        Entry("AccessAllowed", sid, mask, null, 0);

    private static PermissionEntry Deny(string sid, int mask) =>
        Entry("AccessDenied", sid, mask, null, 0);

    private static PermissionEntry Scoped(string sid, int mask, string objectTypeGuid) =>
        Entry("AccessAllowedObject", sid, mask, objectTypeGuid, 0);

    /// <summary>
    /// An entry carrying <c>INHERIT_ONLY_ACE</c> (<c>0x08</c>) beside the container-inherit bit
    /// every real inherit-only entry also carries.
    /// </summary>
    private static PermissionEntry InheritOnly(string sid, int mask) =>
        Entry("AccessAllowed", sid, mask, null, 0x08);

    private static PermissionEntry Entry(
        string aceType, string sid, int mask, string? objectTypeGuid, byte propagationFlags) =>
        new(
            _ordinal++,
            aceType,
            new PermissionTrustee(sid, null, null, Forest, null, null, null),
            mask,
            objectTypeGuid,
            InheritedObjectTypeGuid: null,
            IsInherited: false,
            InheritanceFlags: propagationFlags == 0 ? (byte)0 : (byte)0x02,
            PropagationFlags: propagationFlags,
            HasObjectType: objectTypeGuid is not null,
            HasInheritedObjectType: false,
            ApplicationData: []);

    private static ObjectAttributes Container() =>
        Subject("organizationalUnit");

    private static ObjectAttributes Computer() =>
        Subject("computer");

    private static ObjectAttributes Subject(string mostDerivedClass) => new(
        Target,
        Guid.NewGuid(),
        Started,
        EvidenceCompleteness.Complete,
        [
            new ObjectAttribute(
                "objectClass",
                AttributeCardinality.MultiValued,
                [
                    new AttributeValue(0, "top", null),
                    new AttributeValue(1, mostDerivedClass, null),
                ]),
        ],
        Forest);
}
