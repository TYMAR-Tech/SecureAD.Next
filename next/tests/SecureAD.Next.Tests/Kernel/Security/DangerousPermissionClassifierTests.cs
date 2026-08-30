using SecureAD.Kernel.Schema;
using SecureAD.Kernel.Security;
using Xunit;

namespace SecureAD.Next.Tests.Kernel.Security;

/// <summary>
/// The one place the rebuild answers "is this permission dangerous".
///
/// <para>
/// The map traces five implementations of this question in the previous product and a sixth list
/// in the rule SQL, and they disagree - two of them being the live and stored effective-access
/// panels, which exist to be read side by side. The cases below are the ones that separated them,
/// written as requirements rather than inherited from any of the five.
/// </para>
/// </summary>
public sealed class DangerousPermissionClassifierTests
{
    private static DangerousPermissionClassifier Classifier() => new(SchemaGuidCatalog.Embedded);

    private static string Guid(string ldapName) =>
        SchemaGuidCatalog.Embedded.GuidFor(ldapName)
        ?? throw new InvalidOperationException($"The catalogue does not know {ldapName}.");

    // Mask bits, named as Microsoft names them. Values from ADS_RIGHTS_ENUM.
    private const int CreateChild = 0x00000001;
    private const int DeleteChild = 0x00000002;
    private const int ListChildren = 0x00000004;
    private const int Self = 0x00000008;
    private const int ReadProperty = 0x00000010;
    private const int WriteProperty = 0x00000020;
    private const int ControlAccess = 0x00000100;
    private const int ReadControl = 0x00020000;
    private const int WriteDac = 0x00040000;
    private const int WriteOwner = 0x00080000;
    private const int GenericAllBit = 0x10000000;
    private const int GenericWriteBit = 0x40000000;

    // === The verdict is not a boolean ===

    /// <summary>
    /// The failure the map names: an ACE carrying a GUID the product does not recognise "is
    /// currently not assessed and found safe, never examined". A bool return cannot tell those
    /// apart, which is why the verdict has four states and carries a reason.
    /// </summary>
    [Fact]
    public void WhenTheObjectTypeGuidIsNotInTheCatalogueThenItCannotClassify()
    {
        var result = Classifier().Classify(
            AceType.AccessAllowedObject,
            ControlAccess,
            "11111111-2222-3333-4444-555555555555");

        Assert.Equal(PermissionVerdict.CannotClassify, result.Verdict);
        Assert.NotEqual(PermissionVerdict.NotDangerous, result.Verdict);
        Assert.NotEmpty(result.Reason);
    }

    [Fact]
    public void WhenTheObjectTypeGuidIsNotAGuidAtAllThenItCannotClassify()
    {
        var result = Classifier().Classify(AceType.AccessAllowedObject, ControlAccess, "not-a-guid");

        Assert.Equal(PermissionVerdict.CannotClassify, result.Verdict);
    }

    [Fact]
    public void WhenTheAceTypeIsNotOneWindowsDefinesThenItCannotClassify()
    {
        var result = Classifier().Classify((AceType)0x7F, WriteDac, null);

        Assert.Equal(PermissionVerdict.CannotClassify, result.Verdict);
    }

    /// <summary>
    /// A GUID the catalogue knows, under a mask bit that says nothing about which kind of right is
    /// meant. Recognising the name is not the same as being able to classify the permission.
    /// </summary>
    [Fact]
    public void WhenTheMaskNamesNoRightKindForAKnownGuidThenItCannotClassify()
    {
        var result = Classifier().Classify(
            AceType.AccessAllowedObject,
            ListChildren,
            Guid("userAccountControl"));

        Assert.Equal(PermissionVerdict.CannotClassify, result.Verdict);
    }

    /// <summary>
    /// The point of <c>S-58</c> finding <c>#13</c>, at the layer where it did damage. A right whose
    /// kind the forest did not state is refused rather than judged, and refused with its own reason
    /// - the mask-mismatch wording above describes a different failure and would send an operator
    /// looking for the wrong thing.
    /// </summary>
    /// <remarks>
    /// The bug this replaces was not that the verdict was too quiet. It was that a mislabelled
    /// right selected the wrong branch of <c>ClassifyScoped</c> entirely: an unknown control access
    /// right guessed as an extended right is judged by the extended-right rule and can never reach
    /// the property-set one, so the verdict is computed by a rule that was never about it.
    /// </remarks>
    [Fact]
    public void WhenTheForestDidNotSayWhichKindARightIsThenItCannotClassify()
    {
        var guid = System.Guid.Parse("dddddddd-1111-2222-3333-555555555555");

        var result = ClassifierKnowing(
            new SchemaGuidEntry(
                guid.ToString("D"),
                "contoso-Unstated",
                SchemaGuidKind.Unclassified,
                SchemaGuidSource.Captured))
            .Classify(AceType.AccessAllowedObject, ControlAccess, guid.ToString("D"));

        Assert.Equal(PermissionVerdict.CannotClassify, result.Verdict);
        Assert.Contains("validAccesses", result.Reason, StringComparison.Ordinal);
        Assert.Contains("contoso-Unstated", result.Reason, StringComparison.Ordinal);
    }

    private static DangerousPermissionClassifier ClassifierKnowing(SchemaGuidEntry entry) =>
        new(SchemaGuidCatalog.CapturedOver(
            [entry],
            SchemaGuidCatalog.Embedded,
            new Dictionary<string, IReadOnlyList<string>>()));

    [Fact]
    public void EveryVerdictCarriesAReason()
    {
        var classifier = Classifier();

        PermissionAssessment[] all =
        [
            classifier.Classify(AceType.AccessAllowed, WriteDac, null),
            classifier.Classify(AceType.AccessAllowed, ReadControl, null),
            classifier.Classify(AceType.AccessAllowedObject, ControlAccess, Guid("DS-Replication-Get-Changes")),
            classifier.Classify(AceType.AccessAllowedObject, ControlAccess, "11111111-2222-3333-4444-555555555555"),
        ];

        Assert.All(all, a => Assert.False(string.IsNullOrWhiteSpace(a.Reason)));
    }

    [Fact]
    public void AGenericBitStoredInAnAceIsNotReportedAsTheMappedRightsItWouldHaveRequested()
    {
        var result = Classifier().Classify(AceType.AccessAllowed, GenericAllBit, null);

        Assert.Equal(PermissionVerdict.CannotClassify, result.Verdict);
    }

    // === ACE type ===

    [Theory]
    [InlineData(AceType.AccessDenied)]
    [InlineData(AceType.AccessDeniedObject)]
    [InlineData(AceType.AccessDeniedCallback)]
    [InlineData(AceType.AccessDeniedCallbackObject)]
    public void ADenyAceGrantsNothingAndIsNotDangerous(AceType aceType)
    {
        var result = Classifier().Classify(aceType, GenericAllBit, null);

        Assert.Equal(PermissionVerdict.NotDangerous, result.Verdict);
    }

    [Theory]
    [InlineData(AceType.SystemAudit)]
    [InlineData(AceType.SystemAuditObject)]
    public void AnAuditAceGrantsNothingAndIsNotDangerous(AceType aceType)
    {
        var result = Classifier().Classify(aceType, GenericAllBit, null);

        Assert.Equal(PermissionVerdict.NotDangerous, result.Verdict);
    }

    /// <summary>
    /// A conditional ACE grants what its mask says when its condition holds. The condition is not
    /// evaluated here, so the grant is classified and the narrowing is not credited - which
    /// over-reports rather than under-reports, the only direction an audit tool may err in.
    /// </summary>
    [Fact]
    public void AConditionalAllowAceIsClassifiedOnItsMask()
    {
        var result = Classifier().Classify(AceType.AccessAllowedCallback, WriteDac, null);

        Assert.Equal(PermissionVerdict.Dangerous, result.Verdict);
    }

    // === Object-independent mask bits ===

    [Theory]
    [InlineData(WriteDac)]
    [InlineData(WriteOwner)]
    [InlineData(GenericAllBit)]
    public void TakeoverClassBitsAreDangerousWhateverTheAceIsScopedTo(int mask)
    {
        Assert.Equal(
            PermissionVerdict.Dangerous,
            Classifier().Classify(AceType.AccessAllowed, mask, null).Verdict);
    }

    /// <summary>
    /// <c>CreateChild</c> and <c>DeleteChild</c> used to sit in the theory above, and the name was
    /// never true of them - every case it passes is unscoped, so nothing ever checked the claim.
    /// With no object type the grant is every class the schema permits under the container, which
    /// is the takeover <c>docs/rules/SEC-060.md</c> describes, so the verdict here is unchanged.
    /// The scoped case is <see cref="AChildRightScopedToOneClassIsNotTheContainerTakeover"/>.
    /// Split per <c>S-57</c> finding <c>#8</c>.
    /// </summary>
    [Theory]
    [InlineData(CreateChild)]
    [InlineData(DeleteChild)]
    public void AnUnscopedChildRightIsDangerousBecauseItReachesEveryClass(int mask)
    {
        Assert.Equal(
            PermissionVerdict.Dangerous,
            Classifier().Classify(AceType.AccessAllowed, mask, null).Verdict);
    }

    /// <summary>
    /// The bits above do not become safe because the ACE also names an object type. WRITE_DAC in an
    /// object ACE still rewrites the object's whole DACL.
    /// </summary>
    [Fact]
    public void WriteDaclIsStillDangerousInsideAnObjectScopedAce()
    {
        var result = Classifier().Classify(
            AceType.AccessAllowedObject,
            WriteDac,
            Guid("description"));

        Assert.Equal(PermissionVerdict.Dangerous, result.Verdict);
    }

    // === Child rights are judged with the class in hand (S-57 #8) ===

    /// <summary>
    /// The defect <c>#8</c> names: <i>create user objects here</i> and <i>create any child object
    /// here</i> reached the same verdict by the same words, because the child bits were judged
    /// before <c>objectTypeGuid</c> was read. Microsoft's <c>ADS_RIGHT_DS_CREATE_CHILD</c> says
    /// the GUID "identifies a type of child object", so the two are different grants.
    ///
    /// <para>
    /// The verdict is <see cref="PermissionVerdict.DangerousInCombination"/> and deliberately not
    /// <see cref="PermissionVerdict.NotDangerous"/>: whether one class is a takeover depends on
    /// the container, which this component is not given. See
    /// <see cref="AClassScopedChildRightIsNotReportedSafe"/>.
    /// </para>
    /// </summary>
    [Theory]
    [InlineData(CreateChild)]
    [InlineData(DeleteChild)]
    public void AChildRightScopedToOneClassIsNotTheContainerTakeover(int mask)
    {
        var result = Classifier().Classify(AceType.AccessAllowedObject, mask, Guid("group"));

        Assert.Equal(PermissionVerdict.DangerousInCombination, result.Verdict);
        Assert.Equal("group", result.RightName);
    }

    /// <summary>
    /// The defect <c>#6</c> names: a conditional ACE was judged as though its condition did not
    /// exist, so an entry that grants only when a claim is satisfied was reported as an
    /// unconditional grant.
    /// </summary>
    /// <remarks>
    /// The verdict deliberately stays <see cref="PermissionVerdict.Dangerous"/> rather than
    /// becoming <see cref="PermissionVerdict.CannotClassify"/>. A literal reading of <c>S-56</c> v4
    /// R1 would withdraw it; the owner's decision, recorded in <c>S-58</c>, is that a conditional
    /// grant of full control is a real takeover to anybody who meets the condition, and taking its
    /// mark off the screen would trade a false positive for a false negative - <c>F-S54-2</c>.
    /// </remarks>
    [Theory]
    [InlineData(AceType.AccessAllowedCallback)]
    [InlineData(AceType.AccessAllowedCallbackObject)]
    public void AConditionalGrantKeepsItsVerdictAndSaysItMayNotApply(AceType aceType)
    {
        var result = Classifier().Classify(aceType, WriteDac, null);

        Assert.Equal(PermissionVerdict.Dangerous, result.Verdict);
        Assert.Contains("callback entry", result.Reason, StringComparison.Ordinal);
        Assert.Contains("does not read", result.Reason, StringComparison.Ordinal);
    }

    /// <summary>
    /// The original sentence survives the qualification, so the row still says what the grant does
    /// as well as that it may not apply.
    /// </summary>
    [Fact]
    public void AConditionalGrantStillNamesWhatItWouldGrant()
    {
        var ordinary = Classifier().Classify(AceType.AccessAllowed, WriteDac, null);

        var conditional = Classifier().Classify(AceType.AccessAllowedCallback, WriteDac, null);

        Assert.Contains(
            Uncapitalised(ordinary.Reason), conditional.Reason, StringComparison.Ordinal);
    }

    /// <summary>
    /// A deny entry grants no access whether or not its condition fires, so nothing it claims
    /// needs qualifying and its reason is left exactly as it was.
    /// </summary>
    [Theory]
    [InlineData(AceType.AccessDeniedCallback)]
    [InlineData(AceType.AccessDeniedCallbackObject)]
    public void AConditionalDenialIsNotQualified(AceType aceType)
    {
        var result = Classifier().Classify(aceType, WriteDac, null);

        Assert.Equal(PermissionVerdict.NotDangerous, result.Verdict);
        Assert.DoesNotContain("callback entry", result.Reason, StringComparison.Ordinal);
    }

    /// <summary>
    /// A verdict that claims nothing a condition can falsify is left alone, which is the rule
    /// <c>WhereItLands</c> already applies to inherit-only entries.
    /// </summary>
    [Fact]
    public void AConditionalEntryThatIsNotDangerousIsNotQualified()
    {
        var result = Classifier().Classify(AceType.AccessAllowedCallback, ReadControl, null);

        Assert.Equal(PermissionVerdict.NotDangerous, result.Verdict);
        Assert.DoesNotContain("callback entry", result.Reason, StringComparison.Ordinal);
    }

    /// <summary>
    /// The two qualifications compose. An inherit-only conditional entry is both, and a reader
    /// needs both sentences - one says it grants nothing here, the other says it may grant nothing
    /// anywhere.
    /// </summary>
    [Fact]
    public void AnInheritOnlyConditionalEntryCarriesBothQualifications()
    {
        var result = Classifier().Classify(
            AceType.AccessAllowedCallback, WriteDac, null, EntryReach.DescendantsOnly);

        Assert.Equal(PermissionVerdict.Dangerous, result.Verdict);
        Assert.Contains("callback entry", result.Reason, StringComparison.Ordinal);
        Assert.Contains("inherit-only", result.Reason, StringComparison.Ordinal);
    }

    private static string Uncapitalised(string reason) =>
        char.ToLowerInvariant(reason[0]) + reason[1..];

    /// <summary>
    /// The constraint this fix was done under, from <c>F-S54-2</c>: the change moves the Dangerous
    /// count down, and a count moving in the reassuring direction can hide a silenced true
    /// positive. A class-scoped child right must not come back safe - <c>docs/rules/SEC-121.md</c>
    /// treats <c>CreateChild</c> on the <c>computer</c> class as Critical on the Domain
    /// Controllers OU.
    /// </summary>
    [Fact]
    public void AClassScopedChildRightIsNotReportedSafe()
    {
        var result = Classifier().Classify(
            AceType.AccessAllowedObject,
            CreateChild,
            Guid("computer"));

        Assert.NotEqual(PermissionVerdict.NotDangerous, result.Verdict);
        Assert.Contains("computer", result.Reason, StringComparison.Ordinal);
    }

    /// <summary>
    /// The other half of the same constraint. An entry carrying a class-scoped child right
    /// <i>and</i> <c>WriteDac</c> is caught by the object-independent arm and must not move at all
    /// - it stays <see cref="PermissionVerdict.Dangerous"/> for a different and correct reason.
    /// </summary>
    [Fact]
    public void AChildRightAlongsideWriteDaclStaysDangerousOnTheDaclWrite()
    {
        var result = Classifier().Classify(
            AceType.AccessAllowedObject,
            CreateChild | WriteDac,
            Guid("group"));

        Assert.Equal(PermissionVerdict.Dangerous, result.Verdict);
        Assert.Contains("Modify Permissions", result.Reason, StringComparison.Ordinal);
    }

    /// <summary>
    /// A child right whose GUID names an attribute rather than a class is a contradiction: the bit
    /// says the GUID is a child class and the schema says it is not. That is not assessed, and in
    /// particular it is not safe.
    /// </summary>
    [Fact]
    public void AChildRightScopedToSomethingThatIsNotAClassCannotBeClassified()
    {
        var result = Classifier().Classify(
            AceType.AccessAllowedObject,
            CreateChild,
            Guid("userAccountControl"));

        Assert.Equal(PermissionVerdict.CannotClassify, result.Verdict);
    }

    // === An entry does not govern every object it sits in the DACL of (S-56 R13) ===

    /// <summary>
    /// <c>INHERIT_ONLY_ACE</c> means the entry does not control access to the object it is
    /// attached to (MS-DTYP 2.4.4.1). The grant is real and it lands on the objects beneath, so
    /// the verdict must not soften - an inherit-only grant of Modify Permissions hands over every
    /// descendant. What changes is what the reason is allowed to claim.
    /// </summary>
    [Fact]
    public void AnInheritOnlyEntryIsJustAsDangerousToTheObjectsItReaches()
    {
        var result = Classifier().Classify(
            AceType.AccessAllowed, WriteDac, null, EntryReach.DescendantsOnly);

        Assert.Equal(PermissionVerdict.Dangerous, result.Verdict);
    }

    /// <summary>
    /// The defect <c>F-S58-6</c> names: the reason said the entry hands somebody control of this
    /// object, while the Scope column beside it said the entry reaches only descendants. The
    /// original sentence is kept whole because it still describes the grant correctly - the
    /// correction is about where it lands, not what it is.
    /// </summary>
    [Fact]
    public void AnInheritOnlyEntryDoesNotClaimAGrantOnThisObject()
    {
        var result = Classifier().Classify(
            AceType.AccessAllowed, WriteDac, null, EntryReach.DescendantsOnly);

        Assert.Contains("grants nothing on this object", result.Reason, StringComparison.Ordinal);
        Assert.Contains("Modify Permissions", result.Reason, StringComparison.Ordinal);
    }

    /// <summary>
    /// The same mask without the flag is untouched, so the correction cannot leak into the
    /// ordinary case - which is every entry in the lab bundle that is not inherit-only.
    /// </summary>
    [Fact]
    public void AnOrdinaryEntryKeepsItsReasonExactly()
    {
        var classifier = Classifier();

        var here = classifier.Classify(AceType.AccessAllowed, WriteDac, null);
        var alsoHere = classifier.Classify(
            AceType.AccessAllowed, WriteDac, null, EntryReach.ThisObject);

        Assert.Equal(here.Reason, alsoHere.Reason);
        Assert.DoesNotContain("inherit-only", here.Reason, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Only a claim of danger is rewritten. "Grants no write over the object" and "has not been
    /// assessed" are both still true of an inherit-only entry, so decorating them would add noise
    /// to rows that make no false claim.
    /// </summary>
    [Theory]
    [InlineData(ReadControl)]
    [InlineData(0)]
    public void AnInheritOnlyEntryThatClaimsNothingIsLeftAlone(int mask)
    {
        var classifier = Classifier();

        var here = classifier.Classify(AceType.AccessAllowed, mask, null);
        var below = classifier.Classify(
            AceType.AccessAllowed, mask, null, EntryReach.DescendantsOnly);

        Assert.Equal(PermissionVerdict.NotDangerous, below.Verdict);
        Assert.Equal(here.Reason, below.Reason);
    }

    /// <summary>
    /// The correction reaches a class-scoped child right too, which is the finding this session
    /// fixed and the finding it raised meeting on one entry.
    /// </summary>
    [Fact]
    public void AnInheritOnlyClassScopedChildRightIsCorrectedAsWell()
    {
        var result = Classifier().Classify(
            AceType.AccessAllowedObject, CreateChild, Guid("group"), EntryReach.DescendantsOnly);

        Assert.Equal(PermissionVerdict.DangerousInCombination, result.Verdict);
        Assert.Contains("grants nothing on this object", result.Reason, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData((byte)0x00, EntryReach.ThisObject)]
    [InlineData((byte)0x04, EntryReach.ThisObject)]
    [InlineData((byte)0x08, EntryReach.DescendantsOnly)]
    [InlineData((byte)0x0C, EntryReach.DescendantsOnly)]
    public void ReachIsReadFromTheInheritOnlyBitAlone(byte propagationFlags, EntryReach expected)
    {
        Assert.Equal(expected, EntryReachReader.FromPropagationFlags(propagationFlags));
    }

    /// <summary>
    /// The previous bitmask classifier never used the constant it declared for extended rights, so
    /// an ACE granting all extended rights - which includes Reset Password and the replication
    /// family - was not dangerous by it.
    /// </summary>
    [Fact]
    public void AnUnscopedGrantOfAllExtendedRightsIsDangerous()
    {
        Assert.Equal(
            PermissionVerdict.Dangerous,
            Classifier().Classify(AceType.AccessAllowed, ControlAccess, null).Verdict);
    }

    [Fact]
    public void AnUnscopedGrantOfAllPropertyWritesIsDangerous()
    {
        Assert.Equal(
            PermissionVerdict.Dangerous,
            Classifier().Classify(AceType.AccessAllowed, WriteProperty, null).Verdict);
    }

    [Fact]
    public void AnUnscopedGrantOfAllValidatedWritesIsDangerous()
    {
        Assert.Equal(
            PermissionVerdict.Dangerous,
            Classifier().Classify(AceType.AccessAllowed, Self, null).Verdict);
    }

    /// <summary>
    /// GENERIC_WRITE was absent from the previous bitmask classifier. Reading it as the rights it
    /// stands for reaches the unscoped write case, so the entry is treated as dangerous.
    ///
    /// <para>
    /// <b>This is a judgement about severity, not a statement of what the entry grants.</b> The
    /// name previously said the entry <i>expands to</i> unscoped property write, which asserts that
    /// the mapped rights are in force. [MS-DTYP] 2.4.3 says the access check does not map a generic
    /// bit found in a stored ACE, so that assertion was not ours to make. Reading the mask that
    /// grants most is still right for deciding how much attention an entry deserves - the danger is
    /// that it <i>may</i> carry those rights - and the screen states the doubt separately, through
    /// the wording. Renamed rather than deleted, per <c>docs/next/S-58</c>.
    /// </para>
    /// </summary>
    [Fact]
    public void GenericWriteIsTreatedAsDangerousBecauseItMayCarryUnscopedPropertyWrite()
    {
        Assert.Equal(
            PermissionVerdict.Dangerous,
            Classifier().Classify(AceType.AccessAllowed, GenericWriteBit, null).Verdict);
    }

    [Theory]
    [InlineData(ReadControl)]
    [InlineData(ListChildren)]
    [InlineData(ReadProperty)]
    [InlineData(0)]
    public void ReadClassAndEmptyMasksAreNotDangerous(int mask)
    {
        Assert.Equal(
            PermissionVerdict.NotDangerous,
            Classifier().Classify(AceType.AccessAllowed, mask, null).Verdict);
    }

    // === The nine names handed over by F-S3-2 ===

    [Fact]
    public void ForceChangePasswordIsDangerous()
    {
        var result = Classifier().Classify(
            AceType.AccessAllowedObject,
            ControlAccess,
            Guid("User-Force-Change-Password"));

        Assert.Equal(PermissionVerdict.Dangerous, result.Verdict);
        Assert.Equal("User-Force-Change-Password", result.RightName);
    }

    /// <summary>
    /// Decision 0016: whether a replication right is dangerous is a question about the set a
    /// principal holds, and a per-ACE classifier cannot hold a position on a pair. It says so
    /// rather than answering safe.
    /// </summary>
    [Theory]
    [InlineData("DS-Replication-Get-Changes")]
    [InlineData("DS-Replication-Get-Changes-All")]
    [InlineData("DS-Replication-Get-Changes-In-Filtered-Set")]
    public void AReplicationRightIsDangerousOnlyInCombination(string ldapName)
    {
        var result = Classifier().Classify(AceType.AccessAllowedObject, ControlAccess, Guid(ldapName));

        Assert.Equal(PermissionVerdict.DangerousInCombination, result.Verdict);
        Assert.Equal(ldapName, result.RightName);
    }

    [Theory]
    [InlineData("Self-Membership")]
    [InlineData("Validated-SPN")]
    public void ADangerousValidatedWriteIsDangerous(string ldapName)
    {
        var result = Classifier().Classify(AceType.AccessAllowedObject, Self, Guid(ldapName));

        Assert.Equal(PermissionVerdict.Dangerous, result.Verdict);
        Assert.Equal(ldapName, result.RightName);
    }

    [Theory]
    [InlineData("userAccountControl")]
    [InlineData("unicodePwd")]
    [InlineData("msDS-KeyCredentialLink")]
    [InlineData("msDS-AllowedToActOnBehalfOfOtherIdentity")]
    [InlineData("servicePrincipalName")]
    [InlineData("sIDHistory")]
    [InlineData("member")]
    public void WritingADangerousAttributeIsDangerous(string ldapName)
    {
        var result = Classifier().Classify(AceType.AccessAllowedObject, WriteProperty, Guid(ldapName));

        Assert.Equal(PermissionVerdict.Dangerous, result.Verdict);
        Assert.Equal(ldapName, result.RightName);
    }

    /// <summary>
    /// The kind is decided by the mask bit, not by the GUID. <c>Self-Membership</c> and
    /// <c>member</c> share one GUID, and the catalogue returns both meanings.
    /// </summary>
    [Fact]
    public void TheSharedGuidIsReadAsTheValidatedWriteUnderSelfAndAsTheAttributeUnderWriteProperty()
    {
        var classifier = Classifier();
        var guid = Guid("Self-Membership");

        Assert.Equal("Self-Membership", classifier.Classify(AceType.AccessAllowedObject, Self, guid).RightName);
        Assert.Equal("member", classifier.Classify(AceType.AccessAllowedObject, WriteProperty, guid).RightName);
    }

    /// <summary>
    /// Reading these two is the whole of the LAPS exposure that rule SEC-090 detects, and reading
    /// any other attribute is not a finding.
    /// </summary>
    [Theory]
    [InlineData("ms-Mcs-AdmPwd")]
    [InlineData("msLAPS-Password")]
    public void ReadingALocalAdministratorPasswordIsDangerous(string ldapName)
    {
        var result = Classifier().Classify(AceType.AccessAllowedObject, ReadProperty, Guid(ldapName));

        Assert.Equal(PermissionVerdict.Dangerous, result.Verdict);
        Assert.Equal(ldapName, result.RightName);
    }

    [Fact]
    public void ReadingAnOrdinaryAttributeIsNotDangerous()
    {
        var result = Classifier().Classify(
            AceType.AccessAllowedObject,
            ReadProperty,
            Guid("description"));

        Assert.Equal(PermissionVerdict.NotDangerous, result.Verdict);
        Assert.Equal("description", result.RightName);
    }

    [Fact]
    public void WritingAnOrdinaryAttributeIsNotDangerous()
    {
        var result = Classifier().Classify(
            AceType.AccessAllowedObject,
            WriteProperty,
            Guid("description"));

        Assert.Equal(PermissionVerdict.NotDangerous, result.Verdict);
    }

    [Fact]
    public void AnOrdinaryExtendedRightIsNotDangerous()
    {
        var result = Classifier().Classify(
            AceType.AccessAllowedObject,
            ControlAccess,
            Guid("Send-As"));

        Assert.Equal(PermissionVerdict.NotDangerous, result.Verdict);
        Assert.Equal("Send-As", result.RightName);
    }

    // === The two the live and stored panels disagreed about ===

    /// <summary>
    /// The live panel called these dangerous and the stored panel did not, so the two screens a
    /// user is meant to compare gave different answers about the same ACE. Settled here in favour
    /// of the wider reading, and raised to the owner in the slice document: writing either runs
    /// code across everything in scope, and unlinking a hardening policy through <c>gPLink</c>
    /// needs no other privilege.
    /// </summary>
    [Theory]
    [InlineData("gPLink")]
    [InlineData("scriptPath")]
    public void WritingAPolicyLinkOrALogonScriptIsDangerous(string ldapName)
    {
        var result = Classifier().Classify(AceType.AccessAllowedObject, WriteProperty, Guid(ldapName));

        Assert.Equal(PermissionVerdict.Dangerous, result.Verdict);
        Assert.Equal(ldapName, result.RightName);
    }

    // === Asked one right at a time ===

    /// <summary>
    /// The whole basis of per-right marking. A caller that wants to know which right earned the
    /// verdict asks about one right's bits at a time, and this must reach the same answer it would
    /// have reached about that right inside a wider mask - otherwise splitting the question would
    /// change what the product says is dangerous, and the split is meant to be a change of
    /// presentation only.
    /// </summary>
    [Fact]
    public void OneRightsBitsReachTheSameVerdictAloneAsInsideAWiderMask()
    {
        var classifier = Classifier();

        var alone = classifier.Classify(AceType.AccessAllowed, WriteDac, null);
        var together = classifier.Classify(
            AceType.AccessAllowed, WriteDac | ReadControl | ListChildren, null);

        Assert.Equal(PermissionVerdict.Dangerous, alone.Verdict);
        Assert.Equal(together.Verdict, alone.Verdict);
    }

    /// <summary>
    /// And the reverse, which is the defect Option C repairs. Asked about the whole mask this
    /// answers <see cref="PermissionVerdict.Dangerous"/> - correctly, the entry does hand over the
    /// object - but the harmless right in the same mask is not what earned it. Asked separately,
    /// the two rights part company.
    /// </summary>
    [Fact]
    public void TheHarmlessRightInADangerousMaskIsNotDangerousOnItsOwn()
    {
        var classifier = Classifier();

        var whole = classifier.Classify(AceType.AccessAllowed, WriteDac | ReadControl, null);
        var harmless = classifier.Classify(AceType.AccessAllowed, ReadControl, null);

        Assert.Equal(PermissionVerdict.Dangerous, whole.Verdict);
        Assert.Equal(PermissionVerdict.NotDangerous, harmless.Verdict);
    }

    /// <summary>
    /// A scoped entry names one GUID and can carry several rights over it, and they are not all
    /// the same answer. Write to <c>userAccountControl</c> hands over the account; reading it does
    /// not.
    /// </summary>
    [Fact]
    public void ReadingAndWritingTheSameAttributeAreJudgedSeparately()
    {
        var classifier = Classifier();
        var guid = Guid("userAccountControl");

        var write = classifier.Classify(AceType.AccessAllowedObject, WriteProperty, guid);
        var read = classifier.Classify(AceType.AccessAllowedObject, ReadProperty, guid);

        Assert.Equal(PermissionVerdict.Dangerous, write.Verdict);
        Assert.NotEqual(PermissionVerdict.Dangerous, read.Verdict);
    }

    // === Scanner self-test ===

    /// <summary>
    /// Without this, every case above could pass against a classifier that answers
    /// <see cref="PermissionVerdict.CannotClassify"/> to everything, or against a catalogue that
    /// knows none of the names these tests look up.
    /// </summary>
    [Fact]
    public void TheCheckExercisesEveryVerdictAndTheCatalogueKnowsTheNames()
    {
        var classifier = Classifier();

        var produced = new[]
        {
            classifier.Classify(AceType.AccessAllowed, WriteDac, null).Verdict,
            classifier.Classify(AceType.AccessAllowed, ReadControl, null).Verdict,
            classifier.Classify(AceType.AccessAllowedObject, ControlAccess, Guid("DS-Replication-Get-Changes")).Verdict,
            classifier.Classify(AceType.AccessAllowedObject, ControlAccess, "11111111-2222-3333-4444-555555555555").Verdict,
        };

        Assert.Equal(Enum.GetValues<PermissionVerdict>().OrderBy(v => v), produced.OrderBy(v => v));
    }
}
