using SecureAD.Evidence;
using SecureAD.Kernel.Schema;
using SecureAD.Kernel.Security;
using SecureAD.Shell.ViewModels;
using Xunit;

namespace SecureAD.Next.Tests.Shell;

/// <summary>
/// The first thing in this product that judges rather than reports.
/// </summary>
/// <remarks>
/// <para>
/// <b>What these guard.</b> Every screen before this one stated what a run found. This one runs
/// <see cref="DangerousPermissionClassifier"/> against a bundle and puts an opinion on a row, and
/// the opinion wears a colour an administrator will read as a security verdict. The two failures
/// that matter are a verdict shown when nobody asked for one, and a zero shown where nothing has
/// looked - the second being the defect
/// <c>docs/decisions/0002-absent-view-means-degraded-run.md</c> exists to prevent.
/// </para>
/// <para>
/// The classifier's own correctness is golden-tested in
/// <c>DangerousPermissionClassifierTests</c>. These are about what the screen does with its answer.
/// </para>
/// </remarks>
public sealed class PermissionClassificationTests
{
    private const string ObjectDn = "CN=Alice,DC=contoso,DC=com";
    private const string DomainDn = "DC=contoso,DC=com";

    /// <summary>ADS_RIGHT_WRITE_DAC. Rewriting an object's permissions is a takeover of it.</summary>
    private const int WriteDac = 0x00040000;

    /// <summary>ADS_RIGHT_DS_READ_PROP, scoped to nothing in particular.</summary>
    private const int ReadProperty = 0x00000010;

    /// <summary>ADS_RIGHT_DS_CONTROL_ACCESS, the bit that makes a GUID an extended right.</summary>
    private const int ControlAccess = 0x00000100;

    private const string ReplicationGetChanges = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2";

    /// <summary>ACTRL_DS_CREATE_CHILD, which is scoped to the class it may create.</summary>
    private const int CreateChild = 0x00000001;

    /// <summary>
    /// The <c>group</c> class, and one the shipped table does list - unlike
    /// <see cref="InetOrgPerson"/>, so a class-scoped child right resolves without forest schema.
    /// </summary>
    private const string GroupClass = "bf967a9c-0de6-11d0-a285-00aa003049e2";

    /// <summary>ADS_RIGHT_DS_WRITE_PROP.</summary>
    private const int WriteProperty = 0x00000020;

    /// <summary>READ_CONTROL. Reading an object's permissions is not a takeover of it.</summary>
    private const int ReadControl = 0x00020000;

    /// <summary>
    /// Every standard and directory-specific right at once - the value GENERIC_ALL expands to.
    /// </summary>
    private const int FullControl = 0x000F01FF;

    /// <summary>
    /// GENERIC_ALL, unexpanded. Capture is meant to expand it before it is stored.
    /// </summary>
    private const int GenericAll = 0x10000000;

    /// <summary>
    /// A bit this build has no word for. Reserved in the directory's mask and named by nothing in
    /// <c>PermissionWordingWriter</c>, so it is the case that must never be judged either way.
    /// </summary>
    private const int UnnamedBit = 0x00000200;

    /// <summary>
    /// A stock class the shipped table does not list, and the one on the owner's screenshot.
    /// </summary>
    private const string InetOrgPerson = "4828cc14-1437-45bc-9b07-ad6f015e5f28";

    // ---------------------------------------------------------------------------------------
    // Nothing is a verdict until the operator asks.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void TheToggleIsOffWhenTheSectionIsFirstShown()
    {
        var section = Section(Allowing("S-1-5-32-544", WriteDac));

        Assert.False(section.HighlightRiskyPermissions);
    }

    [Fact]
    public void ATakeoverEntryWearsNoMarkUntilTheToggleIsOn()
    {
        var section = Section(Allowing("S-1-5-32-544", WriteDac));

        Assert.Equal(PermissionRisk.None, OnlyRight(section).Mark);
    }

    [Fact]
    public void ATakeoverEntryIsStillClassifiedWhileUnmarked()
    {
        var section = Section(Allowing("S-1-5-32-544", WriteDac));

        Assert.Equal(PermissionRisk.Dangerous, OnlyEntry(section).Risk);
    }

    [Fact]
    public void TurningTheToggleOnMarksTheTakeoverEntry()
    {
        var section = Section(Allowing("S-1-5-32-544", WriteDac));

        section.HighlightRiskyPermissions = true;

        Assert.Equal(PermissionRisk.Dangerous, OnlyRight(section).Mark);
    }

    [Fact]
    public void TurningTheToggleOffAgainRemovesTheMark()
    {
        var section = Section(Allowing("S-1-5-32-544", WriteDac));

        section.HighlightRiskyPermissions = true;
        section.HighlightRiskyPermissions = false;

        Assert.Equal(PermissionRisk.None, OnlyRight(section).Mark);
    }

    [Fact]
    public void AMarkedEntryCarriesTheClassifiersReason()
    {
        var section = Section(Allowing("S-1-5-32-544", WriteDac));

        section.HighlightRiskyPermissions = true;

        Assert.Contains(
            "Modify Permissions",
            OnlyRight(section).RiskReason,
            StringComparison.Ordinal);
    }

    /// <summary>
    /// An unmarked row offers no justification for a verdict it is not showing.
    /// </summary>
    [Fact]
    public void AnUnmarkedEntryOffersNoReason()
    {
        var section = Section(Allowing("S-1-5-32-544", WriteDac));

        Assert.Null(OnlyRight(section).RiskReason);
    }

    // ---------------------------------------------------------------------------------------
    // Which verdicts get a mark, and which deliberately do not.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// Marking every examined-and-ordinary entry would put a reassurance on most rows of most
    /// objects, and a screen that reassures a hundred times is one an operator stops reading.
    /// </summary>
    [Fact]
    public void AnOrdinaryEntryIsNotMarkedEvenWhenTheToggleIsOn()
    {
        var section = Section(Allowing("S-1-5-11", ReadProperty));

        section.HighlightRiskyPermissions = true;

        Assert.Equal(PermissionRisk.None, OnlyRight(section).Mark);
    }

    /// <summary>
    /// A component of a takeover is marked, and marked as a component. One entry cannot say what
    /// else its principal holds, so calling it a takeover would claim more than the evidence does.
    /// </summary>
    [Fact]
    public void AReplicationRightIsMarkedAsACombination()
    {
        var section = Section(Scoped("S-1-5-21-1-2-3-1000", ControlAccess, ReplicationGetChanges));

        section.HighlightRiskyPermissions = true;

        Assert.Equal(PermissionRisk.DangerousInCombination, OnlyRight(section).Mark);
    }

    /// <summary>
    /// The screen half of <c>S-57</c> finding <c>#8</c>. The classifier's move of the child bits
    /// is only worth anything if it reaches the mark an operator reads, and nothing covered that
    /// path when the move was made - which is how the "In combination" counter kept an
    /// explanation that named only the per-principal reason.
    /// </summary>
    [Fact]
    public void AChildRightScopedToOneClassIsMarkedAsACombinationOnScreen()
    {
        var section = Section(Scoped("S-1-5-32-548", CreateChild, GroupClass));

        section.HighlightRiskyPermissions = true;

        Assert.Equal(PermissionRisk.DangerousInCombination, OnlyRight(section).Mark);
    }

    /// <summary>
    /// And the contrast that makes the mark mean something: with no class named, the same bit is
    /// a grant over every class the schema permits and stays a takeover.
    /// </summary>
    [Fact]
    public void AnUnscopedChildRightIsStillMarkedAsATakeoverOnScreen()
    {
        var section = Section(Allowing("S-1-5-32-548", CreateChild));

        section.HighlightRiskyPermissions = true;

        Assert.Equal(PermissionRisk.Dangerous, OnlyRight(section).Mark);
    }

    /// <summary>
    /// The counters are what <c>F-S54-2</c> is about: this fix moves entries out of
    /// <c>Dangerous</c>, and the operator must be able to see where they went rather than watch a
    /// number fall. Both counters are on the strip at once, so the movement is legible.
    /// </summary>
    [Fact]
    public void AClassScopedChildRightLeavesTheDangerousCountAndJoinsTheCombinationCount()
    {
        var section = Section(Scoped("S-1-5-32-548", CreateChild, GroupClass));

        section.HighlightRiskyPermissions = true;

        Assert.Equal(0, Counter(section, "Dangerous").Value);
        Assert.Equal(1, Counter(section, "In combination").Value);
    }

    /// <summary>
    /// <c>F-S58-6</c>. The row used to show a mark reading "hands somebody control of this object"
    /// beside a Scope column reading "All descendant objects" - the flags were read for the scope
    /// and never passed to the classifier. Nothing covered the seam, which is how it survived.
    /// </summary>
    [Fact]
    public void AnInheritOnlyEntryDoesNotClaimAGrantOnThisObject()
    {
        var section = Section(InheritOnly("S-1-5-32-548", WriteDac));

        section.HighlightRiskyPermissions = true;

        var right = OnlyRight(section);

        Assert.Equal(PermissionRisk.Dangerous, right.Mark);
        Assert.Contains(
            "grants nothing on this object", right.RiskReason, StringComparison.Ordinal);
    }

    /// <summary>
    /// The same entry without the flag keeps the plain reason, so the correction cannot leak into
    /// the ordinary case.
    /// </summary>
    [Fact]
    public void AnEntryThatGovernsThisObjectSaysSoPlainly()
    {
        var section = Section(Allowing("S-1-5-32-548", WriteDac));

        section.HighlightRiskyPermissions = true;

        Assert.DoesNotContain(
            "inherit-only", OnlyRight(section).RiskReason, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// A denial grants nothing, so it is not marked however alarming its mask looks.
    /// </summary>
    [Fact]
    public void ADenialOfATakeoverMaskIsNotMarked()
    {
        var section = Section(
            Ace(nameof(AceType.AccessDenied), "S-1-5-32-544", WriteDac, objectTypeGuid: null));

        section.HighlightRiskyPermissions = true;

        Assert.Equal(PermissionRisk.None, OnlyRight(section).Mark);
    }

    /// <summary>
    /// An entry type this build does not model is not marked, and - just as importantly - is not
    /// reported as safe anywhere. It simply carries no opinion.
    /// </summary>
    [Fact]
    public void AnUnknownAceTypeIsNotMarked()
    {
        var section = Section(
            Ace("SomethingThisBuildHasNeverHeardOf", "S-1-5-32-544", WriteDac, null));

        section.HighlightRiskyPermissions = true;

        Assert.Equal(PermissionRisk.None, OnlyRight(section).Mark);
    }

    /// <summary>
    /// Marking must never narrow the list. A reader shown only the marked entries would conclude
    /// the marked few are all there is, and the entries this build cannot classify are exactly the
    /// ones that would have been hidden.
    /// </summary>
    [Fact]
    public void TurningTheToggleOnHidesNoEntry()
    {
        var section = Section(
            Allowing("S-1-5-32-544", WriteDac),
            Allowing("S-1-5-11", ReadProperty));

        section.HighlightRiskyPermissions = true;

        Assert.Equal(2, section.Principals.Sum(p => p.Entries.Count));
    }

    [Fact]
    public void TurningTheToggleOnHidesNoPrincipal()
    {
        var section = Section(
            Allowing("S-1-5-32-544", WriteDac),
            Allowing("S-1-5-11", ReadProperty));

        section.HighlightRiskyPermissions = true;

        Assert.Equal(2, section.Principals.Count);
    }

    // ---------------------------------------------------------------------------------------
    // Counters. Nothing renders a zero where nothing has looked.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void TheDangerousCounterIsNotComputedBeforeAnybodyAsks()
    {
        var section = Section(Allowing("S-1-5-32-544", WriteDac));

        Assert.False(Counter(section, "Dangerous").IsComputed);
    }

    /// <summary>
    /// The failure this exists to prevent: of the two ways to read a zero, the wrong one is the
    /// reassuring one, and an auditor who reads <i>Dangerous 0</i> off an unclassified object stops
    /// looking.
    /// </summary>
    [Fact]
    public void TheUncomputedDangerousCounterShowsNoNumber()
    {
        var section = Section(Allowing("S-1-5-32-544", WriteDac));

        Assert.Null(Counter(section, "Dangerous").Value);
    }

    [Fact]
    public void TheUncomputedDangerousCounterDoesNotDisplayAZero()
    {
        var section = Section(Allowing("S-1-5-32-544", WriteDac));

        Assert.NotEqual("0", Counter(section, "Dangerous").Display);
    }

    [Fact]
    public void TheUncomputedDangerousCounterSaysHowToAsk()
    {
        var section = Section(Allowing("S-1-5-32-544", WriteDac));

        Assert.Contains(
            "Highlight risky permissions",
            Counter(section, "Dangerous").Explanation,
            StringComparison.Ordinal);
    }

    [Fact]
    public void TheDangerousCounterCountsOnceTheToggleIsOn()
    {
        var section = Section(
            Allowing("S-1-5-32-544", WriteDac),
            Allowing("S-1-5-11", ReadProperty));

        section.HighlightRiskyPermissions = true;

        Assert.Equal(1, Counter(section, "Dangerous").Value);
    }

    /// <summary>
    /// A genuine zero is only shown once something has looked, and then it is a real answer.
    /// </summary>
    [Fact]
    public void TheDangerousCounterIsZeroWhenSomethingLookedAndFoundNone()
    {
        var section = Section(Allowing("S-1-5-11", ReadProperty));

        section.HighlightRiskyPermissions = true;

        Assert.Equal(0, Counter(section, "Dangerous").Value);
    }

    [Fact]
    public void TheDangerousCounterCountsAcrossEveryPrincipal()
    {
        var section = Section(
            Allowing("S-1-5-32-544", WriteDac),
            Allowing("S-1-5-21-1-2-3-1000", WriteDac));

        section.HighlightRiskyPermissions = true;

        Assert.Equal(2, Counter(section, "Dangerous").Value);
    }

    [Fact]
    public void TheEntryCounterIsComputedWithoutAskingAnything()
    {
        var section = Section(
            Allowing("S-1-5-32-544", WriteDac),
            Allowing("S-1-5-11", ReadProperty));

        Assert.Equal(2, Counter(section, "Entries").Value);
    }

    /// <summary>
    /// <c>Control</c> counted the predecessor's escalation control edges, which are derived across
    /// a forest rather than read off one object. Nothing in this build derives them.
    /// </summary>
    [Fact]
    public void TheControlCounterIsNeverComputedByThisBuild()
    {
        var section = Section(Allowing("S-1-5-32-544", WriteDac));

        section.HighlightRiskyPermissions = true;

        Assert.False(Counter(section, "Control").IsComputed);
    }

    /// <summary>
    /// A finding is a rule's verdict, and no rule has been run. This is not zero findings, and the
    /// counter has to say so rather than print one.
    /// </summary>
    [Fact]
    public void TheFindingsCounterIsNeverComputedByThisBuild()
    {
        var section = Section(Allowing("S-1-5-32-544", WriteDac));

        section.HighlightRiskyPermissions = true;

        Assert.False(Counter(section, "Findings").IsComputed);
    }

    [Fact]
    public void TheFindingsCounterSaysItIsNotZero()
    {
        var section = Section(Allowing("S-1-5-32-544", WriteDac));

        Assert.Contains(
            "not zero findings",
            Counter(section, "Findings").Explanation,
            StringComparison.Ordinal);
    }

    /// <summary>
    /// The strip states what it cannot answer rather than leaving it off. A screen that silently
    /// omits Control and Findings makes the object look fully assessed.
    /// </summary>
    [Fact]
    public void TheStripStatesEveryCounterTheReferenceScreenShowed()
    {
        var section = Section(Allowing("S-1-5-32-544", WriteDac));

        Assert.All(
            new[] { "Entries", "Dangerous", "Control", "Findings" },
            label => Assert.Contains(
                section.Counters,
                c => string.Equals(c.Label, label, StringComparison.Ordinal)));
    }

    // ---------------------------------------------------------------------------------------
    // The forest's own schema reaches the row.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// The defect the owner found on <c>build V</c>: an entry scoped to a class the shipped table
    /// does not list rendered as <c>Create 4828cc14-... objects</c>.
    /// </summary>
    [Fact]
    public void AGuidTheShippedTableDoesNotKnowStillRendersAsAGuid()
    {
        var section = new PermissionsSectionViewModel(
            Definition(),
            Permissions(Scoped("S-1-5-32-548", CreateChild, InetOrgPerson)),
            PermissionVocabulary.Shipped);

        Assert.Contains(InetOrgPerson, OnlyEntry(section).Right, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// And with the forest's own schema behind it, the same entry reads as a name. This is the
    /// whole of what <c>0014</c> asked for and nothing had ever done.
    /// </summary>
    [Fact]
    public void TheSameGuidReadsAsANameWhenTheForestSchemaIsBehindIt()
    {
        var section = new PermissionsSectionViewModel(
            Definition(),
            Permissions(Scoped("S-1-5-32-548", CreateChild, InetOrgPerson)),
            ForestKnowing("inetOrgPerson", InetOrgPerson, SchemaGuidKind.ObjectClass));

        Assert.Contains("inetOrgPerson", OnlyEntry(section).Right, StringComparison.Ordinal);
    }

    [Fact]
    public void AForestExtensionReadsAsANameRatherThanAGuid()
    {
        const string PayrollGuid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";

        var section = new PermissionsSectionViewModel(
            Definition(),
            Permissions(Scoped("S-1-5-21-1-2-3-1000", WriteProperty, PayrollGuid)),
            ForestKnowing("contoso-PayrollId", PayrollGuid, SchemaGuidKind.Attribute));

        Assert.Contains(
            "contoso-PayrollId", OnlyEntry(section).Right, StringComparison.Ordinal);
    }

    // ---------------------------------------------------------------------------------------
    // The mark belongs to the right that earned it.
    //
    // An ACCESS_MASK is a set of bits Windows evaluates independently, and the classifier judges
    // them differently by construction. A row is still one access control entry - that is what the
    // directory holds and what an administrator removes - but one mark on it cannot say which of
    // its rights is the problem.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// The case this exists for. One entry, two rights, and only one of them hands over the
    /// object; before this, both wore the row's single mark.
    /// </summary>
    [Fact]
    public void OnlyTheRightThatEarnedTheMarkWearsIt()
    {
        var section = Section(Allowing("S-1-5-32-544", WriteDac | ReadControl));

        section.HighlightRiskyPermissions = true;

        Assert.Equal(PermissionRisk.Dangerous, Right(section, "Modify permissions").Mark);
        Assert.Equal(PermissionRisk.None, Right(section, "Read permissions").Mark);
    }

    /// <summary>
    /// And the reason travels with the right, because the reader is an administrator deciding
    /// which right to remove.
    /// </summary>
    [Fact]
    public void TheUnmarkedRightOfAMarkedEntryOffersNoReason()
    {
        var section = Section(Allowing("S-1-5-32-544", WriteDac | ReadControl));

        section.HighlightRiskyPermissions = true;

        Assert.NotNull(Right(section, "Modify permissions").RiskReason);
        Assert.Null(Right(section, "Read permissions").RiskReason);
    }

    /// <summary>
    /// The row still carries the classifier's answer about the entry, derived from its rights,
    /// because the counters count entries. It is not computed a second time.
    /// </summary>
    [Fact]
    public void AnEntryIsAsDangerousAsTheWorstThingInIt()
    {
        var section = Section(Allowing("S-1-5-32-544", WriteDac | ReadControl));

        Assert.Equal(PermissionRisk.Dangerous, OnlyEntry(section).Risk);
    }

    /// <summary>
    /// An entry granting nothing dangerous is not made dangerous by having several rights.
    /// </summary>
    [Fact]
    public void AnEntryOfOrdinaryRightsIsNotDangerous()
    {
        var section = Section(Allowing("S-1-5-11", ReadProperty | ReadControl));

        Assert.Equal(PermissionRisk.None, OnlyEntry(section).Risk);
    }

    /// <summary>
    /// <b>A bit this build has no word for is never marked and never reported as safe.</b> Asked
    /// about an unnamed bit with no object type, the classifier's unscoped arm would answer
    /// <see cref="PermissionVerdict.NotDangerous"/> - which would state that access nobody examined
    /// is harmless. The right is shown, and it carries no opinion either way.
    /// </summary>
    [Fact]
    public void ABitThisBuildCannotNameIsShownAndNotMarked()
    {
        var section = Section(Allowing("S-1-5-32-544", WriteDac | UnnamedBit));

        section.HighlightRiskyPermissions = true;

        var unnamed = Right(section, "other rights");
        Assert.Equal(PermissionRisk.None, unnamed.Mark);
        Assert.Equal(PermissionRisk.None, unnamed.Risk);
    }

    /// <summary>
    /// <i>Full control</i> is one grant an administrator removes in one action, so it stays one
    /// right wearing one mark rather than becoming fifteen.
    /// </summary>
    [Fact]
    public void FullControlIsOneMarkedRightAndNotFifteen()
    {
        var section = Section(Allowing("S-1-5-32-544", FullControl));

        section.HighlightRiskyPermissions = true;

        var right = OnlyRight(section);
        Assert.Equal("Full control", right.Name);
        Assert.Equal(PermissionRisk.Dangerous, right.Mark);
    }

    /// <summary>
    /// <b>The guard against the trade this change could have made.</b> The wording decides which
    /// bits the classifier is asked about, and an unnamed right is refused classification. So if
    /// <c>GENERIC_ALL</c> fell through to <i>other rights</i>, the most open entry in a forest
    /// would render as one unclassifiable right and the row would say nothing.
    ///
    /// <para>
    /// It is named instead, and still marked. What changed on 2026-08-19 is that the name now
    /// carries the doubt rather than hiding it. This screen previously translated the shorthand
    /// bit into the rights it stands for and then said plainly <c>Full control</c> - but
    /// [MS-DTYP] 2.4.3 says the access check does not translate a shorthand bit found in a stored
    /// entry, so the product was reporting rights the domain controller may not honour as though
    /// they were ordinary. The danger is still shown; the certainty is not. See
    /// <c>docs/next/S-56</c> R2.
    /// </para>
    /// </summary>
    [Fact]
    public void AnUnexpandedGenericAllIsNamedAndMarkedWithoutClaimingItIsEnforced()
    {
        var section = Section(Allowing("S-1-5-32-544", GenericAll));

        section.HighlightRiskyPermissions = true;

        var right = OnlyRight(section);
        Assert.Equal("Full control (shorthand - may not be enforced)", right.Name);
        Assert.Equal(PermissionRisk.Dangerous, right.Mark);
    }

    /// <summary>
    /// The half the rename could hide: a shorthand entry must not read the same as one that
    /// genuinely carries full control, or the distinction this change exists to draw is invisible.
    /// </summary>
    [Fact]
    public void AShorthandFullControlDoesNotReadTheSameAsARealOne()
    {
        var shorthand = OnlyRight(Section(Allowing("S-1-5-32-544", GenericAll)));
        var real = OnlyRight(Section(Allowing("S-1-5-32-544", FullControl)));

        Assert.NotEqual(real.Name, shorthand.Name);
    }

    /// <summary>
    /// The screen half of <c>S-57</c> finding <c>#6</c>. The classifier keeping the verdict is only
    /// half the answer: the row must not go on saying plainly <i>Allow</i>, which is where an
    /// operator reads that the entry grants.
    /// </summary>
    [Fact]
    public void AConditionalEntryDoesNotReadAsAPlainAllow()
    {
        var section = Section(ConditionallyAllowing("S-1-5-32-544", GenericAll));

        Assert.Equal("Allow (conditional)", OnlyEntry(section).Type);
    }

    /// <summary>
    /// And it keeps its mark. Withdrawing the verdict would take the red off a takeover that
    /// applies to anybody meeting the condition, which is <c>F-S54-2</c>.
    /// </summary>
    [Fact]
    public void AConditionalTakeoverIsStillMarkedOnScreen()
    {
        var section = Section(ConditionallyAllowing("S-1-5-32-544", WriteDac));

        section.HighlightRiskyPermissions = true;

        Assert.Equal(PermissionRisk.Dangerous, OnlyRight(section).Mark);
    }

    /// <summary>
    /// A conditional denial is still a denial. <c>IsDenial</c> compared the whole rendered word
    /// against <c>"Deny"</c>, so qualifying the word would have quietly stopped a denial counting
    /// as one.
    /// </summary>
    [Fact]
    public void AConditionalDenialStillCountsAsADenial()
    {
        var section = Section(ConditionallyDenying("S-1-5-32-544", WriteDac));

        Assert.Equal("Deny (conditional)", OnlyEntry(section).Type);
        Assert.True(OnlyEntry(section).IsDenial);
        Assert.True(section.Principals.Single().HasDenials);
    }

    // ---------------------------------------------------------------------------------------
    // Fixtures.
    // ---------------------------------------------------------------------------------------

    /// <summary>A vocabulary over a forest that defined one thing the shipped table has not.</summary>
    private static PermissionVocabulary ForestKnowing(
        string name, string guid, SchemaGuidKind kind) =>
        new(SchemaGuidCatalog.CapturedOver(
            [new SchemaGuidEntry(guid, name, kind, SchemaGuidSource.Captured)],
            SchemaGuidCatalog.Embedded,
            new Dictionary<string, IReadOnlyList<string>>()));
    private static PermissionEntryViewModel OnlyEntry(PermissionsSectionViewModel section) =>
        section.Principals.SelectMany(p => p.Entries).Single();

    /// <summary>
    /// The one right of the one entry. Most fixtures here set a single mask bit, so the entry has
    /// exactly one right - and the mark lives on the right, not on the row.
    /// </summary>
    private static PermissionRightViewModel OnlyRight(PermissionsSectionViewModel section) =>
        OnlyEntry(section).Rights.Single();

    /// <summary>The right of the only entry whose name starts with the given word.</summary>
    private static PermissionRightViewModel Right(
        PermissionsSectionViewModel section, string startingWith) =>
        OnlyEntry(section).Rights.Single(
            r => r.Name.StartsWith(startingWith, StringComparison.Ordinal));

    private static PermissionCounter Counter(PermissionsSectionViewModel section, string label) =>
        section.Counters.Single(c => string.Equals(c.Label, label, StringComparison.Ordinal));

    private static PermissionsSectionViewModel Section(params PermissionEntry[] entries) =>
        new(Definition(), Permissions(entries), PermissionVocabulary.Shipped);

    private static ObjectSectionDefinition Definition() =>
        ObjectSectionCatalog.For("user")
            .Single(s => string.Equals(
                s.Key, ObjectSectionCatalog.Permissions, StringComparison.Ordinal));

    private static ObjectPermissions Permissions(params PermissionEntry[] entries) => new(
        ObjectDn,
        DescriptorAvailability.Read,
        UnreadableReason: null,
        Owner: null,
        DaclState.Present,
        DaclCompleteness.Complete,
        DaclWasCanonical: true,
        IsDaclProtected: false,
        entries,
        []);

    private static PermissionEntry Allowing(string sid, int mask) =>
        Ace(nameof(AceType.AccessAllowed), sid, mask, null);

    private static PermissionEntry Scoped(string sid, int mask, string objectTypeGuid) =>
        Ace(nameof(AceType.AccessAllowedObject), sid, mask, objectTypeGuid);

    /// <summary>An allow entry whose applicability is decided by a condition.</summary>
    private static PermissionEntry ConditionallyAllowing(string sid, int mask) =>
        Ace(nameof(AceType.AccessAllowedCallback), sid, mask, null);

    /// <summary>A deny entry whose applicability is decided by a condition.</summary>
    private static PermissionEntry ConditionallyDenying(string sid, int mask) =>
        Ace(nameof(AceType.AccessDeniedCallback), sid, mask, null);

    /// <summary>
    /// An entry carrying <c>INHERIT_ONLY_ACE</c> (<c>0x08</c>) alongside the container-inherit bit
    /// that every real inherit-only entry also carries - an entry with neither inherit flag would
    /// govern nothing at all, which does not occur in the lab bundle.
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
