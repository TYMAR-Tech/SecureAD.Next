using SecureAD.Evidence;
using SecureAD.Judgement;
using SecureAD.Kernel.Security;
using Xunit;
using static SecureAD.Next.Tests.Judgement.ControlEdgeDeriverTests;

namespace SecureAD.Next.Tests.Judgement;

public sealed class OwnerRightsReadingTests
{
    [Theory]
    [InlineData(0, ControlEvaluationState.NotEstablished)]
    [InlineData(0x10, ControlEvaluationState.NotEstablished)]
    [InlineData(0x40000, ControlEvaluationState.Established)]
    public void OwnerRightsGrantIsEvaluatedRatherThanTreatedAsABooleanBlock(int mask, ControlEvaluationState expected)
        => Assert.Equal(expected, Check(Permissions(Ace(0, "S-1-3-4", mask))).State);

    [Theory]
    [InlineData("AccessAllowed", "AccessDenied", ControlEvaluationState.Established)]
    [InlineData("AccessDenied", "AccessAllowed", ControlEvaluationState.NotEstablished)]
    public void OwnerRightsPreserveTheOriginalOrder(string first, string second, ControlEvaluationState expected)
        => Assert.Equal(expected, Check(Permissions(Ace(0, "S-1-3-4", 0x40000, first), Ace(1, "S-1-3-4", 0x40000, second))).State);

    [Fact]
    public void InheritOnlyOwnerRightsDoNotBlockTheContainer()
        => Assert.Equal(ControlEvaluationState.Established, Check(Permissions(Ace(0, "S-1-3-4", 0, propagation: 8))).State);

    [Fact]
    public void IndependentPermissionDoesNotRequireServerBehavior()
        => Assert.Equal(ControlEvaluationState.Established, Check(Permissions(Ace(0, Holder, 0x40000)), computer: ControlEvaluationState.Established).State);

    [Fact]
    public void EarlierOwnerRightsDenialAppliesToTheIndependentOwnerGrant()
        => Assert.Equal(ControlEvaluationState.NotEstablished, Check(Permissions(Ace(0, "S-1-3-4", 0x40000, "AccessDenied"), Ace(1, Holder, 0x40000))).State);

    [Theory]
    [InlineData('0')]
    [InlineData('1')]
    [InlineData('2')]
    [InlineData('3')]
    [InlineData('x')]
    public void AHeuristicDoesNotInventAServerBaseline(char value)
        => Assert.Equal(ControlEvaluationState.Unknown, Check(Permissions(), ControlEvaluationState.Established, value).State);

    [Theory]
    [InlineData('0', ControlEvaluationState.Established)]
    [InlineData('1', ControlEvaluationState.NotEstablished)]
    [InlineData('2', ControlEvaluationState.Established)]
    [InlineData('x', ControlEvaluationState.NotEstablished)]
    public void RecordedClassicBehaviorUsesTheDocumentedNumericFallback(char value, ControlEvaluationState expected)
        => Assert.Equal(expected, Check(Permissions(), ControlEvaluationState.Established, value, OwnerServerBehavior.ClassicUpdated).State);

    [Fact]
    public void ExemptionAndOwnerAcceptanceAreNotInterchangeable()
        => Assert.Equal(ControlEvaluationState.Unknown, OwnerRightsReading.Check(Permissions(), Ace(0, Holder, 0).Trustee, null,
            ControlEvaluationState.Established, Setting('1'), ControlEvaluationState.Unknown, OwnerServerBehavior.ClassicUpdated).State);

    [Fact]
    public void AProvenRequesterExemptionSurvivesTheComputerBlock()
        => Assert.Equal(ControlEvaluationState.Established, OwnerRightsReading.Check(Permissions(), Ace(0, Holder, 0).Trustee, null,
            ControlEvaluationState.Established, Setting('1'), ControlEvaluationState.Established, OwnerServerBehavior.ClassicUpdated).State);

    [Fact]
    public void UnsupportedModificationRulesAreNotAClaimOfSafety()
        => Assert.Equal(ControlEvaluationState.Unknown, Check(Permissions(), ControlEvaluationState.Established, '0', OwnerServerBehavior.ModificationRestricted).State);

    [Fact]
    public void UnparsedEntriesCannotProveOwnerRightsAbsence()
        => Assert.Equal(ControlEvaluationState.Unknown, Check(Permissions() with { DaclCompleteness = DaclCompleteness.Unknown }).State);

    [Fact]
    public void MissingClassCannotBeTreatedAsANonComputer()
        => Assert.Equal(ControlEvaluationState.Unknown, Check(Permissions(), ControlEvaluationState.Unknown).State);

    [Fact]
    public void AScopedOwnerRightsEntryCannotAnswerAWholeObjectQuestion()
        => Assert.Equal(ControlEvaluationState.Unknown, Check(Permissions(Ace(0, "S-1-3-4", 0x40000) with { HasObjectType = true, ObjectTypeGuid = Guid.Empty.ToString() })).State);

    [Fact]
    public void ACompleteEmptyDaclDoesNotRemoveTheOwnersImplicitRight()
        => Assert.Equal(ControlEvaluationState.Established, Check(Permissions()).State);

    [Theory]
    [InlineData(false, ControlEvaluationState.Established)]
    [InlineData(true, ControlEvaluationState.Unknown)]
    public void UnsupportedOwnerRightsOnlyLimitTheCheckBeforeItsTerminalGrant(bool unsupportedFirst, ControlEvaluationState expected)
    {
        var grant = Ace(1, "S-1-3-4", 0x40000);
        var callback = Ace(0, "S-1-3-4", 0x40000, "AccessDeniedCallback");
        Assert.Equal(expected, Check(Permissions(unsupportedFirst ? [callback, grant] : [grant, callback])).State);
    }

    [Fact]
    public void AnUnknownCrossTrusteeDenyCannotBeIgnoredBeforeTheOwnerGrant()
        => Assert.Equal(ControlEvaluationState.Unknown, Check(Permissions(Ace(0, "S-1-5-21-1-2-3-1500", 0x40000, "AccessDenied"),
            Ace(1, "S-1-3-4", 0x40000))).State);

    private static (ControlEvaluationState State, ControlUncertainty Uncertainty, IReadOnlyList<ControlPrecondition> Checks) Check(
        ObjectPermissions permissions, ControlEvaluationState computer = ControlEvaluationState.NotEstablished,
        char value = '0', OwnerServerBehavior behavior = OwnerServerBehavior.NotRecorded)
        => OwnerRightsReading.Check(permissions, Ace(0, Holder, 0).Trustee, null, computer, Setting(value), ControlEvaluationState.NotEstablished, behavior);

    private static OwnerImplicitRightsSetting Setting(char value)
        => DirectoryHeuristics.OwnerImplicitRights(new string('0', 9) + "1" + new string('0', 9) + "2" + new string('0', 8) + value);
}
