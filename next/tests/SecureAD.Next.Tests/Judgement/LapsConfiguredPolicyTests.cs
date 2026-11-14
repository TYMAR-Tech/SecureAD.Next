using System.Text;
using SecureAD.Evidence;
using SecureAD.Judgement;
using SecureAD.Kernel.GroupPolicy;
using SecureAD.Next.Tests.Evidence;
using Xunit;
using static SecureAD.Next.Tests.Judgement.LapsPrecedenceRun;

namespace SecureAD.Next.Tests.Judgement;

public sealed class LapsConfiguredPolicyTests
{
    [Fact]
    public void LapsPrecedenceEachSettingRetainsItsOwnWinningPolicyAndOriginalInstruction()
    {
        var first = Number("BackupDirectory", 2);
        var encryption = Number("ADPasswordEncryptionEnabled", 1);
        var principal = TextValue(Principal, GroupB);
        var result = Read([new(1, [first, TextValue(Principal, GroupA)]), new(2, [encryption, principal])]);
        var assumptions = Assumptions(result);
        var backup = result.UnderAssumptions(LapsPolicySetting.BackupDirectory, assumptions);
        var group = result.UnderAssumptions(LapsPolicySetting.ADPasswordEncryptionPrincipal, assumptions);
        Assert.Equal(2u, backup.Number);
        Assert.Equal(PolicyGuid(1), backup.Source!.Policy!.ObjectGuid);
        Assert.Equal(GroupB, group.Principal);
        Assert.Equal(PolicyGuid(2), group.Source!.Policy!.ObjectGuid);
        Assert.Equal(principal.Data, group.Source.Instruction!.Data);
        Assert.Equal(1, group.Source.EntryIndex);
        Assert.NotEqual(group.Source.Policy.ObjectGuid!.Value.ToString("B"),
            group.Source.Link.Link.DistinguishedName.Split(',')[0][3..]);
        Assert.True(result.RequestsAdEncryption(assumptions));
        Assert.False(result.RequestsDsrMBackup(assumptions));
        Assert.True(result.HasOpenPolicyScope);
        Assert.All(result.Settings.Values, value => Assert.False(value.IsDefiniteForComputer));
    }

    [Fact]
    public void LapsPrecedenceDocumentedDefaultsAreNotAttributedToAPolicyOrAnotherPolicyRoot()
    {
        var result = Read([new(1, [TextValue(Principal, GroupA, @"Software\Microsoft\Policies\LAPS")])]);
        Assert.True(result.IsGroupPolicyRootOnly);
        Assert.True(result.DefaultsRequireSelectionOfThisPolicyRoot);
        Assert.Equal(0u, result.UnderAssumptions(LapsPolicySetting.BackupDirectory, Empty()).Number);
        Assert.Equal(1u, result.UnderAssumptions(LapsPolicySetting.ADPasswordEncryptionEnabled, Empty()).Number);
        Assert.Equal(0u, result.UnderAssumptions(LapsPolicySetting.ADBackupDSRMPassword, Empty()).Number);
        var group = result.UnderAssumptions(LapsPolicySetting.ADPasswordEncryptionPrincipal, Empty());
        Assert.Equal(LapsConfiguredValueState.DocumentedDefault, group.State);
        Assert.Null(group.Source);
        Assert.Equal("example.test", group.DomainAdmins!.DomainFqdn);
        Assert.Equal("S-1-5-21-1-2-3-512", group.DomainAdmins.Sid);
        Assert.False(result.RequestsAdEncryption(Empty()));
    }

    [Fact]
    public void LapsPrecedenceDomainAdminsDefaultWithoutAReceivingDomainRemainsUnresolved()
    {
        var value = LapsConfiguredPolicyCalculator.Describe(LapsPolicySetting.ADPasswordEncryptionPrincipal,
            new(LapsRegistryState.Untouched, null, null, Previous: null), new(null, null));
        Assert.Equal(LapsConfiguredValueState.Unresolved, value.State);
        Assert.Null(value.DomainAdmins);
        Assert.NotNull(value.Reason);
    }

    [Fact]
    public void LapsPrecedenceDsrMUsesTheReceivingDomainAdminsInsteadOfTheConfiguredCustomPrincipal()
    {
        var result = Read([new(1, []), new(2,
            [Number("BackupDirectory", 2), Number("ADPasswordEncryptionEnabled", 1),
                Number("ADBackupDSRMPassword", 1), TextValue(Principal, GroupB)], ChildDomain: true)]);
        var assumptions = Assumptions(result);
        Assert.Equal(GroupB, result.UnderAssumptions(LapsPolicySetting.ADPasswordEncryptionPrincipal, assumptions).Principal);
        Assert.True(result.RequestsDsrMBackup(assumptions));
        Assert.Equal("example.test", result.DsrMDecryptorWhenApplicable.DomainFqdn);
        Assert.Equal("S-1-5-21-1-2-3-512", result.DsrMDecryptorWhenApplicable.Sid);
        Assert.NotEqual(result.DsrMDecryptorWhenApplicable.Sid, GroupB);
    }

    [Theory]
    [InlineData("**Del.ADPasswordEncryptionPrincipal", " ")]
    [InlineData("**DeleteValues", "ADPasswordEncryptionPrincipal")]
    [InlineData("**DelVals.", " ")]
    [InlineData("**DeleteKeys", "LAPS")]
    public void LapsPrecedenceHigherPolicyDeletionClearsTheLowerValueInsteadOfLettingItWin(string operation, string data)
    {
        var key = operation == "**DeleteKeys" ? @"Software\Microsoft\Windows\CurrentVersion\Policies" : Key;
        var result = Read([new(1, [TextValue(Principal, GroupA)]), new(2, [TextValue(operation, data, key)])]);
        var value = result.UnderAssumptions(LapsPolicySetting.ADPasswordEncryptionPrincipal, Assumptions(result));
        Assert.Equal(LapsConfiguredValueState.DocumentedDefault, value.State);
        Assert.Null(value.Principal);
        Assert.Equal("S-1-5-21-1-2-3-512", value.DomainAdmins!.Sid);
        Assert.Equal(PolicyGuid(2), value.Source!.Policy!.ObjectGuid);
        Assert.Equal(operation, value.Source.Instruction!.ValueName);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void LapsPrecedenceSharedWmiConditionCannotProduceContradictoryPolicyParticipation(bool matches)
    {
        var result = Read([new(1, [TextValue(Principal, GroupA)]), new(2, [TextValue(Principal, GroupB)])]);
        var keys = Conditions(result);
        Assert.Single(keys);
        var value = result.UnderAssumptions(LapsPolicySetting.ADPasswordEncryptionPrincipal,
            keys.ToDictionary(key => key, _ => matches));
        Assert.Equal(matches ? GroupB : null, value.Principal);
        Assert.Equal(matches ? LapsConfiguredValueState.PolicyValue : LapsConfiguredValueState.DocumentedDefault, value.State);
        Assert.Equal(3, result.Settings[LapsPolicySetting.ADPasswordEncryptionPrincipal].DecisionNodeCount);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void LapsPrecedenceMultipleQueryFiltersRemainOneCorrelatedWholeFilterCondition(bool matches)
    {
        var directory = LapsPrecedenceRun.Build(
            [new(1, [TextValue(Principal, GroupA)]), new(2, [TextValue(Principal, GroupB)])],
            filterDefinitions: new Dictionary<int, string> { [1] = GpoWmiFilterTests.MultipleQueryWrapper });
        using var reader = LapsConfiguredPolicyReader.Open(directory, CancellationToken.None).Value;
        var result = reader.Read(reader.Bundle.ReadObjectIdentity(GpoSecurityRun.Computer)!, CancellationToken.None).Value;
        var key = Assert.Single(Conditions(result));
        Assert.All(result.RegistryPolicies, policy =>
        {
            Assert.Equal(2, policy.Applicability.Wmi.Definition.Value.Length);
            Assert.Equal(key, policy.Applicability.Conditional.Wmi!.Condition);
        });
        var value = result.UnderAssumptions(LapsPolicySetting.ADPasswordEncryptionPrincipal,
            new Dictionary<GpoWmiConditionKey, bool> { [key] = matches });
        Assert.Equal(matches ? GroupB : null, value.Principal);
        Assert.Equal(matches ? LapsConfiguredValueState.PolicyValue : LapsConfiguredValueState.DocumentedDefault, value.State);
        Assert.Equal(3, CountDecisionNodes(result.Settings[LapsPolicySetting.ADPasswordEncryptionPrincipal].Decision));
        Assert.True(result.HasOpenPolicyScope);
        Assert.False(result.Settings[LapsPolicySetting.ADPasswordEncryptionPrincipal].IsDefiniteForComputer);
    }

    [Fact]
    public void LapsPrecedenceAnUnsupportedLaterQueryRemainsOpenInfluenceInsteadOfSelectingADecryptor()
    {
        var definition = GpoWmiFilterTests.MultipleQueryWrapper.Replace(";3;10;55;WQL;", ";3;10;55;SQL;", StringComparison.Ordinal);
        var directory = LapsPrecedenceRun.Build([new(1, [TextValue(Principal, GroupB)])],
            filterDefinitions: new Dictionary<int, string> { [1] = definition });
        using var reader = LapsConfiguredPolicyReader.Open(directory, CancellationToken.None).Value;
        var result = reader.Read(reader.Bundle.ReadObjectIdentity(GpoSecurityRun.Computer)!, CancellationToken.None).Value;
        var policy = Assert.Single(result.RegistryPolicies);
        Assert.Null(policy.Applicability.Conditional.Wmi);
        Assert.Contains(policy.Applicability.Limitations, error => error.Code == "Evidence.WmiLanguageUnsupported");
        var value = result.UnderAssumptions(LapsPolicySetting.ADPasswordEncryptionPrincipal, Empty());
        Assert.Equal(LapsConfiguredValueState.Unresolved, value.State);
        Assert.Null(value.Principal);
        Assert.Null(value.DomainAdmins);
        Assert.NotNull(value.Reason);
    }

    [Fact]
    public void LapsPrecedenceDifferentFiltersRetainDifferentPossibleWinnersAndTheirSources()
    {
        var result = Read([new(1, [TextValue(Principal, GroupA)], Filter: 1),
            new(2, [TextValue(Principal, GroupB)], Filter: 2)]);
        var keys = Conditions(result);
        Assert.Equal(2, keys.Length);
        var low = result.RegistryPolicies.Single(policy => policy.Applicability.Policy.ObjectGuid == PolicyGuid(1))
            .Applicability.Conditional.Wmi!.Condition;
        var high = result.RegistryPolicies.Single(policy => policy.Applicability.Policy.ObjectGuid == PolicyGuid(2))
            .Applicability.Conditional.Wmi!.Condition;
        var value = result.UnderAssumptions(LapsPolicySetting.ADPasswordEncryptionPrincipal,
            new Dictionary<GpoWmiConditionKey, bool> { [low] = true, [high] = false });
        Assert.Equal(GroupA, value.Principal);
        Assert.Null(result.Settings[LapsPolicySetting.ADPasswordEncryptionPrincipal].UniformOrderedProjectionValue);
        Assert.Equal(2, result.Settings[LapsPolicySetting.ADPasswordEncryptionPrincipal].PossibleSources.Length);
    }

    [Fact]
    public void LapsPrecedenceInvariantValuesCanAgreeWhileTheirSourcePolicyRemainsConditional()
    {
        var result = Read([new(1, [TextValue(Principal, "S-1-5-21-1-2-3-512")], Filter: 1),
            new(2, [TextValue(Principal, "S-1-5-21-1-2-3-512")], Filter: 2)]);
        var answer = result.Settings[LapsPolicySetting.ADPasswordEncryptionPrincipal];
        Assert.NotNull(answer.UniformOrderedProjectionValue);
        Assert.Equal(2, answer.PossibleSources.Length);
        Assert.False(answer.IsDefiniteForComputer);
        var hierarchy = result.Inputs.Hierarchy with { SiteScopeResolved = true };
        var closed = LapsConfiguredPolicyCalculator.Calculate(result.Inputs with { Hierarchy = hierarchy },
            result.RegistryPolicies.ToDictionary(policy => policy.Applicability.Policy.ObjectId), CancellationToken.None);
        Assert.True(closed.Settings[LapsPolicySetting.ADPasswordEncryptionPrincipal].IsDefiniteForComputer);
    }

    [Theory]
    [InlineData("initial")]
    [InlineData("existing")]
    [InlineData("deleted")]
    public void LapsPrecedenceSoftWritesRespectTheAccumulatedCrossPolicyState(string state)
    {
        RegistryPolicyEntry[] lower = state switch
        {
            "initial" => [],
            "existing" => [TextValue(Principal, GroupA)],
            "deleted" => [TextValue("**Del." + Principal, " ")],
            _ => throw new ArgumentOutOfRangeException(nameof(state)),
        };
        var result = Read([new(1, lower), new(2, [TextValue("**soft." + Principal, GroupB)])]);
        var value = result.UnderAssumptions(LapsPolicySetting.ADPasswordEncryptionPrincipal, Assumptions(result));
        Assert.Equal(state == "initial" ? LapsConfiguredValueState.Unresolved : LapsConfiguredValueState.PolicyValue, value.State);
        Assert.Equal(state == "existing" ? GroupA : state == "deleted" ? GroupB : null, value.Principal);
        if (state == "initial") Assert.Contains("client registry state", value.Reason, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(GpoSettingsOutcome.NotCaptured)]
    [InlineData(GpoSettingsOutcome.Unreadable)]
    [InlineData(GpoSettingsOutcome.PartiallyRead)]
    public void LapsPrecedenceIncompleteHigherPolicyCannotBeTreatedAsAnEmptyOrDefinitePolicy(GpoSettingsOutcome outcome)
    {
        var result = Read([new(1, [TextValue(Principal, GroupA)]),
            new(2, outcome == GpoSettingsOutcome.PartiallyRead ? [TextValue(Principal, GroupB)] : [], Outcome: outcome)]);
        var value = result.UnderAssumptions(LapsPolicySetting.ADPasswordEncryptionPrincipal, Assumptions(result));
        Assert.Equal(LapsConfiguredValueState.Unresolved, value.State);
        Assert.NotNull(value.Reason);
        Assert.Null(result.Settings[LapsPolicySetting.ADPasswordEncryptionPrincipal].UniformOrderedProjectionValue);
        Assert.Contains(result.Limitations, error => error.Code == "Evidence.LapsPolicySettingsIncomplete");
    }

    [Fact]
    public void LapsPrecedenceKnownHigherWriteSurvivesEarlierUnresolvedInputs()
    {
        var result = Read([new(1, [], Outcome: GpoSettingsOutcome.Unreadable),
            new(2, [TextValue(Principal, GroupB)])]);
        Assert.Equal(GroupB, result.UnderAssumptions(LapsPolicySetting.ADPasswordEncryptionPrincipal, Assumptions(result)).Principal);
        Assert.Contains(result.Limitations, error => error.Code == "Evidence.LapsPolicySettingsIncomplete");
    }

    [Fact]
    public void LapsPrecedenceParseErrorsAndUnsupportedInstructionsRemainOpenInfluence()
    {
        var parsed = Read([new(1, [TextValue(Principal, GroupA)]),
            new(2, [TextValue(Principal, GroupB)], ParseErrors: ["Recorded truncated registry file"])]);
        Assert.Equal(LapsConfiguredValueState.Unresolved,
            parsed.UnderAssumptions(LapsPolicySetting.ADPasswordEncryptionPrincipal, Assumptions(parsed)).State);
        var unsupported = Read([new(1, [TextValue(Principal, GroupA)]), new(2, [TextValue("**DelVals", " ")])]);
        Assert.Equal(LapsConfiguredValueState.Unresolved,
            unsupported.UnderAssumptions(LapsPolicySetting.ADPasswordEncryptionPrincipal, Assumptions(unsupported)).State);
    }

    [Theory]
    [InlineData("BackupDirectory", 3u, 0u)]
    [InlineData("ADPasswordEncryptionEnabled", 8u, 1u)]
    [InlineData("ADBackupDSRMPassword", 2u, 0u)]
    public void LapsPrecedenceDocumentedNumericFallbackRetainsTheUnsupportedSource(string name, uint raw, uint expected)
    {
        var result = Read([new(1, [Number(name, raw)])]);
        var answer = result.UnderAssumptions(Enum.Parse<LapsPolicySetting>(name), Assumptions(result));
        Assert.Equal(LapsConfiguredValueState.DocumentedDefault, answer.State);
        Assert.Equal(expected, answer.Number);
        Assert.NotNull(answer.Source);
        Assert.NotNull(answer.Reason);
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("unqualified")]
    public void LapsPrecedenceAnExplicitInvalidPrincipalNeverBecomesDomainAdmins(string text)
    {
        var result = Read([new(1, [TextValue(Principal, text)])]);
        var answer = result.UnderAssumptions(LapsPolicySetting.ADPasswordEncryptionPrincipal, Assumptions(result));
        Assert.Equal(LapsConfiguredValueState.Unresolved, answer.State);
        Assert.Null(answer.DomainAdmins);
        Assert.NotNull(answer.Source);
    }

    [Theory]
    [InlineData("BackupDirectory")]
    [InlineData("ADPasswordEncryptionEnabled")]
    [InlineData("ADBackupDSRMPassword")]
    public void LapsPrecedenceUnqualifiedNumericTypesRemainUnresolvedInsteadOfDefaulted(string name)
    {
        var result = Read([new(1, [TextValue(name, "1")])]);
        Assert.Equal(LapsConfiguredValueState.Unresolved,
            result.UnderAssumptions(Enum.Parse<LapsPolicySetting>(name), Assumptions(result)).State);
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("malformed")]
    [InlineData("non-registry")]
    public void LapsPrecedenceMachineExtensionEvidenceIsNotInferredFromARegistryFile(string declaration)
    {
        var raw = declaration switch
        {
            "missing" => "",
            "malformed" => RegistryCse + "unparsed",
            "non-registry" => "[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{00000000-0000-0000-0000-000000000001}]",
            _ => throw new ArgumentOutOfRangeException(nameof(declaration)),
        };
        var result = Read([new(1, [TextValue(Principal, GroupA)], Extensions: raw)]);
        var answer = result.UnderAssumptions(LapsPolicySetting.ADPasswordEncryptionPrincipal, Assumptions(result));
        Assert.Equal(declaration == "non-registry" ? LapsConfiguredValueState.DocumentedDefault
            : LapsConfiguredValueState.Unresolved, answer.State);
        if (declaration != "non-registry")
            Assert.Contains(result.Limitations, error => error.Code == "Evidence.LapsRegistryExtensionUnresolved");
    }

    [Theory]
    [InlineData("unclosed")]
    [InlineData("tool-only")]
    [InlineData("out-of-order")]
    public void LapsPrecedenceIncompleteOrOutOfOrderExtensionDeclarationsCannotGrantOrExcludeRegistryProcessing(string shape)
    {
        var raw = shape switch
        {
            "unclosed" => RegistryCse[..^1],
            "tool-only" => "[" + SecureAD.Kernel.GroupPolicy.GpoClientSideExtensionCatalog.RegistryCse.ToString("B") + "]",
            "out-of-order" => "[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{00000000-0000-0000-0000-000000000001}]" + RegistryCse,
            _ => throw new ArgumentOutOfRangeException(nameof(shape)),
        };
        var result = Read([new(1, [TextValue(Principal, GroupA)], Extensions: raw)]);
        Assert.Equal(LapsConfiguredValueState.Unresolved,
            result.UnderAssumptions(LapsPolicySetting.ADPasswordEncryptionPrincipal, Assumptions(result)).State);
        Assert.Equal(GpoApplicabilityState.Unknown, Assert.Single(result.RegistryPolicies).RegistryExtension);
    }

    [Fact]
    public void LapsPrecedenceExcludedHigherPolicyDoesNotSuppressAnEstablishedLowerSetting()
    {
        var result = Read([new(1, [TextValue(Principal, GroupA)]), new(2, [TextValue(Principal, GroupB)], Flags: "2")]);
        Assert.Equal(GroupA, result.UnderAssumptions(LapsPolicySetting.ADPasswordEncryptionPrincipal, Assumptions(result)).Principal);
    }

    [Fact]
    public void LapsPrecedenceEnforcedLinkUsesTheQualifiedProcessingOrderRatherThanPolicyEnumeration()
    {
        var result = Read([new(1, [TextValue(Principal, GroupA)], LinkOptions: "2"),
            new(2, [TextValue(Principal, GroupB)])]);
        var answer = result.UnderAssumptions(LapsPolicySetting.ADPasswordEncryptionPrincipal, Assumptions(result));
        Assert.Equal(GroupA, answer.Principal);
        Assert.True(answer.Source!.Link.Enforced);
    }

    [Fact]
    public void LapsPrecedenceRepeatedLinksRetainEveryOccurrenceAndTheLastActualInstructionSource()
    {
        Policy[] policies = [new(1, [TextValue(Principal, GroupA)]), new(2, [TextValue(Principal, GroupB)])];
        var links = "[LDAP://" + PolicyDn(policies[0]) + ";0][LDAP://" + PolicyDn(policies[1])
            + ";0][LDAP://" + PolicyDn(policies[0]) + ";0]";
        using var reader = LapsConfiguredPolicyReader.Open(LapsPrecedenceRun.Build(policies, links), CancellationToken.None).Value;
        var result = reader.Read(reader.Bundle.ReadObjectIdentity(GpoSecurityRun.Computer)!, CancellationToken.None).Value;
        var answer = result.UnderAssumptions(LapsPolicySetting.ADPasswordEncryptionPrincipal, Assumptions(result));
        Assert.Equal(3, result.Inputs.Hierarchy.Links.Length);
        Assert.Equal(2, result.RegistryPolicies.Length);
        Assert.Equal(GroupA, answer.Principal);
        Assert.Equal(3, answer.Source!.Link.DomainOuProcessingOrder);
        Assert.Equal(1, answer.Source.Link.Link.Order);
    }

    [Theory]
    [InlineData(0u, 1u)]
    [InlineData(1u, 1u)]
    [InlineData(2u, 0u)]
    public void LapsPrecedenceBackupAndEncryptionGovernWhetherRecoveryBackupIsRequested(uint backup, uint encryption)
    {
        var result = Read([new(1, [Number("BackupDirectory", backup),
            Number("ADPasswordEncryptionEnabled", encryption), Number("ADBackupDSRMPassword", 1)])]);
        Assert.False(result.RequestsAdEncryption(Assumptions(result)));
        Assert.False(result.RequestsDsrMBackup(Assumptions(result)));
    }

    [Fact]
    public void LapsPrecedenceMissingFilterEvidenceIsNotAQualifiedUnfilteredPolicy()
    {
        var result = Read([new(1, [TextValue(Principal, GroupA)]),
            new(2, [TextValue(Principal, GroupB)], NoFilterReference: true)]);
        var answer = result.UnderAssumptions(LapsPolicySetting.ADPasswordEncryptionPrincipal, Assumptions(result));
        Assert.Equal(LapsConfiguredValueState.Unresolved, answer.State);
        Assert.Contains("WMI", answer.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void LapsPrecedenceForeignCaptureCancellationAndDisposedReadersAreRefused()
    {
        Policy[] policies = [new(1, [TextValue(Principal, GroupA)])];
        using var reader = LapsConfiguredPolicyReader.Open(LapsPrecedenceRun.Build(policies), CancellationToken.None).Value;
        using var foreign = LapsConfiguredPolicyReader.Open(LapsPrecedenceRun.Build(policies), CancellationToken.None).Value;
        var selected = reader.Bundle.ReadObjectIdentity(GpoSecurityRun.Computer)!;
        Assert.Throws<InvalidDataException>(() => foreign.Read(selected, CancellationToken.None));
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();
        Assert.Throws<OperationCanceledException>(() => reader.Read(selected, cancelled.Token));
        Assert.True(reader.Read(selected, CancellationToken.None).IsSuccess);
        reader.Dispose();
        Assert.Throws<ObjectDisposedException>(() => reader.Read(selected, CancellationToken.None));
    }

    [Fact]
    public void LapsPrecedenceSourceSelectionsAndMissingAssumptionsAreExplicitRefusals()
    {
        var first = Read([new(1, [TextValue(Principal, GroupA)])]);
        var second = Read([new(1, [TextValue(Principal, GroupB)])]);
        Assert.Throws<InvalidDataException>(() => first.UnderAssumptions(LapsPolicySetting.ADPasswordEncryptionPrincipal, Empty()));
        var foreign = Assumptions(first);
        foreach (var (key, value) in Assumptions(second)) foreign.Add(key, value);
        Assert.Throws<InvalidDataException>(() => first.UnderAssumptions(LapsPolicySetting.ADPasswordEncryptionPrincipal, foreign));
        var wrong = first.RegistryPolicies.ToDictionary(policy => policy.Applicability.Policy.ObjectId + 1);
        Assert.Throws<InvalidDataException>(() => LapsConfiguredPolicyCalculator.Calculate(first.Inputs, wrong, CancellationToken.None));
    }

    [Fact]
    public void LapsPrecedenceManyIndependentFiltersProduceASharedLinearDecisionShapeNotEveryCombination()
    {
        var policies = Enumerable.Range(1, 40).Select(id => new Policy(id,
            [TextValue(Principal, "S-1-5-21-1-2-3-" + (1200 + id))], Filter: id)).ToArray();
        var directory = LapsPrecedenceRun.Build(policies);
        using var reader = GpoComputerApplicabilityReader.Open(directory, CancellationToken.None).Value;
        var inputs = reader.ReadComputer(reader.Bundle.ReadObjectIdentity(GpoSecurityRun.Computer)!, CancellationToken.None).Value;
        var registry = inputs.Policies.ToDictionary(policy => policy.Policy.ObjectId, policy =>
        {
            var extensions = reader.Bundle.ReadObjectAttributesAt(policy.Policy, ["gPCMachineExtensionNames"]).Snapshot();
            var settings = reader.Bundle.ReadGpoMachineRegistrySettings(policy.Policy.ObjectGuid!.Value);
            return new LapsRegistryPolicyInput(policy, LapsConfiguredPolicyReader.RegistryExtension(extensions),
                extensions, settings, null)
            {
                Instructions = RegistryPolicyInterpreter.ReadInstructions(settings.Settings).Instructions,
            };
        });
        var result = LapsConfiguredPolicyCalculator.Calculate(inputs, registry, CancellationToken.None);
        Assert.Equal(40, Conditions(result).Length);
        Assert.Equal(81, result.Settings[LapsPolicySetting.ADPasswordEncryptionPrincipal].DecisionNodeCount);
        Assert.Equal(81, CountDecisionNodes(result.Settings[LapsPolicySetting.ADPasswordEncryptionPrincipal].Decision));
        Assert.Equal("S-1-5-21-1-2-3-1240",
            result.UnderAssumptions(LapsPolicySetting.ADPasswordEncryptionPrincipal, Assumptions(result)).Principal);
    }

    private static LapsConfiguredPolicy Read(IReadOnlyList<Policy> policies)
    {
        using var reader = LapsConfiguredPolicyReader.Open(LapsPrecedenceRun.Build(policies), CancellationToken.None).Value;
        return reader.Read(reader.Bundle.ReadObjectIdentity(GpoSecurityRun.Computer)!, CancellationToken.None).Value;
    }
    private static GpoWmiConditionKey[] Conditions(LapsConfiguredPolicy result) =>
        result.RegistryPolicies.Where(policy => policy.Applicability.Conditional.Wmi is not null)
            .Select(policy => policy.Applicability.Conditional.Wmi!.Condition).Distinct().ToArray();
    private static Dictionary<GpoWmiConditionKey, bool> Assumptions(LapsConfiguredPolicy result) =>
        Conditions(result).ToDictionary(key => key, _ => true);
    private static Dictionary<GpoWmiConditionKey, bool> Empty() => [];
    private static int CountDecisionNodes(LapsSettingDecision root)
    {
        var found = new HashSet<LapsSettingDecision>(ReferenceEqualityComparer.Instance);
        var pending = new Stack<LapsSettingDecision>();
        pending.Push(root);
        while (pending.TryPop(out var node))
        {
            if (!found.Add(node)) continue;
            if (node is LapsSettingBranch branch)
            {
                pending.Push(branch.WhenMatches);
                pending.Push(branch.WhenDoesNotMatch);
            }
        }
        return found.Count;
    }
}
