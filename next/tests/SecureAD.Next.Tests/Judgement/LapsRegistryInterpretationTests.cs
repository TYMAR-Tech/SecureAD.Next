using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using SecureAD.Kernel.GroupPolicy;
using SecureAD.Shell.Services;
using Xunit;
using static SecureAD.Next.Tests.Kernel.GroupPolicy.RegistryPolicyInterpreterTests;

namespace SecureAD.Next.Tests.Judgement;

public sealed class LapsRegistryInterpretationTests
{
    private const string Key = @"Software\Microsoft\Windows\CurrentVersion\Policies\LAPS";
    private const string Name = "ADPasswordEncryptionPrincipal";
    private const string Broad = "S-1-5-21-1-2-3-513";

    [Theory]
    [InlineData(@"Wrong\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS")]
    [InlineData(@"HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS")]
    [InlineData(@"Microsoft\Windows\CurrentVersion\Policies\LAPS")]
    [InlineData(@"Software\Microsoft\Windows\CurrentVersion\Policies\LAPS\Child")]
    [InlineData(@"Software\Microsoft\Windows\CurrentVersion\Policies\LAPSOther")]
    public void LapsRegistryOnlyTheExactHiveRelativeGroupPolicyRootCanConfigureTheFinding(string path)
    {
        var result = Judge([Entry(path, Name, Broad)]);
        Assert.True(result.IsComplete);
        Assert.Empty(result.Findings);
    }

    [Theory]
    [InlineData("blank")]
    [InlineData("space")]
    [InlineData("wrong-type")]
    [InlineData("unterminated")]
    public void LapsRegistryAnUnusableReplacementDoesNotResurrectAnEarlierBroadValueOrClaimTheDefault(string replacement)
    {
        var last = replacement switch
        {
            "blank" => Entry(Key, Name, ""),
            "space" => Entry(Key, Name, " "),
            "wrong-type" => new RegistryPolicyEntry(Key, Name, (uint)RegistryValueType.Dword, [1, 0, 0, 0]),
            "unterminated" => new(Key, Name, 1, System.Text.Encoding.Unicode.GetBytes(Broad)),
            _ => throw new ArgumentOutOfRangeException(nameof(replacement)),
        };
        var result = Judge([Entry(Key, Name, Broad), last]);
        Assert.False(result.IsComplete);
        Assert.Empty(result.Findings);
        Assert.Contains(result.InputIssues, issue => issue.Attribute == Name && issue.Kind == CapturedInputIssueKind.UnusableValue);
    }

    [Theory]
    [InlineData("**Del.ADPasswordEncryptionPrincipal", " ")]
    [InlineData("**DeleteValues", "ADPasswordEncryptionPrincipal")]
    [InlineData("**DelVals.", " ")]
    [InlineData("**DeleteKeys", "LAPS")]
    public void LapsRegistryDocumentedDeletesRetireTheEarlierPerPolicyFinding(string name, string data)
    {
        var path = name == "**DeleteKeys" ? @"Software\Microsoft\Windows\CurrentVersion\Policies" : Key;
        var result = Judge([Entry(Key, Name, Broad), Entry(path, name, data)]);
        Assert.True(result.IsComplete);
        Assert.Empty(result.Findings);
    }

    [Theory]
    [InlineData("capture")]
    [InlineData("parse")]
    [InlineData("operation")]
    public void LapsRegistryPartialPositivesKeepTheIndependentInputLimitAndApprovedCaution(string incomplete)
    {
        RegistryPolicyEntry[] entries = incomplete == "operation"
            ? [Entry(Key, Name, Broad), Entry(Key, "**DelVals", " ")] : [Entry(Key, Name, Broad)];
        var outcome = incomplete == "capture" ? GpoSettingsOutcome.PartiallyRead : GpoSettingsOutcome.Read;
        var result = Judge(entries, outcome, incomplete == "parse" ? ["Recorded Machine policy parse failure"] : []);
        var finding = Assert.Single(result.Findings);
        var evidence = Assert.IsType<LapsDecryptorEvidence>(finding.Evidence);
        Assert.False(result.IsComplete);
        Assert.True(evidence.ExpansionWasComplete);
        Assert.False(evidence.IsComplete);
        Assert.Equal(incomplete != "capture", evidence.Settings.CaptureWasComplete);
        Assert.Equal(incomplete == "capture", evidence.Settings.InterpretationWasComplete);
        Assert.Contains("A broad LAPS decryptor value was found in the readable policy settings.", finding.Detail, StringComparison.Ordinal);
        Assert.Contains(LapsPolicySettingsEvidence.IncompleteConfigurationText, finding.Detail, StringComparison.Ordinal);
        Assert.DoesNotContain("every machine the policy covers", finding.Detail, StringComparison.Ordinal);
        Assert.DoesNotContain("membership walk did not finish", finding.Detail, StringComparison.Ordinal);
        Assert.Equal(Broad, evidence.Settings.Value.Source.AsString());
        Assert.Equal(Broad, evidence.ConfiguredValue);
    }

    [Fact]
    public void LapsRegistryMembershipLimitsDoNotBecomeCaptureOrParseLimits()
    {
        var result = Judge([Entry(Key, Name, Broad)], membershipComplete: false);
        var evidence = Assert.IsType<LapsDecryptorEvidence>(Assert.Single(result.Findings).Evidence);
        Assert.True(evidence.Settings.IsComplete);
        Assert.False(evidence.ExpansionWasComplete);
        Assert.False(evidence.IsComplete);
        Assert.False(result.IsComplete);
        Assert.Contains(result.Unresolved, input => input.Reason == UnresolvedReason.MembershipIncomplete);
    }

    [Fact]
    public void LapsRegistryCompleteInputsKeepExistingPresentationAndExactOriginalValue()
    {
        var source = Entry(Key.ToUpperInvariant(), Name.ToUpperInvariant(), Broad);
        var result = Judge([source]);
        var finding = Assert.Single(result.Findings);
        var evidence = Assert.IsType<LapsDecryptorEvidence>(finding.Evidence);
        Assert.True(result.IsComplete);
        Assert.True(evidence.IsComplete);
        Assert.Same(source, evidence.Settings.Value.Source);
        Assert.Equal(2, finding.RuleVersion);
        Assert.Contains("The policy sets ADPasswordEncryptionPrincipal", finding.Detail, StringComparison.Ordinal);
        Assert.DoesNotContain("cannot confirm the final", finding.Detail, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("IncompleteValue")]
    [InlineData("UnusableValue")]
    [InlineData("UnsupportedRepresentation")]
    public void LapsRegistryInputReasonsUseTheApprovedPolicyCautionRatherThanAnExpiryMessage(string kind)
    {
        Assert.Equal(LapsPolicySettingsEvidence.IncompleteConfigurationText,
            UnresolvedWording.For("CapturedInput.ADPasswordEncryptionPrincipal." + kind));
    }

    internal static RuleVerdict Judge(IReadOnlyList<RegistryPolicyEntry> entries,
        GpoSettingsOutcome outcome = GpoSettingsOutcome.Read, IReadOnlyList<string>? parseErrors = null,
        bool membershipComplete = true)
    {
        var context = LapsDecryptorBroadPrincipalTests.Context(entries,
            (sid, _) => new PrincipalExpansion(sid,
                membershipComplete ? PrincipalExpansionOutcome.Expanded : PrincipalExpansionOutcome.PrincipalNotFound, []),
            outcome);
        context = context with
        {
            GpoMachineRegistrySettings = _ => new(entries, outcome,
                outcome == GpoSettingsOutcome.Read ? null : "Recorded incomplete SYSVOL settings.")
                { ParseErrors = parseErrors ?? [] },
        };
        return new LapsDecryptorBroadPrincipal().Judge(LapsDecryptorBroadPrincipalTests.Policy(), context);
    }
}
