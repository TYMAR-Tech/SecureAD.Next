using System.Globalization;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Kernel.Capture;
using SecureAD.Shell.Services;
using SecureAD.Shell.ViewModels;
using Xunit;

namespace SecureAD.Next.Tests.Judgement;

public sealed class LapsTimestampQualityTests
{
    internal static readonly DateTimeOffset AsOf = new(2026, 9, 4, 12, 0, 0, TimeSpan.Zero);
    internal static readonly string Future = AsOf.AddDays(7).ToFileTime().ToString(CultureInfo.InvariantCulture);
    internal static readonly string Past = AsOf.AddDays(-3).ToFileTime().ToString(CultureInfo.InvariantCulture);
    private static readonly string AtGrace = AsOf.AddHours(-24).ToFileTime().ToString(CultureInfo.InvariantCulture);
    private static readonly string BeyondGrace = AsOf.AddHours(-24).AddMinutes(-1).ToFileTime().ToString(CultureInfo.InvariantCulture);

    [Theory]
    [InlineData(null, LapsTimestampReading.Absent)]
    [InlineData("", LapsTimestampReading.Unreadable)]
    [InlineData(" ", LapsTimestampReading.Unreadable)]
    [InlineData("0", LapsTimestampReading.Zero)]
    [InlineData("000", LapsTimestampReading.Zero)]
    [InlineData(" +0 ", LapsTimestampReading.Zero)]
    [InlineData("-1", LapsTimestampReading.Unreadable)]
    [InlineData("not-a-filetime", LapsTimestampReading.Unreadable)]
    [InlineData("9223372036854775807", LapsTimestampReading.Unreadable)]
    [InlineData("9223372036854775808", LapsTimestampReading.Unreadable)]
    public void Scout14CapturedQualityDoesNotBecomeAnEpochDate(string? raw, LapsTimestampReading expected)
    {
        var value = LapsTimestamp.Of(raw);
        Assert.Equal(raw, value.Raw);
        Assert.Equal(expected, value.Reading);
        Assert.Equal(raw is not null, value.HasCapturedValue);
        Assert.Null(value.ExpiresUtc);
    }

    [Fact]
    public void Scout14AUsableValueRetainsItsUtcInstantAndOriginalText()
    {
        var value = LapsTimestamp.Of(Future);
        Assert.Equal(Future, value.Raw);
        Assert.Equal(LapsTimestampReading.Present, value.Reading);
        Assert.Equal(AsOf.AddDays(7), value.ExpiresUtc);
        Assert.Equal(TimeSpan.Zero, value.ExpiresUtc!.Value.Offset);
        Assert.True(value.HasCapturedValue);
    }

    public static IEnumerable<object?[]> RuleCases()
    {
        (string Name, string? Modern, string? Legacy, int F91, bool C91, int F92, bool C92, int F94, bool C94)[] rows =
        [
            ("no-values", null, null, 1, true, 0, true, 0, true),
            ("modern-bad", "not-a-filetime", null, 0, false, 0, false, 0, true),
            ("legacy-bad", null, "not-a-filetime", 0, false, 0, false, 0, false),
            ("modern-zero", "0", null, 0, false, 0, false, 0, true),
            ("legacy-zero", null, "0", 0, false, 0, false, 0, false),
            ("both-zero", "0", "0", 0, false, 0, false, 0, false),
            ("modern-empty", "", null, 0, false, 0, false, 0, true),
            ("modern-blank", " ", null, 0, false, 0, false, 0, true),
            ("modern-negative", "-1", null, 0, false, 0, false, 0, true),
            ("modern-overflow", "9223372036854775807", null, 0, false, 0, false, 0, true),
            ("modern-future", Future, null, 0, true, 0, true, 0, true),
            ("legacy-future", null, Future, 0, true, 0, true, 1, true),
            ("both-future", Future, Future, 0, true, 0, true, 0, true),
            ("modern-past", Past, null, 0, true, 1, true, 0, true),
            ("legacy-past", null, Past, 0, true, 1, true, 1, true),
            ("both-past", Past, Past, 0, true, 1, true, 0, true),
            ("modern-past-legacy-bad", Past, "not-a-filetime", 0, true, 0, false, 0, true),
            ("modern-bad-legacy-past", "not-a-filetime", Past, 0, true, 0, false, 0, false),
            ("modern-zero-legacy-future", "0", Future, 0, true, 0, true, 0, false),
            ("modern-future-legacy-bad", Future, "not-a-filetime", 0, true, 0, true, 0, true),
            ("at-grace", AtGrace, null, 0, true, 0, true, 0, true),
            ("beyond-grace", BeyondGrace, null, 0, true, 1, true, 0, true),
        ];
        foreach (var row in rows)
        {
            yield return [row.Name, "SEC-091", row.Modern, row.Legacy, row.F91, row.C91];
            yield return [row.Name, "SEC-092", row.Modern, row.Legacy, row.F92, row.C92];
            yield return [row.Name, "SEC-094", row.Modern, row.Legacy, row.F94, row.C94];
        }
    }

    [Theory]
    [MemberData(nameof(RuleCases))]
    public void Scout14TheSelectedRuleKeepsIndependentAnswersAndExplicitQualityLimits(string name, string ruleId,
        string? modern, string? legacy, int findings, bool complete)
    {
        Assert.NotEmpty(name);
        var verdict = Rule(ruleId).Judge(Subject(modern, legacy), Context());
        Assert.Equal(findings, verdict.Findings.Count);
        Assert.Equal(complete, verdict.IsComplete);
        Assert.Empty(verdict.InputsNotCaptured);
        Assert.Empty(verdict.Unresolved);
        if (complete) Assert.Empty(verdict.InputIssues);
        else
        {
            Assert.NotEmpty(verdict.InputIssues);
            Assert.All(verdict.InputIssues, issue => Assert.StartsWith(CapturedInputIssue.TokenPrefix, issue.Token));
        }
    }

    [Theory]
    [InlineData("SEC-091", "binary")]
    [InlineData("SEC-091", "multiple")]
    [InlineData("SEC-091", "ordinal")]
    [InlineData("SEC-091", "dual")]
    [InlineData("SEC-092", "binary")]
    [InlineData("SEC-092", "multiple")]
    [InlineData("SEC-092", "ordinal")]
    [InlineData("SEC-092", "dual")]
    [InlineData("SEC-094", "binary")]
    [InlineData("SEC-094", "multiple")]
    [InlineData("SEC-094", "ordinal")]
    [InlineData("SEC-094", "dual")]
    public void Scout14UnsupportedCapturedRepresentationsAreNotMissingValues(string ruleId, string representation)
    {
        var subject = Subject(null, ruleId == "SEC-091" ? null : ruleId == "SEC-092" ? Past : Future);
        AttributeValue[] values = representation switch
        {
            "binary" => [new(0, null, [1, 2])],
            "multiple" => [new(0, Future, null), new(1, Past, null)],
            "ordinal" => [new(1, Future, null)],
            "dual" => [new(0, Future, [1])],
            _ => throw new ArgumentOutOfRangeException(nameof(representation)),
        };
        var attribute = new ObjectAttribute(LapsAttributes.WindowsLapsExpiration, AttributeCardinality.SingleValued, values);
        subject = subject with { Attributes = [.. subject.Attributes, attribute] };
        var parsed = LapsTimestamp.FromAttribute(attribute);
        Assert.True(parsed.HasUnsupportedRepresentation);
        Assert.True(parsed.HasCapturedValue);
        Assert.Equal(LapsTimestampReading.Unreadable, parsed.Reading);
        Assert.Null(parsed.ExpiresUtc);
        Assert.Equal(values, attribute.Values);
        var verdict = Rule(ruleId).Judge(subject, Context());
        Assert.False(verdict.IsComplete);
        Assert.Empty(verdict.Findings);
        Assert.Empty(verdict.InputsNotCaptured);
        Assert.Equal(CapturedInputIssueKind.UnsupportedRepresentation, Assert.Single(verdict.InputIssues).Kind);
    }

    [Theory]
    [InlineData("SEC-091", 4098, true)]
    [InlineData("SEC-092", 4098, true)]
    [InlineData("SEC-094", 4098, true)]
    [InlineData("SEC-091", 8192, true)]
    [InlineData("SEC-092", 8192, true)]
    [InlineData("SEC-094", 8192, true)]
    [InlineData("SEC-091", 4096, false)]
    [InlineData("SEC-092", 4096, false)]
    [InlineData("SEC-094", 4096, false)]
    public void Scout14ExistingExclusionsDoNotBecomeInputQualityGaps(string ruleId, uint control, bool computer)
    {
        var verdict = Rule(ruleId).Judge(Subject("0", "not-a-filetime", control, computer), Context());
        Assert.True(verdict.IsComplete);
        Assert.Empty(verdict.Findings);
        Assert.Empty(verdict.InputIssues);
    }

    [Theory]
    [InlineData("SEC-091")]
    [InlineData("SEC-092")]
    [InlineData("SEC-094")]
    public void Scout14UnknownAccountStateRemainsItsOwnMissingInput(string ruleId)
    {
        var verdict = Rule(ruleId).Judge(Subject("0", "not-a-filetime", null), Context());
        Assert.False(verdict.IsComplete);
        Assert.Empty(verdict.InputIssues);
        Assert.Equal("userAccountControl", Assert.Single(verdict.InputsNotCaptured));
    }

    [Theory]
    [InlineData("SEC-091", "0", null, 1)]
    [InlineData("SEC-092", "0", null, 1)]
    [InlineData("SEC-094", null, "0", 1)]
    [InlineData("SEC-091", "0", "not-a-filetime", 2)]
    public void Scout14TheRealPipelineSavesQualityReasonsWithoutInventingCaptureAbsence(string ruleId,
        string? modern, string? legacy, int reasons)
    {
        var directory = LapsBundle.Build("CN=Quality,DC=ad,DC=lab", ["top", "user", "computer"],
            "Windows Server 2022 Datacenter", "10.0 (20348)", modern, legacy, 4096, false, true, AsOf.AddDays(-1));
        Assert.True(Stage2aRun.Derive(directory, ExpansionBudget.Bulk, AsOf, Stage2aRun.Unwatched,
            RunLog.Discarded, CancellationToken.None).IsSuccess);
        var capture = SelfMembershipDiscoveryTests.Hash(directory);
        var error = Record.Exception(() =>
        {
            var judged = JudgingRun.Judge(directory, [Rule(ruleId)], AsOf, AsOf,
                JudgingRun.NobodyIsWatching, RunLog.Discarded, CancellationToken.None);
            Assert.True(judged.IsSuccess);
        });
        Assert.Null(error);
        Assert.Equal(capture, SelfMembershipDiscoveryTests.Hash(directory));
        using var reader = JudgementReader.Open(directory).Value;
        var run = reader.Read();
        Assert.Equal(JudgementRunState.CompletedDegraded, run.Description.State);
        var execution = Assert.Single(run.RulesRun);
        Assert.Equal(ruleId == "SEC-094" ? 3 : 2, execution.RuleVersion);
        Assert.Equal(RuleExecutionOutcome.Indeterminate, execution.Outcome);
        Assert.Equal(1, execution.ObjectsNotJudged);
        Assert.Equal(0, execution.ObjectsJudged);
        Assert.Empty(run.Findings);
        Assert.Equal(reasons, execution.MissingInputs.Count);
        Assert.All(execution.MissingInputs, input =>
        {
            Assert.StartsWith(CapturedInputIssue.TokenPrefix, input.Attribute);
            Assert.Equal(1, input.ObjectsAffected);
            Assert.DoesNotContain("not captured", UnresolvedWording.For(input.Attribute), StringComparison.OrdinalIgnoreCase);
        });
        var display = new RuleRowViewModel(ruleId, Rule(ruleId).Definition, execution);
        Assert.DoesNotContain("not captured", display.Outcome, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Zero (no usable date)", display.Outcome, StringComparison.Ordinal);
        Assert.Equal(FactState.NotEstablished, display.State);
        var row = Assert.Single(SavedLapsTestRun.Read(directory, "DC=ad,DC=lab", ListingScope.Subtree).Computers);
        Assert.Equal(modern, row.WindowsLaps.Raw);
        Assert.Equal(legacy, row.LegacyLaps.Raw);
    }

    [Theory]
    [InlineData(LapsValuePresence.None, "No expiry values")]
    [InlineData(LapsValuePresence.WindowsOnly, "Windows value only")]
    [InlineData(LapsValuePresence.LegacyOnly, "Legacy value only")]
    [InlineData(LapsValuePresence.Both, "Both expiry values")]
    [InlineData(LapsValuePresence.WindowsOnLegacyOnly, "Platform review")]
    public void Scout14EveryValueGroupHasOneNeutralLabelWithoutADeploymentVerdict(LapsValuePresence values, string label)
    {
        var modern = values is LapsValuePresence.WindowsOnly or LapsValuePresence.Both or LapsValuePresence.WindowsOnLegacyOnly ? "0" : null;
        var legacy = values is LapsValuePresence.LegacyOnly or LapsValuePresence.Both ? "not-a-filetime" : null;
        var subject = Subject(modern, legacy);
        if (values == LapsValuePresence.WindowsOnLegacyOnly)
            subject = subject with
            {
                Attributes = [.. subject.Attributes.Where(value => value.LdapDisplayName is not ("operatingSystem" or "operatingSystemVersion")),
                    Text("operatingSystem", "Windows 7 Enterprise"), Text("operatingSystemVersion", "6.1")],
            };
        var recorded = LapsInventoryStorage.CreateComputerResult(subject);
        Assert.Equal(values, recorded.ValuePresence);
        var view = new LapsComputerViewModel(recorded);
        Assert.Equal(label, view.ValuePresence);
        Assert.Equal(label, new LapsCountViewModel(values, 17).Label);
        Assert.Equal(FactState.NotEstablished, view.State);
        Assert.True(view.IsInRuleScope);
    }

    [Theory]
    [InlineData(null, "No value captured", false)]
    [InlineData("0", "Zero (no usable date)", true)]
    [InlineData("not-a-filetime", "Unusable value", true)]
    public void Scout14ExpiryTextKeepsZeroUnusableAndUnreturnedValuesDistinct(string? raw, string text, bool caution)
    {
        var view = new LapsComputerViewModel(LapsInventoryStorage.CreateComputerResult(Subject(raw, raw)));
        Assert.Equal(text, view.WindowsLapsExpiry);
        Assert.Equal(text, view.LegacyLapsExpiry);
        Assert.Equal(caution, view.HasUnusableWindowsExpiry);
        Assert.Equal(caution, view.HasUnusableLegacyExpiry);
    }

    [Fact]
    public void Scout14SavedScopeEligibilityDoesNotClaimThatAnyRuleRan()
    {
        var directory = LapsBundle.Build("CN=Scope,DC=ad,DC=lab", ["top", "user", "computer"],
            "Windows Server 2022", "10.0 (20348)", "0", null, 4096, false, true, AsOf);
        SavedLapsTestRun.Judge(directory);
        using var reader = JudgementReader.Open(directory).Value;
        Assert.Empty(reader.Read().RulesRun);
        var row = Assert.Single(SavedLapsTestRun.Read(directory, "DC=ad,DC=lab", ListingScope.Subtree).Computers);
        Assert.True(row.IsInRuleScope);
        Assert.Equal(LapsTimestampReading.Zero, row.WindowsLaps.Reading);
        Assert.Equal("0", row.WindowsLaps.Raw);
        Assert.Null(row.WindowsLaps.ExpiresUtc);
    }

    [Theory]
    [InlineData("0", "Windows expiry: Zero (no usable date)")]
    [InlineData("not-a-filetime", "Windows expiry: Unusable value")]
    public void Scout14TheSavedQualityTokenHasTheApprovedPlainLanguage(string raw, string expected)
    {
        var verdict = Rule("SEC-091").Judge(Subject(raw, null), Context());
        var issue = Assert.Single(verdict.InputIssues);
        Assert.Equal(expected, UnresolvedWording.For(issue.Token));
    }

    internal static IObjectRule Rule(string id) => id switch
    {
        "SEC-091" => new LapsMissingOnComputer(),
        "SEC-092" => new LapsRotationStale(),
        "SEC-094" => new WindowsLapsNotAppliedOnCapableComputer(),
        _ => throw new ArgumentOutOfRangeException(nameof(id)),
    };

    internal static JudgingContext Context() => JudgingContext.At(AsOf) with
    {
        AttributeVisibility = new([
            new(LapsAttributes.WindowsLapsExpiration, 0, 0),
            new(LapsAttributes.LegacyLapsExpiration, 0, 0),
        ]),
    };

    internal static ObjectAttributes Subject(string? modern, string? legacy, uint? control = 4096, bool computer = true)
    {
        var attributes = new List<ObjectAttribute>
        {
            Text("objectClass", computer ? ["top", "user", "computer"] : ["top", "user"]),
            Text("sAMAccountName", "Quality$"), Text("primaryGroupID", "515"),
            Text("operatingSystem", "Windows Server 2022 Datacenter"),
            Text("operatingSystemVersion", "10.0 (20348)"),
        };
        if (control.HasValue) attributes.Add(Text("userAccountControl", control.Value.ToString(CultureInfo.InvariantCulture)));
        if (modern is not null) attributes.Add(Text(LapsAttributes.WindowsLapsExpiration, modern));
        if (legacy is not null) attributes.Add(Text(LapsAttributes.LegacyLapsExpiration, legacy));
        return new("CN=Quality,DC=ad,DC=lab", Guid.Parse("11111111-2222-3333-4444-555555555555"),
            AsOf.AddDays(-1), EvidenceCompleteness.Complete, attributes, "ad.lab");
    }

    internal static ObjectAttribute Text(string name, params string[] values) =>
        new(name, values.Length > 1 ? AttributeCardinality.MultiValued : AttributeCardinality.SingleValued,
            values.Select((value, index) => new AttributeValue(index, value, null)).ToArray());
}
