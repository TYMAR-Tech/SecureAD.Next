using System.Globalization;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using SecureAD.Kernel;
using Xunit;
using Xunit.Abstractions;

namespace SecureAD.Next.Tests.Judgement;

/// <summary>
/// P-136: an unencrypted read can omit confidential attributes without an LDAP error.
/// The captured schema must keep that absence from becoming a false LAPS conclusion.
/// https://learn.microsoft.com/troubleshoot/windows-server/windows-security/confidential-attributes-unexpected-behavior-using-windows-server-2025-dc
/// </summary>
public sealed class ConfidentialValueJudgingTests(ITestOutputHelper output)
{
    private const string ComputerDn = "CN=FS01,OU=Servers,DC=ad,DC=lab";
    private const string ModernAttribute = "msLAPS-PasswordExpirationTime";
    private const string LegacyAttribute = "ms-Mcs-AdmPwdExpirationTime";
    private readonly DateTimeOffset _asOf = new(2026, 9, 3, 9, 0, 0, TimeSpan.Zero);

    /// <summary>
    /// Only the modern attribute is confidential; a legacy refusal cannot conceal a broken modern guard.
    /// </summary>
    [Fact]
    public void AnUnencryptedReadWithAMissingConfidentialModernTimestampIsIndeterminate()
    {
        var directory = Build(
            ConnectionSecurityLevel.Signed,
            windowsLapsConfidential: true,
            legacyLapsExpiration: Timestamp(10));

        var judgement = Judge(directory, new WindowsLapsNotAppliedOnCapableComputer());
        var execution = Assert.Single(judgement.RulesRun);

        Assert.Equal(
            (RuleExecutionOutcome.Indeterminate, 0, 1, 0, ModernAttribute),
            (execution.Outcome, execution.ObjectsJudged, execution.ObjectsNotJudged,
                execution.FindingsProduced, execution.MissingInputs.Single().Attribute));
    }

    /// <summary>
    /// Each case withholds only one attribute. Encryption does not establish the caller's read
    /// permission, so neither encrypted connection is allowed to turn confidential absence into fact.
    /// </summary>
    [Theory]
    [InlineData("SEC-091", ConnectionSecurityLevel.Signed, true, false, ModernAttribute)]
    [InlineData("SEC-091", ConnectionSecurityLevel.Unprotected, true, false, ModernAttribute)]
    [InlineData("SEC-091", ConnectionSecurityLevel.SignedAndSealed, true, false, ModernAttribute)]
    [InlineData("SEC-091", ConnectionSecurityLevel.Ldaps, true, false, ModernAttribute)]
    [InlineData("SEC-091", ConnectionSecurityLevel.Signed, false, true, LegacyAttribute)]
    [InlineData("SEC-091", ConnectionSecurityLevel.Unprotected, false, true, LegacyAttribute)]
    [InlineData("SEC-091", ConnectionSecurityLevel.SignedAndSealed, false, true, LegacyAttribute)]
    [InlineData("SEC-091", ConnectionSecurityLevel.Ldaps, false, true, LegacyAttribute)]
    [InlineData("SEC-092", ConnectionSecurityLevel.Signed, true, false, ModernAttribute)]
    [InlineData("SEC-092", ConnectionSecurityLevel.Unprotected, true, false, ModernAttribute)]
    [InlineData("SEC-092", ConnectionSecurityLevel.SignedAndSealed, true, false, ModernAttribute)]
    [InlineData("SEC-092", ConnectionSecurityLevel.Ldaps, true, false, ModernAttribute)]
    [InlineData("SEC-092", ConnectionSecurityLevel.Signed, false, true, LegacyAttribute)]
    [InlineData("SEC-092", ConnectionSecurityLevel.Unprotected, false, true, LegacyAttribute)]
    [InlineData("SEC-092", ConnectionSecurityLevel.SignedAndSealed, false, true, LegacyAttribute)]
    [InlineData("SEC-092", ConnectionSecurityLevel.Ldaps, false, true, LegacyAttribute)]
    [InlineData("SEC-094", ConnectionSecurityLevel.Signed, true, false, ModernAttribute)]
    [InlineData("SEC-094", ConnectionSecurityLevel.Unprotected, true, false, ModernAttribute)]
    [InlineData("SEC-094", ConnectionSecurityLevel.SignedAndSealed, true, false, ModernAttribute)]
    [InlineData("SEC-094", ConnectionSecurityLevel.Ldaps, true, false, ModernAttribute)]
    [InlineData("SEC-094", ConnectionSecurityLevel.Signed, false, true, LegacyAttribute)]
    [InlineData("SEC-094", ConnectionSecurityLevel.Unprotected, false, true, LegacyAttribute)]
    [InlineData("SEC-094", ConnectionSecurityLevel.SignedAndSealed, false, true, LegacyAttribute)]
    [InlineData("SEC-094", ConnectionSecurityLevel.Ldaps, false, true, LegacyAttribute)]
    public void AMissingConfidentialTimestampIsNotJudgedAsAnOrdinaryAbsence(
        string ruleId, ConnectionSecurityLevel connectionSecurity,
        bool windowsLapsConfidential, bool legacyLapsConfidential, string missingAttribute)
    {
        var directory = Build(connectionSecurity, windowsLapsConfidential, legacyLapsConfidential);
        var rule = RuleCatalogue.All.Single(r => r.Definition.Id == ruleId);

        var judgement = Judge(directory, rule);
        var execution = Assert.Single(judgement.RulesRun);

        Assert.Equal(
            (RuleExecutionOutcome.Indeterminate, 0, 1, 0, missingAttribute, 1),
            (execution.Outcome, execution.ObjectsJudged, execution.ObjectsNotJudged,
                execution.FindingsProduced, execution.MissingInputs.Single().Attribute,
                execution.MissingInputs.Single().ObjectsAffected));
    }

    /// <summary>The schema's encrypted read must not overwrite the computer's own connection warning.</summary>
    [Theory]
    [InlineData(ConnectionSecurityLevel.Signed, EvidenceCompleteness.MayBeMissingConfidentialValues)]
    [InlineData(ConnectionSecurityLevel.Unprotected, EvidenceCompleteness.MayBeMissingConfidentialValues)]
    [InlineData(ConnectionSecurityLevel.SignedAndSealed, EvidenceCompleteness.Complete)]
    [InlineData(ConnectionSecurityLevel.Ldaps, EvidenceCompleteness.Complete)]
    public void ObjectReadbackRetainsItsOwnConnectionCoverage(
        ConnectionSecurityLevel connectionSecurity, EvidenceCompleteness expected)
    {
        var directory = Build(connectionSecurity);

        var opening = BundleReader.Open(directory);
        Assert.True(opening.IsSuccess, opening.Error?.Description);
        using var reader = opening.Value;
        var subject = Assert.IsType<ObjectAttributes>(reader.ReadObjectAttributes(ComputerDn));

        Assert.Equal(expected, subject.Completeness);
    }

    /// <summary>
    /// Ordinary absent timestamps remain reportable; the finding keeps the warning about other
    /// confidential values instead of either claiming full evidence or suppressing the finding.
    /// </summary>
    [Theory]
    [InlineData(ConnectionSecurityLevel.Signed, EvidenceCompleteness.MayBeMissingConfidentialValues)]
    [InlineData(ConnectionSecurityLevel.Unprotected, EvidenceCompleteness.MayBeMissingConfidentialValues)]
    [InlineData(ConnectionSecurityLevel.SignedAndSealed, EvidenceCompleteness.Complete)]
    [InlineData(ConnectionSecurityLevel.Ldaps, EvidenceCompleteness.Complete)]
    public void AReadableAbsenceFindingRetainsTheObjectConnectionCoverage(
        ConnectionSecurityLevel connectionSecurity, EvidenceCompleteness expected)
    {
        var directory = Build(connectionSecurity);

        var judgement = Judge(directory, new LapsMissingOnComputer());
        var finding = Assert.Single(judgement.Findings);

        Assert.Equal(("SEC-091", ComputerDn, expected),
            (finding.RuleId, finding.DistinguishedName, finding.Coverage));
    }

    /// <summary>An unencrypted read does not hide a conclusion supported by nonconfidential timestamps.</summary>
    [Theory]
    [InlineData("SEC-092", ConnectionSecurityLevel.Signed)]
    [InlineData("SEC-092", ConnectionSecurityLevel.Unprotected)]
    [InlineData("SEC-094", ConnectionSecurityLevel.Signed)]
    [InlineData("SEC-094", ConnectionSecurityLevel.Unprotected)]
    public void AnAbsentReadableModernTimestampDoesNotPreventASupportedFinding(
        string ruleId, ConnectionSecurityLevel connectionSecurity)
    {
        var directory = Build(connectionSecurity, legacyLapsExpiration: Timestamp(-30));
        var rule = RuleCatalogue.All.Single(r => r.Definition.Id == ruleId);

        var judgement = Judge(directory, rule);
        var execution = Assert.Single(judgement.RulesRun);

        Assert.Equal((RuleExecutionOutcome.Succeeded, 1, 0, 1),
            (execution.Outcome, execution.ObjectsJudged, execution.ObjectsNotJudged,
                execution.FindingsProduced));
    }

    /// <summary>Returned readable values retain their meaning on an unencrypted connection.</summary>
    [Theory]
    [InlineData("SEC-091", ConnectionSecurityLevel.Signed)]
    [InlineData("SEC-091", ConnectionSecurityLevel.Unprotected)]
    [InlineData("SEC-092", ConnectionSecurityLevel.Signed)]
    [InlineData("SEC-092", ConnectionSecurityLevel.Unprotected)]
    [InlineData("SEC-094", ConnectionSecurityLevel.Signed)]
    [InlineData("SEC-094", ConnectionSecurityLevel.Unprotected)]
    public void AReturnedReadableModernTimestampStillSupportsACompleteVerdict(
        string ruleId, ConnectionSecurityLevel connectionSecurity)
    {
        var directory = Build(connectionSecurity, windowsLapsExpiration: Timestamp(10));
        var rule = RuleCatalogue.All.Single(r => r.Definition.Id == ruleId);

        var judgement = Judge(directory, rule);
        var execution = Assert.Single(judgement.RulesRun);

        Assert.Equal((RuleExecutionOutcome.Succeeded, 1, 0, 0),
            (execution.Outcome, execution.ObjectsJudged, execution.ObjectsNotJudged,
                execution.FindingsProduced));
    }

    /// <summary>A LAPS input gap cannot discard a neighboring rule's established account-flag finding.</summary>
    [Theory]
    [InlineData(ConnectionSecurityLevel.Signed)]
    [InlineData(ConnectionSecurityLevel.Unprotected)]
    public void AnUnrelatedRuleStillJudgesWhenAConfidentialLapsValueIsMissing(
        ConnectionSecurityLevel connectionSecurity)
    {
        var directory = Build(connectionSecurity,
            windowsLapsConfidential: true, userAccountControl: 0x1020);

        var judgement = Judge(directory, new LapsMissingOnComputer(), new PasswordNotRequired());
        var execution = judgement.RulesRun.Single(r => r.RuleId == "SEC-028");

        Assert.Equal((RuleExecutionOutcome.Succeeded, 1, 0, 1),
            (execution.Outcome, execution.ObjectsJudged, execution.ObjectsNotJudged,
                execution.FindingsProduced));
    }

    private string Build(
        ConnectionSecurityLevel connectionSecurity,
        bool windowsLapsConfidential = false,
        bool legacyLapsConfidential = false,
        string? windowsLapsExpiration = null,
        string? legacyLapsExpiration = null,
        uint userAccountControl = 0x1000)
    {
        var directory = LapsBundle.Build(
            ComputerDn,
            ["top", "person", "organizationalPerson", "user", "computer"],
            operatingSystem: "Windows Server 2022 Standard",
            operatingSystemVersion: "10.0 (20348)",
            windowsLapsExpiration,
            legacyLapsExpiration,
            userAccountControl: userAccountControl,
            confidential: false,
            windowsLapsInSchema: true,
            started: _asOf,
            primaryGroupId: 515,
            connectionSecurity: connectionSecurity,
            windowsLapsConfidential: windowsLapsConfidential,
            legacyLapsConfidential: legacyLapsConfidential);

        output.WriteLine("Synthetic evidence: {0}", directory);
        return directory;
    }

    private StoredJudgement Judge(string directory, params IRule[] rules)
    {
        var derived = Stage2aRun.Derive(
            directory, ExpansionBudget.Bulk, _asOf, Stage2aRun.Unwatched,
            RunLog.Discarded, CancellationToken.None);
        Assert.True(derived.IsSuccess, derived.Error?.Description);

        var judged = JudgingRun.Judge(
            directory, rules, _asOf, _asOf, JudgingRun.NobodyIsWatching,
            RunLog.Discarded, CancellationToken.None);
        Assert.True(judged.IsSuccess, judged.Error?.Description);

        var opening = JudgementReader.Open(directory);
        Assert.True(opening.IsSuccess, opening.Error?.Description);
        using var reader = opening.Value;
        return reader.Read();
    }

    private string Timestamp(int days) =>
        _asOf.AddDays(days).ToFileTime().ToString(CultureInfo.InvariantCulture);
}
