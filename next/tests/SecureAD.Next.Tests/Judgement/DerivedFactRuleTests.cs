using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Evidence.Run;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Kernel.Security;
using Xunit;

namespace SecureAD.Next.Tests.Judgement;

/// <summary>
/// A rule that reads derived facts is not run against evidence alone.
/// </summary>
/// <remarks>
/// <para>
/// <b>What these hold.</b> <c>docs/decisions/0091</c> settles that judging refuses when a scheduled
/// rule declares a derived fact the bundle cannot supply, rather than letting the rule report
/// "could not judge" once per object. A wall of not-judged rows across a forest is technically
/// honest and practically undecodable, and silence from a rule reads as nothing found.
/// </para>
/// <para>
/// <b>Both directions are exercised deliberately.</b> A refusal that has never been observed
/// failing is decoration, so each test that proves a refusal has a partner proving the same run
/// succeeds once the missing thing is present. The negative controls are the point.
/// </para>
/// </remarks>
public sealed class DerivedFactRuleTests
{
    private static readonly DateTimeOffset Started =
        new(2026, 8, 31, 9, 0, 0, TimeSpan.Zero);

    /// <summary>
    /// A rule declaring a derived fact, so a judging can be asked for one without SEC-030 existing.
    /// </summary>
    private sealed class NeedsProtectedPrincipals : IRule
    {
        public RuleDefinition Definition { get; } = new(
            "TEST-DERIVED",
            "Reads protected principals",
            Severity.Medium,
            1,
            ["user"],
            ["objectSid"],
            [nameof(DerivedFactKind.ProtectedPrincipals)]);

        /// <summary>What it saw, so a test can prove the package actually arrived.</summary>
        public StoredProtectedPrincipalDerivation? Seen { get; private set; }

        public RuleVerdict Judge(ObjectAttributes subject) =>
            throw new InvalidOperationException(
                "A rule declaring derived facts must be offered the package overload.");

        public RuleVerdict Judge(ObjectAttributes subject, DerivedFacts derived)
        {
            Seen = derived.ProtectedPrincipals;
            return RuleVerdict.Judged([]);
        }
    }

    /// <summary>A rule that reads only the captured object, as today's two delegation rules do.</summary>
    private sealed class NeedsNothingDerived : IRule
    {
        public RuleDefinition Definition { get; } = new(
            "TEST-PLAIN",
            "Reads only the object",
            Severity.Low,
            1,
            ["user"],
            ["objectSid"],
            RequiredDerivedFacts: []);

        public int Judged { get; private set; }

        public RuleVerdict Judge(ObjectAttributes subject)
        {
            Judged++;
            return RuleVerdict.Judged([]);
        }
    }

    /// <summary>
    /// A rule that reaches the derived facts and finds them undecided, the way SEC-030 will for a
    /// principal whose only route runs through a disputed catalogue entry.
    /// </summary>
    private sealed class CannotResolve : IRule
    {
        public RuleDefinition Definition { get; } = new(
            "TEST-UNRESOLVED",
            "Cannot resolve",
            Severity.Medium,
            1,
            ["user"],
            ["objectSid"],
            [nameof(DerivedFactKind.ProtectedPrincipals)]);

        public RuleVerdict Judge(ObjectAttributes subject) =>
            throw new InvalidOperationException("Offered the wrong overload.");

        public RuleVerdict Judge(ObjectAttributes subject, DerivedFacts derived) =>
            RuleVerdict.CouldNotResolve(
                [new UnresolvedInput(
                    DerivedFactKind.ProtectedPrincipals, UnresolvedReason.ClaimDisputed)]);
    }

    [Fact]
    public void Judging_RefusesWhenADeclaredDerivedFactWasNeverDerived()
    {
        var directory = CapturedButNotDerived();

        var judged = JudgingRun.Judge(
            directory,
            [new NeedsProtectedPrincipals()],
            Started,
            Started,
            JudgingRun.NobodyIsWatching,
            RunLog.Discarded,
            CancellationToken.None);

        Assert.False(judged.IsSuccess);
        Assert.EndsWith("DerivationUnavailable", judged.Error!.Code, StringComparison.Ordinal);

        // The refusal has to name what is missing and what to do, or an operator is left with a
        // failure he cannot act on.
        Assert.Contains("ProtectedPrincipals", judged.Error.Description, StringComparison.Ordinal);
        Assert.Contains("Derive this bundle", judged.Error.Description, StringComparison.Ordinal);
    }

    /// <summary>
    /// The negative control for the refusal above: the same rule, the same bundle, once derived.
    /// </summary>
    [Fact]
    public void Judging_RunsAndDeliversTheFactsOnceTheBundleIsDerived()
    {
        var directory = CapturedButNotDerived();

        Assert.True(
            Stage2aRun.Derive(
                directory,
                ExpansionBudget.Bulk,
                Started,
                Stage2aRun.Unwatched,
                RunLog.Discarded,
                CancellationToken.None).IsSuccess);

        var rule = new NeedsProtectedPrincipals();

        var judged = JudgingRun.Judge(
            directory,
            [rule],
            Started,
            Started,
            JudgingRun.NobodyIsWatching,
            RunLog.Discarded,
            CancellationToken.None);

        Assert.True(judged.IsSuccess, judged.Error?.Description);

        // Delivered rather than merely permitted: the rule recorded what it was handed, so an empty
        // package cannot pass this by looking like a successful run.
        Assert.NotNull(rule.Seen);
        Assert.Equal(2, rule.Seen!.CatalogueVersion);
    }

    /// <summary>
    /// A rule declaring nothing derived is unaffected, which is what keeps the delegation rules and
    /// <c>judge-bundle.ps1</c> working against evidence alone.
    /// </summary>
    [Fact]
    public void Judging_StillRunsARuleThatDeclaresNoDerivedFactsOnAnUnderivedBundle()
    {
        var directory = CapturedButNotDerived();
        var rule = new NeedsNothingDerived();

        var judged = JudgingRun.Judge(
            directory,
            [rule],
            Started,
            Started,
            JudgingRun.NobodyIsWatching,
            RunLog.Discarded,
            CancellationToken.None);

        Assert.True(judged.IsSuccess, judged.Error?.Description);
        Assert.Equal(1, rule.Judged);
    }

    /// <summary>
    /// The judgement records which derivation it consumed, so a stored judgement can be tied to the
    /// derived facts behind it rather than to whatever was there later.
    /// </summary>
    [Fact]
    public void Judging_RecordsTheDerivationGenerationItConsumed()
    {
        var directory = CapturedButNotDerived();

        Assert.True(
            Stage2aRun.Derive(
                directory,
                ExpansionBudget.Bulk,
                Started,
                Stage2aRun.Unwatched,
                RunLog.Discarded,
                CancellationToken.None).IsSuccess);

        using var derivation = DerivationReader.Open(directory).Value!;
        var generation = derivation.Read().Description.GenerationId;

        Assert.True(
            JudgingRun.Judge(
                directory,
                [new NeedsProtectedPrincipals()],
                Started,
                Started,
                JudgingRun.NobodyIsWatching,
                RunLog.Discarded,
                CancellationToken.None).IsSuccess);

        using var judgement = JudgementReader.Open(directory).Value!;
        Assert.Equal(generation, judgement.Read().Description.DerivationGenerationId);
    }

    /// <summary>
    /// A judging with no derived-fact rule records no derivation generation, so the field states a
    /// fact rather than being filled in for tidiness.
    /// </summary>
    [Fact]
    public void Judging_RecordsNoDerivationGenerationWhenNoRuleAskedForOne()
    {
        var directory = CapturedButNotDerived();

        Assert.True(
            Stage2aRun.Derive(
                directory,
                ExpansionBudget.Bulk,
                Started,
                Stage2aRun.Unwatched,
                RunLog.Discarded,
                CancellationToken.None).IsSuccess);

        Assert.True(
            JudgingRun.Judge(
                directory,
                [new NeedsNothingDerived()],
                Started,
                Started,
                JudgingRun.NobodyIsWatching,
                RunLog.Discarded,
                CancellationToken.None).IsSuccess);

        using var judgement = JudgementReader.Open(directory).Value!;
        Assert.Null(judgement.Read().Description.DerivationGenerationId);
    }

    /// <summary>
    /// An unresolved derived fact reaches the store under its own name, and is not reported as a
    /// missing attribute.
    /// </summary>
    /// <remarks>
    /// <b>The distinction is the whole point of the vocabulary.</b> Telling an operator that
    /// <c>objectSid</c> was not captured, when what actually happened is that Microsoft's pages
    /// disagree about a group, sends him to re-run a capture that will change nothing.
    /// <c>docs/decisions/0091</c> requires the two to stay apart, and this is where that is
    /// observed rather than asserted in prose.
    /// </remarks>
    [Fact]
    public void Judging_StoresAnUnresolvedDerivedFactUnderItsOwnNameAndNotAsAnAttribute()
    {
        var directory = CapturedButNotDerived();

        Assert.True(
            Stage2aRun.Derive(
                directory,
                ExpansionBudget.Bulk,
                Started,
                Stage2aRun.Unwatched,
                RunLog.Discarded,
                CancellationToken.None).IsSuccess);

        Assert.True(
            JudgingRun.Judge(
                directory,
                [new CannotResolve()],
                Started,
                Started,
                JudgingRun.NobodyIsWatching,
                RunLog.Discarded,
                CancellationToken.None).IsSuccess);

        using var judgement = JudgementReader.Open(directory).Value!;
        var run = Assert.Single(judgement.Read().RulesRun);

        Assert.Equal(RuleExecutionOutcome.Indeterminate, run.Outcome);
        Assert.Equal(0, run.ObjectsJudged);
        Assert.Equal(1, run.ObjectsNotJudged);

        var recorded = Assert.Single(run.MissingInputs);
        Assert.Equal("ProtectedPrincipals.ClaimDisputed", recorded.Attribute);
        Assert.Equal(1, recorded.ObjectsAffected);

        // The negative control: nothing here may look like an LDAP attribute name, because that is
        // exactly the confusion this vocabulary exists to prevent.
        Assert.DoesNotContain(run.MissingInputs, m => m.Attribute == "objectSid");
    }

    /// <summary>
    /// One sealed bundle holding a single user, captured and never derived.
    /// </summary>
    private static string CapturedButNotDerived()
    {
        var directory = Path.Combine(
            Path.GetTempPath(), "securead-derived-rule-tests", Guid.NewGuid().ToString("N"));

        Directory.CreateDirectory(directory);

        var partition = new PartitionCoverage(
            "DC=ad,DC=lab",
            NamingContextKind.Domain,
            "dc01.ad.lab",
            ConnectionSecurityLevel.SignedAndSealed,
            1,
            1,
            0,
            [],
            false);

        var coverage = RunCoverage.Of(
            CoverageId.ForDomains("ad.lab", ["ad.lab"]),
            [DomainCoverage.Read("ad.lab")],
            [
                ForestPartitionCoverage.Read(
                    "CN=Configuration,DC=ad,DC=lab", NamingContextKind.Configuration),
                ForestPartitionCoverage.Read(
                    "CN=Schema,CN=Configuration,DC=ad,DC=lab", NamingContextKind.Schema),
            ],
            SysvolCoverage.Of([]));

        using (var writer = BundleWriter.Create(directory, Started))
        {
            writer.WriteCoverage(partition);
            writer.WriteObject(
                new EvidenceObject(
                    partition,
                    "CN=Ann,DC=ad,DC=lab",
                    Guid.NewGuid(),
                    [
                        Text("objectClass", "user"),
                        Binary("objectSid", SidBytes("S-1-5-21-1-2-3-1105")),
                    ],
                    Started));

            writer.Complete(coverage, Started.AddMinutes(1));
        }

        return directory;
    }

    private static EvidenceAttribute Text(string name, string value) =>
        new(name, StoredAttributeCompleteness.Complete, [EvidenceValue.OfText(value)]);

    private static EvidenceAttribute Binary(string name, byte[] bytes) =>
        new(name, StoredAttributeCompleteness.Complete, [EvidenceValue.OfBytes(bytes)]);

    /// <summary>
    /// Encodes a SID for a fixture, refusing one the encoder will not accept - a silently empty
    /// value would fail these tests as though judging had dropped the object.
    /// </summary>
    private static byte[] SidBytes(string text) =>
        Sid.ToBytes(text)
        ?? throw new InvalidOperationException($"'{text}' is not a SID this product will encode.");
}
