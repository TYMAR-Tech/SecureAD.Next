using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;

namespace SecureAD.Judgement;

/// <summary>Publishes the existing saved unexpected-route qualifications, never new authorization reasoning.</summary>
public sealed class UnexpectedTier0Route : IRule
{
    public const string RuleId = "SEC-071";
    internal const string Anchor = "Tier0ControlPlane";

    public RuleDefinition Definition { get; } = new(RuleId, "Unexpected route to Tier 0", Severity.High, 1,
        ["user"], ["objectGUID", "objectSid", "objectClass", "sAMAccountName"],
        [nameof(DerivedFactKind.ProtectedPrincipals), nameof(DerivedFactKind.PrincipalExpansion)]);

    internal (RuleExecution Execution, Tier0FindingSummary Summary) JudgeSaved(SqliteConnection connection,
        JudgementDescription description, JudgingInputs sources, CancellationToken cancellationToken)
    {
        sources.RequireFor(description);
        var coverage = PathRequesterRiskStorage.ReadCoverage(connection, description, cancellationToken);
        var findings = new List<Finding>();
        var questions = new List<PathRequesterRiskAssessment>();
        var missing = new Dictionary<PathRiskIssue, int>();
        var counts = Enum.GetValues<PathRequesterFamily>().ToDictionary(family => family, _ => new int[4]);
        string? requester = null;
        var accounts = 0;
        var unresolvedAccounts = 0;
        foreach (var value in PathRequesterRiskStorage.ReadAssessments(connection, description, coverage, null, cancellationToken))
        {
            if (requester is not null && !string.Equals(requester, value.RequesterDn, StringComparison.OrdinalIgnoreCase))
            {
                FinishAccount();
                questions.Clear();
            }
            requester = value.RequesterDn;
            questions.Add(value);
            counts[value.Family][(int)value.Verdict]++;
        }
        if (questions.Count != 0) FinishAccount();
        foreach (var family in coverage.Families)
            if (!counts[family.Family].SequenceEqual(new[] { family.UnexpectedRoutes, family.ExpectedRoutes, family.NotEstablished, family.Unknown }))
                throw Tier0PathStorage.InvalidProof();
        cancellationToken.ThrowIfCancellationRequested();
        var execution = accounts == 0 && coverage.Availability != PathRiskAvailability.Recorded
            ? RuleExecution.DidNotRun(Definition)
            : new RuleExecution(Definition, unresolvedAccounts == 0 ? RuleExecutionOutcome.Succeeded : RuleExecutionOutcome.Indeterminate,
                accounts - unresolvedAccounts, 0, unresolvedAccounts,
                missing.OrderBy(pair => pair.Key).Select(pair => new MissingInput("SavedPathRisk:" + pair.Key, pair.Value)).ToArray(),
                findings, null);
        var summary = new Tier0FindingSummary(1, description.GenerationId, description.DerivationGenerationId,
            description.EvidenceSeal, coverage.CalculationFingerprint, Definition.Version, coverage.Availability,
            execution.Outcome, accounts, findings.Count, coverage.Families.Sum(family => family.Unknown));
        sources.RequireFor(description);
        return (execution, summary);

        void FinishAccount()
        {
            cancellationToken.ThrowIfCancellationRequested();
            accounts++;
            var unresolved = questions.Where(value => value.Verdict == PathRiskVerdict.Unknown).ToArray();
            if (unresolved.Length != 0)
            {
                unresolvedAccounts++;
                foreach (var issue in unresolved.Select(value => value.Issue ?? throw Tier0PathStorage.InvalidProof()).Distinct())
                    missing[issue] = missing.GetValueOrDefault(issue) + 1;
            }
            var unexpected = questions.Where(value => value.Verdict == PathRiskVerdict.UnexpectedRoute).ToArray();
            if (unexpected.Length == 0) return;
            var subject = sources.Bundle.ReadObjectAttributes(unexpected[0].RequesterDn) ?? throw Tier0PathStorage.InvalidProof();
            findings.Add(CreateFinding(subject, unexpected, coverage));
        }
    }

    internal Finding CreateFinding(ObjectAttributes subject, IReadOnlyList<PathRequesterRiskAssessment> unexpected,
        PathRiskCoverage coverage)
    {
        if (subject.ObjectGuid is not { } guid || unexpected.Count == 0
            || unexpected.Any(value => value.Verdict != PathRiskVerdict.UnexpectedRoute
                || value.CurrentAuthority?.Principal.ObjectGuid != guid
                || !string.Equals(value.RequesterDn, subject.DistinguishedName, StringComparison.OrdinalIgnoreCase)
                || value.CalculationFingerprint != coverage.CalculationFingerprint))
            throw Tier0PathStorage.InvalidProof();
        var principal = unexpected[0].CurrentAuthority!.Principal;
        var objectClass = AttributeReading.AllText(subject, "objectClass").LastOrDefault()
            ?? throw Tier0PathStorage.InvalidProof();
        var domain = principal.DomainFqdn ?? throw Tier0PathStorage.InvalidProof();
        var evidence = new Tier0RouteFindingEvidence(coverage.GenerationId, coverage.DerivationGenerationId,
            coverage.EvidenceSeal, coverage.CalculationFingerprint, Anchor, guid,
            principal.Sid ?? throw Tier0PathStorage.InvalidProof(), subject.DistinguishedName,
            unexpected.Count, Tier0PathCalculation.Fingerprint(unexpected));
        // SEC-071 has one synthetic destination. The account GUID supplies its stable identity
        // and directory navigation; concrete endpoints and changing names cannot split the finding.
        return new(Definition.Id, Definition.Version, Definition.Severity,
            new(FindingSubjectKind.Account, guid.ToString("D")), guid, subject.DistinguishedName,
            domain, objectClass, "The saved evidence establishes a supported route to Tier 0 outside this account's expected administrative authority on the reached target.",
            subject.Completeness, evidence)
        {
            PrincipalName = AttributeReading.AllText(subject, "sAMAccountName").SingleOrDefault() ?? subject.DistinguishedName,
        };
    }
}
