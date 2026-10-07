using System.IO;
using SecureAD.Derivation;
using SecureAD.Judgement;
using SecureAD.Kernel.Naming;

namespace SecureAD.Shell.ViewModels;

internal static class Tier0Presentation
{
    internal static string Distance(Tier0DistanceFacts value) => value.SupportedDistance is { } distance
        ? $"{distance:N0} steps" : value.Verdict == Tier0DistanceVerdict.NotAssessed ? "Not assessed" : "Unresolved";
    internal static string Minimum(Tier0DistanceFacts value) => value.SupportedDistance is null
        ? "No complete supported route saved. Not a safe result."
        : value.IsMinimumEstablished ? "Minimum established: this object is a Tier 0 target." : "Overall minimum not established.";
    internal static string Grade(SupportedRouteGrade? value) => value is null ? "Not available"
        : $"{value.Length:N0} steps - {value.Feasibility switch
        {
            RouteFeasibility.Direct => "no modeled change required",
            RouteFeasibility.Conditional => "conditional",
            RouteFeasibility.Potential => "potential",
            _ => throw new InvalidDataException("Unrecognized saved route feasibility."),
        }}";
    internal static string Coverage(Tier0Coverage value) =>
        "Captured evidence: " + (value.InputsComplete ? "no recorded input gap." : "incomplete.")
        + "\nAnalysis support: " + (value.AnalysisComplete ? "complete for the saved analysis." : "unsupported or unresolved analysis remains.")
        + "\nProcessing: " + (value.ProcessingComplete ? "no recorded processing shortfall." : "incomplete; a saved processing limit or shortfall remains.")
        + "\nRecorded limitations: " + value.Limitations + ".";
    internal static string Identity(Tier0Target target) =>
        DnHelper.ExtractNameFromDn(target.DistinguishedName)
        + (target.DomainFqdn is { Length: > 0 } domain ? $" ({domain})" : "");
}

internal sealed record Tier0RowViewModel(Tier0OverviewRow Value)
{
    public string Name => Tier0Presentation.Identity(Value.Subject);
    public string DistinguishedName => Value.Subject.DistinguishedName;
    public string Distance => Tier0Presentation.Distance(Value.Distance);
    public string Qualification => Tier0Presentation.Minimum(Value.Distance);
    public string Best => Tier0Presentation.Grade(Value.BestGrade);
    public string Classification => Value.Distance.Classification == Tier0State.Established ? "Established Tier 0" : "Not established";
}

internal sealed class Tier0RoutePresentation(Tier0RouteDetails value)
{
    public string Distance => Tier0Presentation.Distance(value.Distance);
    public string Minimum => Tier0Presentation.Minimum(value.Distance);
    public string Classification => value.Distance.Classification == Tier0State.Established ? "Established" : "Not established";
    public string Best => Tier0Presentation.Grade(value.BestGrade);
    public string Explanation => value.BestGrade is null ? "No graded complete supported route is available."
        : value.Distance.IsMinimumEstablished ? "The selected object is itself a saved Tier 0 target."
        : "Best among evaluated, graded candidates. Evidence certainty and required conditions are considered before length; this does not change the shortest supported distance.";
    public string Grade => value.BestGrade is not { } grade ? "Not available"
        : $"{grade.Evidence} evidence; {grade.Feasibility} feasibility; {grade.Confidence} proof confidence; {grade.UnmetConditions.Count:N0} modeled unmet conditions.";
    public string GradingCoverage => $"{value.CompleteCandidates:N0} complete candidate records; {value.UngradedCandidates:N0} ungraded candidate records. "
        + "Not distinct-route totals or an exhaustive search."
        + (value.GradingLimitations.Count == 0 ? "" : "\nGrading limitations: " + string.Join(", ", value.GradingLimitations));
    public string Conditions => value.BestGrade is not { } grade ? "No grade available."
        : grade.UnmetConditions.Count == 0 ? "No modeled unmet conditions. This does not attest live access or a current access token."
        : string.Join("\n", grade.UnmetConditions.Select(condition =>
            $"{condition.Kind switch { "MembershipOutcome" => "The membership change must succeed", "MembershipEnabledForAuthorization" => "The resulting membership must be enabled for authorization", _ => throw new InvalidDataException("Unrecognized saved route condition.") }}: {Tier0Presentation.Identity(condition.Requester)}; group {Tier0Presentation.Identity(condition.Group)}; resource {condition.ResourceContext ?? "not recorded"}."));
    public string Coverage => Tier0Presentation.Coverage(value.Coverage);
    public IReadOnlyList<SavedPathStepViewModel> BestSteps { get; } = Steps(value.BestSteps, value.Permissions);
    public IReadOnlyList<SavedPathStepViewModel> ShortestSteps { get; } = Steps(value.ShortestSteps, value.Permissions);
    public string ShortestConditions => value.ShortestSteps.Any(step => step.Kind == Tier0PathStepKind.OwnAccountMembership)
        ? "Conditional: the supported own-account membership change must succeed and the resulting membership must be enabled for authorization in the relevant resource context. No change or access has been exercised."
        : "Saved supported steps only. This does not attest live access, credential extraction or completed takeover.";

    private static IReadOnlyList<SavedPathStepViewModel> Steps(IReadOnlyList<Tier0PathStep> steps, IReadOnlyList<ControlEdge> permissions) =>
        steps.Select(step =>
        {
            var edge = step.PermissionId is { } id ? permissions.Single(value => value.Id == id) : null;
            var relation = step.Kind switch
            {
                Tier0PathStepKind.Membership => "Recorded membership",
                Tier0PathStepKind.OwnAccountMembership => "Supported permission to add own account (conditional)",
                Tier0PathStepKind.WriteDacl => "Supported permission to change permissions",
                Tier0PathStepKind.CurrentOwnerDacl => "Supported owner permission-rewrite operation",
                _ => throw new InvalidDataException("Unrecognized saved path step."),
            };
            var witness = step.MembershipWitness is { } member
                ? $"Captured {member.Attribute}, occurrence {member.Ordinal:N0}."
                : edge is not null ? $"Saved permission #{edge.Id:N0}; inspect the retained permission assessment below."
                : "Saved own-account operation proof; not an observed membership change.";
            return new SavedPathStepViewModel($"{Tier0Presentation.Identity(step.From)} -> {Tier0Presentation.Identity(step.To)}: {relation}", witness);
        }).ToArray();
}
