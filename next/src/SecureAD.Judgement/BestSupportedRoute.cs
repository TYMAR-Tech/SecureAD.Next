using SecureAD.Derivation;

namespace SecureAD.Judgement;

public enum RouteEvidenceClass { Definite, Possible }
public enum RouteFeasibility { Direct, Conditional, Potential }
public enum RouteConfidence { Low, Medium, High }
internal enum RouteSourceKind { FixedTarget, Membership, Terminal, Requester, OwnAccount, MembershipDacl }
public enum RouteGradingLimitation { MembershipAssumptionUnavailable, UnsupportedStep }

/// <summary>A modeled condition, not an assertion that an operation or authentication happened.</summary>
public sealed record RouteCondition(string Kind, Tier0Target Requester, Tier0Target Group, string? ResourceContext);

public sealed record SupportedRouteGrade(RouteEvidenceClass Evidence, RouteFeasibility Feasibility,
    IReadOnlyList<RouteCondition> UnmetConditions, RouteConfidence Confidence, int Length, string StableSignature)
{
    internal static SupportedRouteGrade Combine(IReadOnlyList<SupportedRouteGrade> steps, string signature) =>
        new(steps.Any(step => step.Evidence == RouteEvidenceClass.Possible) ? RouteEvidenceClass.Possible : RouteEvidenceClass.Definite,
            steps.Count == 0 ? RouteFeasibility.Direct : steps.Max(step => step.Feasibility),
            steps.SelectMany(step => step.UnmetConditions).DistinctBy(ConditionKey)
                .OrderBy(ConditionKey, StringComparer.Ordinal).ToArray(),
            steps.Count == 0 ? RouteConfidence.High : steps.Min(step => step.Confidence),
            checked(steps.Sum(step => step.Length)), signature);

    internal static int Compare(SupportedRouteGrade left, SupportedRouteGrade right)
    {
        var value = left.Evidence.CompareTo(right.Evidence);
        if (value != 0) return value;
        value = left.Feasibility.CompareTo(right.Feasibility);
        if (value != 0) return value;
        value = left.UnmetConditions.Count.CompareTo(right.UnmetConditions.Count);
        if (value != 0) return value;
        value = right.Confidence.CompareTo(left.Confidence);
        if (value != 0) return value;
        value = left.Length.CompareTo(right.Length);
        return value != 0 ? value : StringComparer.Ordinal.Compare(left.StableSignature, right.StableSignature);
    }

    internal static string ConditionKey(RouteCondition condition) =>
        condition.Kind + "\0" + condition.Requester.DistinguishedName.ToUpperInvariant() + "\0"
        + condition.Group.DistinguishedName.ToUpperInvariant() + "\0" + condition.ResourceContext?.ToUpperInvariant();
}

/// <summary>References the original saved proof, never a second copy of its permission evidence.</summary>
internal sealed record BestRouteCandidate(Tier0Target Subject, Tier0Target ReachedTarget, SupportedRouteGrade Grade,
    RouteSourceKind Source, long? ProofId, string? ProofFingerprint, Tier0PathStep? Terminal);

/// <summary>Counts evaluated candidate records, not distinct routes or exhaustive path enumeration.</summary>
internal sealed record BestRouteSelection(int Version, Guid GenerationId, Guid? DerivationGenerationId,
    string EvidenceSeal, string CalculationFingerprint, Tier0Target Subject, int CompleteCandidates,
    int UngradedCandidates, BestRouteCandidate? Best)
{
    public IReadOnlyList<RouteGradingLimitation> GradingLimitations { get; init; } = [];
}

internal sealed record SavedBestSupportedRoute(BestRouteSelection Selection, IReadOnlyList<Tier0PathStep> Steps,
    Tier0Coverage Coverage);
