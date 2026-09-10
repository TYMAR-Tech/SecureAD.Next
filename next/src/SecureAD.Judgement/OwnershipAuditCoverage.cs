using System.Globalization;
using System.Resources;
using SecureAD.Derivation;

namespace SecureAD.Judgement;

/// <summary>Stored automatic ownership coverage, separate from primitive permission coverage and on-demand results.</summary>
public sealed record OwnershipAuditCoverage(Guid GenerationId, string? Target, bool InputsAvailable,
    OwnershipScopeState? Selection, OwnershipAssessmentExecution? Execution, Tier0Coverage ScopeCoverage,
    int CandidateCount, int AssessedCount)
{
    private static readonly ResourceManager Resources = new("SecureAD.Judgement.Resources.OwnershipAudit", typeof(OwnershipAuditCoverage).Assembly);

    /// <summary>The approved passive status wording; this performs no assessment or persistence.</summary>
    public string Description
    {
        get
        {
            var message = Target is null ? Text("HolderView") : !InputsAvailable ? Text("InputsUnavailable")
                : Execution is OwnershipAssessmentExecution.Completed or OwnershipAssessmentExecution.CompletedWithLimitations
                    ? Text("Assessed") : Text("NotAssessed");
            return ScopeCoverage.IsComplete ? message : message + " " + Text("Incomplete");
        }
    }

    internal static string Text(string key) => Resources.GetString(key, CultureInfo.CurrentUICulture)
        ?? throw new MissingManifestResourceException(key);
}
