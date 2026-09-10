using System.Globalization;
using System.Resources;
using SecureAD.Derivation;

namespace SecureAD.Judgement;

/// <summary>Why a stored ownership count is a placeholder rather than a measurement.</summary>
public enum OwnershipCountLimit
{
    /// <summary>The number beside this was measured.</summary>
    None,
    /// <summary>No target was asked about, so nothing was counted; the holder view counts nothing.</summary>
    NoTargetRequested,
    /// <summary>The stored audit holds no ownership input, so no target has a countable row.</summary>
    OwnershipInputsUnavailable,
    /// <summary>The target has no stored row, so neither number was ever produced for it.</summary>
    TargetNotStored,
    /// <summary>The target was not assessed, so the stored zero records absence of work, not absence of findings.</summary>
    TargetNotAssessed,
}

/// <summary>
/// A stored ownership count that states whether it was measured, and when it was not, what prevented it.
/// </summary>
/// <remarks>
/// This exists because <c>0</c> arrives at a caller identically from four situations and means
/// something different in each: nobody asked about a target, the audit holds no ownership input, the
/// target has no stored row, and a target that was genuinely assessed and had nothing to report. Per
/// <c>docs/decisions/0004</c> a count the run cannot vouch for renders as unknown naming what
/// prevented it, which neither a bare <c>int</c> nor a nullable one can do.
/// </remarks>
public sealed record OwnershipAuditCount(int? Measured, OwnershipCountLimit Limit)
{
    /// <summary>A measured count, which is the only state whose number may be read as a finding.</summary>
    public static OwnershipAuditCount Of(int measured) => new(measured, OwnershipCountLimit.None);

    /// <summary>An unmeasured count, naming the condition responsible; never a zero.</summary>
    public static OwnershipAuditCount Unmeasured(OwnershipCountLimit limit) => limit == OwnershipCountLimit.None
        ? throw new ArgumentException(null, nameof(limit))
        : new(null, limit);

    /// <summary>Whether the number beside this was reached; false means the count was never produced.</summary>
    public bool IsComplete => Measured is not null && Limit == OwnershipCountLimit.None;
}

/// <summary>Stored automatic ownership coverage, separate from primitive permission coverage and on-demand results.</summary>
public sealed record OwnershipAuditCoverage(Guid GenerationId, string? Target, bool InputsAvailable,
    OwnershipScopeState? Selection, OwnershipAssessmentExecution? Execution, Tier0Coverage ScopeCoverage,
    OwnershipAuditCount CandidateCount, OwnershipAuditCount AssessedCount)
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
