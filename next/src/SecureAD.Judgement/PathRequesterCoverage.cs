namespace SecureAD.Judgement;

/// <summary>Selects captured questions, never permission semantics or a processing ceiling.</summary>
public enum PathRequesterPolicy
{
    /// <summary>No automatic path requester questions are scheduled.</summary>
    Disabled,
    /// <summary>Select the three existing bounded families from sealed permissions and shared targets.</summary>
    SupportedCapturedQuestions,
}

/// <summary>What the saved selection accomplished, not forest-wide coverage or reachability.</summary>
public enum PathRequesterCoverageState
{
    /// <summary>No automatic selection was requested; explicit saved questions remain separate.</summary>
    NotRequested,
    /// <summary>Selection was requested but required saved inputs were unavailable.</summary>
    InputsUnavailable,
    /// <summary>The supported input scan and its selected questions finished, with limitations retained.</summary>
    EvaluatedSupportedQuestions,
}

/// <summary>Diagnostic work boundaries; these do not change screen phases or permission outcomes.</summary>
public enum PathRequesterWorkPhase
{
    /// <summary>Read and validate saved path inputs and calculate existing routes.</summary>
    PreparingPaths,
    /// <summary>Select source-backed questions, without deciding their answers.</summary>
    SelectingQuestions,
    /// <summary>Prepare shared targets and evaluate captured requester DACL questions.</summary>
    RequesterDacl,
    /// <summary>Prepare pre-change membership answers and evaluate their existing continuations.</summary>
    OwnAccountMembership,
    /// <summary>Evaluate obtained membership followed by requester DACL authorization.</summary>
    MembershipDacl,
    /// <summary>Finalize saved proof references, coverage and route selections.</summary>
    WritingProofs,
}

/// <summary>
/// Counts of distinct questions and saved answers, not members, routes or group-held permissions.
/// UnresolvedResults counts the family's authorization/obtainability outcome; unknown current
/// membership and ordinary operation readiness remain independent, including on established routes.
/// </summary>
public sealed record PathRequesterFamilyCoverage(PathRequesterFamily Family, int SelectedQuestions,
    int StoredAssessments, int UnresolvedResults, int UnknownCurrentMembership, int UnknownOperationReadiness);

/// <summary>Saved whole-run counters for completion checks, without loading individual proof or limitation records.</summary>
public sealed record PathRequesterSummary(string EvidenceSeal, Guid? DerivationGenerationId, Guid JudgementGenerationId,
    PathInputAvailability InputAvailability, int? SelectionVersion, bool InputScanCompleted,
    IReadOnlyList<PathRequesterFamilyCoverage> Families, int InputUncertaintyCount, int SelectionLimitationCount)
{
    /// <summary>Whether automatic selection was requested, not whether every possible path was assessed.</summary>
    public bool SelectionRequested => SelectionVersion.HasValue;
    /// <summary>Execution status only; the saved limitations still apply.</summary>
    public PathRequesterCoverageState Verdict => State(SelectionRequested, InputScanCompleted);

    internal static PathRequesterCoverageState State(bool requested, bool completed) => !requested
        ? PathRequesterCoverageState.NotRequested : completed
            ? PathRequesterCoverageState.EvaluatedSupportedQuestions : PathRequesterCoverageState.InputsUnavailable;
}

/// <summary>
/// Passive projection of the saved selection and reconciled proof batches in one exact input generation.
/// No completeness or safety verdict is inferred from zero questions or a finished supported scan.
/// Failed, cancelled or interrupted attempts are not published over this result.
/// </summary>
internal sealed record PathRequesterCoverage(string EvidenceSeal, Guid? DerivationGenerationId,
    SavedPathInputs Inputs, int? SelectionVersion, bool InputScanCompleted,
    IReadOnlyList<PathRequesterFamilyCoverage> Families, IReadOnlyList<PathRequesterSelectionLimitation> Limitations)
{
    /// <summary>Builds saved coverage from complete production inputs while writing or testing.</summary>
    public PathRequesterCoverage(string evidenceSeal, Guid? derivationGenerationId, PathInputs inputs,
        int? selectionVersion, bool inputScanCompleted, IReadOnlyList<PathRequesterFamilyCoverage> families,
        IReadOnlyList<PathRequesterSelectionLimitation> limitations)
        : this(evidenceSeal, derivationGenerationId, SavedPathInputs.From(inputs), selectionVersion,
            inputScanCompleted, families, limitations)
    {
    }

    /// <summary>Whether automatic selection was recorded, independently of explicit requester proofs.</summary>
    public bool SelectionRequested => SelectionVersion.HasValue;

    /// <summary>Selection execution status; limitations still apply to a finished supported scan.</summary>
    public PathRequesterCoverageState Verdict => PathRequesterSummary.State(SelectionRequested, InputScanCompleted);
}
