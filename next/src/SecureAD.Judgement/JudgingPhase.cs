namespace SecureAD.Judgement;

/// <summary>Transient progress stages; these do not change stored judgement semantics or outcomes.</summary>
public enum JudgingPhase
{
    /// <summary>Reading captured objects and evaluating permissions and rules.</summary>
    EvaluatingObjects,
    /// <summary>Opening and validating the required captured and derived inputs.</summary>
    PreparingInputs,
    /// <summary>Producing explicitly budgeted member attribution, when requested.</summary>
    AttributingMembers,
    /// <summary>Evaluating and storing the separately scheduled requester assessments.</summary>
    EvaluatingRequesters,
    /// <summary>Writing final rule executions and findings.</summary>
    WritingFindings,
    /// <summary>Finalizing and sealing the judgement generation before publication.</summary>
    PublishingJudgement,
    /// <summary>Reading the published results for presentation.</summary>
    ReadingResults,
    /// <summary>Selecting automatic ownership targets from shared captured facts.</summary>
    SelectingOwnershipScope,
    /// <summary>Assessing hypothetical ownership only for automatically selected targets.</summary>
    AssessingOwnership,
}

/// <summary>The unit of observed work, never an authorization verdict or a completion percentage.</summary>
public enum JudgingWorkUnit
{
    /// <summary>Ownership targets whose assessment work was performed.</summary>
    OwnershipTargets,
    /// <summary>Relationships examined while selecting ownership scope.</summary>
    ScopeRelationships,
    /// <summary>Resources processed by the current operation.</summary>
    Resources,
    /// <summary>Path objects processed by the current operation.</summary>
    PathObjects,
    /// <summary>Distinct requester answers processed, separately from prerequisites and routes.</summary>
    RequesterAssessments,
    /// <summary>Candidate questions examined during selection, not distinct stored answers.</summary>
    QuestionsConsidered,
    /// <summary>Captured identities indexed for the current selection operation.</summary>
    IdentitiesIndexed,
}
