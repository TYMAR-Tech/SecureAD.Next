namespace SecureAD.Evidence;

/// <summary>
/// How completely a capture reconciled LDAP continuation references against its authorized plan.
/// </summary>
public enum ContinuationReconciliationOutcome
{
    /// <summary>No reconciliation result was supplied by the producer.</summary>
    NotPerformed,

    /// <summary>Every participating search could contribute references and every reference was readable.</summary>
    Complete,

    /// <summary>One or more searches suppressed references, or one or more references were unreadable.</summary>
    Incomplete,
}

/// <summary>
/// The persisted result of reconciling continuation references against the authorized capture plan.
/// </summary>
/// <param name="Outcome">Whether reconciliation was performed and complete.</param>
/// <param name="UnplannedNamingContexts">Readable naming contexts absent from the authorized plan.</param>
/// <param name="UnreadableReferences">References whose naming context could not be read.</param>
/// <param name="UnitsWithSuppressedReferrals">Naming contexts whose searches suppressed referrals.</param>
public sealed record ContinuationReconciliation(
    ContinuationReconciliationOutcome Outcome,
    IReadOnlyList<string> UnplannedNamingContexts,
    IReadOnlyList<string> UnreadableReferences,
    IReadOnlyList<string> UnitsWithSuppressedReferrals)
{
    /// <summary>Whether reconciliation was performed and whether every input was readable.</summary>
    public ContinuationReconciliationOutcome Completeness => Outcome;

    /// <summary>A truthful default for non-capture producers that did not perform reconciliation.</summary>
    public static ContinuationReconciliation NotPerformed { get; } =
        new(ContinuationReconciliationOutcome.NotPerformed, [], [], []);
}
