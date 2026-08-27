namespace SecureAD.Evidence.Findings;

/// <summary>
/// The rules this product runs, as one list.
/// </summary>
/// <remarks>
/// <para>
/// <b>Written out rather than discovered.</b> <c>docs/decisions/0082</c> keeps the rule set out of
/// the customer's hands, and a set assembled by reflection is a set nobody can read off the page.
/// Adding a rule is a line here, which is a line in a diff a reviewer can be asked to look at.
/// </para>
/// <para>
/// <b>Here rather than in the shell, because the shell is not the only caller.</b> This list lived
/// in <c>JudgingLauncher</c> until 2026-08-26, which put the definition of what an audit *is* inside
/// the WPF project - so a command line judging a bundle overnight would have had to keep a second
/// copy. Two lists that can disagree about which rules ran is the kind of difference nobody notices
/// until a finding is missing from one of them, and the store records what was scheduled, so the
/// disagreement would be written down as fact.
/// </para>
/// <para>
/// <b>It is not the run's record of what happened.</b> This is the set offered to a judging;
/// <c>StoredRuleExecution</c> is what became of each one. A rule that is in this list and has no
/// execution record did not run, and the judgement store treats that as a run that did not complete
/// rather than as a forest with nothing wrong with it.
/// </para>
/// </remarks>
public static class RuleCatalogue
{
    /// <summary>
    /// Every rule a judging schedules, in no significant order.
    /// </summary>
    /// <remarks>
    /// Order does not matter: <c>JudgingRun</c> offers every object to every rule, and findings are
    /// sorted when they are read rather than as they are made.
    /// </remarks>
    public static IReadOnlyList<IRule> All { get; } =
    [
        new UnconstrainedDelegationOnAccount(),
        new UnconstrainedDelegationOnNonDomainController(),
    ];
}
