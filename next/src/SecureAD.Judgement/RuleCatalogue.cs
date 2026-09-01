namespace SecureAD.Judgement;

/// <summary>
/// The executable rules this product schedules, as one written-out list.
/// </summary>
/// <remarks>
/// <para>
/// <b>Written out rather than discovered.</b> <c>docs/decisions/0082</c> keeps the rule set out of
/// the customer's hands, and a set assembled by reflection is a set nobody can read off the page.
/// Adding a rule is one line in a diff a reviewer can inspect.
/// </para>
/// <para>
/// <b>Owned by Judgement rather than Evidence or a caller.</b> Evidence owns durable rule and finding
/// data. Judgement owns which executable logic is scheduled. Keeping the list out of the Shell means
/// a GUI and command line cannot disagree about what an audit runs.
/// </para>
/// </remarks>
public static class RuleCatalogue
{
    /// <summary>Every executable rule a judging schedules, in no significant order.</summary>
    /// <remarks>
    /// <b>Adding a rule that reads derived facts changes what a judging requires.</b>
    /// <see cref="AdminCountWithoutProtection"/> declares
    /// <see cref="DerivedFactKind.ProtectedPrincipals"/>, so from here on a scheduled judging needs
    /// a derivation bound to the same evidence, and refuses without one per
    /// <c>docs/decisions/0091</c>. The Shell derives before it judges, so an audit is unaffected.
    /// </remarks>
    public static IReadOnlyList<IRule> All { get; } =
    [
        new UnconstrainedDelegationOnAccount(),
        new UnconstrainedDelegationOnNonDomainController(),
        new AdminCountWithoutProtection(),
        new NoKerberosPreauthentication(),
    ];
}
