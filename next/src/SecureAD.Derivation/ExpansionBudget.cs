namespace SecureAD.Derivation;

/// <summary>
/// The limits an expansion runs under, and what it does when it reaches one.
/// </summary>
/// <remarks>
/// <para>
/// <b>The numbers come from the predecessor, which is the only place either project has measured
/// them.</b> Its bulk expansion budget was fifty levels of nesting, five hundred thousand node
/// visits and thirty minutes. Those exist because somebody hit them against a real forest, which
/// makes them worth more than anything invented here.
/// </para>
/// <para>
/// <b>They do not mean quite the same thing now, and the difference is the point.</b> The
/// predecessor expanded each group from scratch, so a node visited while expanding one group was
/// visited again for every group above it, and its five hundred thousand visits were consumed
/// largely by ground already covered. Here each component is expanded once, so the comparable count
/// is closer to the number of principals. The budget below is therefore over <i>emitted closure
/// entries</i> rather than visits: that is the quantity that can genuinely run away, because it is
/// the size of the answer rather than the cost of computing it.
/// </para>
/// <para>
/// <b>There is no depth budget, deliberately.</b> The predecessor needed one because a per-group
/// traversal following a cycle does not stop on its own. This expansion condenses cycles before it
/// walks anything, so it terminates by construction, and a depth limit could only cut off a legal
/// answer. Nesting depth is still worth reporting; it is not a termination guard.
/// </para>
/// </remarks>
/// <param name="MaxClosureEntries">
/// How many (group, member) pairs may be produced before the expansion stops and reports itself
/// incomplete.
/// </param>
/// <param name="MaxTime">How long the expansion may run.</param>
public sealed record ExpansionBudget(int MaxClosureEntries, TimeSpan MaxTime)
{
    /// <summary>
    /// The budget for deriving a whole bundle, carried over from the predecessor's bulk expansion.
    /// </summary>
    public static ExpansionBudget Bulk { get; } = new(500_000, TimeSpan.FromMinutes(30));
}

/// <summary>
/// Why an expansion stopped short, when it did.
/// </summary>
public enum ExpansionLimit
{
    /// <summary>It did not stop short.</summary>
    None,

    /// <summary>It produced as many closure entries as it was allowed to.</summary>
    MaxClosureEntriesReached,

    /// <summary>It ran for as long as it was allowed to.</summary>
    MaxTimeReached,
}
