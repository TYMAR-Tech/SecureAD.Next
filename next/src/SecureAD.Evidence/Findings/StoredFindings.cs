namespace SecureAD.Evidence.Findings;

/// <summary>
/// One rule that was run over a bundle, at the version of its logic that ran.
/// </summary>
/// <param name="RuleId">The rule, such as <c>SEC-011</c>.</param>
/// <param name="RuleVersion">The version of its logic that ran.</param>
public sealed record EvaluatedRule(string RuleId, int RuleVersion);

/// <summary>
/// The findings a bundle carries, together with the rules that were run to produce them.
/// </summary>
/// <remarks>
/// <para>
/// <b>The second list is why this type exists.</b> A list of findings on its own cannot say whether
/// anyone looked: no findings and no rules run means a bundle nobody has judged, and no findings
/// beside a list of rules that did run means a forest where nothing matched. Those are opposite
/// answers to the question a customer is actually asking, and a bare
/// <c>IReadOnlyList&lt;Finding&gt;</c> hands both to a screen in the same shape - which is the
/// failure <c>docs/decisions/0002</c> forbids and the reason gate 4 rejects an unvouched
/// collection.
/// </para>
/// <para>
/// An earlier version of this code returned the bare list and carried the warning in an XML comment
/// instead. That put the guarantee somewhere a caller cannot see it: the comment is invisible at
/// the call site, and the type still made "nothing was found" the easiest thing to write.
/// </para>
/// </remarks>
/// <param name="Findings">What the rules found. Empty is meaningful only beside <paramref name="RulesRun"/>.</param>
/// <param name="RulesRun">The rules that were run over this bundle.</param>
public sealed record StoredFindings(
    IReadOnlyList<Finding> Findings,
    IReadOnlyList<EvaluatedRule> RulesRun)
{
    /// <summary>
    /// Whether this bundle was never judged, so its findings say nothing about the forest.
    /// </summary>
    /// <remarks>
    /// <b>A caller must consult this before reporting that nothing was found.</b> Capture and
    /// evaluation are separate acts, so a captured bundle that no rule has been run over is an
    /// ordinary state and not an error - but it is not a clean forest, and presenting it as one
    /// tells a customer their directory is sound on the strength of a question nobody asked.
    /// </remarks>
    public bool DidNotRun => RulesRun.Count == 0;
}
