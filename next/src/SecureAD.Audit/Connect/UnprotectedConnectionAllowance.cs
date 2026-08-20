namespace SecureAD.Audit.Connect;

/// <summary>
/// Whether this run was declared permitted to read a controller over an unprotected connection.
/// </summary>
/// <remarks>
/// <para>
/// Per <c>docs/decisions/0018-connection-security-is-an-ordered-ladder.md</c> the bottom rung of the
/// ladder is never reached automatically. It is reached only where somebody said, before the run
/// started, that this run may use one.
/// </para>
/// <para>
/// <b>Why this is a type and not a boolean parameter.</b> Two reasons, and the second is the one
/// that matters. A boolean argument at a call site reads as <c>true</c> with nothing beside it
/// saying what was agreed to. And a declaration carries a reason - the auditor's own words about
/// why this forest is being read this way - which travels with the run into the finding it
/// produces. A flag has nowhere to put that.
/// </para>
/// <para>
/// <b>It is never persisted.</b> Nothing writes this to a file, a registry key or a settings store,
/// and nothing reads it from one. A persisted allowance is one somebody turned on once and nobody
/// has thought about since, which is the failure this product has already deleted a batch of
/// settings for. It is stated when a run is started and it dies with the run.
/// </para>
/// <para>
/// <b>Declaring it does not make the run quiet.</b> A controller that accepts nothing better is a
/// finding about the customer's forest either way, and a run that used the bottom rung says so on
/// its report. The allowance decides whether the run proceeds, not whether it discloses.
/// </para>
/// </remarks>
public sealed class UnprotectedConnectionAllowance
{
    private UnprotectedConnectionAllowance(bool declared, string reason)
    {
        IsDeclared = declared;
        Reason = reason;
    }

    /// <summary>
    /// The default: this run reads nothing over an unprotected connection, and a controller that
    /// accepts nothing better ends the run.
    /// </summary>
    /// <remarks>
    /// Named rather than reached by omission. A run that refuses has refused deliberately, and the
    /// call site says so.
    /// </remarks>
    public static UnprotectedConnectionAllowance Refused { get; } =
        new(declared: false, reason: "No unprotected connection was permitted for this run.");

    /// <summary>Whether the bottom rung of the ladder may be attempted.</summary>
    public bool IsDeclared { get; }

    /// <summary>
    /// What was declared, in the auditor's words, or the standing refusal. Carried into the finding
    /// so that a report can say why rather than only what.
    /// </summary>
    public string Reason { get; }

    /// <summary>
    /// Declares that this run may read a controller over an unprotected connection.
    /// </summary>
    /// <param name="reason">
    /// Why, in the auditor's own words. Required and non-empty: an allowance with no stated reason
    /// is the persisted setting this decision exists to avoid, reached by a different route.
    /// </param>
    public static UnprotectedConnectionAllowance DeclaredFor(string reason)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(reason);

        return new UnprotectedConnectionAllowance(declared: true, reason.Trim());
    }
}
