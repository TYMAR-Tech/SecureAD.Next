namespace SecureAD.Kernel;

/// <summary>
/// The category an <see cref="AuditError"/> belongs to. One per subsystem that can surface a
/// failure to a user.
/// </summary>
/// <remarks>
/// Deliberately short. The previous implementation declared fourteen categories with a matching
/// error-code enum each; thirteen of the fourteen were referenced only by their own declaration
/// and a formatter overload, because nothing was ever obliged to produce one. A category is added
/// here when a subsystem actually surfaces a failure, not in anticipation of one.
/// </remarks>
public enum ErrorCategory
{
    /// <summary>Reading the directory during a capture.</summary>
    Capture,

    /// <summary>Reading or writing an evidence bundle.</summary>
    Evidence,

    /// <summary>
    /// The operator's own settings - where the run library is, and what else they have told this
    /// installation. Added when the shell began surfacing failures of its own, per the rule above:
    /// a category exists because something produces one.
    /// </summary>
    Shell,
}

/// <summary>
/// How much an error matters, and whether the operation can continue past it.
/// </summary>
public enum ErrorSeverity
{
    /// <summary>The operation continued and its result is usable, but something was lost.</summary>
    Degraded,

    /// <summary>The operation did not produce a result.</summary>
    Failed,
}

/// <summary>
/// A structured failure. The only way an operation in this product reports that it did not
/// succeed.
/// </summary>
/// <remarks>
/// <para>
/// The predecessor of this type existed, was well designed, carried a formatter that forbade
/// freeform code strings, and was covered by 250 lines of tests. It was constructed by no
/// production code at all. The reason was structural rather than negligent: every operation
/// returned a value, a <c>bool</c>, or threw, so producing a structured error was optional work
/// with no compiler pressure behind it — and optional work at two hundred call sites does not
/// happen.
/// </para>
/// <para>
/// This type is therefore only half of the mechanism. <see cref="Result{T}"/> is the other half,
/// and it is what makes producing one unavoidable.
/// </para>
/// </remarks>
/// <param name="Category">The subsystem the failure came from.</param>
/// <param name="Code">
/// A stable identifier, formatted <c>Category.Reason</c>. Built by <see cref="Create"/> so it
/// cannot be a freeform string.
/// </param>
/// <param name="Severity">Whether a result survived the failure.</param>
/// <param name="Description">What went wrong, in terms a reader of the audit would understand.</param>
/// <param name="Context">
/// The subject the failure was about — a distinguished name, a domain, a file path. May be null,
/// because some failures have no subject, but it is stated at every construction rather than
/// defaulted: gate 1 exists because a defaulted parameter is a decision nobody makes.
/// </param>
public sealed record AuditError(
    ErrorCategory Category,
    string Code,
    ErrorSeverity Severity,
    string Description,
    string? Context)
{
    /// <summary>
    /// Creates an error whose code is derived from its category and reason, so the two cannot
    /// drift apart and the code cannot be invented at the call site.
    /// </summary>
    /// <param name="category">The subsystem the failure came from.</param>
    /// <param name="reason">
    /// A short PascalCase reason, for example <c>DomainUnreachable</c>. Combined with
    /// <paramref name="category"/> to form the code.
    /// </param>
    /// <param name="severity">Whether a result survived the failure.</param>
    /// <param name="description">What went wrong.</param>
    /// <param name="context">The subject the failure was about, or null if it had none.</param>
    public static AuditError Create(
        ErrorCategory category,
        string reason,
        ErrorSeverity severity,
        string description,
        string? context)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(reason);
        ArgumentException.ThrowIfNullOrWhiteSpace(description);

        return new AuditError(category, $"{category}.{reason}", severity, description, context);
    }
}
