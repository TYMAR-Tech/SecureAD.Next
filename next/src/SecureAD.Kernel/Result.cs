using System.Diagnostics.CodeAnalysis;

namespace SecureAD.Kernel;

/// <summary>
/// The outcome of an operation that can fail: either a value, or an <see cref="AuditError"/>
/// explaining why there is not one.
/// </summary>
/// <remarks>
/// <para>
/// This type exists to make reporting a structured failure unavoidable rather than optional.
/// An operation returning <c>Result&lt;T&gt;</c> cannot hand back a value without having decided
/// what happens when it cannot, and a caller cannot reach the value without acknowledging the
/// alternative.
/// </para>
/// <para>
/// That is the whole point, and it is worth stating plainly because the previous implementation
/// got everything else right and this wrong. It had the error envelope, the categories, the
/// severity, a formatter that forbade freeform codes, and thorough tests. It had no return type
/// that obliged anyone to use them, so nothing did, and every failure a user saw was an
/// interpolated exception message or a silent zero.
/// </para>
/// <para>
/// Exceptions remain correct for defects — a null argument, an invariant violation, a bug. This
/// type is for outcomes the operation is expected to encounter: a domain that will not answer, a
/// bundle that will not open. A rule of thumb: if a reasonable run can produce it, it is a
/// <c>Result</c>; if only a broken build can, it is an exception.
/// </para>
/// </remarks>
/// <typeparam name="T">The value produced when the operation succeeds.</typeparam>
public readonly struct Result<T>
{
    /// <summary>
    /// Reported when a <c>default(Result&lt;T&gt;)</c> is inspected. A default result is a
    /// programming defect rather than an outcome — it means a value was declared and never
    /// assigned from either factory. It is surfaced as a failure with a self-describing code
    /// rather than throwing, so it appears in output as a diagnosable error rather than as an
    /// exception from a property getter.
    /// </summary>
    private static readonly AuditError Uninitialized = AuditError.Create(
        ErrorCategory.Evidence,
        "UninitializedResult",
        ErrorSeverity.Failed,
        "A Result was read before being assigned from Success or Failure. This is a defect in "
        + "the calling code, not a failure of the operation.",
        context: null);

    private readonly T _value;
    private readonly AuditError? _error;
    private readonly bool _isSuccess;

    private Result(T value)
    {
        _value = value;
        _error = null;
        _isSuccess = true;
    }

    private Result(AuditError error)
    {
        _value = default!;
        _error = error;
        _isSuccess = false;
    }

    /// <summary>The failure, or <c>null</c> if the operation succeeded.</summary>
    public AuditError? Error => _isSuccess ? null : (_error ?? Uninitialized);

    /// <summary>Whether the operation produced a value.</summary>
    /// <remarks>
    /// False for <c>default(Result&lt;T&gt;)</c>. <c>Result&lt;T&gt;</c> is a struct, so the
    /// default value is reachable without going through either factory, and the dangerous
    /// reading of it is "succeeded with no value". Success is tracked explicitly so that
    /// reading is impossible.
    /// </remarks>
    [MemberNotNullWhen(false, nameof(Error))]
    public bool IsSuccess => _isSuccess;

    /// <summary>
    /// The value. Throws if the operation failed, so callers must test <see cref="IsSuccess"/>
    /// or use <see cref="Match{TOut}"/> first.
    /// </summary>
    /// <exception cref="InvalidOperationException">The operation failed.</exception>
    public T Value => IsSuccess
        ? _value
        : throw new InvalidOperationException(
            $"Result was a failure ({Error.Code}) and has no value. Test IsSuccess first.");

    /// <summary>Creates a successful result.</summary>
    public static Result<T> Success(T value) => new(value);

    /// <summary>Creates a failed result.</summary>
    public static Result<T> Failure(AuditError error)
    {
        ArgumentNullException.ThrowIfNull(error);
        return new Result<T>(error);
    }

    /// <summary>
    /// Collapses both outcomes into a single value, so neither branch can be forgotten.
    /// </summary>
    /// <typeparam name="TOut">The type both branches produce.</typeparam>
    /// <param name="onSuccess">Invoked with the value when the operation succeeded.</param>
    /// <param name="onFailure">Invoked with the error when it did not.</param>
    public TOut Match<TOut>(Func<T, TOut> onSuccess, Func<AuditError, TOut> onFailure)
    {
        ArgumentNullException.ThrowIfNull(onSuccess);
        ArgumentNullException.ThrowIfNull(onFailure);

        return IsSuccess ? onSuccess(_value) : onFailure(Error);
    }

    /// <summary>Implicitly wraps a value as a successful result.</summary>
    public static implicit operator Result<T>(T value) => Success(value);

    /// <summary>Implicitly wraps an error as a failed result.</summary>
    public static implicit operator Result<T>(AuditError error) => Failure(error);
}
