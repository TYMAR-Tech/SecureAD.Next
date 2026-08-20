using SecureAD.Kernel;
using Xunit;

namespace SecureAD.Next.Tests.Kernel;

public sealed class AuditErrorTests
{
    [Fact]
    public void CreateDerivesTheCodeFromTheCategoryAndReason()
    {
        var error = AuditError.Create(
            ErrorCategory.Capture, "DomainUnreachable", ErrorSeverity.Degraded, "No DC answered.",
            context: "contoso.example");

        Assert.Equal("Capture.DomainUnreachable", error.Code);
    }

    [Fact]
    public void CreateRejectsAnEmptyReason()
    {
        Assert.Throws<ArgumentException>(() => AuditError.Create(
            ErrorCategory.Evidence, "  ", ErrorSeverity.Failed, "Bundle would not open.",
            context: null));
    }

    [Fact]
    public void CreateRejectsAnEmptyDescription()
    {
        Assert.Throws<ArgumentException>(() => AuditError.Create(
            ErrorCategory.Evidence, "OpenFailed", ErrorSeverity.Failed, "  ", context: null));
    }

    [Fact]
    public void ContextIsNullWhenAFailureHasNoSubject()
    {
        var error = AuditError.Create(
            ErrorCategory.Evidence, "OpenFailed", ErrorSeverity.Failed, "Bundle would not open.",
            context: null);

        Assert.Null(error.Context);
    }
}

public sealed class ResultTests
{
    [Fact]
    public void ASuccessfulResultCarriesItsValue()
    {
        var result = Result<int>.Success(42);

        Assert.Equal(42, result.Value);
    }

    [Fact]
    public void ASuccessfulResultHasNoError()
    {
        var result = Result<int>.Success(42);

        Assert.Null(result.Error);
    }

    [Fact]
    public void AFailedResultIsNotSuccessful()
    {
        var result = Result<int>.Failure(Failure());

        Assert.False(result.IsSuccess);
    }

    [Fact]
    public void ReadingTheValueOfAFailedResultThrowsAndNamesTheCode()
    {
        var result = Result<int>.Failure(Failure());

        var ex = Assert.Throws<InvalidOperationException>(() => result.Value);
        Assert.Contains("Capture.DomainUnreachable", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void FailureRejectsANullError()
    {
        Assert.Throws<ArgumentNullException>(() => Result<int>.Failure(null!));
    }

    [Fact]
    public void MatchTakesTheSuccessBranchWhenThereIsAValue()
    {
        var result = Result<int>.Success(7);

        Assert.Equal("7", result.Match(v => v.ToString(), e => e.Code));
    }

    [Fact]
    public void MatchTakesTheFailureBranchWhenThereIsAnError()
    {
        var result = Result<int>.Failure(Failure());

        Assert.Equal("Capture.DomainUnreachable", result.Match(v => v.ToString(), e => e.Code));
    }

    [Fact]
    public void AValueConvertsImplicitlyToASuccessfulResult()
    {
        Result<int> result = 42;

        Assert.True(result.IsSuccess);
    }

    [Fact]
    public void AnErrorConvertsImplicitlyToAFailedResult()
    {
        Result<int> result = Failure();

        Assert.False(result.IsSuccess);
    }

    /// <summary>
    /// A default-constructed Result is a failure rather than a success carrying default(T).
    /// Asserted because <c>Result&lt;T&gt;</c> is a struct, so <c>default</c> is reachable
    /// without going through either factory, and the dangerous reading of that is "succeeded
    /// with no value". The first version of the type had exactly that defect and this test
    /// found it.
    /// </summary>
    [Fact]
    public void ADefaultResultIsNotMistakenForSuccess()
    {
        Result<string> result = default;

        Assert.False(result.IsSuccess);
    }

    [Fact]
    public void ADefaultResultReportsASelfDescribingError()
    {
        Result<string> result = default;

        Assert.Equal("Evidence.UninitializedResult", result.Error?.Code);
    }

    [Fact]
    public void ADefaultResultTakesTheFailureBranchOfMatch()
    {
        Result<string> result = default;

        Assert.Equal("failed", result.Match(_ => "ok", _ => "failed"));
    }

    private static AuditError Failure() => AuditError.Create(
        ErrorCategory.Capture, "DomainUnreachable", ErrorSeverity.Failed, "No DC answered.",
        context: null);
}
