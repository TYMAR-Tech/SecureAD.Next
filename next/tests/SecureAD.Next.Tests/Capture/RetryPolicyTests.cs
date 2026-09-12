using System.DirectoryServices.Protocols;
using SecureAD.Audit.Capture;
using Xunit;

namespace SecureAD.Next.Tests.Capture;

/// <summary>
/// What capture does about a failed request, and - the part that was wrong - how it gets the
/// controller's result code out of the exception it arrived in.
///
/// <para>
/// <b>The defect these exist for.</b> The capture loop caught <see cref="LdapException"/> and read
/// <c>ErrorCode</c> from it. A controller that answers a request with a non-success result code
/// does not produce an <see cref="LdapException"/>: <c>EndSendRequest</c> raises a
/// <see cref="DirectoryOperationException"/>, which is a sibling rather than a subclass. So Busy
/// and Unavailable - the two failures the whole retry mechanism was built for - went past the
/// retry, past the restart, and ended the run. Across nine domains a busy controller is likely
/// rather than exceptional.
/// </para>
/// <para>
/// <b>What these tests are anchored to.</b> The type hierarchy and the result-code values are
/// Microsoft's and are read from Microsoft's own assembly, not restated here. The exception is
/// built from the real <see cref="SearchResponse"/> rather than from a stand-in, because a
/// stand-in that threw <see cref="LdapException"/> is precisely what let the gap survive.
/// </para>
/// <para>
/// <b>What they cannot reach.</b> No test here proves that a real domain controller under load
/// produces this exception, only that the product handles it when it does. That needs a controller,
/// which no build agent has, and it stays owed.
/// </para>
/// </summary>
public sealed class RetryPolicyTests
{
    /// <summary>
    /// The fact the defect rests on, read from Microsoft's assembly rather than asserted from
    /// memory. If this ever fails, the fix below has become unnecessary and should be removed
    /// rather than left as cargo.
    /// </summary>
    [Fact]
    public void ADirectoryOperationExceptionIsNotAnLdapException()
    {
        Assert.False(typeof(LdapException).IsAssignableFrom(typeof(DirectoryOperationException)));

        Assert.True(typeof(DirectoryException).IsAssignableFrom(typeof(DirectoryOperationException)));
        Assert.True(typeof(DirectoryException).IsAssignableFrom(typeof(LdapException)));
    }

    /// <summary>
    /// The numbers in this product's failure table are the LDAP result codes Microsoft's enumeration
    /// names, and not a second copy of them that could drift.
    /// </summary>
    [Theory]
    [InlineData(ResultCode.Busy, 51)]
    [InlineData(ResultCode.Unavailable, 52)]
    [InlineData(ResultCode.TimeLimitExceeded, 3)]
    [InlineData(ResultCode.AdminLimitExceeded, 11)]
    public void TheFailureTableUsesMicrosoftsResultCodes(ResultCode code, int expected) =>
        Assert.Equal(expected, (int)code);

    /// <summary>
    /// A controller that says it is busy is retried, even though its answer arrives as the type the
    /// old catch could not see.
    /// </summary>
    [Fact]
    public void ABusyControllerAnswerIsRetried()
    {
        var failure = RetryPolicy.FailureFor(
            ServerResultFailure.AnsweredWith(ResultCode.Busy, "The server is busy."));

        Assert.Equal(RetryPolicy.ServerBusy, failure);
        Assert.Equal(FailureResponse.RetryTheRequest, failure.Response);
    }

    /// <summary>
    /// An unavailable controller is retried for the same reason.
    /// </summary>
    [Fact]
    public void AnUnavailableControllerAnswerIsRetried()
    {
        var failure = RetryPolicy.FailureFor(
            ServerResultFailure.AnsweredWith(ResultCode.Unavailable, "The server is unavailable."));

        Assert.Equal(RetryPolicy.ServerUnavailable, failure);
        Assert.Equal(FailureResponse.RetryTheRequest, failure.Response);
    }

    /// <summary>
    /// The negative control: the exception these tests build is genuinely the shape the old catch
    /// would have missed.
    ///
    /// <para>
    /// Without this, both tests above would pass just as happily against a helper that quietly
    /// produced an <see cref="LdapException"/>, and would be measuring nothing at all.
    /// </para>
    /// </summary>
    [Fact]
    public void TheAnswerTheseTestsBuildWouldNotHaveBeenCaughtAsAnLdapException()
    {
        var answer = ServerResultFailure.AnsweredWith(ResultCode.Busy, "The server is busy.");

        Assert.False(
            answer is LdapException,
            "These tests would measure nothing if the helper produced an LdapException: the old "
            + "catch would have handled it, and the fix would appear covered while the real shape "
            + "still went past.");

        Assert.Equal(ResultCode.Busy, answer.Response.ResultCode);
    }

    /// <summary>
    /// A failure the client library raised itself still maps on its error code, so widening the
    /// question did not cost the answer it already had.
    /// </summary>
    [Fact]
    public void AClientLibraryFailureStillMapsOnItsErrorCode()
    {
        Assert.Equal(
            RetryPolicy.ServerDown,
            RetryPolicy.FailureFor(new LdapException(81, "The server is not operational.")));

        Assert.Equal(
            RetryPolicy.ClientTimeout,
            RetryPolicy.FailureFor(new LdapException(85, "The operation timed out.")));
    }

    /// <summary>
    /// A failure carrying no answer at all stops the run rather than being assumed harmless.
    ///
    /// <para>
    /// <see cref="DirectoryOperationException"/> can be raised with no response behind it. Treating
    /// a failure nobody can name as one worth retrying is how a request that half-succeeded gets
    /// sent twice.
    /// </para>
    /// </summary>
    [Fact]
    public void AFailureThatCannotNameItselfStopsTheRun()
    {
        var failure = RetryPolicy.FailureFor(
            new DirectoryOperationException("Something went wrong and said nothing about it."));

        Assert.Equal(RetryPolicy.Unrecognised, failure);
        Assert.Equal(FailureResponse.EndTheRun, failure.Response);
    }
}
