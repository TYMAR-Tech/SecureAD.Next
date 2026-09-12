namespace SecureAD.Audit.Capture;

/// <summary>
/// What capture does when a directory request fails.
/// </summary>
/// <remarks>
/// The three answers are ordered by cost, and the reason there are three rather than two is the
/// paging bookmark. A failure that leaves the conversation with the controller intact can be
/// retried where it stands. A failure that ends the conversation takes the bookmark with it, and
/// there is no way to resume a paged read from the middle - so the choice is between reading the
/// partition again from the start and stopping.
/// </remarks>
public enum FailureResponse
{
    /// <summary>
    /// Send the same request again on the same connection. The controller is still there and the
    /// bookmark is still good; it was busy, or momentarily unwilling.
    /// </summary>
    RetryTheRequest,

    /// <summary>
    /// Read this naming context again from its first page, on a fresh connection.
    /// <para>
    /// Everything read in the abandoned attempt is discarded rather than merged, because the two
    /// attempts overlap and merging them would write objects twice. Re-reading costs time and
    /// costs nothing else: a capture is not a frozen instant in the first place - it is read page
    /// by page over minutes, and the forest changes underneath it - so a partition read from the
    /// start at 02:10 is no less accurate than one read from 02:00.
    /// </para>
    /// </summary>
    RestartTheUnit,

    /// <summary>
    /// Stop, naming the naming context and the point reached. Capture is fail-fast: a forest is
    /// only readable as it stands today, and a run that quietly delivered part of one would be
    /// presenting a fraction of a forest as the whole of it.
    /// </summary>
    EndTheRun,
}

/// <summary>
/// One way a directory request can fail, and what capture does about it.
/// </summary>
/// <param name="Name">The failure's name in the LDAP result codes.</param>
/// <param name="ResultCode">
/// The numeric code, as it arrives on <c>LdapException.ErrorCode</c>. Codes up to 80 are the
/// protocol's own result codes; above that they are the client library's, reporting a failure that
/// never reached a server.
/// </param>
/// <param name="FirstWait">
/// How long to wait before the first further attempt. Doubles each time. Zero where the response
/// is to stop, since nothing is waited for.
/// </param>
/// <param name="Response">What capture does.</param>
/// <param name="WhatItMeans">What the failure is telling the client.</param>
/// <param name="WhatCaptureDoes">The response in words, including why it is that one.</param>
public sealed record DirectoryFailure(
    string Name,
    int ResultCode,
    TimeSpan FirstWait,
    FailureResponse Response,
    string WhatItMeans,
    string WhatCaptureDoes);

/// <summary>
/// What capture does when a request to a domain controller fails.
/// </summary>
/// <remarks>
/// <para>
/// This is the second half of inventory row B7, and docs/layers/audit/limits-and-failures.md was the
/// document bound to it. The policy is decided here; the loop that applies it is inventory row B6.
/// </para>
/// <para>
/// <b>Why retry at all, when capture is fail-fast.</b> Because fail-fast is what makes retry
/// valuable rather than what makes it unnecessary. A run that ends on the first stalled request
/// throws away everything read so far, and a forest is minutes of work against a production server
/// somebody has to schedule. Three attempts at a request the controller was merely too busy to
/// answer costs seconds and saves the run.
/// </para>
/// <para>
/// <b>Why not more than three, and why the wait doubles.</b> Two of these failures - busy and
/// unavailable - are a controller saying it is under load or shutting down. Retrying hard against
/// a server that has just said so is the one case where retrying makes the situation worse rather
/// than better, which is why the first wait for those is the longest and why the attempts are few.
/// </para>
/// <para>
/// <b>What is deliberately not here.</b> There is no resume. A paged read cannot be picked up from
/// the middle: the bookmark only means something inside one live conversation with one controller,
/// and LDAP has no way to say "carry on from object forty thousand". Anything that appeared to
/// resume would be a partial read reported as complete, which is the failure this whole component
/// exists to prevent.
/// </para>
/// </remarks>
public static class RetryPolicy
{
    /// <summary>
    /// How many times one request is sent before its failure is treated as the unit's failure.
    /// Three: the original and two more.
    /// </summary>
    public const int MaxAttemptsPerRequest = 3;

    /// <summary>
    /// How many times a naming context is read again from the start before the run ends. One.
    /// </summary>
    /// <remarks>
    /// One gives a network blip a free recovery. A second would be a loop with a plausible excuse,
    /// and a capture that restarts a nine-million-object partition repeatedly is worse for the
    /// customer than one that stops and says why.
    /// </remarks>
    public const int MaxRestartsPerUnit = 1;

    /// <summary>The controller is under load and declined to answer.</summary>
    public static DirectoryFailure ServerBusy { get; } = new(
        "Busy",
        51,
        TimeSpan.FromSeconds(5),
        FailureResponse.RetryTheRequest,
        "The server is busy. The conversation is intact; the controller declined this one request.",
        "Waits and asks again, up to three attempts. The wait starts long and doubles, because a "
        + "controller that has just said it is busy is the last one to ask again immediately.");

    /// <summary>The controller is not accepting work.</summary>
    public static DirectoryFailure ServerUnavailable { get; } = new(
        "Unavailable",
        52,
        TimeSpan.FromSeconds(5),
        FailureResponse.RetryTheRequest,
        "The server is unavailable - typically shutting down, or refusing work while it starts.",
        "Waits and asks again, as for Busy. If it does not recover within three attempts the "
        + "controller is genuinely gone, and the unit's failure carries that rather than a "
        + "timeout nobody can interpret.");

    /// <summary>The connection to the controller is gone.</summary>
    public static DirectoryFailure ServerDown { get; } = new(
        "ServerDown",
        81,
        TimeSpan.FromSeconds(5),
        FailureResponse.RestartTheUnit,
        "The client could not reach the server at all. This is the client library reporting a "
        + "failure that never got to a controller, so the connection - and the paging bookmark "
        + "held inside it - is gone.",
        "Reconnects and reads the naming context again from its first page. Retrying the request "
        + "would send a bookmark the controller has no memory of.");

    /// <summary>The client stopped waiting.</summary>
    public static DirectoryFailure ClientTimeout { get; } = new(
        "Timeout",
        85,
        TimeSpan.FromSeconds(5),
        FailureResponse.RestartTheUnit,
        "The client's own time limit elapsed before an answer arrived. Whether the controller is "
        + "still working on the request, and whether it still holds the paging state behind it, "
        + "is not knowable from the client.",
        "Treated as though the conversation ended, and the naming context is read again from the "
        + "start. Reusing a bookmark whose server-side state may or may not still exist is the "
        + "kind of guess that produces a partial capture nobody can detect.");

    /// <summary>One page took longer than the controller allows a search to run.</summary>
    public static DirectoryFailure TimeLimitExceeded { get; } = new(
        "TimeLimitExceeded",
        3,
        TimeSpan.Zero,
        FailureResponse.EndTheRun,
        "The controller's own time limit for a single search was reached. Under paging that limit "
        + "applies to one page, so this says the page asked for was too expensive to assemble.",
        "Stops. Sending the identical request again meets the identical limit, so retrying is a "
        + "loop with a wait in it. The real remedy is a smaller page, which is a change to how the "
        + "loop asks rather than a response to a failure, and belongs to inventory row B6.");

    /// <summary>The controller's administrative limit was reached.</summary>
    public static DirectoryFailure AdminLimitExceeded { get; } = new(
        "AdminLimitExceeded",
        11,
        TimeSpan.Zero,
        FailureResponse.EndTheRun,
        "A limit set in the controller's LDAP policy was reached.",
        "Stops, and the failure names the limit. This is a configuration mismatch between the "
        + "product and the forest, and it will be reached again on every attempt.");

    /// <summary>Anything else.</summary>
    public static DirectoryFailure Unrecognised { get; } = new(
        "Unrecognised",
        -1,
        TimeSpan.Zero,
        FailureResponse.EndTheRun,
        "A failure this policy has no entry for.",
        "Stops. An unrecognised failure is not assumed to be harmless: retrying something nobody "
        + "has reasoned about is how a request that half-succeeded gets sent twice.");

    /// <summary>
    /// What to do about a failure, given the code it arrived with.
    /// </summary>
    /// <remarks>
    /// Always answers. An unknown code returns <see cref="Unrecognised"/> rather than nothing, so
    /// there is no state in which a caller has a failure and no instruction - which is the shape
    /// that produces a swallowed exception.
    /// </remarks>
    /// <param name="ldapErrorCode">The value of <c>LdapException.ErrorCode</c>.</param>
    public static DirectoryFailure FailureFor(int ldapErrorCode)
    {
        foreach (var failure in Known)
        {
            if (failure.ResultCode == ldapErrorCode)
                return failure;
        }

        return Unrecognised;
    }

    /// <summary>
    /// How long to wait before <paramref name="attempt"/>, counting the first send as attempt one.
    /// </summary>
    /// <param name="failure">The failure that prompted the wait.</param>
    /// <param name="attempt">The attempt about to be made. Two or more.</param>
    public static TimeSpan WaitBefore(DirectoryFailure failure, int attempt)
    {
        ArgumentNullException.ThrowIfNull(failure);
        ArgumentOutOfRangeException.ThrowIfLessThan(attempt, 2);

        return failure.FirstWait * Math.Pow(2, attempt - 2);
    }

    private static readonly DirectoryFailure[] Known =
    [
        ServerBusy, ServerUnavailable, ServerDown, ClientTimeout, TimeLimitExceeded,
        AdminLimitExceeded,
    ];
}
