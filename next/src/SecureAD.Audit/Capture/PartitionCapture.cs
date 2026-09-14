using System.DirectoryServices.Protocols;
using System.Globalization;
using SecureAD.Evidence;
using SecureAD.Kernel;
using SecureAD.Kernel.Capture;

namespace SecureAD.Audit.Capture;

/// <summary>
/// Reads one naming context whole: issue a search, take a page, ask for the next, and know when the
/// controller has nothing left to send.
/// </summary>
/// <remarks>
/// <para>
/// This is inventory row B6, and docs/layers/audit/how-a-controller-is-read.md was the document bound to
/// it. It is the first component in the rebuild that does anything to a customer's directory rather
/// than describing what would be done.
/// </para>
/// <para>
/// <b>The failure it exists not to have.</b> A paged search ends when the controller returns an
/// empty bookmark. A client that chased a subordinate referral mid-search has that bookmark
/// overwritten inside the LDAP runtime, reads an empty one on the first page, and stops - reporting
/// success. A thousand objects out of nine million, no error anywhere, and every silence in the
/// resulting report meaningless. Nothing in the response tells the two apart, because on the wire
/// the controller sent a perfectly good bookmark and the client library discarded it. So this loop
/// does not try to detect it. It refuses to make the claim at all unless it has been told, by the
/// connection, that nothing could have been chased.
/// </para>
/// <para>
/// <b>There is one successful outcome and it is a type.</b> A partition read whole produces a
/// <see cref="PartitionCoverage"/>. Everything else produces an <c>AuditError</c> and ends the run,
/// because capture is fail-fast and a partition it cannot read fully produces no bundle. There is
/// no partial success and nothing that has to be checked afterwards.
/// </para>
/// </remarks>
public sealed class PartitionCapture
{
    /// <summary>
    /// The name every line about reading a forest is recorded under.
    /// </summary>
    /// <remarks>
    /// One name for the whole stage rather than one per component, so that an operator looking for
    /// what a capture did greps for a single word. The message on each line says which part of it
    /// this was.
    /// </remarks>
    public const string PhaseName = "Capture";

    private readonly IDirectoryChannelFactory _connections;
    private readonly ICapturedObjectSink _sink;
    private readonly TimeProvider _time;
    private readonly IRunLog _log;
    private readonly CaptureObjectScope _objectScope;

    /// <summary>
    /// Creates a capture.
    /// </summary>
    /// <param name="connections">
    /// How a connection to a unit's controller is opened, and reopened when a failure ends the
    /// conversation.
    /// </param>
    /// <param name="sink">Where finished objects go.</param>
    /// <param name="time">
    /// The clock the waits between attempts are measured on. Named rather than taken from the
    /// ambient one so that a test of the retry policy does not have to spend the five, ten and
    /// twenty seconds a real one would.
    /// </param>
    /// <param name="log">
    /// Where a retry, a restart and a reconnection are written down. Required rather than
    /// defaulted, per gate 1: this is the only place in the product that knows a controller made a
    /// capture wait, and a log it could be built without is a log it would be built without.
    /// </param>
    public PartitionCapture(
        IDirectoryChannelFactory connections,
        ICapturedObjectSink sink,
        TimeProvider time,
        IRunLog log) : this(connections, sink, time, log, CaptureObjectScope.Default)
    {
    }

    /// <summary>Creates a partition reader bound to one object-class policy for every retry.</summary>
    /// <param name="connections">How controller connections are opened.</param>
    /// <param name="sink">Where captured objects are written.</param>
    /// <param name="time">The retry clock.</param>
    /// <param name="log">Where capture and recovery are recorded.</param>
    /// <param name="objectScope">The run's class exclusions, unchanged across pages and restarts.</param>
    public PartitionCapture(IDirectoryChannelFactory connections, ICapturedObjectSink sink,
        TimeProvider time, IRunLog log, CaptureObjectScope objectScope)
    {
        ArgumentNullException.ThrowIfNull(connections);
        ArgumentNullException.ThrowIfNull(sink);
        ArgumentNullException.ThrowIfNull(time);
        ArgumentNullException.ThrowIfNull(log);
        ArgumentNullException.ThrowIfNull(objectScope);

        _connections = connections;
        _sink = sink;
        _time = time;
        _log = log;
        _objectScope = objectScope;
    }

    /// <summary>
    /// Reads one capture unit, restarting it once if a failure ended the conversation.
    /// </summary>
    /// <remarks>
    /// A restart discards everything the abandoned attempt read rather than merging it, because the
    /// two attempts overlap. Re-reading costs time and costs nothing else: a capture is not a frozen
    /// instant in the first place - it is read page by page over minutes while the forest changes
    /// underneath it.
    /// </remarks>
    /// <param name="unit">The naming context, and the controller to read it from.</param>
    /// <param name="cancellationToken">Cancellation for a capture an operator stopped.</param>
    public async Task<Result<PartitionCoverage>> ReadAsync(
        CaptureUnit unit, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(unit);

        for (var restart = 0; ; restart++)
        {
            var attempt = await ReadOnceAsync(unit, cancellationToken).ConfigureAwait(false);

            if (attempt.Result.IsSuccess
                || !attempt.RestartWanted
                || restart >= RetryPolicy.MaxRestartsPerUnit)
            {
                return attempt.Result;
            }

            // A restart throws away everything the abandoned attempt read, so a run that quietly
            // did one looks in every count like a run that read the partition once. The line is
            // what stops a doubled read time reading as a slow directory.
            _log.Note(
                PhaseName,
                "restarting a partition from its first page",
                [
                    new RunLogDetail("namingContext", unit.NamingContext),
                    new RunLogDetail("controller", unit.DomainController),
                    new RunLogDetail(
                        "restart",
                        $"{restart + 1} of {RetryPolicy.MaxRestartsPerUnit}"),
                    new RunLogDetail(
                        "because",
                        attempt.Result.Error?.Description
                            ?? "No reason was recorded, which is itself a fault in this product."),
                ]);
        }
    }

    private async Task<Outcome<PartitionCoverage>> ReadOnceAsync(
        CaptureUnit unit, CancellationToken cancellationToken)
    {
        var opened = _connections.Connect(unit);
        if (!opened.IsSuccess)
        {
            return new Outcome<PartitionCoverage>(opened.Error!, RestartWanted: true);
        }

        using var channel = opened.Value;

        if (!string.Equals(
                channel.DomainController, unit.DomainController, StringComparison.OrdinalIgnoreCase))
        {
            return Refuse<PartitionCoverage>(
                "ConnectionIsToAnotherController",
                $"{unit.NamingContext} was to be read from {unit.DomainController} and the "
                + $"connection is to {channel.DomainController}. One controller per unit is what "
                + "makes a failure name one unit unambiguously, so this is refused rather than "
                + "read from whichever host answered.",
                unit);
        }

        // The whole correctness of a paged read rests here, and it is checked before a request is
        // sent rather than inferred from one afterwards, because no response distinguishes a
        // partition that ended from a bookmark that was overwritten.
        if (channel.ReferralChasing != CaptureSearchRequestFactory.RequiredReferralChasing)
        {
            return Refuse<PartitionCoverage>(
                "ReferralPolicyNotAppliedToConnection",
                $"The connection to {channel.DomainController} has referral chasing set to "
                + $"{channel.ReferralChasing}, not "
                + $"{CaptureSearchRequestFactory.RequiredReferralChasing}. A paged search on such "
                + "a connection ends after its first page reporting success, and nothing in the "
                + "result says so, so no partition is read on it at all.",
                unit);
        }

        if (!channel.IsComplete)
        {
            return Refuse<PartitionCoverage>(
                "ControllerCapabilitiesWereNotRead",
                $"The connection to {channel.DomainController} cannot say which controls the "
                + "controller advertises. The domain-scope control is sent only where it is "
                + "advertised, so an unread capability list silently drops the second line of the "
                + "referral defence - and a defence that is quietly absent is worse than one that "
                + "was never claimed.",
                unit);
        }

        var referralsSuppressed =
            CaptureSearchRequestFactory.ShouldSendDomainScopeControl(unit, channel.SupportedControls);

        // Written here rather than only on the finished coverage, because a run that dies part way
        // through a partition never reaches the coverage. How well protected the connection was,
        // and whether the controller was asked to suppress referrals, are the two facts about a
        // half-read partition that nothing else would leave behind.
        _log.Note(
            PhaseName,
            "connected to a controller",
            [
                new RunLogDetail("namingContext", unit.NamingContext),
                new RunLogDetail("controller", channel.DomainController),
                new RunLogDetail("connection", channel.SecurityLevel.ToString()),
                new RunLogDetail("referralsSuppressed", referralsSuppressed ? "yes" : "no"),
            ]);

        // The sink is told before the first request, because an object must be attributed to its
        // partition the moment it is written and a receiver cannot work out either the rung this
        // connection reached or whether the controller was asked to suppress referrals. A restart
        // announces the partition again; a sink that has already seen it refuses, which is the
        // guard that stops a restarted unit being recorded twice.
        _sink.BeginPartition(unit, channel.SecurityLevel, referralsSuppressed);
        var completed = false;

        try
        {
            var references = new List<string>();
            var cookie = Array.Empty<byte>();
            var pages = 0;
            var objects = 0;
            var blocks = 0;

            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();

            var request = pages == 0
                ? CaptureSearchRequestFactory.ForUnit(unit, channel.SupportedControls, _objectScope)
                : CaptureSearchRequestFactory.ForNextPage(unit, channel.SupportedControls, cookie, _objectScope);

            var sent = await SendAsync(channel, request, unit, cancellationToken)
                .ConfigureAwait(false);

            if (!sent.Result.IsSuccess)
            {
                return new Outcome<PartitionCoverage>(sent.Result.Error!, sent.RestartWanted);
            }

            var page = sent.Result.Value;

            if (page.Completeness == PageCompleteness.NotPaged)
            {
                return Refuse<PartitionCoverage>(
                    "PagedSearchWasNotPaged",
                    $"A page of {unit.NamingContext} came back without the paging control, so the "
                    + "controller did not say whether there is more to send. An answer that cannot "
                    + "say it was the last one is not the last one, and treating it as one is how "
                    + "part of a forest is reported as the whole of it.",
                    unit);
            }

            pages++;

            foreach (var entry in page.Entries)
            {
                var read = await ReadEntryAsync(channel, entry, unit, cancellationToken)
                    .ConfigureAwait(false);

                if (!read.Result.IsSuccess)
                {
                    return new Outcome<PartitionCoverage>(read.Result.Error!, read.RestartWanted);
                }

                blocks += read.Result.Value.Blocks;
                objects++;
                _sink.Receive(read.Result.Value.Object);
            }

            references.AddRange(page.ContinuationReferences);

                if (page.Completeness == PageCompleteness.LastPage)
                {
                var coverage = new PartitionCoverage(
                    unit.NamingContext,
                    unit.Kind,
                    unit.DomainController,
                    channel.SecurityLevel,
                    pages,
                    objects,
                    blocks,
                    references,
                    referralsSuppressed);

                    _sink.CompletePartition(coverage);
                    completed = true;

                    return new Outcome<PartitionCoverage>(coverage, RestartWanted: false);
                }

            // An empty page is legitimate: Microsoft records that a controller may return one and
            // still report success, meaning it could not build a page this time and has not
            // finished. What is not legitimate is being handed the same bookmark back, because then
            // the next request is the request just made and the loop is a spin.
            if (page.PagingCookie.AsSpan().SequenceEqual(cookie))
            {
                return Refuse<PartitionCoverage>(
                    "PagedSearchRepeatedItsCookie",
                    $"A page of {unit.NamingContext} returned the same paging bookmark it was "
                    + "given, so asking again would send the identical request forever. The read "
                    + "stops here rather than looping or settling for what it has.",
                    unit);
            }

                cookie = page.PagingCookie;
            }
        }
        finally
        {
            if (!completed)
                _sink.AbortPartition();
        }
    }

    /// <summary>
    /// Turns one entry into a finished object, fetching the rest of any attribute the controller
    /// would not send at once.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The continuation happens here, between two pages, and never inside one.</b> The paged
    /// search is halfway through the partition while this runs, and that is safe for a reason worth
    /// stating: a range retrieval is a base-scope search of one object with no paging control, so it
    /// creates no paging state of its own and cannot compete for the controller's
    /// intermediate-result budget with the search already in flight. What would disturb that search
    /// is a referral being followed, and referral chasing is off - checked before the first request.
    /// </para>
    /// <para>
    /// The alternative was to collect every unfinished attribute and drain them after the last page.
    /// It was refused because it means holding every part-read object for the length of a partition,
    /// which is a design that works on a lab forest and exhausts a machine on a customer's - and it
    /// buys nothing, since the bookmark sits in the controller's cache for exactly as long either
    /// way.
    /// </para>
    /// </remarks>
    private async Task<Outcome<(CapturedObject Object, int Blocks)>> ReadEntryAsync(
        IDirectoryChannel channel,
        LdapEntryReader reader,
        CaptureUnit unit,
        CancellationToken cancellationToken)
    {
        var attributes = new List<AttributeValues>();
        var blocks = 0;

        foreach (var attribute in CapturedAttributeCatalog.All)
        {
            var values = reader.ValuesOf(attribute);

            while (values.Completeness == AttributeCompleteness.MoreToFetch)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var request = CaptureSearchRequestFactory.ForAttributeBlock(
                    reader.DistinguishedName,
                    values.NextRange!.SpecifierFor(attribute.LdapDisplayName));

                var sent = await SendAsync(channel, request, unit, cancellationToken)
                    .ConfigureAwait(false);

                if (!sent.Result.IsSuccess)
                {
                    return new Outcome<(CapturedObject, int)>(
                        sent.Result.Error!, sent.RestartWanted);
                }

                blocks++;

                var entries = sent.Result.Value.Entries;

                var block = entries.Count == 1
                    ? entries[0].ValuesOf(attribute)
                    : new AttributeValues(
                        attribute.LdapDisplayName,
                        [],
                        AttributeCompleteness.NotReturned,
                        NextRange: null);

                var joined = LdapEntryReader.Continue(values, block);
                if (!joined.IsSuccess)
                {
                    return new Outcome<(CapturedObject, int)>(
                        joined.Error!, RestartWanted: false);
                }

                values = joined.Value;
            }

            attributes.Add(values);
        }

        return new Outcome<(CapturedObject, int)>(
            (CapturedObject.Create(reader.DistinguishedName, attributes), blocks),
            RestartWanted: false);
    }

    /// <summary>
    /// Sends one request, applying the failure policy to whatever comes back.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Three attempts, waiting between them, and only where the policy says the conversation with
    /// the controller survived. A failure that ended the conversation took the paging bookmark with
    /// it, and sending it again would offer the controller a bookmark it has no memory of.
    /// </para>
    /// <para>
    /// <b>It catches <see cref="DirectoryException"/> rather than <see cref="LdapException"/>, and
    /// the difference is the whole of the retry mechanism.</b> A non-success server result arrives
    /// from <c>EndSendRequest</c> as a <see cref="DirectoryOperationException"/>, which is not an
    /// <see cref="LdapException"/> - so catching the narrower type let Busy and Unavailable, the
    /// two failures retries exist for, past the retry and out of the run.
    /// </para>
    /// </remarks>
    private async Task<Outcome<DirectoryPage>> SendAsync(
        IDirectoryChannel channel,
        SearchRequest request,
        CaptureUnit unit,
        CancellationToken cancellationToken)
    {
        for (var attempt = 1; ; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();

            DirectoryFailure failure;

            try
            {
                var page = await channel.SendAsync(request, cancellationToken)
                    .ConfigureAwait(false);

                return new Outcome<DirectoryPage>(page, RestartWanted: false);
            }
            catch (DirectoryException exception)
            {
                failure = RetryPolicy.FailureFor(exception);
            }

            if (failure.Response == FailureResponse.RetryTheRequest
                && attempt < RetryPolicy.MaxAttemptsPerRequest)
            {
                var wait = RetryPolicy.WaitBefore(failure, attempt + 1);

                // A retry is written down as it happens, not counted and reported at the end. A
                // capture that took six hours because one controller spent five of them saying
                // "busy" is a different story from one that was simply large, and the only place
                // the difference survives is a line with a time on it.
                _log.Note(
                    PhaseName,
                    "retrying a request",
                    [
                        new RunLogDetail("namingContext", unit.NamingContext),
                        new RunLogDetail("controller", unit.DomainController),
                        new RunLogDetail("failure", failure.Name),
                        new RunLogDetail(
                            "resultCode", failure.ResultCode.ToString(CultureInfo.InvariantCulture)),
                        new RunLogDetail(
                            "attempt",
                            $"{attempt + 1} of {RetryPolicy.MaxAttemptsPerRequest}"),
                        new RunLogDetail(
                            "waitSeconds",
                            wait.TotalSeconds.ToString("0.#", CultureInfo.InvariantCulture)),
                    ]);

                await Task.Delay(wait, _time, cancellationToken).ConfigureAwait(false);
                continue;
            }

            var error = AuditError.Create(
                ErrorCategory.Capture,
                "DirectoryRequestFailed",
                ErrorSeverity.Failed,
                $"{unit.NamingContext} on {unit.DomainController} failed with "
                + $"{failure.Name} ({failure.ResultCode}) after {attempt} attempt(s). "
                + failure.WhatCaptureDoes,
                unit.NamingContext);

            return new Outcome<DirectoryPage>(
                error, failure.Response == FailureResponse.RestartTheUnit);
        }
    }

    /// <summary>
    /// A refusal: something about the connection or the answer means no partition can be read on it,
    /// and reading it again would meet the same thing.
    /// </summary>
    private static Outcome<T> Refuse<T>(string reason, string description, CaptureUnit unit) =>
        new(
            AuditError.Create(
                ErrorCategory.Capture,
                reason,
                ErrorSeverity.Failed,
                description,
                unit.NamingContext),
            RestartWanted: false);

    /// <summary>
    /// One step's outcome, and whether the naming context is worth reading again from the start.
    /// </summary>
    /// <remarks>
    /// It carries a <see cref="Result{T}"/> rather than reimplementing one. Whether an operation
    /// succeeded is a question that already has an owner in <c>CONCEPT-REGISTRY.md</c>, and three
    /// private near-copies of it inside one file is how this codebase ended up with six answers to
    /// whether a permission is dangerous. The only thing added is the restart bit, which belongs to
    /// the failure policy rather than to the outcome.
    /// </remarks>
    private readonly record struct Outcome<T>(Result<T> Result, bool RestartWanted);
}
