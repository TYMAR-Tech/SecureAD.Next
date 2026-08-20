namespace SecureAD.Audit.Connect;

/// <summary>
/// Runs preflight's per-domain work together, while letting no single controller be asked two
/// things at once.
/// </summary>
/// <remarks>
/// <para>
/// <b>This file fans work out and knows nothing about directories, deliberately.</b> That division
/// is what <c>SerializedDirectoryAccessGateTests</c> holds: a file may dispatch work or speak to a
/// controller, never both, because two requests in flight against one controller compete for a
/// single budget of paged-search state and can silently truncate each other - a report that is
/// wrong rather than one that fails. <c>Preflight</c> keeps the connections and the plan;
/// <c>DomainPreflightRead</c> does the reading and stays strictly serial; the concurrency is here,
/// expressed over opaque subjects and host names.
/// </para>
/// <para>
/// <b>Turns are taken by host, not by domain.</b> Two domains pinned to one controller is not
/// something Active Directory produces, because a writable controller holds one domain - but
/// <c>ControllerSelection</c> has no rule against it and will pin the same host twice if handed a
/// forest that declares one. A concurrency that is safe because the directory happens to be shaped
/// a certain way is the defect this exists to avoid, so the safety is held here instead.
/// </para>
/// <para>
/// <b>Nothing waits for a host while already holding one.</b> A caller takes a turn, finishes, and
/// releases before asking for the next, so there is no order in which two subjects can wait on each
/// other.
/// </para>
/// </remarks>
internal sealed class PreflightDispatch
{
    private readonly Dictionary<string, SemaphoreSlim> _turns =
        new(StringComparer.OrdinalIgnoreCase);

    private PreflightDispatch()
    {
    }

    /// <summary>
    /// Asks about every subject at once, and returns the answers in the order the subjects were
    /// given rather than the order they arrived.
    /// </summary>
    /// <remarks>
    /// The order matters beyond tidiness: a report ordered by whichever controller answered first
    /// would put the same forest in a different order every run, and an operator comparing two runs
    /// would be reading a difference the forest does not have.
    /// </remarks>
    /// <param name="subjects">What to ask about, in the order the answers are wanted.</param>
    /// <param name="ask">How one subject is asked, given the turns it must take.</param>
    /// <param name="cancellationToken">Cancellation for a check an operator stopped.</param>
    public static async Task<TAnswer[]> TogetherAsync<TSubject, TAnswer>(
        IReadOnlyList<TSubject> subjects,
        Func<TSubject, PreflightDispatch, Task<TAnswer>> ask,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(subjects);
        ArgumentNullException.ThrowIfNull(ask);

        cancellationToken.ThrowIfCancellationRequested();

        var turns = new PreflightDispatch();
        var answers = new TAnswer[subjects.Count];

        // Each task writes one slot and reads none, so there is nothing shared to race over.
        //
        // The yield is not a tidiness: asking a subject begins by opening a connection, and that
        // is synchronous. Without it the first subject would run its connection ladder to
        // completion on this thread before the second subject had started, and the pass would be
        // parallel in shape and sequential in fact - which is the ten seconds per controller this
        // is meant to overlap. It is the difference the guards measure.
        await Task.WhenAll(subjects.Select(async (subject, at) =>
        {
            await Task.Yield();
            answers[at] = await ask(subject, turns).ConfigureAwait(false);
        })).ConfigureAwait(false);

        return answers;
    }

    /// <summary>
    /// Runs <paramref name="work"/> once this host is free, and lets the next caller in after.
    /// </summary>
    /// <param name="host">The machine the work will reach, by DNS host name.</param>
    /// <param name="work">The work to do while holding this host's turn.</param>
    /// <param name="cancellationToken">Cancellation for a check an operator stopped.</param>
    public async Task<TAnswer> OneAtATimeAsync<TAnswer>(
        string host, Func<Task<TAnswer>> work, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(host);
        ArgumentNullException.ThrowIfNull(work);

        SemaphoreSlim turn;

        lock (_turns)
        {
            if (!_turns.TryGetValue(host, out turn!))
            {
                turn = new SemaphoreSlim(1, 1);
                _turns[host] = turn;
            }
        }

        await turn.WaitAsync(cancellationToken).ConfigureAwait(false);

        try
        {
            return await work().ConfigureAwait(false);
        }
        finally
        {
            turn.Release();
        }
    }
}
