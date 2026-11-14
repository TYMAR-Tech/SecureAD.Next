using System.Collections.Concurrent;

namespace SecureAD.Next.Tests.Shell;

/// <summary>
/// Runs an asynchronous body the way a window runs a command: on one thread, with every
/// continuation coming back to it.
/// </summary>
/// <remarks>
/// <para>
/// <b>Without this, a shell test runs in an environment the shell never sees.</b> A view model
/// awaits with <c>ConfigureAwait(true)</c> so that what follows lands back on the dispatcher, which
/// is the only thread WPF permits a bound collection to be changed from. A test with no
/// synchronization context resumes on the thread pool instead, so code that is correct in the
/// application throws here.
/// </para>
/// <para>
/// <b>And the reverse, which is worse.</b> A test can pass whenever the stand-in it awaits happens
/// to complete synchronously, because then nothing ever leaves the test thread and the question is
/// never asked. That is exactly what was happening: <see cref="FakeDerivationLauncher"/> returns a
/// completed task and <see cref="FakeJudgingLauncher"/> yields, so one view-model path was being
/// checked in an environment resembling the product and the other in one that did not - and only
/// the second failed. A check that passes while measuring nothing is the worst kind this repository
/// has, and the asymmetry between two stand-ins is a quiet way to acquire one.
/// </para>
/// <para>
/// The pump is driven rather than completed: a continuation posted after the body has finished has
/// nothing left to run into, and draining to the end avoids having to decide what to do about one.
/// </para>
/// </remarks>
internal static class OneThread
{
    internal static T Run<T>(Func<Task<T>> body)
    {
        ArgumentNullException.ThrowIfNull(body);
        Task<T>? result = null;
        Task Invoke()
        {
            result = body();
            return result;
        }
        Run(Invoke);
        return (result ?? throw new InvalidOperationException("The UI test body did not run."))
            .GetAwaiter().GetResult();
    }

    /// <summary>Runs <paramref name="body"/> to completion on the calling thread.</summary>
    /// <param name="body">The asynchronous test body.</param>
    public static void Run(Func<Task> body)
    {
        ArgumentNullException.ThrowIfNull(body);

        var original = SynchronizationContext.Current;
        var pump = new Pump();

        try
        {
            SynchronizationContext.SetSynchronizationContext(pump);

            var running = body();
            pump.DrainUntil(running);

            // Rethrown with its own stack rather than wrapped in an AggregateException, so a
            // failing assertion inside the body reads as itself.
            running.GetAwaiter().GetResult();
        }
        finally
        {
            SynchronizationContext.SetSynchronizationContext(original);
        }
    }

    private sealed class Pump : SynchronizationContext
    {
        private readonly BlockingCollection<(SendOrPostCallback Work, object? State)> _queue = [];

        public override void Post(SendOrPostCallback d, object? state) => _queue.Add((d, state));

        public override void Send(SendOrPostCallback d, object? state) => d(state);

        /// <summary>Runs queued continuations until <paramref name="running"/> has finished.</summary>
        public void DrainUntil(Task running)
        {
            while (!running.IsCompleted)
            {
                if (_queue.TryTake(out var pending, millisecondsTimeout: 50))
                    pending.Work(pending.State);
            }

            while (_queue.TryTake(out var pending))
                pending.Work(pending.State);
        }
    }
}
