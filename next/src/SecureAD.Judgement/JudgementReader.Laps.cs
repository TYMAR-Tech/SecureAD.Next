using SecureAD.Evidence;

namespace SecureAD.Judgement;

public sealed partial class JudgementReader
{
    /// <summary>Counts the same complete filtered question used by inventory paging, without decoding rows.</summary>
    public LapsInventorySummary ReadLapsInventorySummary(LapsQuery query, ListingCoverage coverage,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (Description.State is not (JudgementRunState.Completed or JudgementRunState.CompletedDegraded))
            throw new InvalidOperationException(LapsInventoryStorage.Message("Unavailable"));
        return LapsInventoryStorage.Summarize(_connection, Description, query, coverage, cancellationToken, _browsing.Laps);
    }

    /// <summary>Reads recorded LAPS inventory, with scoped coverage from the same protected evidence.</summary>
    /// <remarks>The selected-run owner supplies coverage and checks the exact generations before returning the page.</remarks>
    public LapsPage ListLapsComputers(LapsQuery query, LapsPageMark? after,
        ListingCoverage coverage, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (Description.State is not (JudgementRunState.Completed or JudgementRunState.CompletedDegraded))
            throw new InvalidOperationException(LapsInventoryStorage.Message("Unavailable"));
        return LapsInventoryStorage.Read(_connection, Description, query, after, coverage, cancellationToken, _browsing.Laps);
    }
}
