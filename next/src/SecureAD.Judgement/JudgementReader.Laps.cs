using SecureAD.Evidence;

namespace SecureAD.Judgement;

public sealed partial class JudgementReader
{
    /// <summary>Reads recorded LAPS inventory, with scoped coverage from the same protected evidence.</summary>
    /// <remarks>The selected-run owner supplies coverage and checks the exact generations before returning the page.</remarks>
    public LapsPage ListLapsComputers(string containerDn, ListingScope scope, int pageNumber,
        ListingCoverage coverage, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (Description.State is not (JudgementRunState.Completed or JudgementRunState.CompletedDegraded))
            throw new InvalidOperationException(LapsInventoryStorage.Message("Unavailable"));
        return LapsInventoryStorage.Read(_connection, Description, containerDn, scope, pageNumber, coverage, cancellationToken);
    }
}
