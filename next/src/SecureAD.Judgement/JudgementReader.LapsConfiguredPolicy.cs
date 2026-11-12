using SecureAD.Evidence;
using SecureAD.Kernel;

namespace SecureAD.Judgement;

public sealed partial class JudgementReader
{
    internal Result<SavedLapsConfiguredPolicy> ReadLapsConfiguredPolicy(CapturedObjectIdentity computer,
        CancellationToken token = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(_readCancellation, token);
        var selectedToken = cancellation.Token;
        selectedToken.ThrowIfCancellationRequested();
        if (Description.State is not (JudgementRunState.Completed or JudgementRunState.CompletedDegraded))
            throw new InvalidOperationException("The selected judgement has no completed configured LAPS results.");
        OpenPart(StoreSegmentRole.JudgementFacts, selectedToken);
        var derivationSeal = FindingInputBinding.DerivationSeal(BundleDirectory, Description.DerivationGenerationId);
        return LapsConfiguredPolicyStorage.Read(_connection, Description, computer, derivationSeal, selectedToken);
    }
}
