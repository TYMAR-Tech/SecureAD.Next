using SecureAD.Evidence;

namespace SecureAD.Judgement;

internal static class FindingInputBinding
{
    internal static string? DerivationSeal(string directory, Guid? generation)
    {
        if (generation is null) return null;
        var contents = BundleSealing.ReadSeal(BundleLayout.AnalysisGenerationSealPath(directory, AnalysisStoreKind.Derivation, generation.Value));
        if (contents is null || contents.Algorithm != BundleSealing.Algorithm || contents.Hash is not { Length: 64 }
            || !contents.Hash.All(Uri.IsHexDigit)) throw new InvalidDataException("The saved finding's derivation seal is invalid.");
        return contents.Hash;
    }
}
