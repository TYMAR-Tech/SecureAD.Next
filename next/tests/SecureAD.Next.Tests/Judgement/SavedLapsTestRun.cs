using SecureAD.Evidence;
using SecureAD.Judgement;
using SecureAD.Kernel;
using Xunit;

namespace SecureAD.Next.Tests.Judgement;

internal static class SavedLapsTestRun
{
    internal static void Judge(string directory)
    {
        var started = new DateTimeOffset(2026, 9, 3, 9, 0, 0, TimeSpan.Zero);
        var result = JudgingRun.Judge(directory, [], started, started,
            JudgingRun.NobodyIsWatching, RunLog.Discarded, CancellationToken.None);
        Assert.True(result.IsSuccess, result.Error?.Description);
    }

    internal static LapsPage Read(string directory, string dn, ListingScope scope, int pageNumber = 1)
    {
        using var evidence = BundleReader.Open(directory).Value;
        using var judgement = JudgementReader.Open(directory).Value;
        return judgement.ListLapsComputers(dn, scope, pageNumber, evidence.ReadListingCoverage(dn, scope));
    }
}
