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
        var query = new LapsQuery(dn, scope, "", null);
        var coverage = evidence.ReadListingCoverage(dn, scope);
        var page = judgement.ListLapsComputers(query, null, coverage);
        for (var index = 1; index < pageNumber; index++)
            page = judgement.ListLapsComputers(query, Assert.IsType<LapsPageMark>(page.Next), coverage);
        return page;
    }
}
