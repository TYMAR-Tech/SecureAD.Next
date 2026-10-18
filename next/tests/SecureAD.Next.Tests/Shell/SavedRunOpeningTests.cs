using System.Text.RegularExpressions;
using SecureAD.Evidence;
using SecureAD.Next.Tests.Judgement;
using SecureAD.Shell.Services;
using Xunit;
using Checks = SecureAD.Next.Tests.Evidence.VerificationChecks;

namespace SecureAD.Next.Tests.Shell;

/// <summary>
/// Opening a saved run in the viewer verifies every file once, in the background, and then reads from them.
/// </summary>
/// <remarks>
/// The runs are real and complete; the checks are held in place with the product's own measurement
/// (see <see cref="Checks"/>), not by faking a file.
/// </remarks>
public sealed class SavedRunOpeningTests
{
    private const string Descriptor = "O:SYG:SYD:(A;;WP;;;S-1-5-21-1-2-3-1200)(A;;WP;;;S-1-5-21-1-2-3-1200)";
    private const string Target = "CN=Service target,DC=contoso,DC=com";
    private static readonly TimeSpan Patience = Checks.Patience;

    [Fact]
    public async Task OpeningARunVerifiesEveryFileOnceLogsWhatEachCostAndBrowsingThenVerifiesNothingMore()
    {
        var directory = Published();
        using var checks = new Checks(directory);
        using var results = new OpenedRunResults(directory);

        results.BeginVerification();
        await results.Verification!;
        Assert.Equal(10, checks.Started.Count);

        Assert.True(results.ReadOverview(reader => reader.ReadInventory()).IsSuccess);
        Assert.True(results.ReadNavigation(reader => reader.ReadTree()).IsSuccess);
        Assert.True(results.ReadEvidence(reader => reader.ReadObjectAttributes(Target)).IsSuccess);
        Assert.True(results.ReadEvidence(reader => reader.ReadPermissions(Target)).IsSuccess);
        Assert.True(results.ReadFindings(reader => reader.ReadRuleExecutions()).IsSuccess);
        Assert.True(results.ReadFindings(reader => reader.ReadFilterValues()).IsSuccess);
        Assert.Equal(10, checks.Started.Count);

        var log = LogLines(directory);
        var files = log.Where(line => Regex.IsMatch(line, @"\sVerify\s+file verified\s")).ToArray();
        Assert.Equal(10, files.Length);
        foreach (var line in files)
        {
            var name = Regex.Match(line, @"file=(\S+)").Groups[1].Value;
            Assert.Equal(new FileInfo(Path.Combine(directory, name)).Length.ToString(), Regex.Match(line, @"bytes=(\d+)").Groups[1].Value);
            Assert.Contains("outcome=Verified", line);
            Assert.Matches(@"hashMs=\d", line);
            Assert.Matches(@"finishedMs=\d", line);
        }
        var opened = Assert.Single(log, line => Regex.IsMatch(line, @"\sVerify\s+saved run opened"));
        Assert.Contains("shellVersion=", opened);
        var finished = Assert.Single(log, line => Regex.IsMatch(line, @"\sVerify\s+saved run verified\s"));
        Assert.Contains("files=10", finished);
        Assert.Contains("verified=10", finished);
        Assert.Contains("failed=0", finished);
        Assert.Matches(@"wallMs=\d", finished);
    }

    [Fact]
    public async Task ASmallProductIsNotHeldBehindALargeOneStillBeingChecked()
    {
        var directory = Published();
        var judgement = AnalysisStoreLifecycle.ResolveRoot(directory, AnalysisStoreKind.Judgement).Value.Segment(StoreSegmentRole.Judgement).FileName;
        using var checks = new Checks(directory, name => name == judgement);
        using var results = new OpenedRunResults(directory);
        results.BeginVerification();
        Assert.True(checks.WaitUntilBlocked(judgement), "The judgement check never started.");

        var findings = Task.Run(() => results.ReadFindings(reader => reader.ReadRuleExecutions()));
        await Task.Delay(300);
        Assert.False(findings.IsCompleted, "Findings were read before the judgement had been verified.");

        var overview = Task.Run(() => results.ReadOverview(reader => reader.ReadInventory()));
        Assert.True(await Task.WhenAny(overview, Task.Delay(Patience)) == overview, "The Dashboard waited behind the judgement check.");
        var inventory = await overview;
        Assert.True(inventory.IsSuccess, inventory.Error?.Description);

        checks.Release();
        var read = await findings;
        Assert.True(read.IsSuccess, read.Error?.Description);
        await results.Verification!;
        Assert.Equal(10, checks.Started.Count);
    }

    [Fact]
    public async Task ClosingARunWhileItIsBeingVerifiedStopsPromptlyAndLeavesItsFolderRemovable()
    {
        var directory = Published();
        var judgement = AnalysisStoreLifecycle.ResolveRoot(directory, AnalysisStoreKind.Judgement).Value.Segment(StoreSegmentRole.Judgement).FileName;
        using var checks = new Checks(directory, name => name == judgement);
        var results = new OpenedRunResults(directory);
        results.BeginVerification();
        Assert.True(checks.WaitUntilBlocked(judgement));

        var closing = Task.Run(results.Dispose);
        await Task.Delay(300);
        checks.Release();
        Assert.True(await Task.WhenAny(closing, Task.Delay(Patience)) == closing, "Closing the run never finished.");

        // Closing returns only after the background pass has ended, so no log handle outlives the run.
        Assert.True(results.Verification!.IsCompleted, "Closing returned while the verification pass was still running.");
        Directory.Delete(directory, recursive: true);
        Assert.False(Directory.Exists(directory));
    }

    [Fact]
    public async Task SelectingARunInTheApplicationSourceStartsVerifyingItImmediately()
    {
        var directory = Published();
        using var checks = new Checks(directory);
        using var sessions = new RunProtectionSessions();
        using var source = new BundleAssetSource(sessions, verifyOnSelect: true);

        source.SelectRun(directory);

        Assert.True(await LogShows(directory, @"\sVerify\s+saved run verified\s"), "The selected run was not verified in the background.");
        Assert.Equal(10, checks.Started.Count);
        source.CloseRun();
    }

    [Fact]
    public async Task ASourceNotAskedToVerifyLeavesTheFilesUntouchedUntilTheyAreRead()
    {
        var directory = Published();
        using var checks = new Checks(directory);
        using var source = new BundleAssetSource();

        source.SelectRun(directory);
        await Task.Delay(500);
        Assert.Empty(checks.Started);

        Assert.True(source.ReadInventory(directory).IsSuccess);
        Assert.Single(checks.Started);
        Assert.Equal(0, LogLines(directory).Count(line => Regex.IsMatch(line, @"\sVerify\s")));
    }

    [Fact]
    public async Task AClickWhileTheOpeningPassIsWritingItsLogLeavesBothAccountsWhole()
    {
        var directory = Published();
        var judgement = AnalysisStoreLifecycle.ResolveRoot(directory, AnalysisStoreKind.Judgement).Value.Segment(StoreSegmentRole.Judgement).FileName;
        using var checks = new Checks(directory, name => name == judgement);
        using var results = new OpenedRunResults(directory);
        results.BeginVerification();
        Assert.True(checks.WaitUntilBlocked(judgement), "The judgement check never started.");

        // The pass has its log open and four files still to report. A click now opens a second log on the same file.
        using (var navigation = NavigationDiagnostics.Begin(directory, "open Dashboard"))
        {
            NavigationDiagnostics.Mark("query", TimeSpan.FromMilliseconds(1));
            navigation.Complete("success", null);
        }
        checks.Release();
        await results.Verification!;

        var log = LogLines(directory).Select(line => line.TrimEnd('\r')).Where(line => line.Length > 0 && !line.StartsWith("====", StringComparison.Ordinal)).ToArray();
        Assert.All(log, line => Assert.Matches(@"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ  (INFO |WARN |ERROR)", line));
        Assert.DoesNotContain(log, line => Regex.Count(line, @"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ") > 1);
        Assert.Equal(10, log.Count(line => Regex.IsMatch(line, @"\sVerify\s+file verified\s")));
        Assert.Single(log, line => line.Contains("navigation started", StringComparison.Ordinal) && line.Contains("action=\"open Dashboard\"", StringComparison.Ordinal));
        Assert.Single(log, line => line.Contains("navigation finished", StringComparison.Ordinal) && line.Contains("outcome=success", StringComparison.Ordinal));
    }

    [Fact]
    public async Task AFileTheAuditJustVerifiedIsNotVerifiedAgainWhenTheFinishedRunIsOpened()
    {
        var directory = Published();
        using var checks = new Checks(directory);
        using var sessions = new RunProtectionSessions();
        Assert.True(sessions.Produce(directory, files => files.Capture(StoreSegmentRole.Evidence, CancellationToken.None)).IsSuccess);
        Assert.Equal(1, checks.Count("evidence.db"));
        using var source = new BundleAssetSource(sessions, verifyOnSelect: true);

        source.SelectRun(directory);

        Assert.True(await LogShows(directory, @"\sVerify\s+saved run verified\s"));
        Assert.Equal(1, checks.Count("evidence.db"));
        Assert.Equal(10, checks.Started.Count);
        var evidence = Assert.Single(LogLines(directory), line => Regex.IsMatch(line, @"\sVerify\s+file verified\s") && line.Contains("role=Evidence"));
        Assert.Contains("outcome=AlreadyVerified", evidence);
        // A file this pass did not verify reports no hashing time, so the log's times are only what opening cost.
        Assert.DoesNotContain("hashMs=", evidence);
        source.CloseRun();
    }

    private static string Published() => AttributeWriteRuleTests.Published(Descriptor);

    private static string[] LogLines(string directory)
    {
        var path = Path.Combine(directory, "run.log");
        if (!File.Exists(path)) return [];
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd().Split('\n', StringSplitOptions.RemoveEmptyEntries);
    }

    private static async Task<bool> LogShows(string directory, string pattern)
    {
        var deadline = DateTime.UtcNow + Patience;
        while (DateTime.UtcNow < deadline)
        {
            if (LogLines(directory).Any(line => Regex.IsMatch(line, pattern))) return true;
            await Task.Delay(25);
        }
        return false;
    }
}
