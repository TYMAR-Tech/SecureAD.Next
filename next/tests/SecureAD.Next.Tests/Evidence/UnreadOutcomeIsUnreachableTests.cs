using System.IO;
using System.Linq;
using Xunit;

namespace SecureAD.Next.Tests.Evidence;

/// <summary>
/// Holds the guarantee that makes <c>RunCoverage.EveryDeclaredUnitWasRecordedAsRead</c> true in
/// every bundle: nothing in the product records a unit as unread.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why this exists.</b> <c>D3</c> of <c>F-S29-3</c> established that the run-level verdict cannot
/// be false in any bundle a reader can open, because capture is fail-fast per
/// <c>docs/decisions/0003</c> and a failed unit returns before the seal. That makes the verdict an
/// enforcement of <c>docs/decisions/0027</c> rather than a measurement - and an enforcement is only
/// worth keeping if the thing it enforces is actually held somewhere.
/// </para>
/// <para>
/// <b>What it guards.</b> <c>DomainCoverage.NotRead</c> and <c>ForestPartitionCoverage.NotRead</c>
/// are public and, at the time of writing, called by nothing outside tests. They are the door
/// through which a future writer - controller failover, parallel capture, anything
/// re-analysis-shaped - would create the very bundle <c>0027</c> refuses. This test does not forbid
/// that; it makes it deliberate, by failing until somebody states the new path and what the
/// run-level verdict now means.
/// </para>
/// <para>
/// <b>Source text rather than reflection</b>, because the question is which code calls a method,
/// and reflection over a loaded assembly cannot answer it without an IL reader this tree does not
/// carry. The self-test below is what stops the scan passing by reading no files.
/// </para>
/// <para>
/// <b>What it no longer means, since <c>docs/decisions/0044</c>.</b> This test used to be explained
/// as holding that <i>a bundle exists only when everything was read</i>, and that sentence is no
/// longer true of a bundle as a whole. SYSVOL is now read after the directory and is allowed to
/// fail without failing the run, so a sealed bundle can be missing evidence the run tried to
/// collect. The test's subject is unchanged and its code needs no widening: it guards
/// <c>DomainCoverage.NotRead</c> and <c>ForestPartitionCoverage.NotRead</c>, and SYSVOL is neither -
/// it is not a capture unit, which is exactly why <c>0044</c> gave it a record of its own held
/// beside them. So the invariant still holds on its own terms: <b>no capture unit is ever recorded
/// as unread</b>. The correction is made here rather than left to be noticed because a correct test
/// carrying a wrong explanation is how the next session is misled.
/// </para>
/// </remarks>
public class UnreadOutcomeIsUnreachableTests
{
    private const string DomainFactory = "DomainCoverage.NotRead(";
    private const string PartitionFactory = "ForestPartitionCoverage.NotRead(";

    /// <summary>
    /// Nothing in the product records a domain or a forest-wide partition as unread.
    /// </summary>
    [Fact]
    public void NoProductionCodeRecordsAUnitAsUnread()
    {
        var offenders = ProductionSources()
            .Where(file =>
            {
                var text = File.ReadAllText(file);
                return text.Contains(DomainFactory, System.StringComparison.Ordinal)
                       || text.Contains(PartitionFactory, System.StringComparison.Ordinal);
            })
            .Select(file => Path.GetFileName(file))
            .ToList();

        Assert.True(
            offenders.Count == 0,
            "Something now records a capture unit as unread:"
            + System.Environment.NewLine
            + string.Join(System.Environment.NewLine, offenders)
            + System.Environment.NewLine
            + "That is a bundle with a hole in it, which docs/decisions/0027 refuses as a baseline "
            + "and refuses to compare. It may be the right change - controller failover (0040) and "
            + "parallel capture (0041) both reach it - but it changes what "
            + "RunCoverage.AllDeclaredUnitsAreComplete means, from an internal consistency "
            + "check into a statement about a customer's forest. Say so in a decision record and "
            + "in the reader before deleting this test.");
    }

    /// <summary>
    /// The scanner self-test. Without it the check above passes by reading no files and reporting a
    /// product in perfect order, which is the failure this repository has committed three times.
    /// </summary>
    [Fact]
    public void TheScanReadsTheRealProductionSource()
    {
        var files = ProductionSources().ToList();

        Assert.True(files.Count > 50, $"Scanned only {files.Count} source files.");

        // A file that must be among them, and a string that must be findable, so a scan that read
        // the wrong tree or matched nothing would fail here rather than pass silently.
        Assert.Contains(files, f => Path.GetFileName(f) == "RunCoverage.cs");
        Assert.Contains(
            files,
            f => File.ReadAllText(f).Contains(
                "AllDeclaredUnitsAreComplete", System.StringComparison.Ordinal));

        // And the factories the check above looks for really are spelled that way, so a rename
        // cannot quietly turn the check into one that matches nothing.
        var coverageSource = files.Single(f => Path.GetFileName(f) == "DomainCoverage.cs");
        Assert.Contains(
            "public static DomainCoverage NotRead(",
            File.ReadAllText(coverageSource),
            System.StringComparison.Ordinal);
    }

    private static System.Collections.Generic.IEnumerable<string> ProductionSources() =>
        Directory.EnumerateFiles(
            Path.Combine(RepositoryLocation.Root(), "next", "src"),
            "*.cs",
            SearchOption.AllDirectories)
        .Where(f => !f.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}",
                                System.StringComparison.Ordinal)
                    && !f.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}",
                                   System.StringComparison.Ordinal));
}
