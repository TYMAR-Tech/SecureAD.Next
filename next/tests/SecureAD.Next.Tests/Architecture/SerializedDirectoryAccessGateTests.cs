using System.Text.RegularExpressions;
using Xunit;

namespace SecureAD.Next.Tests.Architecture;

/// <summary>
/// Inventory row B7's boundary: capture never has two requests in flight against one domain
/// controller.
///
/// <para>
/// <b>What the rule actually is.</b> Not "capture is single-threaded". Reading several naming
/// contexts at once, each on its own controller, is several controllers each seeing a well-behaved
/// serial client, and it is safe. What is not safe is two requests arriving at the <i>same</i>
/// controller at once.
/// </para>
/// <para>
/// <b>Why that is a correctness rule and not a courtesy.</b> The state a controller keeps between
/// the pages of a paged search comes out of a single per-controller budget - <c>MaxResultSetSize</c>
/// - and when that budget fills the controller discards the oldest intermediate results. Two paged
/// reads at one server can therefore truncate each other, silently, and only on forests large
/// enough for somebody to have wanted the concurrency. That is the same failure as a paged search
/// that stops after one page and reports success, reached from the other direction.
/// </para>
/// <para>
/// This product also has no request rate limit of its own, deliberately - a budget counted in
/// requests measures the wrong thing, since one request is a page of up to a thousand objects - so
/// this rule is the whole of what bounds the load a capture places on any one server.
/// </para>
/// <para>
/// <b>How it is checked.</b> A file may fan work out, or it may talk to a directory, but not both.
/// The code that dispatches naming contexts may run them at once; the code that reads one may not
/// run anything at once. Expressed that way the rule needs no list of exempt files, and a list is
/// the thing that stops being true.
/// </para>
/// <para>
/// <b>What it cannot do.</b> It cannot prove that two units never share a controller, which is a
/// property of the plan a run is given rather than of the code. That obligation belongs with
/// whatever assigns controllers to naming contexts, and is recorded against inventory row B5, where
/// running units at once is decided. Nor can it prove the reading code awaits each page before
/// asking for the next, because no code asks for a page yet - that is inventory row B6.
/// </para>
/// </summary>
public sealed class SerializedDirectoryAccessGateTests
{
    private const string CaptureProject = "SecureAD.Audit";

    /// <summary>
    /// Shapes that put two pieces of work in flight at once.
    /// </summary>
    private static readonly Regex FanOut = new(
        @"\b(Task\.WhenAll|Task\.WhenAny|Task\.Run|Parallel\.For|Parallel\.ForEach"
        + @"|Parallel\.ForEachAsync|Parallel\.Invoke|AsParallel)\b",
        RegexOptions.Compiled);

    /// <summary>
    /// Shapes that mean this file speaks to a directory. A file matching one of these is a file
    /// where a second concurrent request would land on a real domain controller.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Two vocabularies, because there are two ways to reach a controller.</b> The raw
    /// <c>System.DirectoryServices.Protocols</c> types are one. The product's own
    /// <c>IDirectoryChannel</c> is the other, and it is the one everything written since the
    /// rebuild uses.
    /// </para>
    /// <para>
    /// <b>Only the first vocabulary was matched until 2026-08-16, and that was the whole defect.</b>
    /// <c>Preflight.cs</c> opens a connection to every domain controller in the forest and reads
    /// from each, and matched nothing here, because it says <c>channel.SendAsync</c> rather than
    /// <c>connection.SendRequest</c>. So did <c>ForestDiscovery</c>, <c>ForestRoles</c> and
    /// <c>CaptureSession</c>. The guard reported a clean project while ignoring every file that had
    /// been written in the newer style - passing, and measuring nothing where it mattered most.
    /// </para>
    /// </remarks>
    private static readonly Regex TouchesADirectory = new(
        @"\b(LdapConnection|LdapSessionOptions|SearchRequest|SearchResponse|SendRequest"
        + @"|BeginSendRequest|DirectoryControl|DirectoryAttribute"
        + @"|IDirectoryChannel|IDirectoryChannelFactory|SendAsync)\b",
        RegexOptions.Compiled);

    [Fact]
    public void NoFileBothTalksToADirectoryAndFansOutItsWork()
    {
        var offenders = CaptureFiles()
            .Where(f => Matches(f, TouchesADirectory) && Matches(f, FanOut))
            .Select(f => "  " + f)
            .OrderBy(f => f, StringComparer.Ordinal)
            .ToList();

        Assert.True(
            offenders.Count == 0,
            "A file that talks to a domain controller also runs work in parallel. Requests are "
            + "never pipelined: two requests in flight against one controller compete for a single "
            + "budget of paged-search state, which the controller resolves by discarding the "
            + "oldest, so a concurrent read can silently truncate another one. Running several "
            + "naming contexts at once is fine and is expected; running two requests at one "
            + "controller is not. Split the dispatching from the reading. See "
            + "docs/layers/audit/limits-and-failures.md:"
            + Environment.NewLine + string.Join(Environment.NewLine, offenders));
    }

    /// <summary>
    /// The scanner self-test. Without it the check above passes by scanning an empty set of files,
    /// or by using patterns that match nothing, and reports a clean project either way.
    /// </summary>
    [Fact]
    public void TheScannerReadsTheCaptureProjectAndBothPatternsMatch()
    {
        var files = CaptureFiles().ToList();

        Assert.True(
            files.Count > 0,
            $"Scanned no files under {CaptureProject}. The guard would report a clean project by "
            + "having failed to find the project.");

        // The check is a conjunction, so it passes trivially if nothing in the tree talks to a
        // directory at all. At least one file must, or there is nothing being guarded.
        var directoryFiles = files.Where(f => Matches(f, TouchesADirectory)).ToList();
        Assert.True(
            directoryFiles.Count > 0,
            "No file in the capture project talks to a directory, so this guard is watching "
            + "nothing. Either the detection pattern has stopped matching, or the code that "
            + "speaks to a controller has moved out of this project.");

        Assert.Matches(FanOut, "await Task.WhenAll(pages);");
        Assert.Matches(FanOut, "Parallel.ForEach(units, u => Read(u));");
        Assert.Matches(FanOut, "var q = items.AsParallel();");
        Assert.DoesNotMatch(FanOut, "await ReadOnePageAsync(request);");

        Assert.Matches(TouchesADirectory, "var response = connection.SendRequest(request);");
        Assert.Matches(TouchesADirectory, "public SearchRequest ForUnit(CaptureUnit unit)");
        Assert.DoesNotMatch(TouchesADirectory, "var total = objects.Count;");

        // The product's own vocabulary. Matching only the raw LDAP types left every file written
        // since the rebuild unwatched, which is the defect these three lines exist to keep fixed.
        Assert.Matches(TouchesADirectory, "var page = await channel.SendAsync(request, token);");
        Assert.Matches(TouchesADirectory, "IDirectoryChannel channel,");
        Assert.Matches(TouchesADirectory, "IDirectoryChannelFactory connections,");

        // And the file that prompted the widening must now be watched by name, because a pattern
        // that stops matching it fails silently and returns this guard to reporting a clean project.
        var preflight = files.Single(f => f.EndsWith(
            $"{Path.DirectorySeparatorChar}Preflight.cs", StringComparison.Ordinal));

        Assert.True(
            Matches(preflight, TouchesADirectory),
            "Preflight.cs connects to every domain controller in the forest and is no longer "
            + "recognised as touching a directory. The guard is back to the state it was in on "
            + "2026-08-16, when it passed while ignoring the file most able to breach the rule.");
    }

    /// <summary>
    /// Production files belonging to the capture project.
    /// </summary>
    private static IEnumerable<string> CaptureFiles() =>
        RebuildTree.ProductionFiles()
            .Where(f => f.Contains(
                $"{Path.DirectorySeparatorChar}{CaptureProject}{Path.DirectorySeparatorChar}",
                StringComparison.Ordinal));

    /// <summary>
    /// Whether any executable line of the file matches. Comments are skipped, because both of
    /// these patterns name the very things the guard discusses in its own prose.
    /// </summary>
    private static bool Matches(string file, Regex pattern) =>
        RebuildTree.ScanPattern([file], pattern).Count > 0;
}
