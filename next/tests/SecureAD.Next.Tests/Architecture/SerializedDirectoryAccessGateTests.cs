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
    /// Shapes that put two pieces of work in flight at once, with no turn-taking of their own.
    /// </summary>
    /// <remarks>
    /// <b>These are the unsafe ones.</b> Nothing here knows which host a piece of work will reach,
    /// so nothing here can stop two of them reaching the same one.
    /// </remarks>
    private static readonly Regex RawFanOut = new(
        @"\b(Task\.WhenAll|Task\.WhenAny|Task\.Run|Parallel\.For|Parallel\.ForEach"
        + @"|Parallel\.ForEachAsync|Parallel\.Invoke|AsParallel)\b",
        RegexOptions.Compiled);

    /// <summary>
    /// The one sanctioned way to run directory work at once.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b><c>DirectoryWorkDispatch.TogetherAsync</c> is safe where the raw primitives are not</b>,
    /// because it takes a turn per host before letting work start: two subjects on one controller
    /// are serialised against each other while two on different controllers overlap. That is the
    /// whole rule, implemented once.
    /// </para>
    /// <para>
    /// <b>It was absent from this guard until 2026-09-13, and that was a hole rather than an
    /// omission.</b> The rule below says a file may fan out or speak to a directory and never both;
    /// <c>Preflight.cs</c> holds an <c>IDirectoryChannelFactory</c> and fans out through this, so by
    /// the stated rule it was an offender and passed anyway - an invisible, untested allowlist keyed
    /// on a method name, which is what <c>0041</c> forbids when it says narrow the guard and never
    /// exempt a file. It mattered because <c>CaptureRun</c> is about to do the same thing under that
    /// decision, and the guard would have stayed green through the whole change.
    /// </para>
    /// </remarks>
    private static readonly Regex DispatchedFanOut = new(
        @"\bTogetherAsync\b",
        RegexOptions.Compiled);

    /// <summary>
    /// Shapes that put a request on a controller.
    /// </summary>
    /// <remarks>
    /// <b>Sending, not naming.</b> A file that merely holds or passes a connection has not spoken
    /// to anything - <c>Preflight</c> keeps the factory and hands it to <c>DomainPreflightRead</c>,
    /// which does the reading and stays serial. Treating the two alike is what made the old pattern
    /// fire on a file that cannot breach the rule while missing the shape that can.
    /// </remarks>
    private static readonly Regex SendsARequest = new(
        @"\b(SendAsync|SendRequest|BeginSendRequest|EndSendRequest)\b",
        RegexOptions.Compiled);

    /// <summary>
    /// Shapes that mean this file is holding the means to reach a controller.
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
    /// <c>Preflight.cs</c> opens a connection to every domain controller in the forest and matched
    /// nothing here, because it says <c>channel.SendAsync</c> rather than
    /// <c>connection.SendRequest</c>. So did <c>ForestDiscovery</c>, <c>ForestRoles</c> and
    /// <c>CaptureSession</c>. The guard reported a clean project while ignoring every file that had
    /// been written in the newer style - passing, and measuring nothing where it mattered most.
    /// </para>
    /// </remarks>
    private static readonly Regex HoldsAConnection = new(
        @"\b(LdapConnection|LdapSessionOptions|SearchRequest|SearchResponse|SendRequest"
        + @"|BeginSendRequest|DirectoryControl|DirectoryAttribute"
        + @"|IDirectoryChannel|IDirectoryChannelFactory|SendAsync)\b",
        RegexOptions.Compiled);

    /// <summary>
    /// A file that sends a request never runs work in parallel, however it runs it.
    /// </summary>
    /// <remarks>
    /// <b>This is the rule itself.</b> Two requests in flight against one controller compete for a
    /// single budget of paged-search state, which the controller resolves by discarding the oldest -
    /// so a concurrent read can silently truncate another one. The code that sends must therefore
    /// be serial, and that holds whether the concurrency came from a raw primitive or from the
    /// dispatcher: even turn-taking per host cannot save a file that sends two requests inside one
    /// turn.
    /// </remarks>
    [Fact]
    public void NoFileBothSendsARequestAndRunsWorkInParallel()
    {
        var offenders = CaptureFiles()
            .Where(f => Matches(f, SendsARequest)
                        && (Matches(f, RawFanOut) || Matches(f, DispatchedFanOut)))
            .Select(f => "  " + f)
            .OrderBy(f => f, StringComparer.Ordinal)
            .ToList();

        Assert.True(
            offenders.Count == 0,
            "A file that sends a request to a domain controller also runs work in parallel. "
            + "Requests are never pipelined: two in flight against one controller compete for a "
            + "single budget of paged-search state, which the controller resolves by discarding "
            + "the oldest, so a concurrent read can silently truncate another one. Running several "
            + "naming contexts at once is fine and is expected; running two requests at one "
            + "controller is not. Split the dispatching from the reading, as Preflight and "
            + "DomainPreflightRead are split:"
            + Environment.NewLine + string.Join(Environment.NewLine, offenders));
    }

    /// <summary>
    /// A file holding the means to reach a controller fans out only through the dispatcher.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>This is what keeps the rule above true rather than lucky.</b> A raw primitive cannot take
    /// turns, because it does not know which host a piece of work will reach. Work that touches a
    /// directory therefore goes through <c>DirectoryWorkDispatch</c>, which does - and a file that
    /// reaches for <c>Task.WhenAll</c> while holding connections has stepped outside the one place
    /// the rule is implemented.
    /// </para>
    /// <para>
    /// <b>It matters most where it looks least necessary.</b> The configuration partition, the
    /// schema partition and the root domain are commonly served by the same machine, so a fan-out
    /// that happens to be safe on a well-shaped forest is the defect this exists to refuse.
    /// </para>
    /// </remarks>
    [Fact]
    public void NoFileHoldingAConnectionFansOutWithoutTakingTurns()
    {
        var offenders = CaptureFiles()
            .Where(f => Matches(f, HoldsAConnection) && Matches(f, RawFanOut))
            .Select(f => "  " + f)
            .OrderBy(f => f, StringComparer.Ordinal)
            .ToList();

        Assert.True(
            offenders.Count == 0,
            "A file that holds the means to reach a domain controller runs work in parallel "
            + "through a primitive that cannot take turns. Task.WhenAll and its relatives do not "
            + "know which host a piece of work will reach, so they cannot stop two pieces reaching "
            + "the same one. Directory work that runs at once goes through "
            + "DirectoryWorkDispatch.TogetherAsync, which takes a turn per host:"
            + Environment.NewLine + string.Join(Environment.NewLine, offenders));
    }

    /// <summary>
    /// The scanner self-test. Without it the checks above pass by scanning an empty set of files,
    /// or by using patterns that match nothing, and report a clean project either way.
    /// </summary>
    [Fact]
    public void TheScannerReadsTheCaptureProjectAndEveryPatternMatches()
    {
        var files = CaptureFiles().ToList();

        Assert.True(
            files.Count > 0,
            $"Scanned no files under {CaptureProject}. The guard would report a clean project by "
            + "having failed to find the project.");

        // Each check is a conjunction, so each passes trivially if one half of it matches nothing
        // in the tree. Every half must find something real, or there is nothing being guarded.
        Assert.True(
            files.Any(f => Matches(f, SendsARequest)),
            "No file in the capture project sends a request, so the first rule is watching "
            + "nothing. Either the pattern has stopped matching, or the code that speaks to a "
            + "controller has moved out of this project.");

        Assert.True(
            files.Any(f => Matches(f, HoldsAConnection)),
            "No file in the capture project holds the means to reach a controller, so the second "
            + "rule is watching nothing.");

        Assert.True(
            files.Any(f => Matches(f, DispatchedFanOut)),
            "Nothing calls DirectoryWorkDispatch.TogetherAsync, so the shape this guard was "
            + "widened to cover in 2026-09-13 has gone. Either the dispatcher has been renamed - "
            + "in which case this pattern is now an invisible allowlist again - or parallel "
            + "directory work has been removed.");

        Assert.True(
            files.Any(f => Matches(f, RawFanOut)),
            "Nothing uses a raw fan-out primitive anywhere in the capture project, so the second "
            + "rule cannot fire. DirectoryWorkDispatch itself uses Task.WhenAll; if that has gone, "
            + "this guard needs rewriting rather than relaxing.");
    }

    /// <summary>
    /// The patterns tell apart the things they are meant to tell apart.
    /// </summary>
    /// <remarks>
    /// <b>A guard that matched everything or nothing would pass its own scanner self-test.</b>
    /// These assert the discriminations the rules rest on: sending is not the same as holding, and
    /// a dispatched fan-out is not the same as a raw one.
    /// </remarks>
    [Fact]
    public void ThePatternsTellTheRightThingsApart()
    {
        Assert.Matches(RawFanOut, "await Task.WhenAll(pages);");
        Assert.Matches(RawFanOut, "Parallel.ForEach(units, u => Read(u));");
        Assert.Matches(RawFanOut, "var q = items.AsParallel();");
        Assert.DoesNotMatch(RawFanOut, "await ReadOnePageAsync(request);");

        // The dispatcher is a fan-out and must never be mistaken for a raw one, in either
        // direction: counting it as raw would fail Preflight, and counting a raw primitive as
        // dispatched would let the unsafe shape through.
        Assert.Matches(DispatchedFanOut, "await DirectoryWorkDispatch.TogetherAsync(asked, 8,");
        Assert.DoesNotMatch(RawFanOut, "await DirectoryWorkDispatch.TogetherAsync(asked, 8,");
        Assert.DoesNotMatch(DispatchedFanOut, "await Task.WhenAll(pages);");

        // Sending is not holding. This is the distinction the old single pattern collapsed, which
        // is how Preflight was reported as an offender by the stated rule and passed anyway.
        Assert.Matches(SendsARequest, "var page = await channel.SendAsync(request, token);");
        Assert.Matches(SendsARequest, "var response = connection.SendRequest(request);");
        Assert.DoesNotMatch(SendsARequest, "IDirectoryChannelFactory connections,");
        Assert.DoesNotMatch(SendsARequest, "var total = objects.Count;");

        Assert.Matches(HoldsAConnection, "IDirectoryChannelFactory connections,");
        Assert.Matches(HoldsAConnection, "public SearchRequest ForUnit(CaptureUnit unit)");
        Assert.DoesNotMatch(HoldsAConnection, "var total = objects.Count;");
    }

    /// <summary>
    /// Both rules fire on the shapes they exist to refuse.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>This is the check the guard did not have, and its absence is how the hole survived.</b>
    /// Every assertion above proves a pattern matches something; none proved that the
    /// <i>conjunction</i> would ever fail a file. A guard whose rule can never fire passes exactly
    /// as a clean project does.
    /// </para>
    /// <para>
    /// The planted lines are the two ways the rule can be broken: a file that sends inside a
    /// fan-out of any kind, and a file that reaches for a raw primitive while holding connections.
    /// </para>
    /// </remarks>
    [Theory]
    [InlineData("await Task.WhenAll(units.Select(u => channel.SendAsync(For(u), token)));")]
    [InlineData("await DirectoryWorkDispatch.TogetherAsync(units, 8, (u, t) => channel.SendAsync(For(u), token));")]
    public void TheFirstRuleFiresOnAFileThatSendsInsideAFanOut(string planted)
    {
        Assert.Matches(SendsARequest, planted);
        Assert.True(
            RawFanOut.IsMatch(planted) || DispatchedFanOut.IsMatch(planted),
            "The planted line no longer reads as a fan-out, so it would not fail the rule it was "
            + "written to fail.");
    }

    /// <summary>
    /// The second rule fires on a raw fan-out beside a connection.
    /// </summary>
    [Fact]
    public void TheSecondRuleFiresOnARawFanOutBesideAConnection()
    {
        const string planted =
            "await Task.WhenAll(domains.Select(d => Read(d, connections)));"
            + " IDirectoryChannelFactory connections;";

        Assert.Matches(HoldsAConnection, planted);
        Assert.Matches(RawFanOut, planted);
    }

    /// <summary>
    /// The shapes the rules must permit are permitted.
    /// </summary>
    /// <remarks>
    /// <b>The negative control, and it is the half that decides whether this guard is usable.</b> A
    /// rule that failed these would be satisfied only by a product that reads one domain at a time,
    /// which is what <c>0041</c> exists to stop. <c>S-10</c> recorded this obligation when the rule
    /// was written: running several naming contexts at once is expected and safe, and a guard must
    /// permit it rather than forbid it by accident.
    /// </remarks>
    [Fact]
    public void TheShapesTheRulesMustPermitArePermitted()
    {
        // A dispatcher that fans out and holds nothing.
        const string dispatcher = "await Task.WhenAll(subjects.Select(async (subject, at) =>";
        Assert.DoesNotMatch(SendsARequest, dispatcher);
        Assert.DoesNotMatch(HoldsAConnection, dispatcher);

        // A caller that holds connections and fans out through the dispatcher - which is Preflight,
        // and will be CaptureRun under 0041.
        const string caller =
            "var outcomes = await DirectoryWorkDispatch.TogetherAsync(asked, 8,"
            + " (domain, turns) => Read(domain, connections, turns), token);"
            + " IDirectoryChannelFactory connections;";
        Assert.DoesNotMatch(SendsARequest, caller);
        Assert.DoesNotMatch(RawFanOut, caller);

        // A reader that sends and stays serial.
        const string reader = "var page = await channel.SendAsync(request, token);";
        Assert.DoesNotMatch(RawFanOut, reader);
        Assert.DoesNotMatch(DispatchedFanOut, reader);
    }

    /// <summary>
    /// The file that prompted the 2026-08-16 widening is still watched by name.
    /// </summary>
    /// <remarks>
    /// A pattern that stops matching it fails silently and returns this guard to reporting a clean
    /// project. It is watched under <see cref="HoldsAConnection"/> rather than
    /// <see cref="SendsARequest"/> because it keeps the factory and hands it to
    /// <c>DomainPreflightRead</c>, which does the reading - so the second rule is the one standing
    /// between it and a raw fan-out.
    /// </remarks>
    [Fact]
    public void PreflightIsStillWatched()
    {
        var preflight = CaptureFiles().Single(f => f.EndsWith(
            $"{Path.DirectorySeparatorChar}Preflight.cs", StringComparison.Ordinal));

        Assert.True(
            Matches(preflight, HoldsAConnection),
            "Preflight.cs connects to every domain controller in the forest and is no longer "
            + "recognised as holding a connection. The guard is back to the state it was in on "
            + "2026-08-16, when it passed while ignoring the file most able to breach the rule.");

        Assert.True(
            Matches(preflight, DispatchedFanOut),
            "Preflight.cs no longer fans out through the dispatcher. If it now fans out some "
            + "other way, the rules above should have failed; if it no longer fans out at all, "
            + "this guard is watching a file that cannot breach the rule and the pattern that "
            + "covers CaptureRun needs checking instead.");
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
