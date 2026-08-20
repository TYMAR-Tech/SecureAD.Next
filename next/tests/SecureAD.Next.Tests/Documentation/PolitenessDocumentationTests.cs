using System.Reflection;
using SecureAD.Audit.Capture;
using SecureAD.Next.Tests.Inventory;
using Xunit;

namespace SecureAD.Next.Tests.Documentation;

/// <summary>
/// Binds <c>docs/next/S-10-politeness.md</c> to <see cref="ServerLimits"/>.
///
/// <para>
/// This is inventory row B7's deliverable. The row owes "every server-side limit the client respects
/// and the value it uses against each, named rather than guessed", and the thing that makes that
/// real is a check that the document and the code name the same limits with the same defaults -
/// because the failure being guarded against is a plausible number written down once and never
/// traced to a source. <c>docs/decisions/0016</c> is the record that a plausible mechanism is not a
/// source.
/// </para>
/// <para>
/// <b>What it cannot check.</b> That the defaults are right - they are transcribed from Microsoft's
/// article and a reader has to compare them - or that capture is polite in practice, which needs
/// something that issues a request. That is inventory row B6.
/// </para>
/// </summary>
public sealed class PolitenessDocumentationTests
{
    private const string Document = "S-10-politeness.md";
    private const string TableBegin = "<!-- LIMITS:BEGIN -->";
    private const string TableEnd = "<!-- LIMITS:END -->";

    [Fact]
    public void TheDocumentDescribesEveryLimitTheCodeNames()
    {
        var documented = DocumentedLimits();

        var missing = CodeLimits()
            .Where(l => !documented.ContainsKey(l.Name))
            .Select(l => "  " + l.Name)
            .ToList();

        Assert.True(
            missing.Count == 0,
            "Limits the code names that " + Document + " does not describe:"
            + Environment.NewLine + string.Join(Environment.NewLine, missing));
    }

    [Fact]
    public void TheDocumentDescribesNoLimitTheCodeDoesNotName()
    {
        var known = CodeLimits().Select(l => l.Name).ToHashSet(StringComparer.Ordinal);

        var phantom = DocumentedLimits().Keys
            .Where(name => !known.Contains(name))
            .Select(name => "  " + name)
            .ToList();

        Assert.True(
            phantom.Count == 0,
            Document + " describes limits the code does not name. A document promising that "
            + "capture respects a limit nothing in the code has heard of is the exact failure this "
            + "row exists to prevent:"
            + Environment.NewLine + string.Join(Environment.NewLine, phantom));
    }

    [Fact]
    public void EveryLimitCarriesTheSameDocumentedDefaultInBothPlaces()
    {
        var documented = DocumentedLimits();

        var disagreeing = CodeLimits()
            .Where(l => documented.TryGetValue(l.Name, out var row)
                        && row.Default != l.DocumentedDefault)
            .Select(l => $"  {l.Name}: code says '{l.DocumentedDefault}', {Document} says "
                         + $"'{documented[l.Name].Default}'")
            .ToList();

        Assert.True(
            disagreeing.Count == 0,
            "A limit's documented default differs between the code and the document. One of them "
            + "was edited without the other, and a wrong default is a client that pushes harder "
            + "than it believes it does:"
            + Environment.NewLine + string.Join(Environment.NewLine, disagreeing));
    }

    /// <summary>
    /// Every limit says what capture does about it, and never nothing. A limit capture does not
    /// respect is a limit capture will meet, and the answer must at least say what happens then.
    /// </summary>
    [Fact]
    public void EveryLimitSaysWhatCaptureDoesAboutIt()
    {
        var silent = DocumentedLimits()
            .Where(l => l.Value.Response.Length < 3 || l.Value.Response == "-")
            .Select(l => "  " + l.Key)
            .ToList();

        Assert.True(
            silent.Count == 0,
            "Limits in " + Document + " with nothing said about what capture does:"
            + Environment.NewLine + string.Join(Environment.NewLine, silent));
    }

    /// <summary>
    /// The two limits the code does not merely describe but uses. Without this the table could be
    /// perfectly accurate prose beside a request that asks for something else entirely.
    /// </summary>
    [Fact]
    public void TheTwoLimitsCaptureActsOnAreTheValuesItActsWith()
    {
        Assert.Equal("1,000 objects", $"{ServerLimits.PageSize:N0} objects");
        Assert.Equal(ServerLimits.MaxPageSize.DocumentedDefault, $"{ServerLimits.PageSize:N0} objects");

        Assert.Equal(
            ServerLimits.MaxQueryDuration.DocumentedDefault,
            $"{(int)ServerLimits.QueryDuration.TotalSeconds} seconds");
    }

    /// <summary>
    /// The scanner self-test. Without it the two directions above pass by comparing an empty table
    /// with an empty reflection - the failure this repository has committed three times.
    /// </summary>
    [Fact]
    public void TheCheckReadsBothTheTableAndTheCode()
    {
        var documented = DocumentedLimits();
        var code = CodeLimits();

        Assert.True(code.Count >= 10, $"Reflected over {code.Count} limits, expected at least ten.");
        Assert.Equal(code.Count, documented.Count);

        Assert.Contains("MaxConnIdleTime", documented.Keys);
        Assert.Contains(code, l => l.Name == "MaxResultSetSize");

        // The negative control: a limit that is documented as unenforced must still be present,
        // because the reason it is listed is precisely that it must not be cited as a constraint.
        Assert.Contains("MaxActiveQueries", documented.Keys);
        Assert.Contains("not enforced", documented["MaxActiveQueries"].Default, StringComparison.Ordinal);
    }

    [Fact]
    public void TheDocumentDescribesEveryFailureThePolicyAnswers()
    {
        var documented = DocumentedFailures();

        var missing = CodeFailures()
            .Where(f => !documented.ContainsKey(f.Name))
            .Select(f => "  " + f.Name)
            .ToList();

        Assert.True(
            missing.Count == 0,
            "Failures the retry policy answers that " + Document + " does not describe. What "
            + "capture does when a controller stops answering decides whether a customer gets a "
            + "partial forest or an honest failure, so it is not something to leave in the code:"
            + Environment.NewLine + string.Join(Environment.NewLine, missing));
    }

    [Fact]
    public void TheDocumentDescribesNoFailureThePolicyDoesNotAnswer()
    {
        var known = CodeFailures().Select(f => f.Name).ToHashSet(StringComparer.Ordinal);

        var phantom = DocumentedFailures().Keys
            .Where(name => !known.Contains(name))
            .Select(name => "  " + name)
            .ToList();

        Assert.True(
            phantom.Count == 0,
            Document + " describes a response to a failure the policy has no entry for:"
            + Environment.NewLine + string.Join(Environment.NewLine, phantom));
    }

    /// <summary>
    /// The document and the code agree on which code each failure arrives with. A wrong number
    /// here is a failure classified as something else - a dropped connection answered as though
    /// the controller were merely busy, which would resend a bookmark the controller has
    /// forgotten.
    /// </summary>
    [Fact]
    public void EveryFailureCarriesTheSameCodeInBothPlaces()
    {
        var documented = DocumentedFailures();

        var disagreeing = CodeFailures()
            .Where(f => f.ResultCode >= 0)
            .Where(f => documented.TryGetValue(f.Name, out var row) && row.Code != f.ResultCode.ToString())
            .Select(f => $"  {f.Name}: code says {f.ResultCode}, {Document} says "
                         + $"'{documented[f.Name].Code}'")
            .ToList();

        Assert.True(
            disagreeing.Count == 0,
            string.Join(Environment.NewLine, disagreeing));

        // The catch-all has no number of its own - it is what any unlisted code gets - so the
        // document must say so rather than carry a number that looks like a real result code.
        Assert.Equal(-1, RetryPolicy.Unrecognised.ResultCode);
        Assert.Equal("any other", documented["Unrecognised"].Code);
    }

    /// <summary>
    /// The distinction the whole policy turns on: a failure that ends the conversation with the
    /// controller cannot be answered by resending the request, because the paging bookmark went
    /// with it. If these three ever agreed with the others, a partial read would be resumed from a
    /// bookmark nothing remembers.
    /// </summary>
    [Fact]
    public void AFailureThatEndsTheConversationIsNeverAnsweredByResendingTheRequest()
    {
        Assert.Equal(FailureResponse.RestartTheUnit, RetryPolicy.ServerDown.Response);
        Assert.Equal(FailureResponse.RestartTheUnit, RetryPolicy.ClientTimeout.Response);

        Assert.Equal(FailureResponse.RetryTheRequest, RetryPolicy.ServerBusy.Response);
        Assert.Equal(FailureResponse.RetryTheRequest, RetryPolicy.ServerUnavailable.Response);

        Assert.Equal(FailureResponse.EndTheRun, RetryPolicy.Unrecognised.Response);
    }

    /// <summary>
    /// An unknown code gets an answer rather than nothing. A lookup that can return "no
    /// instruction" is the shape that produces a swallowed exception at the call site.
    /// </summary>
    [Fact]
    public void EveryPossibleFailureCodeGetsAnAnswer()
    {
        Assert.Equal(RetryPolicy.ServerBusy, RetryPolicy.FailureFor(51));
        Assert.Equal(RetryPolicy.Unrecognised, RetryPolicy.FailureFor(49));
        Assert.Equal(RetryPolicy.Unrecognised, RetryPolicy.FailureFor(0));
        Assert.Equal(RetryPolicy.Unrecognised, RetryPolicy.FailureFor(int.MaxValue));
    }

    /// <summary>
    /// The wait doubles, and the first one is long. A controller that has just said it is busy is
    /// the last one to ask again immediately.
    /// </summary>
    [Fact]
    public void TheWaitDoublesAndStartsLong()
    {
        var busy = RetryPolicy.ServerBusy;

        Assert.Equal(TimeSpan.FromSeconds(5), RetryPolicy.WaitBefore(busy, 2));
        Assert.Equal(TimeSpan.FromSeconds(10), RetryPolicy.WaitBefore(busy, 3));
        Assert.Equal(3, RetryPolicy.MaxAttemptsPerRequest);
        Assert.Equal(1, RetryPolicy.MaxRestartsPerUnit);
    }

    /// <summary>Every <see cref="DirectoryFailure"/> the policy exposes.</summary>
    private static List<DirectoryFailure> CodeFailures() =>
        typeof(RetryPolicy)
            .GetProperties(BindingFlags.Public | BindingFlags.Static)
            .Where(p => p.PropertyType == typeof(DirectoryFailure))
            .Select(p => (DirectoryFailure)p.GetValue(null)!)
            .ToList();

    private static Dictionary<string, (string Code, string Response)> DocumentedFailures() =>
        Table("<!-- RETRY:BEGIN -->", "<!-- RETRY:END -->", "Failure");

    /// <summary>Every <see cref="ServerLimit"/> the code exposes, found by reflection so that a
    /// new one cannot be added without the document noticing.</summary>
    private static List<ServerLimit> CodeLimits() =>
        typeof(ServerLimits)
            .GetProperties(BindingFlags.Public | BindingFlags.Static)
            .Where(p => p.PropertyType == typeof(ServerLimit))
            .Select(p => (ServerLimit)p.GetValue(null)!)
            .ToList();

    private static Dictionary<string, (string Default, string Response)> DocumentedLimits() =>
        Table(TableBegin, TableEnd, "Limit");

    /// <summary>
    /// A three-column table between two markers, keyed by its first column. Only what lies between
    /// the markers is read, so a limit named in the prose does not count as a documented one, and
    /// a missing marker fails rather than silently emptying the scan.
    /// </summary>
    private static Dictionary<string, (string Second, string Third)> Table(
        string begin, string end, string headerCell)
    {
        var path = Path.Combine(OldAppInventory.RepositoryRoot(), "docs", "next", Document);
        Assert.True(File.Exists(path), $"Expected the document at {path}.");

        var lines = File.ReadAllLines(path);
        var first = Array.FindIndex(lines, l => l.Trim() == begin);
        var last = Array.FindIndex(lines, l => l.Trim() == end);

        if (first < 0 || last < 0 || last < first)
        {
            throw new InvalidOperationException(
                $"Could not find the {begin} / {end} markers in {Document}. The tests parse only "
                + "what lies between them, so a missing marker must fail rather than silently "
                + "widen or empty the scan.");
        }

        var rows = new Dictionary<string, (string, string)>(StringComparer.Ordinal);

        for (var i = first + 1; i < last; i++)
        {
            var line = lines[i].Trim();
            if (!line.StartsWith('|') || !line.EndsWith('|'))
                continue;

            var cells = line.Trim('|').Split('|').Select(c => c.Trim()).ToArray();
            if (cells.Length < 3 || cells[0] == headerCell || cells[0].All(c => c is '-' or ':'))
                continue;

            rows[cells[0]] = (cells[1], cells[2]);
        }

        return rows;
    }
}
