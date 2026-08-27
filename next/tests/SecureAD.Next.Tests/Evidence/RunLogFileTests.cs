using SecureAD.Evidence;
using SecureAD.Kernel;
using Xunit;

namespace SecureAD.Next.Tests.Evidence;

/// <summary>
/// The run log's format, which is the whole of its value.
/// </summary>
/// <remarks>
/// <para>
/// <b>These tests are about legibility, and that is not a soft property here.</b>
/// <c>docs/decisions/0088-a-run-writes-a-log.md</c> chose text over JSON on the grounds that the
/// reader is a person holding a bundle a customer sent, so a format that drifts out of alignment or
/// writes a distinguished name ambiguously has lost the argument that justified it.
/// </para>
/// <para>
/// <b>The quoting rule is the part most likely to be got wrong.</b> Nearly every value this log
/// names is a distinguished name, and a distinguished name contains both spaces and equals signs -
/// the two characters that make <c>name=value</c> ambiguous.
/// </para>
/// </remarks>
public sealed class RunLogFileTests : IDisposable
{
    private static readonly DateTimeOffset Noon =
        new(2026, 8, 28, 11, 6, 2, TimeSpan.Zero);

    private readonly string _directory =
        Path.Combine(Path.GetTempPath(), "runlog-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        if (Directory.Exists(_directory))
            Directory.Delete(_directory, recursive: true);
    }

    /// <summary>
    /// A note carries the time, the level and the phase in fixed columns.
    /// </summary>
    [Fact]
    public void ANoteIsWrittenInColumns()
    {
        var line = Single(log =>
            log.Note("MembershipAndNesting", "read 4,273 objects", []));

        Assert.StartsWith("2026-08-28T11:06:02Z  INFO   MembershipAndNesting", line, StringComparison.Ordinal);
        Assert.EndsWith("read 4,273 objects", line, StringComparison.Ordinal);
    }

    /// <summary>
    /// Every level occupies the same width, so the phase and message columns line up down the file.
    /// </summary>
    /// <remarks>
    /// The reason the level column is padded at all: an operator scanning a long log reads down the
    /// left, and a ragged column defeats that.
    /// </remarks>
    [Fact]
    public void EveryLevelIsTheSameWidth()
    {
        var lines = Lines(log =>
        {
            log.Note("Derive", "started", []);
            log.Record("Derive", Error(ErrorSeverity.Degraded), []);
            log.Record("Derive", Error(ErrorSeverity.Failed), []);
        });

        var phaseColumns = lines
            .Where(l => l.Contains("Derive", StringComparison.Ordinal))
            .Select(l => l.IndexOf("Derive", StringComparison.Ordinal))
            .Distinct()
            .ToList();

        Assert.Single(phaseColumns);
    }

    /// <summary>
    /// An error's level comes from the error, not from whoever logged it.
    /// </summary>
    /// <remarks>
    /// <b>A caller free to choose the level could log a failure as a note.</b> The severity is
    /// already on the <see cref="AuditError"/> and is the only thing consulted.
    /// </remarks>
    [Theory]
    [InlineData(ErrorSeverity.Degraded, "WARN")]
    [InlineData(ErrorSeverity.Failed, "ERROR")]
    public void AnErrorsLevelComesFromTheError(ErrorSeverity severity, string expected)
    {
        var line = Single(log => log.Record("Derive", Error(severity), []));

        Assert.Contains(expected, line, StringComparison.Ordinal);
    }

    /// <summary>
    /// The error's code is on the headline, where it can be searched for.
    /// </summary>
    /// <remarks>
    /// The description goes underneath. A code buried behind a sentence is a code nobody can grep,
    /// and the code is the stable half - descriptions get reworded.
    /// </remarks>
    [Fact]
    public void TheCodeIsOnTheHeadlineAndTheDescriptionBelow()
    {
        var lines = Lines(log => log.Record("Derive", Error(ErrorSeverity.Failed), []));

        var headline = lines.Single(l => l.Contains("ERROR", StringComparison.Ordinal));

        Assert.EndsWith("Evidence.SomethingBroke", headline, StringComparison.Ordinal);
        Assert.Contains(lines, l => l.Contains("it did not work", StringComparison.Ordinal));
    }

    /// <summary>
    /// A distinguished name is written so it can be read back unambiguously.
    /// </summary>
    /// <remarks>
    /// <b>This is the case the format exists to survive.</b> A DN carries spaces and equals signs,
    /// so unquoted <c>object=CN=Domain Admins,CN=Users,DC=ad,DC=lab</c> cannot be split back into a
    /// name and a value by anything - including the person reading it, who cannot tell where the
    /// value ends and the next pair begins.
    /// </remarks>
    [Fact]
    public void ADistinguishedNameIsQuoted()
    {
        var line = Single(log => log.Note(
            "Derive",
            "resolved a member",
            [new RunLogDetail("object", "CN=Domain Admins,CN=Users,DC=ad,DC=lab")]));

        Assert.Contains(
            "object=\"CN=Domain Admins,CN=Users,DC=ad,DC=lab\"",
            line,
            StringComparison.Ordinal);
    }

    /// <summary>
    /// A value with nothing awkward in it is left unquoted, so the common line stays readable.
    /// </summary>
    /// <remarks>
    /// Quoting everything would be simpler and would make every line noisier than it needs to be.
    /// A SID and a domain name are the values this log writes most.
    /// </remarks>
    [Fact]
    public void APlainValueIsNotQuoted()
    {
        var line = Single(log => log.Note(
            "Derive",
            "scoped a principal",
            [new RunLogDetail("sid", "S-1-5-32-544"), new RunLogDetail("domain", "ba.ad.lab")]));

        Assert.Contains("sid=S-1-5-32-544 domain=ba.ad.lab", line, StringComparison.Ordinal);
    }

    /// <summary>
    /// A value carrying a quotation mark does not end the value early.
    /// </summary>
    [Fact]
    public void AQuoteInsideAValueIsEscaped()
    {
        var line = Single(log => log.Note(
            "Derive",
            "read a display name",
            [new RunLogDetail("name", "The \"Old\" Group")]));

        Assert.Contains("name=\"The \\\"Old\\\" Group\"", line, StringComparison.Ordinal);
    }

    /// <summary>
    /// A Windows path is written as it stands, not with every separator doubled.
    /// </summary>
    /// <remarks>
    /// <b>The first real run against a forest produced
    /// <c>bundle="C:\\Users\\ba.admin\\Downloads\\SecureAD"</c></b>, because the rule escaped
    /// backslashes the way logfmt does. It was unambiguous and unreadable, and this log is going to
    /// be full of paths. <c>0088</c> chose text over JSON so a person could read it without
    /// decoding, and doubling every separator gives back exactly what that bought.
    /// </remarks>
    [Fact]
    public void AWindowsPathIsNotDoubledUp()
    {
        var line = Single(log => log.Note(
            "Capture",
            "finished",
            [new RunLogDetail("bundle", @"C:\Users\ba.admin\Downloads\SecureAD\ad.lab-20260827")]));

        Assert.Contains(@"bundle=C:\Users\ba.admin\Downloads\SecureAD\ad.lab-20260827", line, StringComparison.Ordinal);
        Assert.DoesNotContain(@"\\", line, StringComparison.Ordinal);
    }

    /// <summary>
    /// A path with a space in it is still quoted, and still readable inside the quotes.
    /// </summary>
    [Fact]
    public void APathWithASpaceIsQuotedButNotEscaped()
    {
        var line = Single(log => log.Note(
            "Capture",
            "finished",
            [new RunLogDetail("bundle", @"C:\Program Files\SecureAD")]));

        Assert.Contains(@"bundle=""C:\Program Files\SecureAD""", line, StringComparison.Ordinal);
    }

    /// <summary>
    /// A second session appends rather than replacing, and says where it began.
    /// </summary>
    /// <remarks>
    /// One bundle's log is written by the capture, then the derivation, then the judging - and a
    /// bundle can be derived again later. Without a banner the second derivation's lines are
    /// indistinguishable from the first's.
    /// </remarks>
    [Fact]
    public void EachSessionAppendsUnderItsOwnBanner()
    {
        using (var first = Opened("capture"))
            first.Note("Capture", "read a domain", []);

        using (var second = Opened("deriving"))
            second.Note("Derive", "read the nesting", []);

        var text = File.ReadAllText(BundleLayout.RunLogPath(_directory));

        Assert.Contains("capture ====", text, StringComparison.Ordinal);
        Assert.Contains("deriving ====", text, StringComparison.Ordinal);
        Assert.Contains("read a domain", text, StringComparison.Ordinal);
        Assert.Contains("read the nesting", text, StringComparison.Ordinal);
    }

    /// <summary>
    /// A log in a directory that cannot be written refuses rather than throwing.
    /// </summary>
    /// <remarks>
    /// <b>Losing the account of a capture is not a reason to lose the capture.</b> The caller is
    /// told and carries on with <see cref="RunLog.Discarded"/>.
    /// </remarks>
    [Fact]
    public void ALogThatCannotBeOpenedIsARefusalRatherThanAThrow()
    {
        // A path whose parent is a file cannot become a directory.
        Directory.CreateDirectory(_directory);
        var blocker = Path.Combine(_directory, "blocker");
        File.WriteAllText(blocker, string.Empty);

        var opened = RunLogFile.Open(
            Path.Combine(blocker, "inside"),
            "capture",
            new FixedTime(Noon));

        Assert.False(opened.IsSuccess);
        Assert.Equal(ErrorSeverity.Degraded, opened.Error!.Severity);
    }

    /// <summary>
    /// Writing the log leaves the sealed evidence untouched.
    /// </summary>
    /// <remarks>
    /// <b>The log is written while the run is going, and the seal is taken at the end of it.</b> If
    /// logging could disturb the seal then keeping an account of a capture would destroy the proof
    /// that the capture is unmodified - which is the trade <c>0030</c> refuses. This is the same
    /// property <c>RunAnnotations</c> has to hold, proved the same way.
    /// </remarks>
    [Fact]
    public void LoggingLeavesTheSealedEvidenceUntouched()
    {
        Directory.CreateDirectory(_directory);
        File.WriteAllText(BundleLayout.EvidencePath(_directory), "sealed evidence");
        BundleSealing.Seal(
            BundleLayout.EvidencePath(_directory), BundleLayout.SealPath(_directory));

        using (var log = Opened("deriving"))
        {
            log.Note("Derive", "wrote a great many lines", []);
            log.Record("Derive", Error(ErrorSeverity.Failed), []);
        }

        Assert.True(BundleSealing.Verify(_directory).MayBeOpened);
    }

    /// <summary>
    /// The scanner self-test. Proves the seal check above can fail, so that
    /// <see cref="LoggingLeavesTheSealedEvidenceUntouched"/> is not passing because nothing would
    /// ever break it.
    /// </summary>
    [Fact]
    public void TheSealCheckUsedAboveCanFail()
    {
        Directory.CreateDirectory(_directory);
        File.WriteAllText(BundleLayout.EvidencePath(_directory), "sealed evidence");
        BundleSealing.Seal(
            BundleLayout.EvidencePath(_directory), BundleLayout.SealPath(_directory));

        File.AppendAllText(BundleLayout.EvidencePath(_directory), "tampered");

        Assert.False(BundleSealing.Verify(_directory).MayBeOpened);
    }

    private static AuditError Error(ErrorSeverity severity) => AuditError.Create(
        ErrorCategory.Evidence,
        "SomethingBroke",
        severity,
        "it did not work",
        context: null);

    private RunLogFile Opened(string session)
    {
        var opened = RunLogFile.Open(_directory, session, new FixedTime(Noon));
        Assert.True(opened.IsSuccess);
        return opened.Value!;
    }

    /// <summary>Every line a log wrote, banners and blanks removed.</summary>
    private IReadOnlyList<string> Lines(Action<RunLogFile> writing)
    {
        using (var log = Opened("test"))
            writing(log);

        return
        [
            .. File.ReadAllLines(BundleLayout.RunLogPath(_directory))
                .Where(l => !string.IsNullOrWhiteSpace(l))
                .Where(l => !l.StartsWith("====", StringComparison.Ordinal)),
        ];
    }

    private string Single(Action<RunLogFile> writing) => Lines(writing)[0];

    private sealed class FixedTime(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
