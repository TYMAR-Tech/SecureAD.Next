using System.Globalization;
using System.Text;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel;

namespace SecureAD.Evidence.Run;

/// <summary>
/// Writes <see cref="BundleLayout.PortableSummaryFileName"/>, the one file of a run that may leave
/// the environment the run happened in.
/// </summary>
/// <remarks>
/// <para>
/// <b>Typed in, text out, and never the other way round.</b> Every method here takes a record whose
/// members are counts, durations, product-defined words or a domain name. There is deliberately no
/// method that accepts free text, because that is the method a distinguished name would eventually
/// be passed to. The confidentiality guarantee is the shape of this API, not a filter applied
/// afterwards.
/// </para>
/// <para>
/// <b>Sections are appended in the order the run did them.</b> A capture writes first; a derivation
/// and a judging append theirs whenever they happen, which for a capture-only run may be days later
/// and from a different screen. A bundle derived twice gets two derivation sections, which is what
/// the log does and is the honest record.
/// </para>
/// <para>
/// <b>A summary that cannot be written never stops the run.</b> The same rule
/// <see cref="RunLogFile"/> keeps: losing the account of a capture is not a reason to lose the
/// capture.
/// </para>
/// </remarks>
public static class PortableSummaryFile
{
    /// <summary>How wide the label column is, so an eye can run down the values.</summary>
    private const int Label = 14;

    /// <summary>
    /// What this file is, said at the top of it, for whoever is asked to approve it leaving.
    /// </summary>
    /// <remarks>
    /// <b>The claim is stated so it can be checked.</b> A reader who is told exactly what the file
    /// is supposed to contain can look and see whether it does. A file that simply arrived with no
    /// statement of intent would have to be trusted instead, and trust is what the customer has
    /// already declined to extend to <c>run.log</c>.
    /// </remarks>
    private static readonly string[] Preamble =
    [
        "SecureAD run summary",
        "====================",
        "",
        "Written so it can leave the environment the run happened in. It carries counts,",
        "durations, the product's own codes for what went wrong, and domain names.",
        "",
        "It does not carry server names, network addresses, distinguished names, object or",
        "account names, security identifiers, file paths, or any message text from the",
        "directory. The run's full log stays in the bundle and is not summarised here.",
    ];

    /// <summary>Writes the capture section, starting the file.</summary>
    /// <param name="bundleDirectory">The run's directory.</param>
    /// <param name="summary">What the capture did.</param>
    /// <returns>Where it was written, or why it could not be.</returns>
    public static Result<string> WriteCapture(string bundleDirectory, CaptureSummary summary)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(bundleDirectory);
        ArgumentNullException.ThrowIfNull(summary);

        var text = new StringBuilder();

        foreach (var line in Preamble)
            text.AppendLine(line);

        text.AppendLine();
        Field(text, "Product", summary.ProductVersion);
        Field(text, "Runtime", summary.Runtime + " on " + summary.OperatingSystem);
        Field(text, "Capture", summary.RunState + " in " + Spoken(summary.ElapsedMilliseconds));

        Stages(text, "Stages", summary.Stages);
        Domains(text, summary.Domains);
        Problems(text, summary.Problems);

        return Write(bundleDirectory, text.ToString(), append: false);
    }

    /// <summary>Appends the derivation section.</summary>
    /// <param name="bundleDirectory">The run's directory.</param>
    /// <param name="summary">What the derivation did.</param>
    /// <returns>Where it was written, or why it could not be.</returns>
    public static Result<string> AppendDerivation(string bundleDirectory, DerivationSummary summary)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(bundleDirectory);
        ArgumentNullException.ThrowIfNull(summary);

        var text = new StringBuilder();

        Heading(text, "Derivation");
        Field(text, "Result", summary.State + " in " + Spoken(summary.ElapsedMilliseconds));
        Field(text, "Principals", Number(summary.Principals));
        Field(text, "Nesting", Number(summary.NestingEdges) + " relationships");

        Stages(text, "Phases", summary.Phases);
        Problems(text, summary.Problems);

        return Write(bundleDirectory, text.ToString(), append: true);
    }

    /// <summary>Appends the judging section.</summary>
    /// <param name="bundleDirectory">The run's directory.</param>
    /// <param name="summary">What the judging did.</param>
    /// <returns>Where it was written, or why it could not be.</returns>
    public static Result<string> AppendJudging(string bundleDirectory, JudgingSummary summary)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(bundleDirectory);
        ArgumentNullException.ThrowIfNull(summary);

        var text = new StringBuilder();

        Heading(text, "Judging");
        Field(text, "Result", summary.State + " in " + Spoken(summary.ElapsedMilliseconds));
        Field(text, "Objects", Number(summary.ObjectsJudged) + " judged");

        Stages(text, "Phases", summary.Phases);

        if (summary.Rules.Count > 0)
        {
            text.AppendLine();
            text.AppendLine("Rules");
            text.AppendLine("  rule                      outcome        judged    not about        ms");

            foreach (var rule in summary.Rules)
            {
                text.AppendLine(
                    "  " + Fit(rule.Rule, 24)
                    + "  " + Fit(rule.Outcome, 13)
                    + "  " + Right(rule.Judged, 8)
                    + "  " + Right(rule.NotAbout, 11)
                    + "  " + Right(rule.Milliseconds, 8));
            }
        }

        // Counted by severity and never listed. A finding names the object it is about, so the
        // findings themselves stay in the bundle; how many there were of each kind travels.
        text.AppendLine();
        text.AppendLine("Findings");

        if (summary.Findings.Count == 0)
        {
            // Said in words rather than printed as a row of noughts, per
            // docs/decisions/0002-absent-view-means-degraded-run.md: a column of zeros reads as a
            // clean forest, and "none were recorded" is the thing that was actually established.
            text.AppendLine("  None were recorded.");
        }
        else
        {
            foreach (var severity in summary.Findings.OrderByDescending(entry => entry.Key))
                text.AppendLine("  " + Fit(severity.Key.ToString(), 14) + Right(severity.Value, 8));
        }

        Problems(text, summary.Problems);

        return Write(bundleDirectory, text.ToString(), append: true);
    }

    private static void Heading(StringBuilder text, string heading)
    {
        text.AppendLine();
        text.AppendLine(heading);
        text.AppendLine(new string('=', heading.Length));
        text.AppendLine();
    }

    private static void Field(StringBuilder text, string label, string value) =>
        text.AppendLine(Fit(label, Label) + value);

    private static void Stages(StringBuilder text, string heading, IReadOnlyList<StageTiming> stages)
    {
        if (stages.Count == 0)
            return;

        text.AppendLine();
        text.AppendLine(heading);

        foreach (var stage in stages)
            text.AppendLine("  " + Fit(stage.Name, 24) + Right(stage.Milliseconds, 12) + " ms");
    }

    private static void Domains(StringBuilder text, IReadOnlyList<SummarisedDomain> domains)
    {
        if (domains.Count == 0)
            return;

        // GATHERED IN ONE PLACE, DELIBERATELY. Domain names are the only identifying thing the
        // owner permitted into this file, so they are all in one block he can check before sending
        // rather than scattered through it.
        text.AppendLine();
        text.AppendLine("Domains");
        text.AppendLine("  domain                          outcome           objects         entries           ms   controller in site");

        foreach (var domain in domains)
        {
            text.AppendLine(
                "  " + Fit(domain.DomainName, 30)
                + "  " + Fit(domain.Outcome.ToString(), 16)
                + Right(domain.Objects, 8)
                + Right(domain.AccessControlEntries, 16)
                + Right(domain.ElapsedMilliseconds, 13)
                + "   " + domain.ControllerInOperatorSite switch
                {
                    true => "yes",
                    false => "no",
                    // Not a no. The capture machine had no site of its own, so there was nothing to
                    // compare against, and saying "no" would assert a fact nobody established.
                    null => "not established",
                });
        }
    }

    private static void Problems(StringBuilder text, IReadOnlyList<ProblemCount> problems)
    {
        if (problems.Count == 0)
            return;

        text.AppendLine();
        text.AppendLine("Problems");

        foreach (var problem in problems)
        {
            text.AppendLine(
                "  " + Fit(problem.Category + " / " + problem.Code, 44)
                + Fit(problem.Severity.ToString(), 12)
                + "x" + Number(problem.Count));
        }
    }

    private static string Fit(string value, int width) =>
        value.Length >= width ? value + "  " : value.PadRight(width);

    private static string Right(long value, int width) =>
        Number(value).PadLeft(width);

    private static string Number(long value) =>
        value.ToString("N0", CultureInfo.InvariantCulture);

    /// <summary>A duration a person can judge at a glance, rather than eight digits of milliseconds.</summary>
    private static string Spoken(long milliseconds)
    {
        var span = TimeSpan.FromMilliseconds(milliseconds);

        return span.TotalHours >= 1
            ? $"{(int)span.TotalHours} h {span.Minutes} m"
            : span.TotalMinutes >= 1
                ? $"{(int)span.TotalMinutes} m {span.Seconds} s"
                : $"{span.TotalSeconds.ToString("0.0", CultureInfo.InvariantCulture)} s";
    }

    private static Result<string> Write(string bundleDirectory, string text, bool append)
    {
        var path = BundleLayout.PortableSummaryPath(bundleDirectory);

        try
        {
            Directory.CreateDirectory(bundleDirectory);

            if (append)
                File.AppendAllText(path, text, Utf8);
            else
                File.WriteAllText(path, text, Utf8);

            return Result<string>.Success(path);
        }
        catch (Exception failure) when (failure is IOException or UnauthorizedAccessException)
        {
            return Result<string>.Failure(AuditError.Create(
                ErrorCategory.Evidence,
                "PortableSummaryUnwritable",
                ErrorSeverity.Degraded,
                $"The run's summary could not be written in '{bundleDirectory}': {failure.Message} "
                + "The run itself is unaffected, and its log is unchanged.",
                bundleDirectory));
        }
    }

    private static readonly UTF8Encoding Utf8 = new(encoderShouldEmitUTF8Identifier: false);
}
