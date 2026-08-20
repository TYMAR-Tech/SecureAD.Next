using SecureAD.Shell.ViewModels;

namespace SecureAD.Shell.Services;

/// <summary>
/// One domain this run will read, and the controller it will read it from.
/// </summary>
/// <param name="Domain">The domain, as the forest declared it.</param>
/// <param name="Controller">The controller the run will read it from.</param>
internal sealed record ReviewedDomain(string Domain, string Controller);

/// <summary>
/// The whole audit, as it is put to the operator before he commits to it.
/// </summary>
/// <remarks>
/// <para>
/// <b>What this exists to say is what the table cannot.</b> A table of domains answers <i>what
/// will be read, and from where</i>. It cannot answer <i>what will this audit not be able to tell
/// me</i>, because that is a fact about the run as a whole rather than about any row. An operator
/// committing a machine to a read measured in hours is deciding on the second question.
/// </para>
/// <para>
/// <b>Both halves are always present, including when one is empty.</b> A review that listed only
/// what would be read would let a run with three excluded domains look identical to a run with
/// none. Per <c>docs/decisions/0063-excluded-never-looks-like-unreachable.md</c> the domains not
/// covered carry their own cause, so the two kinds are told apart here as everywhere else.
/// </para>
/// </remarks>
/// <param name="ForestFqdn">The forest the run found for itself.</param>
/// <param name="WillBeRead">Every domain the run will read, with its controller.</param>
/// <param name="WillNotBeRead">
/// Every domain leaving the run, each carrying which kind of exclusion it is, what was stated for
/// it and who authorised it.
/// </param>
/// <param name="UnestablishedFactSummary">
/// How much this run will not establish, in the window's own words - or that it is not yet known,
/// which is never rendered as a zero.
/// </param>
/// <param name="Warnings">
/// What the run has to say about particular domains, in the audit layer's own words. Empty where
/// it has nothing to say, which is a different thing from having nothing to report.
/// </param>
internal sealed record AuditReview(
    string ForestFqdn,
    IReadOnlyList<ReviewedDomain> WillBeRead,
    IReadOnlyList<ExclusionView> WillNotBeRead,
    string UnestablishedFactSummary,
    IReadOnlyList<string> Warnings)
{
    /// <summary>Whether anything is leaving this run.</summary>
    public bool HasExclusions => WillNotBeRead.Count > 0;

    /// <summary>Whether the run has anything to say about particular domains.</summary>
    public bool HasWarnings => Warnings.Count > 0;

    /// <summary>How many domains this run will read.</summary>
    public int ReadCount => WillBeRead.Count;

    /// <summary>How many domains this run will not read.</summary>
    public int NotReadCount => WillNotBeRead.Count;

    /// <summary>What this run will read, as a heading.</summary>
    /// <remarks>
    /// <b>Worded here rather than in the view.</b> The screen said <c>"3 domain(s) will be read"</c>
    /// — a programmer's shortcut for not handling one and many, on a screen an auditor reads before
    /// committing a machine for hours. A count is a fact this record already holds, so the sentence
    /// belongs beside it and not in three separate string formats.
    /// </remarks>
    public string ReadHeading => ReadCount == 1
        ? "1 domain will be read"
        : $"{ReadCount} domains will be read";

    /// <summary>What this run will not read, as a heading.</summary>
    /// <remarks>
    /// <b>Zero is said in words, not as a number.</b> <c>"0 domain(s) will not be read"</c> made an
    /// operator do arithmetic to learn that nothing was excluded, and sat above a line already
    /// saying so. Per
    /// <c>docs/decisions/0063-excluded-never-looks-like-unreachable.md</c> the half is still always
    /// shown — what changes is only how it reads when it is empty.
    /// </remarks>
    public string NotReadHeading => NotReadCount switch
    {
        0 => "No domains are being left out",
        1 => "1 domain will not be read",
        _ => $"{NotReadCount} domains will not be read",
    };
}
