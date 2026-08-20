using System.Text.RegularExpressions;
using Xunit;

namespace SecureAD.Next.Tests.Architecture;

/// <summary>
/// Inventory row B4's boundary: every search capture issues is built in one place, and the referral
/// policy is never assigned anywhere else.
///
/// <para>
/// <b>What this catches.</b> The referral policy has two halves - a setting on the connection and
/// a control on the request - and it is only correct while both are in place. Neither is
/// self-explanatory at the point it is written: both look like small performance precautions, and
/// removing either leaves a capture that works perfectly against every forest with no child
/// domains, which is every lab. It fails silently on the first customer forest that has one, and
/// the failure looks like success: a capture reads the first page of a nine-million-object forest,
/// reports no error, and the report presents a fraction of the forest as the whole of it.
/// </para>
/// <para>
/// <b>Why this is a source scan rather than reflection.</b> The subject is a syntax form that must
/// not exist. Reflection can only inspect what compiled, and it cannot tell where a constructor was
/// called. The same choice is made for the same reason in <see cref="NullDefaultGateTests"/>.
/// </para>
/// <para>
/// <b>What it cannot do.</b> It cannot prove a search is ever issued, or that the one issued came
/// from the factory at run time - only that nothing else in the tree is written to build one. That
/// is deliberately half the obligation: the other half is gate 5b, which needs an entry point to
/// trace from and unblocks on inventory row B6. Recording the split is the point. A guard that quietly
/// implied it had proved the whole thing is how gate 5's original wording came to pass against a
/// tree in which nothing was reachable at all.
/// </para>
/// </summary>
public sealed class DirectorySearchGateTests
{
    /// <summary>The one file allowed to build a search request or set a referral option.</summary>
    private const string Factory = "CaptureSearchRequestFactory.cs";

    /// <summary>
    /// Constructing a search request. Written as a pattern rather than a bare term so that a
    /// mention of the type in a signature or a variable declaration does not count - the guard is
    /// about who creates one.
    /// </summary>
    private static readonly Regex SearchRequestConstruction =
        new(@"\bnew\s+SearchRequest\b", RegexOptions.Compiled);

    /// <summary>Assigning the referral policy, whatever it is assigned to.</summary>
    private static readonly Regex ReferralChasingAssignment =
        new(@"\bReferralChasing\s*=", RegexOptions.Compiled);

    /// <summary>
    /// The referral options that chase something. None of them may appear anywhere in production,
    /// including inside the factory: there is one policy and it is <c>None</c>.
    /// </summary>
    private static readonly Regex ChasingReferralOption =
        new(@"\bReferralChasingOptions\.(All|External|Subordinate)\b", RegexOptions.Compiled);

    [Fact]
    public void OnlyTheFactoryBuildsASearchRequest()
    {
        var offenders = RebuildTree
            .ScanPattern(RebuildTree.ProductionFiles(), SearchRequestConstruction)
            .Where(o => !IsFactory(o.File))
            .ToList();

        Assert.True(
            offenders.Count == 0,
            "Search requests built outside " + Factory + ". Every search capture issues carries a "
            + "referral policy and a paging control that are the difference between reading a "
            + "forest and reading its first page while reporting success. A second place that "
            + "builds one is a second policy, and the first sign that the two disagree is a "
            + "customer's report covering part of their forest and saying nothing about it:"
            + Environment.NewLine + RebuildTree.Describe(offenders));
    }

    [Fact]
    public void OnlyTheFactorySetsTheReferralPolicy()
    {
        var offenders = RebuildTree
            .ScanPattern(RebuildTree.ProductionFiles(), ReferralChasingAssignment)
            .Where(o => !IsFactory(o.File))
            .ToList();

        Assert.True(
            offenders.Count == 0,
            "Referral chasing assigned outside " + Factory + ":"
            + Environment.NewLine + RebuildTree.Describe(offenders));
    }

    [Fact]
    public void NothingEverAsksForReferralsToBeChased()
    {
        var offenders = RebuildTree
            .ScanPattern(RebuildTree.ProductionFiles(), ChasingReferralOption)
            .ToList();

        Assert.True(
            offenders.Count == 0,
            "A referral-chasing option other than None appears in production code. Chasing a "
            + "subordinate referral during a paged search overwrites the paged cookie inside the "
            + "LDAP runtime, so the search ends after the first page and the application is told "
            + "nothing went wrong. Microsoft states there is no resolution, only avoidance:"
            + Environment.NewLine + RebuildTree.Describe(offenders));
    }

    /// <summary>
    /// The scanner self-test. Without it all three checks above pass by scanning an empty set of
    /// files and finding no offenders - the failure this repository has committed three times.
    ///
    /// <para>
    /// It is not enough to assert that some files were scanned. The patterns themselves must be
    /// shown to match the thing they police, and the factory must be shown to be there and to
    /// contain the two constructs the first two checks permit only in it. If the factory were
    /// renamed, the exemption would stop matching any file and the checks would keep passing while
    /// the mechanism they guard had gone.
    /// </para>
    /// </summary>
    [Fact]
    public void TheScannerReadsTheFactoryAndItsPatternsMatch()
    {
        var production = RebuildTree.ProductionFiles().ToList();
        Assert.True(production.Count > 0, "Scanned no production files.");

        var factories = production.Where(IsFactory).ToList();
        Assert.True(
            factories.Count == 1,
            $"Expected exactly one {Factory} in the rebuild, found {factories.Count}. The three "
            + "checks in this class exempt that file by name, so a rename would leave them "
            + "policing a tree with no mechanism in it and reporting it clean.");

        Assert.NotEmpty(RebuildTree.ScanPattern(factories, SearchRequestConstruction));
        Assert.NotEmpty(RebuildTree.ScanPattern(factories, ReferralChasingAssignment));

        Assert.Matches(SearchRequestConstruction, "var r = new SearchRequest();");
        Assert.Matches(ReferralChasingAssignment, "options.ReferralChasing = whatever;");
        Assert.Matches(ChasingReferralOption, "x = ReferralChasingOptions.External;");
        Assert.DoesNotMatch(ChasingReferralOption, "x = ReferralChasingOptions.None;");
    }

    private static bool IsFactory(string file) =>
        Path.GetFileName(file).Equals(Factory, StringComparison.Ordinal);
}
