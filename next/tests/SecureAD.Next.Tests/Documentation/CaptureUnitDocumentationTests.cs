using System.DirectoryServices.Protocols;
using SecureAD.Audit.Capture;
using SecureAD.Evidence;
using Xunit;
using SecureAD.Kernel.Capture;

namespace SecureAD.Next.Tests.Documentation;

/// <summary>
/// Binds <c>docs/next/S-9-the-capture-unit.md</c> to the search request
/// <see cref="CaptureSearchRequestFactory"/> builds.
///
/// <para>
/// This is inventory row B4's deliverable, and it is the honest half of it. Nothing in the rebuild
/// issues a search - the component that runs the passes is inventory row B6 - so a test claiming to
/// check "the search capture issues" would be inspecting an empty set and reporting it correct.
/// That is the failure gate 5's original wording fell into and the reason B2's binding was split.
/// </para>
/// <para>
/// So the obligation splits the same way. <b>B4a, here:</b> a real
/// <see cref="SearchRequest"/> is constructed with no directory present and every property the
/// document names is compared with it, and <see cref="DirectorySearchGateTests"/> forbids anything
/// else in the tree from building one. <b>B4b:</b> that the request actually issued is this one is
/// gate 5b, which needs an entry point to trace from and unblocks on B6.
/// </para>
/// <para>
/// <b>What it cannot check.</b> Whether the three refused avoidances were rightly refused, whether
/// the filter is the cheapest one a controller can serve, or whether the prose explaining any of it
/// is any good. Those need a reader.
/// </para>
/// </summary>
public sealed class CaptureUnitDocumentationTests
{
    private const string Document = "S-9-the-capture-unit.md";
    private const string RequestBegin = "<!-- REQUEST:BEGIN -->";
    private const string RequestEnd = "<!-- REQUEST:END -->";
    private const string RefusedBegin = "<!-- REFUSED:BEGIN -->";
    private const string RefusedEnd = "<!-- REFUSED:END -->";

    /// <summary>A unit standing in for any unit. A domain partition, because that is the kind the
    /// paging defect applies to and the kind the domain-scope control is sent for.</summary>
    private static CaptureUnit SampleUnit() =>
        CaptureUnit.Create("DC=example,DC=com", NamingContextKind.Domain, "dc01.example.com").Value;

    /// <summary>A controller advertising the domain-scope control, as a real one does.</summary>
    private static string[] SupportedControls() =>
        ["1.2.840.113556.1.4.319", CaptureSearchRequestFactory.DomainScopeControlOid];

    /// <summary>
    /// The properties the document must describe, and what each documented value has to agree
    /// with in the request the code builds.
    ///
    /// <para>
    /// Held here rather than derived from the document, so that a row silently deleted from S-9
    /// fails rather than shrinking the set being checked - and held as assertions against a real
    /// request rather than as expected strings, so that a value edited in both places to match a
    /// broken change still fails.
    /// </para>
    /// </summary>
    private static Dictionary<string, Func<SearchRequest, string, bool>> Checks() => new(StringComparer.Ordinal)
    {
        ["SearchBase"] = (r, _) => r.DistinguishedName == SampleUnit().NamingContext,
        ["Scope"] = (r, documented) => documented == r.Scope.ToString(),
        ["Filter"] = (r, documented) => documented.Trim('`') == r.Filter as string,
        ["Attributes"] = (r, documented) =>
            documented == "every attribute in the captured attribute catalogue"
            && r.Attributes.Cast<string>().SequenceEqual(
                CapturedAttributeCatalog.All.Select(a => a.LdapDisplayName)),
        ["SizeLimit"] = (r, documented) => documented == r.SizeLimit.ToString(),
        ["TimeLimit"] = (r, documented) => documented == $"{(int)r.TimeLimit.TotalSeconds} seconds",
        ["PageSize"] = (r, documented) => documented == PageControl(r).PageSize.ToString(),
        ["ReferralChasing"] = (_, documented) =>
            documented == CaptureSearchRequestFactory.RequiredReferralChasing.ToString(),
        ["DomainScopeControl"] = (r, documented) =>
            documented == $"{DomainScope(r).Type}, "
                        + (DomainScope(r).IsCritical ? "critical" : "non-critical"),
        ["SecurityDescriptorFlags"] = (r, documented) =>
            documented == SecurityDescriptorFlags(r).SecurityMasks.ToString()
            && (SecurityDescriptorFlags(r).SecurityMasks & SecurityMasks.Sacl) == 0,
    };

    /// <summary>
    /// The security-descriptor flags control on the request, which must be there: without it the
    /// server decides which parts of a descriptor to return, and the SACL is privileged.
    /// </summary>
    private static SecurityDescriptorFlagControl SecurityDescriptorFlags(SearchRequest request) =>
        request.Controls.OfType<SecurityDescriptorFlagControl>().Single();

    [Fact]
    public void EveryPropertyOfTheSearchIsDescribedAndDescribedCorrectly()
    {
        var request = CaptureSearchRequestFactory.ForUnit(SampleUnit(), SupportedControls());
        var documented = RequestRows();

        var wrong = new List<string>();

        foreach (var (property, check) in Checks())
        {
            if (!documented.TryGetValue(property, out var value))
            {
                wrong.Add($"  {property}: not described in {Document}");
                continue;
            }

            if (!check(request, value))
                wrong.Add($"  {property}: {Document} says '{value}', which the request does not");
        }

        Assert.True(
            wrong.Count == 0,
            "The search request capture builds and " + Document + " disagree. A document "
            + "describing a search that is not the search issued is worse than no document: the "
            + "referral policy in it is the difference between reading a forest and reading its "
            + "first page while reporting success:"
            + Environment.NewLine + string.Join(Environment.NewLine, wrong));
    }

    [Fact]
    public void TheDocumentDescribesNoPropertyTheSearchDoesNotHave()
    {
        var known = Checks().Keys.ToHashSet(StringComparer.Ordinal);

        var phantom = RequestRows().Keys
            .Where(p => !known.Contains(p))
            .Select(p => "  " + p)
            .ToList();

        Assert.True(
            phantom.Count == 0,
            Document + " describes properties of the search that this test does not check. Either "
            + "the property is real, in which case add the check, or it is not, in which case the "
            + "document is promising a precaution nobody takes:"
            + Environment.NewLine + string.Join(Environment.NewLine, phantom));
    }

    /// <summary>
    /// The domain-scope control is sent for a domain partition and not for the others, and only
    /// where the controller advertises it. Checked against the code rather than only described,
    /// because "sent non-critical where supported" is three conditions and each is a way to get it
    /// wrong.
    /// </summary>
    [Theory]
    [InlineData(NamingContextKind.Domain, true, true)]
    [InlineData(NamingContextKind.Domain, false, false)]
    [InlineData(NamingContextKind.Configuration, true, false)]
    [InlineData(NamingContextKind.Schema, true, false)]
    public void TheDomainScopeControlIsSentOnlyWhereItApplies(
        NamingContextKind kind, bool advertised, bool expected)
    {
        var unit = CaptureUnit.Create("DC=example,DC=com", kind, "dc01.example.com").Value;
        var controls = advertised ? SupportedControls() : ["1.2.840.113556.1.4.319"];

        var request = CaptureSearchRequestFactory.ForUnit(unit, controls);

        Assert.Equal(
            expected,
            request.Controls.OfType<DomainScopeControl>().Any());
    }

    /// <summary>
    /// The three avoidances Microsoft lists and this product refused are all named. A refusal that
    /// is not written down is a refusal the next session re-derives from scratch, and the global
    /// catalog is the one it will re-derive wrongly.
    /// </summary>
    [Theory]
    [InlineData("Basing the search below the domain root")]
    [InlineData("Searching the global catalog")]
    [InlineData("Chasing referrals and handling the cookie carefully")]
    public void EveryRefusedAvoidanceIsNamed(string avoidance)
    {
        Assert.Contains(avoidance, RefusedRows().Keys);
    }

    // EveryFindingARefusalNamesIsRealAndSoIsEveryLedgerRowTheDocumentCites stood here and was
    // deleted on 2026-08-14. It checked that finding identifiers cited by one document appear in
    // another - markdown against markdown, with no product code on either side of the assertion.

    /// <summary>
    /// The scanner self-test. Without it every check above passes by parsing an empty table and
    /// finding nothing wrong with it - the failure this repository has committed three times.
    ///
    /// <para>
    /// The negative controls matter as much as the positive ones. The refusals table must not name
    /// the avoidance that was <i>chosen</i>, and the request table must not be so lenient that a
    /// wrong value passes: both are asserted here rather than assumed.
    /// </para>
    /// </summary>
    [Fact]
    public void TheCheckReadsBothTablesAndDoesNotAcceptEverything()
    {
        var request = RequestRows();
        var refused = RefusedRows();

        Assert.Equal(Checks().Count, request.Count);
        Assert.Equal(3, refused.Count);

        Assert.DoesNotContain(
            refused.Keys,
            k => k.Contains("enumerat", StringComparison.OrdinalIgnoreCase));

        var built = CaptureSearchRequestFactory.ForUnit(SampleUnit(), SupportedControls());
        Assert.False(Checks()["Scope"](built, "OneLevel"));
        Assert.False(Checks()["ReferralChasing"](built, "External"));
        Assert.False(Checks()["PageSize"](built, "999"));
        Assert.True(Checks()["Scope"](built, "Subtree"));
    }

    private static PageResultRequestControl PageControl(SearchRequest request) =>
        request.Controls.OfType<PageResultRequestControl>().Single();

    private static DomainScopeControl DomainScope(SearchRequest request) =>
        request.Controls.OfType<DomainScopeControl>().Single();

    private static Dictionary<string, string> RequestRows() =>
        Rows(RequestBegin, RequestEnd);

    private static Dictionary<string, string> RefusedRows()
    {
        var path = Path.Combine(RepositoryLocation.Root(), "docs", "next", Document);
        var lines = File.ReadAllLines(path);
        var rows = new Dictionary<string, string>(StringComparer.Ordinal);

        foreach (var cells in RowsBetween(lines, RefusedBegin, RefusedEnd))
        {
            // Key, and the finding cell rather than the reason cell.
            rows[cells[0]] = cells[2];
        }

        return rows;
    }

    private static Dictionary<string, string> Rows(string begin, string end)
    {
        var path = Path.Combine(RepositoryLocation.Root(), "docs", "next", Document);
        Assert.True(File.Exists(path), $"Expected the document at {path}.");

        var rows = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var cells in RowsBetween(File.ReadAllLines(path), begin, end))
            rows[cells[0]] = cells[1];

        return rows;
    }

    private static IEnumerable<string[]> RowsBetween(string[] lines, string begin, string end)
    {
        var first = Array.FindIndex(lines, l => l.Trim() == begin);
        var last = Array.FindIndex(lines, l => l.Trim() == end);

        if (first < 0 || last < 0 || last < first)
        {
            throw new InvalidOperationException(
                $"Could not find the {begin} / {end} markers in {Document}. The tests parse only "
                + "what lies between them, so a missing marker must fail rather than silently "
                + "widen or empty the scan.");
        }

        for (var i = first + 1; i < last; i++)
        {
            var line = lines[i].Trim();
            if (!line.StartsWith('|') || !line.EndsWith('|'))
                continue;

            var cells = line.Trim('|').Split('|').Select(c => c.Trim()).ToArray();
            if (cells.Length < 3 || cells[0] == "Property" || cells[0] == "Avoidance refused")
                continue;

            if (cells[0].All(c => c is '-' or ':'))
                continue;

            yield return cells;
        }
    }
}
