using Xunit;

namespace SecureAD.Next.Tests.Architecture;

/// <summary>
/// Every type a layer document claims in its <c>TYPES</c> table is the type the surface register
/// assigns to that document.
/// </summary>
/// <remarks>
/// <para>
/// <b>This is the check that makes a <c>TYPES</c> table mean something.</b> Each page's own gate
/// holds its table to the public types its source files declare, which stops a page from being
/// silently wrong about its own component. Nothing held the table to the register, so two pages
/// could claim one type and both gates would pass: each would be comparing its table against its
/// own files and finding nothing wrong. That is the shape of <c>P-60</c>, and until this class was
/// written nothing prevented it.
/// </para>
/// <para>
/// <b>It is anchored to the code rather than to another document.</b>
/// <see cref="SurfaceRegisterTests"/> already holds the register to the exported types of the
/// production assemblies in both directions, so a public type that is renamed, moved or removed
/// forces a register row to change, and this check then fails against any page still claiming the
/// old name. A page cannot satisfy it by being edited on its own.
/// </para>
/// <para>
/// <b>Two live violations existed when it was written, and neither was noticed by any gate:</b>
/// <c>IDirectoryChannel</c> and <c>IDirectoryChannelFactory</c> were claimed by
/// <c>docs/layers/audit/how-a-controller-is-read.md</c> while the register still assigned both to
/// the area file <c>which-controller-we-read</c>. Found by measurement 2026-08-24, and the reason
/// that area file reported 36 governed types with 34 undeclared.
/// </para>
/// <para>
/// The register is parsed by <see cref="SurfaceRegister"/> rather than here, for the reason that
/// class exists: one table, one parser. A second parser written beside it drifts from the first.
/// </para>
/// <para>
/// <b>Mutation-tested 2026-08-24 by <c>next/tools/mutate-types-ownership-gate.ps1</c>, four
/// directions. Baseline 5 passed, 0 failed; all three touched files reverted byte-identical.</b>
/// </para>
/// <list type="bullet">
///   <item>Register moves a claimed type to a page that does not claim it - killed by
///   <see cref="EveryClaimedTypeIsRegisteredToThePageThatClaimsIt"/>.</item>
///   <item>A page claims a type with no register row at all - killed by the same.</item>
///   <item>A second page claims a type the first already owns - killed by
///   <see cref="NoTypeIsClaimedByTwoPages"/> and by the same.</item>
///   <item>A page opens a table and fills it with nothing - killed by
///   <see cref="APageThatOpensATypesTableFillsIt"/>, and by nothing else, which is why that check
///   is separate.</item>
/// </list>
/// </remarks>
public sealed class TypesTableOwnershipTests
{
    private const string Begin = "<!-- TYPES:BEGIN -->";

    private const string End = "<!-- TYPES:END -->";

    [Fact]
    public void EveryClaimedTypeIsRegisteredToThePageThatClaimsIt()
    {
        var registered = SurfaceRegister.Entries()
            .ToDictionary(e => e.Type, e => e.Document, StringComparer.Ordinal);

        var wrong = new List<string>();

        foreach (var (page, types) in Claims())
        {
            // The shell exports nothing, so the register cannot hold its types and this check
            // cannot apply to it. ShellLayerTypesTests binds those pages to the internal types
            // their files declare instead, and TheShellExemptionCoversOnlyTypesTheRegisterCannotHold
            // below fails if this exemption ever covers a type the register really does hold.
            if (IsShell(page))
                continue;

            foreach (var type in types)
            {
                if (!registered.TryGetValue(type, out var owner))
                {
                    wrong.Add($"  {page} claims '{type}', which has no row in {SurfaceRegister.FileName}");
                }
                else if (!string.Equals(owner, page, StringComparison.Ordinal))
                {
                    wrong.Add($"  {page} claims '{type}', which the register assigns to {owner}");
                }
            }
        }

        Assert.True(
            wrong.Count == 0,
            "A TYPES table claims a type the register does not give it. A page's table is its "
            + "claim of ownership, and the register allows one owner per type, so these two "
            + "cannot disagree without one of them being wrong about who describes the code:"
            + Environment.NewLine + string.Join(Environment.NewLine, wrong));
    }

    /// <summary>
    /// The shell is exempt from the register check above, and this is what stops that exemption
    /// hiding anything.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Why the exemption exists.</b> <see cref="SurfaceRegister"/> is keyed to the exported
    /// types of the production assemblies, and the shell exports nothing by design -
    /// <see cref="ShellSurfaceGateTests"/> fails the build the day it does. So a shell page can
    /// never satisfy the register check, and holding it to one would mean either registering types
    /// nobody can consume or leaving the shell undocumented. That was <c>P-56</c>, and it blocked
    /// the deletion of an area file carrying 84 capability claims.
    /// </para>
    /// <para>
    /// <b>What replaces it.</b> <c>ShellLayerTypesTests</c> binds each shell page to the internal
    /// types its own files declare, in both directions. The exemption removes a check that cannot
    /// apply; it does not remove the obligation.
    /// </para>
    /// <para>
    /// <b>And this holds the exemption to its terms.</b> If a shell-claimed type ever appeared in
    /// the register, one of two things happened: the shell grew a public surface, or the register
    /// gained a row for something it should not describe. Either way the exemption would be
    /// covering a real disagreement, and this fails rather than letting it pass quietly.
    /// </para>
    /// </remarks>
    [Fact]
    public void TheShellExemptionCoversOnlyTypesTheRegisterCannotHold()
    {
        var registered = SurfaceRegister.Entries()
            .Select(e => e.Type)
            .ToHashSet(StringComparer.Ordinal);

        var shellPages = Claims().Where(c => IsShell(c.Page)).ToList();

        Assert.True(
            shellPages.Count > 0,
            "No shell page carries a TYPES table, so the exemption it exists for is exempting "
            + "nothing and this check reads an empty set.");

        var wrong = shellPages
            .SelectMany(c => c.Types
                .Where(registered.Contains)
                .Select(t => $"  {c.Page} claims '{t}', which the register also holds"))
            .OrderBy(m => m, StringComparer.Ordinal)
            .ToList();

        Assert.True(
            wrong.Count == 0,
            "A shell page claims a type the surface register also holds. The shell is exempt from "
            + "the register check because it exports nothing, so this means either the shell has "
            + "grown a public surface or the register describes something it should not:"
            + Environment.NewLine + string.Join(Environment.NewLine, wrong));
    }

    /// <summary>
    /// A page under <c>docs/layers/shell/</c>, keyed the way the register writes a governing
    /// document.
    /// </summary>
    private static bool IsShell(string page) =>
        page.StartsWith("layers/shell/", StringComparison.Ordinal);

    /// <summary>
    /// A page that carries a <c>TYPES</c> table claims everything the register gives it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>This closes the other direction.</b>
    /// <see cref="EveryClaimedTypeIsRegisteredToThePageThatClaimsIt"/> holds a page's claims to the
    /// register. Nothing held the register to the page, so a type could carry a register row naming
    /// a document that never described it and every check would pass: the register was satisfied
    /// because the row existed, and no page gate looked at it because no page claimed it. The type
    /// was documented in name only. Found by measurement 2026-08-24, with
    /// <c>PartitionCoverage</c> live in exactly that state.
    /// </para>
    /// <para>
    /// <b>It applies only to pages that have opened a table</b>, because a page without one has not
    /// adopted the convention and cannot claim anything. Six layer documents are in that state and
    /// the eleven types registered to two of them are the remaining hole, recorded as <c>P-83</c>
    /// rather than papered over here. Scoping it this way is the difference between a check that
    /// fires on one real defect and one that fires on twelve things nobody has got to yet, which is
    /// how a gate gets silenced.
    /// </para>
    /// </remarks>
    [Fact]
    public void EveryTypeRegisteredToAPageWithATableIsClaimedByIt()
    {
        var claims = Claims().ToDictionary(c => c.Page, c => c.Types, StringComparer.Ordinal);

        var wrong = SurfaceRegister.Entries()
            .Where(e => claims.TryGetValue(e.Document, out var types) && !types.Contains(e.Type))
            .Select(e => $"  {SurfaceRegister.FileName} gives '{e.Type}' to {e.Document}, whose TYPES table does not claim it")
            .OrderBy(m => m, StringComparer.Ordinal)
            .ToList();

        Assert.True(
            wrong.Count == 0,
            "The register assigns a type to a document that carries a TYPES table and does not "
            + "claim it. Nothing else would notice: the register is satisfied because the row "
            + "exists, and no page gate reads a type no page claims, so the type is documented in "
            + "name only:"
            + Environment.NewLine + string.Join(Environment.NewLine, wrong));
    }

    /// <summary>
    /// No type is claimed by two pages. This is implied by the check above whenever the register is
    /// intact, and is stated separately because it is the failure that matters: a reader following
    /// either page believes it is the description, and one of them is a second description nobody
    /// is maintaining.
    /// </summary>
    [Fact]
    public void NoTypeIsClaimedByTwoPages()
    {
        var claimants = new Dictionary<string, List<string>>(StringComparer.Ordinal);

        foreach (var (page, types) in Claims())
        {
            foreach (var type in types)
            {
                if (!claimants.TryGetValue(type, out var pages))
                    claimants[type] = pages = [];

                pages.Add(page);
            }
        }

        var contended = claimants
            .Where(pair => pair.Value.Count > 1)
            .OrderBy(pair => pair.Key, StringComparer.Ordinal)
            .Select(pair => $"  {pair.Key} is claimed by {string.Join(" and ", pair.Value)}")
            .ToList();

        Assert.True(
            contended.Count == 0,
            "These types are claimed by more than one layer document:"
            + Environment.NewLine + string.Join(Environment.NewLine, contended));
    }

    /// <summary>
    /// A page carrying the markers and no rows would pass both checks above by claiming nothing,
    /// which is how a table comes to be decoration.
    /// </summary>
    [Fact]
    public void APageThatOpensATypesTableFillsIt()
    {
        var empty = Claims()
            .Where(claim => claim.Types.Count == 0)
            .Select(claim => claim.Page)
            .ToList();

        Assert.True(
            empty.Count == 0,
            $"These pages open a {Begin} block and claim nothing in it: {string.Join(", ", empty)}.");
    }

    /// <summary>
    /// The scanner self-test. Without it every check above passes by reading no pages, no rows and
    /// no register, and reporting that nothing is wrong with any of them.
    /// </summary>
    /// <remarks>
    /// It deliberately asserts no count of pages or rows. A floor like <i>at least twelve pages
    /// carry a table</i> would have to be edited every time the rewrite progresses, and a threshold
    /// edited to make a gate pass is the defect rather than the fix. What it asserts instead is
    /// that the scan found something, that the register was read, and that the lookup discriminates.
    /// </remarks>
    [Fact]
    public void TheCheckReadsThePagesTheirTablesAndTheRegister()
    {
        var claims = Claims();

        Assert.NotEmpty(claims);
        Assert.Contains(claims, c => c.Types.Count > 0);

        var registered = SurfaceRegister.Entries();
        Assert.NotEmpty(registered);

        // A name no assembly exports is not in the register, so the lookup is not matching anything
        // it is handed.
        Assert.DoesNotContain(registered, e => e.Type == "NotAPublicTypeAnywhere");

        // And a type that is claimed really is found, so the lookup is not failing everything.
        var claimed = claims.SelectMany(c => c.Types).First();
        Assert.Contains(registered, e => e.Type == claimed);
    }

    /// <summary>
    /// A page whose markers are absent is skipped rather than silently read as claiming nothing,
    /// and a page whose opening marker is present without its closing one is a failure. The
    /// difference matters: not every layer document carries a table yet.
    /// </summary>
    [Fact]
    public void AHalfWrittenMarkerBlockIsAFailureRatherThanAnEmptyScan()
    {
        var thrown = Record.Exception(() => TypesIn("intro " + Begin + " | `Something` | a row |"));

        Assert.NotNull(thrown);
    }

    // --- helpers -----------------------------------------------------------------------------------

    /// <summary>
    /// Every layer document that carries a <c>TYPES</c> table, with the types it claims, keyed the
    /// way the register writes a governing document: <c>layers/subsystem/name</c>.
    /// </summary>
    private static List<(string Page, List<string> Types)> Claims()
    {
        var claims = new List<(string, List<string>)>();

        foreach (var file in LayerDocuments.All())
        {
            var text = File.ReadAllText(file);
            if (!text.Contains(Begin, StringComparison.Ordinal))
                continue;

            var name = System.IO.Path.GetFileNameWithoutExtension(file);

            claims.Add(($"layers/{LayerDocuments.SubsystemOf(file)}/{name}", TypesIn(text)));
        }

        return claims;
    }

    /// <summary>
    /// The first column of the rows between the markers, with the backticks stripped.
    /// </summary>
    private static List<string> TypesIn(string text)
    {
        var begin = text.IndexOf(Begin, StringComparison.Ordinal);
        var end = text.IndexOf(End, StringComparison.Ordinal);

        Assert.True(
            begin >= 0 && end > begin,
            $"A page opens {Begin} without closing it. The scan reads only what lies between the "
            + "markers, so an unterminated block must fail rather than quietly empty it.");

        return text[begin..end]
            .Split('\n')
            .Select(l => l.Trim())
            .Where(l => l.StartsWith('|') && !l.Contains("---", StringComparison.Ordinal))
            .Skip(1)
            .Select(l => l.Trim('|').Split('|')[0].Trim().Trim('`'))
            .Where(t => t.Length > 0)
            .ToList();
    }
}
