using System.Text.RegularExpressions;
using Xunit;

namespace SecureAD.Next.Tests.Architecture;

/// <summary>
/// Gate 2, third instance: the range specifier is spelled in exactly one place.
///
/// <para>
/// <b>What this protects.</b> A range specifier - the <c>;range=</c> that turns <c>member</c> into
/// <c>member;range=0-999</c> - is how a client asks for the values of an attribute a block at a
/// time, and how a controller says which block it served. Getting it right is the difference
/// between reading a ten-thousand-member group and reading fifteen hundred of it. Getting it
/// nearly right is worse than getting it wrong, because a specifier a controller cannot parse is
/// answered by an entry that carries the attribute under some other name, which reads exactly like
/// an object with no values.
/// </para>
/// <para>
/// So the string is written once, in the type that owns the concept, and everything else asks that
/// type. A second speller is a second opinion about where a block ends, and the two disagree
/// silently: both produce a plausible name, one of them gets fewer values, and nothing anywhere
/// says so.
/// </para>
/// <para>
/// <b>Scope, and the exemption.</b> Only production source under <c>next/src/</c> is scanned.
/// Test source may spell one, and must be able to: a test that asks the owning type what a
/// specifier looks like and compares it against the owning type is checking a thing against
/// itself. Comment lines are skipped, the same allowance every other guard here makes, because a
/// guard's own prose has to be able to name what it forbids.
/// </para>
/// </summary>
public sealed class RangeSpecifierGateTests
{
    /// <summary>
    /// The range option as it appears in an attribute name. Matched without case, because LDAP
    /// attribute options are not case-sensitive and a guard that only catches one spelling teaches
    /// the next author which spelling to use.
    /// </summary>
    private static readonly Regex Specifier = new(";range=", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    /// <summary>
    /// The one file allowed to contain it, because it is the type that owns the concept. Held as a
    /// file name rather than a type so the scan needs no reflection and still catches a specifier
    /// in a file that does not compile.
    /// </summary>
    private const string TheOwner = "AttributeRange.cs";

    [Fact]
    public void NoProductionFileOutsideTheOwnerSpellsARangeSpecifier()
    {
        var offenders = RebuildTree
            .ScanPattern(RebuildTree.ProductionFiles(), Specifier)
            .Where(s => Path.GetFileName(s.File) != TheOwner)
            .ToList();

        Assert.True(
            offenders.Count == 0,
            "Range specifiers outside " + TheOwner + ". Ask AttributeRange for the name to "
            + "request, and let it read the name that came back. A second place that spells a "
            + "range is a second opinion on where a block of values ends, and the visible symptom "
            + "is a privileged group reported smaller than it is:"
            + Environment.NewLine + RebuildTree.Describe(offenders));
    }

    /// <summary>
    /// The scanner self-test. Without it this gate passes by finding no files, or by carrying a
    /// pattern that matches nothing, and reports a tree in perfect order either way.
    /// </summary>
    [Fact]
    public void TheCheckReadsTheProductionTreeAndItsPatternMatches()
    {
        var files = RebuildTree.ProductionFiles().ToList();

        Assert.True(files.Count > 0, "Found no production source under next/src/ to scan.");
        Assert.Contains(files, f => Path.GetFileName(f) == TheOwner);
        Assert.Matches(Specifier, "member;range=0-999");
        Assert.Matches(Specifier, "member;RANGE=1500-*");
        Assert.DoesNotMatch(Specifier, "member");
        Assert.DoesNotMatch(Specifier, "rangeUpper");
    }

    /// <summary>
    /// The allowlist-decay test. An exemption that is no longer needed must fail rather than
    /// quietly become permanent - so if the specifier ever leaves that file, whether because the
    /// type moved or because the string was built some other way, the exemption goes with it.
    /// </summary>
    [Fact]
    public void TheExemptionIsStillEarningItsPlace()
    {
        var inTheOwner = RebuildTree
            .ScanPattern(RebuildTree.ProductionFiles(), Specifier)
            .Count(s => Path.GetFileName(s.File) == TheOwner);

        Assert.True(
            inTheOwner > 0,
            TheOwner + " is exempt from the range-specifier gate and contains no specifier. "
            + "Either the type moved, in which case the exemption follows it, or the exemption is "
            + "dead and should go.");
    }

    /// <summary>
    /// Scope is deliberate rather than accidental. Tests spell specifiers on purpose, and this
    /// records that they do - so a later widening of the scan to the whole tree fails here first,
    /// with the reason attached, rather than being switched off in a hurry when it turns red.
    /// </summary>
    [Fact]
    public void TestSourceIsOutOfScopeAndActuallyUsesThatFreedom()
    {
        var productionPaths = RebuildTree.ProductionFiles().ToHashSet(StringComparer.Ordinal);

        var inTests = RebuildTree
            .ScanPattern(RebuildTree.AllFiles(), Specifier)
            .Where(s => !productionPaths.Contains(s.File))
            .ToList();

        Assert.True(
            inTests.Count > 0,
            "No test spells a range specifier. The scan is limited to production source because "
            + "tests must be able to state the expected wire form directly; if no test does, "
            + "either the rule is being checked against itself or the exemption is unnecessary.");
    }
}
