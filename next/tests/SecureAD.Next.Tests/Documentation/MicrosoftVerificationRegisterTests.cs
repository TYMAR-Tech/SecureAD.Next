using Xunit;

namespace SecureAD.Next.Tests.Documentation;

/// <summary>
/// The Microsoft verification register, held to the tests and scripts it names.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why the register needs its own guard.</b> It records which values have been checked against
/// Microsoft and when. A row naming an anchor test that does not exist would read as verification
/// while proving nothing - the same shape as the invariants document that named an enforcing test
/// from a repository this one has never contained.
/// </para>
/// <para>
/// <b>The reverse direction matters more here than usual.</b> A component that gains an anchor
/// test but no row would be verified and unrecorded, which is harmless. A component listed as
/// verified whose test has been deleted is the dangerous case, and it is the one checked.
/// </para>
/// </remarks>
public sealed class MicrosoftVerificationRegisterTests
{
    private static string Register() =>
        Path.Combine(RepositoryLocation.Root(), "docs", "MICROSOFT-VERIFICATION.md");

    /// <summary>
    /// Every anchor test the register claims is real, found by reflection rather than by
    /// searching for its name - a comment mentioning a test is not a test.
    /// </summary>
    [Fact]
    public void EveryAnchorTestTheRegisterNamesExists()
    {
        var declared = typeof(MicrosoftVerificationRegisterTests).Assembly
            .GetTypes()
            .Select(t => t.Name)
            .ToHashSet(StringComparer.Ordinal);

        var missing = NamedAnchorTests()
            .Where(name => !declared.Contains(name))
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToArray();

        Assert.True(
            missing.Length == 0,
            "The verification register names anchor tests that are not in the test assembly. A "
            + "row claiming verification by a test that does not exist reads as evidence and is "
            + "not:" + Environment.NewLine + string.Join(Environment.NewLine, missing));
    }

    /// <summary>
    /// Every anchor test in the tree is recorded. A component verified but never written down
    /// leaves the register understating what is known, and the next session redoes the work.
    /// </summary>
    [Fact]
    public void EveryAnchorTestInTheTreeIsRecorded()
    {
        var recorded = NamedAnchorTests();

        var unrecorded = typeof(MicrosoftVerificationRegisterTests).Assembly
            .GetTypes()
            .Where(t => t.Name.EndsWith("MicrosoftAnchorTests", StringComparison.Ordinal))
            .Select(t => t.Name)
            .Where(name => !recorded.Contains(name))
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToArray();

        Assert.True(
            unrecorded.Length == 0,
            "These anchor tests exist but the verification register does not mention them, so "
            + "work already done is invisible:"
            + Environment.NewLine + string.Join(Environment.NewLine, unrecorded));
    }

    /// <summary>
    /// The scanner self-test. Without it both checks pass over an empty register and report that
    /// nothing is wrong with it.
    /// </summary>
    [Fact]
    public void TheCheckReadsTheRegister()
    {
        var names = NamedAnchorTests();

        Assert.True(names.Count >= 3, $"Read only {names.Count} anchor tests from the register.");
        Assert.Contains("Not yet verified", File.ReadAllText(Register()), StringComparison.Ordinal);
    }

    private static HashSet<string> NamedAnchorTests() =>
        [.. System.Text.RegularExpressions.Regex
            .Matches(File.ReadAllText(Register()), "`([A-Za-z0-9_]*MicrosoftAnchorTests)`")
            .Select(m => m.Groups[1].Value)];
}
