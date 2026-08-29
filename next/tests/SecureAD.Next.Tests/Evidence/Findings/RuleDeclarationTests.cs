using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using Xunit;

namespace SecureAD.Next.Tests.Evidence.Findings;

/// <summary>
/// Every rule declares what it reads, held by the build.
/// </summary>
/// <remarks>
/// <para>
/// <b>This is the gate <c>docs/decisions/0083</c> asks for.</b> The predecessor kept every rule's
/// inputs in one hand-maintained dictionary, separate from the rules. A rule added without an
/// entry fell through to a heuristic default and was stamped coverage-complete on a bundle where
/// its real inputs were never captured - a wrong answer stated confidently rather than a visible
/// gap. Declaring inputs beside the rule only helps if forgetting is impossible, which is what
/// this class is for.
/// </para>
/// <para>
/// <b>It carries a scanner self-test</b>, because every check above would pass just as happily
/// over an empty set of rules and report that nothing is wrong.
/// </para>
/// </remarks>
public sealed class RuleDeclarationTests
{
    private static IReadOnlyList<IRule> Rules() =>
    [
        .. typeof(IRule).Assembly
            .GetTypes()
            .Where(t => t.IsClass && !t.IsAbstract && typeof(IRule).IsAssignableFrom(t))
            .Select(t => (IRule)Activator.CreateInstance(t)!),
    ];

    /// <summary>
    /// A rule that declares no inputs fails here rather than defaulting to coverage-complete.
    /// </summary>
    [Fact]
    public void EveryRuleDeclaresTheDataItReads()
    {
        var silent = Rules()
            .Where(r => r.Definition.RequiredAttributes.Count == 0)
            .Select(r => r.Definition.Id)
            .OrderBy(id => id, StringComparer.Ordinal)
            .ToArray();

        Assert.True(
            silent.Length == 0,
            "These rules declare no data dependencies, so nothing can tell whether a bundle "
            + "carried what they need. A rule with undeclared inputs reports clean on a run that "
            + "never read them: " + string.Join(", ", silent));
    }

    /// <summary>
    /// No rule declares an input twice or declares an empty name, either of which would make the
    /// declaration read as more than it is.
    /// </summary>
    [Fact]
    public void NoRuleDeclaresADuplicateOrEmptyInput()
    {
        foreach (var rule in Rules())
        {
            var declared = rule.Definition.RequiredAttributes;

            Assert.All(declared, a => Assert.False(string.IsNullOrWhiteSpace(a)));

            Assert.Equal(
                declared.Count,
                declared.Distinct(StringComparer.OrdinalIgnoreCase).Count());
        }
    }

    /// <summary>
    /// Rule identifiers are unique. Two rules sharing one identifier would give two different
    /// findings the same identity, and 0023 makes the rule part of that identity.
    /// </summary>
    [Fact]
    public void EveryRuleIdIsUnique()
    {
        var ids = Rules().Select(r => r.Definition.Id).ToArray();

        Assert.Equal(ids.Length, ids.Distinct(StringComparer.Ordinal).Count());
    }

    /// <summary>
    /// The scanner self-test. Without it every check above passes over an empty rule set.
    /// </summary>
    [Fact]
    public void ThereAreRulesToCheck()
    {
        var rules = Rules();

        Assert.NotEmpty(rules);
        Assert.All(rules, r => Assert.False(string.IsNullOrWhiteSpace(r.Definition.Id)));
        Assert.All(rules, r => Assert.False(string.IsNullOrWhiteSpace(r.Definition.Name)));
    }
}
