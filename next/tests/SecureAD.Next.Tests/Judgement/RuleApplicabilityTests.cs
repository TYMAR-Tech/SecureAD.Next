using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using SecureAD.Kernel.Capture;
using Xunit;

namespace SecureAD.Next.Tests.Judgement;

/// <summary>
/// Which objects a rule is offered, which is decided before the rule sees anything.
/// </summary>
/// <remarks>
/// <para>
/// <b>Written after the defect it exists to prevent had already shipped into a commit.</b> On
/// 2026-09-05 three rules - <c>SEC-060</c>, <c>SEC-031</c> and <c>SEC-032</c> - were built,
/// registered, documented and covered by thirty-six of their own tests, and every one of them
/// judged <b>zero</b> objects against a real forest. Each declares no subject class because its
/// specification says <i>every object</i>, and <see cref="RuleDefinition.IsAbout"/> read an empty
/// list as matching nothing.
/// </para>
/// <para>
/// <b>Nothing in the suite could have noticed, and that is the part worth fixing.</b> Every rule
/// test calls <c>Judge</c> directly with an object it has chosen, so none of them reaches the
/// question of whether the object would ever have been offered. The rules were green, the gates
/// were green, and the product reported nothing. This is the failure class
/// <c>docs/next/README.md</c> puts first: a check that passes while measuring nothing.
/// </para>
/// <para>
/// <b>Pinned in both directions</b>, because a test that only proved an empty list matches
/// everything would pass equally if <c>IsAbout</c> were changed to return <c>true</c> always.
/// </para>
/// </remarks>
public sealed class RuleApplicabilityTests
{
    /// <summary>
    /// <b>Every rule in the catalogue is about something.</b> A rule that is about nothing is
    /// offered nothing, judges nothing, and reports nothing - while succeeding.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>This is the general form of the defect, and it is why the three hard-coded cases below
    /// are not enough.</b> Those name <c>SEC-060</c>, <c>SEC-031</c> and <c>SEC-032</c> because
    /// those are the three that were caught. This covers the eighteenth rule nobody has written yet.
    /// </para>
    /// <para>
    /// <b>The object handed to each rule is built from the rule's own declared classes, and that is
    /// not circular.</b> The question being asked is not <i>are these the right classes</i> - that is
    /// the rule document's business. It is <i>given the classes this rule declares, is it about
    /// anything at all</i>, and a rule declaring none must be about everything. A rule that declared
    /// a misspelled class would still pass here, and should: the misspelling is a different defect,
    /// and one a lab run finds.
    /// </para>
    /// </remarks>
    [Fact]
    public void EveryRuleInTheCatalogueIsAboutSomething()
    {
        var mute = new List<string>();

        foreach (var rule in RuleCatalogue.All)
        {
            // A rule declaring no class means every object, so a plain object stands in. One
            // declaring classes is offered an object of the first it names.
            var objectClass = rule.Definition.SubjectClasses.Count == 0
                ? "organizationalUnit"
                : rule.Definition.SubjectClasses[0];

            if (!rule.Definition.IsAbout(Subject(objectClass)))
                mute.Add($"  {rule.Definition.Id} declares [{string.Join(", ", rule.Definition.SubjectClasses)}]");
        }

        Assert.True(
            mute.Count == 0,
            "These rules are about no object and would run, succeed, and report nothing:"
            + Environment.NewLine + string.Join(Environment.NewLine, mute)
            + Environment.NewLine
            + "On 2026-09-05 three rules did exactly that against a real forest - all 8,378 "
            + "objects counted as not applicable - while 3,139 tests were green. See F-S45-4.");
    }

    /// <summary>
    /// The catalogue holds rules, so the check above is measuring something.
    /// </summary>
    /// <remarks>
    /// <b>The self-test every gate carries.</b> A loop over an empty catalogue passes while
    /// examining nothing, which is the failure this whole class exists to prevent - and it would be
    /// a poor joke to prevent it in the product and commit it in the test.
    /// </remarks>
    [Fact]
    public void TheCatalogueIsNotEmpty() =>
        Assert.True(RuleCatalogue.All.Count >= 17, $"only {RuleCatalogue.All.Count} rules found");

    /// <summary>A rule declaring no class is offered every object.</summary>
    [Theory]
    [InlineData("organizationalUnit")]
    [InlineData("container")]
    [InlineData("computer")]
    [InlineData("group")]
    [InlineData("pKICertificateTemplate")]
    public void ARuleDeclaringNoClassIsAboutEveryObject(string objectClass) =>
        Assert.True(Definition([]).IsAbout(Subject(objectClass)));

    /// <summary>A rule declaring a class is not offered objects of another.</summary>
    /// <remarks>
    /// The other direction. Without this, returning <c>true</c> unconditionally would satisfy the
    /// test above and every rule in the product would be offered every object.
    /// </remarks>
    [Fact]
    public void ARuleDeclaringAClassIsNotAboutAnother() =>
        Assert.False(Definition(["computer"]).IsAbout(Subject("organizationalUnit")));

    /// <summary>A rule declaring a class is offered objects of that class.</summary>
    [Fact]
    public void ARuleDeclaringAClassIsAboutThatClass() =>
        Assert.True(Definition(["computer"]).IsAbout(Subject("computer")));

    /// <summary>
    /// The class is matched anywhere in the inheritance chain, so a rule about users sees computers.
    /// </summary>
    [Fact]
    public void AClassIsMatchedAnywhereInTheInheritanceChain() =>
        Assert.True(Definition(["user"]).IsAbout(Computer()));

    /// <summary>
    /// The three rules whose specifications say <i>every object</i> really are offered every object.
    /// </summary>
    /// <remarks>
    /// <b>Anchored to the shipped rules rather than to a fixture.</b> A test of
    /// <see cref="RuleDefinition"/> alone would still pass if one of these rules later narrowed its
    /// classes by accident, and the rule would go quiet exactly as it did before.
    /// </remarks>
    [Theory]
    [InlineData("SEC-060")]
    [InlineData("SEC-031")]
    [InlineData("SEC-032")]
    public void TheEveryObjectRulesAreOfferedAnOrganizationalUnit(string ruleId)
    {
        var rule = RuleCatalogue.All.Single(r =>
            string.Equals(r.Definition.Id, ruleId, StringComparison.Ordinal));

        Assert.True(rule.Definition.IsAbout(Subject("organizationalUnit")));
    }

    private static RuleDefinition Definition(IReadOnlyList<string> subjectClasses) => new(
        "SEC-999",
        "A rule used only to test applicability",
        Severity.Low,
        Version: 1,
        SubjectClasses: subjectClasses,
        RequiredAttributes: ["objectClass"],
        RequiredDerivedFacts: []);

    private static ObjectAttributes Computer() => new(
        "CN=WS01,DC=contoso,DC=com",
        Guid.NewGuid(),
        DateTimeOffset.UnixEpoch,
        EvidenceCompleteness.Complete,
        [
            new ObjectAttribute(
                "objectClass",
                AttributeCardinality.MultiValued,
                [
                    new AttributeValue(0, "top", null),
                    new AttributeValue(1, "person", null),
                    new AttributeValue(2, "organizationalPerson", null),
                    new AttributeValue(3, "user", null),
                    new AttributeValue(4, "computer", null),
                ]),
        ],
        "contoso.com");

    private static ObjectAttributes Subject(string objectClass) => new(
        "OU=Thing,DC=contoso,DC=com",
        Guid.NewGuid(),
        DateTimeOffset.UnixEpoch,
        EvidenceCompleteness.Complete,
        [
            new ObjectAttribute(
                "objectClass",
                AttributeCardinality.MultiValued,
                [
                    new AttributeValue(0, "top", null),
                    new AttributeValue(1, objectClass, null),
                ]),
        ],
        "contoso.com");
}
