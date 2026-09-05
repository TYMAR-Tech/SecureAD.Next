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
