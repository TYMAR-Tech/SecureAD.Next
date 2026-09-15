using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using Xunit;

namespace SecureAD.Next.Tests.Judgement;

/// <summary>
/// The guidance an operator reads, bound to the rules that produce findings.
/// </summary>
/// <remarks>
/// <para>
/// <b>Bound in both directions.</b> A rule with no guidance ships a finding an administrator cannot
/// act on; a guidance entry naming no rule is copy nobody will ever see, quietly rotting. Neither is
/// visible without a check, because both look like a full list from one side.
/// </para>
/// <para>
/// <b>What this pair is anchored to.</b> Per <c>F-S44-2</c>, a two-way parity proves only that two
/// lists agree - it cannot tell that a rule is missing from both. That is acceptable here and
/// nowhere else: guidance exists to describe rules this product runs, so the rule catalogue is the
/// right anchor by definition. It would not be an acceptable anchor for anything reassembled from
/// the predecessor.
/// </para>
/// </remarks>
public sealed class RuleGuidanceTests
{
    /// <summary>P-162: shared guidance must distinguish encrypted reads from password retrieval.</summary>
    [Fact]
    public void LapsReadGuidanceSeparatesReadPermissionFromDecryption()
    {
        var guidance = Assert.IsType<RuleGuidance>(RuleGuidanceCatalogue.For("SEC-090"));

        Assert.StartsWith(
            "A broad principal has read access to a LAPS password attribute. A clear-text value "
                + "can expose the local administrator password; an encrypted value requires "
                + "separate decryption permission. Read access alone is not proof of password "
                + "retrieval or control of the machine.",
            guidance.WhyItMatters, StringComparison.Ordinal);
    }

    /// <summary>The rule's stated limits must not promise a decryption check it never performs.</summary>
    [Fact]
    public void LapsReadAboutDoesNotEstablishDecryptionPermission()
    {
        var guidance = Assert.IsType<RuleGuidance>(RuleGuidanceCatalogue.For("SEC-090"));

        Assert.Contains(
            "every one it names has permission to read the attribute. For encrypted values, "
                + "decryption permission is separate and is not established by this rule.",
            guidance.About, StringComparison.Ordinal);
    }

    /// <summary>The action addresses the permission's scope without asserting password retrieval.</summary>
    [Fact]
    public void LapsReadAdviceNamesTheAttributeScope()
    {
        var guidance = Assert.IsType<RuleGuidance>(RuleGuidanceCatalogue.For("SEC-090"));

        Assert.Contains("every attribute on the object rather than only this LAPS attribute",
            guidance.WhatToDo, StringComparison.Ordinal);
    }

    /// <summary>
    /// Every rule that can produce a finding tells the operator what to do about it.
    /// </summary>
    [Fact]
    public void EveryRuleHasGuidance()
    {
        var missing = RuleCatalogue.All
            .Select(r => r.Definition.Id)
            .Where(id => RuleGuidanceCatalogue.For(id) is null)
            .ToArray();

        Assert.True(
            missing.Length == 0,
            "These rules produce findings with nothing telling an operator what they mean or what "
            + "to do: " + string.Join(", ", missing) + ". A finding an administrator cannot act on "
            + "is a row in a grid rather than a thing that gets fixed.");
    }

    /// <summary>
    /// No guidance describes a rule this product does not run.
    /// </summary>
    [Fact]
    public void NoGuidanceDescribesARuleThatDoesNotExist()
    {
        var rules = RuleCatalogue.All.Select(r => r.Definition.Id).ToHashSet(StringComparer.Ordinal);

        var orphans = RuleGuidanceCatalogue.All
            .Select(g => g.RuleId)
            .Where(id => !rules.Contains(id))
            .ToArray();

        Assert.True(
            orphans.Length == 0,
            "This guidance names rules that are not in the catalogue, so nobody will ever read it "
            + "and nothing will keep it true: " + string.Join(", ", orphans));
    }

    /// <summary>
    /// Guidance is written once per rule.
    /// </summary>
    [Fact]
    public void NoRuleHasTwoEntries()
    {
        var duplicated = RuleGuidanceCatalogue.All
            .GroupBy(g => g.RuleId, StringComparer.Ordinal)
            .Where(g => g.Count() > 1)
            .Select(g => g.Key)
            .ToArray();

        Assert.True(
            duplicated.Length == 0,
            "Two entries for one rule means one of them is shown and the other is edited: "
            + string.Join(", ", duplicated));
    }

    /// <summary>
    /// Every field a reader depends on says something.
    /// </summary>
    /// <remarks>
    /// The nullable fields are not checked here: a null MITRE technique or Microsoft reference is a
    /// deliberate statement that no mapping or source has been established, and forcing them full
    /// would produce invented ones.
    /// </remarks>
    [Fact]
    public void NoGuidanceIsBlank()
    {
        foreach (var g in RuleGuidanceCatalogue.All)
        {
            Assert.False(string.IsNullOrWhiteSpace(g.Category), $"{g.RuleId} has no category.");
            Assert.False(
                string.IsNullOrWhiteSpace(g.WhyItMatters), $"{g.RuleId} does not say why it matters.");
            Assert.False(
                string.IsNullOrWhiteSpace(g.WhatToDo), $"{g.RuleId} does not say what to do.");

            // REQUIRED ON EVERY RULE, on the owner's decision of 2026-09-03. Optional was refused:
            // a field populated for some rules and empty for others renders as "this rule has no
            // limitations", which for a bounded rule is the exact false statement About exists to
            // prevent. This assertion is what makes it required.
            Assert.False(
                string.IsNullOrWhiteSpace(g.About),
                $"{g.RuleId} does not say what it looks for and what it does not. Every rule owes "
                + "an About text, because a rule reporting a subset of a problem must not let its "
                + "silence read as 'nothing else is wrong'.");
        }
    }

    /// <summary>
    /// A MITRE technique, where one is claimed, is a technique identifier.
    /// </summary>
    [Fact]
    public void AClaimedMitreTechniqueLooksLikeOne()
    {
        foreach (var g in RuleGuidanceCatalogue.All.Where(g => g.MitreTechnique is not null))
        {
            Assert.Matches(@"^T\d{4}(\.\d{3})?$", g.MitreTechnique!);
        }
    }

    /// <summary>
    /// A Microsoft reference, where one is given, points at Microsoft.
    /// </summary>
    /// <remarks>
    /// The product's claim is that a customer can check what it says. A reference to somewhere else
    /// dressed as a first-party one would be worse than none.
    /// </remarks>
    [Fact]
    public void AMicrosoftReferenceIsAMicrosoftUrl()
    {
        foreach (var g in RuleGuidanceCatalogue.All.Where(g => g.MicrosoftReference is not null))
        {
            Assert.StartsWith(
                "https://learn.microsoft.com/", g.MicrosoftReference!, StringComparison.Ordinal);
        }
    }

    /// <summary>
    /// Guidance never claims that taking the action makes the customer safe.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Why a wording gate exists at all.</b> Saying "this fixes it" is a claim that the action
    /// lies on every route to the object. <c>AC-15</c> requires every recommendation to state its
    /// residual effect and <c>AC-21</c> requires a claimed mandatory action to be proven; both are
    /// stage 8, and neither is met by prose. The danger is not that somebody decides to over-claim -
    /// it is that "this resolves the issue" reads like ordinary helpful writing.
    /// </para>
    /// <para>
    /// <b>The gate is self-tested, because a pattern that matches nothing would pass forever.</b>
    /// Known-bad wording must be caught and known-good wording must not be, and the test refuses to
    /// report a result if either comes out wrong.
    /// </para>
    /// </remarks>
    [Fact]
    public void GuidanceDoesNotClaimTheProblemIsSolved()
    {
        foreach (var g in RuleGuidanceCatalogue.All)
        {
            // About is scanned too, and for a sharper reason than the other two: it is the field
            // whose whole job is to state what the rule cannot see, so wording that drifts into
            // "and therefore nothing else is wrong" would be the failure at its own point of
            // origin.
            var offending = OverClaims(g.WhatToDo)
                .Concat(OverClaims(g.WhyItMatters))
                .Concat(OverClaims(g.About))
                .ToArray();

            Assert.True(
                offending.Length == 0,
                $"{g.RuleId} claims the action settles the matter: '{string.Join("', '", offending)}'. "
                + "Stating that a change closes the exposure is a claim about every route to the "
                + "object, which AC-15 and AC-21 require to be proven and which this product cannot "
                + "yet prove. Say what the action does and what it costs.");
        }

        // THE SELF-TEST. Feeding the matcher wording that is known to over-claim and wording that is
        // known to be fine, so a pattern that stopped matching could not go on reporting zero.
        var mustMatch = new[]
        {
            "Clear the flag. This fixes the issue.",
            "Remove the permission and the account is then secure.",
            "This resolves the finding.",
            "The risk is eliminated once the setting is cleared.",
            "Doing this makes the account safe.",
        };

        var mustNotMatch = new[]
        {
            "Clear \"Do not require Kerberos preauthentication\" on the account.",
            "Move the service to resource-based constrained delegation.",
            "Establish what uses the account before clearing it.",
        };

        foreach (var sample in mustMatch)
        {
            Assert.True(
                OverClaims(sample).Any(),
                $"The over-claim check no longer detects known-bad wording ('{sample}'), so its "
                + "silence on the real guidance means nothing.");
        }

        foreach (var sample in mustNotMatch)
        {
            Assert.False(
                OverClaims(sample).Any(),
                $"The over-claim check now flags wording that is fine ('{sample}'), so it would be "
                + "worked around rather than trusted.");
        }
    }

    /// <summary>
    /// The phrases that turn guidance into a claim this product cannot support.
    /// </summary>
    private static IEnumerable<string> OverClaims(string text) =>
        new[]
        {
            "fixes the issue",
            "fixes this",
            "resolves the finding",
            "resolves the issue",
            "is then secure",
            "will be secure",
            "makes the account safe",
            "makes it safe",
            "eliminates the risk",
            "risk is eliminated",
            "no longer vulnerable",
            "closes the exposure",
            "fully remediates",
        }
        .Where(p => text.Contains(p, StringComparison.OrdinalIgnoreCase));
}
