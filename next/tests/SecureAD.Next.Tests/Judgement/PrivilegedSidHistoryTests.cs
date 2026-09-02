using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using SecureAD.Kernel.Capture;
using SecureAD.Kernel.Security;
using Xunit;

namespace SecureAD.Next.Tests.Judgement;

/// <summary>
/// SEC-027 - a security principal carrying a privileged identifier in its SID history.
/// </summary>
/// <remarks>
/// <para>
/// <b>What is being tested is a judgement over Microsoft's values, and the two are kept apart.</b>
/// The relative identifiers are transcribed from MS-DTYP 2.4.2.4 into <c>WellKnownSidCatalog</c> and
/// held against Microsoft there. What this rule adds is the decision that a subset of them amounts
/// to privilege, and that is what these tests pin -
/// <see cref="EveryPrivilegedIdentifierIsOneMicrosoftDocuments"/> is the join between the two.
/// </para>
/// <para>
/// <b>The negative controls carry the weight.</b> A rule that reported every account with any SID
/// history would pass every positive test here. Four kinds of control exist for that reason: an
/// account with no history at all, an account whose history is ordinary, an account whose <i>own</i>
/// SID is privileged but whose history is not, and the identifiers either side of each accepted one.
/// </para>
/// <para>
/// <b>The SID values are shaped like a real forest's.</b> A migrated account carries a SID issued by
/// a domain that is not its own, so the fixtures use two distinct domain identifiers - which is what
/// makes the "issued by another domain" wording, and the case where it does not apply, testable.
/// </para>
/// </remarks>
public sealed class PrivilegedSidHistoryTests
{
    private const string OldDomain = "S-1-5-21-1834058357-2590327168-2246012571";
    private const string OwnDomain = "S-1-5-21-99887766-55443322-11009988";

    private static readonly PrivilegedSidHistory Rule = new();

    /// <summary>
    /// An account carrying the Enterprise Admins identifier of another domain is reported.
    /// </summary>
    /// <remarks>
    /// This is Microsoft's own worked example, from <i>Unsecure SID History attributes</i>: "a
    /// nonsensitive account in a domain can contain the Enterprise Admin SID in its SID History from
    /// another domain in the Active Directory forest, thus 'elevating' access for the user account
    /// to an effective Domain Admin in all domains in the forest."
    /// </remarks>
    [Fact]
    public void AnAccountCarryingEnterpriseAdminsFromAnotherDomainIsReported()
    {
        var verdict = Rule.Judge(Account("jbloggs", $"{OwnDomain}-1104", [$"{OldDomain}-519"]));

        Assert.True(verdict.IsComplete);
        var finding = Assert.Single(verdict.Findings);

        Assert.Equal("SEC-027", finding.RuleId);
        Assert.Equal(Severity.High, finding.Severity);
        Assert.Equal("jbloggs", finding.Subject.Key);

        var evidence = Assert.IsType<PrivilegedSidHistoryEvidence>(finding.Evidence);
        var match = Assert.Single(evidence.Matches);

        Assert.Equal($"{OldDomain}-519", match.Sid);
        Assert.Equal(519, match.RelativeIdentifier);
        Assert.Equal("Enterprise Admins", match.Name);
        Assert.Equal($"{OwnDomain}-1104", evidence.ObjectSid);
        Assert.Empty(evidence.UnrankedValues);
    }

    /// <summary>
    /// An account with no SID history at all is clean, and is not reported as an unread input.
    /// </summary>
    /// <remarks>
    /// <b>The most important negative control in this file.</b> Nearly every object in a real forest
    /// has no SID history. If absence were treated as a missing input, the rule would name an
    /// unread attribute against tens of thousands of objects, which an operator would correctly read
    /// as a broken capture rather than a clean forest.
    /// </remarks>
    [Fact]
    public void AnAccountWithNoSidHistoryIsCleanRatherThanUnreadable()
    {
        var verdict = Rule.Judge(Account("alice", $"{OwnDomain}-1105", []));

        Assert.True(verdict.IsComplete);
        Assert.Empty(verdict.Findings);
        Assert.Empty(verdict.InputsNotCaptured);
    }

    /// <summary>
    /// An account whose SID history is an ordinary identifier is not reported.
    /// </summary>
    /// <remarks>
    /// <b>This is the rule's stated boundary, pinned so it cannot widen silently.</b> 1157 is what a
    /// custom group of the old domain looks like - Microsoft: relative identifiers are allocated
    /// sequentially by the RID master, so nothing in the number says whether the group was
    /// privileged. Section 6 of the rule document is the argument for leaving it alone; this is
    /// what would fail if somebody decided to report it without changing that document.
    /// </remarks>
    /// <param name="rid">A relative identifier the rule does not treat as privileged.</param>
    [Theory]
    [InlineData(1157)]
    [InlineData(513)]
    [InlineData(1105)]
    public void AnAccountCarryingAnOrdinaryIdentifierIsNotReported(int rid)
    {
        var verdict = Rule.Judge(Account("bob", $"{OwnDomain}-1106", [$"{OldDomain}-{rid}"]));

        Assert.True(verdict.IsComplete);
        Assert.Empty(verdict.Findings);
    }

    /// <summary>
    /// A privileged account whose SID history is ordinary is not reported.
    /// </summary>
    /// <remarks>
    /// <b>This catches the rule reading the wrong attribute.</b> A Domain Admin is not a finding.
    /// If the rule ranked <c>objectSid</c> instead of <c>sIDHistory</c>, every genuinely privileged
    /// account in the forest would be reported and every other positive test here would still pass.
    /// </remarks>
    [Fact]
    public void AnAccountThatIsItselfPrivilegedIsNotReportedForThat()
    {
        var verdict = Rule.Judge(Account("admin", $"{OwnDomain}-512", [$"{OldDomain}-1157"]));

        Assert.True(verdict.IsComplete);
        Assert.Empty(verdict.Findings);
    }

    /// <summary>
    /// The identifiers either side of each accepted one are not reported.
    /// </summary>
    /// <remarks>
    /// <b>What catches a mistyped constant.</b> 511 and 513 sit either side of Domain Admins, 517
    /// and 520 around Schema and Enterprise Admins - except 520 is itself accepted, so 523 and 524
    /// stand in - and 547 and 553 bracket the built-in operator block. A digit wrong in the set
    /// would report one of these.
    /// </remarks>
    /// <param name="rid">A relative identifier adjacent to an accepted one.</param>
    [Theory]
    [InlineData(511)]
    [InlineData(513)]
    [InlineData(517)]
    [InlineData(523)]
    [InlineData(524)]
    [InlineData(547)]
    [InlineData(553)]
    [InlineData(501)]
    [InlineData(503)]
    public void AnIdentifierBesideAnAcceptedOneIsNotReported(int rid)
    {
        var verdict = Rule.Judge(Account("carol", $"{OwnDomain}-1107", [$"{OldDomain}-{rid}"]));

        Assert.True(verdict.IsComplete);
        Assert.Empty(verdict.Findings);
    }

    /// <summary>
    /// Every accepted identifier is reported, and carries Microsoft's name for it.
    /// </summary>
    /// <param name="rid">An accepted relative identifier.</param>
    [Theory]
    [InlineData(500)]
    [InlineData(502)]
    [InlineData(512)]
    [InlineData(516)]
    [InlineData(518)]
    [InlineData(519)]
    [InlineData(520)]
    [InlineData(521)]
    public void EveryAcceptedIdentifierIsReported(int rid)
    {
        var verdict = Rule.Judge(Account("dave", $"{OwnDomain}-1108", [$"{OldDomain}-{rid}"]));

        var finding = Assert.Single(verdict.Findings);
        var evidence = Assert.IsType<PrivilegedSidHistoryEvidence>(finding.Evidence);
        var match = Assert.Single(evidence.Matches);

        Assert.Equal(rid, match.RelativeIdentifier);
        Assert.NotEmpty(match.Name);
    }

    /// <summary>
    /// Every accepted built-in group is reported, and carries Microsoft's name for it.
    /// </summary>
    /// <param name="sid">An accepted built-in SID.</param>
    [Theory]
    [InlineData("S-1-5-32-544")]
    [InlineData("S-1-5-32-548")]
    [InlineData("S-1-5-32-549")]
    [InlineData("S-1-5-32-550")]
    [InlineData("S-1-5-32-551")]
    [InlineData("S-1-5-32-552")]
    public void EveryAcceptedBuiltinGroupIsReported(string sid)
    {
        var verdict = Rule.Judge(Account("erin", $"{OwnDomain}-1109", [sid]));

        var finding = Assert.Single(verdict.Findings);
        var evidence = Assert.IsType<PrivilegedSidHistoryEvidence>(finding.Evidence);
        var match = Assert.Single(evidence.Matches);

        Assert.Equal(sid, match.Sid);
        Assert.NotEmpty(match.Name);
    }

    /// <summary>
    /// A domain SID whose last value happens to equal a built-in alias is not reported.
    /// </summary>
    /// <remarks>
    /// <b>This is the defect the anchor test found, pinned so it cannot come back.</b> The built-in
    /// groups were first written into the relative-identifier set, which reads the last value off
    /// any SID. <c>S-1-5-21-…-544</c> is an ordinary account or group in a domain that issued 544 in
    /// the ordinary course of allocating identifiers, and it would have been reported as the
    /// built-in Administrators group - the product telling a customer something false about who is
    /// privileged.
    /// </remarks>
    /// <param name="rid">A value that is a built-in alias only under the built-in domain.</param>
    [Theory]
    [InlineData(544)]
    [InlineData(548)]
    [InlineData(551)]
    [InlineData(552)]
    public void ADomainSidEndingInABuiltinAliasIsNotReported(int rid)
    {
        var verdict = Rule.Judge(Account("frank", $"{OwnDomain}-1113", [$"{OldDomain}-{rid}"]));

        Assert.True(verdict.IsComplete);
        Assert.Empty(verdict.Findings);
    }

    /// <summary>
    /// A value the rule cannot rank travels in the evidence beside the one it could, and is counted
    /// in the wording.
    /// </summary>
    /// <remarks>
    /// <b>This is section 6 of the rule document, enforced.</b> Storing only the matches would show
    /// an operator a filtered view of the account he is being told about, and leave him believing it
    /// carries nothing else.
    /// </remarks>
    [Fact]
    public void ValuesTheRuleCannotRankAreCarriedBesideTheOnesItCan()
    {
        var verdict = Rule.Judge(Account(
            "frank",
            $"{OwnDomain}-1110",
            [$"{OldDomain}-1157", $"{OldDomain}-512", $"{OldDomain}-1201"]));

        var finding = Assert.Single(verdict.Findings);
        var evidence = Assert.IsType<PrivilegedSidHistoryEvidence>(finding.Evidence);

        Assert.Equal(3, evidence.HistoryValues.Count);
        Assert.Single(evidence.Matches);
        Assert.Equal(2, evidence.UnrankedValues.Count);
        Assert.Contains("2 further SID history values", finding.Detail, StringComparison.Ordinal);
    }

    /// <summary>
    /// An unreadable SID history value does not suppress a privileged one that was read.
    /// </summary>
    /// <remarks>
    /// <b>The finding is true whether or not a sibling value could be decoded.</b> Falling silent
    /// here would suppress a real escalation over a detail that does not bear on it. What must not
    /// happen is the partial answer being presented as complete, so the evidence says how many
    /// values were not read and the wording repeats it.
    /// </remarks>
    [Fact]
    public void AnUnreadableValueDoesNotSuppressAPrivilegedOneThatWasRead()
    {
        var subject = AccountWithRawHistory(
            "grace",
            $"{OwnDomain}-1111",
            [Sid.ToBytes($"{OldDomain}-519")!, [0x00, 0x01, 0x02]]);

        var verdict = Rule.Judge(subject);

        var finding = Assert.Single(verdict.Findings);
        var evidence = Assert.IsType<PrivilegedSidHistoryEvidence>(finding.Evidence);

        Assert.Single(evidence.Matches);
        Assert.Equal(1, evidence.UnreadableValues);
        Assert.False(evidence.IsComplete);
        Assert.Contains("could not be read", finding.Detail, StringComparison.Ordinal);
    }

    /// <summary>
    /// An unreadable value with nothing privileged among the rest stops the rule saying "clean".
    /// </summary>
    /// <remarks>
    /// <b>Absent means clean; unreadable means unknown.</b> The privileged identifier the rule is
    /// looking for could be in the value it could not decode, so silence here would be a claim of
    /// completeness the evidence does not support - decisions 0002 and 0086.
    /// </remarks>
    [Fact]
    public void AnUnreadableValueWithNoMatchIsNotReportedAsClean()
    {
        var subject = AccountWithRawHistory(
            "ivan",
            $"{OwnDomain}-1114",
            [Sid.ToBytes($"{OldDomain}-1157")!, [0x00, 0x01, 0x02]]);

        var verdict = Rule.Judge(subject);

        Assert.False(verdict.IsComplete);
        Assert.Empty(verdict.Findings);
        Assert.Contains("sIDHistory", verdict.InputsNotCaptured);
    }

    /// <summary>
    /// An account whose own identifier could not be read is still reported.
    /// </summary>
    /// <remarks>
    /// The escalation does not stop being true because <c>objectSid</c> was unreadable. Suppressing
    /// the finding would be the product staying quiet about something it knows; the evidence records
    /// the absence instead.
    /// </remarks>
    [Fact]
    public void AnAccountWithNoReadableObjectSidIsStillReported()
    {
        var verdict = Rule.Judge(Account("heidi", objectSid: null, [$"{OldDomain}-512"]));

        var finding = Assert.Single(verdict.Findings);
        var evidence = Assert.IsType<PrivilegedSidHistoryEvidence>(finding.Evidence);

        Assert.Null(evidence.ObjectSid);
        Assert.Single(evidence.Matches);
    }

    /// <summary>
    /// A computer and a group are reported exactly as a user is.
    /// </summary>
    /// <remarks>
    /// Decided by the owner on 2026-09-02. The schema puts <c>sIDHistory</c> on
    /// <c>Security-Principal</c>, so all three carry it and no Microsoft source ranks them
    /// differently. The class travels in the finding instead.
    /// </remarks>
    /// <param name="objectClass">The class of the object carrying the history.</param>
    [Theory]
    [InlineData("user")]
    [InlineData("computer")]
    [InlineData("group")]
    public void EverySecurityPrincipalClassIsReportedTheSame(string objectClass)
    {
        var verdict = Rule.Judge(Account(
            "subject", $"{OwnDomain}-1112", [$"{OldDomain}-512"], objectClass));

        var finding = Assert.Single(verdict.Findings);

        Assert.Equal(Severity.High, finding.Severity);
        Assert.Equal(objectClass, finding.ObjectClass);
    }

    /// <summary>
    /// Every identifier the rule treats as privileged is one Microsoft documents.
    /// </summary>
    /// <remarks>
    /// <b>This is the anchor, and it is the reason the rule holds no names of its own.</b> There is
    /// no card for SEC-027 and no predecessor to port, so a set of tests agreeing with each other
    /// would prove only that the rule agrees with itself - the F-S44-2 shape. Every value the rule
    /// names must resolve in <see cref="WellKnownSidCatalog"/>, which is transcribed from MS-DTYP
    /// 2.4.2.4 and held against Microsoft by its own anchor tests. An invented identifier fails
    /// here.
    /// </remarks>
    [Fact]
    public void EveryPrivilegedIdentifierIsOneMicrosoftDocuments()
    {
        foreach (var rid in PrivilegedSidCatalogue.PrivilegedRelativeIdentifiers)
        {
            Assert.True(
                WellKnownSidCatalog.FindByRid(rid) is not null,
                $"SEC-027 treats relative identifier {rid} as privileged, but MS-DTYP 2.4.2.4 as "
                + "transcribed into WellKnownSidCatalog does not define it. A rule may decide which "
                + "of Microsoft's identifiers amount to privilege; it may not invent one.");
        }

        foreach (var sid in PrivilegedSidCatalogue.PrivilegedWellKnownSids)
        {
            Assert.True(
                WellKnownSidCatalog.FindBySid(sid) is not null,
                $"SEC-027 treats {sid} as privileged, but MS-DTYP 2.4.2.4 as transcribed into "
                + "WellKnownSidCatalog does not define it. A rule may decide which of Microsoft's "
                + "SIDs amount to privilege; it may not invent one.");
        }
    }

    /// <summary>
    /// The two privileged sets do not overlap, so no value can be ranked twice or two ways.
    /// </summary>
    /// <remarks>
    /// A built-in alias listed as a domain-relative identifier as well would make
    /// <c>S-1-5-21-…-544</c> privileged again, which is the defect
    /// <see cref="ADomainSidEndingInABuiltinAliasIsNotReported"/> describes. This states the
    /// separation directly rather than only through its consequence.
    /// </remarks>
    [Fact]
    public void TheTwoPrivilegedSetsDoNotOverlap()
    {
        var builtinAliases = PrivilegedSidCatalogue.PrivilegedWellKnownSids
            .Select(sid => Sid.RelativeIdentifier(sid)!.Value);

        Assert.Empty(
            builtinAliases.Where(PrivilegedSidCatalogue.PrivilegedRelativeIdentifiers.Contains));
    }

    /// <summary>
    /// The rule declares no derived facts, so it can judge a bundle that was never derived.
    /// </summary>
    [Fact]
    public void TheRuleAsksForNothingDerived() =>
        Assert.Empty(Rule.Definition.RequiredDerivedFacts);

    /// <summary>
    /// The rule declares the attributes it reads, so the build gate can see them.
    /// </summary>
    [Fact]
    public void TheRuleDeclaresWhatItReads()
    {
        Assert.Contains("sIDHistory", Rule.Definition.RequiredAttributes);
        Assert.Contains("objectSid", Rule.Definition.RequiredAttributes);
    }

    private static ObjectAttributes Account(
        string name,
        string? objectSid,
        IReadOnlyList<string> history,
        string objectClass = "user") =>
        AccountWithRawHistory(
            name,
            objectSid,
            [.. history.Select(h => Sid.ToBytes(h)!)],
            objectClass);

    private static ObjectAttributes AccountWithRawHistory(
        string name,
        string? objectSid,
        IReadOnlyList<byte[]> history,
        string objectClass = "user")
    {
        var attributes = new List<ObjectAttribute>
        {
            Single("sAMAccountName", name),
            new(
                "objectClass",
                AttributeCardinality.MultiValued,
                [new AttributeValue(0, "top", null), new AttributeValue(1, objectClass, null)]),
        };

        if (objectSid is not null)
        {
            attributes.Add(new ObjectAttribute(
                "objectSid",
                AttributeCardinality.SingleValued,
                [new AttributeValue(0, null, Sid.ToBytes(objectSid)!)]));
        }

        if (history.Count > 0)
        {
            attributes.Add(new ObjectAttribute(
                "sIDHistory",
                AttributeCardinality.MultiValued,
                [.. history.Select((bytes, i) => new AttributeValue(i, null, bytes))]));
        }

        return new ObjectAttributes(
            $"CN={name},CN=Users,DC=ph,DC=ad,DC=lab",
            Guid.NewGuid(),
            DateTimeOffset.UnixEpoch,
            EvidenceCompleteness.Complete,
            attributes,
            DomainFqdn: "ad.lab");
    }

    private static ObjectAttribute Single(string ldapDisplayName, string value) =>
        new(ldapDisplayName, AttributeCardinality.SingleValued, [new AttributeValue(0, value, null)]);
}
