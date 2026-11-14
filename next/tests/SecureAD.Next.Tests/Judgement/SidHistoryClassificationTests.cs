using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Evidence.Run;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Kernel.Capture;
using SecureAD.Kernel.Security;
using Xunit;

namespace SecureAD.Next.Tests.Judgement;

public sealed class SidHistoryClassificationTests
{
    private const string Root = "DC=contoso,DC=com";
    private const string Dn = "CN=Historical identity," + Root;
    private static readonly DateTimeOffset When = DateTimeOffset.UnixEpoch;
    private static readonly string[] History =
    [
        "S-1-5-21-1-2-3-512",
        "S-1-5-21-1-2-3-519",
        "S-1-5-32-544",
        "S-1-5-512",
        "S-1-5-99-512",
        "S-1-5-21-1-512",
        "S-1-5-21-1-2-3-4-512",
        "S-1-5-21-1-2-3-544",
        "S-1-5-21-1-2-3-1100",
    ];

    public static IEnumerable<object?[]> ClassificationCases()
    {
        string?[] names = ["Domain Admins", "Enterprise Admins", "BUILTIN\\Administrators", null, null, null, null, null, null];
        foreach (var kind in new[] { "user", "computer", "group" })
            for (var index = 0; index < History.Length; index++)
                yield return [kind, History[index], names[index]];
    }

    [Theory]
    [MemberData(nameof(ClassificationCases))]
    public void CompleteSidStructureControlsRecognitionForEveryReportedClass(string kind, string sid, string? expectedName)
    {
        var source = Subject(kind, [Sid.ToBytes(sid)!]);
        var verdict = new PrivilegedSidHistory().Judge(source);
        Assert.True(verdict.IsComplete);
        Assert.Equal(expectedName, PrivilegedSidCatalogue.PrivilegedName(sid));
        if (expectedName is null)
        {
            Assert.Empty(verdict.Findings);
            return;
        }
        var finding = Assert.Single(verdict.Findings);
        Assert.Equal((Severity.High, PrivilegedSidHistory.RuleVersion, kind),
            (finding.Severity, finding.RuleVersion, finding.ObjectClass));
        var match = Assert.Single(Assert.IsType<PrivilegedSidHistoryEvidence>(finding.Evidence).Matches);
        Assert.Equal((sid, expectedName), (match.Sid, match.Name));
    }

    [Theory]
    [InlineData("user")]
    [InlineData("computer")]
    [InlineData("group")]
    public void GeneratedDetailUsesTheApprovedConditionalClassAppropriateGuidance(string kind)
    {
        var source = Subject(kind, [Sid.ToBytes(History[0])!]);
        var finding = Assert.Single(new PrivilegedSidHistory().Judge(source).Findings);
        var guidance = RuleGuidanceCatalogue.For("SEC-027")!;
        Assert.Contains(guidance.WhyItMatters, finding.Detail, StringComparison.Ordinal);
        Assert.Contains(guidance.WhatToDo, finding.Detail, StringComparison.Ordinal);
        Assert.Contains(History[0], finding.Detail, StringComparison.Ordinal);
        Assert.DoesNotContain("Set-ADUser", finding.Detail, StringComparison.Ordinal);
        Assert.DoesNotContain("grants access exactly as membership", finding.Detail, StringComparison.Ordinal);
        Assert.DoesNotContain("issued by another domain", finding.Detail, StringComparison.Ordinal);
        Assert.Contains("may break access", finding.Detail, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("user")]
    [InlineData("computer")]
    [InlineData("group")]
    public void CurrentSavedAssessmentKeepsAllOccurrencesAndSeparatesUnrankedAndUnreadableValues(string kind)
    {
        var values = History.Concat([History[0], History[3]]).ToArray();
        var bytes = values.Select(value => Sid.ToBytes(value)!).Concat([new byte[] { 1, 2, 3 }]).ToArray();
        var subject = Subject(kind, bytes);
        var directory = TempDirectories.Create("sid-history-classification");
        var coverage = new PartitionCoverage(Root, NamingContextKind.Domain, "dc.contoso.com",
            ConnectionSecurityLevel.SignedAndSealed, 1, 1, 1, [], false);
        using (var writer = BundleWriter.Create(directory, When))
        {
            writer.WriteCoverage(coverage);
            var attributes = Attributes(kind, bytes).Select(attribute => new EvidenceAttribute(attribute.LdapDisplayName,
                StoredAttributeCompleteness.Complete, attribute.Values.Select(value => value.Text is { } text
                    ? EvidenceValue.OfText(text) : EvidenceValue.OfBytes(value.Bytes!)).ToArray())).ToArray();
            writer.WriteObject(new(coverage, Dn, subject.ObjectGuid, attributes, When));
            writer.Complete(RunCoverage.Of(CoverageId.ForDomains("contoso.com", ["contoso.com"]),
                [DomainCoverage.Read("contoso.com")],
                [ForestPartitionCoverage.Read("CN=Configuration," + Root, NamingContextKind.Configuration),
                 ForestPartitionCoverage.Read("CN=Schema,CN=Configuration," + Root, NamingContextKind.Schema)],
                SysvolCoverage.Of([])), When.AddMinutes(1));
        }
        var original = SelfMembershipDiscoveryTests.Hash(directory);
        var judged = JudgingRun.Judge(directory, [new PrivilegedSidHistory()], When, When,
            JudgingRun.NobodyIsWatching, RunLog.Discarded, CancellationToken.None);
        Assert.True(judged.IsSuccess, judged.Error?.Description);
        using var reader = JudgementReader.Open(directory).Value;
        var stored = Assert.Single(reader.Read().Findings);
        Assert.Equal(PrivilegedSidHistory.RuleVersion, stored.RuleVersion);
        var evidence = Assert.IsType<PrivilegedSidHistoryEvidence>(stored.Evidence);
        Assert.Equal(values, evidence.HistoryValues);
        Assert.Equal(1, evidence.UnreadableValues);
        Assert.False(evidence.IsComplete);
        Assert.Equal(new[] { values[0], values[1], values[2], values[9] }, evidence.Matches.Select(value => value.Sid));
        var row = Assert.Single(reader.ReadListPage(FindingsQuery.About(Dn)).Value.Findings);
        Assert.False(row.EvidenceIsComplete);
        var flagged = reader.ReadSidHistory(row.Reference!.Value, after: null);
        Assert.True(flagged.IsSuccess, flagged.Error?.Description);
        Assert.True(flagged.Value.Context.Matches(row));
        Assert.Equal(new[] { 0, 1, 2, 9 }, flagged.Value.Values.Select(value => value.Ordinal));
        Assert.Null(flagged.Value.Next);
        var other = reader.ReadSidHistory(row.Reference.Value, flagged.Value.Start with { Kind = SidHistoryPageKind.Other });
        Assert.True(other.IsSuccess, other.Error?.Description);
        Assert.Equal(new[] { 3, 4, 5, 6, 7, 8, 10 }, other.Value.Values.Select(value => value.Ordinal));
        Assert.Equal(new[] { values[3], values[4], values[5], values[6], values[7], values[8], values[10] },
            other.Value.Values.Select(value => value.Sid));
        Assert.All(other.Value.Values, value => Assert.Null(value.RecognisedType));
        Assert.Equal(original, SelfMembershipDiscoveryTests.Hash(directory));
    }

    private static ObjectAttributes Subject(string kind, byte[][] history) =>
        new(Dn, Guid.NewGuid(), When, EvidenceCompleteness.Complete, Attributes(kind, history), "contoso.com");

    private static ObjectAttribute[] Attributes(string kind, byte[][] history) =>
    [
        new("objectClass", AttributeCardinality.MultiValued,
            (kind == "computer" ? new[] { "top", "user", "computer" } : ["top", kind])
                .Select((value, ordinal) => new AttributeValue(ordinal, value, null)).ToArray()),
        new("sAMAccountName", AttributeCardinality.SingleValued, [new(0, "Historical identity", null)]),
        new("objectSid", AttributeCardinality.SingleValued, [new(0, null, Sid.ToBytes("S-1-5-21-4-5-6-1100"))]),
        new("sIDHistory", AttributeCardinality.MultiValued,
            history.Select((value, ordinal) => new AttributeValue(ordinal, null, value)).ToArray()),
    ];
}
