using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using SecureAD.Derivation;
using SecureAD.Kernel;
using SecureAD.Kernel.Capture;
using System.Text.Json;
using System.Text.Json.Nodes;
using Xunit;
using static SecureAD.Next.Tests.Judgement.SelfMembershipDiscoveryTests;

namespace SecureAD.Next.Tests.Judgement;

public sealed class DuplicateSpnTests
{
    private static readonly DuplicateServicePrincipalNames Rule = new();
    private static readonly Guid A = Guid.Parse("11111111-1111-1111-1111-111111111111");
    private static readonly Guid B = Guid.Parse("22222222-2222-2222-2222-222222222222");
    private static readonly Guid C = Guid.Parse("33333333-3333-3333-3333-333333333333");
    private static readonly string Seal = new('a', 64);

    // Microsoft setspn: Windows SPNs are case-insensitive; -F selects forest scope.
    // MS-ADTS 2.2.21: port OR instance and optional service-name are part of the value.
    [Theory]
    [InlineData("HTTP/web.contoso.com", "http/WEB.contoso.com")]
    [InlineData("HOST/server", "host/SERVER")]
    [InlineData("RestrictedKrbHost/server", "restrictedkrbhost/SERVER")]
    [InlineData("CustomClass/host:instance", "customclass/HOST:INSTANCE")]
    [InlineData("ldap/dc-01.fabrikam.com/fabrikam.com", "LDAP/DC-01.FABRIKAM.COM/FABRIKAM.COM")]
    [InlineData("MyDBService/host1.example.com/CN=hrdb,OU=mktg,DC=example,DC=com", "mydbservice/HOST1.example.com/CN=hrdb,OU=mktg,DC=example,DC=com")]
    public void Sec026MicrosoftAnchorsMatchFullValuesAcrossDistinctForestOwners(string first, string second)
    {
        var result = Assess(true, Subject(A, "contoso.com", first), Subject(B, "child.contoso.com", second));
        Assert.Equal(RuleExecutionOutcome.Succeeded, result.Outcome);
        Assert.Equal(2, result.Findings.Count);
        Assert.All(result.Findings, finding =>
        {
            Assert.Equal(Severity.High, finding.Severity);
            var evidence = Assert.IsType<DuplicateSpnEvidence>(finding.Evidence);
            var match = Assert.Single(evidence.Duplicates);
            Assert.Equal(2, match.Owners.Count);
            Assert.Equal(new[] { first, second }, match.Occurrences.Select(value => value.Value));
            Assert.Equal(new[] { "contoso.com", "child.contoso.com" }, match.Owners.Select(owner => owner.DomainFqdn));
            Assert.Equal(finding.ObjectGuid.ToString("D"), finding.Subject.Key);
        });
    }

    [Theory]
    [InlineData("MSSQLSvc/host:1433", "MSSQLSvc/host:1434")]
    [InlineData("Custom/host:one", "Custom/host:two")]
    [InlineData("ldap/host/one.example", "ldap/host/two.example")]
    [InlineData("HOST/one", "HOST/two")]
    [InlineData("HOST/server", "CIFS/server")]
    public void Sec026MicrosoftFormatKeepsPortInstanceSuffixAndAliasValuesDistinct(string first, string second)
    {
        var result = Assess(true, Subject(A, "contoso.com", first), Subject(B, "contoso.com", second));
        Assert.Empty(result.Findings);
        Assert.Equal(RuleExecutionOutcome.Succeeded, result.Outcome);
    }

    [Fact]
    public void Sec026RepeatedOwnerAndDuplicateOccurrencesDoNotInflateOwnerCount()
    {
        var owner = Subject(A, "contoso.com", "HTTP/web", "http/WEB");
        Assert.Empty(Assess(true, owner, owner).Findings);
        var result = Assess(true, owner, owner, Subject(B, "contoso.com", "HTTP/web"));
        Assert.Equal(2, result.Findings.Count);
        Assert.All(result.Findings, finding =>
        {
            var match = Assert.Single(Assert.IsType<DuplicateSpnEvidence>(finding.Evidence).Duplicates);
            Assert.Equal(2, match.Owners.Count);
            Assert.Equal(3, match.Occurrences.Count);
        });
    }

    [Theory]
    [InlineData("user")]
    [InlineData("computer")]
    [InlineData("msDS-ManagedServiceAccount")]
    [InlineData("msDS-GroupManagedServiceAccount")]
    public void Sec026IncludesCapturedAccountClassesWithoutDisabledOrLocationExemptions(string kind)
    {
        var first = Subject(A, "contoso.com", "HOST/server") with
        {
            DistinguishedName = "CN=Old host,OU=Disabled,DC=contoso,DC=com",
            Attributes = [Attribute("objectClass", "top", "user", kind), Attribute("servicePrincipalName", "HOST/server"), Attribute("userAccountControl", "514")],
        };
        Assert.Equal(2, Assess(true, first, Subject(B, "contoso.com", "HOST/server")).Findings.Count);
    }

    [Fact]
    public void Sec026AggregatesAllDuplicatedValuesAndOwnersPerSubject()
    {
        var result = Assess(true, Subject(A, "contoso.com", "HTTP/web", "LDAP/dc/domain"),
            Subject(B, "contoso.com", "http/WEB", "LDAP/dc/domain"), Subject(C, "child.contoso.com", "HTTP/web"));
        Assert.Equal(3, result.Findings.Count);
        var evidence = Assert.IsType<DuplicateSpnEvidence>(result.Findings.Single(f => f.ObjectGuid == A).Evidence);
        Assert.Equal(2, evidence.Duplicates.Count);
        Assert.Equal(new[] { 3, 2 }, evidence.Duplicates.Select(value => value.Owners.Count));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Sec026CaptureShortfallNeverBecomesUniqueWhilePositiveEvidenceSurvives(bool duplicate)
    {
        var result = Assess(false, Subject(A, "contoso.com", "HTTP/web"), Subject(B, "contoso.com", duplicate ? "HTTP/web" : "HTTP/other"));
        Assert.Equal(RuleExecutionOutcome.Indeterminate, result.Outcome);
        Assert.Equal(2, result.ObjectsNotJudged);
        Assert.NotEmpty(result.MissingInputs);
        Assert.Equal(duplicate ? 2 : 0, result.Findings.Count);
        Assert.All(result.Findings, finding => Assert.Contains(Assert.IsType<DuplicateSpnEvidence>(finding.Evidence).Limitations,
            value => value.Contains("capture", StringComparison.OrdinalIgnoreCase)));
    }

    [Theory]
    [InlineData("")]
    [InlineData("missing-slash")]
    [InlineData("HTTP/")]
    [InlineData("HTTP/*")]
    [InlineData("HTTP/host:")]
    [InlineData("HTTP/host/domain/extra")]
    public void Sec026UnsupportedValuesAreUnknownNotCleanOrDuplicated(string invalid)
    {
        var result = Assess(true, Subject(A, "contoso.com", invalid), Subject(B, "contoso.com", invalid));
        Assert.Empty(result.Findings);
        Assert.Equal(RuleExecutionOutcome.Indeterminate, result.Outcome);
    }

    [Theory]
    [InlineData("missing-guid")]
    [InlineData("missing-domain")]
    [InlineData("missing-class")]
    [InlineData("missing-spn")]
    [InlineData("bytes")]
    [InlineData("visibility")]
    public void Sec026UnknownInputsRetainProvedDuplicateOwners(string gap)
    {
        var third = Subject(C, "contoso.com", "HTTP/web");
        third = gap switch
        {
            "missing-guid" => third with { ObjectGuid = null },
            "missing-domain" => third with { DomainFqdn = null },
            "missing-class" => third with { Attributes = [Attribute("servicePrincipalName", "HTTP/web")] },
            "missing-spn" => third with { Attributes = [Attribute("objectClass", "user")] },
            "bytes" => third with { Attributes = [Attribute("objectClass", "user"),
                new("servicePrincipalName", AttributeCardinality.MultiValued, [new(0, null, [1])])] },
            _ => third with { Completeness = EvidenceCompleteness.MayBeMissingConfidentialValues },
        };
        var result = Assess(true, Subject(A, "contoso.com", "HTTP/web"), Subject(B, "contoso.com", "HTTP/web"), third);
        Assert.Equal(RuleExecutionOutcome.Indeterminate, result.Outcome);
        Assert.Contains(result.Findings, finding => finding.ObjectGuid == A);
        Assert.Contains(result.Findings, finding => finding.ObjectGuid == B);
        Assert.All(result.Findings, finding => Assert.NotEmpty(Assert.IsType<DuplicateSpnEvidence>(finding.Evidence).Limitations));
    }

    [Fact]
    public void Sec026ConflictingGuidAttributionCannotFabricateAnotherOwner()
    {
        var result = Assess(true, Subject(A, "contoso.com", "HTTP/web"), Subject(A, "child.contoso.com", "HTTP/web"),
            Subject(B, "contoso.com", "HTTP/web"));
        Assert.Empty(result.Findings);
        Assert.Equal(RuleExecutionOutcome.Indeterminate, result.Outcome);
    }

    [Fact]
    public void Sec026ConflictingDistinguishedNameCannotFabricateAnotherOwner()
    {
        var a = Subject(A, "contoso.com", "HTTP/web");
        var b = Subject(B, "contoso.com", "HTTP/web") with { DistinguishedName = a.DistinguishedName.ToUpperInvariant() };
        var result = Assess(true, a, b);
        Assert.Empty(result.Findings);
        Assert.Equal(RuleExecutionOutcome.Indeterminate, result.Outcome);
    }

    [Theory]
    [InlineData("kadmin/changepw")]
    [InlineData("krbtgt/contoso.com")]
    public void Sec026SystemNamesAreNotSilentlyExemptAndRequireSpecificReview(string spn)
    {
        var result = Assess(true, Subject(A, "contoso.com", spn), Subject(B, "contoso.com", spn));
        Assert.Equal(2, result.Findings.Count);
        Assert.All(result.Findings, finding => Assert.Contains("protocol-specific review", finding.Detail));
        Assert.Contains("Do not remove krbtgt", DuplicateServicePrincipalNames.Guidance);
    }

    [Fact]
    public void Sec026HonorsCancellationAndDoesNotReuseACompletedAssessment()
    {
        var assessment = new DuplicateSpnAssessment(Rule, "contoso.com", Seal, true);
        using var stop = new CancellationTokenSource();
        stop.Cancel();
        Assert.ThrowsAny<OperationCanceledException>(() => assessment.Add(Subject(A, "contoso.com", "HTTP/web"), stop.Token));
        Assert.ThrowsAny<OperationCanceledException>(() => assessment.Complete(stop.Token));
        assessment.Complete(CancellationToken.None);
        Assert.Throws<InvalidOperationException>(() => assessment.Complete(CancellationToken.None));
    }

    [Fact]
    public void Sec026NormalJudgingPublishesHighFindingsAndReopensEveryOriginalOccurrence()
    {
        var directory = Prepared();
        using var reader = Open(directory);
        var result = reader.Read();
        Assert.Equal(2, result.Findings.Count);
        Assert.Equal(RuleExecutionOutcome.Succeeded, Assert.Single(reader.ReadRuleExecutions().Executions).Outcome);
        Assert.All(result.Findings, finding =>
        {
            var evidence = Assert.IsType<DuplicateSpnEvidence>(finding.Evidence);
            Assert.Equal(reader.Description.EvidenceSeal, evidence.EvidenceSeal);
            Assert.Equal(2, evidence.Duplicates.Count);
            Assert.Equal(3, evidence.Duplicates[0].Occurrences.Count);
            Assert.Equal("SEC-026", finding.RuleId);
            Assert.Equal(Severity.High, finding.Severity);
            var page = reader.ReadPage(FindingsQuery.About(finding.DistinguishedName));
            Assert.True(page.IsSuccess, page.Error?.Description);
            Assert.Equal(finding.Subject, Assert.Single(page.Value.Findings).Subject);
        });
    }

    [Theory]
    [InlineData("UPDATE finding_duplicate_spn SET fingerprint=zeroblob(32)")]
    [InlineData("UPDATE finding_duplicate_spn SET generation='11111111-1111-1111-1111-111111111111'")]
    [InlineData("DELETE FROM finding_duplicate_spn")]
    [InlineData("UPDATE finding SET distinguished_name='CN=Wrong,DC=contoso,DC=com' WHERE rule_id='SEC-026'")]
    public void Sec026ReadbackRefusesBrokenEvidenceOrBinding(string sql)
    {
        var directory = Prepared();
        SelfMembershipCoverageTests.Mutate(directory, connection =>
        {
            using var command = connection.CreateCommand();
            command.CommandText = sql;
            command.ExecuteNonQuery();
        });
        using var reader = Open(directory);
        Assert.Throws<InvalidDataException>(() => reader.ReadPage(FindingsQuery.Everything()));
    }

    [Theory]
    [InlineData("owner")]
    [InlineData("occurrence")]
    [InlineData("spn")]
    [InlineData("seal")]
    [InlineData("one-owner")]
    public void Sec026RehashedMalformedProofStillCannotBecomeAValidFinding(string change)
    {
        var directory = Prepared();
        SelfMembershipCoverageTests.Mutate(directory, connection =>
        {
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT finding_id,generation,proof FROM finding_duplicate_spn ORDER BY finding_id LIMIT 1";
            long id;
            string generation;
            JsonObject proof;
            using (var row = command.ExecuteReader())
            {
                Assert.True(row.Read());
                id = row.GetInt64(0);
                generation = row.GetString(1);
                proof = JsonNode.Parse(row.GetString(2))!.AsObject();
            }
            var first = proof["Duplicates"]![0]!.AsObject();
            switch (change)
            {
                case "owner": first["Owners"]![1]!["ObjectGuid"] = first["Owners"]![0]!["ObjectGuid"]!.GetValue<string>(); break;
                case "occurrence": first["Occurrences"]![0]!["OwnerGuid"] = Guid.Empty.ToString("D"); break;
                case "spn": first["MatchKey"] = "HTTP/another"; break;
                case "seal": proof["EvidenceSeal"] = new string('f', 64); break;
                case "one-owner": first["Owners"]!.AsArray().RemoveAt(1); break;
            }
            var json = proof.ToJsonString();
            command.CommandText = "UPDATE finding_duplicate_spn SET proof=$proof,fingerprint=$hash WHERE finding_id=$id";
            command.Parameters.AddWithValue("$proof", json);
            command.Parameters.AddWithValue("$hash", OwnershipAuditStorage.Hash(generation + "\0" + json));
            command.Parameters.AddWithValue("$id", id);
            Assert.Equal(1, command.ExecuteNonQuery());
        });
        using var reader = Open(directory);
        Assert.Throws<InvalidDataException>(() => reader.ReadPage(FindingsQuery.Everything()));
    }

    internal static IReadOnlyList<Finding> ReadPublishedFindings()
    {
        using var reader = Open(Prepared());
        return reader.Read().Findings;
    }

    private static string Prepared()
    {
        var directory = Capture();
        var result = JudgingRun.Judge(directory, [Rule], Started, Started, JudgingRun.NobodyIsWatching, RunLog.Discarded, CancellationToken.None);
        Assert.True(result.IsSuccess, result.Error?.Description);
        return directory;
    }

    private static string Capture() => Bundle(users: 0, members: [], writeAdditional: (writer, partition) =>
        {
            foreach (var id in new[] { A, B })
                writer.WriteObject(new(partition, $"CN={id:D},DC=contoso,DC=com", id,
                    [Stored("objectClass", "top", "user"), Stored("sAMAccountName", id.ToString("D")),
                        Stored("servicePrincipalName", id == A ? ["HTTP/web", "http/WEB", "LDAP/dc/domain"] : ["HTTP/web", "LDAP/dc/domain"])], Started));
        });

    [Theory]
    [InlineData("shell")]
    [InlineData("cli-offline")]
    [InlineData("cli-capture")]
    public async Task Sec026NormalHostsScheduleTheSameForestRule(string host)
    {
        var directory = Capture();
        await OwnAccountMembershipPathTests.RunCoverageHostAsync(host, directory, PathRequesterPolicy.SupportedCapturedQuestions);
        using var reader = Open(directory);
        Assert.Equal(2, reader.Read().Findings.Count(finding => finding.RuleId == "SEC-026"));
        Assert.Contains(reader.ReadRuleExecutions().Executions, execution => execution.RuleId == "SEC-026"
            && execution.Outcome == RuleExecutionOutcome.Succeeded);
        Assert.Contains(RuleGuidanceCatalogue.All, guidance => guidance.RuleId == "SEC-026"
            && guidance.WhatToDo == DuplicateServicePrincipalNames.Guidance);
    }

    [Fact]
    public void Sec026CancellationBeforePublicationPreservesPreviousGeneration()
    {
        var directory = Prepared();
        Guid generation;
        using (var previous = Open(directory)) generation = previous.Description.GenerationId;
        using var stopping = new CancellationTokenSource();
        Assert.ThrowsAny<OperationCanceledException>(() => JudgingRun.Judge(directory, [Rule], Started, Started,
            new StopPublication(stopping), RunLog.Discarded, stopping.Token));
        using var current = Open(directory);
        Assert.Equal(generation, current.Description.GenerationId);
        Assert.Equal(2, current.Read().Findings.Count);
    }

    private sealed class StopPublication(CancellationTokenSource stopping) : IProgress<JudgingRun.JudgingProgress>
    {
        public void Report(JudgingRun.JudgingProgress value)
        {
            if (value.Phase == JudgingPhase.PublishingJudgement) stopping.Cancel();
        }
    }

    private static JudgementReader Open(string directory)
    {
        var result = JudgementReader.Open(directory);
        Assert.True(result.IsSuccess, result.Error?.Description);
        return result.Value;
    }
    private static EvidenceAttribute Stored(string name, params string[] values) => new(name,
        StoredAttributeCompleteness.Complete, values.Select(EvidenceValue.OfText).ToArray());
    private static RuleExecution Assess(bool complete, params ObjectAttributes[] subjects)
    {
        var assessment = new DuplicateSpnAssessment(Rule, "contoso.com", Seal, complete);
        foreach (var subject in subjects) assessment.Add(subject, CancellationToken.None);
        return assessment.Complete(CancellationToken.None);
    }
    private static ObjectAttributes Subject(Guid id, string domain, params string[] values) => new(
        $"CN={id:D},DC={domain.Replace(".", ",DC=", StringComparison.Ordinal)}", id, Started, EvidenceCompleteness.Complete,
        [Attribute("objectClass", "top", "user"), Attribute("servicePrincipalName", values)], domain);
    private static ObjectAttribute Attribute(string name, params string[] values) => new(name, AttributeCardinality.MultiValued,
        values.Select((value, ordinal) => new AttributeValue(ordinal, value, null)).ToArray());
}
