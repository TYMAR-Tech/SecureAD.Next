using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Evidence.Run;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Kernel.Security;
using SecureAD.Shell.ViewModels;
using Xunit;
using static SecureAD.Next.Tests.Judgement.SelfMembershipDiscoveryTests;

namespace SecureAD.Next.Tests.Judgement;

public sealed class CircularGroupMembershipTests
{
    private const string Root = "DC=contoso,DC=com";
    private const string A = "CN=Cycle A," + Root;
    private const string B = "CN=Cycle B," + Root;
    private const string C = "CN=Cycle C," + Root;
    private const string D = "CN=Cycle D," + Root;
    private const string DomainSid = "S-1-5-21-1-2-3";
    private static readonly CircularGroupMembership Rule = new();

    [Theory]
    [InlineData("self", 1, 1)]
    [InlineData("pair", 2, 2)]
    [InlineData("overlap", 3, 4)]
    [InlineData("distribution", 2, 2)]
    [InlineData("member-of", 2, 2)]
    [InlineData("privileged", 2, 2)]
    public void Sec052ReportsOneMediumFindingPerRecordedConnectedSet(string variant, int groups, int links)
    {
        using var reader = Open(Prepared(variant));
        var finding = Assert.Single(reader.Read().Findings);
        var evidence = Assert.IsType<CircularMembershipEvidence>(finding.Evidence);
        Assert.Equal(("SEC-052", Severity.Medium, groups, links),
            (finding.RuleId, finding.Severity, evidence.Groups.Count, evidence.Links.Count));
        Assert.Equal(evidence.Groups[0].ObjectGuid, finding.ObjectGuid);
        Assert.Equal(evidence.Groups[0].DistinguishedName, finding.DistinguishedName);
        Assert.Equal(evidence.Groups[0].DomainFqdn, finding.DomainFqdn);
        Assert.Equal(CircularMembershipIndex.Key(evidence.Groups), finding.Subject.Key);
        Assert.True(evidence.InventoryComplete);
        Assert.Contains(CircularGroupMembership.Explanation, finding.Detail);
        Assert.Equal(RuleExecutionOutcome.Succeeded, Assert.Single(reader.ReadRuleExecutions().Executions).Outcome);
    }

    [Fact]
    public void Sec052AcyclicMembershipDoesNotProduceACycleFinding()
    {
        using var reader = Open(Prepared("acyclic"));
        Assert.Empty(reader.Read().Findings);
        Assert.Equal(RuleExecutionOutcome.Succeeded, Assert.Single(reader.ReadRuleExecutions().Executions).Outcome);
    }

    [Fact]
    public void GroupsInventoryKeepsKnownCyclesSeparateFromIncompleteAssessment()
    {
        using var reader = Open(Prepared("partial-input"));
        var query = new GroupInventoryQuery(null, ListingScope.Subtree, "", GroupInventoryScope.All,
            GroupInventoryKind.All, false, GroupInventorySort.Name);
        var all = reader.ReadGroupInventory(query, null);
        Assert.True(all.Groups.Single(group => group.DistinguishedName == A).HasCycle);
        Assert.Null(all.Groups.Single(group => group.DistinguishedName == C).HasCycle);
        Assert.Contains("incomplete", all.CycleQualification);
        var cycles = reader.ReadGroupInventory(query with { CyclesOnly = true }, null);
        Assert.Equal(new[] { A, B }, cycles.Groups.Select(group => group.DistinguishedName));
    }

    [Fact]
    public void Sec052DisjointMultiGroupCyclesProduceIndependentFindings()
    {
        using var reader = Open(Prepared("disjoint"));
        var findings = reader.Read().Findings;
        Assert.Equal(2, findings.Count);
        var components = findings.Select(finding => Assert.IsType<CircularMembershipEvidence>(finding.Evidence)).ToArray();
        Assert.All(components, component => Assert.Equal(2, component.Groups.Count));
        Assert.Equal(4, components.SelectMany(component => component.Groups).Select(group => group.ObjectGuid).Distinct().Count());
        Assert.Equal(2, findings.Select(finding => finding.Subject.Key).Distinct().Count());
    }

    [Fact]
    public void Sec052RepeatedBuiltinSidsInDifferentDomainsRemainDifferentCycles()
    {
        using var reader = Open(Prepared("scoped-builtins"));
        var findings = reader.Read().Findings;
        Assert.Equal(2, findings.Count);
        var groups = findings.Select(finding => Assert.Single(Assert.IsType<CircularMembershipEvidence>(finding.Evidence).Groups)).ToArray();
        Assert.All(groups, group => Assert.Equal("S-1-5-32-544", group.Sid));
        Assert.Equal(new[] { "child.contoso.com", "contoso.com" }, groups.Select(group => group.SidScope).Order(StringComparer.Ordinal));
        Assert.Equal(2, findings.Select(finding => finding.Subject.Key).Distinct().Count());
    }

    [Fact]
    public void Sec052EveryInvolvedGroupCanReadTheSameSingleFinding()
    {
        using var reader = Open(Prepared("pair"));
        var finding = Assert.Single(reader.Read().Findings);
        foreach (var dn in new[] { A, B })
        {
            var page = reader.ReadPage(FindingsQuery.About(dn));
            Assert.True(page.IsSuccess, page.Error?.Description);
            Assert.Equal(finding.Subject, Assert.Single(page.Value.Findings).Subject);
            Assert.False(page.Value.HasMore);
            var container = reader.ReadPage(FindingsQuery.Everything() with { Container = dn });
            Assert.True(container.IsSuccess, container.Error?.Description);
            Assert.Equal(finding.Subject, Assert.Single(container.Value.Findings).Subject);
        }
        Assert.Empty(reader.ReadPage(FindingsQuery.About(C)).Value.Findings);
    }

    [Fact]
    public void Sec052CrossDomainFiltersMustMatchTheSameInvolvedGroup()
    {
        using var reader = Open(Prepared("cross-domain"));
        var finding = Assert.Single(reader.Read().Findings);
        foreach (var domain in new[] { "contoso.com", "child.contoso.com" })
            Assert.Equal(finding.Subject, Assert.Single(reader.ReadPage(FindingsQuery.Everything() with
                { DomainFqdn = domain }).Value.Findings).Subject);
        Assert.Empty(reader.ReadPage(FindingsQuery.About(A) with { DomainFqdn = "child.contoso.com" }).Value.Findings);
        Assert.Equal(2, Assert.IsType<CircularMembershipEvidence>(finding.Evidence).Groups.Count);
    }

    [Fact]
    public void Sec052PublicationRefusesMissingGroupFilterReferences()
    {
        var directory = Prepared("pair");
        using var reader = Open(directory);
        var copyDirectory = TestSealing.CopyJudgement(directory, reader.Description.GenerationId, "cycle-filter-check");
        var copy = BundleLayout.AnalysisGenerationDataPath(copyDirectory, AnalysisStoreKind.Judgement, reader.Description.GenerationId);
        using var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = copy, Pooling = false }.ToString());
        connection.Open();
        TestSealing.AttachJudgementParts(connection, copyDirectory, reader.Description.GenerationId);
        CircularMembershipStorage.RequirePublishable(connection);
        using var command = connection.CreateCommand();
        command.CommandText = "DELETE FROM finding_circular_group WHERE distinguished_name=$dn";
        command.Parameters.AddWithValue("$dn", B);
        Assert.Equal(1, command.ExecuteNonQuery());
        Assert.Throws<InvalidDataException>(() => CircularMembershipStorage.RequirePublishable(connection));
    }

    [Fact]
    public void Sec052OriginalMemberValuesAndGenerationSurviveSavedPaging()
    {
        var directory = Prepared("both-sources");
        CircularMembershipEvidence evidence;
        using (var reader = Open(directory))
        {
            var finding = Assert.Single(reader.Read().Findings);
            evidence = Assert.IsType<CircularMembershipEvidence>(finding.Evidence);
            Assert.Equal(reader.Description.EvidenceSeal, evidence.EvidenceSeal);
            Assert.Equal(reader.Description.DerivationGenerationId, evidence.DerivationGenerationId);
            using var bundle = BundleReader.Open(directory).Value!;
            foreach (var link in evidence.Links)
                foreach (var witness in link.Witnesses)
                {
                    var group = evidence.Groups.Single(group => group.ObjectGuid == witness.SourceObjectGuid);
                    Assert.Contains(bundle.ReadObjectAttributes(group.DistinguishedName)!.Find(witness.Attribute)!.Values,
                        value => value.Ordinal == witness.Ordinal && value.Text == witness.Value);
                }
            Assert.All(evidence.Links, link => Assert.Equal(2, link.Witnesses.Count));
            var row = new FindingRowViewModel(finding);
            Assert.False(row.HasTier0Routes);
        }
        using var passive = Open(directory);
        var before = Snapshot(directory);
        var page = passive.ReadPage(FindingsQuery.Everything());
        Assert.True(page.IsSuccess);
        Assert.Equal(evidence.ComponentKey, Assert.Single(page.Value.Findings).Subject.Key);
        Assert.Equal(before, Snapshot(directory));
    }

    [Fact]
    public void Sec052MissingConsumedDerivationIsRefused()
    {
        var directory = Prepared("pair");
        var manifest = AnalysisStoreLifecycle.ManifestPath(directory, AnalysisStoreKind.Derivation);
        File.Move(manifest, manifest + ".retained");
        var opened = JudgementReader.Open(directory);
        Assert.False(opened.IsSuccess);
        Assert.Contains("Derivation generation", opened.Error.Description);
    }

    [Theory]
    [InlineData("unresolved")]
    [InlineData("missing-guid")]
    public void Sec052IncompleteCaptureCannotClaimNoCycles(string variant)
    {
        using var reader = Open(Prepared(variant));
        Assert.Empty(reader.Read().Findings);
        var execution = Assert.Single(reader.ReadRuleExecutions().Executions);
        Assert.Equal(RuleExecutionOutcome.Indeterminate, execution.Outcome);
    }

    [Fact]
    public void Sec052KnownCyclesSurviveIncompleteInventoryWithAnExplicitLimit()
    {
        using var reader = Open(Prepared("partial-input"));
        var evidence = Assert.IsType<CircularMembershipEvidence>(Assert.Single(reader.Read().Findings).Evidence);
        Assert.False(evidence.InventoryComplete);
        Assert.Equal(2, evidence.Groups.Count);
        Assert.Equal(RuleExecutionOutcome.Indeterminate, Assert.Single(reader.ReadRuleExecutions().Executions).Outcome);
    }

    [Fact]
    public void Sec052MissingDerivationIsRefusedInsteadOfFindingNothing()
    {
        var directory = Capture("pair");
        var result = Judge(directory);
        Assert.False(result.IsSuccess);
        Assert.Contains("DerivationUnavailable", result.Error.Code);
    }

    [Fact]
    public void Sec052DerivationVersionDistinguishesTheCorrectedSelfLoopInventory()
    {
        var directory = Capture("self");
        Derive(directory);
        using var reader = DerivationReader.Open(directory).Value!;
        Assert.Equal(17, reader.Description.SchemaVersion);
        Assert.Single(Assert.Single(reader.Read().NestingCycles.Cycles!));
    }

    [Theory]
    [InlineData("Missing")]
    [InlineData("Failed")]
    [InlineData("DidNotRun")]
    public void Sec052UnavailableCyclePhaseIsRefusedBeforeObjectsAreJudged(string state)
    {
        var directory = Capture("pair");
        var seal = BundleSealing.ReadSeal(BundleLayout.SealPath(directory))!.Hash;
        using (var writer = DerivationWriter.Create(directory, seal, Started))
        {
            writer.WriteSids([], []);
            if (state != "Missing")
                writer.RecordPhase("ExpansionPhase", Enum.Parse<DerivationPhaseOutcome>(state),
                    state == "Failed" ? "Synthetic phase failure" : null);
            writer.RecordCompleteness(new(false, [], [], [], writer.GenerationId, ExpansionLimit.None));
            writer.Complete(Started.AddMinutes(1));
        }
        var result = Judge(directory);
        Assert.False(result.IsSuccess);
        Assert.Contains("DerivedFactsAbsent", result.Error.Code);
        Assert.Contains(state, result.Error.Description);
    }

    [Fact]
    public void Sec052PartialCycleProductRetainsPositiveEvidenceAndMarksTheInventoryIncomplete()
    {
        var directory = Capture("pair");
        Derive(directory);
        using var reader = DerivationReader.Open(directory).Value!;
        var facts = reader.Read();
        var partial = facts with { NestingCycles = facts.NestingCycles with { Availability = NestingCycleAvailability.Partial } };
        var index = CircularMembershipIndex.Create(partial, reader.ReadMembershipInput(), reader.ReadNestingCycleIdentities().Value,
            reader.Description.EvidenceSeal, CancellationToken.None);
        Assert.False(index.IsComplete);
        Assert.False(Assert.Single(index.Findings.Values).InventoryComplete);
    }

    [Fact]
    public void Sec052IncompleteInventoryWithNoCapturedGroupsIsNotReportedAsClean()
    {
        var directory = Capture("empty-partial");
        Derive(directory);
        var result = Judge(directory);
        Assert.False(result.IsSuccess);
        Assert.Contains("DerivedFactsAbsent", result.Error.Code);
        Assert.Contains("contains no captured groups", result.Error.Description);
    }

    [Fact]
    public void Sec052ContextWithoutCycleEvidenceCannotReturnAnEmptyVerdict()
    {
        var directory = Capture("pair");
        using var reader = BundleReader.Open(directory).Value!;
        var subject = reader.ReadObjectAttributes(A)!;
        Assert.Throws<InvalidOperationException>(() => Rule.Judge(subject));
        var result = Rule.Judge(subject, JudgingContext.At(Started));
        Assert.False(result.IsComplete);
        Assert.Equal(new UnresolvedInput(DerivedFactKind.NestingCycles, UnresolvedReason.NotDerived), Assert.Single(result.Unresolved));
    }

    [Fact]
    public void Sec052StoredComponentWithoutOriginalMembershipWitnessesIsNotAValidFinding()
    {
        var directory = Capture("pair");
        Derive(directory);
        using var reader = DerivationReader.Open(directory).Value!;
        var input = reader.ReadMembershipInput();
        var missing = input with { Objects = input.Objects.Select(source => source with
            { Attributes = source.Attributes.Where(attribute => attribute.LdapDisplayName is not ("member" or "memberOf")).ToArray() }).ToArray() };
        var index = CircularMembershipIndex.Create(reader.Read(), missing, reader.ReadNestingCycleIdentities().Value,
            reader.Description.EvidenceSeal, CancellationToken.None);
        Assert.False(index.IsComplete);
        Assert.Empty(index.Findings);
    }

    [Fact]
    public void Sec052SourceGenerationMismatchAndCancellationAreRefused()
    {
        var directory = Capture("pair");
        Derive(directory);
        using var reader = DerivationReader.Open(directory).Value!;
        var input = reader.ReadMembershipInput();
        Assert.Throws<InvalidDataException>(() => CircularMembershipIndex.Create(reader.Read(),
            input with { DerivationGenerationId = Guid.NewGuid() }, reader.ReadNestingCycleIdentities().Value,
            reader.Description.EvidenceSeal, CancellationToken.None));
        using var stopping = new CancellationTokenSource();
        stopping.Cancel();
        Assert.ThrowsAny<OperationCanceledException>(() => CircularMembershipIndex.Create(reader.Read(), input,
            reader.ReadNestingCycleIdentities().Value, reader.Description.EvidenceSeal, stopping.Token));
    }

    [Fact]
    public void Sec052CancelledJudgingKeepsThePublishedCycleFinding()
    {
        var directory = Prepared("pair");
        Guid generation;
        string key;
        using (var reader = Open(directory))
        {
            generation = reader.Description.GenerationId;
            key = Assert.Single(reader.Read().Findings).Subject.Key;
        }
        using var stopping = new CancellationTokenSource();
        Assert.ThrowsAny<OperationCanceledException>(() => JudgingRun.Judge(directory, [Rule], Started, Started,
            new StopPublication(stopping), RunLog.Discarded, stopping.Token));
        using var after = Open(directory);
        Assert.Equal(generation, after.Description.GenerationId);
        Assert.Equal(key, Assert.Single(after.Read().Findings).Subject.Key);
    }

    private sealed class StopPublication(CancellationTokenSource stopping) : IProgress<JudgingRun.JudgingProgress>
    {
        public void Report(JudgingRun.JudgingProgress value)
        {
            if (value.Phase == JudgingPhase.PublishingJudgement) stopping.Cancel();
        }
    }

    [Theory]
    [InlineData("shell")]
    [InlineData("cli-offline")]
    [InlineData("cli-capture")]
    public async Task Sec052OrdinaryHostsScheduleTheRule(string host)
    {
        var directory = Capture("self");
        await OwnAccountMembershipPathTests.RunCoverageHostAsync(host, directory, PathRequesterPolicy.SupportedCapturedQuestions);
        using var reader = Open(directory);
        Assert.Single(reader.Read().Findings, finding => finding.RuleId == "SEC-052");
        Assert.Contains(reader.ReadRuleExecutions().Executions, rule => rule.RuleId == "SEC-052");
        Assert.Equal(CircularGroupMembership.Guidance, RuleGuidanceCatalogue.All.Single(rule => rule.RuleId == "SEC-052").WhatToDo);
    }

    [Theory]
    [InlineData("$.EvidenceSeal", "'changed'")]
    [InlineData("$.ComponentKey", "'wrong'")]
    [InlineData("$.Groups[0].DistinguishedName", "'CN=Wrong,DC=contoso,DC=com'")]
    [InlineData("$.Links[0].Witnesses[0].Ordinal", "-1")]
    [InlineData("$.Links[0].Witnesses[0].Value", "'CN=Wrong,DC=contoso,DC=com'")]
    [InlineData("$.DerivationGenerationId", "'11111111-1111-1111-1111-111111111111'")]
    public void Sec052SavedReadRefusesChangedEvidenceEvenWithARefreshedHash(string path, string value)
    {
        var directory = Prepared("pair");
        SelfMembershipCoverageTests.Mutate(directory, connection =>
        {
            using var command = connection.CreateCommand();
            command.CommandText = $"UPDATE finding_circular_membership SET proof=json_set(proof,$path,{value})";
            command.Parameters.AddWithValue("$path", path);
            command.ExecuteNonQuery();
            command.CommandText = "SELECT generation,proof FROM finding_circular_membership";
            string generation;
            string json;
            using (var read = command.ExecuteReader())
            {
                Assert.True(read.Read());
                generation = read.GetString(0);
                json = read.GetString(1);
            }
            command.Parameters.Clear();
            command.CommandText = "UPDATE finding_circular_membership SET fingerprint=$hash";
            command.Parameters.AddWithValue("$hash", OwnershipAuditStorage.Hash(generation + "\0" + json));
            command.ExecuteNonQuery();
        });
        using var reader = Open(directory);
        Assert.Throws<InvalidDataException>(() => reader.Read());
    }

    [Fact]
    public void Sec052ComponentIdentityDoesNotDependOnCaptureOrder()
    {
        using var first = Open(Prepared("overlap"));
        using var second = Open(Prepared("overlap", reverse: true));
        var one = Assert.Single(first.Read().Findings);
        var two = Assert.Single(second.Read().Findings);
        Assert.Equal((one.Subject, one.ObjectGuid, one.Detail), (two.Subject, two.ObjectGuid, two.Detail));
    }

    [Fact]
    public void Sec052StoredSetOrderDoesNotChooseTheFindingAnchor()
    {
        var directory = Capture("overlap");
        Derive(directory);
        using var reader = DerivationReader.Open(directory).Value!;
        var facts = reader.Read();
        var input = reader.ReadMembershipInput();
        var identities = reader.ReadNestingCycleIdentities().Value;
        var first = CircularMembershipIndex.Create(facts, input, identities, reader.Description.EvidenceSeal, CancellationToken.None);
        var reordered = facts with { NestingCycles = facts.NestingCycles with
            { Cycles = facts.NestingCycles.Cycles!.Select(component => (IReadOnlyList<int>)component.Reverse().ToArray()).ToArray() } };
        var second = CircularMembershipIndex.Create(reordered, input, identities, reader.Description.EvidenceSeal, CancellationToken.None);
        Assert.Equal(Assert.Single(first.Findings.Keys), Assert.Single(second.Findings.Keys));
        Assert.Equal(Tier0PathCalculation.Fingerprint(Assert.Single(first.Findings.Values)),
            Tier0PathCalculation.Fingerprint(Assert.Single(second.Findings.Values)));
    }

    [Fact]
    public void Sec052ApprovedGuidanceDoesNotPromiseOneLinkOrTier0Reachability()
    {
        var guidance = RuleGuidanceCatalogue.All.Single(value => value.RuleId == "SEC-052");
        Assert.Contains("this finding does not establish a route to Tier 0", guidance.WhyItMatters);
        Assert.Equal("Remove unintended nesting links after reviewing their impact. A set containing overlapping loops may require more than one link to be removed.",
            guidance.WhatToDo);
        Assert.DoesNotContain("token", guidance.WhyItMatters, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("infinite", guidance.WhyItMatters, StringComparison.OrdinalIgnoreCase);
    }

    private static string Prepared(string variant, bool reverse = false)
    {
        var directory = Capture(variant, reverse);
        Derive(directory);
        var result = Judge(directory);
        Assert.True(result.IsSuccess, result.Error?.Description);
        return directory;
    }

    [Theory]
    [InlineData("pair")]
    [InlineData("cross-domain")]
    public void Arch03LightweightCycleFiltersKeepTheSameInvolvedGroupWithoutProof(string variant)
    {
        var directory = Prepared(variant);
        var root = AnalysisStoreLifecycle.ResolveRoot(directory, AnalysisStoreKind.Judgement).Value;
        using var locked = new FileStream(Path.Combine(directory, root.Segment(StoreSegmentRole.PermissionProof).FileName),
            FileMode.Open, FileAccess.Read, FileShare.None);
        using var reader = Open(directory);
        var all = reader.ReadListPage(FindingsQuery.Everything()).Value;
        var subject = Assert.Single(all.Findings).Subject;
        if (variant == "pair")
            foreach (var dn in new[] { A, B })
            {
                Assert.Equal(subject, Assert.Single(reader.ReadListPage(FindingsQuery.About(dn)).Value.Findings).Subject);
                Assert.Equal(subject, Assert.Single(reader.ReadListPage(FindingsQuery.Everything() with { Container = dn }).Value.Findings).Subject);
            }
        else
        {
            foreach (var domain in new[] { "contoso.com", "child.contoso.com" })
                Assert.Equal(subject, Assert.Single(reader.ReadListPage(FindingsQuery.Everything() with { DomainFqdn = domain }).Value.Findings).Subject);
            Assert.Empty(reader.ReadListPage(FindingsQuery.About(A) with { DomainFqdn = "child.contoso.com" }).Value.Findings);
        }
        Assert.Empty(reader.ReadListPage(FindingsQuery.About(C)).Value.Findings);
    }

    private static Result<JudgementRunState> Judge(string directory) => JudgingRun.Judge(directory, [Rule],
        Started, Started, JudgingRun.NobodyIsWatching, RunLog.Discarded, CancellationToken.None);

    private static JudgementReader Open(string directory)
    {
        var opened = JudgementReader.Open(directory);
        Assert.True(opened.IsSuccess, opened.Error?.Description);
        return opened.Value;
    }

    private static string Capture(string variant, bool reverse = false)
    {
        var directory = TempDirectories.Create("sec052");
        using var writer = BundleWriter.Create(directory, Started);
        var roots = variant is "scoped-builtins" or "cross-domain" ? new[] { Root, "DC=child," + Root } : new[] { Root };
        foreach (var root in roots)
        {
            var domain = root == Root ? "contoso.com" : "child.contoso.com";
            var partition = new PartitionCoverage(root, NamingContextKind.Domain, "dc01." + domain,
                ConnectionSecurityLevel.SignedAndSealed, 1, 100, 1, [], false);
            writer.WriteCoverage(partition);
            Write(root, ["top", "domainDNS"], root == Root ? DomainSid : "S-1-5-21-4-5-6", [], false);
            if (variant == "scoped-builtins")
            {
                var dn = "CN=Administrators,CN=Builtin," + root;
                Write(dn, ["top", "group"], "S-1-5-32-544",
                    [Text("groupType", "-2147483643"), Values("member", [dn])], false);
            }
            else if (variant == "cross-domain")
            {
                var dn = root == Root ? A : "CN=Cycle B," + root;
                var other = root == Root ? "CN=Cycle B,DC=child," + Root : A;
                Write(dn, ["top", "group"], root == Root ? DomainSid + "-1100" : "S-1-5-21-4-5-6-1100",
                    [Text("groupType", "-2147483640"), Text("member", other)], false);
            }
            else if (variant != "empty-partial")
            {
                var definitions = new[] { A, B, C, D };
                if (reverse) Array.Reverse(definitions);
                foreach (var dn in definitions)
                {
                    string[] members = variant switch
                    {
                        "self" => dn == A ? [A] : [],
                        "unresolved" => dn == A ? ["CN=Missing," + Root] : [],
                        "acyclic" => dn == A ? [B] : [],
                        "member-of" => [],
                        "overlap" => dn == A ? [B] : dn == B ? [A, C] : [B],
                        "disjoint" => dn == A ? [B] : dn == B ? [A] : dn == C ? [D] : [C],
                        _ => dn == A ? [B] : dn == B ? [A] : [],
                    };
                    if (variant == "partial-input" && dn == C) members = ["CN=Missing," + Root];
                    string[] memberOf = variant is "member-of" or "both-sources" ? dn == A ? [B] : dn == B ? [A] : [] : [];
                    var sid = DomainSid + (variant == "privileged" && dn == A ? "-512"
                        : dn == A ? "-1100" : dn == B ? "-1200" : dn == C ? "-1300" : "-1400");
                    Write(dn, ["top", "group"], sid,
                        [Text("groupType", variant == "distribution" ? "2" : "-2147483646"), Values("member", members), Values("memberOf", memberOf)],
                        variant == "missing-guid" && dn == B);
                }
            }

            void Write(string dn, string[] classes, string sid, EvidenceAttribute[] extra, bool missingGuid)
            {
                var guid = new Guid(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(dn)).AsSpan(0, 16));
                writer.WriteObject(new(partition, dn, missingGuid ? null : guid,
                    [Values("objectClass", classes), new("objectSid", StoredAttributeCompleteness.Complete,
                        [EvidenceValue.OfBytes(Sid.ToBytes(sid)!)]), .. extra], Started));
            }
        }
        var domains = variant == "empty-partial" ? new[] { "contoso.com", "child.contoso.com" }
            : roots.Select(root => root == Root ? "contoso.com" : "child.contoso.com").ToArray();
        writer.Complete(RunCoverage.Of(CoverageId.ForDomains("contoso.com", domains),
            domains.Select(domain => variant == "empty-partial" && domain == "child.contoso.com"
                ? DomainCoverage.Excluded(domain, ExclusionKind.ByChoice, "Synthetic unread domain") : DomainCoverage.Read(domain)).ToArray(),
            [ForestPartitionCoverage.Read("CN=Configuration," + Root, NamingContextKind.Configuration),
                ForestPartitionCoverage.Read("CN=Schema,CN=Configuration," + Root, NamingContextKind.Schema)],
            SysvolCoverage.Of([])), Started.AddMinutes(1));
        return directory;
    }

    private static EvidenceAttribute Text(string name, string value) => Values(name, [value]);
    private static EvidenceAttribute Values(string name, string[] values) =>
        new(name, StoredAttributeCompleteness.Complete, values.Select(EvidenceValue.OfText).ToArray());
    private static string[] Snapshot(string directory) => Directory.GetFiles(directory, "*", SearchOption.AllDirectories)
        .Where(path => !path.EndsWith(".db-shm", StringComparison.Ordinal)
            && (!path.EndsWith(".db-wal", StringComparison.Ordinal) || new FileInfo(path).Length != 0))
        .Order(StringComparer.Ordinal).Select(path => path + ":" + Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)))).ToArray();
}
