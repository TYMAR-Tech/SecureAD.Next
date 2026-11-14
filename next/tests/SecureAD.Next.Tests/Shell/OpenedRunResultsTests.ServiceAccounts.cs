using System.Text.Json.Nodes;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Evidence.Run;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Kernel.Security;
using SecureAD.Next.Tests.Judgement;
using SecureAD.Shell.Services;
using Xunit;
using Fixtures = SecureAD.Next.Tests.Judgement.ServiceAccountRuleTests;
using static SecureAD.Next.Tests.Judgement.SelfMembershipDiscoveryTests;

namespace SecureAD.Next.Tests.Shell;

public sealed partial class OpenedRunResultsTests
{
    [Theory]
    [InlineData("SEC-100", false)]
    [InlineData("SEC-100", true)]
    [InlineData("SEC-101", false)]
    [InlineData("SEC-101", true)]
    public void ServiceAccountReadsSelectedOriginalFactsAndRequestedPagesWithoutOtherProducts(string rule, bool partial)
    {
        var directory = ServiceDetailsRun(rule, partial: partial);
        Finding original;
        using (var reader = JudgementReader.Open(directory).Value) original = Assert.Single(reader.Read().Findings);
        var evidence = Assert.IsType<ServiceAccountFindingEvidence>(original.Evidence);
        var before = CoverageFiles(directory);
        using var source = new BundleAssetSource();
        using var counts = new FindingsVerificationCounts(directory);
        using (var locks = new FindingsHeavyLocks(directory, permissionHeaders: true))
        {
            var selected = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings);
            Assert.Equal(0L, counts.Heavy);
            Assert.Equal(SavedServiceAccountContext.Statement(rule), selected.Detail);
            var reference = selected.Reference!.Value;
            var answer = source.ReadServiceAccount(directory, reference);
            Assert.True(answer.IsSuccess, answer.Error?.Description);
            Assert.True(answer.Value.Matches(selected));
            var context = answer.Value.Context;
            Assert.Equal(evidence.Account.UserAccountControl, context.Account.UserAccountControl);
            Assert.Equal(evidence.Account.CapturedUtc, context.Account.CapturedUtc);
            Assert.Equal(evidence.Account.Completeness, context.Account.Coverage);
            Assert.Equal(evidence.Account.Kind, context.Account.Kind);
            Assert.Equal(evidence.IsComplete, context.IsComplete);
            var names = AllServiceRows(after => source.ReadServiceAccountNames(directory, reference, after));
            Assert.Equal(evidence.Account.ServicePrincipalNames.Select(value => (value.Ordinal, value.Text, value.Bytes is not null)),
                names.Select(value => (value.OriginalOrdinal, value.Text, value.HasBinary)));
            Assert.EndsWith(":8443/instance", names[^1].Text, StringComparison.Ordinal);
            Assert.True(names[^1].Text!.Length > 100_000);
            if (rule == "SEC-100")
            {
                var membership = evidence.AdministrativeMembership!;
                Assert.Equal(membership.AccountGuid, context.SourceIdentity!.ObjectGuid);
                Assert.Equal(membership.TargetGuid, context.Target!.ObjectGuid);
                Assert.Equal(membership.RouteIncompleteReasons, context.RouteIncompleteReasons);
                Assert.Equal(membership.InputsComplete, context.InputsComplete);
                var entries = AllServiceRows(after => source.ReadServiceAccountEntryMemberships(directory, reference, after));
                Assert.Equal(57, entries.Count);
                Assert.All(entries, link => Assert.Equal(context.Account.ObjectGuid, link.Member.ObjectGuid));
                var links = AllServiceRows(after => source.ReadServiceAccountLinks(directory, reference, after));
                Assert.Equal(membership.Links.Select(value => (value.GroupGuid, value.MemberGuid, value.MemberReferenceGuid, (long)value.Witnesses.Count)),
                    links.Select(value => (value.ContainingGroup.ObjectGuid, value.Member.ObjectGuid, value.RecordedThrough.ObjectGuid, value.WitnessCount)));
                var selectedLink = Assert.Single(links, link => link.WitnessCount > 50);
                var values = AllServiceRows(after => source.ReadServiceAccountValues(directory, reference, selectedLink.Position, after));
                Assert.Equal(membership.Links[(int)selectedLink.Position].Witnesses.Select(value => (value.SourceObjectGuid, value.Attribute, value.Ordinal, value.Value)),
                    values.Select(value => (value.Source.ObjectGuid, value.Attribute, value.OriginalOrdinal, value.Value)));
                var limits = AllServiceRows(after => source.ReadServiceAccountLimitations(directory, reference, after));
                Assert.Equal(membership.Limitations, limits);
                if (partial) Assert.True(limits.Count > 50);
            }
            else
            {
                Assert.Null(answer.Value.EntryMemberships); Assert.Null(context.Target); Assert.Null(context.SourceIdentity);
                Assert.False(source.ReadServiceAccountEntryMemberships(directory, reference, null).IsSuccess);
                Assert.False(source.ReadServiceAccountLinks(directory, reference, null).IsSuccess);
                Assert.False(source.ReadServiceAccountValues(directory, reference, 0, null).IsSuccess);
                Assert.False(source.ReadServiceAccountLimitations(directory, reference, null).IsSuccess);
            }
            Assert.Equal((1L, 0L, 0L, 0L, 0L), (counts.Count("permission"), counts.Count("path"),
                counts.Count("facts"), counts.Count("evidence"), counts.Count("derivation")));
        }
        Assert.Equal(before, CoverageFiles(directory));
    }

    [Theory]
    [InlineData("msDS-ManagedServiceAccount")]
    [InlineData("msDS-GroupManagedServiceAccount")]
    public void ServiceAccountRetainsManagedClassAssociationWithoutInventingSpns(string kind)
    {
        var directory = ServiceDetailsRun("SEC-100", kind: kind, count: 1);
        using var source = new BundleAssetSource();
        var selected = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings);
        var details = source.ReadServiceAccount(directory, selected.Reference!.Value);
        Assert.True(details.IsSuccess, details.Error?.Description);
        Assert.Equal(kind, details.Value.Context.Account.ObjectClass);
        Assert.Equal(kind == "msDS-ManagedServiceAccount" ? ServiceAccountKind.StandaloneManagedServiceAccount
            : ServiceAccountKind.GroupManagedServiceAccount, details.Value.Context.Account.Kind);
        Assert.Empty(source.ReadServiceAccountNames(directory, selected.Reference.Value, null).Value.Rows);
        Assert.Single(details.Value.EntryMemberships!.Rows);
    }

    [Fact]
    public void ServiceAccountPrimaryGroupUsesItsOriginalAccountValueNotAnInventedMemberEntry()
    {
        var directory = ServiceDetailsRun("SEC-100", primary: true, count: 1);
        using var source = new BundleAssetSource();
        var reference = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings).Reference!.Value;
        var details = source.ReadServiceAccount(directory, reference).Value;
        var link = Assert.Single(details.EntryMemberships!.Rows).Value;
        Assert.True(link.IsPrimaryGroup);
        var value = Assert.Single(source.ReadServiceAccountValues(directory, reference, link.Position, null).Value.Rows).Value;
        Assert.Equal("primaryGroupID", value.Attribute); Assert.Equal("512", value.Value);
        Assert.Equal(details.Context.Account.ObjectGuid, value.Source.ObjectGuid);
        Assert.Equal(link.Member, link.RecordedThrough);
    }

    [Fact]
    public void ServiceAccountForeignReferenceRemainsSeparateFromTheResolvedAccountAndItsDomain()
    {
        var directory = ServiceDetailsRun("SEC-100", foreign: true, count: 1);
        using var source = new BundleAssetSource();
        var reference = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings).Reference!.Value;
        var details = source.ReadServiceAccount(directory, reference).Value;
        var link = Assert.Single(details.EntryMemberships!.Rows).Value;
        Assert.Equal("child.contoso.com", link.Member.DomainFqdn);
        Assert.Equal("contoso.com", link.RecordedThrough.DomainFqdn);
        Assert.Equal("foreignSecurityPrincipal", link.RecordedThrough.ObjectClass);
        Assert.NotEqual(link.Member.ObjectGuid, link.RecordedThrough.ObjectGuid);
        Assert.Equal(link.Member.Sid, link.RecordedThrough.Sid);
        Assert.Equal("contoso.com", details.Context.Target!.SidScope);
        var value = Assert.Single(source.ReadServiceAccountValues(directory, reference, link.Position, null).Value.Rows).Value;
        Assert.Equal(link.RecordedThrough.DistinguishedName, value.Value);
    }

    [Fact]
    public void ServiceAccountKeepsAnUnreadAccountStateAndUnreadableSpnsExplicitWithoutDroppingThePositive()
    {
        var directory = ServiceDetailsRun("SEC-100", count: 1, missingControl: true, unreadableNames: true);
        using var source = new BundleAssetSource();
        var reference = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings).Reference!.Value;
        var details = source.ReadServiceAccount(directory, reference).Value;
        Assert.Null(details.Context.Account.UserAccountControl);
        Assert.Contains("userAccountControl", details.Context.Account.MissingInputs, StringComparison.Ordinal);
        Assert.Contains("servicePrincipalName", details.Context.Account.MissingInputs, StringComparison.Ordinal);
        Assert.False(details.Context.IsComplete); Assert.Single(details.EntryMemberships!.Rows);
        var names = source.ReadServiceAccountNames(directory, reference, null).Value.Rows;
        Assert.Equal(3, names.Count); Assert.True(names[0].Value.IsReadable);
        Assert.False(names[1].Value.IsReadable); Assert.False(names[2].Value.IsReadable);
        Assert.Equal("   ", names[2].Value.Text); Assert.False(names[2].Value.HasBinary);
    }

    [Theory]
    [InlineData("generation")]
    [InlineData("finding")]
    [InlineData("account")]
    [InlineData("target")]
    [InlineData("kind")]
    [InlineData("offset")]
    [InlineData("beyond")]
    [InlineData("link")]
    public void ServiceAccountRefusesUnboundCrossLevelAndCrossRelationshipMarks(string defect)
    {
        var directory = ServiceDetailsRun("SEC-100");
        using var source = new BundleAssetSource();
        var reference = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings).Reference!.Value;
        var mark = source.ReadServiceAccountNames(directory, reference, null).Value.Next!.Value;
        mark = defect switch
        {
            "generation" => mark with { GenerationId = Guid.NewGuid() }, "finding" => mark with { FindingId = mark.FindingId + 1 },
            "account" => mark with { AccountGuid = Guid.NewGuid() }, "target" => mark with { TargetGuid = Guid.NewGuid() },
            "kind" => mark with { Kind = ServiceAccountPageKind.Links }, "offset" => mark with { Offset = 51 },
            "beyond" => mark with { Offset = 1000 }, _ => mark with { LinkPosition = 0 },
        };
        Assert.False(source.ReadServiceAccountNames(directory, reference, mark).IsSuccess);
    }

    [Theory]
    [InlineData("account")]
    [InlineData("class")]
    [InlineData("state")]
    [InlineData("target")]
    [InlineData("generation")]
    [InlineData("policy")]
    [InlineData("complete")]
    [InlineData("missing")]
    public void ServiceAccountRefusesMissingOrInconsistentSavedFacts(string defect)
    {
        var directory = ServiceDetailsRun("SEC-100", count: 1);
        ChangeCoverageProof(directory, defect switch
        {
            "account" => "UPDATE finding_service_account SET proof=json_set(proof,'$.Account.ObjectGuid','00000000-0000-0000-0000-000000000001')",
            "class" => "UPDATE finding_service_account SET proof=json_set(proof,'$.Account.ObjectClasses[#-1].Text','computer')",
            "state" => "UPDATE finding_service_account SET proof=json_set(proof,'$.Account.UserAccountControl',66050)",
            "target" => "UPDATE finding_service_account SET proof=json_set(proof,'$.AdministrativeMembership.TargetGuid','00000000-0000-0000-0000-000000000001')",
            "generation" => "UPDATE finding_service_account SET proof=json_set(proof,'$.AdministrativeMembership.DerivationGenerationId','00000000-0000-0000-0000-000000000001')",
            "policy" => "UPDATE finding_service_account SET proof=json_set(proof,'$.AdministrativeMembership.PolicyVersion',999)",
            "complete" => "UPDATE finding_service_account SET proof=json_set(proof,'$.IsComplete',json('false'))",
            _ => "DELETE FROM finding_service_account",
        });
        using var source = new BundleAssetSource();
        var reference = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings).Reference!.Value;
        var answer = source.ReadServiceAccount(directory, reference);
        Assert.False(answer.IsSuccess); Assert.Contains(SavedServiceAccountContext.InvalidDetails, answer.Error.Description, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("SEC-100")]
    [InlineData("SEC-101")]
    public void ServiceAccountRefusesAnotherGenerationBeforeReadingItsProof(string rule)
    {
        var directory = ServiceDetailsRun(rule, count: 1);
        using var source = new BundleAssetSource();
        using var locks = new FindingsHeavyLocks(directory);
        var reference = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings).Reference!.Value
            with { GenerationId = Guid.NewGuid() };
        var details = source.ReadServiceAccount(directory, reference);
        var names = source.ReadServiceAccountNames(directory, reference, null);
        Assert.False(details.IsSuccess); Assert.Equal("Evidence.FindingSelectionChanged", details.Error.Code);
        Assert.False(names.IsSuccess); Assert.Equal("Evidence.FindingSelectionChanged", names.Error.Code);
    }

    [Fact]
    public void ServiceAccountPasswordSettingCannotReportEnabledWhenBothSavedFlagRepresentationsLackTheOption()
    {
        var directory = ServiceDetailsRun("SEC-101", count: 1);
        ChangeCoverageProof(directory, """
            UPDATE finding_service_account SET proof=json_set(proof,
                '$.Account.UserAccountControl',512,
                '$.Account.AccountControl[0].Text','512',
                '$.Account.AccountControl[0].Stored','512')
            """);
        using var source = new BundleAssetSource();
        var reference = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings).Reference!.Value;
        var answer = source.ReadServiceAccount(directory, reference);
        Assert.False(answer.IsSuccess);
        Assert.Contains(SavedServiceAccountContext.InvalidDetails, answer.Error.Description, StringComparison.Ordinal);
    }

    private static IReadOnlyList<T> AllServiceRows<T>(Func<ServiceAccountMark?, Result<SavedServiceAccountPage<T>>> read)
    {
        var rows = new List<T>(); ServiceAccountMark? after = null;
        do
        {
            var answer = read(after); Assert.True(answer.IsSuccess, answer.Error?.Description);
            Assert.True(answer.Value.IsExpectedPage(after)); Assert.InRange(answer.Value.Rows.Count, 0, 50);
            rows.AddRange(answer.Value.Rows.Select(value => value.Value)); after = answer.Value.Next;
        } while (after is not null);
        return rows;
    }
    private static string ServiceDetailsRun(string rule, string kind = "user", int count = 57, bool partial = false,
        bool primary = false, bool foreign = false, bool missingControl = false, bool unreadableNames = false)
    {
        const string root = "DC=contoso,DC=com", domainSid = "S-1-5-21-1-2-3";
        var accountDn = "CN=Service," + (foreign ? "DC=child," : "") + root;
        var target = foreign ? "CN=Renamed administrators,CN=Builtin," + root : "CN=Renamed domain administration," + root;
        var bridges = Enumerable.Range(0, count).Select(index => "CN=Bridge " + index + "," + root).ToArray();
        var spns = kind == "user" ? Enumerable.Range(0, count).Select(index => "HTTP/service" + index + ".contoso.com:8443/instance").ToArray() : [];
        if (spns.Length > 50) spns[^1] = "HTTP/" + new string('x', 100_001) + ":8443/instance";
        var accountSid = (foreign ? "S-1-5-21-4-5-6" : domainSid) + "-1100";
        var account = Fixtures.Account(kind, spns, uac: 66048, primary: primary ? 512u : 513u, dn: accountDn, sid: accountSid, name: "Service");
        if (missingControl) account = account with { Attributes = account.Attributes.Where(value => value.LdapDisplayName != "userAccountControl").ToArray() };
        if (unreadableNames) account = Fixtures.With(account, "servicePrincipalName",
            [EvidenceValue.OfText("HTTP/service.contoso.com"), EvidenceValue.OfText(""), EvidenceValue.OfText("   ")]);
        var sources = new List<Fixtures.Source> { account };
        if (primary) sources.Add(Fixtures.Group(target, domainSid + "-512", -2147483646));
        else if (foreign)
        {
            var reference = "CN=Service reference,CN=ForeignSecurityPrincipals," + root;
            sources.Add(Fixtures.Group(target, "S-1-5-32-544", -2147483643, reference));
            sources.Add(new(reference, Fixtures.Id(reference),
                [new("objectClass", StoredAttributeCompleteness.Complete, [EvidenceValue.OfText("top"), EvidenceValue.OfText("foreignSecurityPrincipal")]),
                 new("objectSid", StoredAttributeCompleteness.Complete, [EvidenceValue.OfBytes(Sid.ToBytes(accountSid)!)]),
                 new("memberOf", StoredAttributeCompleteness.Complete, [])]));
        }
        else
        {
            var members = bridges.Concat(count > 50 ? Enumerable.Repeat(bridges[0], 56) : []).ToList();
            if (partial) members.AddRange(Enumerable.Range(0, 57).Select(index => "CN=Missing " + index + "," + root));
            sources.Add(Fixtures.Group(target, domainSid + "-512", -2147483646, members.ToArray()));
            sources.AddRange(bridges.Select((dn, index) => Fixtures.Group(dn, domainSid + "-" + (1200 + index), -2147483646, accountDn)));
        }
        var directory = Fixtures.Capture(sources, partial: partial);
        Derive(directory);
        var judged = JudgingRun.Judge(directory, [RuleCatalogue.All.Single(value => value.Definition.Id == rule)],
            Started, Started, JudgingRun.NobodyIsWatching, RunLog.Discarded, CancellationToken.None);
        Assert.True(judged.IsSuccess, judged.Error?.Description);
        if (partial && rule == "SEC-100") AddSavedServiceFixtureLimits(directory);
        return directory;
    }

    private static void AddSavedServiceFixtureLimits(string directory)
    {
        var root = FindingsPublication(directory);
        using (var connection = FindingsDatabase(Path.Combine(directory, root.Segment(StoreSegmentRole.PermissionProof).FileName)))
        {
            long id; string generation, text;
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT finding_id,generation,proof FROM finding_service_account";
            using (var row = command.ExecuteReader())
            {
                Assert.True(row.Read()); id = row.GetInt64(0); generation = row.GetString(1); text = row.GetString(2);
                Assert.False(row.Read());
            }
            var proof = Assert.IsType<JsonObject>(JsonNode.Parse(text));
            var membership = Assert.IsType<JsonObject>(proof["AdministrativeMembership"]);
            var limits = Assert.IsType<JsonArray>(membership["Limitations"]);
            // Exercise the saved reader independently of how many gaps the producer's inventory aggregates.
            for (var index = 0; index < 57; index++)
                limits.Add(new JsonObject
                {
                    ["DistinguishedName"] = "CN=Saved unresolved destination " + index + ",DC=contoso,DC=com",
                    ["Reason"] = nameof(AdministrativeMembershipReason.MemberUncaptured),
                });
            text = proof.ToJsonString(ProofSerialization.Options);
            command.CommandText = "UPDATE finding_service_account SET proof=$proof,fingerprint=$hash WHERE finding_id=$id";
            command.Parameters.AddWithValue("$proof", text);
            command.Parameters.AddWithValue("$hash", OwnershipAuditStorage.Hash(generation + "\0" + text));
            command.Parameters.AddWithValue("$id", id);
            Assert.Equal(1, command.ExecuteNonQuery());
            command.CommandText = "PRAGMA wal_checkpoint(TRUNCATE)"; command.Parameters.Clear(); command.ExecuteNonQuery();
        }
        TestSealing.ResealAnalysis(directory, new(AnalysisStoreKind.Judgement, root.GenerationId));
    }
}
