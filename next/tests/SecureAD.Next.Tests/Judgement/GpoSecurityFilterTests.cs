using System.Security.AccessControl;
using Microsoft.Data.Sqlite;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Judgement;
using SecureAD.Kernel.Security;
using Xunit;
using static SecureAD.Next.Tests.Judgement.GpoSecurityRun;

namespace SecureAD.Next.Tests.Judgement;

public sealed class GpoSecurityFilterTests
{
    [Theory]
    [InlineData(true, "Established")]
    [InlineData(false, "NotEstablished")]
    [InlineData(null, "Unknown")]
    public void GpoSecuritySharedRightPrimitiveDoesNotBypassTheRequesterQualifier(bool? matches, string expected)
    {
        var holder = new PermissionTrustee(ComputerSid, null, Computer, "example.test", null, null, null);
        var entry = new PermissionEntry(0, "AccessAllowed", holder, Apply, null, null,
            false, 0, 0, false, false, []);
        var source = new FullControlSource(Policy, PolicyGuid, null, "example.test", ["top", "groupPolicyContainer"],
            holder, "example.test", true, false, DescriptorAvailability.Read, DaclState.Present,
            DaclCompleteness.Complete, true, [entry]);
        var answer = FullControlEvaluator.AssessRequesterRight(source, Apply, _ => ControlEvaluationState.Established, _ => matches);
        Assert.Equal(expected, answer.State.ToString());
    }

    [Theory]
    [InlineData("authenticated", "Included", "Established", "Established")]
    [InlineData("direct-computer", "Included", "Established", "Established")]
    [InlineData("everyone", "Included", "Established", "Established")]
    [InlineData("read-only", "Excluded", "Established", "NotEstablished")]
    [InlineData("apply-only", "Excluded", "NotEstablished", "Established")]
    [InlineData("read-control-only", "Excluded", "NotEstablished", "Established")]
    [InlineData("read-property-only", "Excluded", "NotEstablished", "Established")]
    [InlineData("empty", "Excluded", "NotEstablished", "NotEstablished")]
    [InlineData("direct-deny", "Excluded", "Established", "NotEstablished")]
    [InlineData("allow-before-deny", "Included", "Established", "Established")]
    [InlineData("inherit-only", "Excluded", "Established", "NotEstablished")]
    [InlineData("inherited", "Included", "Established", "Established")]
    [InlineData("other-extended-right", "Excluded", "Established", "NotEstablished")]
    [InlineData("scoped-read", "Unresolved", "Unknown", "Established")]
    [InlineData("unknown-deny", "Unresolved", "Established", "Unknown")]
    [InlineData("unknown-allow", "Included", "Established", "Established")]
    [InlineData("conditional-grant", "Unresolved", "Established", "Unknown")]
    [InlineData("conditional-then-grant", "Included", "Established", "Established")]
    public void GpoSecurityEachQuestionKeepsReadApplyAndStoredOrderDistinct(string scenario, string decision, string read, string apply)
    {
        Entry[] reads = [new("S-1-5-11", GpoSecurityRun.Read)];
        Entry[] entries = scenario switch
        {
            "authenticated" => [.. reads, new("S-1-5-11", Apply, Scope: ApplyGuid)],
            "direct-computer" => [.. reads, new(ComputerSid, Apply, Scope: ApplyGuid)],
            "everyone" => [new("S-1-1-0", GpoSecurityRun.Read | Apply)],
            "read-only" => reads,
            "apply-only" => [new("S-1-5-11", Apply, Scope: ApplyGuid)],
            "read-control-only" => [new("S-1-5-11", 0x20000), new("S-1-5-11", Apply, Scope: ApplyGuid)],
            "read-property-only" => [new("S-1-5-11", 0x10), new("S-1-5-11", Apply, Scope: ApplyGuid)],
            "empty" => [],
            "direct-deny" => [new(ComputerSid, Apply, Deny: true), .. reads, new("S-1-5-11", Apply, Scope: ApplyGuid)],
            "allow-before-deny" => [new(ComputerSid, Apply), new("S-1-1-0", Apply, Deny: true), .. reads],
            "inherit-only" => [.. reads, new("S-1-5-11", Apply, Flags: AceFlags.InheritOnly)],
            "inherited" => [.. reads, new("S-1-5-11", Apply, Scope: ApplyGuid, Flags: AceFlags.Inherited)],
            "other-extended-right" => [.. reads, new("S-1-5-11", Apply, Scope: "00299570-246d-11d0-a768-00aa006e0529")],
            "scoped-read" => [new("S-1-5-11", 0x20000), new("S-1-5-11", 0x10, Scope: ApplyGuid), new("S-1-5-11", Apply, Scope: ApplyGuid)],
            "unknown-deny" => [new(ParentSid + "-9999", Apply, Deny: true), .. reads, new("S-1-5-11", Apply, Scope: ApplyGuid)],
            "unknown-allow" => [new(ParentSid + "-9999", Apply), .. reads, new("S-1-5-11", Apply, Scope: ApplyGuid)],
            "conditional-grant" => [.. reads, new(ComputerSid, Apply, Callback: true)],
            "conditional-then-grant" => [new(ComputerSid, Apply, Callback: true), .. reads, new("S-1-5-11", Apply, Scope: ApplyGuid)],
            _ => throw new ArgumentOutOfRangeException(nameof(scenario)),
        };
        var result = Assess(new Options { Entries = entries });
        Assert.Equal((decision, read, apply), (result.Decision.ToString(), result.Read.ToString(), result.ApplyGroupPolicy.State.ToString()));
        Assert.Equal(entries.Length, result.Permissions.Entries.Count);
        Assert.Equal(0x20000, result.ReadControl.Mask);
        Assert.Equal(0x10, result.ReadProperties.Mask);
        Assert.Equal(Apply, result.ApplyGroupPolicy.Mask);
        Assert.Equal(ApplyGuid, result.ApplyGroupPolicy.ObjectType);
    }

    [Theory]
    [InlineData("direct", "Included")]
    [InlineData("nested", "Included")]
    [InlineData("primary", "Included")]
    [InlineData("backlink", "Included")]
    [InlineData("distribution", "Unresolved")]
    [InlineData("cross-domain-global", "Unresolved")]
    [InlineData("resource-local", "Included")]
    [InlineData("outside-local", "Excluded")]
    [InlineData("universal", "Included")]
    public void GpoSecurityMembershipUsesQualifiedComputerAndResourceScope(string scenario, string expected)
    {
        var inner = new Group("Inner", 600, Global, false, [Computer], []);
        var outer = new Group("Outer", 601, Global, false, [inner.Dn], []);
        var group = scenario switch
        {
            "primary" => new Group("Primary computers", 515, Global, false, [], []),
            "distribution" => inner with { Type = 2 },
            "cross-domain-global" => inner with { ChildDomain = true },
            "resource-local" => inner with { Type = Local },
            "outside-local" => inner with { Type = Local, ChildDomain = true },
            "universal" => inner with { Type = Universal, ChildDomain = true },
            _ => inner,
        };
        var options = new Options
        {
            Groups = scenario == "nested" ? [inner, outer] : [scenario == "backlink" ? group with { Members = [] } : group],
            Backlinks = scenario == "backlink" ? [group.Dn] : [],
            Entries = [new("S-1-5-11", GpoSecurityRun.Read), new(scenario == "nested" ? outer.Sid : group.Sid, Apply, Scope: ApplyGuid)],
        };
        var result = Assess(options);
        Assert.Equal(expected, result.Decision.ToString());
        var trustee = Assert.Single(result.Trustees, value => value.Sid == (scenario == "nested" ? outer.Sid : group.Sid));
        if (expected == "Included")
        {
            Assert.True(trustee.Matches);
            Assert.NotEmpty(trustee.Route);
            Assert.Equal(ComputerGuid, trustee.Route[0].Member.ObjectGuid);
            Assert.Equal(result.CaptureGenerationId, trustee.Route[^1].Group.CaptureGenerationId);
            Assert.Equal(scenario == "nested" ? 2 : 1, trustee.Route.Length);
            if (scenario == "primary") Assert.Equal("primaryGroupID", trustee.Route[0].Attribute);
            if (scenario == "backlink") Assert.Equal("memberOf", trustee.Route[0].Attribute);
        }
        else Assert.NotEqual(true, trustee.Matches);
    }

    [Theory]
    [InlineData(false, "Included")]
    [InlineData(true, "Excluded")]
    public void GpoSecurityGroupHeldGrantAndDenyUseTheSameConcreteComputer(bool deny, string expected)
    {
        var group = new Group("Delegated", 600, Global, false, [Computer], []);
        Entry[] entries = deny
            ? [new(group.Sid, Apply, Deny: true), new("S-1-5-11", GpoSecurityRun.Read | Apply)]
            : [new("S-1-5-11", GpoSecurityRun.Read), new(group.Sid, Apply, Scope: ApplyGuid)];
        var result = Assess(new Options { Groups = [group], Entries = entries });
        Assert.Equal(expected, result.Decision.ToString());
        Assert.True(Assert.Single(result.Trustees, value => value.Sid == group.Sid).Matches);
    }

    [Theory]
    [InlineData("computer-class")]
    [InlineData("policy-class")]
    [InlineData("missing-sid")]
    [InlineData("unread-descriptor")]
    [InlineData("null-dacl")]
    [InlineData("short-dacl")]
    public void GpoSecurityUnqualifiedInputsDoNotBecomeExclusionsOrGrants(string gap)
    {
        var options = gap switch
        {
            "computer-class" => new Options { ComputerClass = "msDS-GroupManagedServiceAccount" },
            "policy-class" => new Options { PolicyClass = "container" },
            "missing-sid" => new Options { CapturedComputerSid = null },
            "unread-descriptor" => new Options { NoDescriptor = true },
            "null-dacl" => new Options { NullDacl = true },
            "short-dacl" => new Options { ShortDacl = true },
            _ => throw new ArgumentOutOfRangeException(nameof(gap)),
        };
        var result = Assess(options);
        Assert.Equal(GpoSecurityDecision.Unresolved, result.Decision);
        Assert.NotEmpty(result.Limitations);
    }

    [Fact]
    public void GpoSecurityDisabledStateDoesNotEraseConfiguredPermissions()
    {
        var result = Assess(new Options { AccountControl = 4098 });
        Assert.Equal(GpoSecurityDecision.Included, result.Decision);
        Assert.Equal("4098", result.ComputerValues.Find("userAccountControl")!.OnlyValue!.Text);
    }

    [Theory]
    [InlineData("user")]
    [InlineData("distribution-group")]
    public void GpoSecurityHistoricalIdentityDoesNotBecomeAProvenNonmatch(string currentHolder)
    {
        var historical = ParentSid + "-1800";
        var group = new Group("Historical carrier", 600, Global, false, [Computer], [historical]);
        var result = Assess(new Options
        {
            Groups = currentHolder == "user" ? [group] : [group, new("Current distribution identity", 1800, 2, false, [], [])],
            OtherUsers = currentHolder == "user" ? [historical] : [],
            Entries = [new(historical, Apply, Deny: true), new("S-1-5-11", GpoSecurityRun.Read | Apply)],
        });
        Assert.Equal(GpoSecurityDecision.Unresolved, result.Decision);
        Assert.Null(Assert.Single(result.Trustees, value => value.Sid == historical).Matches);
    }

    [Theory]
    [InlineData(515u)]
    [InlineData(600u)]
    public void GpoSecurityPrimaryGroupUsesItsCapturedRidRatherThanAClassDefault(uint rid)
    {
        var group = new Group("Selected primary", rid, Global, false, [], []);
        var result = Assess(new Options
        {
            PrimaryGroup = rid, Groups = [group],
            Entries = [new("S-1-5-11", GpoSecurityRun.Read), new(group.Sid, Apply, Scope: ApplyGuid)],
        });
        Assert.Equal(GpoSecurityDecision.Included, result.Decision);
        var proof = Assert.Single(result.Trustees, value => value.Sid == group.Sid);
        Assert.True(proof.Matches);
        Assert.Equal(rid.ToString(System.Globalization.CultureInfo.InvariantCulture), Assert.Single(proof.Route).Value);
    }

    [Fact]
    public void GpoSecurityMissingPrimaryGroupDoesNotBorrowDomainComputersFromTheClass()
    {
        var result = Assess(new Options
        {
            PrimaryGroup = null,
            Entries = [new("S-1-5-11", GpoSecurityRun.Read), new(ParentSid + "-515", Apply, Scope: ApplyGuid)],
        });
        Assert.Equal(GpoSecurityDecision.Unresolved, result.Decision);
        var trustee = Assert.Single(result.Trustees, value => value.Sid == ParentSid + "-515");
        Assert.Null(trustee.Matches);
        Assert.Contains("primary-group", trustee.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void GpoSecurityImplicitOwnerReadControlIsNotInventedOrDenied()
    {
        var result = Assess(new Options
        {
            Owner = ComputerSid,
            Entries = [new("S-1-5-11", 0x10 | Apply)],
        });
        Assert.Equal(ControlEvaluationState.Unknown, result.ReadControl.State);
        Assert.Equal(GpoSecurityDecision.Unresolved, result.Decision);
        Assert.Contains(result.Limitations, error => error.Code == "Evidence.GpoSecurityOwnerReadUnqualified");
    }

    [Fact]
    public void GpoSecurityMissingDerivationDoesNotEraseAnIndependentDirectAnswer()
    {
        var direct = Assess(new Options { Derive = false });
        Assert.Equal(GpoSecurityDecision.Included, direct.Decision);
        var group = new Group("Delegated", 600, Global, false, [Computer], []);
        var unresolved = Assess(new Options
        {
            Derive = false, Groups = [group],
            Entries = [new("S-1-5-11", GpoSecurityRun.Read), new(group.Sid, Apply)],
        });
        Assert.Equal(GpoSecurityDecision.Unresolved, unresolved.Decision);
        Assert.NotEmpty(unresolved.Limitations);
    }

    [Fact]
    public void GpoSecurityAbsentMembershipPreparationCanBeRetriedWithoutStaleFailure()
    {
        var group = new Group("Delegated", 600, Global, false, [Computer], []);
        var directory = Build(new Options
        {
            Derive = false, Groups = [group],
            Entries = [new("S-1-5-11", GpoSecurityRun.Read), new(group.Sid, Apply)],
        });
        using var reader = GpoSecurityFilterReader.Open(directory, CancellationToken.None).Value;
        var computer = reader.Bundle.ReadObjectIdentity(Computer)!;
        var policy = reader.Bundle.ReadObjectIdentity(Policy)!;
        Assert.Equal(GpoSecurityDecision.Unresolved, reader.Assess(computer, policy, CancellationToken.None).Decision);
        Derive(directory);
        Assert.Equal(GpoSecurityDecision.Included, reader.Assess(computer, policy, CancellationToken.None).Decision);
    }

    [Fact]
    public void GpoSecurityExactSourceLifetimeAndRequestCancellationArePreserved()
    {
        var group = new Group("Delegated", 600, Global, false, [Computer], []);
        var directory = Build(new Options { Groups = [group], Entries = [new("S-1-5-11", GpoSecurityRun.Read), new(group.Sid, Apply)] });
        var before = BundleSealing.HashFile(BundleLayout.EvidencePath(directory));
        using var reader = GpoSecurityFilterReader.Open(directory, CancellationToken.None).Value;
        var computer = reader.Bundle.ReadObjectIdentity(Computer)!;
        var policy = reader.Bundle.ReadObjectIdentity(Policy)!;
        using var request = new CancellationTokenSource();
        var first = reader.Assess(computer, policy, request.Token);
        Assert.Equal(GpoSecurityDecision.Included, first.Decision);
        request.Cancel();
        Assert.Throws<OperationCanceledException>(() => reader.Assess(computer, policy, request.Token));
        Assert.Equal(GpoSecurityDecision.Included, reader.Assess(computer, policy, CancellationToken.None).Decision);
        Assert.Equal(before, BundleSealing.HashFile(BundleLayout.EvidencePath(directory)));
        Assert.Equal(computer, first.Computer);
        Assert.Equal(policy, first.Policy);
        Assert.NotNull(first.DerivationGenerationId);
        Assert.Equal(64, first.EvidenceSeal.Length);
        Assert.Equal(first.CaptureGenerationId, first.Computer.CaptureGenerationId);
        Derive(directory);
        var changed = Assert.Throws<InvalidOperationException>(() => reader.Assess(computer, policy, CancellationToken.None));
        Assert.Contains("source generation", changed.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("computer")]
    [InlineData("policy")]
    public void GpoSecuritySelectionsCannotCrossTheirCapturedGeneration(string changed)
    {
        using var first = GpoSecurityFilterReader.Open(Build(new Options()), CancellationToken.None).Value;
        using var second = GpoSecurityFilterReader.Open(Build(new Options()), CancellationToken.None).Value;
        var computer = (changed == "computer" ? first : second).Bundle.ReadObjectIdentity(Computer)!;
        var policy = (changed == "policy" ? first : second).Bundle.ReadObjectIdentity(Policy)!;
        Assert.Throws<InvalidDataException>(() => second.Assess(computer, policy, CancellationToken.None));
    }

    [Fact]
    public void GpoSecurityPresentationHintsDoNotReplaceTheCapturedIdentity()
    {
        using var reader = GpoSecurityFilterReader.Open(Build(new Options()), CancellationToken.None).Value;
        var computer = reader.Bundle.ReadObjectIdentity(Computer)!;
        var policy = reader.Bundle.ReadObjectIdentity(Policy)!;
        var answer = reader.Assess(computer with { DomainFqdn = "wrong.test", ObjectClass = "user", PrincipalSid = ParentSid + "-9999" },
            policy with { DomainFqdn = "wrong.test", ObjectClass = "computer" }, CancellationToken.None);
        Assert.Equal(GpoSecurityDecision.Included, answer.Decision);
        Assert.Equal(computer, answer.Computer);
        Assert.Equal(policy, answer.Policy);
    }

    [Fact]
    public void GpoSecurityStoredGenericBitsAreNotExpandedIntoAnswers()
    {
        var directory = Build(new Options
        {
            Entries = [new("S-1-5-11", GpoSecurityRun.Read), new(ComputerSid, 0x10000000)],
        });
        using var reader = GpoSecurityFilterReader.Open(directory, CancellationToken.None).Value;
        var answer = reader.Assess(reader.Bundle.ReadObjectIdentity(Computer)!, reader.Bundle.ReadObjectIdentity(Policy)!, CancellationToken.None);
        Assert.Equal(0x10000000, answer.Permissions.Entries[1].AccessMask);
        Assert.Equal(GpoSecurityDecision.Unresolved, answer.Decision);
        Assert.Equal(ControlEvaluationState.Unknown, answer.ApplyGroupPolicy.State);
        Assert.Contains(answer.Limitations, error => error.Code == "Evidence.GpoSecurityStoredGenericRightsUnsupported");
    }

    [Theory]
    [InlineData("mask")]
    [InlineData("propagation")]
    public void GpoSecurityComparisonProjectionCannotReplaceTheStoredPermission(string changed)
    {
        var directory = Build(new Options { Derive = false });
        using (var connection = new SqliteConnection("Data Source=" + BundleLayout.EvidencePath(directory) + ";Pooling=False"))
        {
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = changed == "mask"
                ? "UPDATE access_entry SET access_mask=268435456 WHERE (access_mask & 256)<>0"
                : "UPDATE access_entry SET propagation_flags=64 WHERE (access_mask & 256)<>0";
            Assert.Equal(1, command.ExecuteNonQuery());
            command.CommandText = "PRAGMA wal_checkpoint(TRUNCATE)";
            command.ExecuteNonQuery();
        }
        TestSealing.ResealCapture(directory);
        Derive(directory);
        using var reader = GpoSecurityFilterReader.Open(directory, CancellationToken.None).Value;
        var answer = reader.Assess(reader.Bundle.ReadObjectIdentity(Computer)!, reader.Bundle.ReadObjectIdentity(Policy)!, CancellationToken.None);
        Assert.Equal(GpoSecurityDecision.Included, answer.Decision);
        Assert.Equal(ControlEvaluationState.Established, answer.ApplyGroupPolicy.State);
        Assert.Equal(Apply, answer.Permissions.Entries[1].AccessMask);
        Assert.Equal(0, answer.Permissions.Entries[1].PropagationFlags);
        Assert.Contains(1, answer.ApplyGroupPolicy.GrantOrdinals);
    }

    [Fact]
    public void GpoSecurityMembershipPreparationDoesNotReadUnrelatedProtectedPrincipalFacts()
    {
        var group = new Group("Delegated", 600, Global, false, [Computer], []);
        var directory = Build(new Options { Groups = [group], Entries = [new("S-1-5-11", GpoSecurityRun.Read), new(group.Sid, Apply)] });
        var root = AnalysisStoreLifecycle.ResolveRoot(directory, AnalysisStoreKind.Derivation).Value;
        using (var connection = new SqliteConnection("Data Source=" + Path.Combine(directory,
            root.Segment(StoreSegmentRole.Derivation).FileName) + ";Pooling=False"))
        {
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = "PRAGMA ignore_check_constraints=ON; UPDATE adminsd_derivation SET mask_outcome='not a known outcome'";
            Assert.Equal(1, command.ExecuteNonQuery());
            command.CommandText = "PRAGMA wal_checkpoint(TRUNCATE)";
            command.ExecuteNonQuery();
        }
        TestSealing.ResealAnalysis(directory, new(AnalysisStoreKind.Derivation, root.GenerationId));
        using var sources = JudgingInputs.Open(directory, CancellationToken.None).Value;
        Assert.True(sources.OpenMembershipDerivation().IsSuccess);
        Assert.False(sources.OpenDerivation().IsSuccess);
        using var reader = GpoSecurityFilterReader.Open(directory, CancellationToken.None).Value;
        var error = Record.Exception(() =>
        {
            var answer = reader.Assess(reader.Bundle.ReadObjectIdentity(Computer)!, reader.Bundle.ReadObjectIdentity(Policy)!, CancellationToken.None);
            Assert.Equal(GpoSecurityDecision.Included, answer.Decision);
        });
        Assert.Null(error);
    }

    [Theory]
    [InlineData(false, "Included")]
    [InlineData(true, "Unresolved")]
    public void GpoSecurityOwnerRightsRemainSeparateFromAnUnqualifiedImplicitOwnerBranch(bool deny, string expected)
    {
        var answer = Assess(new Options
        {
            Owner = ComputerSid,
            Entries = [new("S-1-3-4", 0x20000, Deny: deny), new("S-1-5-11", 0x10 | Apply)],
        });
        Assert.Equal(expected, answer.Decision.ToString());
        Assert.Equal(ControlEvaluationState.Established, answer.ApplyGroupPolicy.State);
        Assert.True(Assert.Single(answer.Trustees, value => value.Sid == "S-1-3-4").Matches);
    }

    private static GpoSecurityAssessment Assess(Options options)
    {
        using var reader = GpoSecurityFilterReader.Open(Build(options), CancellationToken.None).Value;
        return reader.Assess(reader.Bundle.ReadObjectIdentity(Computer)!, reader.Bundle.ReadObjectIdentity(Policy)!, CancellationToken.None);
    }
}
