using System.Buffers.Binary;
using System.Security.AccessControl;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using SecureAD.Kernel.Capture;
using SecureAD.Kernel.Security;
using Xunit;
using AceType = SecureAD.Kernel.Security.AceType;

namespace SecureAD.Next.Tests.Judgement;

public sealed class GmsaPasswordReaderTests
{
    internal const string Root = "DC=contoso,DC=com";
    internal const string Domain = "contoso.com";
    internal const string DomainSid = "S-1-5-21-1-2-3";
    internal const string AccountDn = "CN=svc-app," + Root;
    internal const string Holder = DomainSid + "-6000";
    internal const string Broad = "S-1-5-11";
    internal const string GmsaClass = "msDS-GroupManagedServiceAccount";
    internal static readonly Guid AccountGuid = Guid.Parse("00000000-0000-0000-0000-000000000102");
    internal static readonly Guid Generation = Guid.Parse("00000000-0000-0000-0000-000000000201");
    internal static readonly Guid DerivationGeneration = Guid.Parse("00000000-0000-0000-0000-000000000202");
    internal static readonly DateTimeOffset Captured = SelfMembershipDiscoveryTests.Started;
    internal static readonly string EvidenceSeal = new('a', 64);
    internal static readonly string DerivationSeal = new('b', 64);

    [Fact]
    public void MicrosoftManagedPasswordReadPropertyCheckUsesTheEmbeddedDescriptorAndOriginalOccurrences()
    {
        var bytes = Descriptor("O:SYG:SYD:(A;;RP;;;AU)(A;;RP;;;AU)");
        var verdict = new BroadGmsaPasswordReader().Judge(Account(bytes), Context());
        var finding = Assert.Single(verdict.Findings);
        var proof = Proof(finding);
        Assert.True(verdict.IsComplete);
        Assert.Equal(Severity.High, finding.Severity);
        Assert.Equal((AccountGuid, AccountDn, Domain, GmsaClass),
            (finding.ObjectGuid, finding.DistinguishedName, finding.DomainFqdn, finding.ObjectClass));
        Assert.Equal(bytes, proof.Source.Descriptor);
        Assert.Equal(new[] { 0, 1 }, proof.Source.Entries.Select(entry => entry.Ordinal));
        Assert.All(proof.Source.Entries, entry => Assert.Equal(0x10, entry.AccessMask));
        Assert.Equal(new[] { 0, 1 }, Assert.Single(proof.Grants).GrantOrdinals);
        Assert.Equal(Broad, proof.BroadSid);
        Assert.Equal(Captured, proof.Source.CapturedUtc);
        Assert.Equal(EvidenceSeal, proof.EvidenceSeal);
        Assert.Equal(DerivationSeal, proof.DerivationSeal);
        Assert.Equal(DerivationGeneration, proof.DerivationGenerationId);
        bytes[0] = 0xff;
        Assert.Equal(1, proof.Source.Descriptor[0]);
    }

    [Theory]
    [InlineData("CR")]
    [InlineData("WD")]
    [InlineData("WO")]
    [InlineData("WP")]
    [InlineData("GA")]
    public void OtherRightsAndStoredGenericBitsDoNotBecomePasswordReadPermission(string right)
    {
        var verdict = Assess($"O:SYG:SYD:(A;;{right};;;AU)");
        Assert.Empty(verdict.Findings);
        Assert.True(verdict.IsComplete);
    }

    [Theory]
    [InlineData("O:SYG:SYD:(D;;RP;;;AU)(A;;RP;;;AU)", 0)]
    [InlineData("O:SYG:SYD:(A;;RP;;;AU)(D;;RP;;;AU)", 1)]
    [InlineData("O:SYG:SYD:(D;;RP;;;WD)(A;;RP;;;AU)", 0)]
    public void MicrosoftOrderedAccessDoesNotSubtractLaterDenials(string descriptor, int expected)
    {
        var verdict = Assess(descriptor);
        Assert.True(verdict.IsComplete);
        Assert.Equal(expected, verdict.Findings.Count);
        if (expected != 0)
        {
            var proof = Proof(Assert.Single(verdict.Findings));
            Assert.False(proof.Source.DaclWasCanonical);
            Assert.Equal(new[] { AceType.AccessAllowed, AceType.AccessDenied }, proof.Source.Entries.Select(entry => entry.AceType));
        }
    }

    [Theory]
    [InlineData("A;IO;RP;;;AU", 0)]
    [InlineData("A;ID;RP;;;AU", 1)]
    public void InheritOnlyAndAlreadyInheritedOriginalEntriesRemainDifferent(string entry, int expected)
    {
        var verdict = Assess("O:SYG:SYD:(" + entry + ")");
        Assert.True(verdict.IsComplete);
        Assert.Equal(expected, verdict.Findings.Count);
        if (expected != 0) Assert.True(Assert.Single(Proof(Assert.Single(verdict.Findings)).Source.Entries).IsInherited);
    }

    [Theory]
    [InlineData("O:SYG:SY", 1, DaclState.Null)]
    [InlineData("O:SYG:SYD:", 0, DaclState.Empty)]
    public void MicrosoftNullAndEmptyDaclsNeverBecomeTheSameAnswer(string descriptor, int expected, DaclState state)
    {
        var verdict = Assess(descriptor);
        Assert.True(verdict.IsComplete);
        Assert.Equal(expected, verdict.Findings.Count);
        if (expected == 0) return;
        var proof = Proof(Assert.Single(verdict.Findings));
        Assert.Equal(state, proof.Source.DaclState);
        Assert.Empty(proof.Source.Entries);
        var grant = Assert.Single(proof.Grants);
        Assert.True(grant.HasNullDacl);
        Assert.Empty(grant.GrantOrdinals);
        Assert.Equal("S-1-1-0", proof.BroadSid);
    }

    [Theory]
    [InlineData("object-scope", UnresolvedReason.GmsaReaderScopeUnsupported)]
    [InlineData("callback", UnresolvedReason.GmsaReaderConditionalEntryUnsupported)]
    [InlineData("other-deny", UnresolvedReason.GmsaReaderDenialUnassessed)]
    public void UnsupportedScopeConditionsAndRequesterDenialsAreUnassessedNotHighFindings(string variant, UnresolvedReason reason)
    {
        var bytes = Descriptor(variant switch
        {
            "object-scope" => "O:SYG:SYD:(OA;;RP;aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee;;AU)",
            "other-deny" => $"O:SYG:SYD:(D;;RP;;;{Holder})(A;;RP;;;AU)",
            _ => "O:SYG:SYD:(A;;RP;;;AU)",
        });
        if (variant == "callback")
            bytes[BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(16, 4)) + 8] = 0x09;
        var verdict = new BroadGmsaPasswordReader().Judge(Account(bytes), Context());
        Assert.Empty(verdict.Findings);
        Assert.False(verdict.IsComplete);
        Assert.Contains(verdict.Unresolved, issue => issue.Reason == reason);
    }

    [Theory]
    [InlineData("missing", null)]
    [InlineData("zero", CapturedInputIssueKind.ZeroValue)]
    [InlineData("empty", CapturedInputIssueKind.UnusableValue)]
    [InlineData("text", CapturedInputIssueKind.UnsupportedRepresentation)]
    [InlineData("multiple", CapturedInputIssueKind.UnsupportedRepresentation)]
    [InlineData("ordinal", CapturedInputIssueKind.UnsupportedRepresentation)]
    [InlineData("malformed", CapturedInputIssueKind.IncompleteValue)]
    public void MissingMalformedAndUnsupportedCapturedValuesRemainDistinct(string variant, CapturedInputIssueKind? expected)
    {
        var attribute = new ObjectAttribute(GmsaPasswordReaders.Attribute, AttributeCardinality.SingleValued,
            [new(0, null, Descriptor("O:SYG:SYD:(A;;RP;;;AU)"))]);
        attribute = variant switch
        {
            "zero" => attribute with { Values = [] },
            "empty" => attribute with { Values = [new(0, null, [])] },
            "text" => attribute with { Values = [new(0, "not a binary descriptor", null)] },
            "multiple" => attribute with { Values = [.. attribute.Values, new(1, null, Descriptor("O:SYG:SYD:"))] },
            "ordinal" => attribute with { Values = [attribute.Values[0] with { Ordinal = 1 }] },
            "malformed" => attribute with { Values = [new(0, null, [1, 0, 0])] },
            _ => attribute,
        };
        var subject = Account(Descriptor("O:SYG:SYD:"));
        var attributes = subject.Attributes.Where(value => value.LdapDisplayName != GmsaPasswordReaders.Attribute).ToList();
        if (variant != "missing") attributes.Add(attribute);
        var verdict = new BroadGmsaPasswordReader().Judge(new(subject.DistinguishedName, subject.ObjectGuid,
            subject.CapturedUtc, subject.Completeness, attributes, subject.DomainFqdn), Context());
        Assert.Empty(verdict.Findings);
        Assert.False(verdict.IsComplete);
        if (expected is { } kind) Assert.Equal(kind, Assert.Single(verdict.InputIssues).Kind);
        else Assert.Equal(GmsaPasswordReaders.Attribute, Assert.Single(verdict.InputsNotCaptured));
    }

    [Theory]
    [InlineData("computer")]
    [InlineData("msDS-ManagedServiceAccount")]
    public void ThisRuleDoesNotAssessOtherAccountClasses(string kind)
    {
        var verdict = new BroadGmsaPasswordReader().Judge(Account(Descriptor("O:SYG:SYD:(A;;RP;;;AU)"), kind: kind), Context());
        Assert.True(verdict.IsComplete);
        Assert.Empty(verdict.Findings);
    }

    [Fact]
    public void MissingClassAndObjectGuidAreNotCleanGmsaAnswers()
    {
        var subject = Account(Descriptor("O:SYG:SYD:(A;;RP;;;AU)"));
        var noClass = new ObjectAttributes(subject.DistinguishedName, subject.ObjectGuid, subject.CapturedUtc,
            subject.Completeness, subject.Attributes.Where(value => value.LdapDisplayName != "objectClass").ToArray(), subject.DomainFqdn);
        Assert.Contains("objectClass", new BroadGmsaPasswordReader().Judge(noClass, Context()).InputsNotCaptured);
        Assert.Contains("objectGUID", new BroadGmsaPasswordReader().Judge(subject with { ObjectGuid = null }, Context()).InputsNotCaptured);
    }

    [Fact]
    public void NamedHostsAndLargePurposeBuiltGroupsAreNotUnexpectedMerelyForBeingNonAdministrative()
    {
        var verdict = Assess($"O:SYG:SYD:(A;;RP;;;{Holder})", (sid, _) =>
            new(sid, PrincipalExpansionOutcome.Expanded, Enumerable.Range(0, 500)
                .Select(index => new ExpandedPrincipal(DomainSid + "-" + (10000 + index), "", [sid, DomainSid + "-" + (10000 + index)], true)).ToArray()));
        Assert.True(verdict.IsComplete);
        Assert.Empty(verdict.Findings);
    }

    [Fact]
    public void IndependentGrantingGroupsAndOriginalDuplicatesDoNotMultiplyTheBroadIdentityFinding()
    {
        var finding = FindingWithHolders(2);
        var proof = Proof(finding);
        Assert.Equal(2, proof.Grants.Count);
        Assert.All(proof.Grants, grant => Assert.Equal(Broad, grant.MembershipPath[^1].Sid));
        Assert.All(proof.Grants, grant => Assert.False(grant.IsDirect));
        Assert.Equal(AccountGuid, finding.ObjectGuid);
        Assert.Equal(BroadPrincipalCanTakeOverObject.SubjectKeyFor(Broad), finding.Subject.Key);
        Assert.Equal(2, proof.Source.Entries.Count);
    }

    [Theory]
    [InlineData(PrincipalExpansionOutcome.ExpandedThroughUnknownGroupType, UnresolvedReason.GmsaReaderGroupTypeUnavailable, 0)]
    [InlineData(PrincipalExpansionOutcome.StoppedAtBudget, UnresolvedReason.MembershipProcessingLimit, 1)]
    [InlineData(PrincipalExpansionOutcome.ExpandedWithUnidentifiedMember, UnresolvedReason.MembershipIncomplete, 1)]
    [InlineData(PrincipalExpansionOutcome.PrincipalNotFound, UnresolvedReason.NotDerived, 0)]
    public void MembershipUncertaintyAndExistingProcessingLimitsDoNotBecomeSafeOrNewBudgets(
        PrincipalExpansionOutcome outcome, UnresolvedReason reason, int expected)
    {
        var verdict = Assess($"O:SYG:SYD:(A;;RP;;;{Holder})", (sid, _) =>
            new(sid, outcome, outcome == PrincipalExpansionOutcome.PrincipalNotFound ? null : [new(Broad, "", [sid, Broad], true)]));
        Assert.False(verdict.IsComplete);
        Assert.Equal(expected, verdict.Findings.Count);
        Assert.Contains(verdict.Unresolved, issue => issue.Reason == reason);
        if (expected != 0) Assert.False(Proof(Assert.Single(verdict.Findings)).IsComplete);
    }

    [Fact]
    public void UnassessedOtherHoldersDoNotEraseAnIndependentBroadGrant()
    {
        var verdict = Assess($"O:SYG:SYD:(A;;RP;;;AU)(A;;RP;;;{Holder})", (sid, _) =>
            new(sid, PrincipalExpansionOutcome.PrincipalNotFound, null));
        Assert.False(verdict.IsComplete);
        var proof = Proof(Assert.Single(verdict.Findings));
        Assert.Equal(Broad, proof.BroadSid);
        Assert.False(proof.IsComplete);
        Assert.NotEmpty(proof.Limitations);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void DisabledAccountsKeepThePermissionWithoutClaimingSuccessfulUse(bool disabled)
    {
        var finding = Assert.Single(Assess("O:SYG:SYD:(A;;RP;;;AU)", disabled: disabled).Findings);
        Assert.Equal(disabled, Proof(finding).Source.AccountIsDisabled);
        Assert.Equal(Severity.High, finding.Severity);
        Assert.Equal("SEC-102", Assert.Single(RuleCatalogue.All, rule => rule.Definition.Id == "SEC-102").Definition.Id);
        Assert.Equal(GmsaPasswordReaders.Title, RuleCatalogue.All.Single(rule => rule.Definition.Id == "SEC-102").Definition.Name);
        var guidance = RuleGuidanceCatalogue.For("SEC-102")!;
        Assert.Equal(GmsaPasswordReaders.Reference, guidance.MicrosoftReference);
        Assert.Contains("not an individual member's authorization", guidance.About, StringComparison.Ordinal);
        Assert.Contains("Check dependent services", guidance.WhatToDo, StringComparison.Ordinal);
        Assert.DoesNotContain(RuleCatalogue.All, rule => rule.Definition.Id == "SEC-083");
    }

    internal static RuleVerdict Assess(string sddl, Func<string, string, PrincipalExpansion>? expand = null,
        bool disabled = false, bool captureComplete = true) =>
        new BroadGmsaPasswordReader().Judge(Account(Descriptor(sddl), disabled: disabled), Context(expand, captureComplete));

    internal static Finding FindingWithHolders(int count, bool captureComplete = true)
    {
        var sddl = "O:SYG:SYD:" + string.Concat(Enumerable.Range(0, count).Select(index => $"(A;;RP;;;{DomainSid}-{6000 + index})"));
        return Assert.Single(Assess(sddl, (sid, _) => new(sid, PrincipalExpansionOutcome.Expanded,
            [new(Broad, "", [sid, Broad], true)]), captureComplete: captureComplete).Findings);
    }

    internal static GmsaPasswordReaderEvidence Proof(Finding finding) => Assert.IsType<GmsaPasswordReaderEvidence>(finding.Evidence);

    internal static JudgingContext Context(Func<string, string, PrincipalExpansion>? expand = null, bool captureComplete = true) =>
        JudgingContext.At(Captured) with
        {
            MembersOfPrincipal = expand ?? ((sid, _) => new(sid, PrincipalExpansionOutcome.Expanded, [])),
            PrincipalNames = sid => "Captured reader " + sid.Split('-')[^1],
            Permissions = _ => throw new InvalidOperationException("The ordinary object descriptor must not answer the password-reader question."),
            GmsaReaders = new(Generation, new(EvidenceSeal, DerivationGeneration, DerivationSeal, PrincipalClassificationRegistry.Version,
                2, 2, Root, "CN=Configuration," + Root), captureComplete, CancellationToken.None),
        };

    internal static ObjectAttributes Account(byte[] descriptor, bool disabled = false, string kind = GmsaClass) =>
        new(AccountDn, AccountGuid, Captured, EvidenceCompleteness.Complete,
        [
            new("objectClass", AttributeCardinality.MultiValued,
                new[] { "top", "user", "computer", kind }.Select((value, ordinal) => new AttributeValue(ordinal, value, null)).ToArray()),
            new("objectSid", AttributeCardinality.SingleValued, [new(0, null, Sid.ToBytes(DomainSid + "-2400"))]),
            new("sAMAccountName", AttributeCardinality.SingleValued, [new(0, "svc-app$", null)]),
            new("userAccountControl", AttributeCardinality.SingleValued, [new(0, disabled ? "514" : "512", null)]),
            new(GmsaPasswordReaders.Attribute, AttributeCardinality.SingleValued, [new(0, null, descriptor)]),
        ], Domain);

    internal static byte[] Descriptor(string sddl)
    {
        var descriptor = new RawSecurityDescriptor(sddl);
        var bytes = new byte[descriptor.BinaryLength];
        descriptor.GetBinaryForm(bytes, 0);
        return bytes;
    }
}
