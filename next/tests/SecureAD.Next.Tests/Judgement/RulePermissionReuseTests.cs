using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using SecureAD.Kernel;
using Xunit;
using static SecureAD.Next.Tests.Judgement.SelfMembershipDiscoveryTests;

namespace SecureAD.Next.Tests.Judgement;

public sealed class RulePermissionReuseTests
{
    [Fact]
    public void RulesReuseTheSameReadingForTheCurrentObject()
    {
        var first = new ReadingRule("TEST-READ-1");
        var second = new ReadingRule("TEST-READ-2");
        Judge(first, second);

        Assert.Same(first.Seen[UserDn], second.Seen[UserDn]);
    }

    [Fact]
    public void RepeatedRequestsWithinARuleReuseTheSameReading()
    {
        var rule = new ReadingRule("TEST-READ");
        Judge(rule);

        Assert.Same(rule.Seen[UserDn], rule.Repeated[UserDn]);
    }

    [Fact]
    public void MovingToAnotherObjectDoesNotKeepThePreviousPermissions()
    {
        var rule = new ReadingRule("TEST-READ");
        Judge(rule);

        Assert.Equal(0x20, Assert.Single(rule.Seen[TargetDn].Entries).AccessMask);
    }

    [Fact]
    public void RequestForAnotherObjectUsesThatObjectsPermissions()
    {
        var rule = new ReadingRule("TEST-READ");
        Judge(rule);

        Assert.Equal(0x20, Assert.Single(rule.Other[UserDn].Entries).AccessMask);
    }

    [Fact]
    public void MissingObjectDoesNotReturnTheCurrentObjectsPermissions()
    {
        var rule = new ReadingRule("TEST-READ");
        Judge(rule);

        Assert.Null(rule.Missing[UserDn]);
    }

    [Fact]
    public void DifferentlyCasedRequestsKeepTheEvidenceLookupBehavior()
    {
        var rule = new ReadingRule("TEST-READ");
        Judge(rule);

        Assert.Equal(UserDn, rule.DifferentlyCased[UserDn]!.DistinguishedName);
    }

    [Fact]
    public void RetainedContextDoesNotFollowTheNextObject()
    {
        var rule = new ReadingRule("TEST-READ");
        Judge(rule);

        Assert.Same(rule.Seen[UserDn], rule.Contexts[UserDn].Permissions!(UserDn));
    }

    private static void Judge(params ReadingRule[] rules)
    {
        var directory = Bundle(userDescriptor: "O:SYG:SYD:(A;;RP;;;S-1-5-11)",
            sddl: "O:SYG:SYD:(A;;WP;;;S-1-5-11)");
        Derive(directory);
        var judged = JudgingRun.Judge(directory, rules, Started, Started,
            JudgingRun.NobodyIsWatching, RunLog.Discarded, CancellationToken.None);
        Assert.True(judged.IsSuccess, judged.Error?.Description);
    }

    private sealed class ReadingRule(string id) : IRule
    {
        public RuleDefinition Definition { get; } = new(id, "Read object permissions", Severity.Low, 1,
            [], ["objectClass"], [nameof(DerivedFactKind.PrincipalExpansion)]);
        public Dictionary<string, ObjectPermissions> Seen { get; } = new(StringComparer.Ordinal);
        public Dictionary<string, ObjectPermissions> Repeated { get; } = new(StringComparer.Ordinal);
        public Dictionary<string, ObjectPermissions> Other { get; } = new(StringComparer.Ordinal);
        public Dictionary<string, ObjectPermissions?> Missing { get; } = new(StringComparer.Ordinal);
        public Dictionary<string, ObjectPermissions?> DifferentlyCased { get; } = new(StringComparer.Ordinal);
        public Dictionary<string, JudgingContext> Contexts { get; } = new(StringComparer.Ordinal);

        public RuleVerdict Judge(ObjectAttributes subject) => throw new InvalidOperationException();

        public RuleVerdict Judge(ObjectAttributes subject, JudgingContext context)
        {
            var read = context.Permissions ?? throw new InvalidOperationException();
            var dn = subject.DistinguishedName;
            Seen.Add(dn, read(dn) ?? throw new InvalidOperationException());
            Repeated.Add(dn, read(dn) ?? throw new InvalidOperationException());
            Other.Add(dn, read(TargetDn) ?? throw new InvalidOperationException());
            Missing.Add(dn, read("CN=Missing,DC=contoso,DC=com"));
            DifferentlyCased.Add(dn, read(dn.ToUpperInvariant()));
            Contexts.Add(dn, context);
            return RuleVerdict.Judged([]);
        }
    }
}
