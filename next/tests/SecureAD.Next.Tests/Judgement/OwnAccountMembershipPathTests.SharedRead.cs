using System.Text.Json;
using SecureAD.Judgement;
using Xunit;
using static SecureAD.Next.Tests.Judgement.SelfMembershipDiscoveryTests;

namespace SecureAD.Next.Tests.Judgement;

public sealed partial class OwnAccountMembershipPathTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    public void P246SharedReadPreservesSeparateAnswersAndOneValidatedInput(int family)
    {
        var directory = family == 0 ? Prepared() : family == 1
            ? Capture($"O:SYG:SYD:(OA;;WP;{MemberGuid};;{UserSid})")
            : Capture(membershipTail: false, daclTail: true);
        if (family != 0)
        {
            Derive(directory);
            if (family == 1) Judge(directory, [new(UserDn, TargetDn) { PermissionKind = OwnAccountMembershipPermissionKind.WriteMembers }]);
            else JudgeMembershipDacl(directory, [new(UserDn, TargetDn, CoreDn)]);
        }
        using var reader = Open(directory);
        var path = reader.ReadTier0Path(UserDn);
        var coverage = reader.ReadPathRequesterCoverage();
        var before = Snapshot(directory);
        var together = reader.ReadTier0PathWithCoverage(UserDn);
        Assert.Same(together.Path.Inputs, together.Coverage.Inputs);
        Assert.Equal(JsonSerializer.Serialize(path), JsonSerializer.Serialize(together.Path));
        Assert.Equal(JsonSerializer.Serialize(coverage), JsonSerializer.Serialize(together.Coverage));
        Assert.Equal(before, Snapshot(directory));
    }

    [Fact]
    public void P246SharedReadDoesNotCacheAPreviouslyValidatedGeneration()
    {
        var directory = Prepared();
        using var reader = Open(directory);
        reader.ReadTier0PathWithCoverage(UserDn);
        Mutate(directory, "DELETE FROM tier0_path_calculation");
        Assert.Throws<InvalidDataException>(() => reader.ReadTier0PathWithCoverage(UserDn));
    }

    [Fact]
    public void P246SharedReadPropagatesCancellationWithoutReturningCoverage()
    {
        var directory = Prepared();
        using var reader = Open(directory);
        using var stopping = new CancellationTokenSource();
        stopping.Cancel();
        Assert.Throws<OperationCanceledException>(() => reader.ReadTier0PathWithCoverage(UserDn, stopping.Token));
    }
}
