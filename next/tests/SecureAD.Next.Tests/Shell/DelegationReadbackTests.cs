using System.Security.Cryptography;
using SecureAD.Evidence;
using SecureAD.Kernel.Security;
using SecureAD.Next.Tests.Evidence;
using SecureAD.Next.Tests.Kernel.Security;
using SecureAD.Shell.Services;
using Xunit;

namespace SecureAD.Next.Tests.Shell;

public sealed class DelegationReadbackTests
{
    [Fact]
    public async Task RealShellReadsOriginalEvidenceWithoutJudgementOrWritingAnyFile()
    {
        const string sid = "S-1-5-21-1-2-3-1100";
        using var fixture = new DelegationLookupTests.Fixture();
        fixture.Principal("Helpdesk", sid);
        fixture.Target("People", [SdBytes.AllowAce(Sid.ToBytes(sid)!, 0x100)]);
        fixture.Open();
        var before = Files(fixture.DirectoryPath);
        using var source = new BundleAssetSource();
        source.SelectRun(fixture.DirectoryPath);

        var principals = await source.ReadAsync(fixture.DirectoryPath,
            (reader, _) => reader.FindDelegationPrincipals(fixture.DirectoryPath, "Helpdesk", null), CancellationToken.None);
        Assert.True(principals.IsSuccess);
        var principal = Assert.Single(principals.Value.Principals);
        var query = new DelegationQuery(principal, DelegationPermission.ResetPassword, false);
        var page = await source.ReadAsync(fixture.DirectoryPath,
            (reader, _) => reader.ReadDelegations(fixture.DirectoryPath, query, null), CancellationToken.None);

        Assert.True(page.IsSuccess);
        Assert.Equal(sid, Assert.Single(page.Value.Entries).Entry.Trustee.Sid);
        Assert.Equal(before, Files(fixture.DirectoryPath));
        Assert.DoesNotContain(Directory.GetFiles(fixture.DirectoryPath, "*", SearchOption.AllDirectories),
            file => Path.GetFileName(file).Contains("judgement", StringComparison.OrdinalIgnoreCase));
    }

    private static string[] Files(string directory) => Directory.GetFiles(directory, "*", SearchOption.AllDirectories)
        .Order(StringComparer.Ordinal).Select(file => Path.GetRelativePath(directory, file) + ":" +
            Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(file)))).ToArray();
}
