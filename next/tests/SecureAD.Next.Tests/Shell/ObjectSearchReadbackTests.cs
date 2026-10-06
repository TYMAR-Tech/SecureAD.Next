using System.Security.Cryptography;
using SecureAD.Next.Tests.Evidence;
using SecureAD.Shell.Services;
using Xunit;

namespace SecureAD.Next.Tests.Shell;

public sealed class ObjectSearchReadbackTests
{
    [Fact]
    public async Task ObjectSearchUsesOnlyTheSelectedCaptureAndLeavesItUnchanged()
    {
        using var fixture = new DelegationLookupTests.Fixture();
        fixture.Principal("Alice", "S-1-5-21-1-2-3-1100", "child.contoso.com");
        fixture.Open();
        var before = Files(fixture.DirectoryPath);
        using var source = new BundleAssetSource();
        source.SelectRun(fixture.DirectoryPath);

        var page = await source.ReadAsync(fixture.DirectoryPath,
            (reader, _) => reader.SearchObjects(fixture.DirectoryPath, "Alice", null), CancellationToken.None);

        Assert.True(page.IsSuccess);
        Assert.Equal("child.contoso.com", Assert.Single(page.Value.Objects).DomainFqdn);
        Assert.Equal(before, Files(fixture.DirectoryPath));
    }

    private static string[] Files(string directory) => Directory.GetFiles(directory, "*", SearchOption.AllDirectories)
        .Order(StringComparer.Ordinal).Select(file => Path.GetRelativePath(directory, file) + ":" +
            Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(file)))).ToArray();
}
