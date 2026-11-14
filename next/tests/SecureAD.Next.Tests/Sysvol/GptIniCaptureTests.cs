using System.Text;
using Microsoft.Data.Sqlite;
using SecureAD.Audit.Sysvol;
using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using SecureAD.Kernel;
using Xunit;
using static SecureAD.Next.Tests.Sysvol.GpoProtocolRun;

namespace SecureAD.Next.Tests.Sysvol;

public sealed class GptIniCaptureTests
{
    [Theory]
    [InlineData("0", 0u)]
    [InlineData("65537", 65537u)]
    [InlineData("4294967295", uint.MaxValue)]
    public async Task GptCapturePersistsOriginalBytesVersionAndItsOwnPermissions(string text, uint expected)
    {
        var bytes = Encoding.ASCII.GetBytes("[General]\r\nVersion=" + text + "\r\n");
        var result = await CaptureAsync(new InMemorySysvolFileReader().WithPolicy(PolicyPath, Descriptor).WithFile(PolicyPath, "GPT.ini", bytes));
        Assert.Equal(GpoReadOutcome.Read, Assert.Single(result.Coverage.Policies).Outcome);
        using var reader = BundleReader.Open(result.Directory).Value;
        var inputs = reader.ReadGpoProtocolInputs(reader.ReadObjectIdentity(PolicyDn)!, CancellationToken.None).Value;
        Assert.Equal(GpoTemplateVersionOutcome.Read, inputs.TemplateVersion.Outcome);
        Assert.Equal(expected, inputs.TemplateVersion.Version);
        Assert.Equal(bytes, inputs.TemplateVersion.OriginalBytes!.Value.ToArray());
        Assert.Equal(text, inputs.TemplateVersion.OriginalVersion);
        Assert.Equal(PolicyGuid, inputs.Policy.ObjectGuid);
        Assert.NotEqual(PolicyGuid.ToString("B"), Path.GetFileName(PolicyPath));
        using var connection = new SqliteConnection("Data Source=" + BundleLayout.EvidencePath(result.Directory) + ";Mode=ReadOnly;Pooling=False");
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM sysvol_path_security_descriptor WHERE gpo_guid=$gpo AND relative_path='GPT.ini'";
        command.Parameters.AddWithValue("$gpo", PolicyGuid.ToString("D"));
        Assert.Equal(1L, command.ExecuteScalar());
    }

    [Theory]
    [InlineData("missing", "Missing")]
    [InlineData("denied", "Unreadable")]
    [InlineData("invalid", "Invalid")]
    public async Task GptCaptureFileGapsRemainDistinctAndMakeCoveragePartial(string defect, string expected)
    {
        var file = new InMemorySysvolFileReader().WithDescriptor(PolicyPath, "", Descriptor);
        if (defect != "missing") file.WithFile(PolicyPath, "GPT.ini", Encoding.ASCII.GetBytes("[General]\r\nVersion=not-a-number\r\n"))
            .WithDescriptor(PolicyPath, "GPT.ini", Descriptor);
        if (defect == "denied") file.Denying(PolicyPath, "GPT.ini");
        var result = await CaptureAsync(file);
        Assert.Equal(GpoReadOutcome.PartiallyRead, Assert.Single(result.Coverage.Policies).Outcome);
        using var reader = BundleReader.Open(result.Directory).Value;
        var captured = reader.ReadGpoProtocolInputs(reader.ReadObjectIdentity(PolicyDn)!, CancellationToken.None).Value.TemplateVersion;
        Assert.Equal(expected, captured.Outcome.ToString());
        Assert.Null(captured.Version);
        Assert.NotNull(captured.Reason);
        Assert.NotNull(captured.Error);
        Assert.Equal(defect == "invalid", captured.OriginalBytes is not null);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task GptCaptureAnUnavailableRootDoesNotClaimItsVersionFileWasMissing(bool denied)
    {
        var file = new InMemorySysvolFileReader();
        if (denied) file.Denying(PolicyPath, "");
        var result = await CaptureAsync(file);
        Assert.Equal(GpoReadOutcome.Unreadable, Assert.Single(result.Coverage.Policies).Outcome);
        using var reader = BundleReader.Open(result.Directory).Value;
        var version = reader.ReadGpoProtocolInputs(reader.ReadObjectIdentity(PolicyDn)!, CancellationToken.None).Value.TemplateVersion;
        Assert.Equal(GpoTemplateVersionOutcome.Unavailable, version.Outcome);
        Assert.Null(version.OriginalBytes);
        Assert.Null(version.Version);
    }

    [Fact]
    public async Task GptCaptureContentSurvivesItsOwnPermissionFailureWithoutBecomingComplete()
    {
        var bytes = Encoding.ASCII.GetBytes("[General]\r\nVersion=42\r\n");
        var file = new ContentWithDeniedAcl(new InMemorySysvolFileReader().WithPolicy(PolicyPath, Descriptor).WithFile(PolicyPath, "GPT.ini", bytes));
        var result = await CaptureAsync(file);
        Assert.Equal(GpoReadOutcome.PartiallyRead, Assert.Single(result.Coverage.Policies).Outcome);
        using var reader = BundleReader.Open(result.Directory).Value;
        var version = reader.ReadGpoProtocolInputs(reader.ReadObjectIdentity(PolicyDn)!, CancellationToken.None).Value.TemplateVersion;
        Assert.Equal(GpoTemplateVersionOutcome.Read, version.Outcome);
        Assert.Equal(42u, version.Version);
        Assert.Equal(bytes, version.OriginalBytes!.Value.ToArray());
    }

    [Fact]
    public async Task GptCaptureCancellationAfterContentAcquisitionIsNotPublishedAsARead()
    {
        using var request = new CancellationTokenSource();
        var file = new CancelAfterContent(new InMemorySysvolFileReader().WithPolicy(PolicyPath, Descriptor), request);
        await Assert.ThrowsAsync<OperationCanceledException>(() => CaptureAsync(file, request.Token));
    }

    private sealed class ContentWithDeniedAcl(ISysvolFileReader inner) : ISysvolFileReader
    {
        public Task<Result<byte[]?>> ReadFileAsync(GpoTarget target, string path, CancellationToken token) => inner.ReadFileAsync(target, path, token);
        public Task<Result<byte[]?>> ReadSecurityDescriptorAsync(GpoTarget target, string path, CancellationToken token) =>
            path == "GPT.ini" ? Task.FromResult(Result<byte[]?>.Failure(AuditError.Create(ErrorCategory.Capture,
                "GptAclDenied", ErrorSeverity.Degraded, "The GPT.ini descriptor was refused.", path)))
                : inner.ReadSecurityDescriptorAsync(target, path, token);
        public Task<Result<IReadOnlyList<string>>> EnumerateRelativeDirectoriesAsync(GpoTarget target, CancellationToken token) => inner.EnumerateRelativeDirectoriesAsync(target, token);
        public Task<Result<IReadOnlyList<string>>> EnumerateRelativeFilesAsync(GpoTarget target, string pattern, CancellationToken token) => inner.EnumerateRelativeFilesAsync(target, pattern, token);
    }

    private sealed class CancelAfterContent(ISysvolFileReader inner, CancellationTokenSource request) : ISysvolFileReader
    {
        public async Task<Result<byte[]?>> ReadFileAsync(GpoTarget target, string path, CancellationToken token)
        {
            var value = await inner.ReadFileAsync(target, path, token);
            if (path == "GPT.ini") request.Cancel();
            return value;
        }
        public Task<Result<byte[]?>> ReadSecurityDescriptorAsync(GpoTarget target, string path, CancellationToken token) => inner.ReadSecurityDescriptorAsync(target, path, token);
        public Task<Result<IReadOnlyList<string>>> EnumerateRelativeDirectoriesAsync(GpoTarget target, CancellationToken token) => inner.EnumerateRelativeDirectoriesAsync(target, token);
        public Task<Result<IReadOnlyList<string>>> EnumerateRelativeFilesAsync(GpoTarget target, string pattern, CancellationToken token) => inner.EnumerateRelativeFilesAsync(target, pattern, token);
    }
}
