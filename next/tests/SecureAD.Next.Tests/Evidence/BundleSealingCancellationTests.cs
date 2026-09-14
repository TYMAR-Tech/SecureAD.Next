using System.Security.Cryptography;
using SecureAD.Evidence;
using Xunit;
using Xunit.Abstractions;

namespace SecureAD.Next.Tests.Evidence;

public sealed class BundleSealingCancellationTests(ITestOutputHelper output)
{
    [Theory]
    [InlineData(0)]
    [InlineData(3)]
    [InlineData(163857)]
    public void StreamingHashMatchesThePlatformSha256(int length)
    {
        var bytes = Enumerable.Range(0, length).Select(i => (byte)(i % 251)).ToArray();
        using var stream = new MemoryStream(bytes);

        var hash = BundleSealing.HashStream(stream, CancellationToken.None);

        Assert.Equal(Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant(), hash);
    }

    [Fact]
    public void AnAlreadyCancelledHashDoesNotRead()
    {
        using var cancellation = new CancellationTokenSource();
        using var stream = new ObservedStream([1], () => { });
        cancellation.Cancel();

        Record.Exception(() => BundleSealing.HashStream(stream, cancellation.Token));

        Assert.Equal(0, stream.Reads);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    public void CancellationDuringAReadIncludingEofDoesNotReturnAHash(int length)
    {
        using var cancellation = new CancellationTokenSource();
        using var stream = new ObservedStream(new byte[length], cancellation.Cancel);

        var failure = Record.Exception(() => BundleSealing.HashStream(stream, cancellation.Token));

        Assert.Equal(cancellation.Token, Assert.IsType<OperationCanceledException>(failure).CancellationToken);
    }

    [Fact]
    public void AReadFailureIsNotReplacedByConcurrentCancellation()
    {
        using var cancellation = new CancellationTokenSource();
        var failure = new IOException("Synthetic read failure.");
        using var stream = new ObservedStream([1], () => { cancellation.Cancel(); throw failure; });

        var observed = Record.Exception(() => BundleSealing.HashStream(stream, cancellation.Token));

        Assert.Same(failure, observed);
    }

    [Fact]
    public void HashingLeavesTheCallerOwnedStreamOpen()
    {
        using var stream = new MemoryStream([1, 2, 3]);

        BundleSealing.HashStream(stream, CancellationToken.None);

        Assert.True(stream.CanRead);
    }

    [Fact]
    public void FileHashingReleasesItsOwnFile()
    {
        var path = NewFile();

        BundleSealing.HashFile(path, CancellationToken.None);

        using var exclusive = File.Open(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        Assert.Equal(3, exclusive.Length);
    }

    [Fact]
    public void ACancelledSealDoesNotWriteASealFile()
    {
        var path = NewFile();
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        Record.Exception(() => BundleSealing.Seal(path, path + ".seal", cancellation.Token));

        Assert.False(File.Exists(path + ".seal"));
    }

    private string NewFile()
    {
        var path = Path.Combine(Path.GetTempPath(), "securead-p216-hash-" + Guid.NewGuid().ToString("N"));
        output.WriteLine(path);
        File.WriteAllBytes(path, [1, 2, 3]);
        return path;
    }

    private sealed class ObservedStream(byte[] bytes, Action afterRead) : MemoryStream(bytes)
    {
        public int Reads { get; private set; }

        public override int Read(byte[] buffer, int offset, int count)
        {
            Reads++;
            var read = base.Read(buffer, offset, count);
            afterRead();
            return read;
        }
    }
}
