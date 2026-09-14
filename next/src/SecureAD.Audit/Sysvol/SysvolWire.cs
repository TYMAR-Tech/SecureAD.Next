using System.Buffers.Binary;
using System.Globalization;
using System.Resources;
using System.Text.Json;
using SecureAD.Kernel;

namespace SecureAD.Audit.Sysvol;

internal enum SysvolRequestKind { ReadFile, ReadSecurityDescriptor, EnumerateFiles, EnumerateDirectories }

internal sealed record SysvolRequest(long Id, SysvolRequestKind Kind, GpoTarget Target, string Path);
internal sealed record SysvolIoEvent(string Operation, string Path, string State, long Items, long Bytes);
internal sealed record SysvolWorkerMessage(
    long RequestId, SysvolIoEvent? Progress, bool Finished, byte[]? Bytes, string[]? Paths, AuditError? Error);

internal static class SysvolText
{
    private static readonly ResourceManager Resources = new(
        "SecureAD.Audit.Resources.SysvolAcquisition", typeof(SysvolText).Assembly);

    internal static string Get(string key, params object[] values) => string.Format(
        CultureInfo.CurrentCulture,
        Resources.GetString(key, CultureInfo.CurrentUICulture) ?? throw new MissingManifestResourceException(key),
        values);

    internal static AuditError Error(string reason, string key, string path, params object[] values) =>
        AuditError.Create(ErrorCategory.Capture, reason, ErrorSeverity.Failed, Get(key, values), path);
}

internal static class SysvolWire
{
    internal static async Task SendAsync<T>(Stream stream, T value, CancellationToken cancellationToken)
    {
        var payload = JsonSerializer.SerializeToUtf8Bytes(value);
        var header = new byte[sizeof(int)];
        BinaryPrimitives.WriteInt32LittleEndian(header, payload.Length);
        await stream.WriteAsync(header, cancellationToken).ConfigureAwait(false);
        await stream.WriteAsync(payload, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    // The worker reports before entering synchronous Windows calls. This write can block only
    // the disposable worker, never the evidence writer, and is flushed before acquisition starts.
    internal static void Send<T>(Stream stream, T value)
    {
        var payload = JsonSerializer.SerializeToUtf8Bytes(value);
        Span<byte> header = stackalloc byte[sizeof(int)];
        BinaryPrimitives.WriteInt32LittleEndian(header, payload.Length);
        stream.Write(header);
        stream.Write(payload);
        stream.Flush();
    }

    internal static async Task<T> ReceiveAsync<T>(Stream stream, CancellationToken cancellationToken)
    {
        var header = new byte[sizeof(int)];
        await stream.ReadExactlyAsync(header, cancellationToken).ConfigureAwait(false);
        var length = BinaryPrimitives.ReadInt32LittleEndian(header);
        if (length <= 0)
            throw new InvalidDataException(SysvolText.Get("ProtocolInvalid"));
        var payload = new byte[length];
        await stream.ReadExactlyAsync(payload, cancellationToken).ConfigureAwait(false);
        return JsonSerializer.Deserialize<T>(payload)
            ?? throw new InvalidDataException(SysvolText.Get("ProtocolInvalid"));
    }
}
