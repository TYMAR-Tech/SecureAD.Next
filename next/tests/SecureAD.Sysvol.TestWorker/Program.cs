using System.Buffers.Binary;
using System.IO.Pipes;
using System.Text.Json;

using var pipe = new NamedPipeClientStream(".", args[^1], PipeDirection.InOut, PipeOptions.Asynchronous);
await pipe.ConnectAsync(10000);
await SendAsync(Message(0, new { Operation = "WorkerReady", Path = "", State = "Completed", Items = 0L, Bytes = 0L }, false, null, null));
while (true)
{
    using var request = await ReceiveAsync();
    var root = request.RootElement;
    var id = root.GetProperty("Id").GetInt64();
    var target = root.GetProperty("Target");
    var mode = target.GetProperty("DisplayName").GetString();
    var path = target.GetProperty("FileSysPath").GetString() + "\\" + root.GetProperty("Path").GetString();
    await SendAsync(Message(id, new { Operation = "GetAttributes", Path = path, State = "Started", Items = 0L, Bytes = 0L }, false, null, null));
    if (mode == "hang")
        Thread.Sleep(Timeout.Infinite);
    if (mode == "late")
        Thread.Sleep(10000);
    if (mode == "progress")
    {
        for (var count = 1; count <= 3; count++)
            await SendAsync(Message(id, new { Operation = "GetAttributes", Path = path, State = "Progress", Items = (long)count, Bytes = 0L }, false, null, null));
    }
    var kind = root.GetProperty("Kind").GetInt32();
    await SendAsync(Message(mode == "stale" ? id - 1 : id, null, true,
        kind < 2 ? new byte[] { 1, 2, 3 } : null, kind >= 2 ? Array.Empty<string>() : null));
}

static object Message(long id, object? progress, bool finished, byte[]? bytes, string[]? paths) =>
    new { RequestId = id, Progress = progress, Finished = finished, Bytes = bytes, Paths = paths, Error = (object?)null };

async Task SendAsync(object message)
{
    var bytes = JsonSerializer.SerializeToUtf8Bytes(message);
    var header = new byte[4];
    BinaryPrimitives.WriteInt32LittleEndian(header, bytes.Length);
    await pipe.WriteAsync(header);
    await pipe.WriteAsync(bytes);
    await pipe.FlushAsync();
}

async Task<JsonDocument> ReceiveAsync()
{
    var header = new byte[4];
    await pipe.ReadExactlyAsync(header);
    var bytes = new byte[BinaryPrimitives.ReadInt32LittleEndian(header)];
    await pipe.ReadExactlyAsync(bytes);
    return JsonDocument.Parse(bytes);
}
