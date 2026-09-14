using System.Diagnostics;
using System.IO.Pipes;
using System.Reflection;
using System.Security.Principal;
using System.Text.Json;

namespace SecureAD.Audit.Sysvol;

/// <summary>The acquisition-only entry point used by both executable hosts, before normal startup.</summary>
public static class SysvolWorker
{
    /// <summary>Whether this invocation is reserved for supervised SYSVOL work.</summary>
    public static bool IsInvocation(string[] args)
    {
        ArgumentNullException.ThrowIfNull(args);
        return args.Length > 0 && args[0] == SysvolWorkerConnection.Switch;
    }

    /// <summary>Locates the current executable without relying on a separately deployed worker binary.</summary>
    public static ProcessStartInfo CurrentCommand()
    {
        var executable = Environment.ProcessPath;
        if (string.IsNullOrWhiteSpace(executable))
            throw new InvalidOperationException(SysvolText.Get("NoExecutable"));
        var start = new ProcessStartInfo(executable);
        if (string.Equals(Path.GetFileNameWithoutExtension(executable), "dotnet", StringComparison.OrdinalIgnoreCase))
        {
            var entry = Assembly.GetEntryAssembly()?.Location;
            if (string.IsNullOrWhiteSpace(entry))
                throw new InvalidOperationException(SysvolText.Get("NoExecutable"));
            start.ArgumentList.Add(entry);
        }
        return start;
    }

    /// <summary>Serves acquisition requests only; this process receives no evidence destination.</summary>
    public static async Task<int> RunAsync(string[] args)
    {
        ArgumentNullException.ThrowIfNull(args);
        if (args.Length != 2 || !IsInvocation(args) || !args[1].StartsWith("SecureAD.Sysvol.", StringComparison.Ordinal))
            return 2;

        using var pipe = new NamedPipeClientStream(".", args[1], PipeDirection.InOut,
            PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly, TokenImpersonationLevel.Anonymous);
        try
        {
            await pipe.ConnectAsync(30_000, CancellationToken.None).ConfigureAwait(false);
            await SysvolWire.SendAsync(pipe, new SysvolWorkerMessage(0,
                new SysvolIoEvent("WorkerReady", "", "Completed", 0, 0), false, null, null, null),
                CancellationToken.None).ConfigureAwait(false);

            while (true)
            {
                var request = await SysvolWire.ReceiveAsync<SysvolRequest>(pipe, CancellationToken.None).ConfigureAwait(false);
                var target = GpoTarget.Of(request.Target.GpoGuid, request.Target.DisplayName, request.Target.FileSysPath);
                var reader = new SmbSysvolFileReader(progress => SysvolWire.Send(pipe,
                    new SysvolWorkerMessage(request.Id, progress, false, null, null, null)));
                SysvolWorkerMessage response;
                if (request.Kind is SysvolRequestKind.ReadFile or SysvolRequestKind.ReadSecurityDescriptor)
                {
                    var result = request.Kind == SysvolRequestKind.ReadFile
                        ? await reader.ReadFileAsync(target, request.Path, CancellationToken.None).ConfigureAwait(false)
                        : await reader.ReadSecurityDescriptorAsync(target, request.Path, CancellationToken.None).ConfigureAwait(false);
                    response = new SysvolWorkerMessage(request.Id, null, true,
                        result.IsSuccess ? result.Value : null, null, result.Error);
                }
                else if (request.Kind is SysvolRequestKind.EnumerateFiles or SysvolRequestKind.EnumerateDirectories)
                {
                    var result = request.Kind == SysvolRequestKind.EnumerateFiles
                        ? await reader.EnumerateRelativeFilesAsync(target, request.Path, CancellationToken.None).ConfigureAwait(false)
                        : await reader.EnumerateRelativeDirectoriesAsync(target, CancellationToken.None).ConfigureAwait(false);
                    response = new SysvolWorkerMessage(request.Id, null, true, null,
                        result.IsSuccess ? result.Value!.ToArray() : null, result.Error);
                }
                else
                {
                    return 2;
                }
                await SysvolWire.SendAsync(pipe, response, CancellationToken.None).ConfigureAwait(false);
            }
        }
        catch (IOException)
        {
            // EOF or a broken pipe is the supervisor withdrawing the session. A nonzero exit
            // without a complete response is always an acquisition failure at the parent.
            return 2;
        }
        catch (TimeoutException)
        {
            return 2;
        }
        catch (JsonException)
        {
            return 2;
        }
        catch (InvalidDataException)
        {
            return 2;
        }
    }
}
