using System.ComponentModel;
using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace SecureAD.Audit.Sysvol;

internal sealed class SysvolWorkerConnection(Func<ProcessStartInfo> command, TimeSpan shutdownTimeout)
{
    internal const string Switch = "--sysvol-worker";
    private NamedPipeServerStream? _pipe;
    private SysvolWorkerJob? _job;
    private Process? _process;
    private bool _blocked;
    private bool _assigned;

    internal Stream Pipe => _pipe ?? throw new InvalidOperationException(SysvolText.Get("ProtocolInvalid"));
    internal int? ProcessId => _process?.Id;
    internal bool Blocked => _blocked;
    internal string? StopFailure { get; private set; }

    internal async Task StartAsync(CancellationToken cancellationToken)
    {
        if (_blocked)
            throw new InvalidOperationException(SysvolText.Get("WorkerUnavailable"));
        if (_pipe is not null)
            return;

        var name = "SecureAD.Sysvol." + Guid.NewGuid().ToString("N");
        _pipe = new NamedPipeServerStream(name, PipeDirection.InOut, 1,
            PipeTransmissionMode.Byte, PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
        _job = new SysvolWorkerJob();
        var start = command();
        start.UseShellExecute = false;
        start.CreateNoWindow = true;
        start.ArgumentList.Add(Switch);
        start.ArgumentList.Add(name);
        _process = Process.Start(start) ?? throw new InvalidOperationException(SysvolText.Get("NoExecutable"));
        _job.Assign(_process);
        _assigned = true;
        await _pipe.WaitForConnectionAsync(cancellationToken).ConfigureAwait(false);
        if (!GetNamedPipeClientProcessId(_pipe.SafePipeHandle, out var client) || client != (uint)_process.Id)
            throw new InvalidDataException(SysvolText.Get("ProtocolInvalid"));
    }

    internal async Task<bool> StopAsync()
    {
        // A fresh pipe is required for every replacement. No late frame from a discarded worker
        // can be consumed by the next session, even if termination is delayed in the redirector.
        _pipe?.Dispose();
        _pipe = null;
        _job?.Dispose();
        _job = null;
        if (_process is null)
            return true;

        try
        {
            // Also handles startup failures before the process could be assigned to its job.
            if (!_assigned && !_process.HasExited)
                _process.Kill(entireProcessTree: true);
            using var deadline = new CancellationTokenSource(shutdownTimeout);
            await _process.WaitForExitAsync(deadline.Token).ConfigureAwait(false);
            _process.Dispose();
            _process = null;
            _assigned = false;
            return true;
        }
        catch (OperationCanceledException error)
        {
            _blocked = true;
            StopFailure = error.Message;
            return false;
        }
        catch (Win32Exception error)
        {
            _blocked = true;
            StopFailure = error.Message;
            return false;
        }

    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeClientProcessId(SafePipeHandle pipe, out uint processId);
}
