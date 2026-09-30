using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using SecureAD.Kernel;

namespace SecureAD.Judgement;

internal static class JudgingBuildIdentity
{
    internal static void Write(IRunLog log, Guid attempt)
    {
        var engine = typeof(JudgingRun).Assembly;
        var entry = Assembly.GetEntryAssembly();
        var processPath = Environment.ProcessPath;
        var enginePath = engine.Location;
        log.Note("Judge", "judging build",
        [
            new("attempt", attempt.ToString("D")), new("processId", Environment.ProcessId.ToString(System.Globalization.CultureInfo.InvariantCulture)),
            new("processPath", processPath ?? "unavailable"), new("processFileSha256", Hash(processPath)),
            new("entryAssembly", entry?.GetName().Name ?? "unavailable"),
            new("entryMvid", entry?.ManifestModule.ModuleVersionId.ToString("D") ?? "unavailable"),
            new("engineAssembly", engine.GetName().Name!), new("engineMvid", engine.ManifestModule.ModuleVersionId.ToString("D")),
            new("engineVersion", engine.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "unavailable"),
            new("engineConfiguration", engine.GetCustomAttribute<AssemblyConfigurationAttribute>()?.Configuration ?? "unavailable"),
            new("enginePath", string.IsNullOrEmpty(enginePath) ? "bundled" : enginePath),
            new("engineFileSha256", string.IsNullOrEmpty(enginePath) ? "bundled-use-process-file-and-engine-mvid" : Hash(enginePath)),
            new("runtime", RuntimeInformation.FrameworkDescription), new("architecture", RuntimeInformation.ProcessArchitecture.ToString()),
        ]);
    }

    private static string Hash(string? path)
    {
        if (string.IsNullOrEmpty(path)) return "unavailable";
        try
        {
            using var stream = File.OpenRead(path);
            return Convert.ToHexString(SHA256.HashData(stream));
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or NotSupportedException)
        {
            return "unavailable:" + error.GetType().Name;
        }
    }
}
