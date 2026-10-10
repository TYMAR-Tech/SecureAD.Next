using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace SecureAD.JudgementDiagnostic;

internal static class DiagnosticSqlite
{
    internal static string LibrarySha256 { get; private set; } = "";

    internal static void Initialize()
    {
        using var resource = Assembly.GetExecutingAssembly().GetManifestResourceStream("diagnostic_sqlite3.dll")
            ?? throw new InvalidOperationException("The diagnostic SQLite library is missing.");
        using var bytes = new MemoryStream();
        resource.CopyTo(bytes);
        var image = bytes.ToArray();
        LibrarySha256 = Convert.ToHexString(SHA256.HashData(image));
        var directory = Path.Combine(Path.GetTempPath(), "SecureAD.JudgementDiagnostic", LibrarySha256);
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, "diagnostic_sqlite3.dll");
        if (!File.Exists(path))
        {
            using var output = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
            output.Write(image);
        }
        using var guard = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (!SHA256.HashData(guard).AsSpan().SequenceEqual(SHA256.HashData(image)))
            throw new InvalidOperationException("The extracted diagnostic SQLite fingerprint does not match.");
        var library = NativeLibrary.Load(path);
        NativeLibrary.SetDllImportResolver(typeof(SQLitePCL.SQLite3Provider_e_sqlite3).Assembly,
            (name, _, _) => name == "e_sqlite3" ? library : IntPtr.Zero);
        SQLitePCL.Batteries_V2.Init();
    }
}
