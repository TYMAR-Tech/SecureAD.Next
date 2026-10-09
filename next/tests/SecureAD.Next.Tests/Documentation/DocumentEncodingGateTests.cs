using System.Text;
using System.Text.RegularExpressions;
using Xunit;

namespace SecureAD.Next.Tests.Documentation;

/// <summary>
/// No document in the repository carries text that has been through a Windows-1252 round-trip.
/// </summary>
/// <remarks>
/// <para>
/// <b>The corruption is mechanical, and so is detecting it.</b> UTF-8 bytes decoded as
/// Windows-1252 and written back turn one character into three: an em dash becomes
/// <c>U+00E2 U+20AC U+201D</c>, an en dash <c>U+00E2 U+20AC U+201C</c>, an ellipsis
/// <c>U+00E2 U+20AC U+00A6</c>. The pair <c>U+00E2 U+20AC</c> begins every one of them and occurs
/// in no English prose, so its presence is the whole test.
/// </para>
/// <para>
/// <b>It kept coming back because nothing failed.</b> PowerShell's <c>Set-Content -Encoding utf8</c>
/// did this to twenty-nine documents in a single pass while trimming one of them, and it was found
/// by eye. Fifteen documents were still carrying five hundred and fourteen corrupted characters
/// until 2026-08-25, surviving several passes that read those files. A tool existed to report it -
/// <c>next/tools/check-document-encoding.ps1</c> - and a tool nobody is obliged to run is a tool
/// that is not run.
/// </para>
/// <para>
/// <b>Repairing is not this test's job.</b> <c>next/tools/repair-double-encoded-documents.ps1</c>
/// inverts the round-trip exactly, by encoding the three characters back to their 1252 bytes and
/// decoding those as UTF-8. Nothing about the fix is a guess, which is why the gate can be
/// unconditional.
/// </para>
/// </remarks>
public sealed class DocumentEncodingGateTests
{
    /// <summary>
    /// Windows-1252, which .NET does not carry by default. It lives in
    /// <c>System.Text.Encoding.CodePages</c> and has to be registered before
    /// <see cref="Encoding.GetEncoding(int)"/> will return it.
    /// </summary>
    private static Encoding Windows1252()
    {
        Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
        return Encoding.GetEncoding(1252);
    }

    /// <summary>
    /// The signature of a 1252 round-trip. Built from the corruption rather than written down: a
    /// hand-typed constant here would itself be at risk of the fault it detects.
    /// </summary>
    private static readonly string Signature =
        Windows1252().GetString(Encoding.UTF8.GetBytes("—"))[..2];

    [Fact]
    public void NoDocumentCarriesTextFromAWindows1252RoundTrip() =>
        RequireUncorruptedDocuments(RepositoryLocation.Root());

    private static void RequireUncorruptedDocuments(string root)
    {
        var corrupted = new List<string>();

        foreach (var file in Documents(root, _ => { }))
        {
            var text = File.ReadAllText(file, Encoding.UTF8);
            var hits = 0;
            var at = text.IndexOf(Signature, StringComparison.Ordinal);
            while (at >= 0)
            {
                hits++;
                at = text.IndexOf(Signature, at + 1, StringComparison.Ordinal);
            }

            if (hits > 0)
                corrupted.Add($"  {hits,5} sequences  {Path.GetRelativePath(root, file).Replace('\\', '/')}");
        }

        Assert.True(
            corrupted.Count == 0,
            "A document has been written through Windows-1252, turning each em dash, en dash or "
            + "ellipsis into three characters. Repair it with "
            + "next/tools/repair-double-encoded-documents.ps1, which inverts the round-trip exactly, "
            + "and use the .NET file APIs rather than Set-Content for any further edit:"
            + Environment.NewLine
            + string.Join(Environment.NewLine, corrupted.OrderBy(m => m, StringComparer.Ordinal)));
    }

    /// <summary>
    /// The signature is two characters that begin every corrupted sequence, and it is derived
    /// rather than declared. If that derivation ever stopped producing the pair this gate looks
    /// for, the gate would pass over a corrupted tree and say nothing.
    /// </summary>
    [Fact]
    public void TheSignatureIsTheOneAWindows1252RoundTripProduces()
    {
        Assert.Equal(2, Signature.Length);
        Assert.Equal('\u00E2', Signature[0]);
        Assert.Equal('\u20AC', Signature[1]);

        foreach (var ch in new[] { "—", "–", "…" })
        {
            var corrupted = Windows1252().GetString(Encoding.UTF8.GetBytes(ch));
            Assert.StartsWith(Signature, corrupted, StringComparison.Ordinal);
            Assert.Equal(3, corrupted.Length);
        }

        Assert.DoesNotContain(Signature, "An em dash — an en dash – and an ellipsis …",
            StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("bin")]
    [InlineData("BIN")]
    [InlineData("obj")]
    [InlineData("Obj")]
    [InlineData(".git")]
    [InlineData(".vs")]
    [InlineData(".idea")]
    [InlineData("packages")]
    [InlineData("Debug")]
    [InlineData("Release")]
    [InlineData("TestResults")]
    [InlineData("testresult-retained")]
    public void DocumentScanPrunesGeneratedDirectoriesBeforeEnteringThem(string directory)
    {
        using var tree = new DocumentTree();
        var document = tree.Write(@"docs\required.md", "Real document.");
        tree.Write(Path.Combine("next", directory, "deep", "excluded.md"), "Not source.");
        var entered = new List<string>();

        var files = Documents(tree.Root, entered.Add).ToArray();

        Assert.Equal(document, Assert.Single(files));
        Assert.DoesNotContain(entered, path => path.StartsWith(Path.Combine(tree.Root, "next", directory),
            StringComparison.OrdinalIgnoreCase));
    }

    [Theory]
    [InlineData(@".v-campaign\next\docs\excluded.md")]
    [InlineData(@".vt-campaign\deep\excluded.md")]
    [InlineData(@".t-df-campaign\deep\excluded.md")]
    [InlineData(@".m-df-campaign\deep\excluded.md")]
    [InlineData(@"t-1234aBcD\deep\excluded.md")]
    [InlineData(@"verification-output\deep\excluded.md")]
    [InlineData(@"LabBundles\deep\excluded.md")]
    [InlineData(@"Lab Databases\deep\excluded.md")]
    [InlineData(@"next\artifacts\source-copy\excluded.md")]
    [InlineData(@"next\.t\deep\excluded.md")]
    [InlineData(@"next\lab-validation-campaign\deep\excluded.md")]
    public void DocumentScanPrunesLocalEvidenceBeforeEnteringIt(string relative)
    {
        using var tree = new DocumentTree();
        var document = tree.Write(@"docs\required.md", "Real document.");
        tree.Write(relative, "Historical evidence.");
        var entered = new List<string>();
        var parts = relative.Split(Path.DirectorySeparatorChar);
        var excluded = Path.Combine(tree.Root, parts[0] == "next" ? Path.Combine(parts[0], parts[1]) : parts[0]);

        var files = Documents(tree.Root, entered.Add).ToArray();

        Assert.Equal(document, Assert.Single(files));
        Assert.DoesNotContain(entered, path => path.StartsWith(excluded, StringComparison.OrdinalIgnoreCase));
    }

    [Theory]
    [InlineData("README.md")]
    [InlineData(@"docs\specs\required.md")]
    [InlineData(@".github\instructions\new.instructions.md")]
    [InlineData(@"next\src\required.md")]
    [InlineData(@"next\tests\fixtures\required.md")]
    [InlineData(@"lab\README.md")]
    [InlineData(@"docs\artifacts\required.md")]
    [InlineData(@"docs\.v-real-documents\required.md")]
    [InlineData(@"docs\.t\required.md")]
    [InlineData(@"docs\t-1234abcd\required.md")]
    [InlineData(@"next\.v-real-documents\required.md")]
    [InlineData(@"t-not-a-temp-root\required.md")]
    public void DocumentScanStillInspectsRealAndUncommittedDocuments(string relative)
    {
        using var tree = new DocumentTree();
        var document = tree.Write(relative, "Real document, without a Git inventory.");
        tree.Write(@"docs\not-markdown.txt", "Not Markdown.");

        Assert.Equal(document, Assert.Single(Documents(tree.Root, _ => { })));
    }

    [Theory]
    [InlineData("—")]
    [InlineData("–")]
    [InlineData("…")]
    public void PrunedDocumentScanStillRejectsCorruptedSourceText(string character)
    {
        using var tree = new DocumentTree();
        tree.Write(@"docs\clean.md", "Correct text.");
        tree.Write(@"docs\specs\damaged.md", Windows1252().GetString(Encoding.UTF8.GetBytes(character)));

        var error = Assert.Throws<Xunit.Sdk.TrueException>(() => RequireUncorruptedDocuments(tree.Root));

        Assert.Contains("docs/specs/damaged.md", error.Message, StringComparison.Ordinal);
        Assert.Contains("1 sequences", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void PrunedDocumentScanAcceptsCorrectTextWithoutReadingCorruptLocalEvidence()
    {
        using var tree = new DocumentTree();
        tree.Write(@"docs\correct.md", "Correct punctuation — – …");
        tree.Write(@".v-frozen\docs\historical.md", Windows1252().GetString(Encoding.UTF8.GetBytes("—")));

        RequireUncorruptedDocuments(tree.Root);
    }

    [Fact]
    public void PrunedDocumentScanDoesNotTurnAnUnreadableSourceFileIntoSuccess()
    {
        using var tree = new DocumentTree();
        var document = tree.Write(@"docs\locked.md", "Required source.");
        using var locked = new FileStream(document, FileMode.Open, FileAccess.Read, FileShare.None);

        Assert.Throws<IOException>(() => RequireUncorruptedDocuments(tree.Root));
    }

    private static IEnumerable<string> Documents(string root, Action<string> entering)
    {
        var pending = new Stack<string>();
        pending.Push(root);
        while (pending.TryPop(out var directory))
        {
            entering(directory);
            foreach (var file in Directory.EnumerateFiles(directory, "*.md", SearchOption.TopDirectoryOnly))
                yield return file;
            foreach (var child in Directory.EnumerateDirectories(directory))
                if (IsSourceDirectory(root, child)) pending.Push(child);
        }
    }

    private static bool IsSourceDirectory(string root, string directory)
    {
        var relative = Path.GetRelativePath(root, directory);
        var parent = Path.GetDirectoryName(relative);
        var name = Path.GetFileName(relative);
        if (new[] { "bin", "obj", ".git", ".vs", ".idea", "packages", "Debug", "Release" }
                .Contains(name, StringComparer.OrdinalIgnoreCase)
            || name.StartsWith("TestResult", StringComparison.OrdinalIgnoreCase)) return false;

        // These ignored paths hold captures, frozen source copies and verification results,
        // not current documents. Their names elsewhere must not hide real source.
        if (string.IsNullOrEmpty(parent) &&
            (new[] { ".v-", ".vt-", ".t-df-", ".m-df-" }.Any(prefix => name.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                || Regex.IsMatch(name, "^t-[0-9a-f]{8}$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)
                || new[] { "verification-output", "LabBundles", "Lab Databases" }.Contains(name, StringComparer.OrdinalIgnoreCase)))
            return false;
        return !string.Equals(parent, "next", StringComparison.OrdinalIgnoreCase)
            || !(new[] { "artifacts", ".t" }.Contains(name, StringComparer.OrdinalIgnoreCase)
                || name.StartsWith("lab-validation-", StringComparison.OrdinalIgnoreCase));
    }

    private sealed class DocumentTree : IDisposable
    {
        internal string Root { get; } = Path.Combine(Path.GetTempPath(), "document-scan-" + Guid.NewGuid().ToString("N"));

        internal string Write(string relative, string text)
        {
            var path = Path.Combine(Root, relative);
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path, text, Encoding.UTF8);
            return path;
        }

        public void Dispose() => Directory.Delete(Root, recursive: true);
    }
}
