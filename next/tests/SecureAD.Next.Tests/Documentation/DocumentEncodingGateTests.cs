using System.Text;
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
    public void NoDocumentCarriesTextFromAWindows1252RoundTrip()
    {
        var corrupted = new List<string>();

        foreach (var file in Documents())
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
                corrupted.Add($"  {hits,5} sequences  {Relative(file)}");
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

    /// <summary>Every markdown document in the repository, build output excluded.</summary>
    private static IEnumerable<string> Documents() =>
        Directory.EnumerateFiles(RepositoryLocation.Root(), "*.md", SearchOption.AllDirectories)
            .Where(NotBuildOutput)
            .OrderBy(f => f, StringComparer.Ordinal);

    private static bool NotBuildOutput(string file) =>
        !file.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}", StringComparison.Ordinal)
        && !file.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal)
        && !file.Contains($"{Path.DirectorySeparatorChar}.git{Path.DirectorySeparatorChar}", StringComparison.Ordinal);

    private static string Relative(string file) =>
        Path.GetRelativePath(RepositoryLocation.Root(), file).Replace('\\', '/');
}
