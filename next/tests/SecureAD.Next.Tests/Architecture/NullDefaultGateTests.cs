using System.Text.RegularExpressions;
using Xunit;

namespace SecureAD.Next.Tests.Architecture;

/// <summary>
/// Gate 1, second half: no parameter in the rebuild's production code may default to
/// <c>null</c>.
///
/// <para>
/// The first half of gate 1 is carried by the compiler — <c>Result&lt;T&gt;</c> and
/// <c>AuditError</c> are types, so a caller cannot ignore them. This half cannot be, because
/// <c>= null</c> is legal C# that quietly turns a required collaborator into an optional one.
/// </para>
/// <para>
/// That is how the old product ended up with progress reporting, cancellation and the performance
/// log all present, all correct, and all unused: each was introduced as
/// <c>IProgressPublisher? progressPublisher = null</c>, every call site took the default, and
/// nothing ever failed to say so. A mechanism nobody is obliged to use is a mechanism nobody uses.
/// </para>
/// <para>
/// The gate is stated in <c>docs/next/README.md</c> § Gates about service constructors. It is
/// enforced here as the wider rule — no production parameter at all — because the text scan cannot
/// tell a constructor from a method, and because the failure it prevents is the same either way.
/// A parameter that genuinely has no value passes a nullable type explicitly at the call site,
/// which puts the decision in the caller's diff rather than in the signature.
/// </para>
/// </summary>
public sealed class NullDefaultGateTests
{
    /// <summary>
    /// A parameter defaulted to <c>null</c>: a type, then the parameter name, then the literal,
    /// then the comma or closing parenthesis that can only follow it inside a parameter list.
    /// A field or local initialiser ends in a semicolon and so does not match.
    /// </summary>
    /// <remarks>
    /// <b>The type is part of the pattern because without it the gate fired on an object
    /// initialiser.</b> It was written as <c>=\s*null\s*[,)]</c>, on the stated reasoning that an
    /// initialiser ends in a semicolon - true of a field, false of a member inside an object
    /// initialiser, which ends in a comma like a parameter does. It therefore flagged
    /// <c>XmlResolver = null,</c> in <c>GroupPolicyPreferenceParser</c>, which is the setting that
    /// stops the parser resolving external entities in a Group Policy Preferences file. Satisfying
    /// the gate there would have removed an XXE defence from a security product to please a text
    /// scan.
    /// <para>
    /// A parameter default always names a type before the parameter; an object initialiser member
    /// never does. That is the whole difference, and it is what the pattern now requires. The class
    /// admits the characters a type can end with - a word character, <c>?</c> for a nullable,
    /// <c>&gt;</c> for a generic, <c>]</c> for an array.
    /// </para>
    /// </remarks>
    private static readonly Regex NullDefaultedParameter =
        new(@"[\w\?>\]]\s+\w+\s*=\s*null\s*[,)]", RegexOptions.Compiled);

    [Fact]
    public void NoProductionParameterDefaultsToNull()
    {
        var offenders = RebuildTree.ScanPattern(
            RebuildTree.ProductionFiles(), NullDefaultedParameter);

        Assert.True(
            offenders.Count == 0,
            "No parameter may default to null (docs/next/README.md, gate 1). A default of null "
            + "makes a collaborator optional without anyone deciding it should be, which is how "
            + "progress, cancellation and the performance log all became unused in the previous "
            + "implementation. Pass the value explicitly at each call site instead:"
            + Environment.NewLine + RebuildTree.Describe(offenders));
    }

    /// <summary>
    /// The gate read real files. Without this it passes by scanning an empty set, which is the
    /// failure the scanner self-tests exist to catch.
    /// </summary>
    [Fact]
    public void TheGateReadsRealProductionFiles()
    {
        var files = RebuildTree.ProductionFiles().ToList();

        Assert.True(
            files.Count > 0,
            $"Found no production .cs files under {Path.Combine(RebuildTree.Root(), "src")}.");
        Assert.Contains(files, f => f.EndsWith("AceNormalizer.cs", StringComparison.Ordinal));
    }

    /// <summary>
    /// The pattern recognises a defaulted null when one is present, and does not fire on the
    /// constructs that merely look similar. Asserted against literals rather than a temporary file,
    /// so the check needs no fixture on disk.
    /// </summary>
    [Theory]
    [InlineData("public Runner(IProgressPublisher? publisher = null)")]
    [InlineData("    IProgressPublisher? publisher = null,")]
    [InlineData("public void Run(CancellationToken? token = null) { }")]
    [InlineData("    Guid? objectType = null, Guid? inherited = null)")]
    public void ThePatternRecognisesADefaultedNull(string line)
    {
        Assert.Matches(NullDefaultedParameter, line);
    }

    [Theory]
    [InlineData("private string? _path = null;")]
    [InlineData("var parsed = Parse(bytes, null);")]
    [InlineData("return NormalizeGuid(guid) ?? null;")]
    [InlineData("Assert.Equal(null, result.OwnerSid);")]
    // The object initialiser that the original pattern flagged. A member assignment inside one
    // ends in a comma exactly as a parameter does, and names no type - which is what tells them
    // apart. This line is an XXE defence and must never be what a gate argues away.
    [InlineData("            XmlResolver = null,")]
    [InlineData("    Indent = null,")]
    public void ThePatternDoesNotFireOnSomethingElse(string line)
    {
        Assert.DoesNotMatch(NullDefaultedParameter, line);
    }
}
