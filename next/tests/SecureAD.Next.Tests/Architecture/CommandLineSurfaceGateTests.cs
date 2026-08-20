using System.Reflection;
using Xunit;

namespace SecureAD.Next.Tests.Architecture;

/// <summary>
/// The console executable's surface is its command line, and it stays that way.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why this project is not in <see cref="RebuildAssemblies"/>.</b> The architecture gates that
/// reflect over the product - the surface register at gate 5a and the vouched-return rule at gate 4
/// - ask questions about public types. A command-line executable has no public types worth asking
/// about: what it offers the world is three options and four exit codes. Adding it to the covered
/// list would mean registering its argument parser in <c>SURFACE-REGISTER.md</c> as though
/// something might come to depend on it.
/// </para>
/// <para>
/// <b>But an assembly outside the gates is an assembly that escapes them</b>, and this repository
/// has already had one component drop out of gate coverage without anyone noticing - <c>F-S24-4</c>.
/// So the exemption is held to its own terms: the project may stay outside the reflected set only
/// for as long as it exports nothing. The day it exports a type, this fails and the choice has to
/// be made again deliberately.
/// </para>
/// </remarks>
public sealed class CommandLineSurfaceGateTests
{
    /// <summary>
    /// The executable, named by a type that cannot leave it.
    /// </summary>
    /// <remarks>
    /// Reached by name rather than by a type reference, because every type in it is internal and
    /// there is therefore nothing to write <c>typeof</c> against - which is the property this gate
    /// exists to hold.
    ///
    /// <para>
    /// <b>The name must track <c>SecureAD.Cli.csproj</c>.</b> It is <c>securead-cli</c> rather than
    /// <c>securead</c> because the window publishes as <c>SecureAD</c>, and both Windows filenames
    /// and assembly resolution are case-insensitive: the two would be one name, and this gate would
    /// load whichever assembly it found first. It did exactly that once, and reported the window's
    /// public types as the command line's exported surface.
    /// </para>
    /// </remarks>
    private static Assembly CommandLineAssembly() =>
        Assembly.Load("securead-cli");

    [Fact]
    public void TheCommandLineProjectExportsNothing()
    {
        var exported = CommandLineAssembly()
            .GetExportedTypes()
            .Select(t => "  " + t.FullName)
            .OrderBy(t => t, StringComparer.Ordinal)
            .ToList();

        Assert.True(
            exported.Count == 0,
            "The command-line project exports public types. Its surface is meant to be a command "
            + "line, which is why it sits outside the assemblies the architecture gates reflect "
            + "over. A public type here is covered by no gate at all: it is in neither "
            + "SURFACE-REGISTER.md nor the vouched-return rule. Either make it internal, or add "
            + "the assembly to RebuildAssemblies and register what it exports:"
            + Environment.NewLine + string.Join(Environment.NewLine, exported));
    }

    /// <summary>
    /// The scanner self-test. Without it the check above passes by loading nothing and finding no
    /// exported types in it - which is the failure this repository has now committed four times.
    /// </summary>
    [Fact]
    public void TheGateReadsTheRealCommandLineAssembly()
    {
        var assembly = CommandLineAssembly();

        var declared = assembly.GetTypes();

        Assert.True(
            declared.Length > 0,
            "Loaded the command-line assembly and found no types in it at all, so the check above "
            + "would pass against nothing.");

        Assert.Contains(declared, t => t.Name == "Program");
        Assert.Contains(declared, t => t.Name == "CommandLine");
    }
}
