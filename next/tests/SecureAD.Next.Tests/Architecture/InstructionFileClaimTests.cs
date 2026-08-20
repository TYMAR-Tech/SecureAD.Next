using Xunit;

namespace SecureAD.Next.Tests.Architecture;

/// <summary>
/// The factual claims in <c>.github/copilot-instructions.md</c>, held to the repository.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why this exists.</b> That file is the first thing every session reads, so a wrong statement
/// in it costs more than a wrong statement anywhere else. Nothing checked it, and on 2026-09-XX
/// it was found to describe four types as "deliberately surviving" that do not exist in this
/// repository at all, to name a producer member that is not a member of anything, to claim a
/// reflection guard that had never been written, and to give hang-detection timings for a test
/// project that is not here.
/// </para>
/// <para>
/// Only claims with a yes or no answer are checked. The guidance - make decisions yourself, what
/// stops the work, what counts as settled - is judgement, is not testable, and was never the part
/// that went wrong.
/// </para>
/// </remarks>
public sealed class InstructionFileClaimTests
{
    private static string Instructions() =>
        Path.Combine(RepositoryLocation.Root(), ".github", "copilot-instructions.md");

    private static string Repo(params string[] parts) =>
        Path.Combine([RepositoryLocation.Root(), .. parts]);

    /// <summary>
    /// Everything the file says was removed is genuinely absent from the product's source. If one
    /// came back, the file would be telling every session not to reintroduce something that is
    /// already there.
    /// </summary>
    [Theory]
    [InlineData("RunSnapshotAsync")]
    [InlineData("RunConfigurationAuditAsync")]
    [InlineData("ConfigurationModeRunner")]
    [InlineData("ForConfigurationMode")]
    [InlineData("FromComponents")]
    public void WhatTheInstructionsSayWasRemovedIsAbsent(string member)
    {
        var offenders = Directory
            .EnumerateFiles(Repo("next", "src"), "*.cs", SearchOption.AllDirectories)
            .Where(f => File.ReadAllText(f).Contains(member, StringComparison.Ordinal))
            .Select(f => Path.GetFileName(f))
            .ToArray();

        Assert.True(
            offenders.Length == 0,
            $"copilot-instructions.md says '{member}' was removed and must not come back, but it "
            + "is in: " + string.Join(", ", offenders));
    }

    /// <summary>
    /// Documents the file points at are documents that exist. A session told to read a governing
    /// document that is not there either guesses or gives up, and both were observed.
    /// </summary>
    [Fact]
    public void EveryDocumentTheInstructionsPointAtIsThere()
    {
        var text = File.ReadAllText(Instructions());

        var missing = System.Text.RegularExpressions.Regex
            .Matches(text, @"`(docs/[A-Za-z0-9_./*-]+?\.md)`")
            .Select(m => m.Groups[1].Value)
            .Where(p => !p.Contains('*', StringComparison.Ordinal))
            .Distinct(StringComparer.Ordinal)
            .Where(p => !File.Exists(Repo(p.Replace('/', Path.DirectorySeparatorChar))))
            .OrderBy(p => p, StringComparer.Ordinal)
            .ToArray();

        Assert.True(
            missing.Length == 0,
            "copilot-instructions.md cites documents that are not in this repository:"
            + Environment.NewLine + string.Join(Environment.NewLine, missing));
    }

    /// <summary>
    /// The file names one test project and says the suite runs in well under a minute. If a second
    /// project appears, that guidance stops being true and the hang advice with it.
    /// </summary>
    [Fact]
    public void TheSuiteIsTheOneProjectTheInstructionsDescribe()
    {
        var projects = Directory
            .EnumerateFiles(Repo("next", "tests"), "*.csproj", SearchOption.AllDirectories)
            .Select(Path.GetFileNameWithoutExtension)
            .ToArray();

        Assert.Single(projects);
        Assert.Equal("SecureAD.Next.Tests", projects[0]);
    }

    /// <summary>
    /// The scanner self-test. Without it the checks above pass by reading an empty file and
    /// finding nothing wrong with it.
    /// </summary>
    [Fact]
    public void TheCheckReadsTheInstructionFile()
    {
        var text = File.ReadAllText(Instructions());

        Assert.True(text.Length > 5000, $"Read only {text.Length} characters of instructions.");
        Assert.Contains("Who you are working with", text, StringComparison.Ordinal);
        Assert.Contains("When to stop and raise it", text, StringComparison.Ordinal);
    }
}
