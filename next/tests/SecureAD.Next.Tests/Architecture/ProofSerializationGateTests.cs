using System.Text.Json;
using System.Text.RegularExpressions;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using Xunit;

namespace SecureAD.Next.Tests.Architecture;

/// <summary>
/// Gate: a stored proof records enum names, and every store uses the same options to write and read.
/// </summary>
/// <remarks>
/// <para>
/// <b>What went wrong before.</b> <c>System.Text.Json</c> writes an enum as its ordinal by default,
/// so a value hashed into a fingerprint or rehydrated from a store meant what it meant only because
/// of the order somebody typed the members in. Removing an unused member from the middle of
/// <see cref="SecureAD.Derivation.Tier0Basis"/> would have renumbered the one added the day before
/// and changed the meaning of data already written, with no code change and no failure.
/// </para>
/// <para>
/// <b>A <c>[Flags]</c> enum is the sharper case, and it is why this gate exists rather than a
/// comment.</b> Inserting a member into <see cref="MembershipRouteIncompleteReason"/> renumbers the
/// bits of every later one, so a stored route recording <i>membership evidence was incomplete</i>
/// reads back as a different limitation - parsing cleanly, reporting confidently, and being wrong.
/// That is a check passing while measuring something other than what it claims.
/// </para>
/// <para>
/// <b>Two halves, because either alone would pass while the product was broken.</b> The first
/// asserts the options really pin names; the second asserts every stored-proof site uses them,
/// since options that exist and are not reached protect nothing. Two stores previously kept
/// read-only options and wrote with the defaults, which is exactly the shape the second half
/// catches.
/// </para>
/// </remarks>
public sealed partial class ProofSerializationGateTests
{
    /// <summary>The stores whose serialisation feeds a hash or is rehydrated from a database.</summary>
    /// <remarks>
    /// Named individually rather than scanned by folder: a file added to the judgement layer that
    /// serialises for display should not be dragged into this gate, and a stored-proof file that is
    /// added deliberately must be added here deliberately.
    /// </remarks>
    private static readonly string[] StoredProofFiles =
    [
        "SecureAD.Judgement/OwnershipAuditStorage.cs",
        "SecureAD.Judgement/OwnershipAuditValidation.cs",
        "SecureAD.Judgement/OwnershipAuditRun.cs",
        "SecureAD.Judgement/FullControlStorage.cs",
        "SecureAD.Judgement/FullControlEvaluator.cs",
        "SecureAD.Judgement/MemberAttributionStorage.cs",
        "SecureAD.Judgement/SelfMembershipStorage.cs",
        "SecureAD.Judgement/SelfMembershipCoverageStorage.cs",
        "SecureAD.Derivation/MembershipInputStorage.cs",
        "SecureAD.Derivation/Tier0Classifier.cs",
        "SecureAD.Evidence/BundleSealing.cs",
    ];

    [Fact]
    public void AStoredProofRecordsAnEnumByNameRatherThanByPosition()
    {
        // A [Flags] value, because that is the case where an ordinal change is silently wrong
        // rather than loudly absent.
        var summary = new MembershipRouteSummary([], MembershipRouteIncompleteReason.MembershipEvidenceIncomplete);

        var json = JsonSerializer.Serialize(summary, ProofSerialization.Options);

        Assert.Contains("MembershipEvidenceIncomplete", json, StringComparison.Ordinal);
    }

    [Fact]
    public void AStoredProofSurvivesARoundTripThroughTheSharedOptions()
    {
        var summary = new MembershipRouteSummary([], MembershipRouteIncompleteReason.MembershipEvidenceIncomplete);

        var restored = JsonSerializer.Deserialize<MembershipRouteSummary>(
            JsonSerializer.Serialize(summary, ProofSerialization.Options), ProofSerialization.Options);

        Assert.Equal(MembershipRouteIncompleteReason.MembershipEvidenceIncomplete, restored?.IncompleteReasons);
    }

    /// <summary>
    /// The negative control: the default options are what this gate exists to keep out of a store.
    /// </summary>
    /// <remarks>
    /// Without this, both assertions above would pass against a build whose options had quietly lost
    /// the converter, because a round trip is self-consistent either way. This pins the difference
    /// the gate is about: the default writes a number.
    /// </remarks>
    [Fact]
    public void TheDefaultOptionsWriteAPositionAndAreTheReasonThisGateExists()
    {
        var summary = new MembershipRouteSummary([], MembershipRouteIncompleteReason.MembershipEvidenceIncomplete);

        var json = JsonSerializer.Serialize(summary);

        Assert.DoesNotContain("MembershipEvidenceIncomplete", json, StringComparison.Ordinal);
    }

    [Fact]
    public void EveryStoredProofSerialisationNamesTheSharedOptions()
    {
        var offenders = new List<string>();

        foreach (var file in StoredProofFiles)
        {
            var path = Path.Combine(SourceRoot(), file.Replace('/', Path.DirectorySeparatorChar));
            Assert.True(File.Exists(path), $"{file} is named by this gate but does not exist; correct the list.");

            var text = File.ReadAllText(path);
            foreach (Match call in SerializerCalls().Matches(text))
            {
                if (!NamesTheOptions(call.Value))
                    offenders.Add($"{file}: {call.Value.Trim()}");
            }
        }

        Assert.True(offenders.Count == 0,
            "A stored proof is serialised with the default options, so an enum in it is written as a position "
            + "and its meaning depends on declaration order. Pass ProofSerialization.Options:"
            + Environment.NewLine + string.Join(Environment.NewLine, offenders));
    }

    /// <summary>
    /// Proves the scan above can fail, by running it against a call it must object to.
    /// </summary>
    /// <remarks>
    /// A pattern that matched nothing would report every file as clean for ever. This repository has
    /// shipped two gates that passed while measuring nothing, and neither was found by reading them.
    /// </remarks>
    [Theory]
    [InlineData("JsonSerializer.Serialize(value)", true)]
    [InlineData("JsonSerializer.Serialize(value, ProofSerialization.Options)", false)]
    [InlineData("JsonSerializer.Deserialize<Thing>(json)", true)]
    [InlineData("JsonSerializer.Deserialize<Thing>(json, ProofSerialization.Options)", false)]
    [InlineData("JsonSerializer.SerializeToNode(value)", true)]
    [InlineData("JsonSerializer.SerializeToUtf8Bytes(value, ProofSerialization.Options)", false)]
    // A nested call, which is what defeated the first version of the pattern.
    [InlineData("JsonSerializer.Serialize(Assess(a, b), ProofSerialization.Options)", false)]
    [InlineData("JsonSerializer.Serialize(Assess(a, b))", true)]
    // Trailing text belonging to the rest of the statement must not be read as part of the call.
    [InlineData("JsonSerializer.Deserialize<Thing>(json) ?? throw Invalid(ProofSerialization.Options)", true)]
    public void TheScanObjectsToACallThatOmitsTheOptions(string call, bool expectedToBeCaught)
    {
        var match = SerializerCalls().Match(call);
        Assert.True(match.Success, "The pattern matched no call at all, so it can object to nothing.");
        Assert.Equal(expectedToBeCaught, !NamesTheOptions(match.Value));
    }

    /// <summary>
    /// A <c>JsonSerializer</c> call whose argument list does not mention the shared options.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Matched on the text because the question is <i>which overload was written</i>, and a compiled
    /// call site does not record whether an options argument was supplied by name or by default.
    /// </para>
    /// <para>
    /// <b>The argument list is matched by balancing brackets rather than by running to the next
    /// bracket or semicolon.</b> A lazy scan to <c>)</c> stops at the first inner call's bracket and
    /// misses the options that follow it; a scan to <c>;</c> runs past the call into the rest of the
    /// statement and finds options belonging to something else. The first version of this gate did
    /// the second, and reported every already-corrected site as an offender - which at least failed
    /// loudly rather than passing while measuring nothing.
    /// </para>
    /// </remarks>
    [GeneratedRegex(
        @"JsonSerializer\.(?:Serialize|Deserialize|SerializeToNode|SerializeToUtf8Bytes)(?:<[^>]*>)?\((?:[^()]|(?<open>\()|(?<-open>\)))*(?(open)(?!))\)",
        RegexOptions.Singleline)]
    private static partial Regex SerializerCalls();

    /// <summary>Whether a matched call names the shared options.</summary>
    private static bool NamesTheOptions(string call) =>
        call.Contains("ProofSerialization.Options", StringComparison.Ordinal);

    private static string SourceRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !Directory.Exists(Path.Combine(directory.FullName, "src", "SecureAD.Judgement")))
            directory = directory.Parent;

        return Path.Combine(
            directory?.FullName ?? throw new DirectoryNotFoundException("The source root was not found."), "src");
    }
}
