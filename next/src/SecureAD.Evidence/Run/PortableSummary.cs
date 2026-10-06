using SecureAD.Evidence.Findings;
using SecureAD.Kernel;

namespace SecureAD.Evidence.Run;

/// <summary>
/// One stage of a run and how long it took.
/// </summary>
/// <param name="Name">The stage, as the product names it: connect, preflight, capture, seal.</param>
/// <param name="Milliseconds">How long it took.</param>
public readonly record struct StageTiming(string Name, long Milliseconds);

/// <summary>
/// One kind of failure and how often it happened.
/// </summary>
/// <remarks>
/// <b>The description is deliberately absent.</b> An <see cref="AuditError"/> carries a sentence
/// written for an operator, and a sentence about a directory failure routinely quotes the thing it
/// failed on - a distinguished name, an account, sometimes a server. The category, the code and the
/// severity say what kind of thing went wrong and how much it matters, which is what a reader
/// outside that environment can act on, and none of the three can carry a name.
/// </remarks>
/// <param name="Category">Which part of the product the failure came from.</param>
/// <param name="Code">The product's own code for it, stable across runs.</param>
/// <param name="Severity">How much it mattered.</param>
/// <param name="Count">How many times it happened.</param>
public readonly record struct ProblemCount(
    ErrorCategory Category,
    string Code,
    ErrorSeverity Severity,
    int Count);

/// <summary>
/// One domain of the forest, as the portable summary reports it.
/// </summary>
/// <remarks>
/// <para>
/// <b>The name is here because the owner allowed it on 2026-09-22, and nothing else identifying
/// is.</b> No controller, no site name, no address. It arrives through
/// <see cref="PortableNames.DomainNameOf"/>, which keeps only the domain components of a
/// distinguished name, so nothing else can ride along inside one.
/// </para>
/// <para>
/// <b><see cref="ControllerInOperatorSite"/> is a yes or no, never a host.</b> It exists for one
/// question: whether a domain was read from a controller beside the capture machine or across a
/// link. That is the whole of <c>P-258</c>, and answering it needs no name - which is why the
/// answer is a flag rather than the controller it is about. Null where the capture machine had no
/// site of its own to compare against, which is a real state and not a no.
/// </para>
/// </remarks>
/// <param name="DomainName">The domain, in DNS form.</param>
/// <param name="Outcome">What became of reading it.</param>
/// <param name="Objects">How many objects were read from it.</param>
/// <param name="AccessControlEntries">How many access control entries were read from it.</param>
/// <param name="ElapsedMilliseconds">How long reading it took.</param>
/// <param name="ControllerInOperatorSite">
/// Whether it was read from a controller in the capture machine's own site, or null where the
/// capture machine had no site.
/// </param>
public sealed record SummarisedDomain(
    string DomainName,
    DomainReadOutcome Outcome,
    long Objects,
    long AccessControlEntries,
    long ElapsedMilliseconds,
    bool? ControllerInOperatorSite);

/// <summary>What a capture did, in the form that may leave the customer's environment.</summary>
/// <remarks>
/// <b>Every field is a count, a duration, a product-defined word, or a domain name.</b> That is the
/// whole permitted vocabulary. A member that is none of those defeats the purpose of the type, and
/// <c>PortableSummaryLeakTests</c> exists to catch one if it is ever added.
/// </remarks>
/// <param name="ProductVersion">Which build produced this, so the numbers can be placed.</param>
/// <param name="Runtime">The .NET runtime, with no machine name.</param>
/// <param name="OperatingSystem">The operating system version, with no machine name.</param>
/// <param name="RunState">What became of the capture.</param>
/// <param name="ElapsedMilliseconds">How long the whole capture took.</param>
/// <param name="Stages">Where the time went.</param>
/// <param name="Domains">One row per domain the run knew about.</param>
/// <param name="Problems">What went wrong, by kind, and how often.</param>
public sealed record CaptureSummary(
    string ProductVersion,
    string Runtime,
    string OperatingSystem,
    RunState RunState,
    long ElapsedMilliseconds,
    IReadOnlyList<StageTiming> Stages,
    IReadOnlyList<SummarisedDomain> Domains,
    IReadOnlyList<ProblemCount> Problems);

/// <summary>What a derivation did.</summary>
/// <param name="State">What became of it, in the derivation's own vocabulary.</param>
/// <param name="ElapsedMilliseconds">How long it took.</param>
/// <param name="Principals">How many principals it knows about.</param>
/// <param name="NestingEdges">How many direct nesting relationships it holds.</param>
/// <param name="Phases">Where the time went inside it.</param>
/// <param name="Problems">What went wrong, by kind.</param>
public sealed record DerivationSummary(
    string State,
    long ElapsedMilliseconds,
    long Principals,
    long NestingEdges,
    IReadOnlyList<StageTiming> Phases,
    IReadOnlyList<ProblemCount> Problems);

/// <summary>One rule, and what became of it.</summary>
/// <param name="Rule">The rule's own identifier, which is a product name and not a forest one.</param>
/// <param name="Outcome">Whether it finished.</param>
/// <param name="Judged">How many objects it reached a verdict on.</param>
/// <param name="NotAbout">How many objects it was offered and had nothing to say about.</param>
/// <param name="Milliseconds">How long it spent.</param>
public readonly record struct RuleTiming(
    string Rule,
    string Outcome,
    long Judged,
    long NotAbout,
    long Milliseconds);

/// <summary>What a judging did.</summary>
/// <remarks>
/// <b>Findings are counted by severity and never listed.</b> A finding names the object it is
/// about, so the findings themselves stay in the bundle; how many there were of each kind is the
/// part that travels.
/// </remarks>
/// <param name="State">What became of it.</param>
/// <param name="ElapsedMilliseconds">How long it took.</param>
/// <param name="ObjectsJudged">How many captured objects were streamed through it.</param>
/// <param name="Phases">Where the time went, which is what <c>P-257</c> turns on.</param>
/// <param name="Rules">One row per scheduled rule.</param>
/// <param name="Findings">How many findings there were, by severity.</param>
/// <param name="Problems">What went wrong, by kind.</param>
public sealed record JudgingSummary(
    string State,
    long ElapsedMilliseconds,
    long ObjectsJudged,
    IReadOnlyList<StageTiming> Phases,
    IReadOnlyList<RuleTiming> Rules,
    IReadOnlyDictionary<Severity, int> Findings,
    IReadOnlyList<ProblemCount> Problems);

/// <summary>
/// Turns what the product holds into the only shapes the portable summary is allowed to carry.
/// </summary>
public static class PortableNames
{
    /// <summary>
    /// The domain a distinguished name belongs to, in DNS form, and nothing else from it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>A transform, not a passthrough, and that is the whole point.</b> The product holds
    /// partitions as distinguished names - <c>CN=Configuration,DC=ba,DC=ad,DC=lab</c> - and letting
    /// one through as text would carry whatever else happened to be in it. Only <c>DC=</c>
    /// components survive, so a container, an organisational unit or an object name cannot reach the
    /// summary inside a name, including in a shape nobody has thought of yet.
    /// </para>
    /// <para>
    /// The owner permitted domain names on 2026-09-22 and permitted nothing else. This is where that
    /// permission is spent - once, here, rather than at each caller.
    /// </para>
    /// </remarks>
    /// <param name="distinguishedName">The partition's distinguished name.</param>
    /// <returns>The domain in DNS form, or empty where the name had no domain components.</returns>
    public static string DomainNameOf(string distinguishedName)
    {
        ArgumentNullException.ThrowIfNull(distinguishedName);

        var parts = distinguishedName
            .Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
            .Where(part => part.StartsWith("DC=", StringComparison.OrdinalIgnoreCase))
            .Select(part => part[3..])
            .Where(part => part.Length > 0);

        return string.Join('.', parts);
    }
}
