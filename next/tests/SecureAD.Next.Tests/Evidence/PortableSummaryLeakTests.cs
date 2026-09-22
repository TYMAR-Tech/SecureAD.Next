using System.Reflection;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Evidence.Run;
using SecureAD.Kernel;
using Xunit;

namespace SecureAD.Next.Tests.Evidence;

/// <summary>
/// The portable summary, and the one thing it promises.
/// </summary>
/// <remarks>
/// <para>
/// <b>This file leaves the customer's environment, which nothing else about a run does.</b> The run
/// log holds the forest, the controller each partition was read from, naming contexts as
/// distinguished names and the directory's own words when something failed, and a customer is right
/// to keep all of it. The summary exists so something can come back at all - and a summary that
/// claimed to be free of those things and was not would be worse than sending nothing, because
/// somebody would act on the claim.
/// </para>
/// <para>
/// <b>So the checks below are not about formatting.</b> They are about whether a value the owner
/// has forbidden can reach the file, by any route anybody has thought of.
/// </para>
/// </remarks>
public sealed class PortableSummaryLeakTests
{
    /// <summary>
    /// Values from a real forest, spelled the way the product actually holds them.
    /// </summary>
    private const string Controller = "dc01.ba.ad.lab";
    private const string PartitionDn = "CN=Configuration,DC=ba,DC=ad,DC=lab";
    private const string ObjectDn = "CN=Domain Admins,CN=Users,DC=ba,DC=ad,DC=lab";

    /// <summary>
    /// A distinguished name gives up its domain and nothing else.
    /// </summary>
    /// <remarks>
    /// The transform is the only route a name reaches the file by, so this is the case that matters
    /// most: everything to the left of the domain components must be gone, not escaped, not
    /// shortened.
    /// </remarks>
    [Fact]
    public void ADistinguishedNameYieldsItsDomainAndNothingElse() =>
        Assert.Equal("ba.ad.lab", PortableNames.DomainNameOf(ObjectDn));

    [Fact]
    public void APartitionNameYieldsItsDomainAndNothingElse() =>
        Assert.Equal("ba.ad.lab", PortableNames.DomainNameOf(PartitionDn));

    /// <summary>
    /// An organisational unit is a place in the customer's business and must not survive either.
    /// </summary>
    [Fact]
    public void AnOrganisationalUnitDoesNotSurviveTheTransform()
    {
        var name = PortableNames.DomainNameOf("OU=Finance Servers,DC=ba,DC=ad,DC=lab");

        Assert.Equal("ba.ad.lab", name);
        Assert.DoesNotContain("Finance", name, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// A name with no domain components yields nothing rather than passing itself through.
    /// </summary>
    /// <remarks>
    /// The negative control for the transform. Without it, a change that simply returned its input
    /// when it found no <c>DC=</c> would satisfy every case above.
    /// </remarks>
    [Fact]
    public void ANameWithNoDomainComponentsYieldsNothing() =>
        Assert.Equal(string.Empty, PortableNames.DomainNameOf("CN=Domain Admins,CN=Users"));

    /// <summary>
    /// Nothing forbidden reaches the written file, checked against the values themselves.
    /// </summary>
    /// <remarks>
    /// <b>Anchored to what a forest actually holds, not to what the writer believes it kept.</b>
    /// The summary is built the way a capture builds it - domain names through the transform - and
    /// then the file is searched for the controller, the partition name and the object name that
    /// were in play. A check that asked the writer what it had written would agree with itself
    /// whatever it did.
    /// </remarks>
    [Fact]
    public void TheWrittenFileHoldsNoControllerPartitionOrObjectName()
    {
        var directory = ADirectory();

        Written(PortableSummaryFile.WriteCapture(directory, ACapture()));
        Written(PortableSummaryFile.AppendDerivation(directory, ADerivation()));
        Written(PortableSummaryFile.AppendJudging(directory, AJudging()));

        var written = File.ReadAllText(BundleLayout.PortableSummaryPath(directory));

        Assert.DoesNotContain(Controller, written, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("CN=", written, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("OU=", written, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Domain Admins", written, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// The domain the owner allowed does reach the file.
    /// </summary>
    /// <remarks>
    /// The negative control for the test above, which would pass just as well against a writer that
    /// produced an empty file.
    /// </remarks>
    [Fact]
    public void TheDomainNameTheOwnerAllowedDoesReachTheFile()
    {
        var directory = ADirectory();

        PortableSummaryFile.WriteCapture(directory, ACapture());

        Assert.Contains(
            "ba.ad.lab",
            File.ReadAllText(BundleLayout.PortableSummaryPath(directory)),
            StringComparison.Ordinal);
    }

    /// <summary>
    /// Every piece of text the summary can carry was allowed by name.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>This is the check that catches the field nobody has added yet.</b> Numbers, enumerations
    /// and durations cannot carry a forest name; text can. So every string-typed member of every
    /// summary record is held against a list somebody wrote down, and a new one - <c>Controller</c>,
    /// <c>Site</c>, <c>Message</c>, whatever it turns out to be - fails here on the day it is added
    /// rather than on the day a file reaches a customer with it inside.
    /// </para>
    /// <para>
    /// Adding a member to this list is the moment to ask whether it can hold a name. That question
    /// being asked at all is the point of the test.
    /// </para>
    /// </remarks>
    [Fact]
    public void EveryTextMemberOfTheSummaryWasAllowedByName()
    {
        string[] allowed =
        [
            nameof(CaptureSummary.ProductVersion),
            nameof(CaptureSummary.Runtime),
            nameof(CaptureSummary.OperatingSystem),
            nameof(StageTiming.Name),
            nameof(ProblemCount.Code),
            nameof(SummarisedDomain.DomainName),
            nameof(DerivationSummary.State),
            nameof(RuleTiming.Rule),
            nameof(RuleTiming.Outcome),
        ];

        var text = Types()
            .SelectMany(type => type.GetProperties(BindingFlags.Public | BindingFlags.Instance))
            .Where(property => property.PropertyType == typeof(string))
            .Select(property => property.Name)
            .Distinct()
            .Where(name => !allowed.Contains(name, StringComparer.Ordinal))
            .ToArray();

        Assert.Empty(text);
    }

    /// <summary>
    /// The check above is looking at something. A gate scanning nothing passes every time.
    /// </summary>
    [Fact]
    public void TheTextCheckIsActuallyReadingTheSummaryTypes()
    {
        var found = Types()
            .SelectMany(type => type.GetProperties(BindingFlags.Public | BindingFlags.Instance))
            .Count(property => property.PropertyType == typeof(string));

        Assert.True(found >= 8, $"Only {found} text members were found across the summary types.");
    }

    private static Type[] Types() =>
    [
        typeof(CaptureSummary),
        typeof(DerivationSummary),
        typeof(JudgingSummary),
        typeof(StageTiming),
        typeof(ProblemCount),
        typeof(RuleTiming),
        typeof(SummarisedDomain),
    ];

    private static CaptureSummary ACapture() => new(
        "0.1.0+test",
        ".NET 10.0.0",
        "Microsoft Windows 10.0.26100",
        RunState.Sealed,
        11_640_000,
        [new StageTiming("connect", 4_112), new StageTiming("capture", 9_214_551)],
        [
            new SummarisedDomain(
                PortableNames.DomainNameOf(PartitionDn),
                DomainReadOutcome.Read,
                41_002,
                1_104_551,
                1_104_551,
                ControllerInOperatorSite: false),
        ],
        [new ProblemCount(ErrorCategory.Capture, "ReferralNotFollowed", ErrorSeverity.Degraded, 2)]);

    private static DerivationSummary ADerivation() => new(
        "Completed", 141_002, 112_004, 318_229, [new StageTiming("MembershipAndNesting", 120_001)], []);

    private static JudgingSummary AJudging() => new(
        "Completed",
        49_919,
        347_118,
        [new StageTiming("object pass", 21_341)],
        [new RuleTiming("SEC-001", "Completed", 347_118, 0, 1_204)],
        new Dictionary<Severity, int>(),
        []);

    /// <summary>
    /// A directory of its own per test, never cleaned up, so a failure can be looked at afterwards.
    /// </summary>
    private static string ADirectory() =>
        Path.Combine(Path.GetTempPath(), "securead-summary-" + Guid.NewGuid().ToString("N"));

    /// <summary>
    /// A write that failed would leave an empty file, and an empty file passes every leak check.
    /// </summary>
    private static void Written(Result<string> result) =>
        Assert.True(result.IsSuccess, result.IsSuccess ? string.Empty : result.Error.Description);
}
