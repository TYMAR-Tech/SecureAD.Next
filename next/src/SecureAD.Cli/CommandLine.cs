using System.Globalization;
using System.Resources;
using SecureAD.Kernel.Capture;

namespace SecureAD.Cli;

/// <summary>
/// What the operator asked for, once the arguments have been understood.
/// </summary>
/// <remarks>
/// <para>
/// <b>An operator may widen the shipped class scope, never narrow it.</b> P-224's Enatel inclusion
/// option restores three classes to the capture; it neither enables DNS nor requests credential
/// attributes. There is no arbitrary partition/class exclusion list and no choice of transport -
/// the connection ladder is not configurable, because an
/// operator who could pin a run to one rung could pin it to the bottom one.
/// </para>
/// <para>
/// <b>This said "three options and no more" until 2026-09-13</b>, when <c>--concurrent</c> arrived
/// and made the count wrong while leaving the rule untouched. The count was never the rule. What
/// the sentence was really holding is the line above it, and a ceiling on how many domains are read
/// at once passes that test: every domain of the forest is read at every setting, and a bundle
/// captured at one is indistinguishable from a bundle captured at another. What changes is how long
/// it takes and how hard this machine's disk works.
/// </para>
/// <para>
/// <b>The run library root is required and there is no default.</b> That is
/// <c>docs/decisions/0025-the-run-library-is-a-managed-root.md</c>, and it is the one thing here
/// worth being strict about: a tool that picks its own home for several gigabytes of evidence is a
/// tool that fills the wrong disk, which the predecessor did by hardcoding a path into two
/// constructors.
/// </para>
/// </remarks>
/// <param name="LibraryRoot">
/// The directory every run is created inside. Null only when <paramref name="PreviewOnly"/> is set,
/// because a preview writes nothing and must not create anything either.
/// </param>
/// <param name="Forest">
/// A forest or domain name to enter by, used only when this machine cannot find a forest of its
/// own. Null for the ordinary case.
/// </param>
/// <param name="Overrides">
/// Controllers named for particular domains, keyed by the domain's DNS name as typed. Per run and
/// never stored, per <c>docs/decisions/0047-settings-are-per-user-and-per-machine.md</c>.
/// </param>
/// <param name="ValidateOnly">Check the run would work, without reading any object.</param>
/// <param name="PreviewOnly">Print what would be read and from where, contacting no domain.</param>
/// <param name="CaptureOnly">
/// Read the forest and seal the bundle, stopping before anything is derived or judged.
/// </param>
/// <param name="DeriveOnly">Derive from a bundle already captured, capturing nothing.</param>
/// <param name="JudgeOnly">Judge a bundle already captured and derived, capturing nothing.</param>
/// <param name="Concurrency">
/// How many domains to read at the same time, or null where the operator did not say and the
/// capture uses its own default.
///
/// <para>
/// <b>It is not read from the settings file and never written to it</b>, per
/// <c>docs/decisions/0047-settings-are-per-user-and-per-machine.md</c>. A scheduled capture does
/// what its command line says rather than inheriting a number from the profile of whoever last used
/// the window on that machine.
/// </para>
/// <para>
/// <b>It governs this machine, not any controller.</b> Every domain in flight writes a database of
/// its own, so what it spends is local disk - <c>0041</c> as amended. Lowering it makes a capture
/// slower and never gentler on a directory.
/// </para>
/// </param>
internal sealed record CommandLine(
    string? LibraryRoot,
    string? Forest,
    IReadOnlyDictionary<string, string> Overrides,
    bool ValidateOnly,
    bool PreviewOnly,
    bool CaptureOnly,
    string? DeriveOnly,
    string? JudgeOnly,
    int? Concurrency)
{
    /// <summary>The bundle to report the contents of, or null when none was asked for.</summary>
    public string? DescribeOnly { get; init; }

    /// <summary>
    /// Whether the description should measure where the bytes went.
    /// </summary>
    /// <remarks>
    /// Separate from <see cref="DescribeOnly"/> because it costs a full read of the evidence file.
    /// The counts alone answer in seconds; this reads every row of every table, which on a bundle
    /// of tens of gigabytes is a job to leave running rather than one to wait for.
    /// </remarks>
    public bool Sizes { get; init; }
    private static readonly ResourceManager ScopeWording = new(
        "SecureAD.Cli.Resources.CaptureObjectScope", typeof(CommandLine).Assembly);

    public bool IncludeEnatelSso { get; init; }
    public bool ScanGppPasswords { get; init; }
    public CaptureObjectScope ObjectScope => CaptureObjectScope.For(IncludeEnatelSso);
    public string ClassScopeDescription => string.Format(CultureInfo.CurrentCulture,
        ScopeText("ExcludedClasses"), string.Join(", ", ObjectScope.ExcludedClasses));

    private static string ScopeText(string key) =>
        ScopeWording.GetString(key, CultureInfo.CurrentUICulture) ?? throw new InvalidOperationException(key);

    /// <summary>
    /// What to print when the arguments were not understood.
    /// </summary>
    /// <remarks>
    /// It names the run library rather than describing it, because an operator reading this at the
    /// moment a scheduled run failed needs to know what to type, not what the design is.
    /// </remarks>
    public static string Usage =>
        string.Join(
            Environment.NewLine,
            "Reads an Active Directory forest into a sealed evidence bundle.",
            string.Empty,
            "  securead --library <directory> [--forest <name>] [--concurrent <count>]",
            "           [--controller <domain>=<host>]... [--validate | --preview | --capture]",
            "           [--include-enatel-sso]",
            "           [--scan-gpp-passwords]",
            "  securead --derive <bundle directory>",
            "  securead --judge <bundle directory>",
            "  securead --describe <bundle directory> [--sizes]",
            string.Empty,
            "  --library     Where runs are kept. Created if absent. Required for a run or a",
            "                validate: this tool does not choose where several gigabytes of",
            "                evidence go. Not needed for --preview, which writes nothing.",
            "  --forest      Only for a machine that is not joined to the forest being audited, or",
            "                an operator auditing someone else's. Otherwise the run finds the",
            "                forest this machine is already in and needs no name at all.",
            "  --controller  Read one domain from the controller named, instead of the one ranking",
            "                would choose: --controller contoso.com=DC01.contoso.com. Repeat it per",
            "                domain. It applies to this run only and is never remembered. A",
            "                controller that does not serve the domain named stops the run rather",
            "                than being quietly replaced.",
            "  --concurrent  How many domains to read at the same time. Nine by default. This",
            "                governs THIS machine, not your domain controllers: each domain being",
            "                read writes its own database here, so it is the local disk it spends.",
            "                Every controller is read exactly as it would be at any other setting.",
            "                Lower it only for a slow or shared disk - it makes a capture take",
            "                longer and never makes it gentler on the directory. One or more.",
            ScopeText("Usage"),
            "  --validate    Connect, discover the forest and ask every domain's controller what",
            "                it can do, without reading a single object. Every domain is asked, and",
            "                every answer is reported. Seconds, rather than hours.",
            "  --preview     Print which controller each domain would be read from, its site, what",
            "                the run would fall back to, and any domain the forest names no",
            "                controller for. Contacts no domain's controller.",
            "  --capture     Read the forest and seal the bundle, then stop, without deriving or",
            "                judging it. The bundle is complete evidence and can be derived and",
            "                judged later, here or on another machine. Use it to find out what a",
            "                capture of this forest costs, or to take the reading now and analyse",
            "                it when there is time.",
            "  --derive      Derive from a bundle that has already been captured, without capturing",
            "                anything. Contacts no controller and opens the evidence read-only. Use",
            "                it to derive again after this tool has learned something new, or to",
            "                derive a bundle captured elsewhere. Any earlier derivation in that",
            "                bundle is replaced; the evidence is never written to.",
            "  --describe    Report what a sealed bundle holds: how much was captured, whether",
            "                security descriptors are being stored once and shared, and everything",
            "                that could not be read - including every Group Policy object that was",
            "                missed and what the file system said about it. Contacts nothing and",
            "                writes nothing, so it is safe against the only copy of a bundle.",
            "  --sizes       Only with --describe. Also measure which tables the bundle's bytes went",
            "                into. This reads every row, so on a large bundle it is a job to leave",
            "                running rather than one to wait for.");

    /// <summary>
    /// Reads the arguments, or returns null when they were not understood.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Null rather than a thrown exception or a <c>Result</c>: there is exactly one caller, it is
    /// twenty lines away, and the only thing it can do about a bad argument is print the usage and
    /// stop. Wrapping that in an error type would add a vocabulary nobody reads.
    /// </para>
    /// <para>
    /// <b>An unrecognised argument is refused rather than ignored.</b> An operator who mistypes an
    /// option and has it silently dropped gets a run that did something other than what he asked
    /// for, and no indication of it until he reads the bundle. A malformed <c>--controller</c> and
    /// the same domain named twice are refused for the same reason.
    /// </para>
    /// </remarks>
    /// <param name="args">The arguments as the runtime supplied them.</param>
    public static CommandLine? Parse(string[] args)
    {
        ArgumentNullException.ThrowIfNull(args);

        string? library = null;
        string? forest = null;
        var overrides = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var validateOnly = false;
        var previewOnly = false;
        var captureOnly = false;
        string? deriveOnly = null;
        string? judgeOnly = null;
        string? describeOnly = null;
        var sizes = false;
        int? concurrency = null;
        var includeEnatelSso = false;
        var scanGppPasswords = false;

        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--include-enatel-sso":
                    includeEnatelSso = true;
                    break;

                case "--scan-gpp-passwords":
                    scanGppPasswords = true;
                    break;

                case "--library" when i + 1 < args.Length:
                    library = args[++i];
                    break;

                case "--forest" when i + 1 < args.Length:
                    forest = args[++i];
                    break;

                case "--controller" when i + 1 < args.Length:
                    if (!TryAddOverride(overrides, args[++i]))
                    {
                        return null;
                    }

                    break;

                // Zero is refused here rather than clamped, and it is the value that matters: a
                // capture bounded at zero waits for ever while looking exactly like one that is
                // working - 0041. A negative or non-numeric value is refused for the same reason
                // a malformed --controller is, below: an operator whose typo is quietly ignored
                // gets a run that did something other than what he asked for.
                case "--concurrent" when i + 1 < args.Length:
                    if (!int.TryParse(
                            args[++i],
                            System.Globalization.NumberStyles.Integer,
                            System.Globalization.CultureInfo.InvariantCulture,
                            out var wanted)
                        || wanted < 1)
                    {
                        return null;
                    }

                    concurrency = wanted;
                    break;

                case "--validate":
                    validateOnly = true;
                    break;

                case "--preview":
                    previewOnly = true;
                    break;

                case "--capture":
                    captureOnly = true;
                    break;

                case "--derive" when i + 1 < args.Length:
                    deriveOnly = args[++i];
                    break;

                case "--judge" when i + 1 < args.Length:
                    judgeOnly = args[++i];
                    break;

                case "--describe" when i + 1 < args.Length:
                    describeOnly = args[++i];
                    break;

                case "--sizes":
                    sizes = true;
                    break;

                default:
                    return null;
            }
        }

        // --derive, --judge and --describe each read a bundle that already exists, so none needs a
        // library to write runs into nor a forest to contact. Naming one alongside them asks for two
        // different things at once, and guessing which was meant is how an operator ends up with a
        // capture he did not ask for. They are also mutually exclusive: a bundle is derived and then
        // judged, in that order, and one command doing both silently would hide which half failed.
        // --describe joins them rather than standing apart because it is the same kind of verb - it
        // names a bundle, contacts nothing, and writes nothing.
        if (deriveOnly is not null || judgeOnly is not null || describeOnly is not null)
        {
            var named = deriveOnly ?? judgeOnly ?? describeOnly;
            var verbs =
                (deriveOnly is not null ? 1 : 0)
                + (judgeOnly is not null ? 1 : 0)
                + (describeOnly is not null ? 1 : 0);

            var contradicted =
                validateOnly
                || previewOnly
                || captureOnly
                || library is not null
                || forest is not null
                || overrides.Count > 0
                || concurrency is not null
                || includeEnatelSso
                || scanGppPasswords
                || verbs > 1
                // --sizes governs what a description measures, and nothing else performs a
                // measurement to govern. Refused rather than ignored beside --derive or --judge,
                // on the same grounds as --concurrent beside --validate below: an operator who
                // states a flag and is silently not given it has been failed by this file.
                || (sizes && describeOnly is null);

            return contradicted || string.IsNullOrWhiteSpace(named)
                ? null
                : new CommandLine(
                    library, forest, overrides, validateOnly, previewOnly, captureOnly, deriveOnly,
                    judgeOnly, concurrency) { DescribeOnly = describeOnly, Sizes = sizes };
        }

        // --sizes outside a description governs nothing at all, and is refused for the same reason.
        if (sizes)
        {
            return null;
        }

        // --preview writes nothing, so it does not need somewhere to write to. Requiring a library
        // for it would create a directory during what is meant to be a read-only look.
        //
        // --capture DOES need one, because it seals a bundle like any other run - it stops after
        // the seal rather than doing less of a capture. Naming it beside --validate or --preview is
        // asking for a run and for no run at once, which is refused rather than resolved: an
        // operator who meant to look and instead read a forest for two hours has been failed by
        // this file.
        // --concurrent bounds the pass that reads the domains, and neither --validate nor --preview
        // performs one: a preview contacts nothing at all, and a validate asks each controller the
        // four questions without reading an object. So a ceiling given beside either governs
        // nothing. It is refused rather than ignored, on the same grounds as the contradictions
        // above - an operator who states a number and is silently not given it has been failed by
        // this file.
        if ((string.IsNullOrWhiteSpace(library) && !previewOnly)
            || (validateOnly && previewOnly)
            || (captureOnly && (validateOnly || previewOnly))
            || (concurrency is not null && (validateOnly || previewOnly))
            || (scanGppPasswords && (validateOnly || previewOnly)))
        {
            return null;
        }

        return new CommandLine(
            library, forest, overrides, validateOnly, previewOnly, captureOnly, DeriveOnly: null,
            JudgeOnly: null, concurrency)
        {
            IncludeEnatelSso = includeEnatelSso,
            ScanGppPasswords = scanGppPasswords,
        };
    }

    /// <summary>
    /// Reads one <c>domain=host</c> pair.
    /// </summary>
    /// <remarks>
    /// The same domain named twice is refused rather than last-one-wins. An operator who repeats a
    /// domain has contradicted himself, and choosing one of the two for him means a run reading from
    /// a controller he also asked it not to use.
    /// </remarks>
    private static bool TryAddOverride(Dictionary<string, string> overrides, string argument)
    {
        var separator = argument.IndexOf('=', StringComparison.Ordinal);
        if (separator <= 0 || separator == argument.Length - 1)
        {
            return false;
        }

        var domain = argument[..separator].Trim();
        var host = argument[(separator + 1)..].Trim();

        if (string.IsNullOrWhiteSpace(domain) || string.IsNullOrWhiteSpace(host))
        {
            return false;
        }

        return overrides.TryAdd(domain, host);
    }
}
