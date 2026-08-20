namespace SecureAD.Cli;

/// <summary>
/// What the operator asked for, once the arguments have been understood.
/// </summary>
/// <remarks>
/// <para>
/// <b>Three options and no more.</b> Anything an operator could set that changes what a bundle
/// contains would be a scope, and <c>docs/decisions/0052-the-domain-is-the-only-unit-of-scope.md</c>
/// refuses one: nothing an operator can set makes a run smaller. So there is no partition list, no
/// exclusion, and no choice of transport - the connection ladder is not configurable, because an
/// operator who could pin a run to one rung could pin it to the bottom one.
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
internal sealed record CommandLine(
    string? LibraryRoot,
    string? Forest,
    IReadOnlyDictionary<string, string> Overrides,
    bool ValidateOnly,
    bool PreviewOnly)
{
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
            "  securead --library <directory> [--forest <name>]",
            "           [--controller <domain>=<host>]... [--validate | --preview]",
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
            "  --validate    Connect, discover the forest and ask every domain's controller what",
            "                it can do, without reading a single object. Every domain is asked, and",
            "                every answer is reported. Seconds, rather than hours.",
            "  --preview     Print which controller each domain would be read from, its site, what",
            "                the run would fall back to, and any domain the forest names no",
            "                controller for. Contacts no domain's controller.");

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

        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
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

                case "--validate":
                    validateOnly = true;
                    break;

                case "--preview":
                    previewOnly = true;
                    break;

                default:
                    return null;
            }
        }

        // --preview writes nothing, so it does not need somewhere to write to. Requiring a library
        // for it would create a directory during what is meant to be a read-only look.
        if ((string.IsNullOrWhiteSpace(library) && !previewOnly) || (validateOnly && previewOnly))
        {
            return null;
        }

        return new CommandLine(library, forest, overrides, validateOnly, previewOnly);
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
