using CommunityToolkit.Mvvm.ComponentModel;
using SecureAD.Audit.Connect;
using SecureAD.Kernel;

namespace SecureAD.Shell.Settings;

/// <summary>
/// How many domains this machine reads at the same time, as one answer shared by everything that
/// asks.
/// </summary>
/// <remarks>
/// <para>
/// <b>It governs this machine and never the directory.</b> Reading domains at once does not make any
/// one controller work harder than reading them in turn - the same objects are fetched from the same
/// machines, at the same rate, over the same serial per-host conversation. What changes is the load
/// on the computer running the audit, because every domain in flight writes a database of its own.
/// That is the entire reason this may be a setting at all when
/// <c>docs/decisions/0041-capture-reads-domains-in-parallel.md</c> refuses a rate limit, and the
/// reasoning is carried in full on
/// <see cref="DirectoryConnectionSettings.DefaultDomainsAtOnce"/>.
/// </para>
/// <para>
/// <b>Lowering it makes a capture slower and never safer.</b> Anything presenting it to an operator
/// as a politeness dial has misread it.
/// </para>
/// <para>
/// <b>A second settings object over one file, and the fields are disjoint.</b>
/// <see cref="RunLibraryLocation"/> owns the path and this owns the ceiling; neither holds a copy of
/// the other's value, and both write by reading the file back and replacing only their own field. So
/// there is still exactly one owner per setting, which is what that class's own remark requires. Two
/// objects each holding the whole record is the arrangement that would disagree, and it is the one
/// avoided here.
/// </para>
/// </remarks>
internal sealed partial class DomainConcurrency : ObservableObject
{
    private readonly IShellSettingsStore _store;

    [ObservableProperty]
    private int? _chosen;

    [ObservableProperty]
    private string? _problem;

    /// <summary>Creates the ceiling over <paramref name="store"/>.</summary>
    /// <param name="store">Where the operator's choice is kept.</param>
    public DomainConcurrency(IShellSettingsStore store)
    {
        ArgumentNullException.ThrowIfNull(store);

        _store = store;
    }

    /// <summary>The fewest domains a capture may be told to read at once.</summary>
    /// <remarks>
    /// <b>Zero is not a slower capture; it is a capture that never finishes.</b> It would wait for
    /// ever while looking precisely like one that is working, which is why
    /// <see cref="DirectoryConnectionSettings"/> refuses it at construction and why the screen
    /// refuses it before anything is stored.
    /// </remarks>
    public const int Fewest = 1;

    /// <summary>
    /// The ceiling a capture will actually use - what the operator chose, or the default where he
    /// has not chosen.
    /// </summary>
    /// <remarks>
    /// <b>Never null, because a capture cannot be started with an unanswered question.</b> The
    /// distinction between <i>not chosen</i> and <i>chosen</i> matters to the settings file and to
    /// the screen, which must not show a number the operator never picked as though he had. It does
    /// not matter to the run, which needs one figure.
    /// </remarks>
    public int Effective => Chosen ?? DirectoryConnectionSettings.DefaultDomainsAtOnce;

    /// <summary>Whether the operator has chosen a ceiling of his own.</summary>
    public bool IsChosen => Chosen is not null;

    /// <summary>
    /// Loads the stored choice. A failure to read is surfaced rather than treated as "not chosen".
    /// </summary>
    public void Load()
    {
        var read = _store.Read();

        if (!read.IsSuccess)
        {
            Problem = read.Error.Description;
            return;
        }

        Problem = null;
        Chosen = read.Value.DomainsAtOnce;
    }

    /// <summary>Adopts and stores <paramref name="domainsAtOnce"/>.</summary>
    /// <remarks>
    /// <b>Refused below <see cref="Fewest"/> rather than clamped.</b> Silently raising a zero to one
    /// would run a capture the operator did not ask for while showing him the number he did, and
    /// this product does not correct an operator without telling him.
    /// </remarks>
    /// <param name="domainsAtOnce">How many domains to read at the same time.</param>
    public Result<bool> Choose(int domainsAtOnce)
    {
        if (domainsAtOnce < Fewest)
        {
            Problem =
                $"{domainsAtOnce} is not a number of domains to read at once. It must be "
                + $"{Fewest} or more: a capture allowed to read none at once would wait for ever "
                + "without appearing to have stopped.";

            return Result<bool>.Failure(AuditError.Create(
                ErrorCategory.Shell,
                "DomainConcurrencyUnusable",
                ErrorSeverity.Failed,
                Problem,
                domainsAtOnce.ToString(System.Globalization.CultureInfo.InvariantCulture)));
        }

        var current = _store.Read();

        if (!current.IsSuccess)
        {
            Problem = current.Error.Description;
            return Result<bool>.Failure(current.Error);
        }

        var written = _store.Write(current.Value with { DomainsAtOnce = domainsAtOnce });

        if (!written.IsSuccess)
        {
            Problem = written.Error.Description;
            return written;
        }

        Problem = null;
        Chosen = domainsAtOnce;

        return written;
    }

    partial void OnChosenChanged(int? value)
    {
        OnPropertyChanged(nameof(Effective));
        OnPropertyChanged(nameof(IsChosen));
    }
}
