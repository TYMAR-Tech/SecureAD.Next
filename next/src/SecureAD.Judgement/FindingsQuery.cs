using SecureAD.Evidence.Findings;

namespace SecureAD.Judgement;

/// <summary>
/// Where a page of findings ended, so the next page can start after it.
/// </summary>
/// <remarks>
/// <para>
/// <b>A place in the order, not a row number.</b> Paging by counting - <c>LIMIT</c> with an
/// <c>OFFSET</c> - makes the database walk and discard every row before the page, so the hundredth
/// page costs a hundred pages of work. This carries the sort values of the last row shown, and the
/// next page is the rows after them, which costs one seek whatever page it is.
/// </para>
/// <para>
/// <b>The finding's own identity is the tie-breaker, and the other three are not enough.</b> Many
/// findings share a severity and a rule, and rows that sort equal have no fixed order between them -
/// so a page boundary landing inside such a group would show some of them twice and others not at
/// all. This once ordered on the distinguished name and stopped there, on the reasoning that a
/// distinguished name is unique within a forest so no two findings could tie on all three.
/// </para>
/// <para>
/// <b>That reasoning was wrong, and P-160 is what it cost.</b> A distinguished name is unique per
/// <i>object</i>, but the <c>finding</c> table is unique on rule, subject kind, subject key and
/// object GUID - so one rule may report the same object several times, once per principal or per
/// path, and those rows tie on every value the mark carried. Judging <c>ad.lab-20260910-074140</c>
/// produced two SEC-090 findings for one workstation that way. A page boundary inside such a group
/// returned one row and reported nothing after it, so the reader saw fewer findings than the run
/// produced and nothing said so.
/// </para>
/// </remarks>
/// <param name="SeverityRank">The severity of the last row shown, as its rank.</param>
/// <param name="RuleId">The rule of the last row shown.</param>
/// <param name="DistinguishedName">The object of the last row shown.</param>
/// <param name="FindingId">
/// The identity of the last row shown. Required rather than defaulted, because a mark that omitted
/// it would resume from a position no row occupies and drop the rest of its group in silence -
/// which is the defect this parameter exists to close.
/// </param>
public readonly record struct FindingsPageMark(
    int SeverityRank,
    string RuleId,
    string DistinguishedName,
    long FindingId);

/// <summary>
/// What a findings grid's filters may offer.
/// </summary>
/// <remarks>
/// <b>Taken from the findings that exist, so a filter cannot be set to nothing.</b> A list written
/// into a screen offers every severity whether or not any finding has one, and an operator who
/// picks one and gets an empty grid has learned only to distrust the control.
/// </remarks>
/// <param name="Severities">The severities some finding has, worst first.</param>
/// <param name="Rules">The rules some finding came from, in order.</param>
/// <param name="RulesRan">How many rules were run over the bundle these came from.</param>
public sealed record FindingsFilterValues(
    IReadOnlyList<Severity> Severities,
    IReadOnlyList<string> Rules,
    int RulesRan)
{
    /// <summary>
    /// Whether no rule has been run, so empty lists say nothing about the forest.
    /// </summary>
    /// <remarks>
    /// <b>Empty filters have two causes and they are not alike.</b> A judged bundle whose rules
    /// found nothing genuinely offers nothing to filter by. A bundle nobody judged offers nothing
    /// either, and a screen that could not tell them apart would show the same two empty lists for
    /// <i>your forest is quiet</i> and <i>nobody has looked</i>.
    /// </remarks>
    public bool DidNotRun => RulesRan == 0;
}

/// <summary>
/// What a findings grid asks for: which findings, and where to carry on from.
/// </summary>
/// <remarks>
/// <b>The filters are what the screen offers and nothing more.</b> Each is optional, and null means
/// <i>all of them</i> rather than <i>none of them</i>. A request that cannot express a filter the
/// screen has is a screen that has to filter in memory, which is the thing paging exists to avoid.
/// </remarks>
/// <param name="Severity">Only findings of this severity, or null for every severity.</param>
/// <param name="RuleId">Only findings from this rule, or null for every rule.</param>
/// <param name="DomainFqdn">Only findings in this domain, or null for every domain.</param>
/// <param name="Container">
/// Only findings on objects at or beneath this distinguished name, or null for the whole forest.
/// This is how the tree selection scopes the grid.
/// </param>
/// <param name="Object">
/// Only findings about this one object, or null for any object.
/// <para>
/// <b>Beside <paramref name="Container"/> rather than expressed with it.</b> A container match is a
/// suffix and matches everything beneath, so asking for one object that way would also return the
/// findings of everything inside it when that object is itself a container. The two questions are
/// different — <i>what is wrong under here</i> and <i>what is wrong with this</i> — and an operator
/// who opened one object is asking the second.
/// </para>
/// </param>
/// <param name="After">Where the previous page ended, or null for the first page.</param>
/// <param name="PageSize">How many findings to return.</param>
public sealed record FindingsQuery(
    Severity? Severity,
    string? RuleId,
    string? DomainFqdn,
    string? Container,
    string? Object,
    FindingsPageMark? After,
    int PageSize)
{
    /// <summary>
    /// How many findings a page holds when nobody has said otherwise.
    /// </summary>
    /// <remarks>
    /// Fifty, which is what the predecessor's grid used. It is enough to fill a screen and scroll a
    /// little, and small enough that a page arrives without the operator noticing it was fetched.
    /// </remarks>
    public const int DefaultPageSize = 50;

    /// <summary>The first page of everything, worst first.</summary>
    public static FindingsQuery Everything() =>
        new(null, null, null, null, null, null, DefaultPageSize);

    /// <summary>
    /// Everything found about one object.
    /// </summary>
    /// <remarks>
    /// One page of the default size rather than all of them. An object with more findings than that
    /// is rare enough that paging them is not worth a screen, and common enough that reading them
    /// all into a panel would be the one place this product forgot the forest can be large.
    /// </remarks>
    /// <param name="distinguishedName">The object to ask about.</param>
    public static FindingsQuery About(string distinguishedName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(distinguishedName);

        return new(null, null, null, null, distinguishedName, null, DefaultPageSize);
    }

    /// <summary>The same query, resuming after <paramref name="mark"/>.</summary>
    /// <param name="mark">Where the last page ended.</param>
    public FindingsQuery ResumingAfter(FindingsPageMark mark) => this with { After = mark };
}

/// <summary>
/// One page of findings, and whether there is another.
/// </summary>
/// <remarks>
/// <para>
/// <b>There is no total.</b> Counting every finding that matches a filter is a second query over
/// the same rows, and a grid that shows <i>page 3 of 400</i> has paid for the 400 on every page.
/// What an operator needs in order to keep reading is whether there is more, which the page itself
/// knows because it asked for one row more than it returns.
/// </para>
/// <para>
/// <b><see cref="RulesRan"/> travels with the findings because an empty page is not one fact.</b>
/// No findings because every rule ran and matched nothing is a clean forest. No findings because
/// nobody judged the bundle is silence, and drawing it as an empty grid states the first while
/// meaning the second. <see cref="JudgementReader.ReadPage"/> refuses the second case outright, and
/// this carries the answer so that a screen holding a page can still tell them apart.
/// </para>
/// </remarks>
/// <param name="Findings">The findings on this page, worst first.</param>
/// <param name="Next">Where to carry on from, or null when this is the last page.</param>
/// <param name="RulesRan">How many rules were run over the bundle these findings came from.</param>
public sealed record FindingsPage(
    IReadOnlyList<Finding> Findings,
    FindingsPageMark? Next,
    int RulesRan)
{
    /// <summary>Whether another page follows this one.</summary>
    public bool HasMore => Next is not null;

    /// <summary>
    /// Whether no rule was run over the bundle these findings came from, so an empty page says
    /// nothing about the forest.
    /// </summary>
    /// <remarks>
    /// <see cref="JudgementReader.ReadPage"/> refuses to build such a page at all, so this is
    /// always false on a page that was returned. It is declared because a page that could not say
    /// this would be a list of findings a screen can render as a clean grid without ever asking
    /// whether anyone looked - and the type system is where that is prevented.
    /// </remarks>
    public bool DidNotRun => RulesRan == 0;

    /// <summary>
    /// Whether the rules ran and this page of them is genuinely empty.
    /// </summary>
    public bool NothingWasFound => Findings.Count == 0 && !DidNotRun;
}
