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
/// <b>The distinguished name is the tie-breaker and is why this is three values rather than
/// one.</b> Many findings share a severity and a rule, and rows that sort equal have no fixed order
/// between them - so a page boundary landing inside such a group would show some of them twice and
/// others not at all. A distinguished name is unique within a forest, so no two findings can tie on
/// all three.
/// </para>
/// </remarks>
/// <param name="SeverityRank">The severity of the last row shown, as its rank.</param>
/// <param name="RuleId">The rule of the last row shown.</param>
/// <param name="DistinguishedName">The object of the last row shown.</param>
public readonly record struct FindingsPageMark(
    int SeverityRank,
    string RuleId,
    string DistinguishedName);

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
/// <param name="After">Where the previous page ended, or null for the first page.</param>
/// <param name="PageSize">How many findings to return.</param>
public sealed record FindingsQuery(
    Severity? Severity,
    string? RuleId,
    string? DomainFqdn,
    string? Container,
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
        new(null, null, null, null, null, DefaultPageSize);

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
