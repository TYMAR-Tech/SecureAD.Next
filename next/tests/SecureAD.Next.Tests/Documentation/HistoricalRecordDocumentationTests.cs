using System.Text.RegularExpressions;
using Xunit;

namespace SecureAD.Next.Tests.Documentation;

/// <summary>
/// Binds <c>S-16-the-bundle.md</c>, the live description of what a bundle holds, to the schema the
/// code actually creates.
///
/// <para>
/// <b>A historical record is cross-referenced, never corrected.</b> Its account of what was found
/// at a moment is evidence, and <c>S-24</c>'s own rule is that a withdrawn finding is evidence of
/// how an error entered. Rewriting one destroys that, so nothing here asserts anything about what
/// these documents found.
/// </para>
/// <para>
/// <b>What is checked derives from the code.</b> The table list comes out of
/// <c>BundleSchema.cs</c> by reading its <c>CREATE TABLE</c> statements, so adding a table fails
/// this until <c>S-16</c> describes it. That is the only kind of documentation check worth a build
/// failure: one a change to the product can break.
/// </para>
/// </summary>
public sealed class HistoricalRecordDocumentationTests
{
    /// <summary>
    /// Every table <c>BundleSchema</c> creates. <c>S-16-the-bundle.md</c> is the live description
    /// of what a bundle holds, so a table it does not name is a table nobody reading the bundle
    /// documentation knows exists.
    ///
    /// <para>
    /// <b>This is not asked of <c>S-24</c> or <c>S-25</c>.</b> Those record two build sessions, not
    /// the finished article, and holding a historical record to a complete list of what exists now
    /// would force it to be rewritten every time the schema grew - which is the one thing a
    /// historical record may not be. Written the other way round first, and it failed on four
    /// tables that were documented all along.
    /// </para>
    /// </summary>
    private static readonly string[] BundleTables =
    [
        "bundle",
        "captured_object",
        "partition_coverage",
        "domain_coverage",
        "forest_partition_coverage",
        "continuation_reference",
        "unread_partition",
        "excluded_domain",
        "unresolved_reference",
        "security_descriptor",
        "object_security_descriptor",
        "security_descriptor_error",
        "unreadable_security_descriptor",
        "ace",
        "trustee",
        "sysvol_gpo_coverage",
        "gpo_registry_setting",
        "gpo_security_setting",
        "gpo_restricted_group",
        "gpo_stored_credential",
        "gpo_file_error",
        "sysvol_path_security_descriptor",
        "unreadable_sysvol_descriptor",
        "finding",
        "finding_unconstrained_delegation",
        "evaluated_rule",
    ];

    /// <summary>
    /// The live description of a bundle names every table one holds.
    /// </summary>
    [Theory]
    [MemberData(nameof(TableNames))]
    public void TheBundleDocumentNamesEveryTableABundleHolds(string table)
    {
        Assert.True(
            Read("S-16-the-bundle.md").Contains(table, StringComparison.Ordinal),
            $"S-16-the-bundle.md does not name the table `{table}`, which BundleSchema creates. "
            + "S-16 is the live description of what a bundle holds; a table missing from it has "
            + "no description anywhere but the SQL that creates it.");
    }

    public static TheoryData<string> TableNames()
    {
        var names = new TheoryData<string>();
        foreach (var table in BundleTables)
        {
            names.Add(table);
        }

        return names;
    }

    /// <summary>
    /// The schema really does create what the document is held to. Without this the check above
    /// could pass against a list that had drifted from the code in the same direction as the
    /// document - which is <c>F-S24-2</c> exactly: a document and the code agreeing while both
    /// describe a superseded design.
    /// </summary>
    [Fact]
    public void TheTableListMatchesTheSchemaItIsCheckedAgainst()
    {
        var sql = File.ReadAllText(System.IO.Path.Combine(
            RepositoryLocation.Root(), "next", "src", "SecureAD.Evidence", "BundleSchema.cs"));

        var created = Regex
            .Matches(sql, @"CREATE TABLE (?:IF NOT EXISTS )?(?<name>[a-z_]+)")
            .Select(m => m.Groups["name"].Value)
            .Distinct(StringComparer.Ordinal)
            .OrderBy(n => n, StringComparer.Ordinal)
            .ToList();

        Assert.Equal(
            BundleTables.OrderBy(n => n, StringComparer.Ordinal).ToList(),
            created);
    }

    // Two checks stood here and were deleted on 2026-08-14. One asserted that S-20 still contained
    // the exact sentence 'Cross-referenced 2026-08-13 in `S-26`, as `F-S26-4`'; the other asserted
    // that inventory row C1 still held the stale status that sentence corrected. Neither could be
    // broken by any change to the product - only by editing the document each was about, and the
    // second failed if the document was put right. Keeping a document wrong so that a note about
    // its wrongness stays true is not a test, and pinning a correction someone has already made
    // cannot find the next one. What survives here derives its expectation from the schema.

    private static string Read(string document) =>
        File.ReadAllText(System.IO.Path.Combine(
            RepositoryLocation.Root(), "docs", "next", document));
}
