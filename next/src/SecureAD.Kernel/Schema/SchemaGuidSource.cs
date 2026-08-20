namespace SecureAD.Kernel.Schema;

/// <summary>
/// Where a schema-GUID entry's name came from.
/// </summary>
/// <remarks>
/// <para>
/// A name shown in a report is a claim, and the two claims are not equally strong. "Microsoft
/// publishes this GUID as <c>userAccountControl</c>" can be checked by anyone against the schema
/// reference. "Your forest says this GUID is <c>contoso-PayrollId</c>" is true of that forest on
/// that day and nowhere else, which is exactly why it had to be captured.
/// </para>
/// <para>
/// Per <c>docs/decisions/0014-capture-reads-the-schema-partition.md</c>, evidence states which of
/// the two it is rather than presenting both as the same kind of fact.
/// </para>
/// </remarks>
public enum SchemaGuidSource
{
    /// <summary>
    /// From the catalogue shipped with the product. Available offline, without a capture, and the
    /// same in every forest.
    /// </summary>
    Embedded,

    /// <summary>
    /// Read from a forest's own schema partition or extended-rights container during capture.
    /// True of that forest, and not necessarily of any other.
    /// </summary>
    Captured,
}
