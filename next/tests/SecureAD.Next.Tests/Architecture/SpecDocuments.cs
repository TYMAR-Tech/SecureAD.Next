using Xunit;

namespace SecureAD.Next.Tests.Architecture;

/// <summary>
/// The spec documents — designs for code that does not exist yet.
/// </summary>
/// <remarks>
/// <para>
/// <b>They live under <c>docs/layers</c> but are not layer documents, and the distinction is the
/// whole reason this type is separate from <see cref="LayerDocuments"/>.</b> A layer document
/// describes code that exists and is bound to it by a test that derives what it expects from the
/// code. A spec describes code that does not exist, so there is nothing to derive from and no
/// binding to make.
/// </para>
/// <para>
/// <b>Registering the folder in <see cref="LayerDocuments.Subsystems"/> would have been the easy
/// fix and the wrong one.</b> The gates that iterate that list ask for a <c>TYPES</c> table naming
/// the types a document owns, resolved against the assemblies. A spec can only satisfy that with a
/// table of types nobody has written — which is precisely the decoration
/// <c>LayerDocumentGateTests.EveryLayerDirectoryIsARegisteredSubsystem</c> exists to catch, since
/// the shell subsystem shipped two such tables and no gate read either of them.
/// </para>
/// <para>
/// <b>So the folder is scanned, by a rule that fits it.</b>
/// <see cref="SpecDocumentGateTests"/> asks the two questions worth asking of a spec: that it says
/// in writing it is discussion rather than a decision, and that it does not carry a <c>TYPES</c>
/// table, which is what would let it pass for a layer document to a reader going by folder name.
/// </para>
/// <para>
/// <b>The folder is temporary by design.</b> A spec is consumed and deleted as its subject is
/// built, the same discipline <c>docs/areas/</c> is under, and its content moves into the layer
/// document for the code that now exists. When the last spec goes, so does the directory and this
/// type with it.
/// </para>
/// </remarks>
internal static class SpecDocuments
{
    /// <summary>The directory under <c>docs/layers</c> that holds spec documents.</summary>
    internal const string DirectoryName = "specs";

    /// <summary>
    /// The banner every spec carries, stating it does not state the product's position.
    /// </summary>
    /// <remarks>
    /// Matched as a substring rather than a whole line so a spec may word the rest of its banner
    /// as it likes. It is deliberately a phrase a session would not write by accident.
    /// </remarks>
    internal const string DiscussionBanner = "This is discussion, not a decision.";

    /// <summary>The spec directory, whether or not it exists.</summary>
    internal static string Root() => Path.Combine(LayerDocuments.Root(), DirectoryName);

    /// <summary>
    /// Every spec document, ordered. An absent directory yields none rather than failing: the
    /// folder retires when the last spec is consumed, and that is success rather than a fault.
    /// </summary>
    internal static List<string> All()
    {
        var directory = Root();

        if (!Directory.Exists(directory))
            return [];

        return [.. Directory.EnumerateFiles(directory, "*.md").OrderBy(f => f, StringComparer.Ordinal)];
    }
}
