using SecureAD.Next.Tests.Architecture;

namespace SecureAD.Next.Tests;

/// <summary>
/// Where the repository sits on disk, for tests that read files from it.
/// </summary>
/// <remarks>
/// This lived on <c>OldAppInventory</c> until that class was removed with the old application's
/// component map. It never had anything to do with the inventory - thirty-eight call sites across
/// twenty-seven test files wanted the repository root and reached through the inventory helper to
/// get it. It sits in the root test namespace so every test file, all of which are in child
/// namespaces, can see it without a using directive.
/// </remarks>
internal static class RepositoryLocation
{
    /// <summary>The repository root - the parent of the rebuild tree.</summary>
    public static string Root() =>
        Directory.GetParent(RebuildTree.Root())?.FullName
        ?? throw new DirectoryNotFoundException(
            "The rebuild root at " + RebuildTree.Root() + " has no parent directory, so the "
            + "repository root holding docs/ cannot be located.");
}
