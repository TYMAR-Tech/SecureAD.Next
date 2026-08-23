using System.Reflection;

namespace SecureAD.Next.Tests.Architecture;

/// <summary>
/// Whether a citation in a documentation table names a test that really exists.
/// </summary>
/// <remarks>
/// <para>
/// Reflection over the test assembly rather than a text scan, because the question is whether the
/// test is really there — a text scan would be satisfied by the name appearing in a comment, which
/// is how gate 5 came to pass while measuring nothing.
/// </para>
/// <para>
/// <b>Why this is shared.</b> Two resolvers written separately drift apart, and this repository has
/// already been bitten twice by checks that were each narrower than their own names in ways that
/// overlapped. <see cref="AreaFileGateTests"/> resolves citations in <c>docs/areas</c> and
/// <see cref="CapabilityCitationTests"/> resolves them in the layer documents; both ask the
/// question the same way, so both ask it here.
/// </para>
/// </remarks>
internal static class TestCitation
{
    /// <summary>
    /// Resolves <paramref name="citation"/>, written either as <c>TypeName</c> or as
    /// <c>TypeName.MethodName</c>, against the test assembly.
    /// </summary>
    /// <param name="citation">The name as the table writes it, without its backticks.</param>
    /// <param name="reason">Why it did not resolve, or empty when it did.</param>
    /// <returns><see langword="true"/> when the citation names a real test.</returns>
    internal static bool Resolve(string citation, out string reason)
    {
        ArgumentNullException.ThrowIfNull(citation);

        var parts = citation.Split('.');
        var typeName = parts[0];

        var type = typeof(TestCitation).Assembly
            .GetTypes()
            .FirstOrDefault(t => t.Name == typeName && !t.IsNested);

        if (type is null)
        {
            reason = "no such type in the test assembly";
            return false;
        }

        var methods = type.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)
            .Where(IsTestMethod)
            .ToList();

        if (methods.Count == 0)
        {
            reason = "that type declares no tests, so it proves nothing";
            return false;
        }

        if (parts.Length == 1)
        {
            reason = string.Empty;
            return true;
        }

        if (methods.All(m => m.Name != parts[1]))
        {
            reason = $"'{typeName}' declares no test named '{parts[1]}'";
            return false;
        }

        reason = string.Empty;
        return true;
    }

    private static bool IsTestMethod(MethodInfo method) =>
        method.GetCustomAttributes()
            .Any(a => a.GetType().Name is "FactAttribute" or "TheoryAttribute");
}
