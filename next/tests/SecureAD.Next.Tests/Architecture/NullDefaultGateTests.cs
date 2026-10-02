using System.Reflection;
using Xunit;

namespace SecureAD.Next.Tests.Architecture;

/// <summary>
/// Gate 1, second half: no parameter in the rebuild's production code may default to
/// <c>null</c>.
///
/// <para>
/// The first half of gate 1 is carried by the compiler — <c>Result&lt;T&gt;</c> and
/// <c>AuditError</c> are types, so a caller cannot ignore them. This half cannot be, because
/// <c>= null</c> is legal C# that quietly turns a required collaborator into an optional one.
/// </para>
/// <para>
/// That is how the old product ended up with progress reporting, cancellation and the performance
/// log all present, all correct, and all unused: each was introduced as
/// <c>IProgressPublisher? progressPublisher = null</c>, every call site took the default, and
/// nothing ever failed to say so. A mechanism nobody is obliged to use is a mechanism nobody uses.
/// </para>
/// <para>
/// The gate covers every production parameter, including private methods and constructors,
/// because silently optional collaborators cause the same failure at either boundary.
/// A parameter that genuinely has no value passes a nullable type explicitly at the call site,
/// which puts the decision in the caller's diff rather than in the signature.
/// </para>
/// </summary>
public sealed class NullDefaultGateTests
{
    /// <summary>
    /// Compiler metadata distinguishes parameters from locals and object initializers. The old
    /// line pattern mistook both XmlResolver = null and a multi-variable local for parameters.
    /// </summary>
    /// <remarks>
    /// The initializer is an XXE defence; changing valid production code to please an ambiguous
    /// pattern would be the wrong fix. GreenfieldGateTests separately holds source inclusion to
    /// the solution, and this check must run against a rebuilt assembly, like the other reflected
    /// architecture checks. Nonpublic members are included so internal collaborators cannot escape.
    /// </remarks>
    private const BindingFlags DeclaredMembers = BindingFlags.Public | BindingFlags.NonPublic
        | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly;

    // The shared surface gates cover the libraries. This gate also covers both hosts, as the
    // former next/src source scan did. No test or measurement assembly is added to that scope.
    private static IEnumerable<Assembly> ProductionAssemblies() => RebuildAssemblies.All.Concat(
        [Assembly.Load("securead-cli"), Assembly.Load("SecureAD")]);

    private static IEnumerable<ParameterInfo> Parameters(Type type) => type
        .GetConstructors(DeclaredMembers).Cast<MethodBase>()
        .Concat(type.GetMethods(DeclaredMembers))
        .SelectMany(member => member.GetParameters());

    private static bool DefaultsToNull(ParameterInfo parameter) =>
        parameter.HasDefaultValue && parameter.DefaultValue is null
        && (!parameter.ParameterType.IsValueType
            || Nullable.GetUnderlyingType(parameter.ParameterType) is not null);

    [Fact]
    public void NoProductionParameterDefaultsToNull()
    {
        var offenders = ProductionAssemblies().SelectMany(assembly => assembly.GetTypes())
            .SelectMany(Parameters)
            .Where(DefaultsToNull)
            .Select(parameter => $"  {parameter.Member.DeclaringType?.FullName}.{parameter.Member.Name}: {parameter.Name}")
            .OrderBy(value => value, StringComparer.Ordinal)
            .ToList();

        Assert.True(
            offenders.Count == 0,
            "No parameter may default to null (docs/next/README.md, gate 1). A default of null "
            + "makes a collaborator optional without anyone deciding it should be, which is how "
            + "progress, cancellation and the performance log all became unused in the previous "
            + "implementation. Pass the value explicitly at each call site instead:"
            + Environment.NewLine + string.Join(Environment.NewLine, offenders));
    }

    /// <summary>
    /// The gate reads real parameters. Without this it passes by scanning an empty set, which is the
    /// failure the scanner self-tests exist to catch.
    /// </summary>
    [Fact]
    public void TheGateReadsRealProductionParameters()
    {
        var parameters = ProductionAssemblies().SelectMany(assembly => assembly.GetTypes())
            .SelectMany(Parameters).ToList();

        Assert.Contains(parameters, parameter => parameter.Member.DeclaringType == typeof(SecureAD.Judgement.JudgingStatus)
            && parameter.Name == "memory");
    }

    /// <summary>
    /// The compiled fixtures exercise the same distinctions as the old text cases, without
    /// making formatting determine whether a real parameter is inspected.
    /// </summary>
    [Theory]
    [InlineData(typeof(DefaultedConstructor), ".ctor", "path")]
    [InlineData(typeof(Signatures), "PublicDefault", "value")]
    [InlineData(typeof(Signatures), "PrivateDefault", "value")]
    [InlineData(typeof(Signatures), "InternalDefault", "value")]
    [InlineData(typeof(Signatures), "NullableValue", "value")]
    [InlineData(typeof(Signatures), "TwoDefaults", "first")]
    [InlineData(typeof(Signatures), "TwoDefaults", "second")]
    public void TheGateRecognisesADefaultedNull(Type type, string member, string name)
    {
        var parameter = Assert.Single(Parameters(type), p => p.Member.Name == member && p.Name == name);

        Assert.True(DefaultsToNull(parameter));
    }

    [Theory]
    [InlineData("RequiredNullable")]
    [InlineData("ValueDefault")]
    [InlineData("TextDefault")]
    [InlineData("NullLocalsAndInitializers")]
    public void TheGateDoesNotFireOnSomethingElse(string member)
    {
        var parameter = Assert.Single(Parameters(typeof(Signatures)), p => p.Member.Name == member);

        Assert.False(DefaultsToNull(parameter));
    }

    [Fact]
    public void TheGateCoversBothHostsAndEveryLibrary() => Assert.Equal(
        new[] { "SecureAD", "SecureAD.Audit", "SecureAD.Derivation", "SecureAD.Evidence", "SecureAD.Judgement", "SecureAD.Kernel", "securead-cli" },
        ProductionAssemblies().Select(assembly => assembly.GetName().Name).OrderBy(name => name, StringComparer.Ordinal));

    private sealed class DefaultedConstructor(string? path = null)
    {
        internal string? Path { get; } = path;
    }

    private sealed class Signatures
    {
        public static string? PublicDefault(string? value = null) => value;
        private static string? PrivateDefault(string? value = null) => value;
        internal static string? InternalDefault(string? value = null) => value;
        internal static CancellationToken? NullableValue(CancellationToken? value = null) => value;
        internal static (Guid?, Guid?) TwoDefaults(Guid? first = null, Guid? second = null) => (first, second);
        internal static string? RequiredNullable(string? value) => value;
        internal static CancellationToken ValueDefault(CancellationToken value = default) => value;
        internal static string TextDefault(string value = "present") => value;
        internal static object NullLocalsAndInitializers(string? supplied)
        {
            long? working = null, committed = null;
            var settings = new System.Xml.XmlReaderSettings { XmlResolver = null, };
            return (supplied, working, committed, settings);
        }
    }
}
