using System.Collections.Immutable;
using System.Diagnostics.Metrics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace SecureAD.Evidence;

/// <summary>Local syntax extraction only; this adapter creates no WMI provider connection.</summary>
internal static class WindowsWqlParser
{
    private static readonly Meter PreparationMeter = new("SecureAD.Evidence.WqlParser");
    private static readonly Counter<long> NativeParses = PreparationMeter.CreateCounter<long>("wql.native_parses");
    private static readonly Guid ParserClass = new("eac8a024-21e2-4523-ad73-a71a0aa2f56a");
    private static readonly Guid ParserInterface = new("81166f58-dd98-11d3-a120-00105a1f515a");
    private const int ChangedApartment = unchecked((int)0x80010106);

    internal static WqlQueryReading Read(string query, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);
        cancellationToken.ThrowIfCancellationRequested();
        if (query.Contains('\0'))
            return WqlQueryReading.Failed(query, WqlReadingState.Rejected, "WmiQueryEmbeddedNull",
                "The captured query contains an embedded null and cannot be passed intact to the native parser.", null);
        if (!OperatingSystem.IsWindows())
            return Unavailable(query, null, "Microsoft's native WQL parser is unavailable on this operating system.");
        try { return ReadWindows(query, cancellationToken); }
        catch (Exception error) when (error is COMException or DllNotFoundException or EntryPointNotFoundException or PlatformNotSupportedException)
        {
            return Unavailable(query, error.HResult, error.Message);
        }
    }

    internal static WqlQueryReading Unavailable(string query, int? code, string reason) =>
        WqlQueryReading.Failed(query, WqlReadingState.Unavailable, "WmiParserUnavailable", reason, code);

    [SupportedOSPlatform("windows")]
    private static WqlQueryReading ReadWindows(string query, CancellationToken cancellationToken)
    {
        var initialization = CoInitializeEx(IntPtr.Zero, 0);
        if (initialization < 0 && initialization != ChangedApartment)
            return Unavailable(query, initialization, "The native parser's local COM context could not be initialized.");
        try
        {
            var classId = ParserClass;
            var interfaceId = ParserInterface;
            var activation = CoCreateInstance(ref classId, IntPtr.Zero, 1, ref interfaceId, out var parser);
            if (activation < 0)
                return Unavailable(query, activation, "Microsoft's native WQL parser could not be activated.");
            try
            {
                NativeParses.Add(1);
                var parsed = parser.Parse("WQL", query, 0);
                if (parsed < 0)
                    return WqlQueryReading.Failed(query, WqlReadingState.Rejected, "WmiQueryParserRejected",
                        "Microsoft's parser rejected this captured query; no filter match is inferred.", parsed);
                var analyzed = parser.GetAnalysis(1, 0, out var memory);
                try
                {
                    if (analyzed < 0)
                        return WqlQueryReading.Failed(query, WqlReadingState.Unsupported, "WmiQueryAnalysisUnsupported",
                            "The accepted query does not provide the required static condition analysis.", analyzed);
                    if (memory == IntPtr.Zero)
                        return Unavailable(query, analyzed, "The native parser returned no analysis data.");
                    cancellationToken.ThrowIfCancellationRequested();
                    return Copy(query, Marshal.PtrToStructure<EncodedQuery>(memory), cancellationToken);
                }
                finally
                {
                    if (memory != IntPtr.Zero) Marshal.ThrowExceptionForHR(parser.FreeMemory(memory));
                }
            }
            finally { Marshal.FinalReleaseComObject(parser); }
        }
        finally { if (initialization >= 0) CoUninitialize(); }
    }

    private static WqlQueryReading Copy(string query, EncodedQuery result, CancellationToken cancellationToken)
    {
        // The SDK feature flags expose forms that Parse accepts but this batch cannot interpret.
        const ulong allowedFeatures = 1 | 2 | 4 | 16 | 32;
        if (result.Version != 1 || result.TokenType != 0
            || (result.FeatureMask & ~allowedFeatures) != 0 || (result.FeatureMask & 16) == 0
            || result.FromType != 1 || result.ClassCount != 1 || result.Classes == IntPtr.Zero
            || result.FromPath != IntPtr.Zero || result.Polling != 0 || result.Window != 0 || result.OrderCount != 0
            || result.WhereCount > query.Length || result.WhereCount > 0 && result.Where == IntPtr.Zero)
            return Unsupported("The query uses features outside the verified single-class static SELECT subset.");
        var className = Text(Marshal.ReadIntPtr(result.Classes));
        if (!Identifier(className)) return Unsupported("The class name is not a supported simple identifier.");
        var tokens = ImmutableArray.CreateBuilder<WqlConditionToken>();
        var depth = 0;
        for (var index = 0; index < result.WhereCount; index++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var pointer = Marshal.ReadIntPtr(result.Where, checked(index * IntPtr.Size));
            if (pointer == IntPtr.Zero) return Unsupported("The native condition list contains no token.");
            var token = Marshal.PtrToStructure<QueryToken>(pointer);
            if (token.Version != 1) return Unsupported("The native condition token version is not supported.");
            if (token.Type is 2 or 3 or 4)
            {
                var needed = token.Type == 4 ? 1 : 2;
                if (depth < needed) return Unsupported("The native logical expression is incomplete.");
                if (needed == 2) depth--;
                tokens.Add(new WqlLogicalToken(token.Type == 2 ? WqlLogicalOperator.And
                    : token.Type == 3 ? WqlLogicalOperator.Or : WqlLogicalOperator.Not));
                continue;
            }
            if (token.Type != 1 || token.LeftFunction != IntPtr.Zero || token.RightFunction != IntPtr.Zero
                || token.Right != IntPtr.Zero || token.Shape is not (17 or 25))
                return Unsupported("A condition has unsupported functions, property comparisons, multiple constants or operand shape.");
            var property = Property(token.Left);
            if (property is null) return Unsupported("A condition does not identify one supported property.");
            var operation = token.Operator switch
            {
                1 => WqlComparison.Equal, 2 => WqlComparison.NotEqual, 3 => WqlComparison.GreaterOrEqual,
                4 => WqlComparison.LessOrEqual, 5 => WqlComparison.Less, 6 => WqlComparison.Greater,
                7 => WqlComparison.Like, 10 => WqlComparison.IsNull, 11 => WqlComparison.IsNotNull,
                _ => (WqlComparison?)null,
            };
            if (operation is null) return Unsupported("A condition has no supported comparison operator.");
            var nullTest = operation is WqlComparison.IsNull or WqlComparison.IsNotNull;
            if (nullTest != (token.Shape == 17))
                return Unsupported("The comparison's operand shape does not match its operator.");
            WqlLiteral? literal = null;
            if (!nullTest)
            {
                literal = Literal(token.ConstantType, token.Value);
                if (literal is null) return Unsupported("The native constant has no verified scalar representation.");
            }
            tokens.Add(new WqlComparisonToken(property, operation.Value, literal));
            depth++;
        }
        if (result.WhereCount > 0 && depth != 1)
            return Unsupported("The native logical expression does not produce one complete predicate.");
        return new(query, WqlReadingState.ParsedConditions, new(className, tokens.ToImmutable()), null, null);

        WqlQueryReading Unsupported(string reason) =>
            WqlQueryReading.Failed(query, WqlReadingState.Unsupported, "WmiQueryShapeUnsupported", reason, null);
    }

    private static WqlLiteral? Literal(uint type, Constant value) => type switch
    {
        3 => new(WqlLiteralKind.SignedInteger, value.Int32.ToString(CultureInfo.InvariantCulture), type),
        19 => new(WqlLiteralKind.UnsignedInteger, value.UInt32.ToString(CultureInfo.InvariantCulture), type),
        20 => new(WqlLiteralKind.SignedInteger, value.Int64.ToString(CultureInfo.InvariantCulture), type),
        21 => new(WqlLiteralKind.UnsignedInteger, value.UInt64.ToString(CultureInfo.InvariantCulture), type),
        5 when double.IsFinite(value.Double) => new(WqlLiteralKind.Real, value.Double.ToString("R", CultureInfo.InvariantCulture), type),
        31 when value.Text != IntPtr.Zero => new(WqlLiteralKind.Text, Text(value.Text), type),
        _ => null,
    };

    private static string? Property(IntPtr pointer)
    {
        if (pointer == IntPtr.Zero) return null;
        var value = Marshal.PtrToStructure<QualifiedName>(pointer);
        if (value.Version != 1 || value.Type != 1 || value.Count != 1 || value.Names == IntPtr.Zero || value.ArraysUsed != 0) return null;
        var text = Text(Marshal.ReadIntPtr(value.Names));
        return Identifier(text) ? text : null;
    }

    private static bool Identifier(string text) => text.Length > 0
        && (char.IsAsciiLetter(text[0]) || text[0] == '_')
        && text.All(character => char.IsAsciiLetterOrDigit(character) || character == '_');
    private static string Text(IntPtr pointer) => pointer == IntPtr.Zero ? "" : Marshal.PtrToStringUni(pointer)
        ?? throw new InvalidDataException("The native WQL parser returned an unreadable string.");

    [StructLayout(LayoutKind.Sequential)]
    private struct EncodedQuery
    {
        public uint Version, TokenType;
        public ulong FeatureMask;
        public uint FeatureCount;
        public IntPtr Features;
        public uint SelectCount;
        public IntPtr Select;
        public uint FromType;
        public IntPtr FromPath;
        public uint ClassCount;
        public IntPtr Classes;
        public uint WhereCount;
        public IntPtr Where;
        public double Polling, Window;
        public uint OrderCount;
        public IntPtr Order, Direction;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct QueryToken
    {
        public uint Version, Type, Shape, Operator;
        public IntPtr Right, Left;
        public uint ConstantType;
        public Constant Value;
        public uint ConstantType2;
        public Constant Value2;
        public IntPtr RightFunction, LeftFunction;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct QualifiedName
    {
        public uint Version, Type, Count;
        public IntPtr Names;
        public int ArraysUsed;
        public IntPtr ArrayElements, ArrayIndexes;
    }

    [StructLayout(LayoutKind.Explicit, Size = 8)]
    private struct Constant
    {
        [FieldOffset(0)] public IntPtr Text;
        [FieldOffset(0)] public int Int32;
        [FieldOffset(0)] public uint UInt32;
        [FieldOffset(0)] public long Int64;
        [FieldOffset(0)] public ulong UInt64;
        [FieldOffset(0)] public double Double;
    }

    [ComImport, Guid("81166f58-dd98-11d3-a120-00105a1f515a"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IWbemQuery
    {
        [PreserveSig] int Empty();
        [PreserveSig] int SetLanguageFeatures(uint flags, uint count, IntPtr features);
        [PreserveSig] int TestLanguageFeatures(uint flags, ref uint count, IntPtr features);
        [PreserveSig] int Parse([MarshalAs(UnmanagedType.LPWStr)] string language, [MarshalAs(UnmanagedType.LPWStr)] string query, uint flags);
        [PreserveSig] int GetAnalysis(uint type, uint flags, out IntPtr analysis);
        [PreserveSig] int FreeMemory(IntPtr memory);
    }

    [DllImport("ole32.dll", ExactSpelling = true), DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int CoInitializeEx(IntPtr reserved, uint flags);
    [DllImport("ole32.dll", ExactSpelling = true), DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern void CoUninitialize();
    [DllImport("ole32.dll", ExactSpelling = true), DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int CoCreateInstance(ref Guid classId, IntPtr outer, uint context, ref Guid interfaceId,
        [MarshalAs(UnmanagedType.Interface)] out IWbemQuery result);
}
