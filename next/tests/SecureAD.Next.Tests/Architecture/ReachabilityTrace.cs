using System.Reflection;
using System.Reflection.Emit;
using System.Runtime.CompilerServices;

namespace SecureAD.Next.Tests.Architecture;

/// <summary>
/// Walks the compiled product from its entry points and reports which types anything that runs can
/// actually arrive at. The measurement behind gate 5b.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why reachability rather than "is it referenced".</b> Gate 5 was first written as <i>every
/// public type has a production consumer</i> and passed on 2026-08-10 against all fourteen public
/// types in the rebuild while nothing in the tree was used by anything that runs. Types reference
/// each other, which satisfies that wording. The predecessor's six unreachable grids mention
/// plenty, and mention each other. The question that separates them is whether a root can get
/// there, which is what this does. See <c>README.md</c> § Gates.
/// </para>
/// <para>
/// <b>Roots are every method of the two application assemblies</b>, not just their entry points.
/// That over-approximates deliberately: WPF builds views and view models from XAML by name, with no
/// call anywhere in the compiled code, so a precise walk from <c>App.Main</c> would report most of
/// the product dead and the answer would be worthless. Walking outward from those roots into the
/// five library assemblies is precise. <b>The consequence is that a library type reached only from
/// a dead shell method still counts as reached</b>, so the unreachable set this produces is a floor
/// rather than a total. It is sound in the direction that matters: nothing here is accused falsely.
/// </para>
/// <para>
/// <b>Three things a naive walk of the instructions misses</b>, each found during the P-182
/// measurement by producing a wrong number and being checked against the code:
/// </para>
/// <list type="number">
/// <item><b>Async and iterator bodies.</b> The compiler moves them into a generated state machine
/// type; the method itself only starts it. Without following that the walk stops at the first
/// <c>await</c>, and this product is asynchronous throughout. Missing it condemned 59 types
/// including <c>BundleWriter</c>, which every run uses.</item>
/// <item><b>Type initialisers.</b> Run by the runtime on first touch and never the target of a call
/// instruction. <c>RuleCatalogue</c> constructs every rule in one, so missing it condemned every
/// security rule in the product.</item>
/// <item><b>Virtual and interface dispatch.</b> A call names the declaration, not the body that
/// runs. Rules are invoked through <c>IRule</c>, so missing it meant nothing any rule did inside
/// <c>Evaluate</c> was ever seen.</item>
/// </list>
/// <para>
/// <b>What it still cannot see is reflection.</b> A type constructed by name would look dead. This
/// is viable here only because production does no reflective type discovery at all - no
/// <c>Activator.CreateInstance</c>, no assembly scanning; everything is wired explicitly. If that
/// ever changes, this gate has to be revisited rather than trusted.
/// </para>
/// </remarks>
internal sealed class ReachabilityTrace
{
    private static readonly Dictionary<short, OpCode> Opcodes = BuildOpcodeTable();

    private readonly HashSet<Type> _reachableTypes = [];
    private readonly HashSet<MethodBase> _seenMethods = [];
    private readonly HashSet<MethodInfo> _virtualSlots = [];
    private readonly Queue<MethodBase> _queue = new();
    private readonly HashSet<string> _libraryNames;

    private ReachabilityTrace(IEnumerable<Assembly> libraries) =>
        _libraryNames = libraries.Select(a => a.GetName().Name!).ToHashSet(StringComparer.Ordinal);

    /// <summary>Types in the walked libraries that a root can arrive at.</summary>
    public IReadOnlySet<Type> ReachableTypes => _reachableTypes;

    /// <summary>How many methods the roots contributed, for the scanner self-test.</summary>
    public int RootMethodCount { get; private set; }

    /// <summary>How many methods the walk visited in total, for the scanner self-test.</summary>
    public int WalkedMethodCount => _seenMethods.Count;

    /// <summary>
    /// Walks <paramref name="applications"/> outward into <paramref name="libraries"/>.
    /// </summary>
    /// <param name="applications">
    /// The assemblies a person can launch. Every method in them is a root.
    /// </param>
    /// <param name="libraries">The assemblies whose reachability is being measured.</param>
    public static ReachabilityTrace Walk(
        IReadOnlyList<Assembly> applications, IReadOnlyList<Assembly> libraries)
    {
        ArgumentNullException.ThrowIfNull(applications);
        ArgumentNullException.ThrowIfNull(libraries);

        var trace = new ReachabilityTrace(libraries);
        trace.Run(applications);
        return trace;
    }

    private void Run(IReadOnlyList<Assembly> applications)
    {
        foreach (var application in applications)
        {
            foreach (var type in application.GetTypes())
            {
                foreach (var method in AllMethods(type))
                {
                    Enqueue(method);
                }
            }
        }

        RootMethodCount = _queue.Count;

        bool grew;
        do
        {
            Drain();
            grew = BindTypeInitialisers();
            grew |= BindVirtualOverrides();
        }
        while (grew || _queue.Count > 0);
    }

    private void Enqueue(MethodBase method)
    {
        if (_seenMethods.Add(method))
        {
            _queue.Enqueue(method);
        }
    }

    private bool IsLibrary(Type type) =>
        type.Assembly.GetName().Name is { } name && _libraryNames.Contains(name);

    /// <summary>A type initialiser runs on first touch and is never a call target.</summary>
    private bool BindTypeInitialisers()
    {
        var grew = false;

        foreach (var type in _reachableTypes.ToList())
        {
            if (type.TypeInitializer is { } initialiser && _seenMethods.Add(initialiser))
            {
                _queue.Enqueue(initialiser);
                grew = true;
            }
        }

        return grew;
    }

    /// <summary>
    /// A virtual or interface call names the declaration. The body that actually runs is the
    /// override on whichever concrete type is reachable, so those are bound explicitly.
    /// </summary>
    private bool BindVirtualOverrides()
    {
        var grew = false;

        foreach (var slot in _virtualSlots.ToList())
        {
            if (slot.DeclaringType is not { } declaring)
            {
                continue;
            }

            foreach (var type in _reachableTypes.ToList())
            {
                if (type.IsInterface || type.IsAbstract || !declaring.IsAssignableFrom(type))
                {
                    continue;
                }

                if (FindImplementation(declaring, type, slot) is { } implementation
                    && _seenMethods.Add(implementation))
                {
                    _queue.Enqueue(implementation);
                    grew = true;
                }
            }
        }

        return grew;
    }

    private static MethodInfo? FindImplementation(Type declaring, Type type, MethodInfo slot)
    {
        try
        {
            if (!declaring.IsInterface)
            {
                return type
                    .GetMethods(BindingFlags.Public | BindingFlags.NonPublic
                        | BindingFlags.Instance | BindingFlags.DeclaredOnly)
                    .FirstOrDefault(m => m.IsVirtual && m.GetBaseDefinition() == slot);
            }

            var map = type.GetInterfaceMap(declaring);
            for (var i = 0; i < map.InterfaceMethods.Length; i++)
            {
                if (map.InterfaceMethods[i] == slot)
                {
                    return map.TargetMethods[i];
                }
            }
        }
        catch (ArgumentException)
        {
            // The type does not implement the interface in a way that can be mapped.
        }
        catch (NotSupportedException)
        {
            // Open generic or otherwise unmappable; there is nothing to bind.
        }

        return null;
    }

    private void Drain()
    {
        while (_queue.Count > 0)
        {
            var method = _queue.Dequeue();
            AddSignatureTypes(method);

            foreach (var stateMachine in StateMachines(method))
            {
                foreach (var m in AllMethods(stateMachine))
                {
                    Enqueue(m);
                }
            }

            foreach (var member in ResolveTokens(method))
            {
                Visit(member);
            }
        }
    }

    private void Visit(object member)
    {
        switch (member)
        {
            case Type type:
                AddType(type);

                // A display class holding a lambda's captured state is reached as a type, never as
                // a call, so its methods have to be picked up here.
                if (IsCompilerGenerated(type) && IsLibrary(type))
                {
                    foreach (var m in AllMethods(type))
                    {
                        Enqueue(m);
                    }
                }

                break;

            case FieldInfo field:
                AddType(field.DeclaringType);
                AddType(field.FieldType);
                break;

            case MethodBase called:
                AddType(called.DeclaringType);

                if (called is MethodInfo { IsVirtual: true } or MethodInfo { IsAbstract: true })
                {
                    _virtualSlots.Add(((MethodInfo)called).GetBaseDefinition());
                }

                if (called.DeclaringType is not null && IsLibrary(called.DeclaringType))
                {
                    Enqueue(called);
                }

                break;
        }
    }

    private void AddSignatureTypes(MethodBase method)
    {
        if (method is MethodInfo info)
        {
            AddType(info.ReturnType);
        }

        foreach (var parameter in method.GetParameters())
        {
            AddType(parameter.ParameterType);
        }
    }

    private void AddType(Type? type)
    {
        if (type is null)
        {
            return;
        }

        while (type.HasElementType && type.GetElementType() is { } element)
        {
            type = element;
        }

        if (type.IsGenericType && !type.IsGenericTypeDefinition)
        {
            foreach (var argument in type.GetGenericArguments())
            {
                AddType(argument);
            }

            type = type.GetGenericTypeDefinition();
        }

        if (IsLibrary(type))
        {
            _reachableTypes.Add(type);
        }
    }

    private static IEnumerable<Type> StateMachines(MethodBase method)
    {
        if (method.GetCustomAttribute<AsyncStateMachineAttribute>()?.StateMachineType is { } async)
        {
            yield return async;
        }

        if (method.GetCustomAttribute<IteratorStateMachineAttribute>()?.StateMachineType is { } it)
        {
            yield return it;
        }
    }

    private static bool IsCompilerGenerated(Type type) =>
        type.Name.Contains('<', StringComparison.Ordinal)
        || type.IsDefined(typeof(CompilerGeneratedAttribute), inherit: false);

    private static IEnumerable<MethodBase> AllMethods(Type type)
    {
        const BindingFlags Flags = BindingFlags.Public | BindingFlags.NonPublic
            | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly;

        foreach (var method in type.GetMethods(Flags))
        {
            yield return method;
        }

        foreach (var constructor in type.GetConstructors(Flags))
        {
            yield return constructor;
        }
    }

    private static Dictionary<short, OpCode> BuildOpcodeTable()
    {
        var map = new Dictionary<short, OpCode>();

        foreach (var field in typeof(OpCodes).GetFields(BindingFlags.Public | BindingFlags.Static))
        {
            if (field.GetValue(null) is OpCode op)
            {
                map[op.Value] = op;
            }
        }

        return map;
    }

    /// <summary>
    /// Every type, field and method named by a metadata token in a method's instructions.
    /// </summary>
    private static List<object> ResolveTokens(MethodBase method)
    {
        var found = new List<object>();

        byte[] il;
        try
        {
            il = method.GetMethodBody()?.GetILAsByteArray() ?? [];
        }
        catch (Exception e) when (e is InvalidOperationException or NotSupportedException)
        {
            // Abstract, extern or otherwise bodiless. There is nothing to read.
            return found;
        }

        var module = method.Module;
        var typeArguments = GenericArgumentsOf(method.DeclaringType);
        var methodArguments = method.IsGenericMethodDefinition ? method.GetGenericArguments() : null;

        var i = 0;
        while (i < il.Length)
        {
            short value;
            if (il[i] == 0xFE && i + 1 < il.Length)
            {
                value = (short)(0xFE00 | il[i + 1]);
                i += 2;
            }
            else
            {
                value = il[i];
                i += 1;
            }

            if (!Opcodes.TryGetValue(value, out var op))
            {
                // An opcode this table does not know means the rest of the stream cannot be walked
                // safely. Stopping is correct: guessing would resolve arbitrary bytes as tokens.
                break;
            }

            if (op.OperandType == OperandType.InlineSwitch)
            {
                if (i + 4 > il.Length)
                {
                    break;
                }

                i += 4 + (4 * BitConverter.ToInt32(il, i));
                continue;
            }

            if (CarriesToken(op.OperandType) && i + 4 <= il.Length)
            {
                Resolve(module, BitConverter.ToInt32(il, i), typeArguments, methodArguments, found);
            }

            i += OperandSize(op.OperandType);
        }

        return found;
    }

    private static Type[]? GenericArgumentsOf(Type? declaring) =>
        declaring?.IsGenericType == true ? declaring.GetGenericArguments() : null;

    private static bool CarriesToken(OperandType operand) =>
        operand is OperandType.InlineType or OperandType.InlineMethod
            or OperandType.InlineField or OperandType.InlineTok;

    private static int OperandSize(OperandType operand) => operand switch
    {
        OperandType.InlineNone => 0,
        OperandType.ShortInlineBrTarget or OperandType.ShortInlineI
            or OperandType.ShortInlineVar => 1,
        OperandType.InlineVar => 2,
        OperandType.InlineI8 or OperandType.InlineR => 8,
        _ => 4,
    };

    private static void Resolve(
        Module module, int token, Type[]? typeArguments, Type[]? methodArguments, List<object> into)
    {
        try
        {
            if (module.ResolveMember(token, typeArguments, methodArguments) is { } member)
            {
                into.Add(member);
            }
        }
        catch (ArgumentException)
        {
            // A generic instantiation or vararg signature this context cannot close over. The
            // declaring type is reached by other tokens in the same body, so nothing is lost that
            // would change a verdict.
        }
    }
}
