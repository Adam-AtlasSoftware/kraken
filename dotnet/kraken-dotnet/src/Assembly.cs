using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using ICSharpCode.Decompiler;
using ICSharpCode.Decompiler.CSharp;
using ICSharpCode.Decompiler.Metadata;
using ICSharpCode.Decompiler.TypeSystem;

namespace Kraken.DotNet;

/// <summary>One opened assembly: metadata reader, ILSpy type system and decompiler.</summary>
public sealed class LoadedAssembly
{
    public const int MethodTable = 0x06;

    private readonly PEFile _file;
    private readonly MetadataReader _md;
    private readonly CSharpDecompiler _decompiler;
    private readonly DecompilerSettings _settings;
    private readonly MetadataModule _module;
    private readonly List<TypeDefinitionHandle> _typesByName;
    private readonly Dictionary<PEFile, string> _mvids = [];

    public string Path { get; }
    public string Mvid { get; }
    public string Sha256 { get; }
    public long Size { get; }
    public long ImageBase { get; }
    public string Name { get; }
    public string? TargetFramework { get; }
    public int MethodCount => _md.MethodDefinitions.Count;
    public int TypeCount => _typesByName.Count;

    private LoadedAssembly(string path, PEFile file, CSharpDecompiler decompiler, DecompilerSettings settings, byte[] bytes)
    {
        _settings = settings;
        Path = path;
        _file = file;
        _md = file.Metadata;
        _decompiler = decompiler;
        _module = (MetadataModule)decompiler.TypeSystem.MainModule;
        Mvid = MvidOf(file);
        _mvids[file] = Mvid;
        Sha256 = Convert.ToHexStringLower(SHA256.HashData(bytes));
        Size = bytes.Length;
        ImageBase = (long)(file.Reader.PEHeaders.PEHeader?.ImageBase ?? 0);
        Name = _md.GetString(_md.GetAssemblyDefinition().Name);
        TargetFramework = file.DetectTargetFrameworkId();
        _typesByName = _md.TypeDefinitions
            .Where(h => _md.GetString(_md.GetTypeDefinition(h).Name) != "<Module>")
            .OrderBy(h => TypeName(h), StringComparer.Ordinal)
            .ToList();
    }

    public static LoadedAssembly Open(string path)
    {
        byte[] bytes;
        try
        {
            bytes = File.ReadAllBytes(path);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            throw KrakenError.NotFound($"cannot read {path}: {e.Message}");
        }
        PEFile file;
        try
        {
            file = new PEFile(path, new MemoryStream(bytes), PEStreamOptions.PrefetchEntireImage);
        }
        catch (Exception e) when (e is BadImageFormatException or MetadataFileNotSupportedException or InvalidOperationException)
        {
            throw KrakenError.Invalid($"{path} is not a .NET assembly: {e.Message}");
        }
        if (!file.Metadata.IsAssembly)
        {
            throw KrakenError.Invalid($"{path} is a .NET module without an assembly manifest");
        }

        var resolver = new UniversalAssemblyResolver(path, throwOnError: false, file.DetectTargetFrameworkId());
        resolver.AddSearchDirectory(System.IO.Path.GetDirectoryName(path) ?? ".");
        resolver.AddSearchDirectory(System.Runtime.InteropServices.RuntimeEnvironment.GetRuntimeDirectory());
        var settings = new DecompilerSettings
        {
            ThrowOnAssemblyResolveErrors = false,
            ShowXmlDocumentation = false,
            UsingDeclarations = false,
        };
        var decompiler = new CSharpDecompiler(file, resolver, settings);
        return new LoadedAssembly(path, file, decompiler, settings, bytes);
    }

    private static string MvidOf(PEFile file)
    {
        var md = file.Metadata;
        return md.GetGuid(md.GetModuleDefinition().Mvid).ToString("D");
    }

    private string MvidOfModule(IModule? module)
    {
        if (module?.MetadataFile is PEFile pe)
        {
            if (!_mvids.TryGetValue(pe, out string? mvid))
            {
                mvid = MvidOf(pe);
                _mvids[pe] = mvid;
            }
            return mvid;
        }
        return "";
    }

    // ---- names ---------------------------------------------------------------------------

    public string TypeName(TypeDefinitionHandle h)
    {
        var td = _md.GetTypeDefinition(h);
        string name = _md.GetString(td.Name);
        var declaring = td.GetDeclaringType();
        if (!declaring.IsNil)
        {
            return TypeName(declaring) + "." + name;
        }
        string ns = _md.GetString(td.Namespace);
        return ns.Length == 0 ? name : ns + "." + name;
    }

    public string MethodName(MethodDefinitionHandle h)
    {
        var m = _md.GetMethodDefinition(h);
        return TypeName(m.GetDeclaringType()) + "." + _md.GetString(m.Name);
    }

    // ---- locators ------------------------------------------------------------------------

    public JsonObject Locator(EntityHandle h) => Locator(Mvid, MetadataTokens.GetToken(h));

    public static JsonObject Locator(string mvid, int token) => new()
    {
        ["kind"] = "managed",
        ["module"] = mvid,
        ["token"] = token,
    };

    /// <summary>A locator for an ILSpy entity, in whatever module it lives; null if it has no token.</summary>
    public JsonObject? LocatorOf(IEntity e)
    {
        if (e.MetadataToken.IsNil)
        {
            return null;
        }
        string mvid = MvidOfModule(e.ParentModule);
        return mvid.Length == 0 ? null : Locator(mvid, MetadataTokens.GetToken(e.MetadataToken));
    }

    /// <summary>
    /// A locator for the Param row behind a parameter variable of a method of this assembly; null for
    /// locals, `this` and parameters of other modules.
    /// </summary>
    public JsonObject? ParameterLocatorOf(ICSharpCode.Decompiler.IL.ILVariable v)
    {
        if (v.Kind != ICSharpCode.Decompiler.IL.VariableKind.Parameter || v.Index is not int index || index < 0)
        {
            return null;
        }
        var method = v.Function?.Method;
        if (method is null || method.MetadataToken.IsNil || method.MetadataToken.Kind != HandleKind.MethodDefinition
            || !string.Equals(MvidOfModule(method.ParentModule), Mvid, StringComparison.Ordinal))
        {
            return null;
        }
        var def = _md.GetMethodDefinition((MethodDefinitionHandle)method.MetadataToken);
        foreach (var ph in def.GetParameters())
        {
            if (_md.GetParameter(ph).SequenceNumber == index + 1)
            {
                return Locator(ph);
            }
        }
        return null;
    }

    public MethodDefinitionHandle ParseMethod(JsonNode? locator)
    {
        if (locator is not JsonObject o || o["kind"]?.GetValue<string>() != "managed")
        {
            throw KrakenError.Invalid("expected a managed locator");
        }
        string module = o["module"]?.GetValue<string>() ?? throw KrakenError.Invalid("locator.module is missing");
        int token = o["token"]?.GetValue<int>() ?? throw KrakenError.Invalid("locator.token is missing");
        if (!string.Equals(module, Mvid, StringComparison.OrdinalIgnoreCase))
        {
            throw KrakenError.NotFound($"module {module} is not the open assembly ({Mvid})");
        }
        if (token >> 24 != MethodTable)
        {
            throw KrakenError.NotFound($"token 0x{token:x8} is not a method");
        }
        int row = token & 0xFFFFFF;
        if (row < 1 || row > _md.MethodDefinitions.Count)
        {
            throw KrakenError.NotFound($"no method with token 0x{token:x8}");
        }
        return MetadataTokens.MethodDefinitionHandle(row);
    }

    // ---- functions -----------------------------------------------------------------------

    public JsonObject FunctionSummary(MethodDefinitionHandle h)
    {
        var m = _md.GetMethodDefinition(h);
        var o = new JsonObject
        {
            ["locator"] = Locator(h),
            ["name"] = MethodName(h),
        };
        if (_module.GetDefinition(h) is IMethod im)
        {
            o["signature"] = Signature(im);
        }
        if (m.RelativeVirtualAddress != 0)
        {
            byte[] il = _file.Reader.GetMethodBody(m.RelativeVirtualAddress).GetILBytes() ?? [];
            o["size"] = il.Length;
            o["fn_hash"] = Convert.ToHexStringLower(SHA256.HashData(il));
        }
        o["completeness"] = new JsonObject { ["kind"] = "complete" };
        return o;
    }

    private static string Signature(IMethod m)
    {
        string ps = string.Join(", ", m.Parameters.Select(p => p.Type.Name + " " + p.Name));
        return $"{m.ReturnType.Name} {m.Name}({ps})";
    }

    /// <summary>Name, token and IL size of every method (ground-truth dump).</summary>
    public IEnumerable<JsonObject> AllFunctions()
    {
        foreach (var h in _md.MethodDefinitions)
        {
            var m = _md.GetMethodDefinition(h);
            int size = m.RelativeVirtualAddress == 0
                ? -1
                : _file.Reader.GetMethodBody(m.RelativeVirtualAddress).GetILBytes()?.Length ?? 0;
            var o = new JsonObject
            {
                ["name"] = MethodName(h),
                ["token"] = "0x" + MetadataTokens.GetToken(h).ToString("x8"),
            };
            if (size >= 0)
            {
                o["size"] = size;
            }
            yield return o;
        }
    }

    public JsonObject ListFunctions(string? cursor, int limit)
    {
        int after = 0;
        if (cursor is not null && !int.TryParse(cursor, out after))
        {
            throw KrakenError.Invalid($"malformed cursor `{cursor}`");
        }
        if (after < 0)
        {
            throw KrakenError.Invalid($"malformed cursor `{cursor}`");
        }
        int total = _md.MethodDefinitions.Count;
        var items = new JsonArray();
        int row = after;
        while (row < total && items.Count < limit)
        {
            row++;
            items.Add(FunctionSummary(MetadataTokens.MethodDefinitionHandle(row)));
        }
        var page = new JsonObject { ["items"] = items, ["total"] = total };
        if (row < total)
        {
            page["next_cursor"] = row.ToString();
        }
        return page;
    }

    public JsonObject GetFunction(JsonNode? locator) => FunctionSummary(ParseMethod(locator));

    // ---- decompile -----------------------------------------------------------------------

    public JsonObject Decompile(JsonNode? locator, long? timeoutMs)
    {
        var h = ParseMethod(locator);
        using var cts = new CancellationTokenSource();
        if (timeoutMs is > 0)
        {
            cts.CancelAfter(TimeSpan.FromMilliseconds(timeoutMs.Value));
        }
        _decompiler.CancellationToken = cts.Token;
        try
        {
            var tree = _decompiler.Decompile(h);
            var sb = new StringBuilder();
            var writer = new RecordingTokenWriter(this, sb);
            tree.AcceptVisitor(new ICSharpCode.Decompiler.CSharp.OutputVisitor.CSharpOutputVisitor(
                writer, _settings.CSharpFormattingOptions));
            string text = sb.ToString();
            var warnings = new JsonArray();
            if (text.Trim().Length == 0)
            {
                warnings.Add("the decompiler produced no output for this method");
            }
            return new JsonObject
            {
                ["function"] = Locator(h),
                ["language"] = "csharp",
                ["text"] = text,
                ["tokens"] = writer.ToJson(text),
                ["warnings"] = warnings,
                ["completeness"] = new JsonObject { ["kind"] = "complete" },
            };
        }
        catch (OperationCanceledException)
        {
            throw KrakenError.Timeout($"decompiling {MethodName(h)} timed out after {timeoutMs} ms");
        }
        finally
        {
            _decompiler.CancellationToken = CancellationToken.None;
        }
    }

    // ---- types ---------------------------------------------------------------------------

    public JsonObject ListTypes(string? cursor, int limit)
    {
        int start = 0;
        if (cursor is not null && (!int.TryParse(cursor, out start) || start < 0))
        {
            throw KrakenError.Invalid($"malformed cursor `{cursor}`");
        }
        var items = new JsonArray();
        int i = start;
        for (; i < _typesByName.Count && items.Count < limit; i++)
        {
            items.Add(TypeDef(_typesByName[i]));
        }
        var page = new JsonObject { ["items"] = items, ["total"] = _typesByName.Count };
        if (i < _typesByName.Count)
        {
            page["next_cursor"] = i.ToString();
        }
        return page;
    }

    public JsonObject GetType(string name)
    {
        foreach (var h in _typesByName)
        {
            if (TypeName(h) == name)
            {
                return TypeDef(h);
            }
        }
        throw KrakenError.NotFound($"no type named `{name}`");
    }

    /// <summary>
    /// The neutral C-like type model has no managed concepts, so a managed type is mapped loosely:
    /// enums become enums; everything else a struct with size 0 (runtime-defined layout) listing
    /// its instance fields. Field types are primitives or references by C# full name.
    /// </summary>
    private JsonObject TypeDef(TypeDefinitionHandle h)
    {
        string name = TypeName(h);
        if (_module.GetDefinition(h) is not ITypeDefinition td)
        {
            return StructOf(name, []);
        }
        if (td.Kind == TypeKind.Enum)
        {
            var variants = new JsonArray();
            foreach (var f in td.Fields.Where(f => f.IsConst))
            {
                variants.Add(new JsonObject
                {
                    ["name"] = f.Name,
                    ["value"] = Convert.ToInt64(f.GetConstantValue(), System.Globalization.CultureInfo.InvariantCulture),
                });
            }
            return new JsonObject
            {
                ["kind"] = "enum",
                ["name"] = name,
                ["size"] = SizeOf(td.EnumUnderlyingType?.GetDefinition()?.KnownTypeCode ?? KnownTypeCode.Int32),
                ["variants"] = variants,
            };
        }
        var fields = new JsonArray();
        foreach (var f in td.Fields.Where(f => !f.IsStatic && !f.IsConst))
        {
            fields.Add(new JsonObject
            {
                ["name"] = f.Name,
                ["offset"] = 0,
                ["type"] = TypeRef(f.Type),
            });
        }
        return StructOf(name, fields);
    }

    private static JsonObject StructOf(string name, JsonArray fields) => new()
    {
        ["kind"] = "struct",
        ["name"] = name,
        ["size"] = 0,
        ["align"] = 1,
        ["fields"] = fields,
    };

    private static JsonObject TypeRef(IType t)
    {
        var code = t.GetDefinition()?.KnownTypeCode ?? KnownTypeCode.None;
        (string cls, bool signed)? prim = code switch
        {
            KnownTypeCode.Void => ("void", false),
            KnownTypeCode.Boolean => ("bool", false),
            KnownTypeCode.Char => ("char", false),
            KnownTypeCode.SByte or KnownTypeCode.Int16 or KnownTypeCode.Int32 or KnownTypeCode.Int64 or KnownTypeCode.IntPtr => ("int", true),
            KnownTypeCode.Byte or KnownTypeCode.UInt16 or KnownTypeCode.UInt32 or KnownTypeCode.UInt64 or KnownTypeCode.UIntPtr => ("int", false),
            KnownTypeCode.Single or KnownTypeCode.Double => ("float", true),
            _ => null,
        };
        if (prim is { } p)
        {
            return new JsonObject
            {
                ["kind"] = "primitive",
                ["class"] = p.cls,
                ["size"] = SizeOf(code),
                ["signed"] = p.signed,
            };
        }
        return new JsonObject { ["kind"] = "named", ["name"] = t.FullName.Length > 0 ? t.FullName : t.Name };
    }

    private static int SizeOf(KnownTypeCode code) => code switch
    {
        KnownTypeCode.Void => 0,
        KnownTypeCode.Boolean or KnownTypeCode.SByte or KnownTypeCode.Byte => 1,
        KnownTypeCode.Char or KnownTypeCode.Int16 or KnownTypeCode.UInt16 => 2,
        KnownTypeCode.Int32 or KnownTypeCode.UInt32 or KnownTypeCode.Single => 4,
        KnownTypeCode.Int64 or KnownTypeCode.UInt64 or KnownTypeCode.Double => 8,
        KnownTypeCode.IntPtr or KnownTypeCode.UIntPtr => IntPtr.Size,
        _ => 4,
    };

    // ---- info ----------------------------------------------------------------------------

    public JsonObject Info() => new()
    {
        ["arch"] = "cil",
        ["format"] = "dotnet",
        ["base"] = "0x" + ImageBase.ToString("x"),
        ["sha256"] = Sha256,
        ["size"] = Size,
        ["module_mvid"] = Mvid,
        ["assembly"] = Name,
        ["target_framework"] = TargetFramework,
        ["method_count"] = MethodCount,
        ["type_count"] = TypeCount,
    };
}
