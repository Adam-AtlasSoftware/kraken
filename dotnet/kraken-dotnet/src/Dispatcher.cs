using System.Text.Json.Nodes;

namespace Kraken.DotNet;

/// <summary>Maps JSON-RPC methods to the loaded assembly. Requests are served one at a time.</summary>
public sealed class Dispatcher
{
    private const int MaxLimit = 500;
    private const int DefaultLimit = 100;

    private LoadedAssembly? _asm;

    public JsonNode Call(string method, JsonObject p)
    {
        switch (method)
        {
            case "handshake":
                return Handshake();
            case "ping":
                return new JsonObject { ["ok"] = true };
            case "open_assembly":
                {
                    string path = Str(p, "path");
                    if (!System.IO.Path.IsPathRooted(path))
                    {
                        throw KrakenError.Invalid("path must be absolute");
                    }
                    _asm = LoadedAssembly.Open(path);
                    return _asm.Info();
                }
            case "list_functions":
                return Asm().ListFunctions(OptStr(p, "cursor"), Limit(p));
            case "get_function":
                return Asm().GetFunction(p["locator"]);
            case "decompile":
                return Asm().Decompile(p["locator"], p["timeout_ms"]?.GetValue<long>());
            case "list_types":
                return Asm().ListTypes(OptStr(p, "cursor"), Limit(p));
            case "get_type":
                return Asm().GetType(Str(p, "name"));
            case "shutdown":
                _asm = null;
                return new JsonObject { ["ok"] = true };
            default:
                throw KrakenError.Unsupported($"method not found: {method}");
        }
    }

    private LoadedAssembly Asm() => _asm ?? throw KrakenError.Invalid("no assembly is open; call open_assembly first");

    private static JsonObject Handshake()
    {
        string[] names = ["open_assembly", "list_functions", "decompile.tokens", "list_types", "types.read"];
        var caps = new JsonArray();
        foreach (string n in names)
        {
            caps.Add(new JsonObject { ["name"] = n, ["version"] = 1 });
        }
        return new JsonObject
        {
            ["protocol"] = new JsonObject { ["major"] = 0, ["minor"] = 1 },
            ["build"] = $"kraken-dotnet {Program.Version} (ICSharpCode.Decompiler {typeof(ICSharpCode.Decompiler.DecompilerSettings).Assembly.GetName().Version})",
            ["capabilities"] = caps,
        };
    }

    private static string Str(JsonObject p, string key) =>
        p[key]?.GetValue<string>() ?? throw KrakenError.Invalid($"missing parameter `{key}`");

    private static string? OptStr(JsonObject p, string key) => p[key]?.GetValue<string>();

    private static int Limit(JsonObject p)
    {
        int l = p["limit"]?.GetValue<int>() ?? DefaultLimit;
        return Math.Clamp(l, 1, MaxLimit);
    }
}
