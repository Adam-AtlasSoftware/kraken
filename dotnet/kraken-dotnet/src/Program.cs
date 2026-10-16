using System.Net.Sockets;
using System.Text.Json.Nodes;

namespace Kraken.DotNet;

/// <summary>
/// KRAKEN .NET sidecar: JSON-RPC 2.0 with length-prefixed frames. Without --stdio the protocol
/// runs over the socketpair the parent passes as fd 0 (both directions, like the Ghidra sidecar);
/// with --stdio it uses stdin and stdout.
/// </summary>
public static class Program
{
    public const string Version = "0.0.0";

    public static int Main(string[] args)
    {
        bool stdio = false;
        int watchParent = 0;
        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--stdio":
                    stdio = true;
                    break;
                case "--watch-parent" when i + 1 < args.Length && int.TryParse(args[i + 1], out int pid):
                    watchParent = pid;
                    i++;
                    break;
                case "--dump-truth" when i + 1 < args.Length:
                    return DumpTruth(args[i + 1]);
                case "--version":
                    Console.Error.WriteLine($"kraken-dotnet {Version}");
                    return 0;
                default:
                    Console.Error.WriteLine($"unknown argument `{args[i]}`");
                    return 2;
            }
        }

        if (watchParent != 0)
        {
            StartParentWatch(watchParent);
        }

        Stream input;
        Stream output;
        if (stdio)
        {
            input = Console.OpenStandardInput();
            output = Console.OpenStandardOutput();
        }
        else
        {
            // fd 0 is one end of a Unix socketpair; it carries both directions.
            var socket = new Socket(new SafeSocketHandle(0, ownsHandle: false));
            var net = new NetworkStream(socket, ownsSocket: false);
            input = net;
            output = net;
        }

        var framing = new Framing(input, output);
        var dispatcher = new Dispatcher();
        try
        {
            while (true)
            {
                JsonNode? msg = framing.Read();
                if (msg is null)
                {
                    return 0;
                }
                JsonNode? reply = Handle(dispatcher, msg, out bool shutdown);
                if (reply is not null)
                {
                    framing.Write(reply);
                }
                if (shutdown)
                {
                    return 0;
                }
            }
        }
        catch (Exception e) when (e is IOException or InvalidDataException or EndOfStreamException)
        {
            Console.Error.WriteLine($"channel failed: {e.Message}");
            return 1;
        }
    }

    /// <summary>Prints method names, tokens and sizes of an assembly as JSON (corpus ground truth).</summary>
    private static int DumpTruth(string path)
    {
        var asm = LoadedAssembly.Open(System.IO.Path.GetFullPath(path));
        var functions = new JsonArray();
        foreach (var f in asm.AllFunctions())
        {
            functions.Add(f);
        }
        var o = new JsonObject
        {
            ["module_mvid"] = asm.Mvid,
            ["sha256"] = asm.Sha256,
            ["assembly"] = asm.Name,
            ["functions"] = functions,
        };
        Console.Out.WriteLine(o.ToJsonString(new System.Text.Json.JsonSerializerOptions { WriteIndented = true }));
        return 0;
    }

    private static JsonNode? Handle(Dispatcher dispatcher, JsonNode msg, out bool shutdown)
    {
        shutdown = false;
        JsonNode? id = msg["id"];
        string? method = msg["method"]?.GetValue<string>();
        if (method is null)
        {
            return null;
        }
        if (id is null)
        {
            return null; // notifications from the client are not used
        }
        var reply = new JsonObject { ["jsonrpc"] = "2.0", ["id"] = id.DeepClone() };
        try
        {
            JsonObject p = msg["params"] as JsonObject ?? [];
            reply["result"] = dispatcher.Call(method, p);
            shutdown = method == "shutdown";
        }
        catch (KrakenError e)
        {
            reply["error"] = ErrorObject(e.RpcCode, e.Code, e.Message);
        }
        catch (Exception e)
        {
            Console.Error.WriteLine(e);
            reply["error"] = ErrorObject(-32603, "internal", $"{e.GetType().Name}: {e.Message}");
        }
        return reply;
    }

    private static JsonObject ErrorObject(int rpcCode, string code, string message) => new()
    {
        ["code"] = rpcCode,
        ["message"] = message,
        ["data"] = new JsonObject { ["code"] = code },
    };

    private static void StartParentWatch(int pid)
    {
        var t = new Thread(() =>
        {
            try
            {
                using var parent = System.Diagnostics.Process.GetProcessById(pid);
                parent.WaitForExit();
            }
            catch (ArgumentException)
            {
                // already gone
            }
            Environment.Exit(1);
        })
        { IsBackground = true, Name = "parent-watch" };
        t.Start();
    }
}
