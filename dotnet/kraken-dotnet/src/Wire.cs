using System.Buffers.Binary;
using System.Text.Json.Nodes;

namespace Kraken.DotNet;

/// <summary>A failure reported as a JSON-RPC error carrying a kraken-proto ErrorCode string.</summary>
public sealed class KrakenError(string code, string message) : Exception(message)
{
    public string Code { get; } = code;

    public static KrakenError Invalid(string m) => new("invalid_argument", m);
    public static KrakenError NotFound(string m) => new("not_found", m);
    public static KrakenError Unsupported(string m) => new("unsupported", m);
    public static KrakenError Internal(string m) => new("internal", m);
    public static KrakenError Timeout(string m) => new("timeout", m);

    public int RpcCode => Code switch
    {
        "invalid_argument" => -32602,
        "unsupported" => -32601,
        "internal" => -32603,
        _ => -32000,
    };
}

/// <summary>4-byte big-endian length followed by a UTF-8 JSON message (decisions 41, 87).</summary>
public sealed class Framing(Stream input, Stream output)
{
    public const int MaxFrame = 64 * 1024 * 1024;
    private readonly object _writeLock = new();

    /// <summary>Reads one message; null on a clean EOF at a frame boundary.</summary>
    public JsonNode? Read()
    {
        var len = new byte[4];
        int first = input.Read(len, 0, 1);
        if (first == 0)
        {
            return null;
        }
        input.ReadExactly(len.AsSpan(1));
        uint n = BinaryPrimitives.ReadUInt32BigEndian(len);
        if (n > MaxFrame)
        {
            throw new InvalidDataException($"bad frame length {n}");
        }
        var body = new byte[n];
        input.ReadExactly(body);
        return JsonNode.Parse(body);
    }

    public void Write(JsonNode message)
    {
        byte[] body = System.Text.Encoding.UTF8.GetBytes(message.ToJsonString());
        if (body.Length > MaxFrame)
        {
            throw new InvalidDataException($"frame of {body.Length} bytes exceeds the {MaxFrame} byte limit");
        }
        var buf = new byte[4 + body.Length];
        BinaryPrimitives.WriteUInt32BigEndian(buf, (uint)body.Length);
        body.CopyTo(buf, 4);
        lock (_writeLock)
        {
            output.Write(buf);
            output.Flush();
        }
    }
}
