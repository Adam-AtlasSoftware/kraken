using System.Text;
using System.Text.Json.Nodes;
using ICSharpCode.Decompiler.CSharp.OutputVisitor;
using ICSharpCode.Decompiler.CSharp.Syntax;
using ICSharpCode.Decompiler.CSharp.Resolver;
using ICSharpCode.Decompiler.Semantics;
using ICSharpCode.Decompiler.TypeSystem;
using ICSharpCode.Decompiler.CSharp;

namespace Kraken.DotNet;

/// <summary>
/// Writes C# through ILSpy's own token writer into a buffer and records, for each lexical token,
/// its span, a coarse kind and, where ILSpy resolved the identifier to a program entity, a managed
/// locator and the symbol name.
/// </summary>
public sealed class RecordingTokenWriter : TokenWriter
{
    private sealed record Rec(int Start, int End, string Kind, JsonObject? Target, string? Symbol);

    private readonly LoadedAssembly _asm;
    private readonly StringBuilder _sb;
    private readonly TokenWriter _inner;
    private readonly Stack<AstNode> _nodes = new();
    private readonly List<Rec> _tokens = [];

    public RecordingTokenWriter(LoadedAssembly asm, StringBuilder sb)
    {
        _asm = asm;
        _sb = sb;
        _inner = Create(new StringWriter(sb), "    ");
    }

    private void Record(int start, string kind, JsonObject? target = null, string? symbol = null)
    {
        int end = _sb.Length;
        // The inner writer emits pending indentation inside the first token of a line.
        while (start < end && char.IsWhiteSpace(_sb[start]))
        {
            start++;
        }
        if (end > start)
        {
            _tokens.Add(new Rec(start, end, kind, target, symbol));
        }
    }

    public override void StartNode(AstNode node)
    {
        _nodes.Push(node);
        _inner.StartNode(node);
    }

    public override void EndNode(AstNode node)
    {
        _inner.EndNode(node);
        if (_nodes.Count > 0)
        {
            _nodes.Pop();
        }
    }

    public override void WriteIdentifier(Identifier identifier)
    {
        int start = _sb.Length;
        _inner.WriteIdentifier(identifier);
        var (kind, target) = Classify(_nodes.Count > 0 ? _nodes.Peek() : identifier);
        Record(start, kind, target, identifier.Name);
    }

    public override void WriteKeyword(string keyword)
    {
        int start = _sb.Length;
        _inner.WriteKeyword(keyword);
        Record(start, "keyword", null, keyword);
    }

    public override void WriteToken(string token)
    {
        int start = _sb.Length;
        _inner.WriteToken(token);
        Record(start, "op");
    }

    public override void WriteInterpolatedText(string text)
    {
        int start = _sb.Length;
        _inner.WriteInterpolatedText(text);
        Record(start, "constant");
    }

    public override void WritePrimitiveType(string type)
    {
        int start = _sb.Length;
        _inner.WritePrimitiveType(type);
        Record(start, "type", null, type);
    }

    public override void WritePrimitiveValue(object? value, LiteralFormat format)
    {
        int start = _sb.Length;
        _inner.WritePrimitiveValue(value, format);
        Record(start, "constant");
    }

    public override void WriteComment(CommentType commentType, string content)
    {
        int start = _sb.Length;
        _inner.WriteComment(commentType, content);
        Record(start, "comment");
    }

    public override void WritePreProcessorDirective(PreProcessorDirectiveType type, string? argument)
    {
        int start = _sb.Length;
        _inner.WritePreProcessorDirective(type, argument);
        Record(start, "other");
    }

    public override void Space() => _inner.Space();

    public override void Indent() => _inner.Indent();

    public override void Unindent() => _inner.Unindent();

    public override void NewLine() => _inner.NewLine();

    private (string Kind, JsonObject? Target) Classify(AstNode node)
    {
        if (node.Annotation<ILVariableResolveResult>() is not null)
        {
            return ("variable", null);
        }
        ISymbol? symbol = node.GetSymbol();
        if (symbol is null && node.Parent is InvocationExpression inv && ReferenceEquals(inv.Target, node))
        {
            symbol = inv.GetSymbol();
        }
        switch (symbol)
        {
            case IMethod m:
                return ("function", _asm.LocatorOf(m.MemberDefinition));
            case IField or IProperty or IEvent:
                return ("field", _asm.LocatorOf(((IMember)symbol).MemberDefinition));
            case ITypeDefinition td:
                return ("type", _asm.LocatorOf(td));
            case IType t:
                return ("type", t.GetDefinition() is { } d ? _asm.LocatorOf(d) : null);
            case IVariable:
                return ("variable", null);
        }
        return ("other", null);
    }

    /// <summary>The recorded tokens with UTF-16 offsets converted to the UTF-8 byte offsets of the wire.</summary>
    public JsonArray ToJson(string text)
    {
        var arr = new JsonArray();
        int charPos = 0;
        int bytePos = 0;
        int Advance(int to)
        {
            if (to > charPos)
            {
                bytePos += Encoding.UTF8.GetByteCount(text.AsSpan(charPos, to - charPos));
                charPos = to;
            }
            return bytePos;
        }
        foreach (var t in _tokens.OrderBy(t => t.Start).ThenBy(t => t.End))
        {
            if (t.Start < charPos)
            {
                continue; // overlapping record; keep the first
            }
            int s = Advance(t.Start);
            int e = Advance(t.End);
            var o = new JsonObject { ["start"] = s, ["end"] = e, ["kind"] = t.Kind };
            if (t.Target is not null)
            {
                o["target"] = t.Target.DeepClone();
            }
            if (t.Symbol is not null)
            {
                o["symbol"] = t.Symbol;
            }
            arr.Add(o);
        }
        return arr;
    }
}
