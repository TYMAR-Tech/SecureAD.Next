using System.Globalization;
using System.Runtime.Serialization.Json;
using System.Xml;

namespace SecureAD.Judgement;

internal sealed class SavedProofJsonReader
{
    private readonly XmlDictionaryReader _json;
    private readonly CancellationToken _token;
    private readonly string _invalidDetails;

    private SavedProofJsonReader(XmlDictionaryReader json, CancellationToken token, string invalidDetails) =>
        (_json, _token, _invalidDetails) = (json, token, invalidDetails);

    internal static T Read<T>(Stream stream, CancellationToken token, string invalidDetails, Func<SavedProofJsonReader, T> read)
    {
        try
        {
            using var input = new ProofStream(stream, token, invalidDetails);
            // The framework reader skips original values larger than its input buffer
            // without materializing their complete strings or object snapshots.
            using var json = JsonReaderWriterFactory.CreateJsonReader(input, XmlDictionaryReaderQuotas.Max);
            var reader = new SavedProofJsonReader(json, token, invalidDetails);
            var result = read(reader);
            reader.Require(reader.AtEnd);
            input.RequireComplete();
            token.ThrowIfCancellationRequested();
            return result;
        }
        catch (XmlException error)
        {
            throw new InvalidDataException(invalidDetails, error);
        }
    }

    internal bool AtEnd => _json.MoveToContent() == XmlNodeType.None;
    internal void Require(bool condition) { if (!condition) throw new InvalidDataException(_invalidDetails); }
    internal void RequireKeys(HashSet<string> keys, params string[] expected) => Require(keys.SetEquals(expected));

    internal HashSet<string> Object(Action<string> read)
    {
        Type("object");
        var keys = new HashSet<string>(StringComparer.Ordinal);
        var empty = _json.IsEmptyElement;
        _json.ReadStartElement();
        if (empty) return keys;
        while (_json.MoveToContent() == XmlNodeType.Element)
        {
            _token.ThrowIfCancellationRequested();
            var name = _json.LocalName;
            Require(keys.Add(name));
            read(name);
        }
        _json.ReadEndElement();
        return keys;
    }

    internal long Array(Action read)
    {
        Type("array");
        var empty = _json.IsEmptyElement;
        _json.ReadStartElement();
        long count = 0;
        if (empty) return count;
        while (_json.MoveToContent() == XmlNodeType.Element)
        {
            _token.ThrowIfCancellationRequested();
            Require(_json.LocalName == "item");
            read();
            count++;
        }
        _json.ReadEndElement();
        return count;
    }

    internal string Text()
    {
        Type("string");
        var value = _json.ReadElementContentAsString();
        Require(!string.IsNullOrWhiteSpace(value));
        return value;
    }

    internal string ValueText()
    {
        Type("string");
        return _json.ReadElementContentAsString();
    }

    internal long SignedNumber()
    {
        Type("number");
        Require(long.TryParse(_json.ReadElementContentAsString(), NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var value));
        return value;
    }

    internal string? OptionalText()
    {
        if (IsNull()) { _json.Skip(); return null; }
        return Text();
    }

    internal bool IsNull() => _json.MoveToContent() == XmlNodeType.Element && _json.GetAttribute("type") == "null";
    internal void Skip(string type) { Type(type); _json.Skip(); }
    internal void Skip()
    {
        _token.ThrowIfCancellationRequested();
        Require(_json.MoveToContent() == XmlNodeType.Element);
        _json.Skip();
    }

    internal Guid GuidValue()
    {
        Require(Guid.TryParseExact(Text(), "D", out var value) && value != Guid.Empty);
        return value;
    }

    internal long Number()
    {
        Type("number");
        Require(long.TryParse(_json.ReadElementContentAsString(), NumberStyles.None, CultureInfo.InvariantCulture, out var value));
        return value;
    }

    internal bool Bit()
    {
        Type("boolean");
        var value = _json.ReadElementContentAsString();
        Require(value is "true" or "false");
        return value == "true";
    }

    private void Type(string expected)
    {
        _token.ThrowIfCancellationRequested();
        Require(_json.MoveToContent() == XmlNodeType.Element && _json.GetAttribute("type") == expected);
    }

    private sealed class ProofStream(Stream source, CancellationToken token, string invalidDetails) : Stream
    {
        private readonly Stack<byte> _containers = new();
        private bool _started, _finished, _quoted, _escaped;
        private byte _previous;
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => source.Length;
        public override long Position { get => source.Position; set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int offset, int count)
        {
            token.ThrowIfCancellationRequested();
            var read = source.Read(buffer, offset, Math.Min(count, 8192));
            Observe(buffer.AsSpan(offset, read));
            return read;
        }
        public override int Read(Span<byte> buffer)
        {
            token.ThrowIfCancellationRequested();
            var read = source.Read(buffer[..Math.Min(buffer.Length, 8192)]);
            Observe(buffer[..read]);
            return read;
        }
        private void Observe(ReadOnlySpan<byte> bytes)
        {
            foreach (var value in bytes)
            {
                if (_quoted)
                {
                    if (_escaped)
                    {
                        Require(value is (byte)'"' or (byte)'\\' or (byte)'/' or (byte)'b' or (byte)'f'
                            or (byte)'n' or (byte)'r' or (byte)'t' or (byte)'u');
                        _escaped = false;
                    }
                    else if (value == '\\') _escaped = true;
                    else if (value == '"') { _quoted = false; _previous = value; }
                    else Require(value >= 0x20);
                    continue;
                }
                if (value is (byte)' ' or (byte)'\t' or (byte)'\r' or (byte)'\n') continue;
                Require(!_finished);
                if (!_started) { Require(value == '{'); _started = true; }
                switch (value)
                {
                    case (byte)'"': _quoted = true; break;
                    case (byte)'{':
                    case (byte)'[':
                        Require(_containers.Count < 64); // The original proof serializer's default maximum depth.
                        _containers.Push(value);
                        break;
                    case (byte)'}':
                    case (byte)']':
                        Require(_previous is not (byte)',' and not (byte)':' && _containers.TryPop(out var open)
                            && open == (value == '}' ? '{' : '['));
                        if (_containers.Count == 0) _finished = true;
                        break;
                }
                _previous = value;
            }
        }
        internal void RequireComplete()
        {
            // The framework reader can synthesize a truncated root's end and ignore a second root.
            Span<byte> remaining = stackalloc byte[8192];
            while (Read(remaining) != 0) { }
            Require(_started && _finished && !_quoted && !_escaped && _containers.Count == 0);
        }
        private void Require(bool condition) { if (!condition) throw new InvalidDataException(invalidDetails); }
        public override void Flush() => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
