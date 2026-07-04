using System.Buffers;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Cesr.Streaming;

/// <summary>
/// A top-level item read from a CESR stream: a protocol genus/version code, a count code together with the
/// body it frames, or an interleaved non-native (JSON/CBOR/MGPK) serialization. For a
/// <see cref="CesrTokenKind.CountGroup"/> the framed body bytes are held in pooled memory the caller owns; for a
/// <see cref="CesrTokenKind.NonNative"/> the whole serialization is held the same way; for a
/// <see cref="CesrTokenKind.GenusVersion"/> there is no body.
/// </summary>
/// <remarks>
/// The body is owned by the caller, who MUST dispose this instance to return the buffer to its pool. For a count
/// group the body is the framed group bytes in this token's <see cref="Domain"/> — the binary-domain (qb2) bytes
/// when read with <see cref="CesrStreamReader.ReadBinaryAsync"/>, or the text-domain (qb64) characters as ASCII
/// bytes when read with <see cref="CesrStreamReader.ReadTextAsync"/> — ready to be descended into with a
/// semantics-aware reader. For a non-native item the body is the raw JSON/CBOR/MGPK serialization
/// (<see cref="Serialization"/> names which), to be deserialized by the consumer.
/// </remarks>
[SuppressMessage("Performance", "CA1815:Override equals and operator equals on value types", Justification = "This is a disposable owner of pooled memory, not a comparable value; equality is not meaningful.")]
public readonly struct CesrToken: IDisposable
{
    private readonly IMemoryOwner<byte>? bodyOwner;

    /// <summary>
    /// Initializes a new instance of the <see cref="CesrToken"/> struct.
    /// </summary>
    /// <param name="kind">The token kind.</param>
    /// <param name="domain">The representation domain the surrounding CESR stream is in; meaningful for a count group's <see cref="Body"/>.</param>
    /// <param name="serialization">The non-native serialization a <see cref="CesrTokenKind.NonNative"/> body carries, or <see cref="CesrSerializationKind.None"/> for native CESR framing.</param>
    /// <param name="code">The stable (hard) count code, or the empty string for a non-native item.</param>
    /// <param name="count">The quadlet/triplet count for a count group, or the packed version for a genus/version code.</param>
    /// <param name="bodyOwner">The pooled buffer holding the framed body, or <see langword="null"/> when there is no body.</param>
    /// <param name="bodyLength">The number of valid body bytes at the start of <paramref name="bodyOwner"/>.</param>
    public CesrToken(CesrTokenKind kind, CesrDomain domain, CesrSerializationKind serialization, string code, int count, IMemoryOwner<byte>? bodyOwner, int bodyLength)
    {
        Kind = kind;
        Domain = domain;
        Serialization = serialization;
        Code = code;
        Count = count;
        this.bodyOwner = bodyOwner;
        BodyLength = bodyLength;
    }

    /// <summary>
    /// The kind of item.
    /// </summary>
    public CesrTokenKind Kind { get; }

    /// <summary>
    /// For a count group, the representation domain its <see cref="Body"/> is expressed in:
    /// <see cref="CesrDomain.Binary"/> (qb2 bytes) for a token read from a binary stream, or
    /// <see cref="CesrDomain.Text"/> (qb64 characters as ASCII bytes) for a token read from a text stream. For a
    /// non-native item the body is its own serialization (see <see cref="Serialization"/>), not a CESR domain.
    /// </summary>
    public CesrDomain Domain { get; }

    /// <summary>
    /// The non-native serialization a <see cref="CesrTokenKind.NonNative"/> body carries (JSON, CBOR, or MGPK),
    /// or <see cref="CesrSerializationKind.None"/> for a genus/version code or count group.
    /// </summary>
    public CesrSerializationKind Serialization { get; }

    /// <summary>
    /// The stable (hard) count code, for example <c>-V</c>, <c>--V</c>, or <c>-_AAA</c>.
    /// </summary>
    public string Code { get; }

    /// <summary>
    /// The soft value: the number of quadlets/triplets the group body occupies (<see cref="CesrTokenKind.CountGroup"/>),
    /// or the packed protocol version (<see cref="CesrTokenKind.GenusVersion"/>, see <see cref="Version"/>).
    /// </summary>
    public int Count { get; }

    /// <summary>
    /// The number of valid body bytes in <see cref="Body"/>; zero for a genus/version code. For a text-domain
    /// token this is the number of qb64 characters (one ASCII byte each).
    /// </summary>
    public int BodyLength { get; }

    /// <summary>
    /// For a count group, the framed group body in this token's <see cref="Domain"/> (qb2 bytes or qb64 ASCII
    /// characters); for a non-native item, the raw JSON/CBOR/MGPK serialization. An empty span for a
    /// genus/version code.
    /// </summary>
    public ReadOnlySpan<byte> Body => bodyOwner is null ? default : bodyOwner.Memory.Span[..BodyLength];

    /// <summary>
    /// The framed group body as memory, suitable for handing to a semantics-aware reader (for a binary-domain
    /// token, <see cref="CesrGroupReader"/>) to walk the group element by element. Empty for a genus/version
    /// code. Valid only until this token is disposed.
    /// </summary>
    public ReadOnlyMemory<byte> BodyMemory => bodyOwner is null ? default : bodyOwner.Memory[..BodyLength];

    /// <summary>
    /// The major and minor protocol version of a genus/version code, or <see langword="null"/> for a count group.
    /// </summary>
    public (int Major, int Minor)? Version =>
        Kind == CesrTokenKind.GenusVersion ? CesrCountCodeTables.UnpackVersion(Count) : null;

    /// <summary>
    /// Returns the pooled body buffer to its pool.
    /// </summary>
    public void Dispose() => bodyOwner?.Dispose();
}
