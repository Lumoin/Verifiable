using System.Diagnostics;

namespace Verifiable.OAuth.Server;

/// <summary>
/// The body of an <see cref="IncomingRequest"/>. Carries raw bytes plus the
/// declared <c>Content-Type</c> so handlers can dispatch on the media type
/// without re-parsing the wire payload. The empty value
/// (<see cref="None"/>) means the request carried no body — typical for GET
/// requests and for form-encoded POSTs whose payload was already parsed
/// into <see cref="IncomingRequest.Fields"/>.
/// </summary>
/// <remarks>
/// <para>
/// The skin populates this slot only for requests whose body cannot be
/// represented as form fields — for example RFC 7591 §3 dynamic registration
/// (JSON), RFC 7592 §2.2 client update (JSON), OID4VCI credential requests
/// (JSON), and eventually mdoc / SD-CWT credential paths (CBOR).
/// Form-encoded bodies stay in <see cref="IncomingRequest.Fields"/>; this
/// slot remains at <see cref="None"/>.
/// </para>
/// <para>
/// <see cref="Bytes"/> is exposed as <see cref="ReadOnlyMemory{T}"/> rather
/// than <see cref="string"/> so binary bodies (CBOR, COSE) flow through the
/// same slot without a UTF-8 round-trip. UTF-8 text consumers decode at
/// parse time, typically inside a delegate the application wires.
/// </para>
/// </remarks>
[DebuggerDisplay("RequestBody {ContentType,nq} ({Bytes.Length} bytes)")]
public sealed record RequestBody
{
    /// <summary>The raw body bytes.</summary>
    public ReadOnlyMemory<byte> Bytes { get; init; } = ReadOnlyMemory<byte>.Empty;

    /// <summary>The declared Content-Type, or empty when the body is absent.</summary>
    public string ContentType { get; init; } = string.Empty;

    /// <summary>Returns <see langword="true"/> when no body is present.</summary>
    public bool IsEmpty => ContentType.Length == 0;

    /// <summary>The empty body — used for form-encoded POSTs and GET requests.</summary>
    public static RequestBody None { get; } = new();
}
