namespace Verifiable.Cesr;

/// <summary>
/// The serialization of a non-native (non-CESR) field map interleaved at the top level of a CESR stream. A
/// CESR stream may interleave JSON, CBOR, and MGPK (MessagePack) message serializations with native CESR
/// framing; this names which of those a stream item carries.
/// </summary>
/// <remarks>
/// <para>
/// Anchored on the CESR specification's <see href="https://trustoverip.github.io/kswg-cesr-specification/#stream-parsing-rules">
/// Stream parsing rules</see> and <see href="https://trustoverip.github.io/kswg-cesr-specification/#version-string-field">
/// Version String field</see>: a parser MUST support these three interleaved serializations, and the
/// serialization kind is conveyed by the <c>KKKK</c> part of the leading version string. (The version string
/// also admits a <c>CESR</c> kind, but a native CESR field map is framed by a count code rather than
/// interleaved as a non-native body, so it is not represented here.)
/// </para>
/// </remarks>
public enum CesrSerializationKind
{
    /// <summary>
    /// Not a non-native serialization (the stream item is native CESR framing — a genus/version or count code).
    /// </summary>
    None = 0,

    /// <summary>
    /// JSON (<c>KKKK</c> = <c>JSON</c>), per IETF RFC 4627.
    /// </summary>
    Json = 1,

    /// <summary>
    /// CBOR (<c>KKKK</c> = <c>CBOR</c>), per IETF RFC 8949.
    /// </summary>
    Cbor = 2,

    /// <summary>
    /// MGPK / MessagePack (<c>KKKK</c> = <c>MGPK</c>).
    /// </summary>
    Mgpk = 3
}
