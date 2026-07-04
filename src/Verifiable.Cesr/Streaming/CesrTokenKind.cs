namespace Verifiable.Cesr.Streaming;

/// <summary>
/// The kind of top-level item a <see cref="CesrStreamReader"/> yields from a CESR stream. At the top level a
/// stream is self-describing — the cold-start tritet distinguishes the cases — so these are the items that may
/// appear there. Items nested inside a count group (primitives, indexed signatures, sub-groups) are not yielded
/// directly; the group's body is handed back for a semantics-aware consumer to descend into.
/// </summary>
/// <remarks>
/// Anchored on the CESR specification's <see href="https://trustoverip.github.io/kswg-cesr-specification/#stream-parsing-rules">
/// Stream parsing rules</see>: a stream starts or restarts with a count code, an op code, or an interleaved
/// non-native (JSON/CBOR/MGPK) mapping — never a bare primitive.
/// </remarks>
public enum CesrTokenKind
{
    /// <summary>
    /// A protocol genus/version code (<c>-_GGGVVV</c>). It frames no body; it sets the protocol genus and
    /// version of the count codes that follow it.
    /// </summary>
    GenusVersion = 0,

    /// <summary>
    /// A count code (<c>-X</c> / <c>--X</c>) and the group it frames: the following quadlets/triplets are the
    /// group body, returned for the consumer to descend into.
    /// </summary>
    CountGroup = 1,

    /// <summary>
    /// A non-native (JSON, CBOR, or MGPK) field map interleaved at the top level of the stream: the whole
    /// serialization, sized from its leading version string, is returned as the body for the consumer to
    /// deserialize. The serialization is identified by <see cref="CesrToken.Serialization"/>.
    /// </summary>
    NonNative = 2
}
