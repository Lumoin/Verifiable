using Lumoin.Veritas.Cbor;

namespace Verifiable.Cbor;

/// <summary>
/// Holds the four <see cref="CborSerializerOptions"/> presets every reader and writer
/// construction in this library rides: <see cref="Lax"/>, <see cref="Strict"/>,
/// <see cref="RfcCanonical"/> and <see cref="Ctap2Canonical"/>, one per
/// <see cref="CborConformanceMode"/> this library exercises.
/// </summary>
/// <remarks>
/// <para>
/// Each property is a single instance built once, at first access, by
/// <see cref="CborSerializerOptions.Default(CborConformanceMode)"/> and shared by every caller
/// that asks for that mode. It is never mutated after publication: the first
/// <see cref="CborReader"/> or <see cref="CborWriter"/> constructed from an instance freezes its
/// <see cref="CborSerializerOptions.Converters"/> collection, so a later registration attempt on a
/// shared preset would be refused, and a scalar setting changed on a shared preset (its
/// <see cref="CborSerializerOptions.MaxDepth"/> or <see cref="CborSerializerOptions.MaxArrayLength"/>,
/// say) would move every other caller of that preset along with it.
/// </para>
/// <para>
/// None of the four presets registers a converter: this library writes its COSE, CWT, mdoc,
/// CTAP2 and status-list tags by hand rather than through <see cref="CborConverter{T}"/>
/// dispatch, so <see cref="CborSerializerOptions.Converters"/> stays empty on every preset. A
/// call site that needs its own size or depth ceilings, or that does register a converter,
/// builds a fresh instance with <see cref="CborSerializerOptions.Default(CborConformanceMode)"/>
/// instead of reaching for a preset here.
/// </para>
/// </remarks>
public static class CborOptions
{
    /// <summary>
    /// Gets the shared <see cref="CborSerializerOptions"/> for <see cref="CborConformanceMode.Lax"/>:
    /// indefinite-length items allowed, UTF-8 not validated.
    /// </summary>
    public static CborSerializerOptions Lax { get; } = CborSerializerOptions.Default(CborConformanceMode.Lax);

    /// <summary>
    /// Gets the shared <see cref="CborSerializerOptions"/> for <see cref="CborConformanceMode.Strict"/>:
    /// indefinite-length items allowed, UTF-8 validated, no map-key ordering enforced.
    /// </summary>
    public static CborSerializerOptions Strict { get; } = CborSerializerOptions.Default(CborConformanceMode.Strict);

    /// <summary>
    /// Gets the shared <see cref="CborSerializerOptions"/> for <see cref="CborConformanceMode.RfcCanonical"/>:
    /// the RFC 8949 §4.2.1 deterministic encoding rules, indefinite-length items refused.
    /// </summary>
    public static CborSerializerOptions RfcCanonical { get; } = CborSerializerOptions.Default(CborConformanceMode.RfcCanonical);

    /// <summary>
    /// Gets the shared <see cref="CborSerializerOptions"/> for <see cref="CborConformanceMode.Ctap2Canonical"/>:
    /// the CTAP2 canonical CBOR encoding form FIDO2 authenticators require, indefinite-length items refused.
    /// </summary>
    public static CborSerializerOptions Ctap2Canonical { get; } = CborSerializerOptions.Default(CborConformanceMode.Ctap2Canonical);
}
