using System.Buffers;

namespace Verifiable.Core.Model.SelectiveDisclosure;

/// <summary>
/// Builds the CBOR-encoded payload of an SD-CWT Key Binding Token (KBT) per
/// <see href="https://ietf-wg-spice.github.io/draft-ietf-spice-sd-cwt/draft-ietf-spice-sd-cwt.html">
/// draft-ietf-spice-sd-cwt §7.1</see>. The serialization-agnostic
/// <c>KbCwtIssuance</c> orchestrator coordinates this seam; the application wires
/// it to a CBOR implementation — typically <c>Verifiable.Cbor.Sd.SdKbtIssuance.BuildPayload</c>.
/// </summary>
/// <remarks>
/// <para>
/// The KBT payload is a CWT claims map carrying <c>aud</c> (claim key 3, MUST),
/// <c>iat</c> (claim key 6, Unix seconds), and — when
/// <paramref name="cnonce"/> is non-<see langword="null"/> — <c>cnonce</c>
/// (claim key 39). The <c>iss</c> (1) and <c>sub</c> (2) claims MUST NOT be
/// present.
/// </para>
/// <para>
/// The returned <see cref="IMemoryOwner{T}"/> is pool-rented; the caller releases
/// it (typically via a <c>using</c>) once the payload has been signed, so no naked
/// bytes cross the surface.
/// </para>
/// </remarks>
/// <param name="aud">The verifier audience for the <c>aud</c> claim.</param>
/// <param name="iat">The issuance timestamp in Unix seconds for the <c>iat</c> claim.</param>
/// <param name="cnonce">The verifier nonce for the <c>cnonce</c> claim, or <see langword="null"/> to omit it.</param>
/// <param name="pool">Memory pool the returned buffer is rented from.</param>
/// <returns>The CBOR-encoded payload in a pool-rented buffer the caller owns.</returns>
public delegate IMemoryOwner<byte> BuildKbtPayloadDelegate(
    string aud,
    long iat,
    string? cnonce,
    MemoryPool<byte> pool);
