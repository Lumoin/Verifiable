using System.Buffers;
using Verifiable.JCose;

namespace Verifiable.Core.Model.SelectiveDisclosure;

/// <summary>
/// Builds the CBOR-encoded <c>protected</c> header of an SD-CWT Key Binding
/// Token (KBT) per
/// <see href="https://ietf-wg-spice.github.io/draft-ietf-spice-sd-cwt/draft-ietf-spice-sd-cwt.html">
/// draft-ietf-spice-sd-cwt §7.1</see>. The serialization-agnostic
/// <c>KbCwtIssuance</c> orchestrator coordinates this seam; the application wires
/// it to a CBOR implementation — typically <c>Verifiable.Cbor.Sd.SdKbtIssuance.BuildProtectedHeader</c>.
/// </summary>
/// <remarks>
/// <para>
/// The KBT protected header is a CBOR map carrying <c>typ</c> (label 16) set to
/// the KBT type value, <c>alg</c> (label 1) set to <paramref name="coseAlgorithm"/>,
/// and <c>kcwt</c> (label 13) set to the entire embedded presentation SD-CWT. The
/// presentation SD-CWT is derived from <paramref name="presentationToken"/>: its
/// issuer-signed COSE_Sign1 carrying the holder-selected disclosures in the
/// <c>sd_claims</c> unprotected header.
/// </para>
/// <para>
/// The returned <see cref="EncodedCoseProtectedHeader"/> is a pool-routed carrier
/// the caller transfers to the COSE signer; no naked bytes cross the surface.
/// </para>
/// </remarks>
/// <param name="coseAlgorithm">The holder key's COSE algorithm identifier for the <c>alg</c> parameter.</param>
/// <param name="presentationToken">The SD-CWT presentation token whose issuer COSE_Sign1 and selected disclosures are embedded under <c>kcwt</c>.</param>
/// <param name="pool">Memory pool the returned carrier rents its buffer from.</param>
/// <returns>The CBOR-encoded protected header wrapped in a pool-routed carrier.</returns>
public delegate EncodedCoseProtectedHeader BuildKbtProtectedHeaderDelegate(
    int coseAlgorithm,
    SdToken<ReadOnlyMemory<byte>> presentationToken,
    MemoryPool<byte> pool);
