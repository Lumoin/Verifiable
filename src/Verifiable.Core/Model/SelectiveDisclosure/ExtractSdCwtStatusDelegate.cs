using Verifiable.Core.StatusList;

namespace Verifiable.Core.Model.SelectiveDisclosure;

/// <summary>
/// Extracts the <c>status</c> claim (CWT claim 65535) from an SD-CWT's issuer-signed payload — the
/// Status CBOR structure per
/// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.3">
/// Token Status List, Section 6.3</see> — so the verifier can run the same status step it runs for
/// the SD-JWT and mdoc formats.
/// </summary>
/// <remarks>
/// <para>
/// A pure CBOR parse seam — it reads the Status structure from the SD-CWT's COSE_Sign1 payload
/// without any cryptographic validation. Wired by the application to a <c>Verifiable.Cbor</c>
/// implementation — typically <c>Verifiable.Cbor.Sd.SdCwtVpParsing.ExtractStatus</c>. The SD-CWT
/// analog of <see cref="ExtractSdCwtIssuerDelegate"/> and
/// <see cref="ExtractSdCwtCredentialTypeDelegate"/>, differing only in that the claim's value is a
/// structure rather than a text string.
/// </para>
/// <para>
/// Section 6.3 says the Referenced Token "MAY be encoded as a "CBOR Web Token (CWT)" object
/// according to [RFC8392], as an SD-CWTs [I-D.ietf-spice-sd-cwt] or as an ISO mdoc", so the
/// structure this reads is the same one an mdoc's Mobile Security Object carries under its own
/// <c>status</c> member; both decode to <see cref="StatusClaim"/>.
/// </para>
/// </remarks>
/// <param name="sdCwt">The embedded presentation SD-CWT whose issuer-signed payload may carry <c>status</c>.</param>
/// <returns>The decoded status claim, or <see langword="null"/> when the claim is absent.</returns>
/// <exception cref="System.FormatException">
/// Thrown when the claim is present but its Status structure is not well-formed. Implementations
/// normalize a CBOR-level rejection to this type at their own public boundary, the way
/// <see cref="ParseSdCwtTokenDelegate"/> and <see cref="ExtractKcwtFromKbtDelegate"/> do, because the
/// OID4VP verifier that classifies the presentation as Wallet-attributable malformation cannot name
/// the CBOR leaf's own exception type.
/// </exception>
public delegate StatusClaim? ExtractSdCwtStatusDelegate(SdToken<System.ReadOnlyMemory<byte>> sdCwt);
