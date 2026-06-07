namespace Verifiable.Core.Model.SelectiveDisclosure;

/// <summary>
/// Extracts the <c>iss</c> claim (CWT claim 1 = <c>WellKnownCwtClaimNames.Iss</c>)
/// from an SD-CWT's issuer-signed payload so the verifier can resolve the issuer's
/// public key via <see cref="ResolveSdCwtIssuerKeyDelegate"/>.
/// </summary>
/// <remarks>
/// <para>
/// A pure CBOR parse seam — it reads the <c>iss</c> text string from the SD-CWT's
/// COSE_Sign1 payload without any cryptographic validation. Wired by the application
/// to a <c>Verifiable.Cbor</c> implementation — typically
/// <c>Verifiable.Cbor.Sd.SdCwtVpParsing.ExtractIssuer</c>.
/// </para>
/// </remarks>
/// <param name="sdCwt">The embedded presentation SD-CWT whose issuer-signed payload carries <c>iss</c>.</param>
/// <returns>The <c>iss</c> claim value, or <see langword="null"/> when absent.</returns>
public delegate string? ExtractSdCwtIssuerDelegate(SdToken<System.ReadOnlyMemory<byte>> sdCwt);
