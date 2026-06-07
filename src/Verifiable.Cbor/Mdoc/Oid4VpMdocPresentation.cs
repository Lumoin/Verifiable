using System.Buffers;
using Verifiable.Core.Model.Mdoc;
using Verifiable.Cryptography;

namespace Verifiable.Cbor.Mdoc;

/// <summary>
/// High-level wallet-side assembler for an OID4VP mdoc presentation.
/// Composes <see cref="MdocCborDeviceResponseWriter.EncodeDeviceResponse"/>
/// with a caller-supplied base64url codec to produce the value that goes
/// into the OID4VP <c>vp_token</c> slot per OID4VP 1.0 Appendix B.2.6.
/// </summary>
/// <remarks>
/// <para>
/// Codec functions are passed in as <see cref="EncodeDelegate"/> /
/// <see cref="DecodeDelegate"/> so the application's base64url binding
/// (already wired through <c>TestSetup.Base64UrlEncoder</c> /
/// <c>TestSetup.Base64UrlDecoder</c> in tests and the equivalent
/// production wiring) flows through without re-binding. Same plug-in
/// shape <see cref="Verifiable.JCose.CryptoFormatConversions.DefaultAlgorithmToJwkConverter"/>
/// uses for its base64url-encoded JWK fields.
/// </para>
/// <para>
/// The wallet flow this composes:
/// </para>
/// <list type="number">
///   <item><description>
///     Call <see cref="Oid4VpMdocSessionTranscriptEncoder.GenerateMdocGeneratedNonce"/>
///     and store the bytes for the response.
///   </description></item>
///   <item><description>
///     Call <see cref="Oid4VpMdocSessionTranscriptEncoder.Encode"/> with
///     <c>client_id</c>, <c>response_uri</c>, the authorization-request
///     <c>nonce</c>, and the fresh <c>mdoc_generated_nonce</c>.
///   </description></item>
///   <item><description>
///     Call <see cref="MdocCborDeviceSignedSigner.SignAsync"/> with the
///     SessionTranscript bytes from step 2 to produce
///     <see cref="MdocDeviceSigned"/>.
///   </description></item>
///   <item><description>
///     Combine the existing <see cref="MdocDocument"/> (with M.3 issuer
///     signature) and the device-signed half into a complete
///     <see cref="MdocDocument"/>, wrap as a one-element
///     <see cref="MdocDeviceResponse"/>, and call
///     <see cref="AssembleVpTokenValue"/> here to get the base64url string
///     for the OID4VP <c>vp_token</c> response.
///   </description></item>
///   <item><description>
///     Transmit the vp_token value along with the
///     <c>mdoc_generated_nonce</c> (typically base64url-encoded via
///     <see cref="EncodeMdocGeneratedNonceForTransmission"/>) so the
///     verifier can reconstruct the SessionTranscript and run the M.3b
///     verifier against the same bytes.
///   </description></item>
/// </list>
/// </remarks>
public static class Oid4VpMdocPresentation
{
    /// <summary>
    /// Encodes <paramref name="deviceResponse"/> as the OID4VP single-
    /// credential <c>vp_token</c> value — base64url-encoded CBOR bytes per
    /// OID4VP 1.0 Appendix B.2.6.
    /// </summary>
    /// <param name="deviceResponse">The DeviceResponse to encode.</param>
    /// <param name="base64UrlEncoder">
    /// The application's base64url encoder delegate. Typically wired once
    /// at setup time as part of the encoding-codec configuration.
    /// </param>
    /// <returns>The base64url string suitable for the vp_token slot.</returns>
    public static string AssembleVpTokenValue(
        MdocDeviceResponse deviceResponse,
        EncodeDelegate base64UrlEncoder)
    {
        ArgumentNullException.ThrowIfNull(deviceResponse);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);

        ReadOnlyMemory<byte> encoded = MdocCborDeviceResponseWriter.EncodeDeviceResponse(deviceResponse);

        return base64UrlEncoder(encoded.Span);
    }


    /// <summary>
    /// Decodes an OID4VP single-credential mdoc <c>vp_token</c> value
    /// (base64url string) back to the raw CBOR-encoded
    /// <see cref="MdocDeviceResponse"/> bytes. The verifier feeds the
    /// resulting bytes into a CBOR reader to parse the response. A full
    /// reader for the device-response wire envelope is outside M.7a; the
    /// verifier flows already in place consume the constituent
    /// <see cref="MdocIssuerAuth"/> / <see cref="MdocDeviceSigned"/> parts
    /// directly when the wallet hands them through.
    /// </summary>
    /// <param name="vpTokenValue">The base64url-encoded vp_token value.</param>
    /// <param name="base64UrlDecoder">The application's base64url decoder delegate.</param>
    /// <param name="pool">Memory pool for the decoded buffer.</param>
    /// <returns>
    /// The decoded CBOR bytes. Caller owns the returned memory and must
    /// dispose it.
    /// </returns>
    public static IMemoryOwner<byte> DecodeVpTokenValue(
        string vpTokenValue,
        DecodeDelegate base64UrlDecoder,
        MemoryPool<byte> pool)
    {
        ArgumentException.ThrowIfNullOrEmpty(vpTokenValue);
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(pool);

        return base64UrlDecoder(vpTokenValue.AsSpan(), pool);
    }


    /// <summary>
    /// Encodes the wallet's <c>mdoc_generated_nonce</c> as base64url for
    /// transmission alongside the vp_token. The verifier base64url-decodes
    /// the same value via
    /// <see cref="DecodeMdocGeneratedNonceForTransmissionRoundTrip"/> to
    /// reconstruct the SessionTranscript.
    /// </summary>
    /// <param name="mdocGeneratedNonce">The raw nonce bytes.</param>
    /// <param name="base64UrlEncoder">The application's base64url encoder delegate.</param>
    /// <returns>The base64url string suitable for transmission.</returns>
    public static string EncodeMdocGeneratedNonceForTransmission(
        ReadOnlySpan<byte> mdocGeneratedNonce,
        EncodeDelegate base64UrlEncoder)
    {
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);

        return base64UrlEncoder(mdocGeneratedNonce);
    }


    /// <summary>
    /// Decodes the base64url-encoded <c>mdoc_generated_nonce</c> the wallet
    /// transmitted in the presentation response. Symmetric inverse of
    /// <see cref="EncodeMdocGeneratedNonceForTransmission"/>.
    /// </summary>
    /// <param name="transmitted">The base64url-encoded nonce as received.</param>
    /// <param name="base64UrlDecoder">The application's base64url decoder delegate.</param>
    /// <param name="pool">Memory pool for the decoded buffer.</param>
    /// <returns>
    /// The decoded nonce bytes. Caller owns the returned memory and must
    /// dispose it.
    /// </returns>
    public static IMemoryOwner<byte> DecodeMdocGeneratedNonceForTransmissionRoundTrip(
        string transmitted,
        DecodeDelegate base64UrlDecoder,
        MemoryPool<byte> pool)
    {
        ArgumentException.ThrowIfNullOrEmpty(transmitted);
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(pool);

        return base64UrlDecoder(transmitted.AsSpan(), pool);
    }
}
