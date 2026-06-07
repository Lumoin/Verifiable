using System;

namespace Verifiable.Core.Model.Mdoc;

/// <summary>
/// Encodes the OID4VP 1.0 Appendix B.2.6.1 <c>SessionTranscript</c> the device
/// COSE_Sign1 commits to — the binding that ties an mdoc presentation to a
/// specific OID4VP authorization request.
/// </summary>
/// <remarks>
/// <para>
/// The CBOR seam the mdoc VP-token verifier composes but does not perform
/// itself. Wired by the application to
/// <c>Verifiable.Cbor.Mdoc.Oid4VpMdocSessionTranscriptEncoder.Encode</c>. The
/// verifier and wallet must produce byte-identical transcripts from the same
/// four inputs, or the device signature verifies as invalid.
/// </para>
/// </remarks>
/// <param name="clientId">The authorization-request <c>client_id</c>; byte-exact.</param>
/// <param name="responseUri">The authorization-request <c>response_uri</c>; byte-exact.</param>
/// <param name="authorizationRequestNonce">The authorization-request <c>nonce</c>.</param>
/// <param name="mdocGeneratedNonce">The wallet-supplied <c>mdoc_generated_nonce</c> echoed alongside the vp_token.</param>
/// <returns>The canonical CBOR encoding of <c>SessionTranscript</c>.</returns>
public delegate ReadOnlyMemory<byte> EncodeMdocSessionTranscriptDelegate(
    string clientId,
    string responseUri,
    string authorizationRequestNonce,
    ReadOnlySpan<byte> mdocGeneratedNonce);
