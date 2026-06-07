using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Text;

namespace Verifiable.Cbor.Mdoc;

/// <summary>
/// Encodes the <c>SessionTranscript</c> CBOR shape per OID4VP 1.0
/// Appendix B.2.6.1 — the binding the device signature commits to that
/// ties an mdoc presentation to a specific OID4VP authorization request.
/// </summary>
/// <remarks>
/// <para>
/// On the wire:
/// </para>
/// <code>
/// SessionTranscript = [
///   null,                ; DeviceEngagementBytes — null for HTTP transports
///   null,                ; EReaderKeyBytes — null for HTTP transports
///   OID4VPHandover       ; the OID4VP handover-data
/// ]
///
/// OID4VPHandover = [
///   clientIdToHash,      ; SHA-256(CBOR([client_id, mdoc_generated_nonce]))
///   responseUriToHash,   ; SHA-256(CBOR([response_uri, mdoc_generated_nonce]))
///   nonce                ; the nonce from the authorization request
/// ]
/// </code>
/// <para>
/// The wallet generates a fresh <c>mdoc_generated_nonce</c> per
/// presentation (≥ 16 bytes of CSPRNG output per the spec), uses it both
/// in the two hashes AND echoes the same value to the verifier so the
/// verifier can reconstruct the SessionTranscript byte-for-byte. The
/// verifier's reconstruction MUST hash to the same bytes — otherwise the
/// COSE_Sign1 in <see cref="Core.Model.Mdoc.MdocDeviceSigned"/> won't
/// verify.
/// </para>
/// <para>
/// This encoder is transport-shape-aware (OID4VP-over-HTTP) but otherwise
/// format-agnostic. The wallet and verifier flows on both sides call
/// <see cref="Encode"/> with the same four inputs to produce identical
/// bytes.
/// </para>
/// </remarks>
public static class Oid4VpMdocSessionTranscriptEncoder
{
    /// <summary>
    /// Builds the OID4VP SessionTranscript byte sequence that
    /// <see cref="MdocCborDeviceSignedSigner.SignAsync"/> and
    /// <see cref="MdocCborDeviceSignedVerifier.VerifyAsync"/> consume as
    /// their <c>encodedSessionTranscript</c> argument.
    /// </summary>
    /// <param name="clientId">
    /// The OID4VP authorization-request <c>client_id</c>. Verifier and
    /// wallet must use byte-identical strings.
    /// </param>
    /// <param name="responseUri">
    /// The OID4VP authorization-request <c>response_uri</c>. Same byte-
    /// identical constraint.
    /// </param>
    /// <param name="authorizationRequestNonce">
    /// The <c>nonce</c> claim from the JAR's authorization request. Echoed
    /// verbatim as the third element of <c>OID4VPHandover</c>.
    /// </param>
    /// <param name="mdocGeneratedNonce">
    /// The wallet-side fresh nonce (≥ 16 bytes per the spec). The wallet
    /// transmits this value to the verifier in the presentation response
    /// alongside the <c>vp_token</c> so the verifier can reconstruct the
    /// transcript.
    /// </param>
    /// <returns>The canonical CBOR encoding of <c>SessionTranscript</c>.</returns>
    /// <remarks>
    /// <paramref name="responseUri"/> is typed as <see cref="string"/>
    /// rather than <see cref="Uri"/> because the OID4VP B.2.6.1 hashing
    /// inputs the byte-exact string the verifier sees in the
    /// authorization request — <see cref="Uri"/>'s normalisation (case,
    /// default ports, trailing-slash) would risk a different CBOR
    /// encoding on the two sides.
    /// </remarks>
    [System.Diagnostics.CodeAnalysis.SuppressMessage(
        "Design", "CA1054:URI-like parameters should not be strings",
        Justification = "Byte-exact string hashing per OID4VP 1.0 §B.2.6.1; Uri normalisation would break the wallet/verifier hash agreement.")]
    public static ReadOnlyMemory<byte> Encode(
        string clientId,
        string responseUri,
        string authorizationRequestNonce,
        ReadOnlySpan<byte> mdocGeneratedNonce)
    {
        ArgumentException.ThrowIfNullOrEmpty(clientId);
        ArgumentException.ThrowIfNullOrEmpty(responseUri);
        ArgumentException.ThrowIfNullOrEmpty(authorizationRequestNonce);

        if(mdocGeneratedNonce.Length < MinimumMdocGeneratedNonceLength)
        {
            throw new ArgumentException(
                $"mdoc_generated_nonce must be at least {MinimumMdocGeneratedNonceLength} bytes per OID4VP 1.0 Appendix B.2.6.1.",
                nameof(mdocGeneratedNonce));
        }

        byte[] clientIdHash = HashIdentifierWithNonce(clientId, mdocGeneratedNonce);
        byte[] responseUriHash = HashIdentifierWithNonce(responseUri, mdocGeneratedNonce);

        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartArray(3);

        writer.WriteNull(); //DeviceEngagementBytes — null per HTTP transport
        writer.WriteNull(); //EReaderKeyBytes — null per HTTP transport

        //OID4VPHandover = [clientIdHash, responseUriHash, nonce]
        writer.WriteStartArray(3);
        writer.WriteByteString(clientIdHash);
        writer.WriteByteString(responseUriHash);
        writer.WriteTextString(authorizationRequestNonce);
        writer.WriteEndArray();

        writer.WriteEndArray();

        return writer.Encode();
    }


    /// <summary>
    /// Generates a fresh <c>mdoc_generated_nonce</c> per the OID4VP B.2.6.1
    /// requirement of at least 16 bytes of cryptographically secure
    /// randomness. The wallet keeps the returned buffer alive for the
    /// duration of the presentation (it consults the bytes twice — once for
    /// the SessionTranscript hashes, once to base64url-encode for
    /// transmission alongside the vp_token).
    /// </summary>
    /// <param name="fillEntropy">
    /// The entropy source delegate filling the nonce bytes. The wallet owns
    /// the entropy source and its provenance tracking; there is deliberately
    /// no overload that fills from the OS CSPRNG directly.
    /// </param>
    /// <param name="pool">Memory pool the wallet allocates from.</param>
    /// <param name="byteLength">Nonce length in bytes (≥ 16). Defaults to <see cref="MinimumMdocGeneratedNonceLength"/>.</param>
    /// <returns>The freshly-generated nonce. Caller owns and must dispose.</returns>
    public static System.Buffers.IMemoryOwner<byte> GenerateMdocGeneratedNonce(
        Verifiable.Cryptography.FillEntropyDelegate fillEntropy,
        System.Buffers.MemoryPool<byte> pool,
        int byteLength = MinimumMdocGeneratedNonceLength)
    {
        ArgumentNullException.ThrowIfNull(fillEntropy);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentOutOfRangeException.ThrowIfLessThan(byteLength, MinimumMdocGeneratedNonceLength);

        System.Buffers.IMemoryOwner<byte> owner = pool.Rent(byteLength);
        Span<byte> span = owner.Memory.Span[..byteLength];
        fillEntropy(span);

        return owner;
    }


    /// <summary>The OID4VP 1.0 Appendix B.2.6.1 minimum length for <c>mdoc_generated_nonce</c>.</summary>
    public const int MinimumMdocGeneratedNonceLength = 16;


    /// <summary>
    /// Computes <c>SHA-256(CBOR([identifier, mdoc_generated_nonce]))</c>
    /// per OID4VP 1.0 Appendix B.2.6.1. Both <c>clientIdToHash</c> and
    /// <c>responseUriToHash</c> follow this exact shape — only the
    /// identifier value differs.
    /// </summary>
    private static byte[] HashIdentifierWithNonce(string identifier, ReadOnlySpan<byte> mdocGeneratedNonce)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartArray(2);
        writer.WriteTextString(identifier);
        writer.WriteByteString(mdocGeneratedNonce);
        writer.WriteEndArray();

        byte[] encoded = writer.Encode();

        return SHA256.HashData(encoded);
    }
}
