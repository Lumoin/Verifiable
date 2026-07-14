using System.Buffers;
using Verifiable.Core.Model.Mdoc;
using Verifiable.Core.Model.SelectiveDisclosure;
using Verifiable.Cryptography;
using Verifiable.JCose;

namespace Verifiable.OAuth.Oid4Vp.Server;

/// <summary>
/// Parses and cryptographically verifies an mdoc (ISO/IEC 18013-5)
/// <c>DeviceResponse</c> VP token presented through OID4VP 1.0 §8.1, returning
/// the same <see cref="VpTokenParsed"/> result boundary the SD-JWT path produces
/// so the executor can validate every format uniformly.
/// </summary>
/// <remarks>
/// <para>
/// This class contains no serialization dependencies. The CBOR work — decoding
/// the DeviceResponse envelope, reconstructing the SessionTranscript, decoding
/// each element value — crosses the
/// <see cref="ParseMdocDeviceResponseDelegate"/>,
/// <see cref="EncodeMdocSessionTranscriptDelegate"/>, and
/// <see cref="DecodeMdocElementValueDelegate"/> seams the application wires to
/// <c>Verifiable.Cbor.Mdoc</c>. The COSE_Sign1 parse / Sig_structure delegates
/// (<see cref="ParseCoseSign1Delegate"/>, <see cref="BuildSigStructureDelegate"/>,
/// <see cref="EncodeDeviceAuthenticationBytesDelegate"/>) are the same seams the
/// Core mdoc verify extensions already take.
/// </para>
/// <para>
/// The verification sequence per document:
/// </para>
/// <list type="number">
///   <item><description>Base64url-decode the vp_token value, then parse the DeviceResponse via <see cref="ParseMdocDeviceResponseDelegate"/>.</description></item>
///   <item><description>Verify the issuer-auth COSE_Sign1 against the key the trust framework resolves from the IssuerAuth (<see cref="ResolveMdocIssuerKeyDelegate"/>).</description></item>
///   <item><description>Validate the MSO digest binding over every presented item (<see cref="MdocMsoDigestBindingValidator"/>).</description></item>
///   <item><description>Derive the device key from the issuer-committed MSO (<see cref="CoseKeyExtensions.ToPublicKeyMemory"/>).</description></item>
///   <item><description>Reconstruct the SessionTranscript and verify the device COSE_Sign1 over it.</description></item>
///   <item><description>Surface the disclosed claims keyed by element identifier.</description></item>
/// </list>
/// <para>
/// Result mapping: <see cref="VpTokenParsed.CredentialSignatureValid"/> is the
/// issuer-auth signature AND the digest binding;
/// <see cref="VpTokenParsed.SessionTranscriptValid"/> is the device signature
/// over the reconstructed transcript. mdoc carries no KB-JWT — the transcript
/// binds <c>client_id</c>/<c>response_uri</c>/<c>nonce</c>, so this check
/// subsumes the SD-JWT nonce+aud binding. The KB-JWT and <c>sd_hash</c> axes are
/// not applicable to mdoc and follow the codebase's "N/A is not a failure"
/// convention (mirroring the SD-JWT path's <see cref="VpTokenParsed.SessionTranscriptValid"/>).
/// </para>
/// </remarks>
public static class MdocVpTokenVerification
{
    /// <summary>
    /// Verifies an mdoc VP token and returns the extracted, verified contents.
    /// </summary>
    /// <param name="vpToken">The base64url-encoded DeviceResponse value from the OID4VP vp_token slot.</param>
    /// <param name="credentialQueryId">
    /// The DCQL credential query identifier that matched this token. Used as the
    /// key in <see cref="VpTokenParsed.ExtractedClaims"/>.
    /// </param>
    /// <param name="resolveIssuerKey">
    /// Application-provided trust delegate that resolves the issuer's
    /// verification key from the IssuerAuth (typically an IACA x5chain resolver).
    /// </param>
    /// <param name="extractAuthorityIdentifier">
    /// Optional delegate that extracts the leaf certificate's AuthorityKeyIdentifier
    /// (base64url) from the IssuerAuth x5chain, surfaced on
    /// <see cref="VpTokenParsed.CredentialIssuer"/> for DCQL <c>trusted_authorities</c>
    /// (type <c>aki</c>) enforcement. <see langword="null"/> surfaces no authority identifier.
    /// </param>
    /// <param name="clientId">The authorization-request <c>client_id</c> bound into the SessionTranscript.</param>
    /// <param name="responseUri">The authorization-request <c>response_uri</c> bound into the SessionTranscript.</param>
    /// <param name="authorizationRequestNonce">The authorization-request <c>nonce</c> bound into the SessionTranscript.</param>
    /// <param name="mdocGeneratedNonce">
    /// The wallet-supplied <c>mdoc_generated_nonce</c> (already base64url-decoded)
    /// echoed alongside the vp_token so the verifier reconstructs the transcript.
    /// </param>
    /// <param name="parseDeviceResponse">Delegate that parses the DeviceResponse wire bytes. Wired to <c>MdocCborDeviceResponseReader.Read</c>.</param>
    /// <param name="encodeSessionTranscript">Delegate that encodes the SessionTranscript. Wired to <c>Oid4VpMdocSessionTranscriptEncoder.Encode</c>.</param>
    /// <param name="decodeElementValue">Delegate that decodes a CBOR element value to a string. Wired over <c>CborValueConverter.ReadValue</c>.</param>
    /// <param name="parseCoseSign1">Delegate that parses the issuer-auth COSE_Sign1. Wired to <c>CoseSerialization.ParseCoseSign1</c>.</param>
    /// <param name="parseCoseSign1AllowingNilPayload">Delegate that parses the nil-payload device COSE_Sign1. Wired to <c>CoseSerialization.ParseCoseSign1AllowingNilPayload</c>.</param>
    /// <param name="encodeDeviceAuthenticationBytes">Delegate that reconstructs the DeviceAuthenticationBytes. Wired to <c>MdocCborDeviceAuthenticationEncoder.EncodeAuthenticationBytes</c>.</param>
    /// <param name="buildSigStructure">Delegate that builds the COSE Sig_structure. Wired to <c>CoseSerialization.BuildSigStructure</c>.</param>
    /// <param name="decoder">Delegate for Base64Url decoding the vp_token value.</param>
    /// <param name="pool">Memory pool for cryptographic allocations.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The parsed and crypto-verified VP token contents.</returns>
    [System.Diagnostics.CodeAnalysis.SuppressMessage(
        "Design", "CA1054:URI-like parameters should not be strings",
        Justification = "Byte-exact string hashing per OID4VP 1.0 §B.2.6.1; Uri normalisation would break the wallet/verifier SessionTranscript hash agreement, mirroring Oid4VpMdocSessionTranscriptEncoder.Encode.")]
    public static async ValueTask<VpTokenParsed> VerifyAsync(
        string vpToken,
        string credentialQueryId,
        ResolveMdocIssuerKeyDelegate resolveIssuerKey,
        ExtractMdocAuthorityIdentifierDelegate? extractAuthorityIdentifier,
        string clientId,
        string responseUri,
        string authorizationRequestNonce,
        ReadOnlyMemory<byte> mdocGeneratedNonce,
        ParseMdocDeviceResponseDelegate parseDeviceResponse,
        EncodeMdocSessionTranscriptDelegate encodeSessionTranscript,
        DecodeMdocElementValueDelegate decodeElementValue,
        ParseCoseSign1Delegate parseCoseSign1,
        ParseCoseSign1Delegate parseCoseSign1AllowingNilPayload,
        EncodeDeviceAuthenticationBytesDelegate encodeDeviceAuthenticationBytes,
        BuildSigStructureDelegate buildSigStructure,
        DecodeDelegate decoder,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(vpToken);
        ArgumentException.ThrowIfNullOrWhiteSpace(credentialQueryId);
        ArgumentNullException.ThrowIfNull(resolveIssuerKey);
        ArgumentException.ThrowIfNullOrWhiteSpace(clientId);
        ArgumentException.ThrowIfNullOrWhiteSpace(responseUri);
        ArgumentException.ThrowIfNullOrWhiteSpace(authorizationRequestNonce);
        ArgumentNullException.ThrowIfNull(parseDeviceResponse);
        ArgumentNullException.ThrowIfNull(encodeSessionTranscript);
        ArgumentNullException.ThrowIfNull(decodeElementValue);
        ArgumentNullException.ThrowIfNull(parseCoseSign1);
        ArgumentNullException.ThrowIfNull(parseCoseSign1AllowingNilPayload);
        ArgumentNullException.ThrowIfNull(encodeDeviceAuthenticationBytes);
        ArgumentNullException.ThrowIfNull(buildSigStructure);
        ArgumentNullException.ThrowIfNull(decoder);
        ArgumentNullException.ThrowIfNull(pool);

        cancellationToken.ThrowIfCancellationRequested();

        //Base64url-decode the vp_token value, then parse the DeviceResponse wire envelope into
        //owned carriers. Both the decoded bytes and the parsed response are disposed on the way out.
        using IMemoryOwner<byte> deviceResponseBytes = decoder(vpToken, pool);
        using MdocParsedDeviceResponse parsed = parseDeviceResponse(deviceResponseBytes.Memory.Span, pool);

        bool credentialSignatureValid = false;
        bool sessionTranscriptValid = false;
        string? credentialIssuer = null;
        var extractedClaims = new Dictionary<string, string>(StringComparer.Ordinal);
        var disclosedByPath = new Dictionary<CredentialPath, object?>();

        //One DCQL credential query maps to one mdoc Document in the response.
        if(parsed.Documents.Count > 0)
        {
            MdocParsedDocument document = parsed.Documents[0];

            //The mdoc authority identifier for DCQL trusted_authorities (type aki) is the
            //leaf certificate's AuthorityKeyIdentifier — extracted from the same IssuerAuth
            //x5chain the trust resolver walks (the extractor captures its own pool). Null when
            //no extractor is wired or no x5chain is present, leaving trusted_authorities unenforced.
            credentialIssuer = extractAuthorityIdentifier?.Invoke(document.IssuerSigned.IssuerAuth);

            //CredentialSignatureValid = issuer-auth COSE_Sign1 (under the trust-resolved key)
            //AND the MSO digest binding over every presented item.
            bool issuerAuthValid = await document.IssuerSigned.IssuerAuth.VerifyAsync(
                resolveIssuerKey, pool, parseCoseSign1, buildSigStructure, cancellationToken).ConfigureAwait(false);

            MdocDigestBindingResult binding = MdocMsoDigestBindingValidator.Validate(document.IssuerSigned);

            credentialSignatureValid = issuerAuthValid && binding.IsValid;

            //SessionTranscriptValid = device COSE_Sign1 over the verifier-reconstructed
            //SessionTranscript, keyed by the device key the issuer committed to in the MSO.
            if(document.DeviceSigned is MdocDeviceSigned deviceSigned)
            {
                ReadOnlyMemory<byte> sessionTranscript = encodeSessionTranscript(
                    clientId, responseUri, authorizationRequestNonce, mdocGeneratedNonce.Span);

                using PublicKeyMemory deviceVerificationKey =
                    document.IssuerSigned.IssuerAuth.Mso.DeviceKeyInfo.DeviceKey.ToPublicKeyMemory(pool);

                sessionTranscriptValid = await deviceSigned.VerifyAsync(
                    document.DocType, sessionTranscript, deviceVerificationKey, pool,
                    parseCoseSign1AllowingNilPayload, encodeDeviceAuthenticationBytes, buildSigStructure,
                    cancellationToken).ConfigureAwait(false);
            }

            //Surface the disclosed claims two ways: ExtractedClaims keyed by element
            //identifier for the relying party, and DisclosedClaimPaths keyed by the
            //full canonical "/{namespace}/{elementIdentifier}" path for the engine —
            //the mdoc DCQL claim path is [namespace, element_identifier] and the same
            //element id may occur in two namespaces, so the engine view keeps both.
            foreach(KeyValuePair<string, IReadOnlyList<MdocIssuerSignedItem>> nsEntry in document.IssuerSigned.NameSpaces)
            {
                foreach(MdocIssuerSignedItem item in nsEntry.Value)
                {
                    string decoded = decodeElementValue(item.EncodedElementValue);
                    extractedClaims[item.ElementIdentifier] = decoded;
                    disclosedByPath[CredentialPath.Root.Append(nsEntry.Key).Append(item.ElementIdentifier)] = decoded;
                }
            }
        }

        return new VpTokenParsed
        {
            KbJwtNonce = null,
            KbJwtAud = null,
            KbJwtIat = null,
            KbJwtSignatureValid = true,
            CredentialSignatureValid = credentialSignatureValid,
            CredentialIssuer = credentialIssuer,
            SdHashValid = true,
            SessionTranscriptValid = sessionTranscriptValid,
            ExtractedClaims = new Dictionary<string, IReadOnlyDictionary<string, string>>(StringComparer.Ordinal)
            {
                [credentialQueryId] = extractedClaims
            },
            DisclosedClaimPaths = new Dictionary<string, IReadOnlyDictionary<CredentialPath, object?>>(StringComparer.Ordinal)
            {
                [credentialQueryId] = disclosedByPath
            }
        };
    }
}
