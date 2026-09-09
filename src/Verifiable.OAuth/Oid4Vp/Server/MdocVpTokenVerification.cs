using System.Buffers;
using Verifiable.Core.Dcql;
using Verifiable.Core.Model.Dcql;
using Verifiable.Core.Model.Mdoc;
using Verifiable.Core.Model.SelectiveDisclosure;
using Verifiable.Core.StatusList;
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
/// The issuer key is resolved here rather than inside the composed
/// <c>MdocIssuerAuth.VerifyAsync</c> overload, because
/// <see cref="ResolveMdocIssuerKeyDelegate"/> transfers ownership of the key it
/// resolves and that key has to outlive this parse: it rides
/// <see cref="VpTokenParsed.CredentialIssuerKey"/> into the credential-status step
/// that runs after it. The resolution is therefore returned alongside the parsed
/// result and released by the caller when the flow step ends, which is what keeps
/// <see cref="VpTokenParsed.CredentialIssuerKey"/> a borrowed reference on every
/// format.
/// </para>
/// <para>
/// Result mapping: <see cref="VpTokenParsed.CredentialSignatureValid"/> is the
/// issuer-auth signature AND the digest binding;
/// <see cref="VpTokenParsed.SessionTranscriptValid"/> is the device signature
/// over the reconstructed transcript. mdoc carries no KB-JWT — the transcript
/// binds <c>client_id</c>/<c>response_uri</c>/<c>nonce</c>, so this check
/// subsumes the SD-JWT nonce+aud binding. The KB-JWT and <c>sd_hash</c> axes are
/// not applicable to mdoc and follow the codebase's "N/A is not a failure"
/// convention (mirroring the SD-JWT path's <see cref="VpTokenParsed.SessionTranscriptValid"/>).
/// <see cref="VpCredentialClaims.Status"/> is the MSO's optional
/// <see cref="MdocMobileSecurityObject.Status"/> carried whole. It reads
/// <see langword="null"/> only when the MSO carries no <c>status</c> member at all;
/// a Status structure whose mechanisms this library does not model (e.g.
/// <c>identifier_list</c>) surfaces as a claim naming them with no
/// <see cref="StatusClaim.StatusList"/>, which the shared status step tells apart.
/// Surfacing the claim here keeps the fetch and trust of the status list the caller's
/// concern, not the parser's, exactly as the SD-JWT and SD-CWT paths do.
/// </para>
/// <para>
/// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-21.html#section-8.3">Token Status
/// List §8.3</see>: "Upon receiving a Referenced Token, a Relying Party MUST first perform the validation
/// of the Referenced Token - e.g., checking for expected attributes, valid signature and expiration time."
/// The document's own issuer-auth signature, digest binding, and device-signature checks above run and
/// populate <see cref="VpTokenParsed.CredentialSignatureValid"/>/<see cref="VpTokenParsed.SessionTranscriptValid"/>
/// before <see cref="VpCredentialClaims.Status"/> is read by the shared status step; an mdoc that fails
/// those checks never reaches status evaluation.
/// </para>
/// </remarks>
public static class MdocVpTokenVerification
{
    /// <summary>
    /// Verifies an mdoc VP token and returns the extracted, verified contents.
    /// </summary>
    /// <param name="vpToken">The base64url-encoded DeviceResponse value from the OID4VP vp_token slot.</param>
    /// <param name="credentialQueryId">
    /// The DCQL credential query identifier that matched this token. Carried onto
    /// <see cref="VpTokenParsed.CredentialQueryId"/>.
    /// </param>
    /// <param name="resolveIssuerKey">
    /// Application-provided trust delegate that resolves the issuer's
    /// verification key from the IssuerAuth (typically an IACA x5chain resolver).
    /// </param>
    /// <param name="extractTrustedAuthorityEvidence">
    /// Optional delegate that resolves the OID4VP 1.0 §6.1.1 trust evidence from the IssuerAuth
    /// x5chain, surfaced on <see cref="VpCredentialClaims.TrustedAuthorityEvidence"/> for DCQL
    /// <c>trusted_authorities</c> enforcement. <see langword="null"/> surfaces no evidence.
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
    /// <returns>
    /// The verification result: the parsed and crypto-verified VP token contents together with the
    /// IACA trust resolution whose key the issuer signature was checked under —
    /// <see cref="MdocVpVerificationResult.IssuerTrust"/> is <see langword="null"/> when the response
    /// carried no document to resolve a key for. The result owns the resolution, so the caller disposes
    /// it once the flow step that reads <see cref="VpTokenParsed.CredentialIssuerKey"/> is done; a
    /// failure thrown out of this method releases it here instead.
    /// </returns>
    [System.Diagnostics.CodeAnalysis.SuppressMessage(
        "Design", "CA1054:URI-like parameters should not be strings",
        Justification = "Byte-exact string hashing per OID4VP 1.0 §B.2.6.1; Uri normalisation would break the wallet/verifier SessionTranscript hash agreement, mirroring Oid4VpMdocSessionTranscriptEncoder.Encode.")]
    public static async ValueTask<MdocVpVerificationResult> VerifyAsync(
        string vpToken,
        CredentialQueryId credentialQueryId,
        ResolveMdocIssuerKeyDelegate resolveIssuerKey,
        ExtractMdocTrustedAuthorityEvidenceDelegate? extractTrustedAuthorityEvidence,
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
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(vpToken);
        ArgumentNullException.ThrowIfNull(credentialQueryId);
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

        MdocIacaTrustResolution? issuerTrust = null;
        bool credentialSignatureValid = false;
        bool sessionTranscriptValid = false;
        string? credentialType = null;
        StatusClaim? credentialStatus = null;
        TrustedAuthorityEvidence? trustedAuthorityEvidence = null;
        var extractedClaims = new Dictionary<CredentialPath, string>();
        var disclosedByPath = new Dictionary<CredentialPath, object?>();

        //Every step below runs after the trust delegate has handed over a resolution it owns, so a
        //throw on the way out — a malformed element value, an unreadable device signature — releases
        //that resolution here rather than leaving its pooled key unreturned. A successful return hands
        //ownership to the caller instead.
        try
        {
            //One DCQL credential query maps to one mdoc Document in the response.
            if(parsed.Documents.Count > 0)
            {
                MdocParsedDocument document = parsed.Documents[0];

                //The credential's own declared type — DCQL meta.doctype_value is answered against
                //the document's own DocType, the mdoc analog of the SD-JWT VC vct claim.
                credentialType = document.DocType;

                //The MSO's optional Token Status List status claim, carried whole: the mechanisms the
                //issuer named alongside the status_list reference when that mechanism is one of them.
                //Null here means the MSO carries no status member at all, which the shared status step
                //tells apart from a Status structure naming only mechanisms this library does not model
                //(e.g. identifier_list). Fetching and trusting the referenced status list stays the
                //caller's concern — the shared credential-status step reads this the same way it reads
                //the SD-JWT and SD-CWT paths' status claims.
                credentialStatus = document.IssuerSigned.IssuerAuth.Mso.Status;

                //The mdoc trust evidence for DCQL trusted_authorities is resolved from the IssuerAuth
                //x5chain (the extractor captures its own pool and composed resolver). Null when no
                //extractor is wired, leaving trusted_authorities fail-closed for want of evidence.
                if(extractTrustedAuthorityEvidence is not null)
                {
                    trustedAuthorityEvidence = await extractTrustedAuthorityEvidence(
                        document.IssuerSigned.IssuerAuth, cancellationToken).ConfigureAwait(false);
                }

                //CredentialSignatureValid = issuer-auth COSE_Sign1 (under the trust-resolved key)
                //AND the MSO digest binding over every presented item. The trust delegate is called here
                //rather than through the composed overload so the resolution — which owns the key it
                //resolved — survives this method and can be read as the credential's issuer key downstream.
                issuerTrust = await resolveIssuerKey(document.IssuerSigned.IssuerAuth, cancellationToken).ConfigureAwait(false);

                bool issuerAuthValid = false;
                if(issuerTrust.IsTrusted && issuerTrust.IssuerVerificationKey is PublicKeyMemory trustedIssuerKey)
                {
                    issuerAuthValid = await document.IssuerSigned.IssuerAuth.VerifyAsync(
                        trustedIssuerKey, pool, parseCoseSign1, buildSigStructure, cancellationToken).ConfigureAwait(false);
                }

                MdocDigestBindingResult binding = MdocMsoDigestBindingValidator.Validate(document.IssuerSigned, pool);

                credentialSignatureValid = issuerAuthValid && binding.IsValid;

                //SessionTranscriptValid = device COSE_Sign1 over the verifier-reconstructed
                //SessionTranscript, keyed by the device key the issuer committed to in the MSO.
                if(document.DeviceSigned is MdocDeviceSigned deviceSigned)
                {
                    ReadOnlyMemory<byte> sessionTranscript = encodeSessionTranscript(
                        clientId, responseUri, authorizationRequestNonce, mdocGeneratedNonce.Span, pool);

                    using PublicKeyMemory deviceVerificationKey =
                        document.IssuerSigned.IssuerAuth.Mso.DeviceKeyInfo.DeviceKey.ToPublicKeyMemory(pool);

                    sessionTranscriptValid = await deviceSigned.VerifyAsync(
                        document.DocType, sessionTranscript, deviceVerificationKey, pool,
                        parseCoseSign1AllowingNilPayload, encodeDeviceAuthenticationBytes, buildSigStructure,
                        cancellationToken).ConfigureAwait(false);
                }

                //Surface the disclosed claims keyed by the full canonical
                //"/{namespace}/{elementIdentifier}" path — the mdoc DCQL claim path is
                //[namespace, element_identifier] and the same element id may occur in two
                //namespaces, so the leaf identifier alone cannot key either map.
                foreach(KeyValuePair<string, IReadOnlyList<MdocIssuerSignedItem>> nsEntry in document.IssuerSigned.NameSpaces)
                {
                    foreach(MdocIssuerSignedItem item in nsEntry.Value)
                    {
                        string decoded = decodeElementValue(item.EncodedElementValue);
                        CredentialPath path = CredentialPath.Root.Append(nsEntry.Key).Append(item.ElementIdentifier);
                        extractedClaims[path] = decoded;
                        disclosedByPath[path] = decoded;
                    }
                }
            }

            VpTokenParsed verified = new()
            {
                CredentialQueryId = credentialQueryId,
                CredentialIssuerKey = credentialSignatureValid ? issuerTrust?.IssuerVerificationKey : null,
                Credential = new VpCredentialClaims
                {
                    Extracted = extractedClaims,
                    Disclosed = disclosedByPath,
                    CredentialType = credentialType,
                    Issuer = null,
                    TrustedAuthorityEvidence = trustedAuthorityEvidence,
                    Status = credentialStatus
                },
                KbJwtNonce = null,
                KbJwtAud = null,
                KbJwtIat = null,
                KbJwtSignatureValid = true,
                CredentialSignatureValid = credentialSignatureValid,
                SdHashValid = true,
                SessionTranscriptValid = sessionTranscriptValid
            };

            return new MdocVpVerificationResult { Parsed = verified, IssuerTrust = issuerTrust };
        }
        catch
        {
            issuerTrust?.Dispose();

            throw;
        }
    }
}
