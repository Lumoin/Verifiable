using System.Buffers;
using System.Security.Cryptography;
using System.Text;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Pki;
using Verifiable.JCose;
using Verifiable.Core.Dcql;
using Verifiable.Core.Model.Dcql;
using Verifiable.Core.Model.SelectiveDisclosure;
using Verifiable.Core.StatusList;

namespace Verifiable.OAuth.Oid4Vp.Server;

/// <summary>
/// Resolves an issuer's public key from its identifier.
/// The application provides the implementation based on its trust framework
/// (e.g., JWKS endpoint, OpenID Federation, X.509 trust list).
/// </summary>
/// <param name="issuerId">The <c>iss</c> claim from the credential.</param>
/// <returns>
/// The issuer's public key, or <see langword="null"/> if the issuer is not trusted.
/// </returns>
public delegate PublicKeyMemory? ResolveIssuerKeyDelegate(string issuerId);


/// <summary>
/// Parses and cryptographically verifies an SD-JWT VP token with Key Binding JWT
/// per <see href="https://www.rfc-editor.org/rfc/rfc9901#section-4.3">RFC 9901 §4.3</see>
/// and <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.1">OID4VP 1.0 §8.1</see>.
/// </summary>
/// <remarks>
/// <para>
/// This class contains no serialization dependencies. JSON field extraction uses
/// <see cref="JwkJsonReader"/> (span-based UTF-8 scanning). SD-JWT wire format
/// parsing and hash input computation are supplied via delegates that the application
/// wires to <c>SdJwtSerializer</c> implementations in <c>Verifiable.Json.Sd</c>.
/// </para>
/// <para>
/// The verification sequence:
/// </para>
/// <list type="number">
///   <item><description>Parse SD-JWT wire format via <see cref="ParseSdJwtTokenDelegate"/>.</description></item>
///   <item><description>Base64url-decode the issuer JWT payload segment.</description></item>
///   <item><description>Extract <c>iss</c> and resolve the issuer's public key via <see cref="ResolveIssuerKeyDelegate"/>.</description></item>
///   <item><description>Verify the issuer credential signature via <see cref="Jws.VerifyAsync"/>.</description></item>
///   <item><description>Extract <c>cnf.jwk</c> and reconstruct the holder's public key.</description></item>
///   <item><description>Verify the KB-JWT signature against the holder key.</description></item>
///   <item><description>Extract KB-JWT claims (<c>nonce</c>, <c>aud</c>, <c>iat</c>, <c>sd_hash</c>).</description></item>
///   <item><description>Recompute <c>sd_hash</c> via <see cref="ComputeSdJwtHashInputDelegate"/> and compare.</description></item>
///   <item><description>Collect disclosed claims from the parsed disclosures.</description></item>
/// </list>
/// <para>
/// The credential's <c>status</c> claim (Section 6.1) and the <c>status_list</c> reference it may
/// carry (Section 6.2) are read via <see cref="StatusClaimReader.TryRead"/> off the still-live
/// issuer payload span, never re-encoded to a string. Whether the claim EXISTS is answered by a
/// member probe on the payload, apart from what its value contains, so a present claim whose value
/// carries no mechanism is a malformed presentation rather than an unchecked one. "When the status claim is present and using
/// the status_list mechanism, the associated Status List Token MUST be in JWT format." — an
/// application wiring a resolver for the surfaced <see cref="VpCredentialClaims.Status"/> therefore
/// composes <c>StatusListTokenResolvers.BuildResolving</c>, which fetches and verifies the JWT
/// format only.
/// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-18#section-2.2.2.3">SD-JWT VC, Section 2.2.2.3</see>.
/// </para>
/// </remarks>
public static class SdJwtVpTokenVerification
{
    /// <summary>
    /// Verifies an SD-JWT VP token and returns the extracted, verified contents.
    /// </summary>
    /// <param name="vpToken">The serialized SD-JWT with disclosures and KB-JWT.</param>
    /// <param name="credentialQueryId">
    /// The DCQL credential query identifier that matched this token.
    /// Carried onto <see cref="VpTokenParsed.CredentialQueryId"/>.
    /// </param>
    /// <param name="parseSdJwtToken">
    /// Delegate for parsing the SD-JWT wire format.
    /// Wired to <c>SdJwtSerializer.ParseToken</c>.
    /// </param>
    /// <param name="computeHashInput">
    /// Delegate for computing the <c>sd_hash</c> input string.
    /// Wired to <c>SdJwtSerializer.GetSdJwtForHashing</c>.
    /// </param>
    /// <param name="resolveIssuerKey">
    /// Application-provided delegate that resolves the issuer's public key.
    /// </param>
    /// <param name="computeDigest">
    /// Computes a digest. Wired to a provider-side implementation registered on
    /// <see cref="CryptographicKeyFactory"/> such as
    /// <c>MicrosoftCryptographicFunctions.ComputeDigestAsync</c>. The algorithm is carried in
    /// the <see cref="Tag"/> argument constructed per-call from the credential's
    /// <c>_sd_alg</c> claim.
    /// </param>
    /// <param name="decoder">Delegate for Base64Url decoding.</param>
    /// <param name="encoder">Delegate for Base64Url encoding.</param>
    /// <param name="pool">Memory pool for cryptographic allocations.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <param name="parseX5c">
    /// Optional delegate that parses the issuer JWS <c>x5c</c> header (RFC 7515 §4.1.6) into
    /// certificates, for OID4VP 1.0 §6.1.1 trust evidence. <see langword="null"/> when the
    /// credential's issuer identity is carried only by <c>iss</c>.
    /// </param>
    /// <param name="resolveTrustedAuthorityEvidence">
    /// Optional delegate that resolves the OID4VP 1.0 §6.1.1 trust evidence from the issuer's
    /// certificate chain (when <paramref name="parseX5c"/> is supplied and the header carries one)
    /// and the verified <c>iss</c>, surfaced on <see cref="VpCredentialClaims.TrustedAuthorityEvidence"/>.
    /// <see langword="null"/> surfaces no evidence.
    /// </param>
    /// <returns>The parsed and crypto-verified VP token contents.</returns>
    /// <exception cref="FormatException">
    /// Thrown when the issuer-signed payload repeats a top-level claim name, or when it carries a
    /// <c>status</c> claim whose value does not meet Token Status List Section 6.1/6.2. Both are
    /// Wallet-attributable malformed presentations on the executor's own malformed route.
    /// </exception>
    public static async ValueTask<VpTokenParsed> VerifyAsync(
        string vpToken,
        CredentialQueryId credentialQueryId,
        ParseSdJwtTokenDelegate parseSdJwtToken,
        ComputeSdJwtHashInputDelegate computeHashInput,
        ResolveIssuerKeyDelegate resolveIssuerKey,
        ComputeDigestDelegate computeDigest,
        DecodeDelegate decoder,
        EncodeDelegate encoder,
        BaseMemoryPool pool,
        CommitmentReuseDetectionSeam? saltReuseSeam,
        CancellationToken cancellationToken,
        ParseX5cDelegate? parseX5c = null,
        ResolveTrustedAuthorityEvidenceDelegate? resolveTrustedAuthorityEvidence = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(vpToken);
        ArgumentNullException.ThrowIfNull(credentialQueryId);
        ArgumentNullException.ThrowIfNull(parseSdJwtToken);
        ArgumentNullException.ThrowIfNull(computeHashInput);
        ArgumentNullException.ThrowIfNull(resolveIssuerKey);
        ArgumentNullException.ThrowIfNull(computeDigest);
        ArgumentNullException.ThrowIfNull(decoder);
        ArgumentNullException.ThrowIfNull(encoder);
        ArgumentNullException.ThrowIfNull(pool);

        cancellationToken.ThrowIfCancellationRequested();

        //Parse the SD-JWT wire format into issuer JWS, disclosures, and KB-JWT. The token owns a
        //pooled salt buffer per disclosure, so it is disposed on every exit from this method;
        //everything the returned VpTokenParsed carries is a detached CLR value (claim values come
        //from the parse's own object graph, keys are CredentialPath, the rest are strings).
        using SdToken<string> token = parseSdJwtToken(vpToken);

        //Decode the issuer JWT payload and extract all fields synchronously
        //before any await boundaries (ReadOnlySpan cannot cross await).
        string? iss;
        string? vct;
        List<string>? akaVcts;
        string? sdAlg;
        Dictionary<string, object>? jwkDict;
        StatusClaim? credentialStatus;

        {
            string[] issuerParts = token.IssuerSigned.Split('.');
            using IMemoryOwner<byte> issuerPayloadBytes = decoder(issuerParts[1], pool);
            ReadOnlySpan<byte> issuerPayload = issuerPayloadBytes.Memory.Span;

            //A top-level claim name that repeats is refused before any claim is read: the span
            //scanner below resolves a repeated name to its FIRST occurrence while a serializer-based
            //reader keeps the LAST, so a signed payload carrying the same claim twice shows one
            //verifier one value and another verifier a different one — the validate-one/act-on-another
            //smuggling class JarVerification refuses on the Request Object for the same reason. No
            //conformant Issuer emits a duplicate top-level claim, so the presentation is malformed.
            if(JwkJsonReader.HasDuplicateTopLevelKeys(issuerPayload))
            {
                throw new FormatException(
                    "The credential's issuer-signed payload carries a duplicate top-level claim name.");
            }

            iss = JwkJsonReader.ExtractStringValue(issuerPayload, "iss"u8);
            vct = JwkJsonReader.ExtractStringValue(issuerPayload, "vct"u8);
            //SD-JWT VC §2.2.2.2: aka_vcts is OPTIONAL — the credential's other declared types,
            //read for the DCQL meta.vct_values inheritance MAY (Appendix B.3.5).
            akaVcts = JwkJsonReader.ExtractStringArrayProperty(issuerPayload, "aka_vcts"u8);
            sdAlg = JwkJsonReader.ExtractStringValue(issuerPayload, "_sd_alg"u8);
            jwkDict = JwkJsonReader.ExtractNestedObjectProperties(
                issuerPayload, "cnf"u8, "jwk"u8);

            //"1. Check for the existence of a status claim, check for the existence of a status_list
            //claim within the status claim and validate that the content of status_list adheres to the
            //rules defined in Section 6.2 for JOSE-based Referenced Tokens" — read directly off the
            //still-live issuer payload span, no string re-encode, through StatusClaimReader.TryRead,
            //which answers the whole claim rather than the status_list member alone: the mechanisms
            //the issuer named, plus the reference when status_list is one of them.
            //
            //The claim's EXISTENCE is a member probe on the payload, kept apart from its content: an
            //absent member is the not-status-checked case, while a member whose value is an empty
            //object or is not an object at all yields the same empty content slice and is a present
            //claim that fails Section 6.1's "MUST specify a JSON Object that contains at least one
            //reference to a status mechanism". Every present claim therefore reaches the reader, whose
            //refusal — no member, a repeated member, or a status_list that does not meet Section 6.2 —
            //is a malformed presentation at this seat's own parse boundary rather than a silent
            //degradation to "not referenced".
            credentialStatus = null;
            if(JwkJsonReader.ContainsKey(issuerPayload, WellKnownJwtClaimNames.StatusUtf8))
            {
                ReadOnlySpan<byte> statusObject = JwkJsonReader.ExtractObjectContent(
                    issuerPayload, WellKnownJwtClaimNames.StatusUtf8);

                if(!StatusClaimReader.TryRead(statusObject, out StatusClaim? statusClaim))
                {
                    throw new FormatException(
                        "The credential's 'status' claim does not adhere to Section 6.1/6.2.");
                }

                credentialStatus = statusClaim;
            }
        }

        //Resolve the issuer's public key from the trust framework.
        PublicKeyMemory? issuerPublicKey = iss is not null ? resolveIssuerKey(iss) : null;

        bool credentialSignatureValid = false;
        if(issuerPublicKey is not null)
        {
            credentialSignatureValid = await Jws.VerifyAsync(
                token.IssuerSigned, decoder,
                pool,
                issuerPublicKey, cancellationToken).ConfigureAwait(false);
        }

        bool kbJwtSignatureValid = false;
        string? kbNonce = null;
        string? kbAud = null;
        DateTimeOffset? kbIat = null;
        bool sdHashValid = false;
        IReadOnlyList<string>? kbTransactionDataHashes = null;
        string? kbTransactionDataHashesAlg = null;

        if(token.HasKeyBinding && jwkDict is not null)
        {
            //Extract KB-JWT payload fields synchronously before signature verification.
            string? claimedSdHash;

            {
                string[] kbParts = token.KeyBinding!.Split('.');
                using IMemoryOwner<byte> kbPayloadBytes = decoder(kbParts[1], pool);
                ReadOnlySpan<byte> kbPayload = kbPayloadBytes.Memory.Span;

                kbNonce = JwkJsonReader.ExtractStringValue(kbPayload, "nonce"u8);
                kbAud = JwkJsonReader.ExtractStringValue(kbPayload, "aud"u8);
                claimedSdHash = JwkJsonReader.ExtractStringValue(kbPayload, "sd_hash"u8);

                if(JwkJsonReader.TryExtractLongValue(kbPayload, "iat"u8, out long iatEpoch))
                {
                    kbIat = DateTimeOffset.FromUnixTimeSeconds(iatEpoch);
                }

                //OID4VP 1.0 §8.4: optional transaction_data_hashes array bound
                //into the KB-JWT when the Authorization Request carried a
                //transaction_data parameter.
                kbTransactionDataHashes = JwkJsonReader.ExtractStringArrayProperty(
                    kbPayload, "transaction_data_hashes"u8);
                kbTransactionDataHashesAlg = JwkJsonReader.ExtractStringValue(
                    kbPayload, "transaction_data_hashes_alg"u8);
            }

            //Reconstruct the holder's public key from the JWK dictionary.
            var (algorithm, purpose, scheme, keyBytesOwner) =
                CryptoFormatConversions.DefaultJwkToAlgorithmConverter(
                    jwkDict, pool, decoder);
            Tag holderTag = Tag.Create(algorithm).With(purpose).With(scheme);
            using PublicKeyMemory holderPublicKey = new(keyBytesOwner, holderTag);

            //Verify KB-JWT signature against the holder key from cnf.
            kbJwtSignatureValid = await Jws.VerifyAsync(
                token.KeyBinding!, decoder,
                pool,
                holderPublicKey, cancellationToken).ConfigureAwait(false);

            //Verify sd_hash using the algorithm specified by _sd_alg.
            if(claimedSdHash is not null && sdAlg is not null)
            {
                HashAlgorithmName algorithmName = WellKnownHashAlgorithms.ToHashAlgorithmName(sdAlg);
                int digestByteLength = WellKnownHashAlgorithms.GetSizeBytes(algorithmName);
                Tag digestTag = Tag.Create(algorithmName).With(Purpose.Digest);

                string hashInput = computeHashInput(token);
                int inputByteCount = Encoding.ASCII.GetByteCount(hashInput);
                using IMemoryOwner<byte> inputOwner = pool.Rent(inputByteCount);
                Span<byte> inputBytes = inputOwner.Memory.Span[..inputByteCount];
                Encoding.ASCII.GetBytes(hashInput, inputBytes);

                (DigestValue digest, _) = await computeDigest(
                    new ReadOnlySequence<byte>(inputOwner.Memory[..inputByteCount]),
                    digestByteLength, digestTag, pool, null, cancellationToken).ConfigureAwait(false);

                using(digest)
                {
                    string computedSdHash = encoder(digest.AsReadOnlySpan());
                    sdHashValid = string.Equals(
                        claimedSdHash, computedSdHash, StringComparison.Ordinal);
                }
            }
        }

        //Collect disclosed claims from the parsed disclosures at their real position in the
        //issuer-signed structure — token.DisclosurePaths is the parse's own resolution
        //(RFC 9901 §9.3: the same claim name legitimately recurs at different depths with
        //independent salts, so the leaf name alone cannot key this map) — and observe the
        //shortest salt length (the verifier-side salt-length signal — RFC 9901 §9.3).
        var extractedClaims = new Dictionary<CredentialPath, string>();
        var disclosedByPath = new Dictionary<CredentialPath, object?>();

        //The unconditionally disclosed claims are as present in the presentation as the released
        //disclosures are — vct, iss and any business claim the Issuer chose not to make
        //selectively disclosable. They belong in the addressable structure both sides resolve a
        //DCQL query over, or an RP query naming one would report it missing from a presentation
        //that plainly carries it, while the holder's own adapter matched it.
        foreach(KeyValuePair<CredentialPath, object?> claim in token.IssuerSignedClaims)
        {
            disclosedByPath[claim.Key] = claim.Value;
        }

        int? minimumSaltLength = null;
        foreach(SdDisclosure disclosure in token.Disclosures)
        {
            int saltLength = disclosure.Salt.Length;
            if(minimumSaltLength is null || saltLength < minimumSaltLength)
            {
                minimumSaltLength = saltLength;
            }

            if(token.DisclosurePaths.TryGetPath(disclosure, out CredentialPath path))
            {
                extractedClaims[path] = disclosure.ClaimValue?.ToString() ?? "";
                //Engine-facing view: the disclosure's real path with the native disclosed value.
                disclosedByPath[path] = disclosure.ClaimValue;
            }
        }

        //Salt-reuse detection (opt-in): commit to each disclosure salt and ask the application store.
        //Only true when a seam was wired and a reuse was found — the verifier mirror of DPoP-JTI replay.
        //commitments is a per-disclosure list, not one disposable value, so it is disposed in its own
        //finally rather than through a using declaration.
        bool saltReused = false;
        if(saltReuseSeam is not null)
        {
            var commitments = new List<DigestValue>();
            try
            {
                foreach(SdDisclosure disclosure in token.Disclosures)
                {
                    commitments.Add(disclosure.Salt.ComputeCommitment(
                        saltReuseSeam.HashFunction, saltReuseSeam.HashOutputByteLength, saltReuseSeam.HashTag, pool));
                }

                IReadOnlyList<DigestValue> reused = await CommitmentReuseDetection.DetectAsync(
                    commitments, saltReuseSeam.IsSeen, saltReuseSeam.Record, cancellationToken).ConfigureAwait(false);
                saltReused = reused.Count > 0;
            }
            finally
            {
                foreach(DigestValue commitment in commitments)
                {
                    commitment.Dispose();
                }
            }
        }

        //Resolve OID4VP 1.0 §6.1.1 trust evidence once: the x5c header (when a parser is wired and
        //the header carries one) plus the verified iss, run through the composed resolver. Neither
        //wire is required — a credential with an x5c but no resolver, or a resolver but no x5c
        //header, surfaces no evidence, and DcqlEvaluator fails a trusted_authorities constraint
        //closed rather than being told to skip it.
        TrustedAuthorityEvidence? trustedAuthorityEvidence = null;
        if(resolveTrustedAuthorityEvidence is not null)
        {
            //chain is a per-certificate list, not one disposable value, so it is disposed in its own
            //finally rather than through a using declaration.
            IReadOnlyList<PkiCertificateMemory> chain = [];
            if(parseX5c is not null && SdJwtIssuerHeader.TryReadX5c(token.IssuerSigned, decoder, pool, out IReadOnlyList<string> x5c))
            {
                chain = parseX5c(x5c, pool);
            }

            try
            {
                trustedAuthorityEvidence = await resolveTrustedAuthorityEvidence(
                    chain, iss, pool, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                foreach(PkiCertificateMemory certificate in chain)
                {
                    certificate.Dispose();
                }
            }
        }

        return new VpTokenParsed
        {
            CredentialQueryId = credentialQueryId,
            CredentialIssuerKey = credentialSignatureValid ? issuerPublicKey : null,
            Credential = new VpCredentialClaims
            {
                Extracted = extractedClaims,
                Disclosed = disclosedByPath,
                UnconditionallyDisclosed = new HashSet<CredentialPath>(token.IssuerSignedClaims.Keys),
                CredentialType = vct,
                AdditionalTypes = new HashSet<string>(akaVcts ?? [], StringComparer.Ordinal),
                Issuer = iss,
                TrustedAuthorityEvidence = trustedAuthorityEvidence,
                Status = credentialStatus
            },
            KbJwtNonce = kbNonce,
            KbJwtAud = kbAud,
            KbJwtIat = kbIat,
            KbJwtSignatureValid = kbJwtSignatureValid,
            CredentialSignatureValid = credentialSignatureValid,
            SdHashValid = sdHashValid,
            SessionTranscriptValid = true,
            KbJwtTransactionDataHashes = kbTransactionDataHashes,
            KbJwtTransactionDataHashesAlg = kbTransactionDataHashesAlg,
            MinimumDisclosureSaltLengthBytes = minimumSaltLength,
            SaltReused = saltReused
        };
    }
}
