using Verifiable.Core;
using Verifiable.Core.Dcql;
using Verifiable.Core.Model.Dcql;
using Verifiable.Core.Model.SelectiveDisclosure;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.JCose;
using Verifiable.OAuth.Validation;

namespace Verifiable.OAuth.Oid4Vp.Server;

/// <summary>
/// Parses and cryptographically verifies an SD-CWT VP token presented as an SD-CWT
/// Key Binding Token (KBT) through OID4VP 1.0 §8.1, returning the same
/// <see cref="VpTokenParsed"/> result boundary the SD-JWT and mdoc paths produce so the
/// executor can validate every format uniformly.
/// </summary>
/// <remarks>
/// <para>
/// This class contains no serialization dependencies. It is a thin OID4VP-layer caller
/// over <see cref="KbCwtVerification.VerifyAsync"/> (the SD-CWT KB orchestration that
/// lives in <c>Verifiable.Core</c>): it base64url-decodes the vp_token value to the KBT
/// wire bytes and threads the CBOR/COSE seams the application wired into
/// <see cref="SdCwtVpVerificationSeams"/>, then maps the
/// <see cref="SdCwtKbtVerificationResult"/> onto the shared result shape.
/// </para>
/// <para>
/// Result mapping: the SD-CWT holder binding is the KBT COSE_Sign1 the holder signs over
/// the embedded presentation SD-CWT, so its outcome and the KBT's <c>aud</c>/<c>iat</c>/
/// <c>cnonce</c> populate the key-binding axes
/// (<see cref="VpTokenParsed.KbJwtSignatureValid"/>, <see cref="VpTokenParsed.KbJwtAud"/>,
/// <see cref="VpTokenParsed.KbJwtIat"/>, <see cref="VpTokenParsed.KbJwtNonce"/>) — the same
/// axes the SD-JWT KB-JWT fills. <see cref="VpTokenParsed.CredentialSignatureValid"/> is the
/// embedded SD-CWT issuer signature plus its per-disclosure digest binding. SD-CWT carries
/// no <c>sd_hash</c> and no SessionTranscript, so those axes follow the codebase's
/// "N/A is not a failure" convention.
/// </para>
/// </remarks>
public static class SdCwtVpTokenVerification
{
    /// <summary>
    /// Verifies an SD-CWT VP token and returns the extracted, verified contents, or the defect of a presentation whose part the
    /// reading that owns its wire shape refused.
    /// </summary>
    /// <param name="vpToken">The base64url-encoded SD-CWT Key Binding Token from the vp_token slot.</param>
    /// <param name="credentialQueryId">
    /// The DCQL credential query identifier that matched this token. Carried onto
    /// <see cref="VpTokenParsed.CredentialQueryId"/>.
    /// </param>
    /// <param name="seams">The CBOR/COSE verification seams plus the issuer-key resolver.</param>
    /// <param name="decoder">Delegate for Base64Url decoding the vp_token value.</param>
    /// <param name="saltReuseSeam">
    /// Optional detector that flags a disclosure salt reused across presentations; <see langword="null"/>
    /// skips the check.
    /// </param>
    /// <param name="pool">Memory pool for cryptographic allocations.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// The parsed and crypto-verified VP token contents; or the defect (<see cref="SdCwtPresentationDefect"/>) of a value the
    /// decoder refuses as no base64url text, a Key Binding Token, embedded SD-CWT, <c>x5chain</c>, holder key or claim its
    /// reading seam refuses with its <see cref="FormatException"/>. Any other failure - of the decoder beyond its refusal, of the
    /// issuer-key or trust-evidence resolver, of the credential's verification, of a signature or digest backend, of the
    /// allocator - is a fault and surfaces as one, cancellation among them.
    /// </returns>
    public static async ValueTask<Result<VpTokenParsed, SdCwtPresentationDefect>> VerifyAsync(
        string vpToken,
        CredentialQueryId credentialQueryId,
        SdCwtVpVerificationSeams seams,
        DecodeDelegate decoder,
        CommitmentReuseDetectionSeam? saltReuseSeam,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(vpToken);
        ArgumentNullException.ThrowIfNull(credentialQueryId);
        ArgumentNullException.ThrowIfNull(seams);
        ArgumentNullException.ThrowIfNull(decoder);
        ArgumentNullException.ThrowIfNull(pool);

        cancellationToken.ThrowIfCancellationRequested();

        //Base64url-decode the vp_token value to the KBT COSE_Sign1 wire bytes, then run
        //the Core SD-CWT KB verification through the application-wired seams. The decoder's refusal of the value as no base64url
        //text is the presentation's defect; any other failure of the decoder is a fault.
        using var kbtBytes = JwsSegmentDecoding.DecodedOrNone(vpToken, decoder, pool);

        if(kbtBytes is null)
        {
            return Result.Failure<VpTokenParsed, SdCwtPresentationDefect>(SdCwtPresentationDefect.NotBase64UrlText);
        }

        //The Key Binding Token is read once, by its typed reading, and its embedded presentation SD-CWT extracted once from the
        //kcwt protected-header parameter; both are handed to the verification, which reads neither again. Each reading's refusal
        //is the defect of the part it reads. This method owns the read token and disposes it once the verification is done.
        if(seams.ParseCoseSign1(kbtBytes.Memory, pool) is not CoseSign1Read { Message: var kbtMessage })
        {
            return Result.Failure<VpTokenParsed, SdCwtPresentationDefect>(SdCwtPresentationDefect.KeyBindingTokenMalformed);
        }

        using var keyBindingToken = kbtMessage;

        if(KbCwtVerification.EmbeddedSdCwtOrNone(keyBindingToken, seams.ExtractKcwt) is not { } embeddedSdCwt)
        {
            return Result.Failure<VpTokenParsed, SdCwtPresentationDefect>(SdCwtPresentationDefect.EmbeddedCredentialMalformed);
        }

        //When an x5chain evidence resolver is wired, the embedded SD-CWT's x5chain is read for OID4VP 1.0 §6.1.1 trust evidence
        //from the bytes extracted above. The chain certificates are pool-owned copies; they are resolved and disposed once the
        //verified iss is known.
        var trustedAuthorityChain = (IReadOnlyList<PkiCertificateMemory>)[];
        if(seams.ResolveTrustedAuthorityEvidence is not null && seams.ExtractCoseSign1X5Chain is not null)
        {
            if(ChainOrNone(embeddedSdCwt, seams.ExtractCoseSign1X5Chain, pool) is not { } chain)
            {
                return Result.Failure<VpTokenParsed, SdCwtPresentationDefect>(SdCwtPresentationDefect.CertificateChainMalformed);
            }

            trustedAuthorityChain = chain;
        }

        try
        {
            var verification = await KbCwtVerification.VerifyReadAsync(
                keyBindingToken,
                embeddedSdCwt,
                seams.ParseSdCwt,
                seams.ExtractHolderKey,
                seams.ReadKbtClaims,
                seams.ExtractIssuer,
                seams.ExtractCredentialType,
                seams.ExtractStatus,
                seams.ResolveIssuerKey,
                seams.VerifyCredential,
                seams.BuildSigStructure,
                saltReuseSeam,
                pool,
                cancellationToken).ConfigureAwait(false);

            if(!verification.IsSuccess)
            {
                return Result.Failure<VpTokenParsed, SdCwtPresentationDefect>(verification.Error);
            }

            var result = verification.Value;

            //The relying-party-facing string projection of the same path-keyed map KbCwtVerification
            //already resolved (embeddedToken.DisclosurePaths) — no re-flattening onto claim names.
            var extractedClaims = new Dictionary<CredentialPath, string>();
            foreach(KeyValuePair<CredentialPath, object?> claim in result.DisclosedClaims)
            {
                extractedClaims[claim.Key] = claim.Value?.ToString() ?? "";
            }

            //Resolve the trust evidence now that the verified iss is known; the outer finally
            //disposes the chain certificates extracted above regardless of outcome.
            TrustedAuthorityEvidence? trustedAuthorityEvidence = null;
            if(seams.ResolveTrustedAuthorityEvidence is not null)
            {
                trustedAuthorityEvidence = await seams.ResolveTrustedAuthorityEvidence(
                    trustedAuthorityChain, result.Issuer, pool, cancellationToken).ConfigureAwait(false);
            }

            //Both the status claim and the issuer key come off the verification result: the Core
            //orchestration read the status at the parse boundary of the embedded token it already
            //held, and the key is the one the credential's issuer signature verified under, borrowed
            //from the seam that resolved it. Nothing here re-parses the presentation or re-resolves
            //the key, and nothing here disposes the key.
            return Result.Success<VpTokenParsed, SdCwtPresentationDefect>(new VpTokenParsed
            {
                CredentialQueryId = credentialQueryId,
                CredentialIssuerKey = result.IssuerVerificationKey,
                Credential = new VpCredentialClaims
                {
                    Extracted = extractedClaims,
                    Disclosed = result.DisclosedClaims,
                    UnconditionallyDisclosed = result.UnconditionallyDisclosedPaths,
                    CredentialType = result.CredentialType,
                    Issuer = result.Issuer,
                    TrustedAuthorityEvidence = trustedAuthorityEvidence,
                    Status = result.Status
                },
                KbJwtNonce = result.Cnonce,
                KbJwtAud = result.Audience,
                KbJwtIat = result.IssuedAt,
                KbJwtSignatureValid = result.HolderSignatureValid,
                CredentialSignatureValid = result.CredentialSignatureValid,
                SdHashValid = true,
                SessionTranscriptValid = true,
                MinimumDisclosureSaltLengthBytes = result.MinimumDisclosureSaltLengthBytes,
                SaltReused = result.SaltReused
            });
        }
        finally
        {
            foreach(PkiCertificateMemory certificate in trustedAuthorityChain)
            {
                certificate.Dispose();
            }
        }
    }


    /// <summary>
    /// The embedded presentation SD-CWT's <c>x5chain</c>, or <see langword="null"/> when the chain's extraction refuses it with
    /// its <see cref="FormatException"/>. Any other failure of the extraction is a fault and surfaces as one.
    /// </summary>
    /// <param name="embeddedSdCwt">The embedded SD-CWT's wire bytes, extracted once from the Key Binding Token.</param>
    /// <param name="extractX5Chain">The chain's extraction.</param>
    /// <param name="pool">The pool the certificates are rented from.</param>
    /// <returns>The chain, which the caller disposes, or <see langword="null"/>.</returns>
    private static IReadOnlyList<PkiCertificateMemory>? ChainOrNone(
        ReadOnlyMemory<byte> embeddedSdCwt,
        ExtractCoseSign1X5ChainDelegate extractX5Chain,
        BaseMemoryPool pool)
    {
        try
        {
            return extractX5Chain(embeddedSdCwt, pool);
        }
        catch(FormatException)
        {
            return null;
        }
    }
}
