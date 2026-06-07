using System.Buffers;
using Verifiable.Core.Model.SelectiveDisclosure;
using Verifiable.Cryptography;

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
    /// Verifies an SD-CWT VP token and returns the extracted, verified contents.
    /// </summary>
    /// <param name="vpToken">The base64url-encoded SD-CWT Key Binding Token from the vp_token slot.</param>
    /// <param name="credentialQueryId">
    /// The DCQL credential query identifier that matched this token. Used as the key in
    /// <see cref="VpTokenParsed.ExtractedClaims"/>.
    /// </param>
    /// <param name="seams">The CBOR/COSE verification seams plus the issuer-key resolver.</param>
    /// <param name="decoder">Delegate for Base64Url decoding the vp_token value.</param>
    /// <param name="pool">Memory pool for cryptographic allocations.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The parsed and crypto-verified VP token contents.</returns>
    public static async ValueTask<VpTokenParsed> VerifyAsync(
        string vpToken,
        string credentialQueryId,
        SdCwtVpVerificationSeams seams,
        DecodeDelegate decoder,
        CommitmentReuseDetectionSeam? saltReuseSeam,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(vpToken);
        ArgumentException.ThrowIfNullOrWhiteSpace(credentialQueryId);
        ArgumentNullException.ThrowIfNull(seams);
        ArgumentNullException.ThrowIfNull(decoder);
        ArgumentNullException.ThrowIfNull(pool);

        cancellationToken.ThrowIfCancellationRequested();

        //Base64url-decode the vp_token value to the KBT COSE_Sign1 wire bytes, then run
        //the Core SD-CWT KB verification through the application-wired seams.
        using IMemoryOwner<byte> kbtBytes = decoder(vpToken, pool);

        SdCwtKbtVerificationResult result = await KbCwtVerification.VerifyAsync(
            kbtBytes.Memory,
            seams.ParseCoseSign1,
            seams.ExtractKcwt,
            seams.ParseSdCwt,
            seams.ExtractHolderKey,
            seams.ReadKbtClaims,
            seams.ExtractIssuer,
            seams.ResolveIssuerKey,
            seams.VerifyCredential,
            seams.BuildSigStructure,
            saltReuseSeam,
            pool,
            cancellationToken).ConfigureAwait(false);

        //Engine-facing view: full canonical "/claimName" path with the disclosed value.
        var disclosedByPath = new Dictionary<CredentialPath, object?>();
        foreach(KeyValuePair<string, string> claim in result.DisclosedClaims)
        {
            disclosedByPath[CredentialPath.Root.Append(claim.Key)] = claim.Value;
        }

        return new VpTokenParsed
        {
            KbJwtNonce = result.Cnonce,
            KbJwtAud = result.Audience,
            KbJwtIat = result.IssuedAt,
            KbJwtSignatureValid = result.HolderSignatureValid,
            CredentialSignatureValid = result.CredentialSignatureValid,
            CredentialIssuer = result.Issuer,
            SdHashValid = true,
            SessionTranscriptValid = true,
            ExtractedClaims = new Dictionary<string, IReadOnlyDictionary<string, string>>(StringComparer.Ordinal)
            {
                [credentialQueryId] = result.DisclosedClaims
            },
            DisclosedClaimPaths = new Dictionary<string, IReadOnlyDictionary<CredentialPath, object?>>(StringComparer.Ordinal)
            {
                [credentialQueryId] = disclosedByPath
            },
            MinimumDisclosureSaltLengthBytes = result.MinimumDisclosureSaltLengthBytes,
            SaltReused = result.SaltReused
        };
    }
}
