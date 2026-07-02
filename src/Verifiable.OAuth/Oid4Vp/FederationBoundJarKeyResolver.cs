using System.Buffers;
using System.Diagnostics;
using System.Security;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.OAuth.Federation;
using Verifiable.OAuth.Trust;

namespace Verifiable.OAuth.Oid4Vp;

/// <summary>
/// Resolves the Verifier's JAR signing public key for the
/// <c>openid_federation:</c> Client Identifier Prefix per
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.9.3">OID4VP 1.0 §5.9.3</see>
/// and
/// <see href="https://openid.net/specs/openid-federation-1_0.html#section-4.3">Federation 1.0 §4.3</see>.
/// </summary>
/// <remarks>
/// <para>
/// Orchestrates two delegate-based operations supplied by the application:
/// </para>
/// <list type="number">
///   <item><description>
///     <see cref="ValidateTrustChainAsyncDelegate"/> — parses each compact
///     JWS, verifies per-link signatures, runs
///     <see cref="TrustChainValidator"/>, and returns the validated chain.
///   </description></item>
///   <item><description>
///     Subject identifier match — chain[0]'s <see cref="EntityStatement.Subject"/>
///     must equal the expected client_id (with the
///     <c>openid_federation:</c> prefix stripped). Ordinal-equal URL match;
///     simpler than X.509 DNS SAN matching, so no delegate.
///   </description></item>
/// </list>
/// <para>
/// Shape parallels <see cref="X509SanDnsKeyResolver"/>: a single call that
/// takes raw trust material plus the identifier the chain MUST bind to,
/// and returns the leaf signing key the JAR's signature verifies against.
/// Wallets integrating both X.509 and Federation client_id schemes get
/// the same call-site shape; only the delegate slots differ.
/// </para>
/// </remarks>
[DebuggerDisplay("FederationBoundJarKeyResolver")]
public static class FederationBoundJarKeyResolver
{
    /// <summary>
    /// Validates the inline trust chain, confirms the subject identifier
    /// matches <paramref name="expectedSubject"/>, and returns the JAR
    /// signing key extracted from the subject Entity Configuration's
    /// <c>jwks</c> claim.
    /// </summary>
    /// <param name="trustChainValues">
    /// The compact JWS strings from the JAR's <c>trust_chain</c> JOSE header,
    /// positionally aligned leaf → trust anchor (Federation §4.3).
    /// </param>
    /// <param name="expectedSubject">
    /// The expected subject Entity Identifier — the JAR's client_id with
    /// the <c>openid_federation:</c> prefix stripped. The chain validates
    /// only if chain[0].sub equals this value.
    /// </param>
    /// <param name="trustAnchors">
    /// The application's trust anchor allow-list. The chain's terminal
    /// statement's issuer must appear here.
    /// </param>
    /// <param name="validationTime">
    /// The UTC time at which to evaluate per-link iat / exp checks.
    /// </param>
    /// <param name="clockSkew">
    /// Maximum acceptable clock skew for temporal checks.
    /// </param>
    /// <param name="jarHeader">
    /// The JAR's unverified JOSE protected header. Its <c>kid</c> parameter
    /// drives the jwks lookup in chain[0]; absent <c>kid</c> selects the
    /// first key.
    /// </param>
    /// <param name="validateChain">
    /// Delegate that walks the inline chain. See
    /// <see cref="ValidateTrustChainAsyncDelegate"/>.
    /// </param>
    /// <param name="base64UrlDecoder">
    /// Base64url decoder used by the JWK-to-key conversion when materialising
    /// the resolved signing key.
    /// </param>
    /// <param name="pool">Memory pool the reconstructed key rents from.</param>
    /// <param name="cancellationToken">Token to monitor for cancellation requests.</param>
    /// <returns>
    /// The Verifier's JAR signing public key. The caller owns the returned
    /// <see cref="PublicKeyMemory"/> and is responsible for disposing it.
    /// </returns>
    /// <exception cref="SecurityException">
    /// Thrown when chain validation fails, the subject identifier does not
    /// match, or the subject Entity Configuration's <c>jwks</c> does not
    /// produce a key matching the JAR header's <c>kid</c>.
    /// </exception>
    public static async ValueTask<PublicKeyMemory> ResolveAsync(
        IReadOnlyList<string> trustChainValues,
        EntityIdentifier expectedSubject,
        IReadOnlyCollection<EntityIdentifier> trustAnchors,
        DateTimeOffset validationTime,
        TimeSpan clockSkew,
        UnverifiedJwtHeader jarHeader,
        ValidateTrustChainAsyncDelegate validateChain,
        DecodeDelegate base64UrlDecoder,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(trustChainValues);
        ArgumentNullException.ThrowIfNull(trustAnchors);
        ArgumentNullException.ThrowIfNull(jarHeader);
        ArgumentNullException.ThrowIfNull(validateChain);
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(pool);

        TrustChainValidationOutcome outcome = await validateChain(
            trustChainValues, trustAnchors, validationTime, clockSkew, pool, cancellationToken)
            .ConfigureAwait(false);

        //Route the trust decision through the party-trust engine. The Federation
        //assessors (chain validity + freshness) decide whether the verifier is
        //trusted; this centralises the decision and adds defence-in-depth — a failing
        //validation claim is rejected even if the outcome flag reported the chain valid.
        TrustEvidence<TrustChainValidationOutcome> trustEvidence = FederationTrustAdapter.ToEvidence(outcome);
        TrustDecisionRecord<TrustChainValidationOutcome> trust = await PartyTrustEngine.AssessAsync(
            trustEvidence,
            TrustSignalSnapshot.Empty(validationTime),
            FederationTrustAdapter.Assessors,
            validationTime,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        if(!trust.Assessment.IsTrusted || outcome.Chain is null)
        {
            throw new SecurityException(
                $"Federation-bound JAR rejected: {trust.Assessment.RejectionReason ?? outcome.FailureReason}");
        }

        if(outcome.Chain.Statements.Count == 0
            || !outcome.Chain.Statements[0].Subject.Equals(expectedSubject))
        {
            throw new SecurityException(
                $"Federation-bound JAR rejected: chain[0].sub does not match expected client_id '{expectedSubject.Value}'.");
        }

        PublicKeyMemory? signingKey = ResolveJarSigningKey(
            outcome.Chain, jarHeader, base64UrlDecoder, pool);

        return signingKey
            ?? throw new SecurityException(
                "Federation-bound JAR rejected: could not extract signing key from chain[0]'s jwks.");
    }


    /// <summary>
    /// Low-level helper that extracts the Verifier's JAR signing key from
    /// an already-validated chain's subject Entity Configuration. Useful
    /// when the caller has its own chain-walking pipeline and only needs
    /// the final key-extraction step. Production callers typically go
    /// through <see cref="ResolveAsync"/>.
    /// </summary>
    public static PublicKeyMemory? ResolveJarSigningKey(
        TrustChain validatedChain,
        UnverifiedJwtHeader jarHeader,
        DecodeDelegate base64UrlDecoder,
        MemoryPool<byte> memoryPool)
    {
        ArgumentNullException.ThrowIfNull(validatedChain);
        ArgumentNullException.ThrowIfNull(jarHeader);
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(memoryPool);

        if(validatedChain.Statements.Count == 0)
        {
            return null;
        }

        EntityStatement subjectStatement = validatedChain.Statements[0];

        if(!subjectStatement.Payload.TryGetValue(WellKnownFederationClaimNames.Jwks, out object? jwksObj)
            || jwksObj is not IReadOnlyDictionary<string, object> jwksDict
            || !jwksDict.TryGetValue("keys", out object? keysObj)
            || keysObj is not IEnumerable<object> keys)
        {
            return null;
        }

        string? targetKid = null;
        if(jarHeader.TryGetValue(WellKnownJwkMemberNames.Kid, out object? kidObj)
            && kidObj is string kid)
        {
            targetKid = kid;
        }

        Dictionary<string, object>? matchedJwk = null;
        foreach(object item in keys)
        {
            if(item is not IReadOnlyDictionary<string, object> jwk)
            {
                continue;
            }

            if(targetKid is null)
            {
                matchedJwk = CopyJwk(jwk);
                break;
            }

            if(jwk.TryGetValue("kid", out object? jwkKidObj)
                && jwkKidObj is string jwkKid
                && string.Equals(jwkKid, targetKid, StringComparison.Ordinal))
            {
                matchedJwk = CopyJwk(jwk);
                break;
            }
        }

        if(matchedJwk is null)
        {
            return null;
        }

        (CryptoAlgorithm algorithm, Purpose purpose, EncodingScheme scheme, IMemoryOwner<byte> keyMaterial) =
            CryptoFormatConversions.DefaultJwkToAlgorithmConverter(matchedJwk, memoryPool, base64UrlDecoder);

        Tag tag = Tag.Create(algorithm).With(purpose).With(scheme);

        return new PublicKeyMemory(keyMaterial, tag);
    }


    private static Dictionary<string, object> CopyJwk(IReadOnlyDictionary<string, object> source)
    {
        Dictionary<string, object> result = new(source.Count, StringComparer.Ordinal);
        foreach(KeyValuePair<string, object> kvp in source)
        {
            result[kvp.Key] = kvp.Value;
        }
        return result;
    }
}
