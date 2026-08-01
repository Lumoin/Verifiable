using System.Buffers;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// Factory for the library's default
/// <see cref="ResolveEntityKeyDelegate"/> — resolves verification keys
/// against in-chain <c>jwks</c> claims by walking the issuer statement's
/// declared keys and matching the kid header.
/// </summary>
/// <remarks>
/// <para>
/// The "in-chain" qualifier matters. This resolver assumes the chain
/// already carries every statement that contributes a verification key.
/// Resolvers that fetch keys over HTTP from a
/// <c>federation_fetch_endpoint</c> are a separate concern; deployments
/// that want both behaviours wire a composite resolver that tries
/// in-chain first and falls back to fetch.
/// </para>
/// <para>
/// Closes the no-default state of
/// <see cref="ResolveEntityKeyDelegate"/> noted in
/// <see cref="FederationDefaultHooks"/>'s class remark — applications no
/// longer have to write the jwks-walk themselves for the common case.
/// </para>
/// </remarks>
[DebuggerDisplay("FederationKeyResolver")]
public static class FederationKeyResolver
{
    /// <summary>
    /// Builds a <see cref="ResolveEntityKeyDelegate"/> that resolves the
    /// verification key for a statement from the issuer statement's
    /// <c>jwks</c> claim. The returned delegate matches on the
    /// to-be-verified statement's <c>kid</c> header; an absent <c>kid</c> is
    /// a resolution miss (<see langword="null"/>), never a silent
    /// first-key selection, because
    /// <see href="https://openid.net/specs/openid-federation-1_0.html#section-3.1">Federation §3.1</see>
    /// makes the <c>kid</c> header a MUST on Entity Statement JWTs.
    /// </summary>
    /// <param name="base64UrlDecoder">
    /// Base64url decoder used by <see cref="CryptoFormatConversions.DefaultJwkToAlgorithmConverter"/>
    /// when reconstructing key bytes from the JWK's encoded coordinates.
    /// </param>
    /// <param name="memoryPool">
    /// Memory pool the reconstructed key material rents from. The caller
    /// owns the returned <see cref="PublicKeyMemory"/> and is responsible
    /// for disposing it after the verification call completes.
    /// </param>
    public static ResolveEntityKeyDelegate BuildInChainResolver(
        DecodeDelegate base64UrlDecoder,
        MemoryPool<byte> memoryPool)
    {
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(memoryPool);

        return (statementToVerify, headerOfStatementToVerify, issuerStatement, cancellationToken) =>
        {
            cancellationToken.ThrowIfCancellationRequested();

            string? targetKid = ReadKid(headerOfStatementToVerify);

            Dictionary<string, object>? matchedJwk = TryMatchJwk(issuerStatement, targetKid);
            if(matchedJwk is null)
            {
                return ValueTask.FromResult<PublicKeyMemory?>(null);
            }

            (CryptoAlgorithm algorithm, Purpose purpose, EncodingScheme scheme, IMemoryOwner<byte> keyMaterial) =
                CryptoFormatConversions.DefaultJwkToAlgorithmConverter(matchedJwk, memoryPool, base64UrlDecoder);

            Tag tag = Tag.Create(algorithm).With(purpose).With(scheme);

            //The resolved key is owned by and returned to the caller, who disposes it after the verify call.
            return ValueTask.FromResult<PublicKeyMemory?>(new PublicKeyMemory(keyMaterial, tag));
        };
    }


    /// <summary>
    /// Resolves a verification key keyed by issuer Entity Identifier and <c>kid</c> across the whole
    /// <paramref name="chain"/>, rather than from a single issuer link. This is the resolver a trust-mark
    /// verifier needs: a mark's issuer may be any entity in the chain — the Trust Anchor (its self-asserted
    /// Entity Configuration) or a subordinate whose keys a superior attests — and in both shapes the entity's
    /// <c>jwks</c> rides on the statement whose <c>sub</c> is that entity. The first statement whose
    /// <see cref="EntityStatement.Subject"/> equals <paramref name="issuerEntityId"/> and that carries a key
    /// matching <paramref name="kid"/> wins; an absent <paramref name="kid"/> is a resolution miss
    /// (<see langword="null"/>), never a silent first-key selection —
    /// <see href="https://openid.net/specs/openid-federation-1_0.html#section-7">Federation §7</see> (and §8.4.2
    /// for the Trust Mark Status Response) makes the <c>kid</c> header a MUST on Trust Mark JWTs.
    /// </summary>
    /// <param name="chain">The resolved trust chain carrying the candidate statements.</param>
    /// <param name="issuerEntityId">The Entity Identifier whose key is sought (a trust mark's <c>iss</c>).</param>
    /// <param name="kid">The key id to match. A <see langword="null"/> value is a resolution miss, not a wildcard.</param>
    /// <param name="base64UrlDecoder">
    /// Base64url decoder used by <see cref="CryptoFormatConversions.DefaultJwkToAlgorithmConverter"/> when
    /// reconstructing key bytes from the JWK's encoded coordinates.
    /// </param>
    /// <param name="memoryPool">
    /// Memory pool the reconstructed key material rents from. The caller owns the returned
    /// <see cref="PublicKeyMemory"/> and is responsible for disposing it.
    /// </param>
    /// <param name="cancellationToken">Token to monitor for cancellation requests.</param>
    /// <returns>
    /// The resolved <see cref="PublicKeyMemory"/>, or <see langword="null"/> when no chain statement declares a
    /// matching key for the issuer.
    /// </returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "The resolved PublicKeyMemory is the method's return value — ownership transfers to the caller, who disposes it after the verify call, as the parameter docs state.")]
    public static ValueTask<PublicKeyMemory?> ResolveInChainKeyAsync(
        TrustChain chain,
        string issuerEntityId,
        string? kid,
        DecodeDelegate base64UrlDecoder,
        MemoryPool<byte> memoryPool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(chain);
        ArgumentException.ThrowIfNullOrWhiteSpace(issuerEntityId);
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(memoryPool);

        cancellationToken.ThrowIfCancellationRequested();

        foreach(EntityStatement statement in chain.Statements)
        {
            if(!string.Equals(statement.Subject.Value, issuerEntityId, StringComparison.Ordinal))
            {
                continue;
            }

            Dictionary<string, object>? matchedJwk = TryMatchJwk(statement, kid);
            if(matchedJwk is null)
            {
                continue;
            }

            (CryptoAlgorithm algorithm, Purpose purpose, EncodingScheme scheme, IMemoryOwner<byte> keyMaterial) =
                CryptoFormatConversions.DefaultJwkToAlgorithmConverter(matchedJwk, memoryPool, base64UrlDecoder);

            Tag tag = Tag.Create(algorithm).With(purpose).With(scheme);

            //The resolved key is owned by and returned to the caller, who disposes it after the verify call.
            return ValueTask.FromResult<PublicKeyMemory?>(new PublicKeyMemory(keyMaterial, tag));
        }

        return ValueTask.FromResult<PublicKeyMemory?>(null);
    }


    /// <summary>
    /// Reads the <c>kid</c> header value from a to-be-verified statement's protected header, or
    /// <see langword="null"/> when absent.
    /// </summary>
    /// <param name="header">The protected header to read the <c>kid</c> from.</param>
    /// <returns>The <c>kid</c> string, or <see langword="null"/> when the header carries no string <c>kid</c>.</returns>
    private static string? ReadKid(UnverifiedJwtHeader header)
    {
        if(header.TryGetValue(WellKnownJwkMemberNames.Kid, out object? kidObj) && kidObj is string kid)
        {
            return kid;
        }

        return null;
    }


    /// <summary>
    /// Selects the JWK from <paramref name="issuerStatement"/>'s <c>jwks</c> claim whose <c>kid</c> equals
    /// <paramref name="targetKid"/>, returned as the mutable dictionary
    /// <see cref="CryptoFormatConversions.DefaultJwkToAlgorithmConverter"/> expects. <see langword="null"/> when
    /// <paramref name="targetKid"/> is <see langword="null"/> (an absent <c>kid</c> header is malformed input per
    /// <see href="https://openid.net/specs/openid-federation-1_0.html#section-3.1">Federation §3.1</see>, not a
    /// wildcard), or when the statement carries no <c>jwks</c>, or when no key matches.
    /// </summary>
    /// <param name="issuerStatement">The statement whose <c>jwks</c> claim supplies the candidate keys.</param>
    /// <param name="targetKid">The <c>kid</c> to match. A <see langword="null"/> value never matches — it is a resolution miss.</param>
    /// <returns>The matched JWK as a mutable dictionary, or <see langword="null"/> when no key matches.</returns>
    private static Dictionary<string, object>? TryMatchJwk(EntityStatement issuerStatement, string? targetKid)
    {
        //Federation §3.1 makes the kid header a MUST on Entity Statement JWTs (§7 / §8.4.2 for Trust Mark and
        //Trust Mark Status Response JWTs). An absent kid is therefore malformed input, not a wildcard: silently
        //returning the first published key would defeat kid-pinning and let a stripped kid — or a rotated-away
        //key that happens to sit first in the set — be mis-selected. A resolution miss is the secure answer.
        if(targetKid is null)
        {
            return null;
        }

        if(!issuerStatement.Payload.TryGetValue(WellKnownFederationClaimNames.Jwks, out object? jwksObj)
            || jwksObj is not IReadOnlyDictionary<string, object> jwksDict
            || !jwksDict.TryGetValue("keys", out object? keysObj)
            || keysObj is not IEnumerable<object> keys)
        {
            return null;
        }

        foreach(object item in keys)
        {
            if(item is not IReadOnlyDictionary<string, object> jwk)
            {
                continue;
            }

            if(jwk.TryGetValue("kid", out object? jwkKidObj)
                && jwkKidObj is string jwkKid
                && string.Equals(jwkKid, targetKid, StringComparison.Ordinal))
            {
                return CopyJwk(jwk);
            }
        }

        return null;
    }


    //CryptoFormatConversions.DefaultJwkToAlgorithmConverter expects
    //Dictionary<string, object> — copy from the read-only view rather than
    //casting.
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
