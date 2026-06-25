using System.Buffers;
using System.Diagnostics;
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
    /// to-be-verified statement's <c>kid</c> header; absent kid selects
    /// the first key in the issuer's jwks.
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

            if(!issuerStatement.Payload.TryGetValue(WellKnownFederationClaimNames.Jwks, out object? jwksObj)
                || jwksObj is not IReadOnlyDictionary<string, object> jwksDict
                || !jwksDict.TryGetValue("keys", out object? keysObj)
                || keysObj is not IEnumerable<object> keys)
            {
                return ValueTask.FromResult<PublicKeyMemory?>(null);
            }

            string? targetKid = null;
            if(headerOfStatementToVerify.TryGetValue(WellKnownJwkMemberNames.Kid, out object? kidObj)
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
                return ValueTask.FromResult<PublicKeyMemory?>(null);
            }

            (CryptoAlgorithm algorithm, Purpose purpose, EncodingScheme scheme, IMemoryOwner<byte> keyMaterial) =
                CryptoFormatConversions.DefaultJwkToAlgorithmConverter(matchedJwk, memoryPool, base64UrlDecoder);

            Tag tag = new(new Dictionary<Type, object>
            {
                [typeof(CryptoAlgorithm)] = algorithm,
                [typeof(Purpose)] = purpose,
                [typeof(EncodingScheme)] = scheme,
            });

            return ValueTask.FromResult<PublicKeyMemory?>(new PublicKeyMemory(keyMaterial, tag));
        };
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
