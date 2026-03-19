using System.Buffers;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;

namespace Verifiable.OAuth.Oid4Vp;

/// <summary>
/// Default implementation of <see cref="ResolveKeyFromVerifierAttestationDelegate"/>.
/// Validates a Verifier Attestation JWT and extracts the JAR signing public key from
/// its <c>cnf</c> claim per
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-12">OID4VP 1.0 §12</see>.
/// </summary>
/// <remarks>
/// <para>
/// Application developers wire up <see cref="ResolveAsync"/> as the
/// <see cref="ResolveKeyFromVerifierAttestationDelegate"/> for the Wallet's JAR
/// verification step, passing a trust anchor key obtained from the ecosystem's
/// trust framework configuration.
/// </para>
/// <para>
/// Typical wiring in application setup:
/// </para>
/// <code>
/// ResolveKeyFromVerifierAttestationDelegate resolver =
///     (attestation, expectedClientId, pool, ct) =>
///         VerifierAttestationKeyResolver.ResolveAsync(
///             attestation, expectedClientId, trustAnchorPublicKey,
///             base64UrlDecoder, headerDeserializer, payloadDeserializer,
///             pool, ct);
/// </code>
/// </remarks>
public static class VerifierAttestationKeyResolver
{
    /// <summary>
    /// Validates the Verifier Attestation JWT signature against the provided trust
    /// anchor key, verifies the <c>sub</c> claim, and extracts the JAR signing public
    /// key from the <c>cnf.jwk</c> claim.
    /// </summary>
    /// <param name="attestation">The Verifier Attestation JWT from the JAR header.</param>
    /// <param name="expectedClientId">
    /// The Client Identifier (without the <c>verifier_attestation:</c> prefix) that the
    /// attestation's <c>sub</c> claim must equal.
    /// </param>
    /// <param name="trustAnchorPublicKey">
    /// The public key of the trust anchor that issued the attestation. Obtained from
    /// the ecosystem's trust framework configuration.
    /// </param>
    /// <param name="base64UrlDecoder">Delegate for Base64Url decoding.</param>
    /// <param name="headerDeserializer">
    /// Delegate for deserializing the JWT JOSE header into a claim dictionary.
    /// </param>
    /// <param name="payloadDeserializer">
    /// Delegate for deserializing the JWT payload into a claim dictionary.
    /// </param>
    /// <param name="pool">Memory pool for key material allocations.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// The Verifier's JAR signing public key. The caller owns the returned
    /// <see cref="PublicKeyMemory"/> and must dispose it.
    /// </returns>
    /// <exception cref="InvalidOperationException">
    /// Thrown when the attestation signature is invalid, the <c>sub</c> claim does not
    /// match the expected Client Identifier, or the <c>cnf.jwk</c> claim is absent or
    /// malformed.
    /// </exception>
    public static async ValueTask<PublicKeyMemory> ResolveAsync(
        VerifierAttestationJwt attestation,
        string expectedClientId,
        PublicKeyMemory trustAnchorPublicKey,
        DecodeDelegate base64UrlDecoder,
        Func<ReadOnlySpan<byte>, IReadOnlyDictionary<string, object>> headerDeserializer,
        Func<ReadOnlySpan<byte>, Dictionary<string, object>> payloadDeserializer,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(attestation);
        ArgumentNullException.ThrowIfNull(expectedClientId);
        ArgumentNullException.ThrowIfNull(trustAnchorPublicKey);
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(headerDeserializer);
        ArgumentNullException.ThrowIfNull(payloadDeserializer);
        ArgumentNullException.ThrowIfNull(pool);

        //Verify the attestation signature against the trust anchor's key.
        //Pass the compact JWT string directly to avoid redundant parsing.
        bool attestationValid = await Jws.VerifyAsync(
            attestation.CompactJwt,
            base64UrlDecoder,
            static (ReadOnlySpan<byte> _) => (object?)null,
            pool,
            trustAnchorPublicKey).ConfigureAwait(false);

        if(!attestationValid)
        {
            throw new InvalidOperationException(
                "Verifier Attestation JWT signature verification failed. " +
                "The attestation was not signed by a trusted trust anchor.");
        }

        //Parse the payload to extract sub and cnf. The signature is already verified
        //above so the payload claims are now trustworthy.
        using UnverifiedJwsMessage unverified = JwsParsing.ParseCompact(
            attestation.CompactJwt,
            base64UrlDecoder,
            headerDeserializer,
            pool);

        Dictionary<string, object> claims = payloadDeserializer(unverified.Payload.Span);

        //Verify sub matches the expected client identifier.
        if(!claims.TryGetValue(WellKnownJwtClaims.Sub, out object? subObj)
            || subObj is not string sub
            || !string.Equals(sub, expectedClientId, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"Verifier Attestation JWT sub claim '{subObj}' does not match " +
                $"expected client identifier '{expectedClientId}'.");
        }

        //Extract the JAR signing public key from the cnf.jwk claim.
        if(!claims.TryGetValue("cnf", out object? cnfObj)
            || cnfObj is not Dictionary<string, object> cnf
            || !cnf.TryGetValue("jwk", out object? jwkObj)
            || jwkObj is not Dictionary<string, object> jwk)
        {
            throw new InvalidOperationException(
                "Verifier Attestation JWT does not carry a cnf.jwk claim. " +
                "The JAR signing public key cannot be resolved.");
        }

        var (algorithm, purpose, _, keyMaterialOwner) =
            CryptoFormatConversions.DefaultJwkToAlgorithmConverter(jwk, pool, base64UrlDecoder);

        Tag tag = (algorithm, purpose) switch
        {
            var (a, p) when a.Equals(CryptoAlgorithm.P256) && p.Equals(Purpose.Verification)
                => CryptoTags.P256PublicKey,
            var (a, p) when a.Equals(CryptoAlgorithm.P384) && p.Equals(Purpose.Verification)
                => CryptoTags.P384PublicKey,
            var (a, p) when a.Equals(CryptoAlgorithm.P521) && p.Equals(Purpose.Verification)
                => CryptoTags.P521PublicKey,
            _ => throw new NotSupportedException(
                $"Unsupported algorithm '{algorithm}' or purpose '{purpose}' in cnf.jwk claim.")
        };

        return new PublicKeyMemory(keyMaterialOwner, tag);
    }
}
