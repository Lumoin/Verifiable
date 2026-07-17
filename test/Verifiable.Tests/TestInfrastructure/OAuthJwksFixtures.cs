using System;
using System.Collections.Generic;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Shared single-key JWKS assembly for OAuth federation and OID4VP flow tests, delegating to
/// <see cref="CryptoFormatConversions.DefaultAlgorithmToJwkConverter"/> for the JWK projection.
/// </summary>
internal static class OAuthJwksFixtures
{
    /// <summary>
    /// Builds a single-key JWKS (<c>{"keys":[jwk]}</c>) for <paramref name="publicKey"/>, tagged for
    /// signature use (<c>use=sig</c>).
    /// </summary>
    /// <param name="publicKey">The public key to project as a JWK.</param>
    /// <returns>The JWKS document as a wire-shaped dictionary.</returns>
    internal static Dictionary<string, object> BuildSingleEcKeyJwks(PublicKeyMemory publicKey)
    {
        JsonWebKey jwk = CryptoFormatConversions.DefaultAlgorithmToJwkConverter(
            publicKey.Tag.Get<CryptoAlgorithm>(),
            publicKey.Tag.Get<Purpose>(),
            publicKey.AsReadOnlySpan(),
            TestSetup.Base64UrlEncoder);
        jwk.Use = WellKnownJwkValues.UseSig;

        return new Dictionary<string, object>(StringComparer.Ordinal)
        {
            ["keys"] = new List<object> { jwk }
        };
    }
}
