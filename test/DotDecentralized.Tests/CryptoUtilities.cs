using DotDecentralized.BouncyCastle;
using DotDecentralized.Core.Did;
using Microsoft.IdentityModel.Tokens;
using NSec.Cryptography;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.Diagnostics.CodeAnalysis;

namespace DotDecentralized.Tests
{
    /// <summary>
    /// Cryptographic utilities used in testing.
    /// </summary>
    public static class CryptoUtilities
    {
        /// <summary>
        /// Creates a JWK string with valid public and private key information.
        /// </summary>
        /// <param name="keyType">The JWK key type.</param>
        /// <param name="curve">The JWK curve type.</param>
        /// <param name="seed">The seed for the public private key type.</param>
        /// <returns>A JWK string with public and private key type information.</returns>
        [return: NotNull]
        public static string GeneratePublicPrivateJwk(string keyType, string curve, byte[] seed)
        {
            var key = Key.Create(SignatureAlgorithm.Ed25519, new KeyCreationParameters() { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });

            var publicKeyBytes = key.Export(KeyBlobFormat.RawPublicKey);
            var privateKeyBytes = key.Export(KeyBlobFormat.RawPrivateKey);

            var publicKeyBytesInBase64 = Base64UrlEncoder.Encode(publicKeyBytes);
            var privateKeyBytesInBase64 = Base64UrlEncoder.Encode(privateKeyBytes);

            return $@"{{ ""kty"": ""{keyType}"", ""crv"": ""{curve}"", ""x"": ""{publicKeyBytesInBase64}"", ""d"": ""{privateKeyBytesInBase64}"" }}";
        }
    }
}
