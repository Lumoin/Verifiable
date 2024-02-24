using System;
using System.Collections.Generic;
using Verifiable.Core.Cryptography.Context;
using Verifiable.Core.Did;
using Verifiable.Jwt;

namespace Verifiable.Core.Cryptography
{
    public delegate Dictionary<string, object> AlgorithmToJwkDelegate(CryptoAlgorithm algorithm, Purpose purpose, ReadOnlySpan<byte> keyMaterial);
    public delegate string AlgorithmToBase58Delegate(CryptoAlgorithm algorithm, Purpose purpose, ReadOnlySpan<byte> keyMaterial, BufferAllocationEncodeDelegate encoder);

    public static class KeyHeaderConversion
    {
        public static AlgorithmToJwkDelegate DefaultAlgorithmToJwkConverter => (algorithm, purpose, keyMaterial) =>
        {
            static Dictionary<string, object> AddEcHeaders(string alg, string crv, ReadOnlySpan<byte> keyMaterial, Dictionary<string, object> headers, EllipticCurveTypes curveType)
            {
                ReadOnlySpan<byte> compressedXAndY = keyMaterial;
                byte[] uncompressedY = EllipticCurveUtilities.Decompress(compressedXAndY, curveType);
                ReadOnlySpan<byte> uncompressedX = compressedXAndY.Slice(1);

                var compressedJwt = Base64Url.Encode(compressedXAndY);
                var jwtX = Base64Url.Encode(uncompressedX);
                var jwtY = Base64Url.Encode(uncompressedY);

                headers.Add(JwkProperties.Kty, WellKnownKeyTypeValues.Ec);
                headers.Add(JwkProperties.Alg, alg);
                headers.Add(JwkProperties.Crv, crv);
                headers.Add(JwkProperties.X, jwtX);
                headers.Add(JwkProperties.Y, jwtY);

                return headers;
            }

            static Dictionary<string, object> AddRsaHeaders(ReadOnlySpan<byte> keyMaterial, Dictionary<string, object> headers)
            {
                ReadOnlySpan<byte> keyBytes = keyMaterial;
                var base64UrlencodedKeyBytes = Base64Url.Encode(keyBytes);

                headers.Add(JwkProperties.Kty, WellKnownKeyTypeValues.Rsa);
                headers.Add(JwkProperties.E, RsaUtilities.DefaultExponent);
                headers.Add(JwkProperties.N, base64UrlencodedKeyBytes);

                return headers;
            }

            static Dictionary<string, object> AddEd25519Headers(ReadOnlySpan<byte> keyMaterial, Dictionary<string, object> headers)
            {
                var base64UrlencodedKeyBytes = Base64Url.Encode(keyMaterial);

                headers.Add(JwkProperties.Kty, WellKnownKeyTypeValues.Okp);
                headers.Add(JwkProperties.Crv, WellKnownCurveValues.Ed25519);
                headers.Add(JwkProperties.X, base64UrlencodedKeyBytes);

                return headers;
            }

            static Dictionary<string, object> AddX25519Headers(ReadOnlySpan<byte> keyMaterial, Dictionary<string, object> headers)
            {
                var base64UrlencodedKeyBytes = Base64Url.Encode(keyMaterial);

                headers.Add(JwkProperties.Kty, WellKnownKeyTypeValues.Okp);
                headers.Add(JwkProperties.Crv, WellKnownCurveValues.X25519);
                headers.Add(JwkProperties.X, base64UrlencodedKeyBytes);

                return headers;
            }

            var jwkHeaders = new Dictionary<string, object>();
            return (algorithm, purpose) switch
            {
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.P256) && p.Equals(Purpose.Public) => AddEcHeaders(WellKnownJwaValues.Es256, WellKnownCurveValues.P256, keyMaterial, jwkHeaders, EllipticCurveTypes.P256),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.P384) && p.Equals(Purpose.Public) => AddEcHeaders(WellKnownJwaValues.Es384, WellKnownCurveValues.P384, keyMaterial, jwkHeaders, EllipticCurveTypes.P384),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.P521) && p.Equals(Purpose.Public) => AddEcHeaders(WellKnownJwaValues.Es512, WellKnownCurveValues.P521, keyMaterial, jwkHeaders, EllipticCurveTypes.P521),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.Secp256k1) && p.Equals(Purpose.Public) => AddEcHeaders(WellKnownJwaValues.Es256k1, WellKnownCurveValues.Secp256k1, keyMaterial, jwkHeaders, EllipticCurveTypes.Secp256k1),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.Rsa2048) && p.Equals(Purpose.Public) => AddRsaHeaders(keyMaterial, jwkHeaders),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.Rsa4096) && p.Equals(Purpose.Public) => AddRsaHeaders(keyMaterial, jwkHeaders),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.Ed25519) && p.Equals(Purpose.Public) => AddEd25519Headers(keyMaterial, jwkHeaders),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.X25519) && p.Equals(Purpose.Exchange) => AddX25519Headers(keyMaterial, jwkHeaders),
                _ => throw new ArgumentException($"Unknown combination of algorithm and purpose: {algorithm}, {purpose}")
            };
        };


        public static AlgorithmToBase58Delegate DefaultAlgorithmToBase58Converter => (algorithm, purpose, keyMaterial, encoder) =>
        {
            static string EncodeKey(ReadOnlySpan<byte> keyMaterial, BufferAllocationEncodeDelegate encoder, ReadOnlySpan<byte> multicodecHeader)
            {
                return SsiSerializer.Encode(keyMaterial, multicodecHeader, MultibaseAlgorithms.Base58Btc, ExactSizeMemoryPool<char>.Shared, encoder);
            }

            return (algorithm, purpose) switch
            {
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.P256) && p.Equals(Purpose.Public) => EncodeKey(keyMaterial, encoder, MulticodecHeaders.P256PublicKey),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.P384) && p.Equals(Purpose.Public) => EncodeKey(keyMaterial, encoder, MulticodecHeaders.P384PublicKey),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.P521) && p.Equals(Purpose.Public) => EncodeKey(keyMaterial, encoder, MulticodecHeaders.P521PublicKey),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.Secp256k1) && p.Equals(Purpose.Public) => EncodeKey(keyMaterial, encoder, MulticodecHeaders.Secp256k1PublicKey),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.Rsa2048) && p.Equals(Purpose.Public) => EncodeKey(keyMaterial, encoder, MulticodecHeaders.RsaPublicKey),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.Rsa4096) && p.Equals(Purpose.Public) => EncodeKey(keyMaterial, encoder, MulticodecHeaders.RsaPublicKey),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.Bls12381G1) && p.Equals(Purpose.Public) => EncodeKey(keyMaterial, encoder, MulticodecHeaders.Bls12381G1PublicKey),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.Ed25519) && p.Equals(Purpose.Public) => EncodeKey(keyMaterial, encoder, MulticodecHeaders.Ed25519PublicKey),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.X25519) && p.Equals(Purpose.Exchange) => EncodeKey(keyMaterial, encoder, MulticodecHeaders.X25519PublicKey),
                _ => throw new ArgumentException($"Unknown combination of algorithm and purpose: {algorithm}, {purpose}")
            };
        };
    }
}
