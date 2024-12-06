using System;
using System.Buffers;
using System.Collections.Generic;
using Verifiable.Core.Cryptography.Context;
using Verifiable.Core.Did;
using Verifiable.Jwt;
using Verifiable.Cryptography;

namespace Verifiable.Core.Cryptography
{
    public delegate Dictionary<string, object> AlgorithmToJwkDelegate(CryptoAlgorithm algorithm, Purpose purpose, ReadOnlySpan<byte> keyMaterial);
    public delegate string AlgorithmToBase58Delegate(CryptoAlgorithm algorithm, Purpose purpose, ReadOnlySpan<byte> keyMaterial, BufferAllocationEncodeDelegate encoder);

    public delegate (CryptoAlgorithm Algorithm, Purpose Purpose, EncodingScheme Scheme, IMemoryOwner<byte>) JwkToAlgorithmDelegate(Dictionary<string, object> jwk, MemoryPool<byte> memoryPool);
    public delegate (CryptoAlgorithm Algorithm, Purpose Purpose, EncodingScheme Scheme, IMemoryOwner<byte> keyMaterial) Base58ToAlgorithmDelegate(string base58Key, MemoryPool<byte> memoryPool, BufferAllocationDecodeDelegate encoder);

    public delegate (CryptoAlgorithm Algorithm, Purpose Purpose, EncodingScheme Scheme, IMemoryOwner<byte> keyMaterial) VerificationMethodToAlgorithmConverterDelegate(VerificationMethod method, MemoryPool<byte> memoryPool);


    /// <summary>
    /// This class defines default conversions from <em>Verifiable</em> internal representation to others
    /// and from <em>Verifiable</em> representation to other formats.
    /// </summary>
    public static class VerifiableCryptoFormatConversions
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
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.P256) && p.Equals(Purpose.Verification) => AddEcHeaders(WellKnownJwaValues.Es256, WellKnownCurveValues.P256, keyMaterial, jwkHeaders, EllipticCurveTypes.P256),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.P384) && p.Equals(Purpose.Verification) => AddEcHeaders(WellKnownJwaValues.Es384, WellKnownCurveValues.P384, keyMaterial, jwkHeaders, EllipticCurveTypes.P384),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.P521) && p.Equals(Purpose.Verification) => AddEcHeaders(WellKnownJwaValues.Es512, WellKnownCurveValues.P521, keyMaterial, jwkHeaders, EllipticCurveTypes.P521),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.Secp256k1) && p.Equals(Purpose.Verification) => AddEcHeaders(WellKnownJwaValues.Es256k1, WellKnownCurveValues.Secp256k1, keyMaterial, jwkHeaders, EllipticCurveTypes.Secp256k1),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.Rsa2048) && p.Equals(Purpose.Verification) => AddRsaHeaders(keyMaterial, jwkHeaders),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.Rsa4096) && p.Equals(Purpose.Verification) => AddRsaHeaders(keyMaterial, jwkHeaders),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.Ed25519) && p.Equals(Purpose.Verification) => AddEd25519Headers(keyMaterial, jwkHeaders),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.X25519) && p.Equals(Purpose.Exchange) => AddX25519Headers(keyMaterial, jwkHeaders),
                _ => throw new ArgumentException($"Unknown combination of algorithm and purpose: \"{algorithm}\", \"{purpose}\".")
            };
        };


        public static AlgorithmToBase58Delegate DefaultAlgorithmToBase58Converter => (algorithm, purpose, keyMaterial, encoder) =>
        {
            static string EncodeKey(ReadOnlySpan<byte> keyMaterial, ReadOnlySpan<byte> multicodecHeader, BufferAllocationEncodeDelegate encoder)
            {
                return MultibaseSerializer.Encode(keyMaterial, multicodecHeader, MultibaseAlgorithms.Base58Btc, ExactSizeMemoryPool<char>.Shared, encoder);
            }

            return (algorithm, purpose) switch
            {
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.P256) && p.Equals(Purpose.Verification) => EncodeKey(keyMaterial, MulticodecHeaders.P256PublicKey, encoder),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.P384) && p.Equals(Purpose.Verification) => EncodeKey(keyMaterial, MulticodecHeaders.P384PublicKey, encoder),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.P521) && p.Equals(Purpose.Verification) => EncodeKey(keyMaterial, MulticodecHeaders.P521PublicKey, encoder),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.Secp256k1) && p.Equals(Purpose.Verification) => EncodeKey(keyMaterial, MulticodecHeaders.Secp256k1PublicKey, encoder),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.Rsa2048) && p.Equals(Purpose.Verification) => EncodeKey(keyMaterial, MulticodecHeaders.RsaPublicKey, encoder),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.Rsa4096) && p.Equals(Purpose.Verification) => EncodeKey(keyMaterial, MulticodecHeaders.RsaPublicKey, encoder),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.Bls12381G1) && p.Equals(Purpose.Verification) => EncodeKey(keyMaterial, MulticodecHeaders.Bls12381G1PublicKey, encoder),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.Ed25519) && p.Equals(Purpose.Verification) => EncodeKey(keyMaterial, MulticodecHeaders.Ed25519PublicKey, encoder),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.X25519) && p.Equals(Purpose.Exchange) => EncodeKey(keyMaterial, MulticodecHeaders.X25519PublicKey, encoder),
                _ => throw new ArgumentException($"Unknown combination of algorithm and purpose: \"{algorithm}\", \"{purpose}\".")
            };
        };



        public static JwkToAlgorithmDelegate DefaultJwkToAlgorithmConverter => (jwk, memoryPool) =>
        {
            if(jwk == null)
            {
                throw new ArgumentNullException(nameof(jwk), "JWK cannot be null.");
            }
            
            if(!jwk.TryGetValue(JwkProperties.Kty, out var kty) || !(kty is string keyType))
            {
                throw new ArgumentException($"JWK must contain a valid '{JwkProperties.Kty}' field.", nameof(jwk));
            }

            if(!jwk.TryGetValue(JwkProperties.Alg, out var alg) || !(alg is string algorithm))
            {
                throw new ArgumentException($"JWK must contain a valid '{JwkProperties.Alg}' field.", nameof(jwk));
            }

            if(!jwk.TryGetValue(JwkProperties.X, out var x) || !(x is string xBase64))
            {
                throw new ArgumentException($"JWK must contain a valid '{JwkProperties.X}' field for key material.", nameof(jwk));
            }

            var keyMaterial = DecodeKeyMaterial(jwk, keyType);
            var (cryptoAlgorithm, purpose) = MapToAlgorithmAndPurpose(keyType, algorithm);

            IMemoryOwner<byte> keyMaterialOwner = memoryPool.Rent(keyMaterial.Length);
            keyMaterial.CopyTo(keyMaterialOwner.Memory.Span);

            return (cryptoAlgorithm, purpose, EncodingScheme.Raw, keyMaterialOwner);

            static ReadOnlySpan<byte> DecodeKeyMaterial(Dictionary<string, object> jwk, string keyType)
            {
                return keyType switch
                {
                    var key when WellKnownKeyTypeValues.IsEc(key) => DecodeEcKey(jwk),
                    var key when WellKnownKeyTypeValues.IsOkp(key) => DecodeOkpKey(jwk),
                    var key when WellKnownKeyTypeValues.IsRsa(key) => DecodeRsaKey(jwk),
                    _ => throw new ArgumentException($"Unsupported key type: '{keyType}'.")
                };
            }

            static ReadOnlySpan<byte> DecodeEcKey(Dictionary<string, object> jwk)
            {
                if(!jwk.TryGetValue(JwkProperties.Y, out object? y) || y is not string yBase64)
                {
                    throw new ArgumentException($"JWK must contain a valid '{JwkProperties.Y}' field for EC keys.", nameof(jwk));
                }

                var xBytes = Base64Url.Decode((string)jwk[JwkProperties.X]);
                var yBytes = Base64Url.Decode(yBase64);
                return EllipticCurveUtilities.Compress(xBytes, yBytes); // Recreates the compressed EC key
            }


            static ReadOnlySpan<byte> DecodeOkpKey(Dictionary<string, object> jwk)
            {
                return Base64Url.Decode((string)jwk[JwkProperties.X]);
            }

            static ReadOnlySpan<byte> DecodeRsaKey(Dictionary<string, object> jwk)
            {
                if(!jwk.TryGetValue(JwkProperties.N, out var n) || !(n is string nBase64))
                {
                    throw new ArgumentException($"JWK must contain a valid '{JwkProperties.N}' field for RSA keys.", nameof(jwk));
                }

                return Base64Url.Decode(nBase64);
            }

            static CryptoAlgorithm DetermineRsaAlgorithm(int keyLength = 0)
            {
                return keyLength switch
                {
                    256 => CryptoAlgorithm.Rsa2048,
                    512 => CryptoAlgorithm.Rsa4096,
                    _ => throw new ArgumentException($"Unsupported RSA key size: {keyLength}.")
                };
            }

            static (CryptoAlgorithm, Purpose) MapToAlgorithmAndPurpose(string keyType, string algorithm)
            {
                return (keyType, algorithm) switch
                {
                    var (key, alg) when WellKnownKeyTypeValues.IsEc(key) && WellKnownJwaValues.IsEs256(alg) => (CryptoAlgorithm.P256, Purpose.Verification),
                    var (key, alg) when WellKnownKeyTypeValues.IsEc(key) && WellKnownJwaValues.IsEs384(alg) => (CryptoAlgorithm.P384, Purpose.Verification),
                    var (key, alg) when WellKnownKeyTypeValues.IsEc(key) && WellKnownJwaValues.IsEs512(alg) => (CryptoAlgorithm.P521, Purpose.Verification),

                    var (key, alg) when WellKnownKeyTypeValues.IsOkp(key) && WellKnownCurveValues.IsEd25519(alg) => (CryptoAlgorithm.Ed25519, Purpose.Verification),
                    var (key, alg) when WellKnownKeyTypeValues.IsOkp(key) && WellKnownCurveValues.IsX25519(alg) => (CryptoAlgorithm.X25519, Purpose.Exchange),

                    var (key, _) when WellKnownKeyTypeValues.IsRsa(key) => (DetermineRsaAlgorithm(), Purpose.Verification),

                    _ => throw new ArgumentException($"Unsupported key type or algorithm: '{keyType}', '{algorithm}'.")
                };
            }
        };


        public static Base58ToAlgorithmDelegate DefaultBase58ToAlgorithmConverter => (base58Key, memoryPool, decoder) =>
        {
            if(string.IsNullOrWhiteSpace(base58Key))
            {
                throw new ArgumentNullException(nameof(base58Key), "Base58 key cannot be null or empty.");
            }

            if(!base58Key[0].Equals(MultibaseAlgorithms.Base58Btc))
            {
                throw new ArgumentException($"Base58 key must start with '{MultibaseAlgorithms.Base58Btc}' for multibase format.", nameof(base58Key));
            }

            //Validate and fetch canonicalized header.
            ReadOnlySpan<char> header = Base58BtcEncodedMulticodecHeaders.GetCanonicalizedHeader(base58Key.AsSpan(0, 4));
            if(header.SequenceEqual(base58Key))
            {
                throw new ArgumentException("Unknown or unsupported multicodec header.", nameof(base58Key));
            }

            int headerLength = header.Length;
            var decodedKeyMaterialWithoutHeader = MultibaseSerializer.Decode(base58Key, memoryPool, decoder);

            return header switch
            {
                var h when Base58BtcEncodedMulticodecHeaders.IsSecp256k1PublicKey(h) => (CryptoAlgorithm.Secp256k1, Purpose.Verification, EncodingScheme.Raw, decodedKeyMaterialWithoutHeader),
                var h when Base58BtcEncodedMulticodecHeaders.IsEd25519PublicKey(h) => (CryptoAlgorithm.Ed25519, Purpose.Verification, EncodingScheme.Raw, decodedKeyMaterialWithoutHeader),
                var h when Base58BtcEncodedMulticodecHeaders.IsX25519PublicKey(h) => (CryptoAlgorithm.X25519, Purpose.Exchange, EncodingScheme.Raw, decodedKeyMaterialWithoutHeader),
                var h when Base58BtcEncodedMulticodecHeaders.IsP256PublicKey(h) => (CryptoAlgorithm.P256, Purpose.Verification, EncodingScheme.Raw, decodedKeyMaterialWithoutHeader),
                var h when Base58BtcEncodedMulticodecHeaders.IsP384PublicKey(h) => (CryptoAlgorithm.P384, Purpose.Verification, EncodingScheme.Raw, decodedKeyMaterialWithoutHeader),
                var h when Base58BtcEncodedMulticodecHeaders.IsP521PublicKey(h) => (CryptoAlgorithm.P521, Purpose.Verification, EncodingScheme.Raw, decodedKeyMaterialWithoutHeader),
                var h when Base58BtcEncodedMulticodecHeaders.IsRsaPublicKey2048(h) => (CryptoAlgorithm.Rsa2048, Purpose.Verification, EncodingScheme.Raw, decodedKeyMaterialWithoutHeader),
                var h when Base58BtcEncodedMulticodecHeaders.IsRsaPublicKey4096(h) => (CryptoAlgorithm.Rsa4096, Purpose.Verification, EncodingScheme.Raw, decodedKeyMaterialWithoutHeader),
                _ => throw new ArgumentException($"Unsupported header: {header}", nameof(base58Key))
            };
        };


        public static VerificationMethodToAlgorithmConverterDelegate DefaultVerificationMethodToAlgorithmConverter => (method, memoryPool) =>
        {
            if(method == null)
            {
                throw new ArgumentNullException(nameof(method), "VerificationMethod cannot be null.");
            }

            if(string.IsNullOrWhiteSpace(method.Type))
            {
                throw new ArgumentException("VerificationMethod must have a valid 'Type' property.", nameof(method));
            }

            if(method.KeyFormat == null)
            {
                throw new ArgumentException("VerificationMethod must have a valid 'KeyFormat' property.", nameof(method));
            }

            
            Type keyFormatType = method.KeyFormat.GetType();
            return method.KeyFormat switch
            {                
                PublicKeyMultibase multibaseKey when !string.IsNullOrWhiteSpace(multibaseKey.Key) =>
                    VerifiableCryptoFormatConversions.DefaultBase58ToAlgorithmConverter(
                        multibaseKey.Key,
                        memoryPool,
                        DefaultCoderSelector.SelectDecoder(multibaseKey.GetType())),

                PublicKeyJwk jwkKey when jwkKey.Header is Dictionary<string, object> jwkHeader =>
                    VerifiableCryptoFormatConversions.DefaultJwkToAlgorithmConverter(
                        jwkHeader,
                        memoryPool),
                
                _ => throw new ArgumentException($"Unsupported KeyFormat for VerificationMethod of Type '{method.Type}'.", nameof(method))
            };
        };
    }
}        
