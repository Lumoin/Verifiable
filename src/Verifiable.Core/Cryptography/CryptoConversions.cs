using System;
using System.Buffers;
using System.Collections.Generic;
using Verifiable.Core.Cryptography.Context;
using Verifiable.Core.Cryptography.testing;
using Verifiable.Core.Did;
using Verifiable.Cryptography;
using Verifiable.Jwt;

namespace Verifiable.Core.Cryptography
{
    public delegate Dictionary<string, object> AlgorithmToJwkDelegate(CryptoAlgorithm algorithm, Purpose purpose, ReadOnlySpan<byte> keyMaterial, EncodeDelegate base64UrlEncoder);
    public delegate string AlgorithmToBase58Delegate(CryptoAlgorithm algorithm, Purpose purpose, ReadOnlySpan<byte> keyMaterial, EncodeDelegate base58Encoder);

    public delegate (CryptoAlgorithm Algorithm, Purpose Purpose, EncodingScheme Scheme, IMemoryOwner<byte>) JwkToAlgorithmDelegate(Dictionary<string, object> jwk, MemoryPool<byte> memoryPool, DecodeDelegate base64UrlDecoder);
    public delegate (CryptoAlgorithm Algorithm, Purpose Purpose, EncodingScheme Scheme, IMemoryOwner<byte> keyMaterial) Base58ToAlgorithmDelegate(string base58Key, MemoryPool<byte> memoryPool, DecodeDelegate base58Decoder);

    public delegate (CryptoAlgorithm Algorithm, Purpose Purpose, EncodingScheme Scheme, IMemoryOwner<byte> keyMaterial) VerificationMethodToAlgorithmConverterDelegate(VerificationMethod method, MemoryPool<byte> memoryPool);


    /// <summary>
    /// This class defines default conversions from <em>Verifiable</em> internal representation to others
    /// and from <em>Verifiable</em> representation to other formats.
    /// </summary>
    public static class VerifiableCryptoFormatConversions
    {
        public static AlgorithmToJwkDelegate DefaultAlgorithmToJwkConverter => (algorithm, purpose, keyMaterial, base64UrlEncoder) =>
        {
            static Dictionary<string, object> AddEcHeaders(string alg, string crv, ReadOnlySpan<byte> keyMaterial, Dictionary<string, object> headers, EllipticCurveTypes curveType, EncodeDelegate encoder)
            {
                ReadOnlySpan<byte> compressedXAndY = keyMaterial;
                byte[] uncompressedY = EllipticCurveUtilities.Decompress(compressedXAndY, curveType);
                ReadOnlySpan<byte> uncompressedX = compressedXAndY.Slice(1);

                var jwtX = EncodeForJwk(uncompressedX, encoder);
                var jwtY = EncodeForJwk(uncompressedY, encoder);

                headers.Add(JwkProperties.Kty, WellKnownKeyTypeValues.Ec);
                headers.Add(JwkProperties.Alg, alg);
                headers.Add(JwkProperties.Crv, crv);
                headers.Add(JwkProperties.X, jwtX);
                headers.Add(JwkProperties.Y, jwtY);

                return headers;
            }

            static Dictionary<string, object> AddRsaHeaders(string alg, ReadOnlySpan<byte> keyMaterial, Dictionary<string, object> headers, Tag keyTag, EncodeDelegate encoder)
            {
                var encodingScheme = keyTag.Get<EncodingScheme>();
                byte[] rawModulus = encodingScheme switch
                {
                    EncodingScheme enc when enc.Equals(EncodingScheme.Der) => RsaUtilities.Decode(keyMaterial),
                    EncodingScheme enc when enc.Equals(EncodingScheme.Raw) => keyMaterial.ToArray(),
                    _ => throw new ArgumentException($"Unsupported encoding scheme for RSA: {encodingScheme}")
                };

                ReadOnlySpan<byte> keyBytes = rawModulus;
                var base64UrlencodedKeyBytes = EncodeForJwk(keyBytes, encoder);

                headers.Add(JwkProperties.Alg, alg);
                headers.Add(JwkProperties.Kty, WellKnownKeyTypeValues.Rsa);
                headers.Add(JwkProperties.E, RsaUtilities.DefaultExponent);
                headers.Add(JwkProperties.N, base64UrlencodedKeyBytes);

                return headers;
            }

            static Dictionary<string, object> AddEd25519Headers(ReadOnlySpan<byte> keyMaterial, Dictionary<string, object> headers, EncodeDelegate encoder)
            {
                var base64UrlencodedKeyBytes = EncodeForJwk(keyMaterial, encoder);

                headers.Add(JwkProperties.Kty, WellKnownKeyTypeValues.Okp);
                headers.Add(JwkProperties.Alg, WellKnownJwaValues.EdDsa);
                headers.Add(JwkProperties.Crv, WellKnownCurveValues.Ed25519);
                headers.Add(JwkProperties.X, base64UrlencodedKeyBytes);

                return headers;
            }

            static Dictionary<string, object> AddX25519Headers(ReadOnlySpan<byte> keyMaterial, Dictionary<string, object> headers, EncodeDelegate encoder)
            {
                var base64UrlencodedKeyBytes = EncodeForJwk(keyMaterial, encoder);

                headers.Add(JwkProperties.Kty, WellKnownKeyTypeValues.Okp);
                headers.Add(JwkProperties.Crv, WellKnownCurveValues.X25519);
                headers.Add(JwkProperties.X, base64UrlencodedKeyBytes);

                return headers;
            }

            //Helper method to encode data for JWK using the provided encoder.
            static string EncodeForJwk(ReadOnlySpan<byte> data, EncodeDelegate encoder)
            {
                return encoder(data);
            }

            var jwkHeaders = new Dictionary<string, object>();
            return (algorithm, purpose) switch
            {
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.P256) && p.Equals(Purpose.Verification) => AddEcHeaders(WellKnownJwaValues.Es256, WellKnownCurveValues.P256, keyMaterial, jwkHeaders, EllipticCurveTypes.P256, base64UrlEncoder),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.P384) && p.Equals(Purpose.Verification) => AddEcHeaders(WellKnownJwaValues.Es384, WellKnownCurveValues.P384, keyMaterial, jwkHeaders, EllipticCurveTypes.P384, base64UrlEncoder),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.P521) && p.Equals(Purpose.Verification) => AddEcHeaders(WellKnownJwaValues.Es512, WellKnownCurveValues.P521, keyMaterial, jwkHeaders, EllipticCurveTypes.P521, base64UrlEncoder),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.Secp256k1) && p.Equals(Purpose.Verification) => AddEcHeaders(WellKnownJwaValues.Es256k1, WellKnownCurveValues.Secp256k1, keyMaterial, jwkHeaders, EllipticCurveTypes.Secp256k1, base64UrlEncoder),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.Rsa2048) && p.Equals(Purpose.Verification) => AddRsaHeaders(WellKnownJwaValues.Rs256, keyMaterial, jwkHeaders, Tag.Rsa2048PublicKey, base64UrlEncoder),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.Rsa4096) && p.Equals(Purpose.Verification) => AddRsaHeaders(WellKnownJwaValues.Rs256, keyMaterial, jwkHeaders, Tag.Rsa4096PublicKey, base64UrlEncoder),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.Ed25519) && p.Equals(Purpose.Verification) => AddEd25519Headers(keyMaterial, jwkHeaders, base64UrlEncoder),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.X25519) && p.Equals(Purpose.Exchange) => AddX25519Headers(keyMaterial, jwkHeaders, base64UrlEncoder),
                _ => throw new ArgumentException($"Unknown combination of algorithm and purpose: \"{algorithm}\", \"{purpose}\".")
            };
        };

        public static AlgorithmToBase58Delegate DefaultAlgorithmToBase58Converter => (algorithm, purpose, keyMaterial, base58Encoder) =>
        {
            static string EncodeKey(ReadOnlySpan<byte> keyMaterial, ReadOnlySpan<byte> multicodecHeader, EncodeDelegate encoder)
            {
                return MultibaseSerializer.Encode(keyMaterial, multicodecHeader, MultibaseAlgorithms.Base58Btc, encoder, SensitiveMemoryPool<byte>.Shared);
            }

            return (algorithm, purpose) switch
            {
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.P256) && p.Equals(Purpose.Verification) => EncodeKey(keyMaterial, MulticodecHeaders.P256PublicKey, base58Encoder),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.P384) && p.Equals(Purpose.Verification) => EncodeKey(keyMaterial, MulticodecHeaders.P384PublicKey, base58Encoder),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.P521) && p.Equals(Purpose.Verification) => EncodeKey(keyMaterial, MulticodecHeaders.P521PublicKey, base58Encoder),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.Secp256k1) && p.Equals(Purpose.Verification) => EncodeKey(keyMaterial, MulticodecHeaders.Secp256k1PublicKey, base58Encoder),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.Rsa2048) && p.Equals(Purpose.Verification) => EncodeKey(keyMaterial, MulticodecHeaders.RsaPublicKey, base58Encoder),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.Rsa4096) && p.Equals(Purpose.Verification) => EncodeKey(keyMaterial, MulticodecHeaders.RsaPublicKey, base58Encoder),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.Bls12381G1) && p.Equals(Purpose.Verification) => EncodeKey(keyMaterial, MulticodecHeaders.Bls12381G1PublicKey, base58Encoder),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.Ed25519) && p.Equals(Purpose.Verification) => EncodeKey(keyMaterial, MulticodecHeaders.Ed25519PublicKey, base58Encoder),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.X25519) && p.Equals(Purpose.Exchange) => EncodeKey(keyMaterial, MulticodecHeaders.X25519PublicKey, base58Encoder),
                _ => throw new ArgumentException($"Unknown combination of algorithm and purpose: \"{algorithm}\", \"{purpose}\".")
            };
        };

        public static JwkToAlgorithmDelegate DefaultJwkToAlgorithmConverter => static (jwk, memoryPool, base64UrlDecoder) =>
        {
            if(jwk == null)
            {
                throw new ArgumentNullException(nameof(jwk), "JWK cannot be null.");
            }

            if(!jwk.TryGetValue(JwkProperties.Kty, out var kty) || !(kty is string keyType))
            {
                throw new ArgumentException($"JWK must contain a valid '{JwkProperties.Kty}' field.", nameof(jwk));
            }

            //Check for required fields based on key type.
            ValidateRequiredFields(jwk, keyType);

            //Make 'alg' optional with fallback logic.
            string algorithm = string.Empty;
            if(jwk.TryGetValue(JwkProperties.Alg, out var alg) && alg is string algString)
            {
                algorithm = algString;
            }

            var keyMaterial = DecodeKeyMaterial(jwk, keyType, base64UrlDecoder);
            var (cryptoAlgorithm, purpose) = MapToAlgorithmAndPurpose(keyType, algorithm, keyMaterial.Length);

            IMemoryOwner<byte> keyMaterialOwner = memoryPool.Rent(keyMaterial.Length);
            keyMaterial.CopyTo(keyMaterialOwner.Memory.Span);

            return (cryptoAlgorithm, purpose, EncodingScheme.Raw, keyMaterialOwner);

            static void ValidateRequiredFields(Dictionary<string, object> jwk, string keyType)
            {
                switch(keyType)
                {
                    case string key when WellKnownKeyTypeValues.IsEc(key):
                        //EC keys require 'x' and 'y' coordinates.
                        if(!jwk.ContainsKey(JwkProperties.X) || jwk[JwkProperties.X] is not string)
                        {
                            throw new ArgumentException($"EC JWK must contain a valid '{JwkProperties.X}' field.", nameof(jwk));
                        }
                        if(!jwk.ContainsKey(JwkProperties.Y) || jwk[JwkProperties.Y] is not string)
                        {
                            throw new ArgumentException($"EC JWK must contain a valid '{JwkProperties.Y}' field.", nameof(jwk));
                        }
                        break;

                    case string key when WellKnownKeyTypeValues.IsOkp(key):
                        //OKP keys require 'x' coordinate.
                        if(!jwk.ContainsKey(JwkProperties.X) || jwk[JwkProperties.X] is not string)
                        {
                            throw new ArgumentException($"OKP JWK must contain a valid '{JwkProperties.X}' field.", nameof(jwk));
                        }
                        break;

                    case string key when WellKnownKeyTypeValues.IsRsa(key):
                        //RSA keys require 'n' (modulus) and 'e' (exponent).
                        if(!jwk.ContainsKey(JwkProperties.N) || jwk[JwkProperties.N] is not string)
                        {
                            throw new ArgumentException($"RSA JWK must contain a valid '{JwkProperties.N}' field.", nameof(jwk));
                        }
                        if(!jwk.ContainsKey(JwkProperties.E) || jwk[JwkProperties.E] is not string)
                        {
                            throw new ArgumentException($"RSA JWK must contain a valid '{JwkProperties.E}' field.", nameof(jwk));
                        }
                        break;

                    default:
                        throw new ArgumentException($"Unsupported key type: '{keyType}'.");
                }
            }

            static byte[] DecodeKeyMaterial(Dictionary<string, object> jwk, string keyType, DecodeDelegate decoder)
            {
                return keyType switch
                {
                    string key when WellKnownKeyTypeValues.IsEc(key) => DecodeEcKey(jwk, decoder),
                    string key when WellKnownKeyTypeValues.IsOkp(key) => DecodeOkpKey(jwk, decoder),
                    string key when WellKnownKeyTypeValues.IsRsa(key) => DecodeRsaKey(jwk, decoder),
                    _ => throw new ArgumentException($"Unsupported key type: '{keyType}'.")
                };
            }

            static byte[] DecodeEcKey(Dictionary<string, object> jwk, DecodeDelegate decoder)
            {
                //Fields already validated by ValidateRequiredFields.
                using var xBytes = DecodeForJwk((string)jwk[JwkProperties.X], decoder);
                using var yBytes = DecodeForJwk((string)jwk[JwkProperties.Y], decoder);

                return EllipticCurveUtilities.Compress(xBytes.Memory.Span, yBytes.Memory.Span);
            }

            static byte[] DecodeOkpKey(Dictionary<string, object> jwk, DecodeDelegate decoder)
            {
                //Fields already validated by ValidateRequiredFields.
                using var decoded = DecodeForJwk((string)jwk[JwkProperties.X], decoder);
                return decoded.Memory.Span.ToArray();
            }

            static byte[] DecodeRsaKey(Dictionary<string, object> jwk, DecodeDelegate decoder)
            {
                //Fields already validated by ValidateRequiredFields.
                //Return only the modulus for now.
                using var decoded = DecodeForJwk((string)jwk[JwkProperties.N], decoder);
                return decoded.Memory.Span.ToArray();
            }

            //Helper method to decode JWK data using the provided decoder.
            static IMemoryOwner<byte> DecodeForJwk(string encodedData, DecodeDelegate decoder)
            {
                //For JWK, we don't have codec headers, so pass 0 as header length.
                return decoder(encodedData, SensitiveMemoryPool<byte>.Shared);
            }

            static CryptoAlgorithm DetermineRsaAlgorithm(int keyLength)
            {
                return keyLength switch
                {
                    256 => CryptoAlgorithm.Rsa2048,  //2048 bits = 256 bytes.
                    512 => CryptoAlgorithm.Rsa4096,  //4096 bits = 512 bytes.
                    _ => throw new ArgumentException($"Unsupported RSA key size: '{keyLength}' bytes.")
                };
            }

            static (CryptoAlgorithm, Purpose) MapToAlgorithmAndPurpose(string keyType, string algorithm, int keyMaterialLength)
            {
                return (keyType, algorithm) switch
                {
                    //EC keys.
                    (string kt, string alg) when WellKnownKeyTypeValues.IsEc(kt) && WellKnownJwaValues.IsEs256(alg) => (CryptoAlgorithm.P256, Purpose.Verification),
                    (string kt, string alg) when WellKnownKeyTypeValues.IsEc(kt) && WellKnownJwaValues.IsEs384(alg) => (CryptoAlgorithm.P384, Purpose.Verification),
                    (string kt, string alg) when WellKnownKeyTypeValues.IsEc(kt) && WellKnownJwaValues.IsEs512(alg) => (CryptoAlgorithm.P521, Purpose.Verification),
                    (string kt, string alg) when WellKnownKeyTypeValues.IsEc(kt) && WellKnownJwaValues.IsEs256k1(alg) => (CryptoAlgorithm.Secp256k1, Purpose.Verification),

                    //OKP keys.
                    (string kt, string alg) when WellKnownKeyTypeValues.IsOkp(kt) && WellKnownJwaValues.IsEdDsa(alg) => (CryptoAlgorithm.Ed25519, Purpose.Verification),
                    (string kt, string alg) when WellKnownKeyTypeValues.IsOkp(kt) && WellKnownJwaValues.IsEcdha(alg) => (CryptoAlgorithm.X25519, Purpose.Exchange),

                    //RSA keys - determine algorithm based on key size if no algorithm specified.
                    (string kt, _) when WellKnownKeyTypeValues.IsRsa(kt) => (DetermineRsaAlgorithm(keyMaterialLength), Purpose.Verification),

                    _ => throw new ArgumentException($"Unsupported key type or algorithm: '{keyType}', '{algorithm}'.")
                };
            }
        };


        public static Base58ToAlgorithmDelegate DefaultBase58ToAlgorithmConverter => (base58Key, memoryPool, base58Decoder) =>
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

            //Determine codec header length based on the detected header type.
            int codecHeaderLength = Base58BtcEncodedMulticodecHeaders.GetMulticodecHeaderLength(header);
            var decodedKeyMaterialWithoutHeader = MultibaseSerializer.Decode(base58Key, codecHeaderLength, base58Decoder, memoryPool);
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
                        memoryPool,
                        DefaultCoderSelector.SelectDecoder(jwkKey.GetType())),

                _ => throw new ArgumentException($"Unsupported KeyFormat for VerificationMethod of Type '{method.Type}'.", nameof(method))
            };
        };
    }
}