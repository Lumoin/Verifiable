using System.Collections.Frozen;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Verifiable.BouncyCastle;
using Verifiable.Jwt;
using Verifiable.Tests.DataProviders;

namespace Verifiable.Tests.Jwt
{
    /// <summary>
    /// These are JWT tests that use predefined data from services such as  https://jwt.io/.
    /// The purpose of these tests is to cross-check this JWT implementation for
    /// compatibility with other implementations.
    /// </summary>
    [TestClass]
    public sealed class JwtTestsWithPredefinedData
    {
        [TestMethod]
        [DynamicData(nameof(JwtTestDataProvider.GetHsTestData), typeof(JwtTestDataProvider), DynamicDataSourceType.Method)]
        public async Task HsJwtTokenEncodingSigningAndVerifyingSucceeds(HsTestData testData)
        {
            string signedJwt = JwtExtensions.SignJwt(
                serializer: section => { return Encoding.UTF8.GetBytes(JsonSerializer.Serialize(section)); },
                base64UrlEncoder: Base64Url.Encode,
                header: testData.Header,
                payload: testData.Payload,
                keyIdentifierSelector: header => { return Encoding.UTF8.GetBytes(testData.PrivateKey); },
                contextLoader: (header, KeyIdentifier) =>
                {
                    return new CryptoContext
                    {
                        Parameters = testData.Header,
                        Key = Encoding.UTF8.GetBytes(testData.PrivateKey)
                    };
                },
                signingFunctionMatcher: DefaultVerifierSelector.JwtDefaultSigner);

            var isSignatureValid = await JwtExtensions.VerifyCompactSignature(
                jwtDataWithSignature: signedJwt,
                base64UrlDecoder: Base64Url.Decode,
                partDecoder: section =>
                {
                    //The validation rules at https://www.rfc-editor.org/rfc/rfc7519#section-7.2.
                    //If this were encrypted, there would be five parts in the split and more processing.
                    //So "to be be certain" more delegates would be needed as parameters.
                    //See https://www.scottbrady91.com/jose/json-web-encryption.
                    var part = Encoding.UTF8.GetString(section);

                    var converter = new DictionaryStringObjectJsonConverter();
                    return JsonSerializer.Deserialize<Dictionary<string, object>>(part, new JsonSerializerOptions { Converters = { converter } })!;
                },
                keyIdentifierSelector: header =>
                {
                    //Uses the previously decoded header and payload to load the right key material.
                    //SO! Not from the jwtTestData like here. In fact, this test should use a facility
                    //where the key data is used!
                    string thisISReallyAKidOrSomethingToChooseTheKeyToLoad = (string)header[JwkProperties.Alg];
                    return thisISReallyAKidOrSomethingToChooseTheKeyToLoad;
                },
                contextLoader: (header, keyIdentifier) =>
                {
                    return new CryptoContext { Key = Encoding.UTF8.GetBytes(testData.PrivateKey) };
                },
                DefaultVerifierSelector.MicrosoftJwtDefaultMatcher,
                verificationFunction: (keyIdentifierSelector, contextLoader, jwaAlgorithm, dataToVerify, signature, header, payload) =>
                {
                    //Here signature should be checked before the whole JWT is converted.
                    string alg = (string)header[JwkProperties.Alg];
                    string keyIdentifier = keyIdentifierSelector(header);
                    CryptoContext context = contextLoader(header, keyIdentifier);

                    bool result = false;
                    if(WellKnownJwaValues.IsHs256(alg))
                    {
                        result = MicrosoftCryptographicFunctions.VerifyHs256(context.Key, dataToVerify, signature);
                    }
                    else if(WellKnownJwaValues.IsHs384(alg))
                    {
                        result = MicrosoftCryptographicFunctions.VerifyHs384(context.Key, dataToVerify, signature);
                    }
                    else if(WellKnownJwaValues.IsHs512(alg))
                    {
                        result = MicrosoftCryptographicFunctions.VerifyHs512(context.Key, dataToVerify, signature);
                    }
                    else
                    {
                        throw new Exception("HSxx");
                    }

                    return ValueTask.FromResult(result);
                });

            //There is no random components, so all values should match
            //with the given test values.
            Assert.IsTrue(isSignatureValid);
            Assert.AreEqual(testData.CrossCheckJwt.Split('.')[0], signedJwt.Split('.')[0]);
            Assert.AreEqual(testData.CrossCheckJwt.Split('.')[1], signedJwt.Split('.')[1]);
            Assert.AreEqual(testData.CrossCheckJwt.Split('.')[2], signedJwt.Split('.')[2]);
            Assert.AreEqual(testData.CrossCheckJwt, signedJwt);
        }


        [TestMethod]
        [DynamicData(nameof(JwtTestDataProvider.GetESTestData), typeof(JwtTestDataProvider), DynamicDataSourceType.Method)]
        public async Task ESJwtTokenEncodingSigningAndVerifyingSucceeds(ESTestData jwtTestData)
        {
            string signedJwt = JwtExtensions.SignJwt(
                serializer: section => { return Encoding.UTF8.GetBytes(JsonSerializer.Serialize(section)); },
                base64UrlEncoder: Base64Url.Encode,
                header: jwtTestData.Header,
                payload: jwtTestData.Payload,
                keyIdentifierSelector: header => { return Encoding.UTF8.GetBytes(jwtTestData.PrivateKeyInPem); },
                contextLoader: (header, KeyIdentifier) =>
                {
                    static ReadOnlySpan<byte> GetPrivateKeyBytes(ESTestData jwtTestData)
                    {
                        var key = ECDsa.Create();
                        key.ImportFromPem(jwtTestData.PrivateKeyInPem);
                        return key.ExportParameters(includePrivateParameters: true).D;
                    };

                    return new CryptoContext
                    {
                        Parameters = jwtTestData.Header,
                        Key = GetPrivateKeyBytes(jwtTestData).ToArray()
                    };
                },
                signingFunctionMatcher: DefaultVerifierSelector.JwtDefaultSigner);

            var isSignatureValid = await JwtExtensions.VerifyCompactSignature(
                jwtDataWithSignature: signedJwt,
                base64UrlDecoder: Base64Url.Decode,
                partDecoder: section =>
                {
                    //The validation rules at https://www.rfc-editor.org/rfc/rfc7519#section-7.2.
                    //If this were encrypted, there would be five parts in the split and more processing.
                    //So "to be be certain" more delegates would be needed as parameters.
                    //See https://www.scottbrady91.com/jose/json-web-encryption.
                    var part = Encoding.UTF8.GetString(section);

                    var converter = new DictionaryStringObjectJsonConverter();
                    return JsonSerializer.Deserialize<Dictionary<string, object>>(part, new JsonSerializerOptions { Converters = { converter } })!;
                },
                keyIdentifierSelector: header =>
                {
                    //Uses the previously decoded header and payload to load to construct the information
                    //on how to identify the key material.
                    string thisISReallyAKidOrSomethingToChooseTheKeyToLoad = (string)header[JwkProperties.Alg];
                    return new CryptoContext
                    {
                        KeyIdentifier = thisISReallyAKidOrSomethingToChooseTheKeyToLoad
                    };
                },
                contextLoader: (header, context) =>
                {
                    var alg = (string)header[JwkProperties.Alg];
                    context.Algorithm = alg;
                    context.Parameters["alg"] = alg;
                    context.Parameters["kty"] = "EC";
                    var key = ECDsa.Create();
                    key.ImportFromPem(jwtTestData.PublicKeyInPem);

                    context.Key = key.ExportSubjectPublicKeyInfo();
                    return context;
                },
                DefaultVerifierSelector.MicrosoftJwtDefaultMatcher,
                verificationFunction: (keyIdentifierSelector, contextLoader, jwtAlgorithm, dataToVerify, signature, header, payload) =>
                {
                    CryptoContext keyIdentifier = keyIdentifierSelector(header);
                    CryptoContext context = contextLoader(header, keyIdentifier);
                    var verifier = jwtAlgorithm(context);

                    return ValueTask.FromResult(verifier(dataToVerify, signature, context.Key));
                });

            Assert.IsTrue(isSignatureValid);

            //The signature varies since it has a random component.
            Assert.AreEqual(jwtTestData.CrossCheckJwt.Split('.')[0], signedJwt.Split('.')[0]);
            Assert.AreEqual(jwtTestData.CrossCheckJwt.Split('.')[1], signedJwt.Split('.')[1]);
        }


        [TestMethod]
        [DynamicData(nameof(JwtTestDataProvider.GetRsaRsTestData), typeof(JwtTestDataProvider), DynamicDataSourceType.Method)]
        public async Task RsaRsJwtTokenEncodingSigningAndVerifyingSucceeds(RsaRSTestData testData)
        {
            string signedJwt = JwtExtensions.SignJwt(
                section => { return Encoding.UTF8.GetBytes(JsonSerializer.Serialize(section)); },
                Base64Url.Encode,
                testData.Header,
                testData.Payload,
                keyIdentifierSelector: header => { return Encoding.UTF8.GetBytes(testData.PrivateKeyInPem); },
                contextLoader: (header, KeyIdentifier) =>
                {
                    static ReadOnlySpan<byte> GetPrivateKeyBytes(RsaRSTestData jwtTestData)
                    {
                        var key = RSA.Create();
                        key.ImportFromPem(jwtTestData.PrivateKeyInPem);

                        return key.ExportPkcs8PrivateKey();
                    };

                    return new CryptoContext
                    {
                        Parameters = testData.Header,
                        Key = GetPrivateKeyBytes(testData).ToArray()
                    };
                },
                signingFunctionMatcher: DefaultVerifierSelector.JwtDefaultSigner);

            var isSignatureValid = await JwtExtensions.VerifyCompactSignature(
                jwtDataWithSignature: signedJwt,
                base64UrlDecoder: Base64Url.Decode,
                partDecoder: section =>
                {
                    //The validation rules at https://www.rfc-editor.org/rfc/rfc7519#section-7.2.
                    //If this were encrypted, there would be five parts in the split and more processing.
                    var part = Encoding.UTF8.GetString(section);

                    var converter = new DictionaryStringObjectJsonConverter();
                    return JsonSerializer.Deserialize<Dictionary<string, object>>(part, new JsonSerializerOptions { Converters = { converter } })!;
                },
                keyIdentifierSelector: header =>
                {
                    //Uses the previously decoded header and payload to load the right key material.
                    //SO! Not from the jwtTestData like here. In fact, this test should use a facility
                    //where the key data is used!
                    var h = header[JwkProperties.Alg];
                    string thisISReallyAKidOrSomethingToChooseTheKeyToLoad = (string)header[JwkProperties.Alg];
                    return thisISReallyAKidOrSomethingToChooseTheKeyToLoad;
                },
                contextLoader: (header, keyHandle) =>
                {
                    var key = RSA.Create();
                    key.ImportFromPem(testData.PrivateKeyInPem);

                    return new CryptoContext { Key = key.ExportSubjectPublicKeyInfo() };
                },
                DefaultVerifierSelector.MicrosoftJwtDefaultMatcher,
                verificationFunction: (keyIdentifierSelector, keyLoadingFunction, jwaAlgorithm, dataToVerify, signature, header, payload) =>
                {
                    string keyIdentifier = keyIdentifierSelector(header);
                    CryptoContext context = keyLoadingFunction(header, keyIdentifier);
                    using(var key = RSA.Create())
                    {
                        key.ImportSubjectPublicKeyInfo(context.Key, out _);

                        HashAlgorithmName hashAlgorithm = HashAlgorithmName.SHA256;
                        var alg = (string)testData.Header[JwkProperties.Alg];
                        if(WellKnownJwaValues.IsRs256(alg))
                        {
                            hashAlgorithm = HashAlgorithmName.SHA256;
                        }

                        if(WellKnownJwaValues.IsRs384(alg))
                        {
                            hashAlgorithm = HashAlgorithmName.SHA384;
                        }

                        if(WellKnownJwaValues.IsRs512(alg))
                        {
                            hashAlgorithm = HashAlgorithmName.SHA512;
                        }

                        return ValueTask.FromResult(key.VerifyData(dataToVerify, signature, hashAlgorithm, RSASignaturePadding.Pkcs1));
                    }
                });

            Assert.IsTrue(isSignatureValid);
            Assert.AreEqual(testData.CrossCheckJwt.Split('.')[0], signedJwt.Split('.')[0]);
            Assert.AreEqual(testData.CrossCheckJwt.Split('.')[1], signedJwt.Split('.')[1]);
            Assert.AreEqual(testData.CrossCheckJwt.Split('.')[2], signedJwt.Split('.')[2]);
            Assert.AreEqual(testData.CrossCheckJwt, signedJwt);
        }


        [TestMethod]
        [DynamicData(nameof(JwtTestDataProvider.GetRsaPsTestData), typeof(JwtTestDataProvider), DynamicDataSourceType.Method)]
        public async Task RsaPSJwtTokenEncodingSigningAndVerifyingSucceeds(RsaPSTestData testData)
        {
            string signedJwt = JwtExtensions.SignJwt(
                section => { return Encoding.UTF8.GetBytes(JsonSerializer.Serialize(section)); },
                Base64Url.Encode,
                testData.Header,
                testData.Payload,
                keyIdentifierSelector: header => { return Encoding.UTF8.GetBytes(testData.PrivateKeyInPem); },
                contextLoader: (header, KeyIdentifier) =>
                {
                    static ReadOnlySpan<byte> GetPrivateKeyBytes(RsaPSTestData jwtTestData)
                    {
                        using(var key = RSA.Create())
                        {
                            key.ImportFromPem(jwtTestData.PrivateKeyInPem);
                            return key.ExportPkcs8PrivateKey();
                        }
                    };

                    return new CryptoContext
                    {
                        Parameters = testData.Header,
                        Key = GetPrivateKeyBytes(testData).ToArray()
                    };
                },
                signingFunctionMatcher: DefaultVerifierSelector.JwtDefaultSigner);

            var isSignatureValid = await JwtExtensions.VerifyCompactSignature(
                jwtDataWithSignature: signedJwt,
                base64UrlDecoder: Base64Url.Decode,
                partDecoder: section =>
            {
                //The validation rules at https://www.rfc-editor.org/rfc/rfc7519#section-7.2.
                //If this were encrypted, there would be five parts in the split and more processing.
                //So "to be be certain" more delegates would be needed as parameters.
                //See https://www.scottbrady91.com/jose/json-web-encryption.
                var part = Encoding.UTF8.GetString(section);

                var converter = new DictionaryStringObjectJsonConverter();
                return JsonSerializer.Deserialize<Dictionary<string, object>>(part, new JsonSerializerOptions { Converters = { converter } })!;
            },
            keyIdentifierSelector: header =>
            {
                //KeyIdentifierSelector<Dictionary<string, object>, string> keyIdentifierSelector = header => (string)header[JwkProperties.Kid];

                //Uses the previously decoded header and payload to load the right key material.
                //SO! Not from the jwtTestData like here. In fact, this test should use a facility
                //where the key data is used!
                var h = header[JwkProperties.Alg];
                string thisISReallyAKidOrSomethingToChooseTheKeyToLoad = (string)header[JwkProperties.Alg];
                return thisISReallyAKidOrSomethingToChooseTheKeyToLoad;
            },
            contextLoader: (header, keyHandle) =>
            {
                var key = RSA.Create();
                key.ImportFromPem(testData.PrivateKeyInPem);

                return new CryptoContext { Key = key.ExportSubjectPublicKeyInfo() };
            },
            DefaultVerifierSelector.MicrosoftJwtDefaultMatcher,
            verificationFunction: (keyIdentifierSelector, keyLoadingFunction, jwaAlgorithm, dataToVerify, signature, header, payload) =>
            {
                string keyIdentifier = keyIdentifierSelector(header);
                CryptoContext context = keyLoadingFunction(header, keyIdentifier);
                using(var key = RSA.Create())
                {
                    key.ImportSubjectPublicKeyInfo(context.Key, out _);
                    {
                        HashAlgorithmName hashAlgorithm = HashAlgorithmName.SHA256;
                        string alg = (string)testData.Header[JwkProperties.Alg];
                        if(WellKnownJwaValues.IsPs256(alg))
                        {
                            hashAlgorithm = HashAlgorithmName.SHA256;
                        }

                        if(WellKnownJwaValues.IsPs384(alg))
                        {
                            hashAlgorithm = HashAlgorithmName.SHA384;
                        }

                        if(WellKnownJwaValues.IsPs512(alg))
                        {
                            hashAlgorithm = HashAlgorithmName.SHA512;
                        }

                        return ValueTask.FromResult(key.VerifyData(dataToVerify, signature, hashAlgorithm, RSASignaturePadding.Pss));
                    }
                }
            });

            //The signature varies since it has a random component. Consequently
            //the signature value cannot be compared byte-by-byte.
            Assert.IsTrue(isSignatureValid);
            Assert.AreEqual(testData.CrossCheckJwt.Split('.')[0], signedJwt.Split('.')[0]);
            Assert.AreEqual(testData.CrossCheckJwt.Split('.')[1], signedJwt.Split('.')[1]);
        }


        [TestMethod]
        [DynamicData(nameof(JwtTestDataProvider.GetMixedJwtTestData), typeof(JwtTestDataProvider), DynamicDataSourceType.Method)]
        public void MixedJwtTokenEncodingSigningAndVerifyingSucceeds(BaseJwtTestData testData)
        {
            string signedJwt = JwtExtensions.SignJwt(
               serializer: section => { return Encoding.UTF8.GetBytes(JsonSerializer.Serialize(section)); },
               base64UrlEncoder: Base64Url.Encode,
               header: testData.Header,
               payload: testData.Payload,
               keyIdentifierSelector: header => { return Encoding.UTF8.GetBytes(testData.PrivateKey); },
               contextLoader: (header, KeyIdentifier) =>
               {
                   return new CryptoContext
                   {
                       Parameters = testData.Header,
                       Key = Encoding.UTF8.GetBytes(testData.PrivateKey)
                   };
               },
               signingFunctionMatcher: DefaultVerifierSelector.JwtDefaultSigner);

            Assert.AreEqual(testData.CrossCheckJwt, signedJwt);
        }
    }


    public static class DefaultVerifierSelector
    {
        private static VerifyImplementation<byte> WrapAsync(Func<ReadOnlySpan<byte>, ReadOnlySpan<byte>, ReadOnlySpan<byte>, FrozenDictionary<string, object>?, ValueTask<bool>> asyncMethod)
        {
            return (dataToVerify, signature, publicKeyMaterial) => asyncMethod(dataToVerify, signature, publicKeyMaterial, null).Result;
        }


        public static VerifyImplementationMatcher<CryptoContext, byte> JwtDefaultMatcher => context =>
        {
            string kty = (string)context.Parameters["kty"];
            string alg = (string)context.Parameters["alg"];
            VerifyImplementation<byte> operation = (kty, alg) switch
            {
                (null, "ES256") or ("", "ES256") or ("EC", "ES256") => WrapAsync(BouncyCastleCryptographicFunctions.VerifyP256Async),
                (null, "ES384") or ("", "ES384") or ("EC", "ES384") => WrapAsync(BouncyCastleCryptographicFunctions.VerifyP384Async),
                (null, "ES512") or ("", "ES512") or ("EC", "ES512") => WrapAsync(BouncyCastleCryptographicFunctions.VerifyP521Async),
                (null, "ES256K") or ("", "ES256K") or ("EC", "ES256K") => WrapAsync(BouncyCastleCryptographicFunctions.VerifySecp256k1Async),
                (null, "EdDSA") or ("", "EdDSA") or ("OKP", "EdDSA") => WrapAsync(BouncyCastleCryptographicFunctions.VerifyEd25519Async),

                //Default delegate always returns false for unsupported combinations.
                _ => (dataToVerify, signature, publicKeyMaterial) => false
            };

            return operation;
        };


        public static VerifyImplementationMatcher<CryptoContext, byte> MicrosoftJwtDefaultMatcher => context =>
        {
            string kty = (string)context.Parameters["kty"];
            string alg = (string)context.Parameters["alg"];
            VerifyImplementation<byte> operation = (kty, alg) switch
            {
                (null, "ES256") or ("", "ES256") or ("EC", "ES256") => MicrosoftCryptographicFunctions.VerifyP256,
                (null, "ES384") or ("", "ES384") or ("EC", "ES384") => MicrosoftCryptographicFunctions.VerifyP384,
                (null, "ES512") or ("", "ES512") or ("EC", "ES512") => MicrosoftCryptographicFunctions.VerifyP521,
                (null, "ES256K") or ("", "ES256K") or ("EC", "ES256K") => WrapAsync(BouncyCastleCryptographicFunctions.VerifySecp256k1Async),
                (null, "EdDSA") or ("", "EdDSA") or ("OKP", "EdDSA") => WrapAsync(BouncyCastleCryptographicFunctions.VerifyEd25519Async),

                //Default delegate always returns false for unsupported combinations.
                _ => (dataToVerify, signature, publicKeyMaterial) => false
            };

            return operation;
        };


        public static SignImplementationMatcher<CryptoContext, byte> JwtDefaultSigner => context =>
        {
            string alg = (string)context.Parameters[JwkProperties.Alg];
            SignImplementation<byte> operation = alg switch
            {
                "HS256" => MicrosoftCryptographicFunctions.SignHs256,
                "HS384" => MicrosoftCryptographicFunctions.SignHs384,
                "HS512" => MicrosoftCryptographicFunctions.SignHs512,
                "RS256" => MicrosoftCryptographicFunctions.SignRs256,
                "RS384" => MicrosoftCryptographicFunctions.SignRs384,
                "RS512" => MicrosoftCryptographicFunctions.SignRs512,
                "ES256" => MicrosoftCryptographicFunctions.SignP256,
                "ES384" => MicrosoftCryptographicFunctions.SignP384,
                "ES512" => MicrosoftCryptographicFunctions.SignP521,
                "PS256" => MicrosoftCryptographicFunctions.SignPs256,
                "PS384" => MicrosoftCryptographicFunctions.SignPs384,
                "PS512" => MicrosoftCryptographicFunctions.SignPs512,
                _ => throw new NotSupportedException("Unsupported algorithm: " + alg)
            };

            return operation;
        };
    }


    public static class MicrosoftCryptographicFunctions
    {
        public static bool VerifyP256(ReadOnlySpan<byte> dataToVerify, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKeyMaterial)
        {
            HashAlgorithmName hashAlgorithm = HashAlgorithmName.SHA256;
            ECCurve curve = ECCurve.NamedCurves.nistP256;

            return VerifyEcdsa(dataToVerify, signature, publicKeyMaterial, hashAlgorithm, curve);
        }


        public static bool VerifyP384(ReadOnlySpan<byte> dataToVerify, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKeyMaterial)
        {
            HashAlgorithmName hashAlgorithm = HashAlgorithmName.SHA384;
            ECCurve curve = ECCurve.NamedCurves.nistP384;

            return VerifyEcdsa(dataToVerify, signature, publicKeyMaterial, hashAlgorithm, curve);
        }


        public static bool VerifyP521(ReadOnlySpan<byte> dataToVerify, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKeyMaterial)
        {
            HashAlgorithmName hashAlgorithm = HashAlgorithmName.SHA512;
            ECCurve curve = ECCurve.NamedCurves.nistP521;

            return VerifyEcdsa(dataToVerify, signature, publicKeyMaterial, hashAlgorithm, curve);
        }

        public static ReadOnlySpan<byte> SignP256(ReadOnlySpan<byte> privateKeyBytes, ReadOnlySpan<byte> dataToSign)
        {
            var key = ECDsa.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                D = privateKeyBytes.ToArray()
            });

            return key.SignData(dataToSign, HashAlgorithmName.SHA256);
        }


        public static ReadOnlySpan<byte> SignP384(ReadOnlySpan<byte> privateKeyBytes, ReadOnlySpan<byte> dataToSign)
        {
            var key = ECDsa.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP384,
                D = privateKeyBytes.ToArray()
            });

            return key.SignData(dataToSign, HashAlgorithmName.SHA384);
        }


        public static ReadOnlySpan<byte> SignP521(ReadOnlySpan<byte> privateKeyBytes, ReadOnlySpan<byte> dataToSign)
        {
            var key = ECDsa.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP521,
                D = privateKeyBytes.ToArray()
            });

            return key.SignData(dataToSign, HashAlgorithmName.SHA512);
        }


        public static ReadOnlySpan<byte> SignHs256(ReadOnlySpan<byte> privateKeyBytes, ReadOnlySpan<byte> dataToSign)
        {
            return HMACSHA256.HashData(privateKeyBytes, dataToSign);
        }


        public static ReadOnlySpan<byte> SignHs384(ReadOnlySpan<byte> privateKeyBytes, ReadOnlySpan<byte> dataToSign)
        {
            return HMACSHA384.HashData(privateKeyBytes, dataToSign);
        }


        public static ReadOnlySpan<byte> SignHs512(ReadOnlySpan<byte> privateKeyBytes, ReadOnlySpan<byte> dataToSign)
        {
            return HMACSHA512.HashData(privateKeyBytes, dataToSign);
        }


        public static ReadOnlySpan<byte> SignRs256(ReadOnlySpan<byte> privateKeyBytes, ReadOnlySpan<byte> dataToSign)
        {
            return SignRsa(privateKeyBytes, dataToSign, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }


        public static ReadOnlySpan<byte> SignRs384(ReadOnlySpan<byte> privateKeyBytes, ReadOnlySpan<byte> dataToSign)
        {
            return SignRsa(privateKeyBytes, dataToSign, HashAlgorithmName.SHA384, RSASignaturePadding.Pkcs1);
        }


        public static ReadOnlySpan<byte> SignRs512(ReadOnlySpan<byte> privateKeyBytes, ReadOnlySpan<byte> dataToSign)
        {
            return SignRsa(privateKeyBytes, dataToSign, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
        }


        public static ReadOnlySpan<byte> SignPs256(ReadOnlySpan<byte> privateKeyBytes, ReadOnlySpan<byte> dataToSign)
        {
            return SignRsa(privateKeyBytes, dataToSign, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        }


        public static ReadOnlySpan<byte> SignPs384(ReadOnlySpan<byte> privateKeyBytes, ReadOnlySpan<byte> dataToSign)
        {
            return SignRsa(privateKeyBytes, dataToSign, HashAlgorithmName.SHA384, RSASignaturePadding.Pss);
        }


        public static ReadOnlySpan<byte> SignPs512(ReadOnlySpan<byte> privateKeyBytes, ReadOnlySpan<byte> dataToSign)
        {
            return SignRsa(privateKeyBytes, dataToSign, HashAlgorithmName.SHA512, RSASignaturePadding.Pss);
        }


        public static bool VerifyHs256(ReadOnlySpan<byte> publicKeyBytes, ReadOnlySpan<byte> dataToSign, ReadOnlySpan<byte> signatureBytesToVerify)
        {
            return signatureBytesToVerify.SequenceEqual(SignHs256(publicKeyBytes, dataToSign));
        }


        public static bool VerifyHs384(ReadOnlySpan<byte> publicKeyBytes, ReadOnlySpan<byte> dataToSign, ReadOnlySpan<byte> signatureBytesToVerify)
        {
            return signatureBytesToVerify.SequenceEqual(SignHs384(publicKeyBytes, dataToSign));
        }


        public static bool VerifyHs512(ReadOnlySpan<byte> publicKeyBytes, ReadOnlySpan<byte> dataToSign, ReadOnlySpan<byte> signatureBytesToVerify)
        {
            return signatureBytesToVerify.SequenceEqual(SignHs512(publicKeyBytes, dataToSign));
        }


        private static ReadOnlySpan<byte> SignRsa(ReadOnlySpan<byte> privateKeyBytes, ReadOnlySpan<byte> dataToSign, HashAlgorithmName hashAlgorithmName, RSASignaturePadding rsaSignaturePadding)
        {
            using(var key = RSA.Create())
            {
                key.ImportPkcs8PrivateKey(privateKeyBytes, out _);
                return key.SignData(dataToSign, hashAlgorithmName, rsaSignaturePadding);
            }
        }


        private static bool VerifyEcdsa(ReadOnlySpan<byte> dataToVerify, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKeyMaterial, HashAlgorithmName hashAlgorithm, ECCurve curve)
        {
            using(var key = ECDsa.Create(curve))
            {
                key.ImportSubjectPublicKeyInfo(publicKeyMaterial, out _);
                return key.VerifyData(dataToVerify, signature, hashAlgorithm);
            }
        }
    }
}
