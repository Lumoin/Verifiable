using System;
using System.Collections.Generic;
using Verifiable.Core;
using Verifiable.Core.Cryptography;
using Verifiable.Core.Cryptography.Context;
using Verifiable.Core.Did;
using Verifiable.Jwt;
using Xunit;

namespace Verifiable.Tests.TestDataProviders
{
    public record DidKeyTestData(
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> KeyPair,        
        CryptoSuite CryptoSuite,
        Type ExpectedKeyFormat)
    {

        public override string ToString()
        {            
            return $"Algorithm: {((CryptoAlgorithm)KeyPair.PublicKey.Tag[typeof(CryptoAlgorithm)]).Algorithm} CryptoSuite: {CryptoSuite.CryptoSuiteId}, ExpectedKeyFormat: {ExpectedKeyFormat.Name}";
        }
    }

    public delegate bool KeyFormatValidatorDelegate(KeyFormat keyFormat, CryptoAlgorithm alg);


    public class KeyFormatValidator
    {
        private List<(Type Type, KeyFormatValidatorDelegate Validator)> Validators { get; } = new();


        public void AddValidator(Type type, KeyFormatValidatorDelegate validator)
        {
            Validators.Add((type, validator));
        }


        public bool Validate(KeyFormat keyFormat, CryptoAlgorithm alg)
        {
            foreach((Type type, KeyFormatValidatorDelegate validator) in Validators)
            {
                if(keyFormat.GetType() == type)
                {
                    return validator(keyFormat, alg);
                }
            }

            return false;
        }
    }


    /// <summary>
    /// <para>These validators are primarily designed for testing scenarios where the expected key material is known a priori. 
    /// They ensure that the key format and its internal attributes, such as the cryptographic algorithm, 
    /// are aligned with what was intended by the DID method builder.</para>
    /// 
    /// <para>In a production environment, it's common to only validate against available input, 
    /// such as the 'publicKeyJwk' tag, to confirm its internal consistency (e.g., if it declares itself as EC P-256, 
    /// then it should adhere to the EC P-256 specifications). However, without knowing the original parameters 
    /// provided to the builder, one cannot confirm that the key material was generated as intended.</para>
    /// 
    /// <para>These validators serve to bridge that gap in testing by double-checking that the generated key material 
    /// conforms to the original builder parameters.</para>
    /// </summary>
    public static class TestOnlyKeyFormatValidators
    {
        public static bool KeyDidJwkValidator(KeyFormat keyFormatInTest, CryptoAlgorithm algorithmInTest)
        {
            static bool ValidateEcKeyFormatContentsMatchesRequested(PublicKeyJwk actualKeyFormat, Func<string, bool> curveValidator, Func<string, bool> algValidator)
            {
                return WellKnownKeyTypeValues.IsEc((string)actualKeyFormat.Header[JwkProperties.Kty])
                    && curveValidator((string)actualKeyFormat.Header[JwkProperties.Crv])
                    && algValidator((string)actualKeyFormat.Header[JwkProperties.Alg]);
            }

            static bool ValidateRsaKeyFormatContentsMatchesRequested(PublicKeyJwk actualKeyFormat, CryptoAlgorithm alg)
            {
                //TODO: Constants for RSA key lengths...
                const int Rsa2048DerEncodedBase64UrlEncodedLength = 360;
                const int Rsa4096DerEncodedBase64UrlEncodedLength = 702;

                return WellKnownKeyTypeValues.IsRsa((string)actualKeyFormat.Header[JwkProperties.Kty])
                    && ((string)actualKeyFormat.Header[JwkProperties.E]).Equals(RsaUtilities.DefaultExponent, StringComparison.OrdinalIgnoreCase)
                    && (alg == CryptoAlgorithm.Rsa2048 && actualKeyFormat.Header[JwkProperties.N] is string { Length: Rsa2048DerEncodedBase64UrlEncodedLength }
                        || alg == CryptoAlgorithm.Rsa4096 && actualKeyFormat.Header[JwkProperties.N] is string { Length: Rsa4096DerEncodedBase64UrlEncodedLength });
            }

            static bool ValidateEd25519KeyFormatContentsMatchesRequested(PublicKeyJwk actualKeyFormat)
            {
                return WellKnownKeyTypeValues.IsOkp((string)actualKeyFormat.Header[JwkProperties.Kty])
                    && WellKnownCurveValues.IsEd25519((string)actualKeyFormat.Header[JwkProperties.Crv]);
            }

            static bool ValidateX25519KeyFormatContentsMatchesRequested(PublicKeyJwk actualKeyFormat)
            {
                return WellKnownKeyTypeValues.IsOkp((string)actualKeyFormat.Header[JwkProperties.Kty])
                    && WellKnownCurveValues.IsX25519((string)actualKeyFormat.Header[JwkProperties.Crv]);
            }

            return keyFormatInTest switch
            {
                PublicKeyJwk actualKeyFormat => algorithmInTest switch
                {
                    var a when a == CryptoAlgorithm.P256 => ValidateEcKeyFormatContentsMatchesRequested(actualKeyFormat, WellKnownCurveValues.IsP256, WellKnownJwaValues.IsEs256),
                    var a when a == CryptoAlgorithm.P384 => ValidateEcKeyFormatContentsMatchesRequested(actualKeyFormat, WellKnownCurveValues.IsP384, WellKnownJwaValues.IsEs384),
                    var a when a == CryptoAlgorithm.P521 => ValidateEcKeyFormatContentsMatchesRequested(actualKeyFormat, WellKnownCurveValues.IsP521, WellKnownJwaValues.IsEs512),
                    var a when a == CryptoAlgorithm.Secp256k1 => ValidateEcKeyFormatContentsMatchesRequested(actualKeyFormat, WellKnownCurveValues.IsSecp256k1, WellKnownJwaValues.IsEs256k1),
                    var a when a == CryptoAlgorithm.Rsa2048 => ValidateRsaKeyFormatContentsMatchesRequested(actualKeyFormat, a),
                    var a when a == CryptoAlgorithm.Rsa4096 => ValidateRsaKeyFormatContentsMatchesRequested(actualKeyFormat, a),
                    var a when a == CryptoAlgorithm.Ed25519 => ValidateEd25519KeyFormatContentsMatchesRequested(actualKeyFormat),
                    var a when a == CryptoAlgorithm.X25519 => ValidateX25519KeyFormatContentsMatchesRequested(actualKeyFormat),
                    _ => false
                },
                _ => false
            };
        }


        public static bool KeyDidMultibaseValidator(KeyFormat keyFormatInTest, CryptoAlgorithm algorithmInTest)
        {
            if(keyFormatInTest is PublicKeyMultibase actualKeyFormat)
            {
                string prefix = algorithmInTest switch
                {
                    var a when a == CryptoAlgorithm.P256 => Base58BtcEncodedMulticodecHeaders.P256PublicKey.ToString(),
                    var a when a == CryptoAlgorithm.P384 => Base58BtcEncodedMulticodecHeaders.P384PublicKey.ToString(),
                    var a when a == CryptoAlgorithm.P521 => Base58BtcEncodedMulticodecHeaders.P521PublicKey.ToString(),
                    var a when a == CryptoAlgorithm.Secp256k1 => Base58BtcEncodedMulticodecHeaders.Secp256k1PublicKey.ToString(),
                    var a when a == CryptoAlgorithm.Rsa2048 => Base58BtcEncodedMulticodecHeaders.RsaPublicKey2048.ToString(),
                    var a when a == CryptoAlgorithm.Rsa4096 => Base58BtcEncodedMulticodecHeaders.RsaPublicKey4096.ToString(),
                    var a when a == CryptoAlgorithm.Ed25519 => Base58BtcEncodedMulticodecHeaders.Ed25519PublicKey.ToString(),
                    var a when a == CryptoAlgorithm.X25519 => Base58BtcEncodedMulticodecHeaders.X25519PublicKey.ToString(),
                    _ => string.Empty
                };

                return actualKeyFormat.Key.StartsWith(prefix, StringComparison.OrdinalIgnoreCase);
            }

            return false;
        }
    }


    public class DidKeyTheoryData: TheoryData<DidKeyTestData>
    {
        public DidKeyTheoryData()
        {                        
            void AddTestData(PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyPair)
            {                
                Add(new DidKeyTestData(keyPair, JsonWebKey2020.DefaultInstance, typeof(PublicKeyJwk)));
                Add(new DidKeyTestData(keyPair, Multikey.DefaultInstance, typeof(PublicKeyMultibase)));
            }

            AddTestData(TestKeyMaterialProvider.P256KeyMaterial);
            AddTestData(TestKeyMaterialProvider.P384KeyMaterial);
            AddTestData(TestKeyMaterialProvider.P521KeyMaterial);
            AddTestData(TestKeyMaterialProvider.Secp256k1KeyMaterial);
            AddTestData(TestKeyMaterialProvider.Rsa2048KeyMaterial);
            AddTestData(TestKeyMaterialProvider.Rsa4096KeyMaterial);
            AddTestData(TestKeyMaterialProvider.Ed25519KeyMaterial);
            AddTestData(TestKeyMaterialProvider.X25519KeyMaterial);
        }
    }
}
