using Verifiable.BouncyCastle;
using Verifiable.Core.Cryptography;
using Verifiable.Core.Cryptography.Context;

namespace Verifiable.Tests
{
    /*
    public static class CryptographicKeyFactory
    {
        public static PublicKey CreatePublicKey(
            PublicKeyMemory publicKeyMemory,
            string keyIdentifier,
            CryptoAlgorithm algorithm,
            Purpose purpose)
        {
            VerificationFunction<byte, byte, Signature, ValueTask<bool>> verificationFunction = (algorithm, purpose) switch
            {
                var (a, p) when a.Equals(CryptoAlgorithm.Ed25519) && p.Equals(Purpose.Verification) => BouncyCastleAlgorithms.VerifyEd25519Async,
                var (a, p) when a.Equals(CryptoAlgorithm.P256) && p.Equals(Purpose.Verification) => MicrosoftCryptographicFunctions2.VerifyP256Async,
                var (a, p) when a.Equals(CryptoAlgorithm.P384) && p.Equals(Purpose.Verification) => MicrosoftCryptographicFunctions2.VerifyP384Async,
                var (a, p) when a.Equals(CryptoAlgorithm.P521) && p.Equals(Purpose.Verification) => MicrosoftCryptographicFunctions2.VerifyP521Async,
                var (a, p) when a.Equals(CryptoAlgorithm.Rsa2048) && p.Equals(Purpose.Verification) => MicrosoftCryptographicFunctions2.VerifyRsaSha256Pkcs1Async,
                var (a, p) when a.Equals(CryptoAlgorithm.Rsa4096) && p.Equals(Purpose.Verification) => MicrosoftCryptographicFunctions2.VerifyRsaSha512Pkcs1Async,
                var (a, p) when a.Equals(CryptoAlgorithm.Secp256k1) && p.Equals(Purpose.Verification) => MicrosoftCryptographicFunctions2.VerifySecp256k1Async,
                _ => throw new ArgumentException($"Unsupported combination of algorithm and purpose: {algorithm}, {purpose}")
            };

            return new PublicKey(publicKeyMemory, keyIdentifier, verificationFunction);
        }


        public static PrivateKey CreatePrivateKey(
            PrivateKeyMemory privateKeyMemory,
            string keyIdentifier,
            CryptoAlgorithm algorithm,
            Purpose purpose)
        {
            SigningFunction<byte, byte, ValueTask<Signature>> signingFunction = (algorithm, purpose) switch
            {
                var (a, p) when a.Equals(CryptoAlgorithm.Ed25519) && p.Equals(Purpose.Signing) => BouncyCastleAlgorithms.SignEd25519Async,
                //var (a, p) when a.Equals(CryptoAlgorithm.P256) && p.Equals(Purpose.Signing) => MicrosoftCryptographicFunctions2.SignP256Async,
                //var (a, p) when a.Equals(CryptoAlgorithm.P384) && p.Equals(Purpose.Signing) => MicrosoftCryptographicFunctions2.SignP384Async,
                //var (a, p) when a.Equals(CryptoAlgorithm.P521) && p.Equals(Purpose.Signing) => MicrosoftCryptographicFunctions2.SignP521Async,
                //var (a, p) when a.Equals(CryptoAlgorithm.Rsa2048) && p.Equals(Purpose.Signature) => MicrosoftCryptographicFunctions2.Rsa,
                //var (a, p) when a.Equals(CryptoAlgorithm.Rsa4096) && p.Equals(Purpose.Signature) => throw new NotImplementedException("RSA4096 signing not implemented."),
                //var (a, p) when a.Equals(CryptoAlgorithm.Secp256k1) && p.Equals(Purpose.Signature) => MicrosoftCryptographicFunctions2.SignSecp256k1Async,
                _ => throw new ArgumentException($"Unsupported combination of algorithm and purpose: {algorithm}, {purpose}")
            };

            return new PrivateKey(privateKeyMemory, keyIdentifier, signingFunction);
        }
    }*/
}
