using System;
using System.Security.Cryptography;
using System.Threading;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Microsoft;

namespace Verifiable;

/// <summary>
/// Registers a cryptographic provider for the CLI at startup. This is the single,
/// reusable wiring step that backs every provider-dependent command — the CBOM
/// <c>--observe</c> workload today and the future <c>did</c> / <c>vc</c> commands.
/// </summary>
/// <remarks>
/// <para>
/// The CLI wires the <c>Verifiable.Microsoft</c> backend because it is built entirely on
/// <c>System.Security.Cryptography</c> and stays AOT/trim-clean, which the CLI requires
/// (the whole-solution build runs the trim and AOT analyzers with warnings treated as
/// errors). Signing and verification register through
/// <see cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}"/>; entropy, salt,
/// and digest register through <see cref="CryptographicKeyFactory"/>. The set wired here
/// is the subset the AOT-clean Microsoft backend supports natively
/// (ECDSA P-256/384/521 signing and verification, RSA-2048/4096 verification and the six
/// RSA padding/hash family verifications — PKCS#1 v1.5 and PSS at SHA-256/384/512 — plus
/// CSPRNG entropy and SHA-2 digests). EdDSA verification is deferred until an Ed25519 backend
/// (<c>Verifiable.NSec</c> or <c>Verifiable.BouncyCastle</c>) is referenced from this project.
/// secp256k1 (ES256K, RFC 8812 §3) is deferred for the same reason: the CLI wires only the
/// AOT-clean Microsoft backend, and this project does not reference
/// <c>Verifiable.BouncyCastle</c>, which secp256k1 needs for key material and signing.
/// </para>
/// </remarks>
internal static class CryptoProviderStartup
{
    /// <summary>
    /// Guards <see cref="EnsureRegistered"/> so the registry initializes exactly once per process;
    /// <c>0</c> before registration, <c>1</c> after.
    /// </summary>
    private static int isRegistered;


    /// <summary>
    /// Registers the cryptographic provider exactly once per process. Subsequent calls are
    /// no-ops, so any number of commands may call this without re-initializing the registry.
    /// </summary>
    public static void EnsureRegistered()
    {
        if(Interlocked.CompareExchange(ref isRegistered, 1, 0) != 0)
        {
            return;
        }

        RegisterSigningAndVerification();
        RegisterEntropyAndDigest();
        RegisterKeyCreation();
    }


    /// <summary>
    /// Initializes <see cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}"/> with the
    /// <c>Verifiable.Microsoft</c> signing and verification functions this CLI supports: ECDSA
    /// P-256/384/521 signing and verification, plus RSA-2048/4096 verification and the six
    /// alg-resolved RSA padding/hash family verifications (RSASSA-PKCS1-v1.5 and RSASSA-PSS at
    /// SHA-256/384/512, RFC 8812 §2 / RFC 8230 §2) that <see cref="Verifiable.JCose.CoseKeyExtensions.ToPublicKeyMemory"/>
    /// resolves from a COSE_Key's <c>alg</c> parameter. RSA-2048/4096 signing and EdDSA (Ed25519)
    /// verification are not wired here — RSA signing has no CLI caller yet, and EdDSA verification
    /// needs an Ed25519 backend (<c>Verifiable.NSec</c> or <c>Verifiable.BouncyCastle</c>) that this
    /// project does not currently reference.
    /// </summary>
    private static void RegisterSigningAndVerification()
    {
        CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.Initialize(
            (CryptoAlgorithm algorithm, Purpose purpose, string? qualifier) =>
                (algorithm, purpose) switch
                {
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.P256) && p.Equals(Purpose.Signing) => MicrosoftCryptographicFunctions.SignP256Async,
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.P384) && p.Equals(Purpose.Signing) => MicrosoftCryptographicFunctions.SignP384Async,
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.P521) && p.Equals(Purpose.Signing) => MicrosoftCryptographicFunctions.SignP521Async,
                    _ => throw new ArgumentException(
                        $"No signing function registered for '{algorithm}', '{purpose}' with qualifier '{qualifier}'.")
                },
            (CryptoAlgorithm algorithm, Purpose purpose, string? qualifier) =>
                (algorithm, purpose) switch
                {
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.P256) && p.Equals(Purpose.Verification) => MicrosoftCryptographicFunctions.VerifyP256Async,
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.P384) && p.Equals(Purpose.Verification) => MicrosoftCryptographicFunctions.VerifyP384Async,
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.P521) && p.Equals(Purpose.Verification) => MicrosoftCryptographicFunctions.VerifyP521Async,
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.Rsa2048) && p.Equals(Purpose.Verification) => MicrosoftCryptographicFunctions.VerifyRsa2048Async,
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.Rsa4096) && p.Equals(Purpose.Verification) => MicrosoftCryptographicFunctions.VerifyRsa4096Async,
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.RsaSha256) && p.Equals(Purpose.Verification) => MicrosoftCryptographicFunctions.VerifyRsaSha256Pkcs1Async,
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.RsaSha256Pss) && p.Equals(Purpose.Verification) => MicrosoftCryptographicFunctions.VerifyRsaSha256PssAsync,
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.RsaSha384) && p.Equals(Purpose.Verification) => MicrosoftCryptographicFunctions.VerifyRsaSha384Pkcs1Async,
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.RsaSha384Pss) && p.Equals(Purpose.Verification) => MicrosoftCryptographicFunctions.VerifyRsaSha384PssAsync,
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.RsaSha512) && p.Equals(Purpose.Verification) => MicrosoftCryptographicFunctions.VerifyRsaSha512Pkcs1Async,
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.RsaSha512Pss) && p.Equals(Purpose.Verification) => MicrosoftCryptographicFunctions.VerifyRsaSha512PssAsync,
                    _ => throw new ArgumentException(
                        $"No verification function registered for '{algorithm}', '{purpose}' with qualifier '{qualifier}'.")
                });
    }


    /// <summary>
    /// Registers the <c>Verifiable.Microsoft</c> entropy, salt, and digest functions with
    /// <see cref="CryptographicKeyFactory"/>: CSPRNG-backed nonce/salt generation, the async SHA-2
    /// digest, and the synchronous SHA-256/384/512 hash functions (SHA-256 default, SHA-384/512
    /// under qualifiers).
    /// </summary>
    private static void RegisterEntropyAndDigest()
    {
        CryptographicKeyFactory.RegisterFunction(
            typeof(GenerateNonceDelegate),
            (GenerateNonceDelegate)MicrosoftEntropyFunctions.GenerateNonce);

        CryptographicKeyFactory.RegisterFunction(
            typeof(GenerateSaltDelegate),
            (GenerateSaltDelegate)MicrosoftEntropyFunctions.GenerateSalt);

        CryptographicKeyFactory.RegisterFunction(
            typeof(ComputeDigestDelegate),
            (ComputeDigestDelegate)MicrosoftEntropyFunctions.ComputeDigestAsync);

        //The synchronous SHA-family seam for hashes that are sync by nature (a JWK thumbprint, a PKCE S256
        //challenge, a Concat KDF round, an SD-JWT disclosure digest): public/local-data hashes with no
        //hardware-async backend. SHA*.HashData match the HashFunctionDelegate signature and are the same Microsoft
        //backend the async digest above uses. SHA-256 is the default; SHA-384/512 are registered under qualifiers
        //for the algorithm-agile SD-JWT caller.
        CryptographicKeyFactory.RegisterFunction(
            typeof(HashFunctionDelegate),
            (HashFunctionDelegate)SHA256.HashData);

        CryptographicKeyFactory.RegisterFunction(
            typeof(HashFunctionDelegate),
            (HashFunctionDelegate)SHA384.HashData,
            qualifier: nameof(HashAlgorithmName.SHA384));

        CryptographicKeyFactory.RegisterFunction(
            typeof(HashFunctionDelegate),
            (HashFunctionDelegate)SHA512.HashData,
            qualifier: nameof(HashAlgorithmName.SHA512));
    }


    /// <summary>
    /// Initializes <see cref="KeyCreationFunctionRegistry{TDiscriminator1, TDiscriminator2}"/> with the
    /// <c>Verifiable.Microsoft</c> key-creation adapters for exactly the algorithm/purpose combinations this
    /// CLI can also bind for signing: ECDSA P-256/384/521. RSA-2048/4096 keygen is not wired here because
    /// this CLI never registers RSA <em>signing</em> (only RSA verification, see
    /// <see cref="RegisterSigningAndVerification"/>) — a minted RSA key could never be bound for signing
    /// through <see cref="CryptographicKeyFactory"/> anyway. secp256k1 and the P-256/384/521 exchange keys
    /// are deferred for the same reason as their sign/exchange counterparts: this project references neither
    /// <c>Verifiable.BouncyCastle</c> (secp256k1) nor wires <c>KeyAgreementFunctionRegistry</c> (exchange).
    /// </summary>
    private static void RegisterKeyCreation()
    {
        KeyCreationFunctionRegistry<CryptoAlgorithm, Purpose>.Initialize(
            (CryptoAlgorithm algorithm, Purpose purpose, string? qualifier) =>
                (algorithm, purpose) switch
                {
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.P256) && p.Equals(Purpose.Signing) =>
                        pool => MicrosoftKeyMaterialCreator.CreateKeysWithEvent(
                            MicrosoftKeyMaterialCreator.CreateP256Keys, CryptoAlgorithm.P256, Purpose.Signing, pool),
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.P384) && p.Equals(Purpose.Signing) =>
                        pool => MicrosoftKeyMaterialCreator.CreateKeysWithEvent(
                            MicrosoftKeyMaterialCreator.CreateP384Keys, CryptoAlgorithm.P384, Purpose.Signing, pool),
                    (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.P521) && p.Equals(Purpose.Signing) =>
                        pool => MicrosoftKeyMaterialCreator.CreateKeysWithEvent(
                            MicrosoftKeyMaterialCreator.CreateP521Keys, CryptoAlgorithm.P521, Purpose.Signing, pool),
                    _ => throw new ArgumentException(
                        $"No key creation function registered for '{algorithm}', '{purpose}' with qualifier '{qualifier}'.")
                });
    }
}
