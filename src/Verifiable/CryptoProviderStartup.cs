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
/// (ECDSA P-256/384/521 plus CSPRNG entropy and SHA-2 digests).
/// </para>
/// </remarks>
internal static class CryptoProviderStartup
{
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
    }


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
                    _ => throw new ArgumentException(
                        $"No verification function registered for '{algorithm}', '{purpose}' with qualifier '{qualifier}'.")
                });
    }


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
}
