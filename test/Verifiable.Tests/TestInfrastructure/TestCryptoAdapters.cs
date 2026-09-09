using System;
using System.Buffers;
using System.Collections.Frozen;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Time.Testing;
using Verifiable.BouncyCastle;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Aead;
using Verifiable.Cryptography.Context;
using Verifiable.Libsodium;
using Verifiable.Microsoft;
using Verifiable.Tpm;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// The suite's canonical fixed clock for the provider-adapter classes below.
/// </summary>
internal static class TestCryptoAdapterClock
{
    /// <summary>The clock every adapted provider call in this file threads through.</summary>
    public static TimeProvider Instance { get; } = new FakeTimeProvider(TestClock.CanonicalEpoch);
}

/// <summary>
/// Forwards to <see cref="MicrosoftEntropyFunctions"/>'s real (clock-taking) overloads with the suite's
/// canonical fixed clock, exposing each provider function's pre-clock parameter shape so a
/// test that holds a bare method-group reference to it (assigning it to a
/// <see cref="SigningDelegate"/>/<see cref="VerificationDelegate"/>/<see cref="ComputeDigestDelegate"/>
/// or a sibling delegate type, rather than calling it immediately) keeps compiling without a
/// per-site inline lambda.
/// </summary>
internal static class MicrosoftEntropyFunctionsAdapter
{
    /// <summary>Forwards to <see cref="MicrosoftEntropyFunctions.GenerateNonce"/> with the suite's canonical fixed clock, <see cref="TestCryptoAdapterClock.Instance"/>.</summary>
    public static (Nonce Result, CryptoEvent? Event) GenerateNonce(int byteLength, Tag tag, BaseMemoryPool pool) => MicrosoftEntropyFunctions.GenerateNonce(byteLength, tag, pool, TestCryptoAdapterClock.Instance);
    /// <summary>Forwards to <see cref="MicrosoftEntropyFunctions.GenerateSalt"/> with the suite's canonical fixed clock, <see cref="TestCryptoAdapterClock.Instance"/>.</summary>
    public static (Salt Result, CryptoEvent? Event) GenerateSalt(int byteLength, Tag tag, BaseMemoryPool pool) => MicrosoftEntropyFunctions.GenerateSalt(byteLength, tag, pool, TestCryptoAdapterClock.Instance);
}

/// <summary>
/// Forwards to <see cref="MicrosoftCryptographicFunctions"/>'s real (clock-taking) overloads with the suite's
/// canonical fixed clock, exposing each provider function's pre-clock parameter shape so a
/// test that holds a bare method-group reference to it (assigning it to a
/// <see cref="SigningDelegate"/>/<see cref="VerificationDelegate"/>/<see cref="ComputeDigestDelegate"/>
/// or a sibling delegate type, rather than calling it immediately) keeps compiling without a
/// per-site inline lambda.
/// </summary>
internal static class MicrosoftCryptographicFunctionsAdapter
{
    /// <summary>Forwards to <see cref="MicrosoftCryptographicFunctions.ComputeDigestAsync"/> with the suite's canonical fixed clock, <see cref="TestCryptoAdapterClock.Instance"/>.</summary>
    public static ValueTask<(DigestValue Result, CryptoEvent? Event)> ComputeDigestAsync(ReadOnlySequence<byte> input, int outputByteLength, Tag tag, BaseMemoryPool pool, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default) => MicrosoftCryptographicFunctions.ComputeDigestAsync(input, outputByteLength, tag, pool, TestCryptoAdapterClock.Instance, context, cancellationToken);
    /// <summary>Forwards to <see cref="MicrosoftCryptographicFunctions.VerifyP256Async"/> with the suite's canonical fixed clock, <see cref="TestCryptoAdapterClock.Instance"/>.</summary>
    public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyP256Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default) => MicrosoftCryptographicFunctions.VerifyP256Async(dataToVerify, signature, publicKeyMaterial, TestCryptoAdapterClock.Instance, context, cancellationToken);
    /// <summary>Forwards to <see cref="MicrosoftCryptographicFunctions.SignP256Async"/> with the suite's canonical fixed clock, <see cref="TestCryptoAdapterClock.Instance"/>.</summary>
    public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignP256Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, BaseMemoryPool signaturePool, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default) => MicrosoftCryptographicFunctions.SignP256Async(privateKeyBytes, dataToSign, signaturePool, TestCryptoAdapterClock.Instance, context, cancellationToken);
    /// <summary>Forwards to <see cref="MicrosoftCryptographicFunctions.VerifyP384Async"/> with the suite's canonical fixed clock, <see cref="TestCryptoAdapterClock.Instance"/>.</summary>
    public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyP384Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default) => MicrosoftCryptographicFunctions.VerifyP384Async(dataToVerify, signature, publicKeyMaterial, TestCryptoAdapterClock.Instance, context, cancellationToken);
    /// <summary>Forwards to <see cref="MicrosoftCryptographicFunctions.SignP384Async"/> with the suite's canonical fixed clock, <see cref="TestCryptoAdapterClock.Instance"/>.</summary>
    public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignP384Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, BaseMemoryPool signaturePool, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default) => MicrosoftCryptographicFunctions.SignP384Async(privateKeyBytes, dataToSign, signaturePool, TestCryptoAdapterClock.Instance, context, cancellationToken);
    /// <summary>Forwards to <see cref="MicrosoftCryptographicFunctions.VerifyP521Async"/> with the suite's canonical fixed clock, <see cref="TestCryptoAdapterClock.Instance"/>.</summary>
    public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyP521Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default) => MicrosoftCryptographicFunctions.VerifyP521Async(dataToVerify, signature, publicKeyMaterial, TestCryptoAdapterClock.Instance, context, cancellationToken);
    /// <summary>Forwards to <see cref="MicrosoftCryptographicFunctions.SignP521Async"/> with the suite's canonical fixed clock, <see cref="TestCryptoAdapterClock.Instance"/>.</summary>
    public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignP521Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, BaseMemoryPool signaturePool, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default) => MicrosoftCryptographicFunctions.SignP521Async(privateKeyBytes, dataToSign, signaturePool, TestCryptoAdapterClock.Instance, context, cancellationToken);
    /// <summary>Forwards to <see cref="MicrosoftCryptographicFunctions.VerifySecp256k1Async"/> with the suite's canonical fixed clock, <see cref="TestCryptoAdapterClock.Instance"/>.</summary>
    public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifySecp256k1Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default) => MicrosoftCryptographicFunctions.VerifySecp256k1Async(dataToVerify, signature, publicKeyMaterial, TestCryptoAdapterClock.Instance, context, cancellationToken);
    /// <summary>Forwards to <see cref="MicrosoftCryptographicFunctions.SignSecp256k1Async"/> with the suite's canonical fixed clock, <see cref="TestCryptoAdapterClock.Instance"/>.</summary>
    public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignSecp256k1Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, BaseMemoryPool signaturePool, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default) => MicrosoftCryptographicFunctions.SignSecp256k1Async(privateKeyBytes, dataToSign, signaturePool, TestCryptoAdapterClock.Instance, context, cancellationToken);
    /// <summary>Forwards to <see cref="MicrosoftCryptographicFunctions.SignRsa2048Async"/> with the suite's canonical fixed clock, <see cref="TestCryptoAdapterClock.Instance"/>.</summary>
    public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignRsa2048Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, BaseMemoryPool signaturePool, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default) => MicrosoftCryptographicFunctions.SignRsa2048Async(privateKeyBytes, dataToSign, signaturePool, TestCryptoAdapterClock.Instance, context, cancellationToken);
    /// <summary>Forwards to <see cref="MicrosoftCryptographicFunctions.VerifyRsa2048Async"/> with the suite's canonical fixed clock, <see cref="TestCryptoAdapterClock.Instance"/>.</summary>
    public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyRsa2048Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default) => MicrosoftCryptographicFunctions.VerifyRsa2048Async(dataToVerify, signature, publicKeyMaterial, TestCryptoAdapterClock.Instance, context, cancellationToken);
    /// <summary>Forwards to <see cref="MicrosoftCryptographicFunctions.SignRsa4096Async"/> with the suite's canonical fixed clock, <see cref="TestCryptoAdapterClock.Instance"/>.</summary>
    public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignRsa4096Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, BaseMemoryPool signaturePool, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default) => MicrosoftCryptographicFunctions.SignRsa4096Async(privateKeyBytes, dataToSign, signaturePool, TestCryptoAdapterClock.Instance, context, cancellationToken);
    /// <summary>Forwards to <see cref="MicrosoftCryptographicFunctions.VerifyRsa4096Async"/> with the suite's canonical fixed clock, <see cref="TestCryptoAdapterClock.Instance"/>.</summary>
    public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyRsa4096Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default) => MicrosoftCryptographicFunctions.VerifyRsa4096Async(dataToVerify, signature, publicKeyMaterial, TestCryptoAdapterClock.Instance, context, cancellationToken);
    /// <summary>Forwards to <see cref="MicrosoftCryptographicFunctions.VerifyRsaSha256Pkcs1Async"/> with the suite's canonical fixed clock, <see cref="TestCryptoAdapterClock.Instance"/>.</summary>
    public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyRsaSha256Pkcs1Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default) => MicrosoftCryptographicFunctions.VerifyRsaSha256Pkcs1Async(dataToVerify, signature, publicKeyMaterial, TestCryptoAdapterClock.Instance, context, cancellationToken);
    /// <summary>Forwards to <see cref="MicrosoftCryptographicFunctions.SignRsaSha256Pkcs1Async"/> with the suite's canonical fixed clock, <see cref="TestCryptoAdapterClock.Instance"/>.</summary>
    public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignRsaSha256Pkcs1Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, BaseMemoryPool signaturePool, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default) => MicrosoftCryptographicFunctions.SignRsaSha256Pkcs1Async(privateKeyBytes, dataToSign, signaturePool, TestCryptoAdapterClock.Instance, context, cancellationToken);
    /// <summary>Forwards to <see cref="MicrosoftCryptographicFunctions.VerifyRsaSha256PssAsync"/> with the suite's canonical fixed clock, <see cref="TestCryptoAdapterClock.Instance"/>.</summary>
    public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyRsaSha256PssAsync(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default) => MicrosoftCryptographicFunctions.VerifyRsaSha256PssAsync(dataToVerify, signature, publicKeyMaterial, TestCryptoAdapterClock.Instance, context, cancellationToken);
    /// <summary>Forwards to <see cref="MicrosoftCryptographicFunctions.SignRsaSha256PssAsync"/> with the suite's canonical fixed clock, <see cref="TestCryptoAdapterClock.Instance"/>.</summary>
    public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignRsaSha256PssAsync(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, BaseMemoryPool signaturePool, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default) => MicrosoftCryptographicFunctions.SignRsaSha256PssAsync(privateKeyBytes, dataToSign, signaturePool, TestCryptoAdapterClock.Instance, context, cancellationToken);
    /// <summary>Forwards to <see cref="MicrosoftCryptographicFunctions.VerifyRsaSha384Pkcs1Async"/> with the suite's canonical fixed clock, <see cref="TestCryptoAdapterClock.Instance"/>.</summary>
    public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyRsaSha384Pkcs1Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default) => MicrosoftCryptographicFunctions.VerifyRsaSha384Pkcs1Async(dataToVerify, signature, publicKeyMaterial, TestCryptoAdapterClock.Instance, context, cancellationToken);
    /// <summary>Forwards to <see cref="MicrosoftCryptographicFunctions.SignRsaSha384Pkcs1Async"/> with the suite's canonical fixed clock, <see cref="TestCryptoAdapterClock.Instance"/>.</summary>
    public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignRsaSha384Pkcs1Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, BaseMemoryPool signaturePool, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default) => MicrosoftCryptographicFunctions.SignRsaSha384Pkcs1Async(privateKeyBytes, dataToSign, signaturePool, TestCryptoAdapterClock.Instance, context, cancellationToken);
    /// <summary>Forwards to <see cref="MicrosoftCryptographicFunctions.VerifyRsaSha384PssAsync"/> with the suite's canonical fixed clock, <see cref="TestCryptoAdapterClock.Instance"/>.</summary>
    public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyRsaSha384PssAsync(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default) => MicrosoftCryptographicFunctions.VerifyRsaSha384PssAsync(dataToVerify, signature, publicKeyMaterial, TestCryptoAdapterClock.Instance, context, cancellationToken);
    /// <summary>Forwards to <see cref="MicrosoftCryptographicFunctions.SignRsaSha384PssAsync"/> with the suite's canonical fixed clock, <see cref="TestCryptoAdapterClock.Instance"/>.</summary>
    public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignRsaSha384PssAsync(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, BaseMemoryPool signaturePool, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default) => MicrosoftCryptographicFunctions.SignRsaSha384PssAsync(privateKeyBytes, dataToSign, signaturePool, TestCryptoAdapterClock.Instance, context, cancellationToken);
    /// <summary>Forwards to <see cref="MicrosoftCryptographicFunctions.VerifyRsaSha512Pkcs1Async"/> with the suite's canonical fixed clock, <see cref="TestCryptoAdapterClock.Instance"/>.</summary>
    public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyRsaSha512Pkcs1Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default) => MicrosoftCryptographicFunctions.VerifyRsaSha512Pkcs1Async(dataToVerify, signature, publicKeyMaterial, TestCryptoAdapterClock.Instance, context, cancellationToken);
    /// <summary>Forwards to <see cref="MicrosoftCryptographicFunctions.SignRsaSha512Pkcs1Async"/> with the suite's canonical fixed clock, <see cref="TestCryptoAdapterClock.Instance"/>.</summary>
    public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignRsaSha512Pkcs1Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, BaseMemoryPool signaturePool, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default) => MicrosoftCryptographicFunctions.SignRsaSha512Pkcs1Async(privateKeyBytes, dataToSign, signaturePool, TestCryptoAdapterClock.Instance, context, cancellationToken);
    /// <summary>Forwards to <see cref="MicrosoftCryptographicFunctions.VerifyRsaSha512PssAsync"/> with the suite's canonical fixed clock, <see cref="TestCryptoAdapterClock.Instance"/>.</summary>
    public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyRsaSha512PssAsync(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default) => MicrosoftCryptographicFunctions.VerifyRsaSha512PssAsync(dataToVerify, signature, publicKeyMaterial, TestCryptoAdapterClock.Instance, context, cancellationToken);
    /// <summary>Forwards to <see cref="MicrosoftCryptographicFunctions.SignRsaSha512PssAsync"/> with the suite's canonical fixed clock, <see cref="TestCryptoAdapterClock.Instance"/>.</summary>
    public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignRsaSha512PssAsync(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, BaseMemoryPool signaturePool, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default) => MicrosoftCryptographicFunctions.SignRsaSha512PssAsync(privateKeyBytes, dataToSign, signaturePool, TestCryptoAdapterClock.Instance, context, cancellationToken);
}

/// <summary>
/// Forwards to <see cref="MicrosoftHmacFunctions"/>'s real (clock-taking) overloads with the suite's
/// canonical fixed clock, exposing each provider function's pre-clock parameter shape so a
/// test that holds a bare method-group reference to it (assigning it to a
/// <see cref="SigningDelegate"/>/<see cref="VerificationDelegate"/>/<see cref="ComputeDigestDelegate"/>
/// or a sibling delegate type, rather than calling it immediately) keeps compiling without a
/// per-site inline lambda.
/// </summary>
internal static class MicrosoftHmacFunctionsAdapter
{
    /// <summary>Forwards to <see cref="MicrosoftHmacFunctions.ComputeHmacAsync"/> with the suite's canonical fixed clock, <see cref="TestCryptoAdapterClock.Instance"/>.</summary>
    public static ValueTask<(HmacValue Result, CryptoEvent? Event)> ComputeHmacAsync(ReadOnlyMemory<byte> message, ReadOnlyMemory<byte> keyBytes, int outputByteLength, Tag tag, BaseMemoryPool pool, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default) => MicrosoftHmacFunctions.ComputeHmacAsync(message, keyBytes, outputByteLength, tag, pool, TestCryptoAdapterClock.Instance, context, cancellationToken);
    /// <summary>Forwards to <see cref="MicrosoftHmacFunctions.ComputeHmacAsync"/> with the suite's canonical fixed clock, <see cref="TestCryptoAdapterClock.Instance"/>.</summary>
    public static ValueTask<(HmacValue Result, CryptoEvent? Event)> ComputeHmacAsync(ReadOnlySequence<byte> message, ReadOnlyMemory<byte> keyBytes, int outputByteLength, Tag tag, BaseMemoryPool pool, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default) => MicrosoftHmacFunctions.ComputeHmacAsync(message, keyBytes, outputByteLength, tag, pool, TestCryptoAdapterClock.Instance, context, cancellationToken);
    /// <summary>Forwards to <see cref="MicrosoftHmacFunctions.VerifyHmacAsync"/> with the suite's canonical fixed clock, <see cref="TestCryptoAdapterClock.Instance"/>.</summary>
    public static ValueTask<(bool IsValid, CryptoEvent? Event)> VerifyHmacAsync(ReadOnlyMemory<byte> message, ReadOnlyMemory<byte> keyBytes, ReadOnlyMemory<byte> expectedMac, Tag tag, BaseMemoryPool pool, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default) => MicrosoftHmacFunctions.VerifyHmacAsync(message, keyBytes, expectedMac, tag, pool, TestCryptoAdapterClock.Instance, context, cancellationToken);
    /// <summary>Forwards to <see cref="MicrosoftHmacFunctions.VerifyHmacAsync"/> with the suite's canonical fixed clock, <see cref="TestCryptoAdapterClock.Instance"/>.</summary>
    public static ValueTask<(bool IsValid, CryptoEvent? Event)> VerifyHmacAsync(ReadOnlySequence<byte> message, ReadOnlyMemory<byte> keyBytes, ReadOnlyMemory<byte> expectedMac, Tag tag, BaseMemoryPool pool, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default) => MicrosoftHmacFunctions.VerifyHmacAsync(message, keyBytes, expectedMac, tag, pool, TestCryptoAdapterClock.Instance, context, cancellationToken);
}

/// <summary>
/// Forwards to <see cref="MicrosoftKeyMaterialCreator"/>'s real (clock-taking) overloads with the suite's
/// canonical fixed clock, exposing each provider function's pre-clock parameter shape so a
/// test that holds a bare method-group reference to it (assigning it to a
/// <see cref="SigningDelegate"/>/<see cref="VerificationDelegate"/>/<see cref="ComputeDigestDelegate"/>
/// or a sibling delegate type, rather than calling it immediately) keeps compiling without a
/// per-site inline lambda.
/// </summary>
internal static class MicrosoftKeyMaterialCreatorAdapter
{
    /// <summary>Forwards to <see cref="MicrosoftKeyMaterialCreator.CreateKeysWithEvent"/> with the suite's canonical fixed clock, <see cref="TestCryptoAdapterClock.Instance"/>.</summary>
    public static (PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> Keys, CryptoEvent? Event) CreateKeysWithEvent(PublicPrivateKeyCreationDelegate<PublicKeyMemory, PrivateKeyMemory> creator, CryptoAlgorithm algorithm, Purpose purpose, BaseMemoryPool memoryPool) => MicrosoftKeyMaterialCreator.CreateKeysWithEvent(creator, algorithm, purpose, memoryPool, TestCryptoAdapterClock.Instance);
}

/// <summary>
/// Forwards to <see cref="BouncyCastleEntropyFunctions"/>'s real (clock-taking) overloads with the suite's
/// canonical fixed clock, exposing each provider function's pre-clock parameter shape so a
/// test that holds a bare method-group reference to it (assigning it to a
/// <see cref="SigningDelegate"/>/<see cref="VerificationDelegate"/>/<see cref="ComputeDigestDelegate"/>
/// or a sibling delegate type, rather than calling it immediately) keeps compiling without a
/// per-site inline lambda.
/// </summary>
internal static class BouncyCastleEntropyFunctionsAdapter
{
    /// <summary>Forwards to <see cref="BouncyCastleEntropyFunctions.GenerateNonce"/> with the suite's canonical fixed clock, <see cref="TestCryptoAdapterClock.Instance"/>.</summary>
    public static (Nonce Result, CryptoEvent? Event) GenerateNonce(int byteLength, Tag tag, BaseMemoryPool pool) => BouncyCastleEntropyFunctions.GenerateNonce(byteLength, tag, pool, TestCryptoAdapterClock.Instance);
    /// <summary>Forwards to <see cref="BouncyCastleEntropyFunctions.GenerateSalt"/> with the suite's canonical fixed clock, <see cref="TestCryptoAdapterClock.Instance"/>.</summary>
    public static (Salt Result, CryptoEvent? Event) GenerateSalt(int byteLength, Tag tag, BaseMemoryPool pool) => BouncyCastleEntropyFunctions.GenerateSalt(byteLength, tag, pool, TestCryptoAdapterClock.Instance);
}

/// <summary>
/// Forwards to <see cref="BouncyCastleCryptographicFunctions"/>'s real (clock-taking) overloads with the suite's
/// canonical fixed clock, exposing each provider function's pre-clock parameter shape so a
/// test that holds a bare method-group reference to it (assigning it to a
/// <see cref="SigningDelegate"/>/<see cref="VerificationDelegate"/>/<see cref="ComputeDigestDelegate"/>
/// or a sibling delegate type, rather than calling it immediately) keeps compiling without a
/// per-site inline lambda.
/// </summary>
internal static class BouncyCastleCryptographicFunctionsAdapter
{
    /// <summary>Forwards to <see cref="BouncyCastleCryptographicFunctions.ComputeDigest"/> with the suite's canonical fixed clock, <see cref="TestCryptoAdapterClock.Instance"/>.</summary>
    public static (DigestValue Result, CryptoEvent? Event) ComputeDigest(ReadOnlySpan<byte> input, int outputByteLength, Tag tag, BaseMemoryPool pool) => BouncyCastleCryptographicFunctions.ComputeDigest(input, outputByteLength, tag, pool, TestCryptoAdapterClock.Instance);
    /// <summary>Forwards to <see cref="BouncyCastleCryptographicFunctions.ComputeBlake3DigestAsync"/> with the suite's canonical fixed clock, <see cref="TestCryptoAdapterClock.Instance"/>.</summary>
    public static ValueTask<(DigestValue Result, CryptoEvent? Event)> ComputeBlake3DigestAsync(ReadOnlySequence<byte> input, int outputByteLength, Tag tag, BaseMemoryPool pool, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default) => BouncyCastleCryptographicFunctions.ComputeBlake3DigestAsync(input, outputByteLength, tag, pool, TestCryptoAdapterClock.Instance, context, cancellationToken);
    /// <summary>Forwards to <see cref="BouncyCastleCryptographicFunctions.SignEd25519Async"/> with the suite's canonical fixed clock, <see cref="TestCryptoAdapterClock.Instance"/>.</summary>
    public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignEd25519Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, BaseMemoryPool signaturePool, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default) => BouncyCastleCryptographicFunctions.SignEd25519Async(privateKeyBytes, dataToSign, signaturePool, TestCryptoAdapterClock.Instance, context, cancellationToken);
    /// <summary>Forwards to <see cref="BouncyCastleCryptographicFunctions.VerifyEd25519Async"/> with the suite's canonical fixed clock, <see cref="TestCryptoAdapterClock.Instance"/>.</summary>
    public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyEd25519Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default) => BouncyCastleCryptographicFunctions.VerifyEd25519Async(dataToVerify, signature, publicKeyMaterial, TestCryptoAdapterClock.Instance, context, cancellationToken);
    /// <summary>Forwards to <see cref="BouncyCastleCryptographicFunctions.SignP256Async"/> with the suite's canonical fixed clock, <see cref="TestCryptoAdapterClock.Instance"/>.</summary>
    public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignP256Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, BaseMemoryPool signaturePool, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default) => BouncyCastleCryptographicFunctions.SignP256Async(privateKeyBytes, dataToSign, signaturePool, TestCryptoAdapterClock.Instance, context, cancellationToken);
    /// <summary>Forwards to <see cref="BouncyCastleCryptographicFunctions.VerifyP256Async"/> with the suite's canonical fixed clock, <see cref="TestCryptoAdapterClock.Instance"/>.</summary>
    public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyP256Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default) => BouncyCastleCryptographicFunctions.VerifyP256Async(dataToVerify, signature, publicKeyMaterial, TestCryptoAdapterClock.Instance, context, cancellationToken);
    /// <summary>Forwards to <see cref="BouncyCastleCryptographicFunctions.SignP384Async"/> with the suite's canonical fixed clock, <see cref="TestCryptoAdapterClock.Instance"/>.</summary>
    public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignP384Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, BaseMemoryPool signaturePool, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default) => BouncyCastleCryptographicFunctions.SignP384Async(privateKeyBytes, dataToSign, signaturePool, TestCryptoAdapterClock.Instance, context, cancellationToken);
    /// <summary>Forwards to <see cref="BouncyCastleCryptographicFunctions.VerifyP384Async"/> with the suite's canonical fixed clock, <see cref="TestCryptoAdapterClock.Instance"/>.</summary>
    public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyP384Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default) => BouncyCastleCryptographicFunctions.VerifyP384Async(dataToVerify, signature, publicKeyMaterial, TestCryptoAdapterClock.Instance, context, cancellationToken);
    /// <summary>Forwards to <see cref="BouncyCastleCryptographicFunctions.SignP521Async"/> with the suite's canonical fixed clock, <see cref="TestCryptoAdapterClock.Instance"/>.</summary>
    public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignP521Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, BaseMemoryPool signaturePool, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default) => BouncyCastleCryptographicFunctions.SignP521Async(privateKeyBytes, dataToSign, signaturePool, TestCryptoAdapterClock.Instance, context, cancellationToken);
    /// <summary>Forwards to <see cref="BouncyCastleCryptographicFunctions.VerifyP521Async"/> with the suite's canonical fixed clock, <see cref="TestCryptoAdapterClock.Instance"/>.</summary>
    public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyP521Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default) => BouncyCastleCryptographicFunctions.VerifyP521Async(dataToVerify, signature, publicKeyMaterial, TestCryptoAdapterClock.Instance, context, cancellationToken);
    /// <summary>Forwards to <see cref="BouncyCastleCryptographicFunctions.SignBrainpoolP224r1Async"/> with the suite's canonical fixed clock, <see cref="TestCryptoAdapterClock.Instance"/>.</summary>
    public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignBrainpoolP224r1Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, BaseMemoryPool signaturePool, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default) => BouncyCastleCryptographicFunctions.SignBrainpoolP224r1Async(privateKeyBytes, dataToSign, signaturePool, TestCryptoAdapterClock.Instance, context, cancellationToken);
    /// <summary>Forwards to <see cref="BouncyCastleCryptographicFunctions.VerifyBrainpoolP224r1Async"/> with the suite's canonical fixed clock, <see cref="TestCryptoAdapterClock.Instance"/>.</summary>
    public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyBrainpoolP224r1Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default) => BouncyCastleCryptographicFunctions.VerifyBrainpoolP224r1Async(dataToVerify, signature, publicKeyMaterial, TestCryptoAdapterClock.Instance, context, cancellationToken);
    /// <summary>Forwards to <see cref="BouncyCastleCryptographicFunctions.SignBrainpoolP256r1Async"/> with the suite's canonical fixed clock, <see cref="TestCryptoAdapterClock.Instance"/>.</summary>
    public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignBrainpoolP256r1Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, BaseMemoryPool signaturePool, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default) => BouncyCastleCryptographicFunctions.SignBrainpoolP256r1Async(privateKeyBytes, dataToSign, signaturePool, TestCryptoAdapterClock.Instance, context, cancellationToken);
    /// <summary>Forwards to <see cref="BouncyCastleCryptographicFunctions.VerifyBrainpoolP256r1Async"/> with the suite's canonical fixed clock, <see cref="TestCryptoAdapterClock.Instance"/>.</summary>
    public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyBrainpoolP256r1Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default) => BouncyCastleCryptographicFunctions.VerifyBrainpoolP256r1Async(dataToVerify, signature, publicKeyMaterial, TestCryptoAdapterClock.Instance, context, cancellationToken);
    /// <summary>Forwards to <see cref="BouncyCastleCryptographicFunctions.SignBrainpoolP320r1Async"/> with the suite's canonical fixed clock, <see cref="TestCryptoAdapterClock.Instance"/>.</summary>
    public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignBrainpoolP320r1Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, BaseMemoryPool signaturePool, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default) => BouncyCastleCryptographicFunctions.SignBrainpoolP320r1Async(privateKeyBytes, dataToSign, signaturePool, TestCryptoAdapterClock.Instance, context, cancellationToken);
    /// <summary>Forwards to <see cref="BouncyCastleCryptographicFunctions.VerifyBrainpoolP320r1Async"/> with the suite's canonical fixed clock, <see cref="TestCryptoAdapterClock.Instance"/>.</summary>
    public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyBrainpoolP320r1Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default) => BouncyCastleCryptographicFunctions.VerifyBrainpoolP320r1Async(dataToVerify, signature, publicKeyMaterial, TestCryptoAdapterClock.Instance, context, cancellationToken);
    /// <summary>Forwards to <see cref="BouncyCastleCryptographicFunctions.SignBrainpoolP384r1Async"/> with the suite's canonical fixed clock, <see cref="TestCryptoAdapterClock.Instance"/>.</summary>
    public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignBrainpoolP384r1Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, BaseMemoryPool signaturePool, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default) => BouncyCastleCryptographicFunctions.SignBrainpoolP384r1Async(privateKeyBytes, dataToSign, signaturePool, TestCryptoAdapterClock.Instance, context, cancellationToken);
    /// <summary>Forwards to <see cref="BouncyCastleCryptographicFunctions.VerifyBrainpoolP384r1Async"/> with the suite's canonical fixed clock, <see cref="TestCryptoAdapterClock.Instance"/>.</summary>
    public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyBrainpoolP384r1Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default) => BouncyCastleCryptographicFunctions.VerifyBrainpoolP384r1Async(dataToVerify, signature, publicKeyMaterial, TestCryptoAdapterClock.Instance, context, cancellationToken);
    /// <summary>Forwards to <see cref="BouncyCastleCryptographicFunctions.SignBrainpoolP512r1Async"/> with the suite's canonical fixed clock, <see cref="TestCryptoAdapterClock.Instance"/>.</summary>
    public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignBrainpoolP512r1Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, BaseMemoryPool signaturePool, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default) => BouncyCastleCryptographicFunctions.SignBrainpoolP512r1Async(privateKeyBytes, dataToSign, signaturePool, TestCryptoAdapterClock.Instance, context, cancellationToken);
    /// <summary>Forwards to <see cref="BouncyCastleCryptographicFunctions.VerifyBrainpoolP512r1Async"/> with the suite's canonical fixed clock, <see cref="TestCryptoAdapterClock.Instance"/>.</summary>
    public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyBrainpoolP512r1Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default) => BouncyCastleCryptographicFunctions.VerifyBrainpoolP512r1Async(dataToVerify, signature, publicKeyMaterial, TestCryptoAdapterClock.Instance, context, cancellationToken);
    /// <summary>Forwards to <see cref="BouncyCastleCryptographicFunctions.SignSecp256k1Async"/> with the suite's canonical fixed clock, <see cref="TestCryptoAdapterClock.Instance"/>.</summary>
    public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignSecp256k1Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, BaseMemoryPool signaturePool, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default) => BouncyCastleCryptographicFunctions.SignSecp256k1Async(privateKeyBytes, dataToSign, signaturePool, TestCryptoAdapterClock.Instance, context, cancellationToken);
    /// <summary>Forwards to <see cref="BouncyCastleCryptographicFunctions.VerifySecp256k1Async"/> with the suite's canonical fixed clock, <see cref="TestCryptoAdapterClock.Instance"/>.</summary>
    public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifySecp256k1Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default) => BouncyCastleCryptographicFunctions.VerifySecp256k1Async(dataToVerify, signature, publicKeyMaterial, TestCryptoAdapterClock.Instance, context, cancellationToken);
    /// <summary>Forwards to <see cref="BouncyCastleCryptographicFunctions.SignRsa2048Async"/> with the suite's canonical fixed clock, <see cref="TestCryptoAdapterClock.Instance"/>.</summary>
    public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignRsa2048Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, BaseMemoryPool signaturePool, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default) => BouncyCastleCryptographicFunctions.SignRsa2048Async(privateKeyBytes, dataToSign, signaturePool, TestCryptoAdapterClock.Instance, context, cancellationToken);
    /// <summary>Forwards to <see cref="BouncyCastleCryptographicFunctions.VerifyRsa2048Async"/> with the suite's canonical fixed clock, <see cref="TestCryptoAdapterClock.Instance"/>.</summary>
    public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyRsa2048Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default) => BouncyCastleCryptographicFunctions.VerifyRsa2048Async(dataToVerify, signature, publicKeyMaterial, TestCryptoAdapterClock.Instance, context, cancellationToken);
    /// <summary>Forwards to <see cref="BouncyCastleCryptographicFunctions.SignRsa4096Async"/> with the suite's canonical fixed clock, <see cref="TestCryptoAdapterClock.Instance"/>.</summary>
    public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignRsa4096Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, BaseMemoryPool signaturePool, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default) => BouncyCastleCryptographicFunctions.SignRsa4096Async(privateKeyBytes, dataToSign, signaturePool, TestCryptoAdapterClock.Instance, context, cancellationToken);
    /// <summary>Forwards to <see cref="BouncyCastleCryptographicFunctions.VerifyRsa4096Async"/> with the suite's canonical fixed clock, <see cref="TestCryptoAdapterClock.Instance"/>.</summary>
    public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyRsa4096Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default) => BouncyCastleCryptographicFunctions.VerifyRsa4096Async(dataToVerify, signature, publicKeyMaterial, TestCryptoAdapterClock.Instance, context, cancellationToken);
    /// <summary>Forwards to <see cref="BouncyCastleCryptographicFunctions.SignRsaSha256Pkcs1Async"/> with the suite's canonical fixed clock, <see cref="TestCryptoAdapterClock.Instance"/>.</summary>
    public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignRsaSha256Pkcs1Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, BaseMemoryPool signaturePool, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default) => BouncyCastleCryptographicFunctions.SignRsaSha256Pkcs1Async(privateKeyBytes, dataToSign, signaturePool, TestCryptoAdapterClock.Instance, context, cancellationToken);
    /// <summary>Forwards to <see cref="BouncyCastleCryptographicFunctions.VerifyRsaSha256Pkcs1Async"/> with the suite's canonical fixed clock, <see cref="TestCryptoAdapterClock.Instance"/>.</summary>
    public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyRsaSha256Pkcs1Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default) => BouncyCastleCryptographicFunctions.VerifyRsaSha256Pkcs1Async(dataToVerify, signature, publicKeyMaterial, TestCryptoAdapterClock.Instance, context, cancellationToken);
    /// <summary>Forwards to <see cref="BouncyCastleCryptographicFunctions.SignRsaSha256PssAsync"/> with the suite's canonical fixed clock, <see cref="TestCryptoAdapterClock.Instance"/>.</summary>
    public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignRsaSha256PssAsync(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, BaseMemoryPool signaturePool, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default) => BouncyCastleCryptographicFunctions.SignRsaSha256PssAsync(privateKeyBytes, dataToSign, signaturePool, TestCryptoAdapterClock.Instance, context, cancellationToken);
    /// <summary>Forwards to <see cref="BouncyCastleCryptographicFunctions.VerifyRsaSha256PssAsync"/> with the suite's canonical fixed clock, <see cref="TestCryptoAdapterClock.Instance"/>.</summary>
    public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyRsaSha256PssAsync(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default) => BouncyCastleCryptographicFunctions.VerifyRsaSha256PssAsync(dataToVerify, signature, publicKeyMaterial, TestCryptoAdapterClock.Instance, context, cancellationToken);
    /// <summary>Forwards to <see cref="BouncyCastleCryptographicFunctions.SignRsaSha384Pkcs1Async"/> with the suite's canonical fixed clock, <see cref="TestCryptoAdapterClock.Instance"/>.</summary>
    public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignRsaSha384Pkcs1Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, BaseMemoryPool signaturePool, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default) => BouncyCastleCryptographicFunctions.SignRsaSha384Pkcs1Async(privateKeyBytes, dataToSign, signaturePool, TestCryptoAdapterClock.Instance, context, cancellationToken);
    /// <summary>Forwards to <see cref="BouncyCastleCryptographicFunctions.VerifyRsaSha384Pkcs1Async"/> with the suite's canonical fixed clock, <see cref="TestCryptoAdapterClock.Instance"/>.</summary>
    public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyRsaSha384Pkcs1Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default) => BouncyCastleCryptographicFunctions.VerifyRsaSha384Pkcs1Async(dataToVerify, signature, publicKeyMaterial, TestCryptoAdapterClock.Instance, context, cancellationToken);
    /// <summary>Forwards to <see cref="BouncyCastleCryptographicFunctions.SignRsaSha384PssAsync"/> with the suite's canonical fixed clock, <see cref="TestCryptoAdapterClock.Instance"/>.</summary>
    public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignRsaSha384PssAsync(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, BaseMemoryPool signaturePool, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default) => BouncyCastleCryptographicFunctions.SignRsaSha384PssAsync(privateKeyBytes, dataToSign, signaturePool, TestCryptoAdapterClock.Instance, context, cancellationToken);
    /// <summary>Forwards to <see cref="BouncyCastleCryptographicFunctions.VerifyRsaSha384PssAsync"/> with the suite's canonical fixed clock, <see cref="TestCryptoAdapterClock.Instance"/>.</summary>
    public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyRsaSha384PssAsync(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default) => BouncyCastleCryptographicFunctions.VerifyRsaSha384PssAsync(dataToVerify, signature, publicKeyMaterial, TestCryptoAdapterClock.Instance, context, cancellationToken);
    /// <summary>Forwards to <see cref="BouncyCastleCryptographicFunctions.SignRsaSha512Pkcs1Async"/> with the suite's canonical fixed clock, <see cref="TestCryptoAdapterClock.Instance"/>.</summary>
    public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignRsaSha512Pkcs1Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, BaseMemoryPool signaturePool, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default) => BouncyCastleCryptographicFunctions.SignRsaSha512Pkcs1Async(privateKeyBytes, dataToSign, signaturePool, TestCryptoAdapterClock.Instance, context, cancellationToken);
    /// <summary>Forwards to <see cref="BouncyCastleCryptographicFunctions.VerifyRsaSha512Pkcs1Async"/> with the suite's canonical fixed clock, <see cref="TestCryptoAdapterClock.Instance"/>.</summary>
    public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyRsaSha512Pkcs1Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default) => BouncyCastleCryptographicFunctions.VerifyRsaSha512Pkcs1Async(dataToVerify, signature, publicKeyMaterial, TestCryptoAdapterClock.Instance, context, cancellationToken);
    /// <summary>Forwards to <see cref="BouncyCastleCryptographicFunctions.SignRsaSha512PssAsync"/> with the suite's canonical fixed clock, <see cref="TestCryptoAdapterClock.Instance"/>.</summary>
    public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignRsaSha512PssAsync(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, BaseMemoryPool signaturePool, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default) => BouncyCastleCryptographicFunctions.SignRsaSha512PssAsync(privateKeyBytes, dataToSign, signaturePool, TestCryptoAdapterClock.Instance, context, cancellationToken);
    /// <summary>Forwards to <see cref="BouncyCastleCryptographicFunctions.VerifyRsaSha512PssAsync"/> with the suite's canonical fixed clock, <see cref="TestCryptoAdapterClock.Instance"/>.</summary>
    public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyRsaSha512PssAsync(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default) => BouncyCastleCryptographicFunctions.VerifyRsaSha512PssAsync(dataToVerify, signature, publicKeyMaterial, TestCryptoAdapterClock.Instance, context, cancellationToken);
    /// <summary>Forwards to <see cref="BouncyCastleCryptographicFunctions.SignMlDsa44Async"/> with the suite's canonical fixed clock, <see cref="TestCryptoAdapterClock.Instance"/>.</summary>
    public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignMlDsa44Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, BaseMemoryPool signaturePool, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default) => BouncyCastleCryptographicFunctions.SignMlDsa44Async(privateKeyBytes, dataToSign, signaturePool, TestCryptoAdapterClock.Instance, context, cancellationToken);
    /// <summary>Forwards to <see cref="BouncyCastleCryptographicFunctions.VerifyMlDsa44Async"/> with the suite's canonical fixed clock, <see cref="TestCryptoAdapterClock.Instance"/>.</summary>
    public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyMlDsa44Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default) => BouncyCastleCryptographicFunctions.VerifyMlDsa44Async(dataToVerify, signature, publicKeyMaterial, TestCryptoAdapterClock.Instance, context, cancellationToken);
    /// <summary>Forwards to <see cref="BouncyCastleCryptographicFunctions.SignMlDsa65Async"/> with the suite's canonical fixed clock, <see cref="TestCryptoAdapterClock.Instance"/>.</summary>
    public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignMlDsa65Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, BaseMemoryPool signaturePool, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default) => BouncyCastleCryptographicFunctions.SignMlDsa65Async(privateKeyBytes, dataToSign, signaturePool, TestCryptoAdapterClock.Instance, context, cancellationToken);
    /// <summary>Forwards to <see cref="BouncyCastleCryptographicFunctions.VerifyMlDsa65Async"/> with the suite's canonical fixed clock, <see cref="TestCryptoAdapterClock.Instance"/>.</summary>
    public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyMlDsa65Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default) => BouncyCastleCryptographicFunctions.VerifyMlDsa65Async(dataToVerify, signature, publicKeyMaterial, TestCryptoAdapterClock.Instance, context, cancellationToken);
    /// <summary>Forwards to <see cref="BouncyCastleCryptographicFunctions.SignMlDsa87Async"/> with the suite's canonical fixed clock, <see cref="TestCryptoAdapterClock.Instance"/>.</summary>
    public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignMlDsa87Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, BaseMemoryPool signaturePool, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default) => BouncyCastleCryptographicFunctions.SignMlDsa87Async(privateKeyBytes, dataToSign, signaturePool, TestCryptoAdapterClock.Instance, context, cancellationToken);
    /// <summary>Forwards to <see cref="BouncyCastleCryptographicFunctions.VerifyMlDsa87Async"/> with the suite's canonical fixed clock, <see cref="TestCryptoAdapterClock.Instance"/>.</summary>
    public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyMlDsa87Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default) => BouncyCastleCryptographicFunctions.VerifyMlDsa87Async(dataToVerify, signature, publicKeyMaterial, TestCryptoAdapterClock.Instance, context, cancellationToken);
}

/// <summary>
/// Forwards to <see cref="BouncyCastleKeyMaterialCreator"/>'s real (clock-taking) overloads with the suite's
/// canonical fixed clock, exposing each provider function's pre-clock parameter shape so a
/// test that holds a bare method-group reference to it (assigning it to a
/// <see cref="SigningDelegate"/>/<see cref="VerificationDelegate"/>/<see cref="ComputeDigestDelegate"/>
/// or a sibling delegate type, rather than calling it immediately) keeps compiling without a
/// per-site inline lambda.
/// </summary>
internal static class BouncyCastleKeyMaterialCreatorAdapter
{
    /// <summary>Forwards to <see cref="BouncyCastleKeyMaterialCreator.CreateKeysWithEvent"/> with the suite's canonical fixed clock, <see cref="TestCryptoAdapterClock.Instance"/>.</summary>
    public static (PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> Keys, CryptoEvent? Event) CreateKeysWithEvent(PublicPrivateKeyCreationDelegate<PublicKeyMemory, PrivateKeyMemory> creator, CryptoAlgorithm algorithm, Purpose purpose, BaseMemoryPool memoryPool) => BouncyCastleKeyMaterialCreator.CreateKeysWithEvent(creator, algorithm, purpose, memoryPool, TestCryptoAdapterClock.Instance);
}

/// <summary>
/// Forwards to <see cref="BouncyCastleSymmetricFunctions"/>'s real (clock-taking) overloads with the suite's
/// canonical fixed clock, exposing each provider function's pre-clock parameter shape so a
/// test that holds a bare method-group reference to it (assigning it to a
/// <see cref="SigningDelegate"/>/<see cref="VerificationDelegate"/>/<see cref="ComputeDigestDelegate"/>
/// or a sibling delegate type, rather than calling it immediately) keeps compiling without a
/// per-site inline lambda.
/// </summary>
internal static class BouncyCastleSymmetricFunctionsAdapter
{
    /// <summary>Forwards to <see cref="BouncyCastleSymmetricFunctions.SymmetricEncryptAsync"/> with the suite's canonical fixed clock, <see cref="TestCryptoAdapterClock.Instance"/>.</summary>
    public static ValueTask<(Ciphertext Result, CryptoEvent? Event)> SymmetricEncryptAsync(ReadOnlyMemory<byte> plaintext, ReadOnlyMemory<byte> keyBytes, ReadOnlyMemory<byte> iv, Tag tag, BaseMemoryPool pool, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default) => BouncyCastleSymmetricFunctions.SymmetricEncryptAsync(plaintext, keyBytes, iv, tag, pool, TestCryptoAdapterClock.Instance, context, cancellationToken);
    /// <summary>Forwards to <see cref="BouncyCastleSymmetricFunctions.SymmetricDecryptAsync"/> with the suite's canonical fixed clock, <see cref="TestCryptoAdapterClock.Instance"/>.</summary>
    public static ValueTask<(DecryptedContent Result, CryptoEvent? Event)> SymmetricDecryptAsync(ReadOnlyMemory<byte> ciphertext, ReadOnlyMemory<byte> keyBytes, ReadOnlyMemory<byte> iv, Tag tag, BaseMemoryPool pool, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default) => BouncyCastleSymmetricFunctions.SymmetricDecryptAsync(ciphertext, keyBytes, iv, tag, pool, TestCryptoAdapterClock.Instance, context, cancellationToken);
    /// <summary>Forwards to <see cref="BouncyCastleSymmetricFunctions.ComputeBlockCipherMacAsync"/> with the suite's canonical fixed clock, <see cref="TestCryptoAdapterClock.Instance"/>.</summary>
    public static ValueTask<(MacValue Result, CryptoEvent? Event)> ComputeBlockCipherMacAsync(ReadOnlyMemory<byte> message, ReadOnlyMemory<byte> keyBytes, int outputByteLength, Tag tag, BaseMemoryPool pool, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default) => BouncyCastleSymmetricFunctions.ComputeBlockCipherMacAsync(message, keyBytes, outputByteLength, tag, pool, TestCryptoAdapterClock.Instance, context, cancellationToken);
    /// <summary>Forwards to <see cref="BouncyCastleSymmetricFunctions.VerifyBlockCipherMacAsync"/> with the suite's canonical fixed clock, <see cref="TestCryptoAdapterClock.Instance"/>.</summary>
    public static ValueTask<(bool IsValid, CryptoEvent? Event)> VerifyBlockCipherMacAsync(ReadOnlyMemory<byte> message, ReadOnlyMemory<byte> keyBytes, ReadOnlyMemory<byte> expectedMac, Tag tag, BaseMemoryPool pool, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default) => BouncyCastleSymmetricFunctions.VerifyBlockCipherMacAsync(message, keyBytes, expectedMac, tag, pool, TestCryptoAdapterClock.Instance, context, cancellationToken);
}

/// <summary>
/// Forwards to <see cref="BouncyCastleRecoverableSignatureFunctions"/>'s real (clock-taking) overloads with the suite's
/// canonical fixed clock, exposing each provider function's pre-clock parameter shape so a
/// test that holds a bare method-group reference to it (assigning it to a
/// <see cref="SigningDelegate"/>/<see cref="VerificationDelegate"/>/<see cref="ComputeDigestDelegate"/>
/// or a sibling delegate type, rather than calling it immediately) keeps compiling without a
/// per-site inline lambda.
/// </summary>
internal static class BouncyCastleRecoverableSignatureFunctionsAdapter
{
    /// <summary>Forwards to <see cref="BouncyCastleRecoverableSignatureFunctions.SignRsaIso9796d2Async"/> with the suite's canonical fixed clock, <see cref="TestCryptoAdapterClock.Instance"/>.</summary>
    public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignRsaIso9796d2Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> nonRecoverableMessage, BaseMemoryPool signaturePool, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default) => BouncyCastleRecoverableSignatureFunctions.SignRsaIso9796d2Async(privateKeyBytes, nonRecoverableMessage, signaturePool, TestCryptoAdapterClock.Instance, context, cancellationToken);
    /// <summary>Forwards to <see cref="BouncyCastleRecoverableSignatureFunctions.VerifyRsaIso9796d2Async"/> with the suite's canonical fixed clock, <see cref="TestCryptoAdapterClock.Instance"/>.</summary>
    public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyRsaIso9796d2Async(ReadOnlyMemory<byte> nonRecoverableMessage, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default) => BouncyCastleRecoverableSignatureFunctions.VerifyRsaIso9796d2Async(nonRecoverableMessage, signature, publicKeyMaterial, TestCryptoAdapterClock.Instance, context, cancellationToken);
}

/// <summary>
/// Forwards to <see cref="LibsodiumCryptographicFunctions"/>'s real (clock-taking) overloads with the suite's
/// canonical fixed clock, exposing each provider function's pre-clock parameter shape so a
/// test that holds a bare method-group reference to it (assigning it to a
/// <see cref="SigningDelegate"/>/<see cref="VerificationDelegate"/>/<see cref="ComputeDigestDelegate"/>
/// or a sibling delegate type, rather than calling it immediately) keeps compiling without a
/// per-site inline lambda.
/// </summary>
internal static class LibsodiumCryptographicFunctionsAdapter
{
    /// <summary>Forwards to <see cref="LibsodiumCryptographicFunctions.SignEd25519Async"/> with the suite's canonical fixed clock, <see cref="TestCryptoAdapterClock.Instance"/>.</summary>
    public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignEd25519Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, BaseMemoryPool signaturePool, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default) => LibsodiumCryptographicFunctions.SignEd25519Async(privateKeyBytes, dataToSign, signaturePool, TestCryptoAdapterClock.Instance, context, cancellationToken);
    /// <summary>Forwards to <see cref="LibsodiumCryptographicFunctions.VerifyEd25519Async"/> with the suite's canonical fixed clock, <see cref="TestCryptoAdapterClock.Instance"/>.</summary>
    public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyEd25519Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default) => LibsodiumCryptographicFunctions.VerifyEd25519Async(dataToVerify, signature, publicKeyMaterial, TestCryptoAdapterClock.Instance, context, cancellationToken);
}

/// <summary>
/// Forwards to <see cref="TpmCryptographicFunctions"/>'s real (clock-taking) overloads with the suite's
/// canonical fixed clock, exposing each provider function's pre-clock parameter shape so a
/// test that holds a bare method-group reference to it (assigning it to a
/// <see cref="SigningDelegate"/>/<see cref="VerificationDelegate"/>/<see cref="ComputeDigestDelegate"/>
/// or a sibling delegate type, rather than calling it immediately) keeps compiling without a
/// per-site inline lambda.
/// </summary>
internal static class TpmCryptographicFunctionsAdapter
{
    /// <summary>Forwards to <see cref="TpmCryptographicFunctions.SignAsync"/> with the suite's canonical fixed clock, <see cref="TestCryptoAdapterClock.Instance"/>.</summary>
    public static async ValueTask<(Signature Signature, CryptoEvent? Event)> SignAsync(ReadOnlyMemory<byte> handleBytes, ReadOnlyMemory<byte> dataToSign, BaseMemoryPool signaturePool, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default) => await TpmCryptographicFunctions.SignAsync(handleBytes, dataToSign, signaturePool, TestCryptoAdapterClock.Instance, context, cancellationToken).ConfigureAwait(false);
}

