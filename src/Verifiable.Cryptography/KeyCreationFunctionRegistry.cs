using System;
using System.Buffers;

namespace Verifiable.Cryptography;

/// <summary>
/// Creates public/private key material and reports it via an optional <see cref="CryptoEvent"/>.
/// </summary>
/// <remarks>
/// <para>
/// Key creation does not fit the detached <see cref="SigningDelegate"/>/<see cref="VerificationDelegate"/>
/// contract — it takes no <c>dataToSign</c>/<c>signature</c> and produces a key pair rather than consuming
/// one — so it is given its own delegate and registry, the same way message recovery
/// (<see cref="RecoverableSigningDelegate"/>) and key agreement (<c>KeyAgreementEncryptDelegate</c>) each
/// have their own.
/// </para>
/// <para>
/// The existing backend <c>Create*Keys</c> methods (e.g. <c>MicrosoftKeyMaterialCreator.CreateP256Keys</c>)
/// keep their own bare-value signature unchanged — widening all 28 of them to this tuple shape directly
/// would break every one of their ~254 existing test and production call sites. Instead, a thin per-class
/// adapter (e.g. <c>MicrosoftKeyMaterialCreator.CreateKeysWithEvent</c>) wraps one of them into this shape
/// for registration here, so a caller that still invokes a <c>Create*Keys</c> method directly keeps
/// compiling and keeps forfeiting the event — exactly as a caller that invokes a resolved
/// <see cref="SigningDelegate"/> directly forfeits <see cref="SignatureProducedEvent"/> today.
/// </para>
/// </remarks>
/// <param name="pool">The memory pool to allocate the key material from.</param>
/// <returns>
/// The created key pair, paired with an optional <see cref="KeyMaterialGeneratedEvent"/> describing the
/// operation. A creator that does not support observability returns <see langword="null"/> for the event.
/// </returns>
public delegate (PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> Keys, CryptoEvent? Event) KeyCreationDelegate(
    MemoryPool<byte> pool);


/// <summary>
/// Selects a <see cref="KeyCreationDelegate"/> based on algorithm, purpose, and optional qualifier.
/// </summary>
public delegate KeyCreationDelegate KeyCreationPatternMatcher<TDiscriminator1, TDiscriminator2>(
    TDiscriminator1 algorithm,
    TDiscriminator2 purpose,
    string? qualifier = null);


/// <summary>
/// Central dispatch mechanism for routing key-material-creation operations to backend
/// implementations — the key-creation counterpart of
/// <see cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}"/>.
/// </summary>
/// <remarks>
/// <para>
/// Register only the <c>(algorithm, purpose)</c> combinations a composition root can actually consume
/// downstream (through <see cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}"/> or the key
/// agreement registry) — a registered creation for a combination nothing can bind produces a
/// <see cref="KeyMaterialGeneratedEvent"/> for a key that then has no consumer.
/// </para>
/// <para>
/// <see cref="Initialize"/> is not thread-safe; call it once during application startup before concurrent
/// access begins. The registered matcher is immutable thereafter and safe for concurrent read access.
/// </para>
/// </remarks>
/// <typeparam name="TDiscriminator1">First discriminator type, typically <see cref="Context.CryptoAlgorithm"/>.</typeparam>
/// <typeparam name="TDiscriminator2">Second discriminator type, typically <see cref="Context.Purpose"/>.</typeparam>
public static class KeyCreationFunctionRegistry<TDiscriminator1, TDiscriminator2>
{
    private static KeyCreationPatternMatcher<TDiscriminator1, TDiscriminator2>? CreationMatcher { get; set; }


    /// <summary>
    /// Initializes the registry with a key-creation pattern matcher.
    /// </summary>
    /// <param name="creationMatcher">Pattern matcher that selects key-creation functions.</param>
    /// <remarks>
    /// Not thread-safe. Call only during application startup before concurrent access begins.
    /// </remarks>
    public static void Initialize(KeyCreationPatternMatcher<TDiscriminator1, TDiscriminator2> creationMatcher)
    {
        CreationMatcher = creationMatcher;
    }


    /// <summary>
    /// Resolves a key-creation function for the specified algorithm and purpose.
    /// </summary>
    /// <exception cref="InvalidOperationException">Thrown if the registry has not been initialized.</exception>
    public static KeyCreationDelegate ResolveCreation(TDiscriminator1 algorithm, TDiscriminator2 purpose, string? qualifier = null)
    {
        if(CreationMatcher is null)
        {
            throw new InvalidOperationException(
                "Key creation matcher has not been initialized. " +
                "Call KeyCreationFunctionRegistry.Initialize during application startup.");
        }

        return CreationMatcher(algorithm, purpose, qualifier);
    }
}
