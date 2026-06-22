using Verifiable.Cryptography.Context;

namespace Verifiable.Cryptography.Aead;

/// <summary>
/// Delegate that selects a <see cref="KeyAgreementEncryptDelegate"/> based on algorithm and purpose.
/// </summary>
public delegate KeyAgreementEncryptDelegate KeyAgreementEncryptPatternMatcher<TDiscriminator1, TDiscriminator2>(
    TDiscriminator1 algorithm,
    TDiscriminator2 purpose,
    string? qualifier = null);


/// <summary>
/// Delegate that selects a <see cref="KeyAgreementDecryptDelegate"/> based on algorithm and purpose.
/// </summary>
public delegate KeyAgreementDecryptDelegate KeyAgreementDecryptPatternMatcher<TDiscriminator1, TDiscriminator2>(
    TDiscriminator1 algorithm,
    TDiscriminator2 purpose,
    string? qualifier = null);


/// <summary>
/// Delegate that selects a <see cref="KeyDerivationDelegate"/> based on algorithm and purpose.
/// </summary>
public delegate KeyDerivationDelegate KeyDerivationPatternMatcher<TDiscriminator1, TDiscriminator2>(
    TDiscriminator1 algorithm,
    TDiscriminator2 purpose,
    string? qualifier = null);


/// <summary>
/// Delegate that selects an <see cref="AeadEncryptDelegate"/> based on algorithm and purpose.
/// </summary>
public delegate AeadEncryptDelegate AeadEncryptPatternMatcher<TDiscriminator1, TDiscriminator2>(
    TDiscriminator1 algorithm,
    TDiscriminator2 purpose,
    string? qualifier = null);


/// <summary>
/// Delegate that selects an <see cref="AeadDecryptDelegate"/> based on algorithm and purpose.
/// </summary>
public delegate AeadDecryptDelegate AeadDecryptPatternMatcher<TDiscriminator1, TDiscriminator2>(
    TDiscriminator1 algorithm,
    TDiscriminator2 purpose,
    string? qualifier = null);


/// <summary>
/// Delegate that selects a <see cref="KemDecapsulationDelegate"/> based on algorithm and purpose.
/// </summary>
public delegate KemDecapsulationDelegate KemDecapsulationPatternMatcher<TDiscriminator1, TDiscriminator2>(
    TDiscriminator1 algorithm,
    TDiscriminator2 purpose,
    string? qualifier = null);


/// <summary>
/// Delegate that selects an <see cref="AuthenticatedKeyAgreementEncryptDelegate"/> based on algorithm and purpose.
/// </summary>
public delegate AuthenticatedKeyAgreementEncryptDelegate AuthenticatedKeyAgreementEncryptPatternMatcher<TDiscriminator1, TDiscriminator2>(
    TDiscriminator1 algorithm,
    TDiscriminator2 purpose,
    string? qualifier = null);


/// <summary>
/// Delegate that selects an <see cref="AuthenticatedKeyAgreementDecryptDelegate"/> based on algorithm and purpose.
/// </summary>
public delegate AuthenticatedKeyAgreementDecryptDelegate AuthenticatedKeyAgreementDecryptPatternMatcher<TDiscriminator1, TDiscriminator2>(
    TDiscriminator1 algorithm,
    TDiscriminator2 purpose,
    string? qualifier = null);


/// <summary>
/// Delegate that selects an <see cref="AuthenticatedKeyDerivationDelegate"/> based on algorithm and purpose.
/// </summary>
public delegate AuthenticatedKeyDerivationDelegate AuthenticatedKeyDerivationPatternMatcher<TDiscriminator1, TDiscriminator2>(
    TDiscriminator1 algorithm,
    TDiscriminator2 purpose,
    string? qualifier = null);


/// <summary>
/// Delegate that selects a <see cref="KeyWrapDelegate"/> based on algorithm and purpose.
/// </summary>
public delegate KeyWrapDelegate KeyWrapPatternMatcher<TDiscriminator1, TDiscriminator2>(
    TDiscriminator1 algorithm,
    TDiscriminator2 purpose,
    string? qualifier = null);


/// <summary>
/// Delegate that selects a <see cref="KeyUnwrapDelegate"/> based on algorithm and purpose.
/// </summary>
public delegate KeyUnwrapDelegate KeyUnwrapPatternMatcher<TDiscriminator1, TDiscriminator2>(
    TDiscriminator1 algorithm,
    TDiscriminator2 purpose,
    string? qualifier = null);


/// <summary>
/// Delegate that selects a <see cref="MultiRecipientKeyAgreementEncryptDelegate"/> based on algorithm and purpose.
/// </summary>
public delegate MultiRecipientKeyAgreementEncryptDelegate MultiRecipientKeyAgreementEncryptPatternMatcher<TDiscriminator1, TDiscriminator2>(
    TDiscriminator1 algorithm,
    TDiscriminator2 purpose,
    string? qualifier = null);


/// <summary>
/// Delegate that selects a <see cref="MultiRecipientAuthenticatedKeyAgreementEncryptDelegate"/> based on algorithm and purpose.
/// </summary>
public delegate MultiRecipientAuthenticatedKeyAgreementEncryptDelegate MultiRecipientAuthenticatedKeyAgreementEncryptPatternMatcher<TDiscriminator1, TDiscriminator2>(
    TDiscriminator1 algorithm,
    TDiscriminator2 purpose,
    string? qualifier = null);


/// <summary>
/// Central dispatch mechanism for routing key agreement, key derivation, symmetric
/// encryption and decryption, and KEM decapsulation operations to backend implementations.
/// </summary>
/// <remarks>
/// <para>
/// The five ECDH-ES operations are kept separate so each can be backed by a different
/// hardware boundary:
/// </para>
/// <list type="bullet">
/// <item><description>
/// Encrypt-side ECDH (TPM2_ECDH_KeyGen or software) →
/// <see cref="ResolveAgreementEncrypt"/>.
/// </description></item>
/// <item><description>
/// Decrypt-side ECDH (TPM2_ECDH_ZGen or software) →
/// <see cref="ResolveAgreementDecrypt"/>.
/// </description></item>
/// <item><description>
/// Key derivation (always software, pure math) → <see cref="ResolveKeyDerivation"/>.
/// </description></item>
/// <item><description>
/// Symmetric encryption (AES-GCM, software or HSM) →
/// <see cref="ResolveAeadEncrypt"/>.
/// </description></item>
/// <item><description>
/// Symmetric decryption (AES-GCM, software or HSM) →
/// <see cref="ResolveAeadDecrypt"/>.
/// </description></item>
/// </list>
/// <para>
/// Register backends at application startup before any concurrent access begins.
/// <see cref="Initialize"/> is not thread-safe and must be called exactly once.
/// </para>
/// </remarks>
/// <typeparam name="TDiscriminator1">First discriminator type, typically <see cref="CryptoAlgorithm"/>.</typeparam>
/// <typeparam name="TDiscriminator2">Second discriminator type, typically <see cref="Purpose"/>.</typeparam>
public static class KeyAgreementFunctionRegistry<TDiscriminator1, TDiscriminator2>
{
    private static KeyAgreementEncryptPatternMatcher<TDiscriminator1, TDiscriminator2>? agreementEncryptMatcher;
    private static KeyAgreementDecryptPatternMatcher<TDiscriminator1, TDiscriminator2>? agreementDecryptMatcher;
    private static KeyDerivationPatternMatcher<TDiscriminator1, TDiscriminator2>? keyDerivationMatcher;
    private static AeadEncryptPatternMatcher<TDiscriminator1, TDiscriminator2>? aeadEncryptMatcher;
    private static AeadDecryptPatternMatcher<TDiscriminator1, TDiscriminator2>? aeadDecryptMatcher;
    private static KemDecapsulationPatternMatcher<TDiscriminator1, TDiscriminator2>? kemMatcher;
    private static AuthenticatedKeyAgreementEncryptPatternMatcher<TDiscriminator1, TDiscriminator2>? authenticatedAgreementEncryptMatcher;
    private static AuthenticatedKeyAgreementDecryptPatternMatcher<TDiscriminator1, TDiscriminator2>? authenticatedAgreementDecryptMatcher;
    private static AuthenticatedKeyDerivationPatternMatcher<TDiscriminator1, TDiscriminator2>? authenticatedDerivationMatcher;
    private static KeyWrapPatternMatcher<TDiscriminator1, TDiscriminator2>? keyWrapMatcher;
    private static KeyUnwrapPatternMatcher<TDiscriminator1, TDiscriminator2>? keyUnwrapMatcher;
    private static MultiRecipientKeyAgreementEncryptPatternMatcher<TDiscriminator1, TDiscriminator2>? multiRecipientAgreementEncryptMatcher;
    private static MultiRecipientAuthenticatedKeyAgreementEncryptPatternMatcher<TDiscriminator1, TDiscriminator2>? multiRecipientAuthenticatedAgreementEncryptMatcher;


    /// <summary>
    /// Initializes the registry with matchers for each operation.
    /// Pass <see langword="null"/> for any matcher that is not needed.
    /// </summary>
    public static void Initialize(
        KeyAgreementEncryptPatternMatcher<TDiscriminator1, TDiscriminator2>? keyAgreementEncryptMatcher,
        KeyAgreementDecryptPatternMatcher<TDiscriminator1, TDiscriminator2>? keyAgreementDecryptMatcher,
        KeyDerivationPatternMatcher<TDiscriminator1, TDiscriminator2>? derivationMatcher,
        AeadEncryptPatternMatcher<TDiscriminator1, TDiscriminator2>? encryptMatcher,
        AeadDecryptPatternMatcher<TDiscriminator1, TDiscriminator2>? decryptMatcher,
        KemDecapsulationPatternMatcher<TDiscriminator1, TDiscriminator2>? kemDecapsulationMatcher,
        AuthenticatedKeyAgreementEncryptPatternMatcher<TDiscriminator1, TDiscriminator2>? authenticatedKeyAgreementEncryptMatcher = null,
        AuthenticatedKeyAgreementDecryptPatternMatcher<TDiscriminator1, TDiscriminator2>? authenticatedKeyAgreementDecryptMatcher = null,
        AuthenticatedKeyDerivationPatternMatcher<TDiscriminator1, TDiscriminator2>? authenticatedKeyDerivationMatcher = null,
        KeyWrapPatternMatcher<TDiscriminator1, TDiscriminator2>? wrapMatcher = null,
        KeyUnwrapPatternMatcher<TDiscriminator1, TDiscriminator2>? unwrapMatcher = null,
        MultiRecipientKeyAgreementEncryptPatternMatcher<TDiscriminator1, TDiscriminator2>? multiRecipientKeyAgreementEncryptMatcher = null,
        MultiRecipientAuthenticatedKeyAgreementEncryptPatternMatcher<TDiscriminator1, TDiscriminator2>? multiRecipientAuthenticatedKeyAgreementEncryptMatcher = null)
    {
        agreementEncryptMatcher = keyAgreementEncryptMatcher;
        agreementDecryptMatcher = keyAgreementDecryptMatcher;
        keyDerivationMatcher = derivationMatcher;
        aeadEncryptMatcher = encryptMatcher;
        aeadDecryptMatcher = decryptMatcher;
        kemMatcher = kemDecapsulationMatcher;
        authenticatedAgreementEncryptMatcher = authenticatedKeyAgreementEncryptMatcher;
        authenticatedAgreementDecryptMatcher = authenticatedKeyAgreementDecryptMatcher;
        authenticatedDerivationMatcher = authenticatedKeyDerivationMatcher;
        keyWrapMatcher = wrapMatcher;
        keyUnwrapMatcher = unwrapMatcher;
        multiRecipientAgreementEncryptMatcher = multiRecipientKeyAgreementEncryptMatcher;
        multiRecipientAuthenticatedAgreementEncryptMatcher = multiRecipientAuthenticatedKeyAgreementEncryptMatcher;
    }


    /// <summary>Resolves the encrypt-side key agreement delegate.</summary>
    public static KeyAgreementEncryptDelegate ResolveAgreementEncrypt(
        TDiscriminator1 algorithm, TDiscriminator2 purpose, string? qualifier = null)
    {
        if(agreementEncryptMatcher is null)
        {
            throw new InvalidOperationException(
                "Key agreement encrypt matcher has not been initialized. " +
                "Call KeyAgreementFunctionRegistry.Initialize during application startup.");
        }

        return agreementEncryptMatcher(algorithm, purpose, qualifier);
    }


    /// <summary>Resolves the decrypt-side key agreement delegate.</summary>
    public static KeyAgreementDecryptDelegate ResolveAgreementDecrypt(
        TDiscriminator1 algorithm, TDiscriminator2 purpose, string? qualifier = null)
    {
        if(agreementDecryptMatcher is null)
        {
            throw new InvalidOperationException(
                "Key agreement decrypt matcher has not been initialized. " +
                "Call KeyAgreementFunctionRegistry.Initialize during application startup.");
        }

        return agreementDecryptMatcher(algorithm, purpose, qualifier);
    }


    /// <summary>Resolves the key derivation delegate.</summary>
    public static KeyDerivationDelegate ResolveKeyDerivation(
        TDiscriminator1 algorithm, TDiscriminator2 purpose, string? qualifier = null)
    {
        if(keyDerivationMatcher is null)
        {
            throw new InvalidOperationException(
                "Key derivation matcher has not been initialized. " +
                "Call KeyAgreementFunctionRegistry.Initialize during application startup.");
        }

        return keyDerivationMatcher(algorithm, purpose, qualifier);
    }


    /// <summary>Resolves the AEAD encrypt delegate.</summary>
    public static AeadEncryptDelegate ResolveAeadEncrypt(
        TDiscriminator1 algorithm, TDiscriminator2 purpose, string? qualifier = null)
    {
        if(aeadEncryptMatcher is null)
        {
            throw new InvalidOperationException(
                "AEAD encrypt matcher has not been initialized. " +
                "Call KeyAgreementFunctionRegistry.Initialize during application startup.");
        }

        return aeadEncryptMatcher(algorithm, purpose, qualifier);
    }


    /// <summary>Resolves the AEAD decrypt delegate.</summary>
    public static AeadDecryptDelegate ResolveAeadDecrypt(
        TDiscriminator1 algorithm, TDiscriminator2 purpose, string? qualifier = null)
    {
        if(aeadDecryptMatcher is null)
        {
            throw new InvalidOperationException(
                "AEAD decrypt matcher has not been initialized. " +
                "Call KeyAgreementFunctionRegistry.Initialize during application startup.");
        }

        return aeadDecryptMatcher(algorithm, purpose, qualifier);
    }


    /// <summary>Resolves the KEM decapsulation delegate.</summary>
    public static KemDecapsulationDelegate ResolveKem(
        TDiscriminator1 algorithm, TDiscriminator2 purpose, string? qualifier = null)
    {
        if(kemMatcher is null)
        {
            throw new InvalidOperationException(
                "KEM decapsulation matcher has not been initialized. " +
                "Call KeyAgreementFunctionRegistry.Initialize during application startup.");
        }

        return kemMatcher(algorithm, purpose, qualifier);
    }


    /// <summary>Resolves the encrypt-side ECDH-1PU authenticated key agreement delegate.</summary>
    public static AuthenticatedKeyAgreementEncryptDelegate ResolveAuthenticatedAgreementEncrypt(
        TDiscriminator1 algorithm, TDiscriminator2 purpose, string? qualifier = null)
    {
        if(authenticatedAgreementEncryptMatcher is null)
        {
            throw new InvalidOperationException(
                "Authenticated key agreement encrypt matcher has not been initialized. " +
                "Call KeyAgreementFunctionRegistry.Initialize during application startup.");
        }

        return authenticatedAgreementEncryptMatcher(algorithm, purpose, qualifier);
    }


    /// <summary>Resolves the decrypt-side ECDH-1PU authenticated key agreement delegate.</summary>
    public static AuthenticatedKeyAgreementDecryptDelegate ResolveAuthenticatedAgreementDecrypt(
        TDiscriminator1 algorithm, TDiscriminator2 purpose, string? qualifier = null)
    {
        if(authenticatedAgreementDecryptMatcher is null)
        {
            throw new InvalidOperationException(
                "Authenticated key agreement decrypt matcher has not been initialized. " +
                "Call KeyAgreementFunctionRegistry.Initialize during application startup.");
        }

        return authenticatedAgreementDecryptMatcher(algorithm, purpose, qualifier);
    }


    /// <summary>Resolves the ECDH-1PU key derivation delegate with tag commitment.</summary>
    public static AuthenticatedKeyDerivationDelegate ResolveAuthenticatedKeyDerivation(
        TDiscriminator1 algorithm, TDiscriminator2 purpose, string? qualifier = null)
    {
        if(authenticatedDerivationMatcher is null)
        {
            throw new InvalidOperationException(
                "Authenticated key derivation matcher has not been initialized. " +
                "Call KeyAgreementFunctionRegistry.Initialize during application startup.");
        }

        return authenticatedDerivationMatcher(algorithm, purpose, qualifier);
    }


    /// <summary>Resolves the key wrap delegate.</summary>
    public static KeyWrapDelegate ResolveKeyWrap(
        TDiscriminator1 algorithm, TDiscriminator2 purpose, string? qualifier = null)
    {
        if(keyWrapMatcher is null)
        {
            throw new InvalidOperationException(
                "Key wrap matcher has not been initialized. " +
                "Call KeyAgreementFunctionRegistry.Initialize during application startup.");
        }

        return keyWrapMatcher(algorithm, purpose, qualifier);
    }


    /// <summary>Resolves the key unwrap delegate.</summary>
    public static KeyUnwrapDelegate ResolveKeyUnwrap(
        TDiscriminator1 algorithm, TDiscriminator2 purpose, string? qualifier = null)
    {
        if(keyUnwrapMatcher is null)
        {
            throw new InvalidOperationException(
                "Key unwrap matcher has not been initialized. " +
                "Call KeyAgreementFunctionRegistry.Initialize during application startup.");
        }

        return keyUnwrapMatcher(algorithm, purpose, qualifier);
    }


    /// <summary>Resolves the multi-recipient ECDH-ES encrypt-side agreement delegate (shared ephemeral key).</summary>
    public static MultiRecipientKeyAgreementEncryptDelegate ResolveMultiRecipientAgreementEncrypt(
        TDiscriminator1 algorithm, TDiscriminator2 purpose, string? qualifier = null)
    {
        if(multiRecipientAgreementEncryptMatcher is null)
        {
            throw new InvalidOperationException(
                "Multi-recipient key agreement encrypt matcher has not been initialized. " +
                "Call KeyAgreementFunctionRegistry.Initialize during application startup.");
        }

        return multiRecipientAgreementEncryptMatcher(algorithm, purpose, qualifier);
    }


    /// <summary>Resolves the multi-recipient ECDH-1PU encrypt-side agreement delegate (shared ephemeral key).</summary>
    public static MultiRecipientAuthenticatedKeyAgreementEncryptDelegate ResolveMultiRecipientAuthenticatedAgreementEncrypt(
        TDiscriminator1 algorithm, TDiscriminator2 purpose, string? qualifier = null)
    {
        if(multiRecipientAuthenticatedAgreementEncryptMatcher is null)
        {
            throw new InvalidOperationException(
                "Multi-recipient authenticated key agreement encrypt matcher has not been initialized. " +
                "Call KeyAgreementFunctionRegistry.Initialize during application startup.");
        }

        return multiRecipientAuthenticatedAgreementEncryptMatcher(algorithm, purpose, qualifier);
    }
}
