using System.Buffers;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;

namespace Verifiable.JCose;

/// <summary>
/// COSE_Sign1 operations using secure key memory abstractions.
/// </summary>
/// <remarks>
/// <para>
/// This is the COSE equivalent of the <see cref="Jws"/> class. It provides multiple API patterns:
/// </para>
/// <list type="bullet">
/// <item><description>
/// <strong>Registry-based</strong>: Uses <see cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}"/>
/// to resolve signing/verification functions from the key's <see cref="Tag"/>.
/// </description></item>
/// <item><description>
/// <strong>Explicit function</strong>: Caller provides signing/verification functions directly,
/// useful for testing or custom cryptographic backends.
/// </description></item>
/// <item><description>
/// <strong>Resolver/Binder</strong>: Uses <see cref="KeyMaterialResolver{TResult, TContext, TState}"/>
/// and <see cref="KeyMaterialBinder{TInput, TResult, TState}"/> for complex key resolution scenarios.
/// </description></item>
/// </list>
/// <para>
/// All methods work with <see cref="CoseSign1Message"/> POCOs. CBOR serialization is handled
/// separately in <c>Verifiable.Cbor</c> via <c>CoseSerialization</c>.
/// </para>
/// </remarks>
public static class Cose
{
    /// <summary>
    /// Creates a COSE_Sign1 message using registry-resolved signing function.
    /// </summary>
    /// <param name="protectedHeaderBytes">The serialized protected header.</param>
    /// <param name="unprotectedHeader">The unprotected header map (optional).</param>
    /// <param name="payload">The payload bytes.</param>
    /// <param name="buildSigStructure">Delegate to build the Sig_structure for signing.</param>
    /// <param name="privateKey">The private key for signing.</param>
    /// <param name="signaturePool">Memory pool for signature allocation.</param>
    /// <returns>The COSE_Sign1 message containing the signature.</returns>
    public static async ValueTask<CoseSign1Message> SignAsync(
        ReadOnlyMemory<byte> protectedHeaderBytes,
        IReadOnlyDictionary<int, object>? unprotectedHeader,
        ReadOnlyMemory<byte> payload,
        BuildSigStructureDelegate buildSigStructure,
        PrivateKeyMemory privateKey,
        MemoryPool<byte> signaturePool)
    {
        ArgumentNullException.ThrowIfNull(buildSigStructure);
        ArgumentNullException.ThrowIfNull(privateKey);
        ArgumentNullException.ThrowIfNull(signaturePool);

        byte[] toBeSigned = buildSigStructure(
            protectedHeaderBytes.Span,
            payload.Span,
            []);

        CryptoAlgorithm algorithm = privateKey.Tag.Get<CryptoAlgorithm>();
        Purpose purpose = privateKey.Tag.Get<Purpose>();
        SigningDelegate signingDelegate = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveSigning(algorithm, purpose);

        Signature signatureMemory = await signingDelegate(
            privateKey.AsReadOnlyMemory(),
            toBeSigned,
            signaturePool).ConfigureAwait(false);

        return new CoseSign1Message(
            protectedHeaderBytes,
            unprotectedHeader,
            payload,
            signatureMemory.AsReadOnlyMemory());
    }


    /// <summary>
    /// Creates a COSE_Sign1 message using an explicit signing delegate.
    /// </summary>
    /// <param name="protectedHeaderBytes">The serialized protected header.</param>
    /// <param name="unprotectedHeader">The unprotected header map (optional).</param>
    /// <param name="payload">The payload bytes.</param>
    /// <param name="buildSigStructure">Delegate to build the Sig_structure for signing.</param>
    /// <param name="privateKey">The private key for signing.</param>
    /// <param name="signingDelegate">The signing delegate to use.</param>
    /// <param name="signaturePool">Memory pool for signature allocation.</param>
    /// <returns>The COSE_Sign1 message containing the signature.</returns>
    public static async ValueTask<CoseSign1Message> SignAsync(
        ReadOnlyMemory<byte> protectedHeaderBytes,
        IReadOnlyDictionary<int, object>? unprotectedHeader,
        ReadOnlyMemory<byte> payload,
        BuildSigStructureDelegate buildSigStructure,
        PrivateKeyMemory privateKey,
        SigningDelegate signingDelegate,
        MemoryPool<byte> signaturePool)
    {
        ArgumentNullException.ThrowIfNull(buildSigStructure);
        ArgumentNullException.ThrowIfNull(privateKey);
        ArgumentNullException.ThrowIfNull(signingDelegate);
        ArgumentNullException.ThrowIfNull(signaturePool);

        byte[] toBeSigned = buildSigStructure(
            protectedHeaderBytes.Span,
            payload.Span,
            []);

        Signature signature = await signingDelegate(
            privateKey.AsReadOnlyMemory(),
            toBeSigned,
            signaturePool).ConfigureAwait(false);

        return new CoseSign1Message(
            protectedHeaderBytes,
            unprotectedHeader,
            payload,
            signature.AsReadOnlyMemory());
    }


    /// <summary>
    /// Creates a COSE_Sign1 message using an explicit bound signing function.
    /// </summary>
    /// <param name="protectedHeaderBytes">The serialized protected header.</param>
    /// <param name="unprotectedHeader">The unprotected header map (optional).</param>
    /// <param name="payload">The payload bytes.</param>
    /// <param name="buildSigStructure">Delegate to build the Sig_structure for signing.</param>
    /// <param name="privateKey">The private key for signing.</param>
    /// <param name="signingFunction">The bound signing function to use.</param>
    /// <param name="signaturePool">Memory pool for signature allocation.</param>
    /// <returns>The COSE_Sign1 message containing the signature.</returns>
    public static async ValueTask<CoseSign1Message> SignAsync(
        ReadOnlyMemory<byte> protectedHeaderBytes,
        IReadOnlyDictionary<int, object>? unprotectedHeader,
        ReadOnlyMemory<byte> payload,
        BuildSigStructureDelegate buildSigStructure,
        PrivateKeyMemory privateKey,
        SigningFunction<byte, byte, ValueTask<Signature>> signingFunction,
        MemoryPool<byte> signaturePool)
    {
        ArgumentNullException.ThrowIfNull(buildSigStructure);
        ArgumentNullException.ThrowIfNull(privateKey);
        ArgumentNullException.ThrowIfNull(signingFunction);
        ArgumentNullException.ThrowIfNull(signaturePool);

        byte[] toBeSigned = buildSigStructure(
            protectedHeaderBytes.Span,
            payload.Span,
            []);

        using Signature signature = await privateKey.SignWithKeyBytesAsync(signingFunction, toBeSigned, signaturePool).ConfigureAwait(false);

        return new CoseSign1Message(
            protectedHeaderBytes,
            unprotectedHeader,
            payload,
            signature.AsReadOnlySpan().ToArray());
    }


    /// <summary>
    /// Verifies a COSE_Sign1 message using registry-resolved verification function.
    /// </summary>
    /// <param name="message">The COSE_Sign1 message to verify.</param>
    /// <param name="buildSigStructure">Delegate to build the Sig_structure for verification.</param>
    /// <param name="publicKey">The public key for verification.</param>
    /// <returns><see langword="true"/> if the signature is valid; otherwise <see langword="false"/>.</returns>
    public static async ValueTask<bool> VerifyAsync(
        CoseSign1Message message,
        BuildSigStructureDelegate buildSigStructure,
        PublicKeyMemory publicKey)
    {
        ArgumentNullException.ThrowIfNull(message);
        ArgumentNullException.ThrowIfNull(buildSigStructure);
        ArgumentNullException.ThrowIfNull(publicKey);

        byte[] toBeSigned = buildSigStructure(
            message.ProtectedHeaderBytes.Span,
            message.Payload.Span,
            []);

        CryptoAlgorithm algorithm = publicKey.Tag.Get<CryptoAlgorithm>();
        Purpose purpose = publicKey.Tag.Get<Purpose>();
        VerificationDelegate verificationDelegate = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveVerification(algorithm, purpose);

        return await verificationDelegate(
            toBeSigned,
            message.Signature,
            publicKey.AsReadOnlyMemory()).ConfigureAwait(false);
    }


    /// <summary>
    /// Verifies a COSE_Sign1 message using an explicit verification delegate.
    /// </summary>
    /// <param name="message">The COSE_Sign1 message to verify.</param>
    /// <param name="buildSigStructure">Delegate to build the Sig_structure for verification.</param>
    /// <param name="publicKey">The public key for verification.</param>
    /// <param name="verificationDelegate">The verification delegate to use.</param>
    /// <returns><see langword="true"/> if the signature is valid; otherwise <see langword="false"/>.</returns>
    public static async ValueTask<bool> VerifyAsync(
        CoseSign1Message message,
        BuildSigStructureDelegate buildSigStructure,
        PublicKeyMemory publicKey,
        VerificationDelegate verificationDelegate)
    {
        ArgumentNullException.ThrowIfNull(message);
        ArgumentNullException.ThrowIfNull(buildSigStructure);
        ArgumentNullException.ThrowIfNull(publicKey);
        ArgumentNullException.ThrowIfNull(verificationDelegate);

        byte[] toBeSigned = buildSigStructure(
            message.ProtectedHeaderBytes.Span,
            message.Payload.Span,
            ReadOnlySpan<byte>.Empty);

        return await verificationDelegate(
            toBeSigned,
            message.Signature,
            publicKey.AsReadOnlyMemory()).ConfigureAwait(false);
    }


    /// <summary>
    /// Verifies a COSE_Sign1 message using an explicit bound verification function.
    /// </summary>
    /// <param name="message">The COSE_Sign1 message to verify.</param>
    /// <param name="buildSigStructure">Delegate to build the Sig_structure for verification.</param>
    /// <param name="publicKey">The public key for verification.</param>
    /// <param name="verificationFunction">The verification function to use.</param>
    /// <param name="pool">Memory pool for allocations.</param>
    /// <returns><see langword="true"/> if the signature is valid; otherwise <see langword="false"/>.</returns>
    public static async ValueTask<bool> VerifyAsync(
        CoseSign1Message message,
        BuildSigStructureDelegate buildSigStructure,
        PublicKeyMemory publicKey,
        VerificationFunction<byte, byte, Signature, ValueTask<bool>> verificationFunction,
        MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(message);
        ArgumentNullException.ThrowIfNull(buildSigStructure);
        ArgumentNullException.ThrowIfNull(publicKey);
        ArgumentNullException.ThrowIfNull(verificationFunction);
        ArgumentNullException.ThrowIfNull(pool);

        byte[] toBeSigned = buildSigStructure(
            message.ProtectedHeaderBytes.Span,
            message.Payload.Span,
            ReadOnlySpan<byte>.Empty);

        IMemoryOwner<byte> signatureMemory = pool.Rent(message.Signature.Length);
        message.Signature.Span.CopyTo(signatureMemory.Memory.Span);

        using var signature = new Signature(signatureMemory, publicKey.Tag);

        return await verificationFunction(publicKey.AsReadOnlyMemory(), toBeSigned, signature).ConfigureAwait(false);
    }


    /// <summary>
    /// Creates a COSE_Sign1 message using resolver/binder pattern for key resolution.
    /// </summary>
    /// <typeparam name="TResolverState">The state type for key material resolution.</typeparam>
    /// <typeparam name="TBinderState">The state type for key material binding.</typeparam>
    /// <param name="protectedHeaderBytes">The serialized protected header.</param>
    /// <param name="unprotectedHeader">The unprotected header map (optional).</param>
    /// <param name="payload">The payload bytes.</param>
    /// <param name="buildSigStructure">Delegate to build the Sig_structure for signing.</param>
    /// <param name="pool">Memory pool for signature allocation.</param>
    /// <param name="resolverState">State for key material resolution.</param>
    /// <param name="resolver">Resolves and loads private key material from context.</param>
    /// <param name="binderState">State for key material binding.</param>
    /// <param name="binder">Binds signing function to key material.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The COSE_Sign1 message containing the signature.</returns>
    /// <exception cref="InvalidOperationException">Thrown when key resolution fails.</exception>
    public static async ValueTask<CoseSign1Message> SignAsync<TResolverState, TBinderState>(
        ReadOnlyMemory<byte> protectedHeaderBytes,
        IReadOnlyDictionary<int, object>? unprotectedHeader,
        ReadOnlyMemory<byte> payload,
        BuildSigStructureDelegate buildSigStructure,
        MemoryPool<byte> pool,
        TResolverState resolverState,
        KeyMaterialResolver<PrivateKeyMemory, CoseKeyContext, TResolverState> resolver,
        TBinderState binderState,
        KeyMaterialBinder<PrivateKeyMemory, PrivateKey, TBinderState> binder,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(buildSigStructure);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentNullException.ThrowIfNull(resolver);
        ArgumentNullException.ThrowIfNull(binder);

        byte[] toBeSigned = buildSigStructure(
            protectedHeaderBytes.Span,
            payload.Span,
            []);

        var context = new CoseKeyContext(protectedHeaderBytes, unprotectedHeader, payload);

        PrivateKeyMemory? material = await resolver(context, pool, resolverState, cancellationToken).ConfigureAwait(false);

        if(material is null)
        {
            throw new InvalidOperationException("Key material resolution failed.");
        }

        using PrivateKey privateKey = await binder(material, binderState, cancellationToken).ConfigureAwait(false);
        Signature signature = await privateKey.SignAsync(toBeSigned, pool).ConfigureAwait(false);

        //TODO: Change CoseSign1Message to take Signature.
        return new CoseSign1Message(
            protectedHeaderBytes,
            unprotectedHeader,
            payload,
            signature.AsReadOnlySpan().ToArray());
    }


    /// <summary>
    /// Verifies a COSE_Sign1 message using resolver/binder pattern for key resolution.
    /// </summary>
    /// <typeparam name="TResolverState">The state type for key material resolution.</typeparam>
    /// <typeparam name="TBinderState">The state type for key material binding.</typeparam>
    /// <param name="message">The COSE_Sign1 message to verify.</param>
    /// <param name="buildSigStructure">Delegate to build the Sig_structure for verification.</param>
    /// <param name="pool">Memory pool for key material allocation.</param>
    /// <param name="resolverState">State for key material resolution.</param>
    /// <param name="resolver">Resolves and loads public key material from context.</param>
    /// <param name="binderState">State for key material binding.</param>
    /// <param name="binder">Binds verification function to key material.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns><see langword="true"/> if the signature is valid; otherwise <see langword="false"/>.</returns>
    /// <exception cref="InvalidOperationException">Thrown when key resolution fails.</exception>
    public static async ValueTask<bool> VerifyAsync<TResolverState, TBinderState>(
        CoseSign1Message message,
        BuildSigStructureDelegate buildSigStructure,
        MemoryPool<byte> pool,
        TResolverState resolverState,
        KeyMaterialResolver<PublicKeyMemory, CoseKeyContext, TResolverState> resolver,
        TBinderState binderState,
        KeyMaterialBinder<PublicKeyMemory, PublicKey, TBinderState> binder,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(message);
        ArgumentNullException.ThrowIfNull(buildSigStructure);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentNullException.ThrowIfNull(resolver);
        ArgumentNullException.ThrowIfNull(binder);

        byte[] toBeSigned = buildSigStructure(
            message.ProtectedHeaderBytes.Span,
            message.Payload.Span,
            ReadOnlySpan<byte>.Empty);

        var context = new CoseKeyContext(
            message.ProtectedHeaderBytes,
            message.UnprotectedHeader,
            message.Payload);

        PublicKeyMemory? material = await resolver(context, pool, resolverState, cancellationToken).ConfigureAwait(false) ?? throw new InvalidOperationException("Key material resolution failed.");
        Tag signatureTag = material.Tag;
        using PublicKey publicKey = await binder(material, binderState, cancellationToken).ConfigureAwait(false);

        IMemoryOwner<byte> signatureMemory = pool.Rent(message.Signature.Length);
        message.Signature.Span.CopyTo(signatureMemory.Memory.Span);

        using var signature = new Signature(signatureMemory, signatureTag);

        return await publicKey.VerifyAsync(toBeSigned, signature).ConfigureAwait(false);
    }
}