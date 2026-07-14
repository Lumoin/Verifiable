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
/// All methods work with <see cref="CoseSign1Message"/> instances that own
/// their <see cref="CoseSign1Message.ProtectedHeader"/> and
/// <see cref="CoseSign1Message.Signature"/> carriers (both pool-routed,
/// CBOM-tagged). Callers passing in a protected header transfer ownership
/// to the resulting message; disposing the message disposes both carriers.
/// CBOR serialization is handled separately in <c>Verifiable.Cbor</c> via
/// <c>CoseSerialization</c>.
/// </para>
/// </remarks>
public static class Cose
{
    /// <summary>
    /// Creates a COSE_Sign1 message using registry-resolved signing function.
    /// </summary>
    /// <param name="protectedHeader">
    /// The serialized protected header carrier (pool-routed). Ownership
    /// transfers to the returned message.
    /// </param>
    /// <param name="unprotectedHeader">The unprotected header map (optional).</param>
    /// <param name="payload">The payload bytes (borrowed; caller manages lifetime).</param>
    /// <param name="buildSigStructure">Delegate to build the Sig_structure for signing.</param>
    /// <param name="privateKey">The private key for signing.</param>
    /// <param name="signaturePool">Memory pool for signature allocation.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The COSE_Sign1 message containing the signature.</returns>
    public static ValueTask<CoseSign1Message> SignAsync(
        EncodedCoseProtectedHeader protectedHeader,
        IReadOnlyDictionary<int, object>? unprotectedHeader,
        ReadOnlyMemory<byte> payload,
        BuildSigStructureDelegate buildSigStructure,
        PrivateKeyMemory privateKey,
        MemoryPool<byte> signaturePool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(privateKey);

        CryptoAlgorithm algorithm = privateKey.Tag.Get<CryptoAlgorithm>();
        Purpose purpose = privateKey.Tag.Get<Purpose>();
        SigningDelegate signingDelegate =
            CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveSigning(algorithm, purpose);

        return SignAsync(
            protectedHeader,
            unprotectedHeader,
            payload,
            buildSigStructure,
            privateKey,
            signingDelegate,
            signaturePool,
            cancellationToken: cancellationToken);
    }


    /// <summary>
    /// Creates a COSE_Sign1 message using an explicit signing delegate.
    /// </summary>
    /// <param name="protectedHeader">
    /// The serialized protected header carrier (pool-routed). Ownership
    /// transfers to the returned message.
    /// </param>
    /// <param name="unprotectedHeader">The unprotected header map (optional).</param>
    /// <param name="payload">The payload bytes (borrowed; caller manages lifetime).</param>
    /// <param name="buildSigStructure">Delegate to build the Sig_structure for signing.</param>
    /// <param name="privateKey">The private key for signing.</param>
    /// <param name="signingDelegate">The signing delegate to use.</param>
    /// <param name="signaturePool">Memory pool for signature allocation.</param>
    /// <param name="eventSink">
    /// Receives the <see cref="SignatureProducedEvent"/> the resolved <paramref name="signingDelegate"/>
    /// constructs, or <see langword="null"/> to route it to <see cref="CryptographicKeyEvents.DefaultSink"/>
    /// (the process-wide <see cref="CryptographicKeyEvents.Events"/> stream). This overload resolves and
    /// invokes <paramref name="signingDelegate"/> directly rather than through a bound
    /// <see cref="PrivateKey"/>, so a <see cref="CryptoEventSink"/> is this call site's route — see
    /// <see cref="CryptoEventSink"/> for the two-route rationale.
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The COSE_Sign1 message containing the signature.</returns>
    public static async ValueTask<CoseSign1Message> SignAsync(
        EncodedCoseProtectedHeader protectedHeader,
        IReadOnlyDictionary<int, object>? unprotectedHeader,
        ReadOnlyMemory<byte> payload,
        BuildSigStructureDelegate buildSigStructure,
        PrivateKeyMemory privateKey,
        SigningDelegate signingDelegate,
        MemoryPool<byte> signaturePool,
        CryptoEventSink? eventSink = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(protectedHeader);
        ArgumentNullException.ThrowIfNull(buildSigStructure);
        ArgumentNullException.ThrowIfNull(privateKey);
        ArgumentNullException.ThrowIfNull(signingDelegate);
        ArgumentNullException.ThrowIfNull(signaturePool);

        cancellationToken.ThrowIfCancellationRequested();

        byte[] toBeSigned = buildSigStructure(
            protectedHeader.AsReadOnlySpan(),
            payload.Span,
            []);

        (Signature signature, CryptoEvent? evt) = await signingDelegate(
            privateKey.AsReadOnlyMemory(),
            toBeSigned,
            signaturePool,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        if(evt is not null)
        {
            (eventSink ?? CryptographicKeyEvents.DefaultSink)(evt);
        }

        return new CoseSign1Message(
            protectedHeader,
            unprotectedHeader,
            payload,
            signature);
    }


    /// <summary>
    /// Creates a COSE_Sign1 message using an explicit bound signing function.
    /// </summary>
    /// <param name="protectedHeader">
    /// The serialized protected header carrier (pool-routed). Ownership
    /// transfers to the returned message.
    /// </param>
    /// <param name="unprotectedHeader">The unprotected header map (optional).</param>
    /// <param name="payload">The payload bytes (borrowed; caller manages lifetime).</param>
    /// <param name="buildSigStructure">Delegate to build the Sig_structure for signing.</param>
    /// <param name="privateKey">The private key for signing.</param>
    /// <param name="signingFunction">The bound signing function to use.</param>
    /// <param name="signaturePool">Memory pool for signature allocation.</param>
    /// <returns>The COSE_Sign1 message containing the signature.</returns>
    public static async ValueTask<CoseSign1Message> SignAsync(
        EncodedCoseProtectedHeader protectedHeader,
        IReadOnlyDictionary<int, object>? unprotectedHeader,
        ReadOnlyMemory<byte> payload,
        BuildSigStructureDelegate buildSigStructure,
        PrivateKeyMemory privateKey,
        SigningFunction<byte, byte, ValueTask<Signature>> signingFunction,
        MemoryPool<byte> signaturePool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(protectedHeader);
        ArgumentNullException.ThrowIfNull(buildSigStructure);
        ArgumentNullException.ThrowIfNull(privateKey);
        ArgumentNullException.ThrowIfNull(signingFunction);
        ArgumentNullException.ThrowIfNull(signaturePool);

        cancellationToken.ThrowIfCancellationRequested();

        byte[] toBeSigned = buildSigStructure(
            protectedHeader.AsReadOnlySpan(),
            payload.Span,
            []);

        Signature signature = await privateKey.WithKeyBytesAsync(signingFunction, toBeSigned, signaturePool).ConfigureAwait(false);

        return new CoseSign1Message(
            protectedHeader,
            unprotectedHeader,
            payload,
            signature);
    }


    /// <summary>
    /// Verifies a COSE_Sign1 message using registry-resolved verification function.
    /// </summary>
    /// <param name="message">The COSE_Sign1 message to verify.</param>
    /// <param name="buildSigStructure">Delegate to build the Sig_structure for verification.</param>
    /// <param name="publicKey">The public key for verification.</param>
    /// <returns><see langword="true"/> if the signature is valid; otherwise <see langword="false"/>.</returns>
    public static ValueTask<bool> VerifyAsync(
        CoseSign1Message message,
        BuildSigStructureDelegate buildSigStructure,
        PublicKeyMemory publicKey,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(publicKey);

        CryptoAlgorithm algorithm = publicKey.Tag.Get<CryptoAlgorithm>();
        Purpose purpose = publicKey.Tag.Get<Purpose>();
        VerificationDelegate verificationDelegate =
            CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveVerification(algorithm, purpose);

        return VerifyAsync(
            message,
            buildSigStructure,
            publicKey,
            verificationDelegate,
            cancellationToken: cancellationToken);
    }


    /// <summary>
    /// Verifies a COSE_Sign1 message using an explicit verification delegate.
    /// </summary>
    /// <param name="message">The COSE_Sign1 message to verify.</param>
    /// <param name="buildSigStructure">Delegate to build the Sig_structure for verification.</param>
    /// <param name="publicKey">The public key for verification.</param>
    /// <param name="verificationDelegate">The verification delegate to use.</param>
    /// <param name="eventSink">
    /// Receives the <see cref="VerificationCompletedEvent"/> the resolved <paramref name="verificationDelegate"/>
    /// constructs, or <see langword="null"/> to route it to <see cref="CryptographicKeyEvents.DefaultSink"/>.
    /// This overload resolves and invokes <paramref name="verificationDelegate"/> directly rather than
    /// through a bound <see cref="PublicKey"/>, so a <see cref="CryptoEventSink"/> is this call site's
    /// route — see <see cref="CryptoEventSink"/>.
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns><see langword="true"/> if the signature is valid; otherwise <see langword="false"/>.</returns>
    public static async ValueTask<bool> VerifyAsync(
        CoseSign1Message message,
        BuildSigStructureDelegate buildSigStructure,
        PublicKeyMemory publicKey,
        VerificationDelegate verificationDelegate,
        CryptoEventSink? eventSink = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(message);
        ArgumentNullException.ThrowIfNull(buildSigStructure);
        ArgumentNullException.ThrowIfNull(publicKey);
        ArgumentNullException.ThrowIfNull(verificationDelegate);

        cancellationToken.ThrowIfCancellationRequested();

        byte[] toBeSigned = buildSigStructure(
            message.ProtectedHeader.AsReadOnlySpan(),
            message.Payload.Span,
            ReadOnlySpan<byte>.Empty);

        (bool isVerified, CryptoEvent? evt) = await verificationDelegate(
            toBeSigned,
            message.Signature.AsReadOnlyMemory(),
            publicKey.AsReadOnlyMemory(),
            cancellationToken: cancellationToken).ConfigureAwait(false);

        if(evt is not null)
        {
            (eventSink ?? CryptographicKeyEvents.DefaultSink)(evt);
        }

        return isVerified;
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
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(message);
        ArgumentNullException.ThrowIfNull(buildSigStructure);
        ArgumentNullException.ThrowIfNull(publicKey);
        ArgumentNullException.ThrowIfNull(verificationFunction);
        ArgumentNullException.ThrowIfNull(pool);

        cancellationToken.ThrowIfCancellationRequested();

        byte[] toBeSigned = buildSigStructure(
            message.ProtectedHeader.AsReadOnlySpan(),
            message.Payload.Span,
            ReadOnlySpan<byte>.Empty);

        return await verificationFunction(publicKey.AsReadOnlyMemory(), toBeSigned, message.Signature).ConfigureAwait(false);
    }


    /// <summary>
    /// Creates a COSE_Sign1 message using resolver/binder pattern for key resolution.
    /// </summary>
    /// <remarks>
    /// This is the second sanctioned route <see cref="CryptoEventSink"/> describes: <paramref name="binder"/>
    /// constructs a <see cref="PrivateKey"/> around the resolved material, so signing goes through
    /// <see cref="PrivateKey.SignAsync"/> — the choke point that always emits to
    /// <see cref="CryptographicKeyEvents.Events"/> — with no <see cref="CryptoEventSink"/> parameter needed
    /// here at all. A caller already holding (or able to cheaply construct) key material uses this route; a
    /// caller that only holds raw, disassembled key material uses the sink-threaded
    /// <see cref="SignAsync(EncodedCoseProtectedHeader, IReadOnlyDictionary{int, object}?, ReadOnlyMemory{byte}, BuildSigStructureDelegate, PrivateKeyMemory, SigningDelegate, MemoryPool{byte}, CryptoEventSink?, CancellationToken)"/>
    /// overload instead. Both routes emit; neither discards.
    /// </remarks>
    /// <typeparam name="TResolverState">The state type for key material resolution.</typeparam>
    /// <typeparam name="TBinderState">The state type for key material binding.</typeparam>
    /// <param name="protectedHeader">
    /// The serialized protected header carrier (pool-routed). Ownership
    /// transfers to the returned message.
    /// </param>
    /// <param name="unprotectedHeader">The unprotected header map (optional).</param>
    /// <param name="payload">The payload bytes (borrowed; caller manages lifetime).</param>
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
        EncodedCoseProtectedHeader protectedHeader,
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
        ArgumentNullException.ThrowIfNull(protectedHeader);
        ArgumentNullException.ThrowIfNull(buildSigStructure);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentNullException.ThrowIfNull(resolver);
        ArgumentNullException.ThrowIfNull(binder);

        byte[] toBeSigned = buildSigStructure(
            protectedHeader.AsReadOnlySpan(),
            payload.Span,
            []);

        var context = new CoseKeyContext(protectedHeader.AsReadOnlyMemory(), unprotectedHeader, payload);

        PrivateKeyMemory? material = await resolver(context, pool, resolverState, cancellationToken).ConfigureAwait(false);

        if(material is null)
        {
            throw new InvalidOperationException("Key material resolution failed.");
        }

        using PrivateKey privateKey = await binder(material, binderState, cancellationToken).ConfigureAwait(false);
        Signature signature = await privateKey.SignAsync(toBeSigned, pool).ConfigureAwait(false);

        return new CoseSign1Message(
            protectedHeader,
            unprotectedHeader,
            payload,
            signature);
    }


    /// <summary>
    /// Verifies a COSE_Sign1 message using resolver/binder pattern for key resolution.
    /// </summary>
    /// <remarks>
    /// The verify-side counterpart of the resolver/binder <c>SignAsync</c> overload's remarks: <paramref name="binder"/>
    /// constructs a <see cref="PublicKey"/>, so verification goes through <see cref="PublicKey.VerifyAsync"/>
    /// and emits with no <see cref="CryptoEventSink"/> parameter needed.
    /// </remarks>
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
            message.ProtectedHeader.AsReadOnlySpan(),
            message.Payload.Span,
            ReadOnlySpan<byte>.Empty);

        var context = new CoseKeyContext(
            message.ProtectedHeader.AsReadOnlyMemory(),
            message.UnprotectedHeader,
            message.Payload);

        PublicKeyMemory? material = await resolver(context, pool, resolverState, cancellationToken).ConfigureAwait(false) ?? throw new InvalidOperationException("Key material resolution failed.");
        using PublicKey publicKey = await binder(material, binderState, cancellationToken).ConfigureAwait(false);

        return await publicKey.VerifyAsync(toBeSigned, message.Signature).ConfigureAwait(false);
    }
}
