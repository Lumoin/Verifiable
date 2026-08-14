using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;

namespace Verifiable.JCose;

/// <summary>
/// RFC 9338 version 2 countersignature operations using secure key memory abstractions.
/// </summary>
/// <remarks>
/// <para>
/// The countersignature counterpart of <see cref="CoseSign"/>/<see cref="Cose"/>: builds the
/// Countersign_structure (<see href="https://www.rfc-editor.org/rfc/rfc9338#section-3.3">RFC
/// 9338 §3.3</see>) for one of the two ETSI-relevant <see cref="CountersignTarget"/> shapes,
/// then signs or verifies through the same crypto delegate seams <see cref="Cose"/> uses.
/// </para>
/// <para>
/// All methods work with <see cref="CounterSignatureV2"/>/<see cref="CounterSignature0V2"/>
/// instances that own their pool-routed, CBOM-tagged carriers. Callers passing in a protected
/// header transfer ownership to the resulting countersignature; disposing it disposes every
/// carrier it owns.
/// </para>
/// </remarks>
public static class CoseCounterSign
{
    /// <summary>
    /// Creates a full <see cref="CounterSignatureV2"/> over <paramref name="target"/> using a
    /// registry-resolved signing function.
    /// </summary>
    /// <param name="target">The countersigned target.</param>
    /// <param name="counterSignerProtectedHeader">
    /// The countersigner's own serialized protected header carrier (pool-routed) — RFC 9338
    /// §3.3's own <c>sign_protected</c> field. Ownership transfers to the returned countersignature.
    /// </param>
    /// <param name="counterSignerUnprotectedHeader">The countersigner's own unprotected header map, if any.</param>
    /// <param name="externalAad">The externally supplied additional authenticated data (usually empty).</param>
    /// <param name="buildCountersignStructure">Delegate to build the Countersign_structure.</param>
    /// <param name="privateKey">The countersigner's private key.</param>
    /// <param name="signaturePool">Memory pool for signature allocation.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The full countersignature.</returns>
    public static ValueTask<CounterSignatureV2> CountersignFullAsync(
        CountersignTarget target,
        EncodedCoseProtectedHeader counterSignerProtectedHeader,
        IReadOnlyDictionary<int, object>? counterSignerUnprotectedHeader,
        ReadOnlyMemory<byte> externalAad,
        BuildCountersignStructureDelegate buildCountersignStructure,
        PrivateKeyMemory privateKey,
        BaseMemoryPool signaturePool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(privateKey);

        CryptoAlgorithm algorithm = privateKey.Tag.Get<CryptoAlgorithm>();
        Purpose purpose = privateKey.Tag.Get<Purpose>();
        SigningDelegate signingDelegate = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveSigning(algorithm, purpose);

        return CountersignFullAsync(
            target,
            counterSignerProtectedHeader,
            counterSignerUnprotectedHeader,
            externalAad,
            buildCountersignStructure,
            privateKey,
            signingDelegate,
            signaturePool,
            cancellationToken: cancellationToken);
    }


    /// <summary>
    /// Creates a full <see cref="CounterSignatureV2"/> over <paramref name="target"/> using an
    /// explicit signing delegate.
    /// </summary>
    /// <param name="target">The countersigned target.</param>
    /// <param name="counterSignerProtectedHeader">
    /// The countersigner's own serialized protected header carrier (pool-routed).
    /// <strong>Consumed:</strong> once every argument-null check above has passed, this call spends
    /// <paramref name="counterSignerProtectedHeader"/> regardless of outcome — ownership transfers to the
    /// returned countersignature on success; on a cancellation or a <paramref name="signingDelegate"/>
    /// throw, this call disposes it itself before rethrowing, so the caller never disposes it either way.
    /// </param>
    /// <param name="counterSignerUnprotectedHeader">The countersigner's own unprotected header map, if any.</param>
    /// <param name="externalAad">The externally supplied additional authenticated data (usually empty).</param>
    /// <param name="buildCountersignStructure">Delegate to build the Countersign_structure.</param>
    /// <param name="privateKey">The countersigner's private key.</param>
    /// <param name="signingDelegate">The signing delegate to use.</param>
    /// <param name="signaturePool">Memory pool for signature allocation.</param>
    /// <param name="eventSink">
    /// Receives the <see cref="SignatureProducedEvent"/> the resolved
    /// <paramref name="signingDelegate"/> constructs, or <see langword="null"/> to route it to
    /// <see cref="CryptographicKeyEvents.DefaultSink"/>. See <see cref="CryptoEventSink"/> for
    /// the two-route rationale <see cref="Cose"/> documents.
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The full countersignature.</returns>
    public static async ValueTask<CounterSignatureV2> CountersignFullAsync(
        CountersignTarget target,
        EncodedCoseProtectedHeader counterSignerProtectedHeader,
        IReadOnlyDictionary<int, object>? counterSignerUnprotectedHeader,
        ReadOnlyMemory<byte> externalAad,
        BuildCountersignStructureDelegate buildCountersignStructure,
        PrivateKeyMemory privateKey,
        SigningDelegate signingDelegate,
        BaseMemoryPool signaturePool,
        CryptoEventSink? eventSink = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(target);
        ArgumentNullException.ThrowIfNull(counterSignerProtectedHeader);
        ArgumentNullException.ThrowIfNull(buildCountersignStructure);
        ArgumentNullException.ThrowIfNull(privateKey);
        ArgumentNullException.ThrowIfNull(signingDelegate);
        ArgumentNullException.ThrowIfNull(signaturePool);

        try
        {
            cancellationToken.ThrowIfCancellationRequested();

            CountersignStructureInput input = CountersignStructureInput.ForTarget(
                target, isAbbreviated: false, counterSignerProtectedHeader.AsReadOnlyMemory(), externalAad);

            byte[] toBeSigned = buildCountersignStructure(input);

            (Signature signature, CryptoEvent? evt) = await signingDelegate(
                privateKey.AsReadOnlyMemory(), toBeSigned, signaturePool, cancellationToken: cancellationToken).ConfigureAwait(false);

            if(evt is not null)
            {
                (eventSink ?? CryptographicKeyEvents.DefaultSink)(evt);
            }

            return new CounterSignatureV2(new CoseSignatureComponent(counterSignerProtectedHeader, counterSignerUnprotectedHeader, signature));
        }
        catch
        {
            //Metered custody: counterSignerProtectedHeader is consumed by this call from here on --
            //ownership transfers to the returned countersignature only on the success path above, so a
            //cancellation or a signing-delegate throw must not orphan the caller-supplied carrier.
            counterSignerProtectedHeader.Dispose();

            throw;
        }
    }


    /// <summary>
    /// Creates an abbreviated <see cref="CounterSignature0V2"/> over <paramref name="target"/>
    /// using a registry-resolved signing function.
    /// </summary>
    /// <param name="target">The countersigned target.</param>
    /// <param name="externalAad">The externally supplied additional authenticated data (usually empty).</param>
    /// <param name="buildCountersignStructure">Delegate to build the Countersign_structure.</param>
    /// <param name="privateKey">The countersigner's private key.</param>
    /// <param name="signaturePool">Memory pool for signature allocation.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The abbreviated countersignature.</returns>
    public static ValueTask<CounterSignature0V2> CountersignAbbreviatedAsync(
        CountersignTarget target,
        ReadOnlyMemory<byte> externalAad,
        BuildCountersignStructureDelegate buildCountersignStructure,
        PrivateKeyMemory privateKey,
        BaseMemoryPool signaturePool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(privateKey);

        CryptoAlgorithm algorithm = privateKey.Tag.Get<CryptoAlgorithm>();
        Purpose purpose = privateKey.Tag.Get<Purpose>();
        SigningDelegate signingDelegate = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveSigning(algorithm, purpose);

        return CountersignAbbreviatedAsync(
            target, externalAad, buildCountersignStructure, privateKey, signingDelegate, signaturePool, cancellationToken: cancellationToken);
    }


    /// <summary>
    /// Creates an abbreviated <see cref="CounterSignature0V2"/> over <paramref name="target"/>
    /// using an explicit signing delegate.
    /// </summary>
    /// <param name="target">The countersigned target.</param>
    /// <param name="externalAad">The externally supplied additional authenticated data (usually empty).</param>
    /// <param name="buildCountersignStructure">Delegate to build the Countersign_structure.</param>
    /// <param name="privateKey">The countersigner's private key.</param>
    /// <param name="signingDelegate">The signing delegate to use.</param>
    /// <param name="signaturePool">Memory pool for signature allocation.</param>
    /// <param name="eventSink">
    /// Receives the <see cref="SignatureProducedEvent"/> the resolved
    /// <paramref name="signingDelegate"/> constructs, or <see langword="null"/> to route it to
    /// <see cref="CryptographicKeyEvents.DefaultSink"/>.
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The abbreviated countersignature.</returns>
    public static async ValueTask<CounterSignature0V2> CountersignAbbreviatedAsync(
        CountersignTarget target,
        ReadOnlyMemory<byte> externalAad,
        BuildCountersignStructureDelegate buildCountersignStructure,
        PrivateKeyMemory privateKey,
        SigningDelegate signingDelegate,
        BaseMemoryPool signaturePool,
        CryptoEventSink? eventSink = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(target);
        ArgumentNullException.ThrowIfNull(buildCountersignStructure);
        ArgumentNullException.ThrowIfNull(privateKey);
        ArgumentNullException.ThrowIfNull(signingDelegate);
        ArgumentNullException.ThrowIfNull(signaturePool);

        cancellationToken.ThrowIfCancellationRequested();

        CountersignStructureInput input = CountersignStructureInput.ForTarget(target, isAbbreviated: true, signProtected: null, externalAad);

        byte[] toBeSigned = buildCountersignStructure(input);

        (Signature signature, CryptoEvent? evt) = await signingDelegate(
            privateKey.AsReadOnlyMemory(), toBeSigned, signaturePool, cancellationToken: cancellationToken).ConfigureAwait(false);

        if(evt is not null)
        {
            (eventSink ?? CryptographicKeyEvents.DefaultSink)(evt);
        }

        return new CounterSignature0V2(signature);
    }


    /// <summary>
    /// Verifies <paramref name="counterSignature"/> against <paramref name="target"/>'s own
    /// reconstructed Countersign_structure, using a registry-resolved verification function.
    /// </summary>
    /// <param name="counterSignature">The countersignature to verify.</param>
    /// <param name="target">The countersigned target.</param>
    /// <param name="externalAad">The externally supplied additional authenticated data (must match what was signed).</param>
    /// <param name="buildCountersignStructure">Delegate to build the Countersign_structure.</param>
    /// <param name="publicKey">The countersigner's public key.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns><see langword="true"/> if the countersignature is valid; otherwise <see langword="false"/>.</returns>
    public static ValueTask<bool> VerifyAsync(
        CoseCounterSignature counterSignature,
        CountersignTarget target,
        ReadOnlyMemory<byte> externalAad,
        BuildCountersignStructureDelegate buildCountersignStructure,
        PublicKeyMemory publicKey,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(publicKey);

        CryptoAlgorithm algorithm = publicKey.Tag.Get<CryptoAlgorithm>();
        Purpose purpose = publicKey.Tag.Get<Purpose>();
        VerificationDelegate verificationDelegate = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveVerification(algorithm, purpose);

        return VerifyAsync(
            counterSignature, target, externalAad, buildCountersignStructure, publicKey, verificationDelegate, cancellationToken: cancellationToken);
    }


    /// <summary>
    /// Verifies <paramref name="counterSignature"/> against <paramref name="target"/>'s own
    /// reconstructed Countersign_structure, using an explicit verification delegate.
    /// </summary>
    /// <param name="counterSignature">The countersignature to verify.</param>
    /// <param name="target">The countersigned target.</param>
    /// <param name="externalAad">The externally supplied additional authenticated data (must match what was signed).</param>
    /// <param name="buildCountersignStructure">Delegate to build the Countersign_structure.</param>
    /// <param name="publicKey">The countersigner's public key.</param>
    /// <param name="verificationDelegate">The verification delegate to use.</param>
    /// <param name="eventSink">
    /// Receives the <see cref="VerificationCompletedEvent"/> the resolved
    /// <paramref name="verificationDelegate"/> constructs, or <see langword="null"/> to route
    /// it to <see cref="CryptographicKeyEvents.DefaultSink"/>.
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns><see langword="true"/> if the countersignature is valid; otherwise <see langword="false"/>.</returns>
    public static async ValueTask<bool> VerifyAsync(
        CoseCounterSignature counterSignature,
        CountersignTarget target,
        ReadOnlyMemory<byte> externalAad,
        BuildCountersignStructureDelegate buildCountersignStructure,
        PublicKeyMemory publicKey,
        VerificationDelegate verificationDelegate,
        CryptoEventSink? eventSink = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(counterSignature);
        ArgumentNullException.ThrowIfNull(target);
        ArgumentNullException.ThrowIfNull(buildCountersignStructure);
        ArgumentNullException.ThrowIfNull(publicKey);
        ArgumentNullException.ThrowIfNull(verificationDelegate);

        cancellationToken.ThrowIfCancellationRequested();

        (bool isAbbreviated, ReadOnlyMemory<byte>? signProtected, ReadOnlyMemory<byte> signatureBytes) = counterSignature switch
        {
            CounterSignatureV2 full =>
                (false, (ReadOnlyMemory<byte>?)full.Component.ProtectedHeader.AsReadOnlyMemory(), full.Component.Signature.AsReadOnlyMemory()),
            CounterSignature0V2 abbreviated => (true, (ReadOnlyMemory<byte>?)null, abbreviated.Value.AsReadOnlyMemory()),
            _ => throw new ArgumentOutOfRangeException(nameof(counterSignature), counterSignature, "Unsupported countersignature form.")
        };

        CountersignStructureInput input = CountersignStructureInput.ForTarget(target, isAbbreviated, signProtected, externalAad);
        byte[] toBeVerified = buildCountersignStructure(input);

        (bool isVerified, CryptoEvent? evt) = await verificationDelegate(
            toBeVerified, signatureBytes, publicKey.AsReadOnlyMemory(), cancellationToken: cancellationToken).ConfigureAwait(false);

        if(evt is not null)
        {
            (eventSink ?? CryptographicKeyEvents.DefaultSink)(evt);
        }

        return isVerified;
    }
}
