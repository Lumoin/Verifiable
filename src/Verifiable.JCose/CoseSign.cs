using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;

namespace Verifiable.JCose;

/// <summary>
/// Per-signer input for creating a COSE_Sign multi-signer message via
/// <see cref="CoseSign.SignAsync"/>.
/// </summary>
/// <param name="ProtectedHeader">
/// The signer's own serialized protected header carrier. Ownership transfers to the
/// resulting <see cref="CoseSignatureComponent"/> on success.
/// </param>
/// <param name="UnprotectedHeader">The signer's own unprotected header map, if any.</param>
/// <param name="PrivateKey">
/// The private key material this signer signs with; its <see cref="Tag"/> resolves the
/// signing algorithm through
/// <see cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}"/>.
/// </param>
public readonly record struct CoseSignerInput(
    EncodedCoseProtectedHeader ProtectedHeader,
    IReadOnlyDictionary<int, object>? UnprotectedHeader,
    PrivateKeyMemory PrivateKey);


/// <summary>
/// COSE_Sign (multi-signer) operations using secure key memory abstractions.
/// </summary>
/// <remarks>
/// <para>
/// This is the multi-signer counterpart of <see cref="Cose"/>: <see cref="Cose"/> composes
/// exactly one <see cref="Signature"/> into a <see cref="CoseSign1Message"/>; this class
/// composes one <see cref="CoseSignatureComponent"/> PER configured signer into a
/// <see cref="CoseSignMessage"/>, calling the same single-signer primitives
/// <see cref="Cose"/> uses once per signer — the same division of labor
/// <see cref="JwsMessage"/>'s General JSON composition uses on the JOSE side (one
/// single-signer primitive, a caller-side loop assembling the multi-signer envelope), not
/// a dedicated many-key-at-once signing method.
/// </para>
/// <para>
/// All methods work with <see cref="CoseSignMessage"/>/<see cref="CoseSignatureComponent"/>
/// instances that own their pool-routed, CBOM-tagged carriers. Callers passing in a
/// protected header transfer ownership to the resulting message/component; disposing the
/// message disposes every carrier it owns, including every signer's own. CBOR
/// serialization is handled separately in <c>Verifiable.Cbor</c> via
/// <c>CoseSerialization</c>.
/// </para>
/// </remarks>
public static class CoseSign
{
    /// <summary>
    /// Signs one <see cref="CoseSignatureComponent"/> using an explicit signing delegate —
    /// the single-signer primitive <see cref="SignAsync"/> calls once per configured
    /// signer.
    /// </summary>
    /// <param name="bodyProtectedHeader">
    /// The COSE_Sign body layer's serialized protected header carrier — supplies the
    /// Sig_structure's <c>body_protected</c> field (RFC 9052 §4.4). Borrowed; not disposed
    /// or consumed by this method.
    /// </param>
    /// <param name="signerProtectedHeader">
    /// The signer's own serialized protected header carrier (pool-routed). Ownership
    /// transfers to the returned <see cref="CoseSignatureComponent"/>.
    /// </param>
    /// <param name="signerUnprotectedHeader">The signer's own unprotected header map (optional).</param>
    /// <param name="payload">The payload bytes (borrowed; caller manages lifetime).</param>
    /// <param name="buildSigStructure">Delegate to build the "Signature"-context Sig_structure.</param>
    /// <param name="privateKey">The private key for signing.</param>
    /// <param name="signingDelegate">The signing delegate to use.</param>
    /// <param name="signaturePool">Memory pool for signature allocation.</param>
    /// <param name="eventSink">
    /// Receives the <see cref="SignatureProducedEvent"/> the resolved
    /// <paramref name="signingDelegate"/> constructs, or <see langword="null"/> to route it
    /// to <see cref="CryptographicKeyEvents.DefaultSink"/>. See <see cref="CryptoEventSink"/>
    /// for the two-route rationale <see cref="Cose"/> documents.
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The signed <see cref="CoseSignatureComponent"/> for this signer.</returns>
    public static async ValueTask<CoseSignatureComponent> SignOneAsync(
        EncodedCoseProtectedHeader bodyProtectedHeader,
        EncodedCoseProtectedHeader signerProtectedHeader,
        IReadOnlyDictionary<int, object>? signerUnprotectedHeader,
        ReadOnlyMemory<byte> payload,
        BuildCoseSignatureSigStructureDelegate buildSigStructure,
        PrivateKeyMemory privateKey,
        SigningDelegate signingDelegate,
        BaseMemoryPool signaturePool,
        CryptoEventSink? eventSink = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(bodyProtectedHeader);
        ArgumentNullException.ThrowIfNull(signerProtectedHeader);
        ArgumentNullException.ThrowIfNull(buildSigStructure);
        ArgumentNullException.ThrowIfNull(privateKey);
        ArgumentNullException.ThrowIfNull(signingDelegate);
        ArgumentNullException.ThrowIfNull(signaturePool);

        cancellationToken.ThrowIfCancellationRequested();

        byte[] toBeSigned = buildSigStructure(
            bodyProtectedHeader.AsReadOnlySpan(),
            signerProtectedHeader.AsReadOnlySpan(),
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

        return new CoseSignatureComponent(signerProtectedHeader, signerUnprotectedHeader, signature);
    }


    /// <summary>
    /// Creates a COSE_Sign message by signing once per entry of <paramref name="signers"/>,
    /// using registry-resolved signing functions (each signer's own
    /// <see cref="PrivateKeyMemory.Tag"/> resolves its own algorithm, so signers may use
    /// different algorithms in the same message).
    /// </summary>
    /// <param name="bodyProtectedHeader">
    /// The body-layer serialized protected header carrier (pool-routed). Ownership
    /// transfers to the returned message.
    /// </param>
    /// <param name="bodyUnprotectedHeader">The body-layer unprotected header map (optional).</param>
    /// <param name="payload">The payload bytes (borrowed; caller manages lifetime).</param>
    /// <param name="signers">
    /// The per-signer inputs. One <see cref="CoseSignatureComponent"/> is appended per
    /// entry, in order. <strong>Consumed:</strong> every entry's <see cref="CoseSignerInput.ProtectedHeader"/>
    /// is spent by this call regardless of outcome — on success, ownership transfers into the
    /// corresponding <see cref="CoseSignatureComponent"/> the same way <see cref="SignOneAsync"/> transfers
    /// it for a single signer; on a mid-loop failure, this call disposes every already-built component AND
    /// every remaining (including the failing) signer's own protected header itself, so the caller never
    /// disposes a <see cref="CoseSignerInput"/> it passed in here. <paramref name="bodyProtectedHeader"/> is
    /// not one of these inputs and keeps its own separate contract (below).
    /// </param>
    /// <param name="buildSigStructure">Delegate to build the "Signature"-context Sig_structure.</param>
    /// <param name="signaturePool">Memory pool for signature allocation.</param>
    /// <param name="eventSink">
    /// Receives every resolved signing delegate's <see cref="SignatureProducedEvent"/>, or
    /// <see langword="null"/> to route to <see cref="CryptographicKeyEvents.DefaultSink"/>.
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The COSE_Sign message containing one signature per entry of <paramref name="signers"/>.</returns>
    public static async ValueTask<CoseSignMessage> SignAsync(
        EncodedCoseProtectedHeader bodyProtectedHeader,
        IReadOnlyDictionary<int, object>? bodyUnprotectedHeader,
        ReadOnlyMemory<byte> payload,
        IReadOnlyList<CoseSignerInput> signers,
        BuildCoseSignatureSigStructureDelegate buildSigStructure,
        BaseMemoryPool signaturePool,
        CryptoEventSink? eventSink = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(bodyProtectedHeader);
        ArgumentNullException.ThrowIfNull(signers);
        ArgumentNullException.ThrowIfNull(buildSigStructure);
        ArgumentNullException.ThrowIfNull(signaturePool);

        if(signers.Count == 0)
        {
            throw new ArgumentException("COSE_Sign requires at least one signer.", nameof(signers));
        }

        cancellationToken.ThrowIfCancellationRequested();

        List<CoseSignatureComponent> components = new(signers.Count);

        try
        {
            foreach(CoseSignerInput signer in signers)
            {
                CryptoAlgorithm algorithm = signer.PrivateKey.Tag.Get<CryptoAlgorithm>();
                Purpose purpose = signer.PrivateKey.Tag.Get<Purpose>();
                SigningDelegate signingDelegate = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveSigning(algorithm, purpose);

                CoseSignatureComponent component = await SignOneAsync(
                    bodyProtectedHeader,
                    signer.ProtectedHeader,
                    signer.UnprotectedHeader,
                    payload,
                    buildSigStructure,
                    signer.PrivateKey,
                    signingDelegate,
                    signaturePool,
                    eventSink,
                    cancellationToken).ConfigureAwait(false);

                components.Add(component);
            }
        }
        catch
        {
            //Metered custody: SignAsync consumes every entry of signers regardless of outcome, per this
            //method's own doc contract -- a signer partway through this loop failing must not leak the
            //pool-rented carriers of the signers that already succeeded, NOR strand the failing signer's
            //own protected header, NOR strand any signer this loop never reached. Every already-signed
            //signer's own protected header + signature carrier is owned by its component at this point
            //(transferred in SignOneAsync's return), so disposing the component is enough; the signer at
            //components.Count (the one that just failed) and every signer after it never had ownership
            //transferred (SignOneAsync only transfers it on its own success path), so those are disposed
            //directly here. bodyProtectedHeader is not one of signers' own inputs; it keeps its own
            //separate contract and stays caller-owned on this path.
            foreach(CoseSignatureComponent component in components)
            {
                component.Dispose();
            }

            for(int i = components.Count; i < signers.Count; i++)
            {
                signers[i].ProtectedHeader.Dispose();
            }

            throw;
        }

        return new CoseSignMessage(bodyProtectedHeader, bodyUnprotectedHeader, payload, components);
    }


    /// <summary>
    /// Verifies one COSE_Signature entry from its constituent parts — the body layer's and the
    /// signer's own serialized protected-header bytes, the payload, and the signature value —
    /// using an explicit verification delegate, with no <see cref="CoseSignMessage"/> or
    /// <see cref="CoseSignatureComponent"/> required. This is the core every message-shaped
    /// <c>VerifyAsync</c> overload below delegates to; a caller already holding these parts on
    /// borrowed carriers (e.g. a parse result it owns for reasons unrelated to this verification,
    /// never a message/component of its own) calls this directly instead of wrapping the borrowed
    /// memory in throwaway message/component objects merely to satisfy a message-shaped signature.
    /// </summary>
    /// <param name="bodyProtectedHeader">
    /// The COSE_Sign body layer's serialized protected header bytes — supplies the
    /// Sig_structure's <c>body_protected</c> field (RFC 9052 §4.4). Borrowed; not disposed or
    /// consumed by this method.
    /// </param>
    /// <param name="signerProtectedHeader">
    /// The signer's own serialized protected header bytes — supplies the Sig_structure's
    /// <c>sign_protected</c> field. Borrowed; not disposed or consumed by this method.
    /// </param>
    /// <param name="payload">
    /// The payload bytes the signature covers. Borrowed; not disposed or consumed by this method.
    /// </param>
    /// <param name="signatureValue">
    /// The signer's own signature value bytes. Borrowed; not disposed or consumed by this method.
    /// </param>
    /// <param name="buildSigStructure">Delegate to build the "Signature"-context Sig_structure.</param>
    /// <param name="publicKey">The public key for verification.</param>
    /// <param name="verificationDelegate">The verification delegate to use.</param>
    /// <param name="eventSink">
    /// Receives the <see cref="VerificationCompletedEvent"/> the resolved
    /// <paramref name="verificationDelegate"/> constructs, or <see langword="null"/> to
    /// route it to <see cref="CryptographicKeyEvents.DefaultSink"/>.
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns><see langword="true"/> if the signature is valid; otherwise <see langword="false"/>.</returns>
    public static async ValueTask<bool> VerifyAsync(
        ReadOnlyMemory<byte> bodyProtectedHeader,
        ReadOnlyMemory<byte> signerProtectedHeader,
        ReadOnlyMemory<byte> payload,
        ReadOnlyMemory<byte> signatureValue,
        BuildCoseSignatureSigStructureDelegate buildSigStructure,
        PublicKeyMemory publicKey,
        VerificationDelegate verificationDelegate,
        CryptoEventSink? eventSink = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(buildSigStructure);
        ArgumentNullException.ThrowIfNull(publicKey);
        ArgumentNullException.ThrowIfNull(verificationDelegate);

        cancellationToken.ThrowIfCancellationRequested();

        byte[] toBeSigned = buildSigStructure(
            bodyProtectedHeader.Span,
            signerProtectedHeader.Span,
            payload.Span,
            ReadOnlySpan<byte>.Empty);

        (bool isVerified, CryptoEvent? evt) = await verificationDelegate(
            toBeSigned,
            signatureValue,
            publicKey.AsReadOnlyMemory(),
            cancellationToken: cancellationToken).ConfigureAwait(false);

        if(evt is not null)
        {
            (eventSink ?? CryptographicKeyEvents.DefaultSink)(evt);
        }

        return isVerified;
    }


    /// <summary>
    /// Verifies one COSE_Signature entry from its constituent parts using a registry-resolved
    /// verification function — resolves <see cref="VerificationDelegate"/> from
    /// <paramref name="publicKey"/>'s own <see cref="Tag"/> and delegates to the explicit-delegate
    /// overload, per this family's registry-delegates-to-parameter convention (the registry
    /// overload never duplicates the verification body).
    /// </summary>
    /// <param name="bodyProtectedHeader">The COSE_Sign body layer's serialized protected header bytes.</param>
    /// <param name="signerProtectedHeader">The signer's own serialized protected header bytes.</param>
    /// <param name="payload">The payload bytes the signature covers.</param>
    /// <param name="signatureValue">The signer's own signature value bytes.</param>
    /// <param name="buildSigStructure">Delegate to build the "Signature"-context Sig_structure.</param>
    /// <param name="publicKey">The public key for verification.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns><see langword="true"/> if the signature is valid; otherwise <see langword="false"/>.</returns>
    public static ValueTask<bool> VerifyAsync(
        ReadOnlyMemory<byte> bodyProtectedHeader,
        ReadOnlyMemory<byte> signerProtectedHeader,
        ReadOnlyMemory<byte> payload,
        ReadOnlyMemory<byte> signatureValue,
        BuildCoseSignatureSigStructureDelegate buildSigStructure,
        PublicKeyMemory publicKey,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(publicKey);

        CryptoAlgorithm algorithm = publicKey.Tag.Get<CryptoAlgorithm>();
        Purpose purpose = publicKey.Tag.Get<Purpose>();
        VerificationDelegate verificationDelegate =
            CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveVerification(algorithm, purpose);

        return VerifyAsync(
            bodyProtectedHeader,
            signerProtectedHeader,
            payload,
            signatureValue,
            buildSigStructure,
            publicKey,
            verificationDelegate,
            eventSink: null,
            cancellationToken: cancellationToken);
    }


    /// <summary>
    /// Verifies one signer's <see cref="CoseSignatureComponent"/> within a
    /// <see cref="CoseSignMessage"/>, addressed by index, using an explicit verification
    /// delegate. Delegates to the parts-taking <see cref="VerifyAsync(ReadOnlyMemory{byte}, ReadOnlyMemory{byte}, ReadOnlyMemory{byte}, ReadOnlyMemory{byte}, BuildCoseSignatureSigStructureDelegate, PublicKeyMemory, VerificationDelegate, CryptoEventSink?, CancellationToken)"/>
    /// overload above.
    /// </summary>
    /// <param name="message">The COSE_Sign message to verify.</param>
    /// <param name="signerIndex">The index into <see cref="CoseSignMessage.Signatures"/> to verify.</param>
    /// <param name="buildSigStructure">Delegate to build the "Signature"-context Sig_structure.</param>
    /// <param name="publicKey">The public key for verification.</param>
    /// <param name="verificationDelegate">The verification delegate to use.</param>
    /// <param name="eventSink">
    /// Receives the <see cref="VerificationCompletedEvent"/> the resolved
    /// <paramref name="verificationDelegate"/> constructs, or <see langword="null"/> to
    /// route it to <see cref="CryptographicKeyEvents.DefaultSink"/>.
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns><see langword="true"/> if that signer's signature is valid; otherwise <see langword="false"/>.</returns>
    public static ValueTask<bool> VerifyAsync(
        CoseSignMessage message,
        int signerIndex,
        BuildCoseSignatureSigStructureDelegate buildSigStructure,
        PublicKeyMemory publicKey,
        VerificationDelegate verificationDelegate,
        CryptoEventSink? eventSink = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(message);
        ArgumentNullException.ThrowIfNull(buildSigStructure);
        ArgumentNullException.ThrowIfNull(publicKey);
        ArgumentNullException.ThrowIfNull(verificationDelegate);
        ThrowIfSignerIndexOutOfRange(message, signerIndex);

        CoseSignatureComponent signer = message.Signatures[signerIndex];

        return VerifyAsync(
            message.ProtectedHeader.AsReadOnlyMemory(),
            signer.ProtectedHeader.AsReadOnlyMemory(),
            message.Payload,
            signer.Signature.AsReadOnlyMemory(),
            buildSigStructure,
            publicKey,
            verificationDelegate,
            eventSink,
            cancellationToken);
    }


    /// <summary>
    /// Verifies one signer's <see cref="CoseSignatureComponent"/> within a
    /// <see cref="CoseSignMessage"/>, addressed by index, using a registry-resolved
    /// verification function.
    /// </summary>
    /// <param name="message">The COSE_Sign message to verify.</param>
    /// <param name="signerIndex">The index into <see cref="CoseSignMessage.Signatures"/> to verify.</param>
    /// <param name="buildSigStructure">Delegate to build the "Signature"-context Sig_structure.</param>
    /// <param name="publicKey">The public key for verification.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns><see langword="true"/> if that signer's signature is valid; otherwise <see langword="false"/>.</returns>
    public static ValueTask<bool> VerifyAsync(
        CoseSignMessage message,
        int signerIndex,
        BuildCoseSignatureSigStructureDelegate buildSigStructure,
        PublicKeyMemory publicKey,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(publicKey);

        CryptoAlgorithm algorithm = publicKey.Tag.Get<CryptoAlgorithm>();
        Purpose purpose = publicKey.Tag.Get<Purpose>();
        VerificationDelegate verificationDelegate =
            CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveVerification(algorithm, purpose);

        return VerifyAsync(message, signerIndex, buildSigStructure, publicKey, verificationDelegate, cancellationToken: cancellationToken);
    }


    /// <summary>
    /// Verifies a "named" signer — the first <see cref="CoseSignatureComponent"/> for which
    /// <paramref name="signerSelector"/> returns <see langword="true"/> (e.g. matching a
    /// <c>kid</c> in <see cref="CoseSignatureComponent.UnprotectedHeader"/>) — using a
    /// registry-resolved verification function.
    /// </summary>
    /// <param name="message">The COSE_Sign message to verify.</param>
    /// <param name="signerSelector">Predicate identifying the signer to verify.</param>
    /// <param name="buildSigStructure">Delegate to build the "Signature"-context Sig_structure.</param>
    /// <param name="publicKey">The public key for verification.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns><see langword="true"/> if the selected signer's signature is valid; otherwise <see langword="false"/>.</returns>
    /// <exception cref="InvalidOperationException">Thrown when no signer matches <paramref name="signerSelector"/>.</exception>
    public static async ValueTask<bool> VerifyAsync(
        CoseSignMessage message,
        Func<CoseSignatureComponent, bool> signerSelector,
        BuildCoseSignatureSigStructureDelegate buildSigStructure,
        PublicKeyMemory publicKey,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(message);
        ArgumentNullException.ThrowIfNull(signerSelector);

        int signerIndex = -1;
        for(int i = 0; i < message.Signatures.Count; i++)
        {
            if(signerSelector(message.Signatures[i]))
            {
                signerIndex = i;
                break;
            }
        }

        if(signerIndex < 0)
        {
            throw new InvalidOperationException("No COSE_Signature entry matched the supplied selector.");
        }

        return await VerifyAsync(message, signerIndex, buildSigStructure, publicKey, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Verifies every signer in <paramref name="message"/>, each against its own
    /// registry-resolved public key, aligned by index.
    /// </summary>
    /// <param name="message">The COSE_Sign message to verify.</param>
    /// <param name="publicKeys">
    /// The public keys, one per entry of <see cref="CoseSignMessage.Signatures"/>, in the
    /// same order.
    /// </param>
    /// <param name="buildSigStructure">Delegate to build the "Signature"-context Sig_structure.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// <see langword="true"/> when every signer's signature verifies; <see langword="false"/>
    /// on the first signer that does not (short-circuits; later signers are not attempted).
    /// </returns>
    public static async ValueTask<bool> VerifyAllAsync(
        CoseSignMessage message,
        IReadOnlyList<PublicKeyMemory> publicKeys,
        BuildCoseSignatureSigStructureDelegate buildSigStructure,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(message);
        ArgumentNullException.ThrowIfNull(publicKeys);

        if(publicKeys.Count != message.Signatures.Count)
        {
            throw new ArgumentException(
                "One public key is required per COSE_Signature entry, in the same order.", nameof(publicKeys));
        }

        for(int i = 0; i < message.Signatures.Count; i++)
        {
            bool isVerified = await VerifyAsync(message, i, buildSigStructure, publicKeys[i], cancellationToken).ConfigureAwait(false);
            if(!isVerified)
            {
                return false;
            }
        }

        return true;
    }


    /// <summary>
    /// Throws when <paramref name="signerIndex"/> does not address an entry of
    /// <paramref name="message"/>'s <see cref="CoseSignMessage.Signatures"/>.
    /// </summary>
    /// <param name="message">The message <paramref name="signerIndex"/> is addressed against.</param>
    /// <param name="signerIndex">The candidate index.</param>
    private static void ThrowIfSignerIndexOutOfRange(CoseSignMessage message, int signerIndex)
    {
        if(signerIndex < 0 || signerIndex >= message.Signatures.Count)
        {
            throw new ArgumentOutOfRangeException(
                nameof(signerIndex), signerIndex, "Signer index is out of range for this COSE_Sign message.");
        }
    }
}
