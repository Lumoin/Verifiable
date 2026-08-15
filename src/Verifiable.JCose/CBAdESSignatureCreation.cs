using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Pki;

namespace Verifiable.JCose;

/// <summary>
/// The COSE Payload input a CB-AdES B-B creation call signs over — the small closed sum
/// <see cref="CBAdESSignatureCreation"/> dispatches on to resolve both the bytes the Sig_structure actually
/// covers and the wire <c>payload</c> field's attached/detached shape (clause 4.5). A DU-ready closed sum: no
/// external type may derive from it.
/// </summary>
/// <remarks>
/// <para>
/// Three concrete arms: <see cref="CBAdESAttachedPayloadInput"/> (attached, no <c>sigD</c>),
/// <see cref="CBAdESDetachedExternalPayloadInput"/> (detached, no <c>sigD</c> — the plain out-of-band-agreement
/// case clause 4.5 permits without requiring the reference mechanism), and
/// <see cref="CBAdESDetachedSigDPayloadInput"/> (detached, referenced via <c>sigD</c> — covers BOTH built-in
/// mechanisms of clause 5.2.8.2 plus any third-party <c>mId</c>, unified into one arm because all three share
/// the same <c>(mechanism, references, optional hashM)</c> shape and differ only in how
/// <see cref="CBAdESSignatureCreation"/> resolves them).
/// </para>
/// <para>
/// <strong>Same-payload invariant with <see cref="CBAdESPayloadTimestampAcquisitionSource"/>.</strong>
/// When an <c>adoTst</c> is acquired ahead of creation
/// (<see cref="CBAdESSignatureAugmentation.AcquirePayloadTimestampAsync"/>), the
/// <see cref="CBAdESPayloadTimestampAcquisitionSource"/> that call was given and the instance of THIS sum
/// <see cref="CBAdESSignatureCreation"/> is later given must describe the SAME payload — neither call
/// cross-checks the other's, so a caller-side mismatch is never caught at creation time; it surfaces only at
/// validation, as a <see cref="CBAdESTimestampTokenBindingViolation"/> naming
/// <see cref="CBAdESTimestampTokenBindingKind.PayloadTimestamp"/> and
/// <see cref="CBAdESTimestampTokenBindingFailureReason.ImprintMismatch"/>. The two sums stay deliberately
/// separate types, a recorded design call rather than an oversight: THIS one is
/// creation's SIGN-time union of already-resolved bytes, the other the pre-sign ACQUISITION-time union (with
/// its raw <c>sigD.pars</c> third arm) — see <see cref="CBAdESPayloadTimestampAcquisitionSource"/>'s own
/// remarks for the identical cross-reference from the other side.
/// </para>
/// </remarks>
public abstract class CBAdESSigningPayloadInput
{
    /// <summary>Restricts direct subtyping to the sibling types declared in this file.</summary>
    private protected CBAdESSigningPayloadInput()
    {
    }
}


/// <summary>
/// An attached COSE Payload (clause 4.5): the bytes both become the wire <c>payload</c> field and are what the
/// Sig_structure covers.
/// </summary>
[DebuggerDisplay("CBAdESAttachedPayloadInput: {Payload.Length} bytes")]
public sealed class CBAdESAttachedPayloadInput : CBAdESSigningPayloadInput
{
    /// <summary>Initializes a new <see cref="CBAdESAttachedPayloadInput"/>.</summary>
    /// <param name="payload">
    /// The payload bytes. <strong>Borrowed</strong> view — the caller owns the underlying memory for the duration
    /// of the <see cref="CBAdESSignatureCreation"/> call.
    /// </param>
    public CBAdESAttachedPayloadInput(ReadOnlyMemory<byte> payload)
    {
        Payload = payload;
    }

    /// <summary>
    /// The payload bytes. <strong>Borrowed</strong> view — the caller owns the underlying memory for the duration
    /// of the <see cref="CBAdESSignatureCreation"/> call.
    /// </summary>
    public ReadOnlyMemory<byte> Payload { get; }
}


/// <summary>
/// A detached COSE Payload agreed out of band, without a <c>sigD</c> header parameter (clause 4.5 permits a
/// detached payload with no reference mechanism attached; <c>sigD</c> per clause 5.2.8 is optional even for a
/// detached payload — CB-5.2.8-04).
/// </summary>
[DebuggerDisplay("CBAdESDetachedExternalPayloadInput: {Payload.Length} bytes")]
public sealed class CBAdESDetachedExternalPayloadInput : CBAdESSigningPayloadInput
{
    /// <summary>Initializes a new <see cref="CBAdESDetachedExternalPayloadInput"/>.</summary>
    /// <param name="payload">
    /// The bytes the Sig_structure covers. <strong>Borrowed</strong> view — the caller owns the underlying memory
    /// for the duration of the <see cref="CBAdESSignatureCreation"/> call. The wire <c>payload</c> field is nil;
    /// these bytes never appear on the wire through this call, matching a verifier that reconstructs them by its
    /// own out-of-band agreement.
    /// </param>
    public CBAdESDetachedExternalPayloadInput(ReadOnlyMemory<byte> payload)
    {
        Payload = payload;
    }

    /// <summary>
    /// The bytes the Sig_structure covers. <strong>Borrowed</strong> view — the caller owns the underlying memory
    /// for the duration of the <see cref="CBAdESSignatureCreation"/> call. The wire <c>payload</c> field is nil;
    /// these bytes never appear on the wire through this call, matching a verifier that reconstructs them by its
    /// own out-of-band agreement.
    /// </summary>
    public ReadOnlyMemory<byte> Payload { get; }
}


/// <summary>
/// A detached COSE Payload referenced through <c>sigD</c> (clause 5.2.8) — the "hashV-less" per-call input:
/// no digest travels in yet, because <see cref="CBAdESSignatureCreation"/>
/// computes it (for the <see cref="CBAdESDetachedMechanisms.ObjectIdByURIHash"/> mechanism) or omits it
/// entirely (for <see cref="CBAdESDetachedMechanisms.ObjectIdByURI"/> and any third-party mechanism) as part of
/// resolving this arm.
/// </summary>
[DebuggerDisplay("CBAdESDetachedSigDPayloadInput: {MechanismIdentifier}, {References.Count} reference(s)")]
public sealed class CBAdESDetachedSigDPayloadInput : CBAdESSigningPayloadInput
{
    /// <summary>Initializes a new <see cref="CBAdESDetachedSigDPayloadInput"/>.</summary>
    /// <param name="mechanismIdentifier">
    /// The <c>mId</c> value (CB-5.2.8-14/15) — <see cref="CBAdESDetachedMechanisms.ObjectIdByURI"/>,
    /// <see cref="CBAdESDetachedMechanisms.ObjectIdByURIHash"/>, or a third-party URI (CB-5.2.6-07/CB-5.2.8-08).
    /// </param>
    /// <param name="references">The <c>sigD.pars</c> entries, in wire order (CB-5.2.8.2.2-05: order is load-bearing).</param>
    /// <param name="hashAlgorithm">
    /// The <c>hashM</c> value the <see cref="CBAdESDetachedMechanisms.ObjectIdByURIHash"/> mechanism requires
    /// (CB-5.2.8.2.3-02) and the <see cref="CBAdESDetachedMechanisms.ObjectIdByURI"/> mechanism forbids
    /// (CB-5.2.8.2.2-02); <see langword="null"/> for <see cref="CBAdESDetachedMechanisms.ObjectIdByURI"/>. A
    /// third-party mechanism supplying a non-<see langword="null"/> value here is refused — see
    /// <see cref="CBAdESUnknownDetachedObjectMechanismDelegate"/>'s remarks for why.
    /// </param>
    public CBAdESDetachedSigDPayloadInput(string mechanismIdentifier, IReadOnlyList<CBAdESDetachedObjectReferenceInput> references, AdESDigestAlgorithmIdentifier? hashAlgorithm = null)
    {
        MechanismIdentifier = mechanismIdentifier;
        References = references;
        HashAlgorithm = hashAlgorithm;
    }

    /// <summary>
    /// The <c>mId</c> value (CB-5.2.8-14/15) — <see cref="CBAdESDetachedMechanisms.ObjectIdByURI"/>,
    /// <see cref="CBAdESDetachedMechanisms.ObjectIdByURIHash"/>, or a third-party URI (CB-5.2.6-07/CB-5.2.8-08).
    /// </summary>
    public string MechanismIdentifier { get; }

    /// <summary>The <c>sigD.pars</c> entries, in wire order (CB-5.2.8.2.2-05: order is load-bearing).</summary>
    public IReadOnlyList<CBAdESDetachedObjectReferenceInput> References { get; }

    /// <summary>
    /// The <c>hashM</c> value the <see cref="CBAdESDetachedMechanisms.ObjectIdByURIHash"/> mechanism requires
    /// (CB-5.2.8.2.3-02) and the <see cref="CBAdESDetachedMechanisms.ObjectIdByURI"/> mechanism forbids
    /// (CB-5.2.8.2.2-02); <see langword="null"/> for <see cref="CBAdESDetachedMechanisms.ObjectIdByURI"/>. A
    /// third-party mechanism supplying a non-<see langword="null"/> value here is refused — see
    /// <see cref="CBAdESUnknownDetachedObjectMechanismDelegate"/>'s remarks for why.
    /// </summary>
    public AdESDigestAlgorithmIdentifier? HashAlgorithm { get; }
}


/// <summary>
/// The outcome of <see cref="CBAdESSignatureCreation"/>: the signed <c>COSE_Sign1</c> message together with the
/// signed-header-set aggregate that was actually encoded — the "completed" form when
/// the payload mechanism computed a <c>hashV</c> the caller-supplied aggregate could not carry yet.
/// </summary>
/// <remarks>
/// <strong>Ownership.</strong> This instance owns both <see cref="Message"/> and <see cref="Headers"/>;
/// <see cref="Dispose"/> disposes both. See <see cref="CBAdESSignatureCreation"/>'s class remarks for why the
/// caller must dispose ONLY this result — never the original <c>headers</c> argument passed to
/// <see cref="CBAdESSignatureCreation"/> — after a successful call: ownership of that argument transfers to
/// this call, and <see cref="Headers"/> may share owned members with it.
/// </remarks>
[DebuggerDisplay("CBAdESSignatureCreationResult: alg={Headers.Algorithm}")]
public sealed class CBAdESSignatureCreationResult: IDisposable
{
    private bool disposed;


    /// <summary>
    /// Initializes a new <see cref="CBAdESSignatureCreationResult"/>. Ownership of <paramref name="message"/>
    /// and <paramref name="headers"/> transfers to this instance.
    /// </summary>
    /// <param name="message">See <see cref="Message"/>.</param>
    /// <param name="headers">See <see cref="Headers"/>.</param>
    /// <exception cref="ArgumentNullException"><paramref name="message"/> or <paramref name="headers"/> is <see langword="null"/>.</exception>
    public CBAdESSignatureCreationResult(CoseSign1Message message, CBAdESProtectedHeaders headers)
    {
        ArgumentNullException.ThrowIfNull(message);
        ArgumentNullException.ThrowIfNull(headers);

        Message = message;
        Headers = headers;
    }


    /// <summary>Gets the signed <c>COSE_Sign1</c> message. Owned by this instance; disposed via <see cref="Dispose"/>.</summary>
    public CoseSign1Message Message { get; }

    /// <summary>
    /// Gets the signed-header-set aggregate that was actually encoded into <see cref="Message"/>'s protected
    /// header — identical to the <c>headers</c> argument <see cref="CBAdESSignatureCreation"/> received when no
    /// <c>sigD</c> completion was needed, or a new instance carrying the completed
    /// <see cref="CBAdESProtectedHeaders.DetachedObjects"/> otherwise. Owned by this instance; disposed via
    /// <see cref="Dispose"/>.
    /// </summary>
    public CBAdESProtectedHeaders Headers { get; }


    /// <summary>Disposes <see cref="Message"/> and <see cref="Headers"/>.</summary>
    public void Dispose()
    {
        if(!disposed)
        {
            Message.Dispose();
            Headers.Dispose();
            disposed = true;
        }
    }
}


/// <summary>
/// Per-signer input for creating a CB-AdES signature over a <c>COSE_Sign</c> (multi-signer) structure via
/// <see cref="CBAdESSignatureCreation.SignCoseSignAsync"/>.
/// </summary>
[DebuggerDisplay("CBAdESCoseSignSignerInput: alg={Headers.Algorithm}")]
public sealed class CBAdESCoseSignSignerInput
{
    /// <summary>Initializes a new <see cref="CBAdESCoseSignSignerInput"/>.</summary>
    /// <param name="headers">
    /// This signer's own signed-header-set aggregate — checked through the SAME
    /// <see cref="CBAdESHeaderRules.EnsureConformant"/> rule body the <c>COSE_Sign1</c> creation path runs.
    /// Ownership transfers to <see cref="CBAdESSignatureCreation.SignCoseSignAsync"/> on success; the caller
    /// disposes only the returned result's own <see cref="CBAdESCoseSignSignatureCreationResult.SignerHeaders"/>
    /// afterwards.
    /// </param>
    /// <param name="unsignedHeaders">This signer's own <c>uHeaders</c> set, or <see langword="null"/> to omit it.</param>
    /// <param name="privateKey">This signer's own private key.</param>
    public CBAdESCoseSignSignerInput(CBAdESProtectedHeaders headers, CBAdESUnsignedHeaders? unsignedHeaders, PrivateKeyMemory privateKey)
    {
        Headers = headers;
        UnsignedHeaders = unsignedHeaders;
        PrivateKey = privateKey;
    }

    /// <summary>
    /// This signer's own signed-header-set aggregate — checked through the SAME
    /// <see cref="CBAdESHeaderRules.EnsureConformant"/> rule body the <c>COSE_Sign1</c> creation path runs.
    /// Ownership transfers to <see cref="CBAdESSignatureCreation.SignCoseSignAsync"/> on success; the caller
    /// disposes only the returned result's own <see cref="CBAdESCoseSignSignatureCreationResult.SignerHeaders"/>
    /// afterwards.
    /// </summary>
    public CBAdESProtectedHeaders Headers { get; }

    /// <summary>This signer's own <c>uHeaders</c> set, or <see langword="null"/> to omit it.</summary>
    public CBAdESUnsignedHeaders? UnsignedHeaders { get; }

    /// <summary>This signer's own private key.</summary>
    public PrivateKeyMemory PrivateKey { get; }
}


/// <summary>
/// The outcome of <see cref="CBAdESSignatureCreation.SignCoseSignAsync"/>: the signed <c>COSE_Sign</c> message
/// together with every signer's own signed-header-set aggregate that was actually encoded.
/// </summary>
/// <remarks>
/// <strong>Ownership.</strong> This instance owns both <see cref="Message"/> and every entry of
/// <see cref="SignerHeaders"/>; <see cref="Dispose"/> disposes all of them.
/// </remarks>
[DebuggerDisplay("CBAdESCoseSignSignatureCreationResult: signers={SignerHeaders.Count}")]
public sealed class CBAdESCoseSignSignatureCreationResult: IDisposable
{
    private bool disposed;


    /// <summary>
    /// Initializes a new <see cref="CBAdESCoseSignSignatureCreationResult"/>. Ownership of
    /// <paramref name="message"/> and every entry of <paramref name="signerHeaders"/> transfers to this
    /// instance.
    /// </summary>
    /// <param name="message">See <see cref="Message"/>.</param>
    /// <param name="signerHeaders">See <see cref="SignerHeaders"/>.</param>
    /// <exception cref="ArgumentNullException"><paramref name="message"/> or <paramref name="signerHeaders"/> is <see langword="null"/>.</exception>
    public CBAdESCoseSignSignatureCreationResult(CoseSignMessage message, IReadOnlyList<CBAdESProtectedHeaders> signerHeaders)
    {
        ArgumentNullException.ThrowIfNull(message);
        ArgumentNullException.ThrowIfNull(signerHeaders);

        Message = message;
        SignerHeaders = signerHeaders;
    }


    /// <summary>Gets the signed <c>COSE_Sign</c> message. Owned by this instance; disposed via <see cref="Dispose"/>.</summary>
    public CoseSignMessage Message { get; }

    /// <summary>
    /// Gets every signer's own signed-header-set aggregate that was actually encoded into <see cref="Message"/>,
    /// in the same order as <see cref="CoseSignMessage.Signatures"/>. Owned by this instance; disposed via
    /// <see cref="Dispose"/>.
    /// </summary>
    public IReadOnlyList<CBAdESProtectedHeaders> SignerHeaders { get; }


    /// <summary>Disposes <see cref="Message"/> and every entry of <see cref="SignerHeaders"/>.</summary>
    public void Dispose()
    {
        if(!disposed)
        {
            Message.Dispose();
            foreach(CBAdESProtectedHeaders headers in SignerHeaders)
            {
                headers.Dispose();
            }

            disposed = true;
        }
    }
}


/// <summary>
/// Creates a CB-AdES-B-B signature
/// (<see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1</see>, clause 6.1's baseline level): composes <see cref="Cose.SignAsync(EncodedCoseProtectedHeader, IReadOnlyDictionary{int, object}?, ReadOnlyMemory{byte}, BuildSigStructureDelegate, PrivateKeyMemory, BaseMemoryPool, CancellationToken)"/>
/// over a <see cref="CBAdESProtectedHeaders"/> aggregate, the shared <see cref="CBAdESHeaderRules"/> rule
/// surface, the <see cref="CBAdESSerializationDelegates"/>-declared CBOR seams, and (for a detached, referenced
/// payload) the <see cref="CBAdESDetachedObjectDereferencing"/> seam.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Overload flavors mirror <see cref="Cose"/>.</strong> The registry-resolved
/// <see cref="SignAsync(CBAdESProtectedHeaders, CBAdESSigningPayloadInput, CBAdESUnsignedHeaders?, EncodeCBAdESProtectedHeaderDelegate, EncodeCBAdESUnprotectedHeaderDelegate, BuildSigStructureDelegate, PrivateKeyMemory, CBAdESDetachedObjectDereferenceDelegate?, CBAdESDetachedObjectDereferenceContext?, CBAdESUnknownDetachedObjectMechanismDelegate?, BaseMemoryPool, CancellationToken)"/>
/// resolves a <see cref="SigningDelegate"/> from <paramref name="privateKey"/>'s <see cref="Tag"/> through
/// <see cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}"/> and forwards to the explicit-delegate
/// overload — the same two-flavor split <see cref="Cose"/>'s own <c>SignAsync</c> uses for COSE_Sign1.
/// </para>
/// <para>
/// <strong>Two throw-posture rule passes, run out of the naive single-pass order, with grounds.</strong> A
/// single pass over "run the m1 rules in throw posture, then resolve the signing payload per mechanism" would need
/// <see cref="CBAdESProtectedHeaders.DetachedObjects"/> to exist BEFORE the sigD-mechanism gates
/// (CB-5.2.8.2.2-02, CB-5.2.8.2.3-02) can fire — but <see cref="CBAdESDetachedObjects"/>'s own constructor
/// invariant (a mechanism-level <c>hashM</c> requires at least one entry already carrying a digest) makes a
/// "hashM present, no digests yet" input UNREPRESENTABLE through that type, which is exactly why this
/// orchestrator completes a "hashV-less" input into the final aggregate rather than
/// receiving one ready-made. This method therefore runs <see cref="CBAdESHeaderRules.EnsureConformant"/> TWICE:
/// PASS 1, on the caller-supplied <paramref name="headers"/> as-is (whose
/// <see cref="CBAdESProtectedHeaders.DetachedObjects"/> is always <see langword="null"/> at this point — see
/// the next paragraph), catches every rule that does not depend on <c>sigD</c>'s resolved mechanism (the
/// x5t/x5ts/x5chain tri-way, the <c>content type</c>/<c>sigD</c> exclusion, the MD5 denylist on
/// <see cref="CBAdESProtectedHeaders.X5T"/>/<see cref="CBAdESProtectedHeaders.CertificateDigests"/>/
/// <see cref="CBAdESProtectedHeaders.SignaturePolicyIdentifier"/>, the <c>sigPSt</c> gate) STRICTLY BEFORE any
/// dereferencing I/O runs — this is what makes "MD5 denylist runs before any signing" true in the strongest
/// sense this design permits: before network I/O, not merely before the cryptographic signature. PASS 2, on
/// the fully-merged <c>effectiveHeaders</c> after mechanism resolution, re-checks everything (cheap — no I/O)
/// as the final gate immediately before <see cref="Cose.SignAsync(EncodedCoseProtectedHeader, IReadOnlyDictionary{int, object}?, ReadOnlyMemory{byte}, BuildSigStructureDelegate, PrivateKeyMemory, BaseMemoryPool, CancellationToken)"/>,
/// and is the ONLY pass that can see the sigD-mechanism-digest-presence gates (CB-5.2.8.2.2-02/CB-5.2.8.2.3-02),
/// because only now does <see cref="CBAdESProtectedHeaders.DetachedObjects"/> exist. Both passes still run
/// strictly before any cryptographic signing call, satisfying the MD5-before-signing requirement
/// either way; PASS 1 is the stronger, additional guarantee.
/// </para>
/// <para>
/// <strong>This orchestrator is the SOLE producer of <see cref="CBAdESProtectedHeaders.DetachedObjects"/>.</strong>
/// A caller-supplied <paramref name="headers"/> whose <see cref="CBAdESProtectedHeaders.DetachedObjects"/> is
/// already non-null is refused with <see cref="ArgumentException"/> — the sigD reference set travels through
/// <paramref name="payloadInput"/>'s <see cref="CBAdESDetachedSigDPayloadInput"/> arm instead, precisely
/// because (per the previous paragraph) a caller cannot construct a legal hashV-less
/// <see cref="CBAdESDetachedObjects"/> for the <see cref="CBAdESDetachedMechanisms.ObjectIdByURIHash"/>
/// mechanism through that type's own constructor.
/// </para>
/// <para>
/// <strong>Creation is conformant by construction.</strong> When
/// <paramref name="payloadInput"/> resolves a <c>sigD</c> reference set, this orchestrator auto-adds label
/// <see cref="CBAdESHeaderParameters.SigD"/> (267) to <see cref="CBAdESProtectedHeaders.CriticalLabels"/> if it
/// is not already present (CB-5.1.10-04) — the caller never has to remember this coupling.
/// </para>
/// <para>
/// <strong>The <c>ObjectIdByURI</c> wire-detach step, recorded here.</strong>
/// <see cref="Cose.SignAsync(EncodedCoseProtectedHeader, IReadOnlyDictionary{int, object}?, ReadOnlyMemory{byte}, BuildSigStructureDelegate, PrivateKeyMemory, BaseMemoryPool, CancellationToken)"/>'s
/// <c>payload</c> parameter is BOTH the Sig_structure input AND, unchanged, the resulting
/// <see cref="CoseSign1Message.Payload"/> — one parameter serves both roles. Under
/// <see cref="CBAdESDetachedMechanisms.ObjectIdByURI"/> the Sig_structure must cover the concatenated
/// dereferenced bytes (CB-5.2.8.2.2-05) while the WIRE payload stays nil (the signature is over a detached
/// payload, clause 4.5). This method resolves that by calling <c>Cose.SignAsync</c> with the concatenation as
/// its <c>payload</c> argument, then — for every detached arm — constructing a SECOND
/// <see cref="CoseSign1Message"/> around the SAME <see cref="CoseSign1Message.ProtectedHeader"/> and
/// <see cref="CoseSign1Message.Signature"/> carriers <c>Cose.SignAsync</c> already produced, with
/// <see cref="CoseSign1Message.Payload"/> set to empty. The first (intermediate) message is abandoned — never
/// disposed — because its two disposable members now belong to the second, returned message; no data is
/// copied, and no resource is leaked, since exactly one of the two wrapper objects ever has <c>Dispose</c>
/// called on it and both wrap the identical underlying carriers.
/// </para>
/// <para>
/// <strong><c>ObjectIdByURIHash</c> signs the empty payload directly (CB-5.2.8.2.3-06)</strong> — no wire-detach
/// step is needed there beyond the same empty-payload construction every detached arm gets, because the
/// Sig_structure input IS already empty for that mechanism; there is nothing to differ between the intermediate
/// and final message. The per-<c>pars</c>-entry <c>hashV</c> digests are computed here, via the REGISTERED
/// digest delegate (<see cref="CryptographicKeyEvents.ComputeDigestAsync(ReadOnlyMemory{byte}, int, Tag, BaseMemoryPool, System.Collections.Frozen.FrozenDictionary{string, object}?, string?, System.Threading.CancellationToken)"/>,
/// never a direct framework hash), resolved from <c>hashM</c> — only SHA-256/384/512 resolve (the same
/// coverage <see cref="CBAdESHeaderRules"/>'s MD5 denylist documents for every other <c>hashAlg</c>-typed
/// surface); any other identifier, including the literal text <c>"MD5"</c>, is refused with
/// <see cref="NotSupportedException"/> BEFORE any dereferencing for that entry runs.
/// </para>
/// <para>
/// <strong>Unknown <c>mId</c> (CB-5.2.6-07/CB-5.2.8-08).</strong> When
/// <paramref name="payloadInput"/>'s mechanism identifier is neither built-in,
/// <paramref name="unknownMechanismHandler"/> is invoked to retrieve the COSE Payload; absent a handler, this
/// method throws <see cref="NotSupportedException"/> citing CB-5.2.6-07. See
/// <see cref="CBAdESUnknownDetachedObjectMechanismDelegate"/>'s remarks for this extension point's documented
/// scope limit (payload retrieval only, no per-entry digests).
/// </para>
/// <para>
/// Creation-side failures are typed exceptions (<see cref="ArgumentException"/>, <see cref="NotSupportedException"/>,
/// <see cref="CBAdESDetachedObjectDereferenceException"/>), never the validation-side conclusion model,
/// matching the CAdES creation precedent (<see cref="CAdESSignatureCreation"/>).
/// </para>
/// </remarks>
public static class CBAdESSignatureCreation
{
    /// <summary>
    /// Creates a CB-AdES-B-B signature using registry-resolved signing function.
    /// </summary>
    /// <param name="headers">
    /// The signed-header-set aggregate. Its <see cref="CBAdESProtectedHeaders.DetachedObjects"/> shall be
    /// <see langword="null"/> — see the class remarks for why this orchestrator is the sole producer of that
    /// member. Ownership transfers to this call on success; dispose only the returned result's
    /// <see cref="CBAdESSignatureCreationResult.Headers"/> afterwards.
    /// </param>
    /// <param name="payloadInput">The COSE Payload to sign over; see <see cref="CBAdESSigningPayloadInput"/>.</param>
    /// <param name="unsignedHeaders">The <c>uHeaders</c> set to incorporate, or <see langword="null"/> to omit it.</param>
    /// <param name="encodeProtectedHeader">The protected-header CBOR encode seam.</param>
    /// <param name="encodeUnprotectedHeader">The unprotected-header (<c>uHeaders</c>) CBOR encode seam.</param>
    /// <param name="buildSigStructure">Delegate to build the Sig_structure for signing.</param>
    /// <param name="privateKey">The private key for signing.</param>
    /// <param name="dereference">
    /// The <c>sigD</c> URI-reference dereference delegate; required when <paramref name="payloadInput"/> is a
    /// <see cref="CBAdESDetachedSigDPayloadInput"/> selecting a built-in mechanism, otherwise unused.
    /// </param>
    /// <param name="dereferenceContext">
    /// The per-call caller state for <paramref name="dereference"/>/<paramref name="unknownMechanismHandler"/>;
    /// required whenever <paramref name="payloadInput"/> is a <see cref="CBAdESDetachedSigDPayloadInput"/>.
    /// </param>
    /// <param name="unknownMechanismHandler">
    /// The extension point for a third-party <c>mId</c>; see <see cref="CBAdESUnknownDetachedObjectMechanismDelegate"/>.
    /// </param>
    /// <param name="pool">Memory pool every allocation this call performs is rented from.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The signature creation result. The caller owns and disposes it.</returns>
    public static ValueTask<CBAdESSignatureCreationResult> SignAsync(
        CBAdESProtectedHeaders headers,
        CBAdESSigningPayloadInput payloadInput,
        CBAdESUnsignedHeaders? unsignedHeaders,
        EncodeCBAdESProtectedHeaderDelegate encodeProtectedHeader,
        EncodeCBAdESUnprotectedHeaderDelegate encodeUnprotectedHeader,
        BuildSigStructureDelegate buildSigStructure,
        PrivateKeyMemory privateKey,
        CBAdESDetachedObjectDereferenceDelegate? dereference,
        CBAdESDetachedObjectDereferenceContext? dereferenceContext,
        CBAdESUnknownDetachedObjectMechanismDelegate? unknownMechanismHandler,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(privateKey);

        CryptoAlgorithm algorithm = privateKey.Tag.Get<CryptoAlgorithm>();
        Purpose purpose = privateKey.Tag.Get<Purpose>();
        SigningDelegate signingDelegate =
            CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveSigning(algorithm, purpose);

        return SignAsync(
            headers,
            payloadInput,
            unsignedHeaders,
            encodeProtectedHeader,
            encodeUnprotectedHeader,
            buildSigStructure,
            privateKey,
            signingDelegate,
            dereference,
            dereferenceContext,
            unknownMechanismHandler,
            pool,
            cancellationToken: cancellationToken);
    }


    /// <summary>
    /// Creates a CB-AdES-B-B signature using an explicit signing delegate.
    /// </summary>
    /// <param name="headers">See the registry-resolved overload.</param>
    /// <param name="payloadInput">See the registry-resolved overload.</param>
    /// <param name="unsignedHeaders">See the registry-resolved overload.</param>
    /// <param name="encodeProtectedHeader">See the registry-resolved overload.</param>
    /// <param name="encodeUnprotectedHeader">See the registry-resolved overload.</param>
    /// <param name="buildSigStructure">See the registry-resolved overload.</param>
    /// <param name="privateKey">See the registry-resolved overload.</param>
    /// <param name="signingDelegate">The signing delegate to use.</param>
    /// <param name="dereference">See the registry-resolved overload.</param>
    /// <param name="dereferenceContext">See the registry-resolved overload.</param>
    /// <param name="unknownMechanismHandler">See the registry-resolved overload.</param>
    /// <param name="pool">See the registry-resolved overload.</param>
    /// <param name="eventSink">
    /// Receives the <see cref="SignatureProducedEvent"/> the resolved <paramref name="signingDelegate"/>
    /// constructs, or <see langword="null"/> to route it to <see cref="CryptographicKeyEvents.DefaultSink"/> —
    /// see <see cref="CryptoEventSink"/> for the two-route rationale <see cref="Cose"/> documents.
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The signature creation result. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException">Any required argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="headers"/>.<see cref="CBAdESProtectedHeaders.DetachedObjects"/> is already non-null; a
    /// <see cref="CBAdESDetachedSigDPayloadInput"/> was supplied with no <paramref name="dereferenceContext"/>;
    /// a built-in mechanism was combined with a <c>hashM</c> presence that mechanism forbids/requires
    /// (CB-5.2.8.2.2-02/CB-5.2.8.2.3-02); or an unrecognized mechanism carried a non-null <c>hashM</c> (see
    /// <see cref="CBAdESUnknownDetachedObjectMechanismDelegate"/>'s remarks).
    /// </exception>
    /// <exception cref="NotSupportedException">
    /// At least one B-B rule is violated (<see cref="CBAdESHeaderRules.EnsureConformant"/>'s
    /// <see cref="ArgumentException"/> is NOT what is thrown for that case — see the next remark); a <c>hashM</c>
    /// digest algorithm other than SHA-256/384/512 was supplied; or an unrecognized <c>mId</c> was supplied with
    /// no <paramref name="unknownMechanismHandler"/> (CB-5.2.6-07/CB-5.2.8-08).
    /// </exception>
    /// <exception cref="CBAdESDetachedObjectDereferenceException">A referenced detached object could not be dereferenced.</exception>
    /// <remarks>
    /// <strong>Same-payload invariant with <see cref="CBAdESPayloadTimestampAcquisitionSource"/>.</strong>
    /// When an <c>adoTst</c> was acquired ahead of this call
    /// (<see cref="CBAdESSignatureAugmentation.AcquirePayloadTimestampAsync"/>) and placed into
    /// <paramref name="headers"/>'s <see cref="CBAdESProtectedHeaders.PayloadTimestamps"/>, that acquisition's
    /// own <see cref="CBAdESPayloadTimestampAcquisitionSource"/> and THIS call's <paramref name="payloadInput"/>
    /// must describe the SAME payload — this method never re-derives or cross-checks the imprint that
    /// acquisition already computed against <paramref name="payloadInput"/>'s resolved bytes. A caller-side
    /// mismatch is never caught here; it surfaces only at validation, as a
    /// <see cref="CBAdESTimestampTokenBindingViolation"/> naming
    /// <see cref="CBAdESTimestampTokenBindingKind.PayloadTimestamp"/> and
    /// <see cref="CBAdESTimestampTokenBindingFailureReason.ImprintMismatch"/>. See
    /// <see cref="CBAdESSigningPayloadInput"/>'s own remarks for why <paramref name="payloadInput"/>'s sum and
    /// <see cref="CBAdESPayloadTimestampAcquisitionSource"/> stay deliberately separate types rather than one
    /// unified shape (a recorded design call).
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "CompleteHeaders (below) returns a new CBAdESProtectedHeaders sharing every unchanged " +
            "member -- X5T, CertificateDigests, PayloadTimestamps, SignaturePolicyIdentifier, and the rest -- by " +
            "reference with the caller-owned `headers` argument; only DetachedObjects/CriticalLabels are " +
            "genuinely new. Roslyn sees a locally-constructed IDisposable assigned to `effectiveHeaders` with no " +
            "visible Dispose call, but the true ownership split is: `headers` (and therefore every shared member " +
            "effectiveHeaders carries) transfers to the returned CBAdESSignatureCreationResult on success, and " +
            "the catch clause below disposes resolution.DetachedObjects -- the one internally-" +
            "built member -- on every failure path (CB-5.1.3-03 is the canonical trigger a PASS 2 rule check can " +
            "reach only after that member exists). effectiveHeaders itself is never disposed directly on either " +
            "path.")]
    public static async ValueTask<CBAdESSignatureCreationResult> SignAsync(
        CBAdESProtectedHeaders headers,
        CBAdESSigningPayloadInput payloadInput,
        CBAdESUnsignedHeaders? unsignedHeaders,
        EncodeCBAdESProtectedHeaderDelegate encodeProtectedHeader,
        EncodeCBAdESUnprotectedHeaderDelegate encodeUnprotectedHeader,
        BuildSigStructureDelegate buildSigStructure,
        PrivateKeyMemory privateKey,
        SigningDelegate signingDelegate,
        CBAdESDetachedObjectDereferenceDelegate? dereference,
        CBAdESDetachedObjectDereferenceContext? dereferenceContext,
        CBAdESUnknownDetachedObjectMechanismDelegate? unknownMechanismHandler,
        BaseMemoryPool pool,
        CryptoEventSink? eventSink = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(headers);
        ArgumentNullException.ThrowIfNull(payloadInput);
        ArgumentNullException.ThrowIfNull(encodeProtectedHeader);
        ArgumentNullException.ThrowIfNull(encodeUnprotectedHeader);
        ArgumentNullException.ThrowIfNull(buildSigStructure);
        ArgumentNullException.ThrowIfNull(privateKey);
        ArgumentNullException.ThrowIfNull(signingDelegate);
        ArgumentNullException.ThrowIfNull(pool);

        cancellationToken.ThrowIfCancellationRequested();

        if(headers.DetachedObjects is not null)
        {
            throw new ArgumentException(
                "This orchestrator is the sole producer of DetachedObjects (see the class remarks) -- supply " +
                "the sigD reference set through payloadInput's CBAdESDetachedSigDPayloadInput arm instead of " +
                "pre-populating headers.DetachedObjects.",
                nameof(headers));
        }

        bool payloadIsDetached = payloadInput switch
        {
            CBAdESAttachedPayloadInput => false,
            CBAdESDetachedExternalPayloadInput => true,
            CBAdESDetachedSigDPayloadInput => true,
            _ => throw new NotSupportedException($"Unrecognized {nameof(CBAdESSigningPayloadInput)} kind '{payloadInput.GetType().Name}'.")
        };

        //PASS 1 -- see the class remarks for why this runs before any dereferencing I/O, and why a second pass
        //follows mechanism resolution.
        CBAdESHeaderRules.EnsureConformant(headers, payloadIsDetached, unsignedHeaders);

        PayloadResolution resolution = await ResolvePayloadAsync(
            payloadInput, dereference, dereferenceContext, unknownMechanismHandler, pool, cancellationToken).ConfigureAwait(false);

        try
        {
            CBAdESProtectedHeaders effectiveHeaders = resolution.DetachedObjects is null
                ? headers
                : CompleteHeaders(headers, resolution.DetachedObjects, MergeCriticalLabel(headers.CriticalLabels, new CoseHeaderIntegerLabel(CBAdESHeaderParameters.SigD)));

            //PASS 2 -- the final gate, now able to see the sigD-mechanism-digest-presence rules; still strictly
            //before any cryptographic signing call below.
            CBAdESHeaderRules.EnsureConformant(effectiveHeaders, payloadIsDetached, unsignedHeaders);

            EncodedCoseProtectedHeader encodedProtectedHeader = encodeProtectedHeader(effectiveHeaders, pool);
            CoseSign1Message signed;
            try
            {
                IReadOnlyDictionary<int, object>? unprotectedHeader = encodeUnprotectedHeader(unsignedHeaders, pool);

                signed = await Cose.SignAsync(
                    encodedProtectedHeader,
                    unprotectedHeader,
                    resolution.SigningPayload,
                    buildSigStructure,
                    privateKey,
                    signingDelegate,
                    pool,
                    eventSink,
                    cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                encodedProtectedHeader.Dispose();
                throw;
            }

            //Ownership of encodedProtectedHeader has transferred into `signed` (Cose.SignAsync's own contract);
            //any failure from here on disposes `signed`, never encodedProtectedHeader directly (see the class
            //remarks for the wire-detach step this performs for every detached arm).
            try
            {
                if(payloadIsDetached)
                {
                    CoseSign1Message attached = signed;
                    signed = new CoseSign1Message(attached.ProtectedHeader, attached.UnprotectedHeader, ReadOnlyMemory<byte>.Empty, attached.Signature);
                }

                return new CBAdESSignatureCreationResult(signed, effectiveHeaders);
            }
            catch
            {
                signed.Dispose();
                throw;
            }
        }
        catch
        {
            //resolution.DetachedObjects is the ONLY internally-built member effectiveHeaders can
            //own that `headers` (the caller's own aggregate) does not already own -- when non-null, it was
            //allocated by ResolveSigDPayloadAsync above (its per-entry hashV digests included) and has not yet
            //been attached to anything this method has returned ownership of, so a failure anywhere in this try
            //(PASS 2's CBAdESHeaderRules.EnsureConformant, e.g. CB-5.1.3-03; the protected-header encode; the
            //signing call itself) must dispose it here or its digest/entry pool rentals leak. `effectiveHeaders`
            //itself is NEVER disposed: when resolution.DetachedObjects is null it IS `headers` (caller-owned,
            //disposed by the caller on a throw), and even when CompleteHeaders built a new instance, every OTHER
            //member on it (X5T, CertificateDigests, PayloadTimestamps, SignaturePolicyIdentifier, ...) is shared
            //by reference with `headers` -- disposing the aggregate here would double-dispose caller state.
            resolution.DetachedObjects?.Dispose();
            throw;
        }
        finally
        {
            resolution.RentedSigningPayload?.Dispose();
        }
    }


    /// <summary>
    /// Resolves <paramref name="input"/> into the bytes the Sig_structure covers, the completed
    /// <see cref="CBAdESDetachedObjects"/> (when <paramref name="input"/> is a <see cref="CBAdESDetachedSigDPayloadInput"/>),
    /// and which pool-rented buffer (if any) the caller must dispose. Shared by both
    /// <see cref="SignAsync(CBAdESProtectedHeaders, CBAdESSigningPayloadInput, CBAdESUnsignedHeaders?, EncodeCBAdESProtectedHeaderDelegate, EncodeCBAdESUnprotectedHeaderDelegate, BuildSigStructureDelegate, PrivateKeyMemory, SigningDelegate, CBAdESDetachedObjectDereferenceDelegate?, CBAdESDetachedObjectDereferenceContext?, CBAdESUnknownDetachedObjectMechanismDelegate?, BaseMemoryPool, CryptoEventSink?, CancellationToken)"/>
    /// (<c>COSE_Sign1</c>) and <see cref="SignCoseSignAsync"/> (<c>COSE_Sign</c>, one shared resolution for the
    /// message's ONE payload field, RFC 9052 §4.1).
    /// </summary>
    /// <param name="input">The payload input to resolve.</param>
    /// <param name="dereferenceDelegate">The <c>sigD</c> dereference seam.</param>
    /// <param name="context">The per-call dereference context.</param>
    /// <param name="unknownHandler">The unknown-<c>mId</c> handler.</param>
    /// <param name="rentPool">The memory pool every allocation this call performs is rented from.</param>
    /// <param name="token">Cancellation token.</param>
    /// <returns>The resolved payload; see <see cref="PayloadResolution"/>.</returns>
    private static ValueTask<PayloadResolution> ResolvePayloadAsync(
        CBAdESSigningPayloadInput input,
        CBAdESDetachedObjectDereferenceDelegate? dereferenceDelegate,
        CBAdESDetachedObjectDereferenceContext? context,
        CBAdESUnknownDetachedObjectMechanismDelegate? unknownHandler,
        BaseMemoryPool rentPool,
        CancellationToken token) => input switch
    {
        CBAdESAttachedPayloadInput attached =>
            ValueTask.FromResult(new PayloadResolution(null, attached.Payload, null)),

        CBAdESDetachedExternalPayloadInput external =>
            ValueTask.FromResult(new PayloadResolution(null, external.Payload, null)),

        CBAdESDetachedSigDPayloadInput sigD =>
            ResolveSigDPayloadAsync(sigD, dereferenceDelegate, context, unknownHandler, rentPool, token),

        _ => throw new NotSupportedException($"Unrecognized {nameof(CBAdESSigningPayloadInput)} kind '{input.GetType().Name}'.")
    };


    /// <summary>
    /// Resolves a <see cref="CBAdESDetachedSigDPayloadInput"/>: dispatches on
    /// <see cref="CBAdESDetachedSigDPayloadInput.MechanismIdentifier"/> to either mechanism this document
    /// defines, or the caller-supplied <paramref name="unknownHandler"/> for anything else.
    /// </summary>
    /// <param name="sigD">The sigD payload input to resolve.</param>
    /// <param name="dereferenceDelegate">The dereference delegate.</param>
    /// <param name="context">The per-call dereference context.</param>
    /// <param name="unknownHandler">The unknown-mechanism extension point.</param>
    /// <param name="rentPool">The memory pool every allocation this call performs is rented from.</param>
    /// <param name="token">Cancellation token.</param>
    /// <returns>The resolved payload; see <see cref="PayloadResolution"/>.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Each of the three CBAdESDetachedObjects this method constructs (one per mechanism " +
            "arm) is returned as PayloadResolution.DetachedObjects: ownership either transfers into the " +
            "completed CBAdESProtectedHeaders aggregate CompleteHeaders builds in the calling method, or is " +
            "disposed by that method's catch clause on any later failure. Roslyn cannot see " +
            "across this method's ValueTask return into the caller-side try/catch that actually owns the " +
            "disposal decision.")]
    private static async ValueTask<PayloadResolution> ResolveSigDPayloadAsync(
        CBAdESDetachedSigDPayloadInput sigD,
        CBAdESDetachedObjectDereferenceDelegate? dereferenceDelegate,
        CBAdESDetachedObjectDereferenceContext? context,
        CBAdESUnknownDetachedObjectMechanismDelegate? unknownHandler,
        BaseMemoryPool rentPool,
        CancellationToken token)
    {
        if(sigD.References is null || sigD.References.Count == 0)
        {
            throw new ArgumentException(
                "sigD shall reference one or more detached data objects (ETSI TS 119 152-1 V1.1.1, clause 5.2.8.1, CB-5.2.8-06).",
                nameof(sigD));
        }

        if(context is null)
        {
            throw new ArgumentException(
                "A CBAdESDetachedSigDPayloadInput requires a non-null dereference context.",
                nameof(context));
        }

        if(CBAdESDetachedMechanisms.IsObjectIdByURI(sigD.MechanismIdentifier))
        {
            if(sigD.HashAlgorithm is not null)
            {
                throw new ArgumentException(
                    "Under the ObjectIdByURI mechanism, neither hashM nor hashV shall be present (ETSI TS " +
                    "119 152-1 V1.1.1, clause 5.2.8.2.2, CB-5.2.8.2.2-02).",
                    nameof(sigD));
            }

            if(dereferenceDelegate is null)
            {
                throw new ArgumentException(
                    "The ObjectIdByURI mechanism requires a non-null dereference delegate.",
                    nameof(dereferenceDelegate));
            }

            var references = new string[sigD.References.Count];
            for(int i = 0; i < sigD.References.Count; ++i)
            {
                references[i] = sigD.References[i].Reference;
            }

            PooledMemory reconstructed = await CBAdESDetachedObjectDereferencing.ReconstructObjectIdByURIPayloadAsync(
                references, dereferenceDelegate, context, rentPool, token).ConfigureAwait(false);
            try
            {
                var entries = new List<CBAdESDetachedObjectEntry>(sigD.References.Count);
                for(int i = 0; i < sigD.References.Count; ++i)
                {
                    entries.Add(new CBAdESDetachedObjectEntry(sigD.References[i].Reference, digest: null, sigD.References[i].ContentType));
                }

                var detachedObjects = new CBAdESDetachedObjects(sigD.MechanismIdentifier, entries, hashAlgorithm: null);

                return new PayloadResolution(detachedObjects, reconstructed.AsReadOnlyMemory(), reconstructed);
            }
            catch
            {
                reconstructed.Dispose();
                throw;
            }
        }

        if(CBAdESDetachedMechanisms.IsObjectIdByURIHash(sigD.MechanismIdentifier))
        {
            if(sigD.HashAlgorithm is null)
            {
                throw new ArgumentException(
                    "Under the ObjectIdByURIHash mechanism, both hashM and hashV shall be present (ETSI TS " +
                    "119 152-1 V1.1.1, clause 5.2.8.2.3, CB-5.2.8.2.3-02).",
                    nameof(sigD));
            }

            if(dereferenceDelegate is null)
            {
                throw new ArgumentException(
                    "The ObjectIdByURIHash mechanism requires a non-null dereference delegate.",
                    nameof(dereferenceDelegate));
            }

            (Tag digestTag, int outputByteLength) = ResolveDigestParameters(sigD.HashAlgorithm);

            //Every entry this loop adds owns a real DigestValue (unlike the other two branches, whose
            //entries carry no digest) -- a mid-loop failure (a later reference's dereference failing, or
            //cancellation) must dispose every digest already computed, or those pool rentals leak.
            var entries = new List<CBAdESDetachedObjectEntry>(sigD.References.Count);
            try
            {
                for(int i = 0; i < sigD.References.Count; ++i)
                {
                    token.ThrowIfCancellationRequested();

                    CBAdESDetachedObjectReferenceInput reference = sigD.References[i];
                    CBAdESDetachedObjectDereferenceResult dereferenced = await dereferenceDelegate(
                        reference.Reference, context, rentPool, token).ConfigureAwait(false);

                    if(dereferenced is not CBAdESDetachedObjectDereferenceSuccess success)
                    {
                        string reason = dereferenced is CBAdESDetachedObjectDereferenceFailure failure
                            ? failure.Reason
                            : "the dereference delegate returned neither a success nor a failure result.";

                        throw new CBAdESDetachedObjectDereferenceException(reference.Reference, reason);
                    }

                    using(success.Content)
                    {
                        DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
                            success.Content.AsReadOnlyMemory(), outputByteLength, digestTag, rentPool,
                            cancellationToken: token).ConfigureAwait(false);

                        entries.Add(new CBAdESDetachedObjectEntry(reference.Reference, digest, reference.ContentType));
                    }
                }

                var detachedObjects = new CBAdESDetachedObjects(sigD.MechanismIdentifier, entries, sigD.HashAlgorithm);

                //CB-5.2.8.2.3-06: the COSE Payload contributes as an empty stream to the signature-value
                //computation under this mechanism -- no rented signing-payload buffer to dispose.
                return new PayloadResolution(detachedObjects, ReadOnlyMemory<byte>.Empty, null);
            }
            catch
            {
                for(int i = 0; i < entries.Count; ++i)
                {
                    entries[i].Dispose();
                }

                throw;
            }
        }

        //Unknown mId (CB-5.2.6-07/CB-5.2.8-08) -- see CBAdESUnknownDetachedObjectMechanismDelegate's remarks
        //for this extension point's documented scope limit.
        if(sigD.HashAlgorithm is not null)
        {
            throw new ArgumentException(
                "An unrecognized sigD mechanism carrying a non-null hashM is not supported by this " +
                "extension point (CBAdESUnknownDetachedObjectMechanismDelegate retrieves the COSE Payload " +
                "only, per CB-5.2.6-07's literal wording, and cannot produce the per-entry digests a " +
                "non-null hashM on CBAdESDetachedObjects would require) -- leave hashM null for a " +
                "third-party mechanism, or use one of the two built-in mechanisms.",
                nameof(sigD));
        }

        if(unknownHandler is null)
        {
            throw new NotSupportedException(
                $"sigD.mId '{sigD.MechanismIdentifier}' is neither ObjectIdByURI nor ObjectIdByURIHash, and " +
                "no unknown-mechanism handler was supplied; the specification defining that mId value shall " +
                "specify how to retrieve the COSE Payload (ETSI TS 119 152-1 V1.1.1, clause 5.2.6, " +
                "CB-5.2.6-07; clause 5.2.8.1, CB-5.2.8-08).");
        }

        var unknownEntries = new List<CBAdESDetachedObjectEntry>(sigD.References.Count);
        for(int i = 0; i < sigD.References.Count; ++i)
        {
            unknownEntries.Add(new CBAdESDetachedObjectEntry(sigD.References[i].Reference, digest: null, sigD.References[i].ContentType));
        }

        PooledMemory unknownPayload = await unknownHandler(
            sigD.MechanismIdentifier, sigD.References, sigD.HashAlgorithm, context, rentPool, token).ConfigureAwait(false);

        var unknownDetachedObjects = new CBAdESDetachedObjects(sigD.MechanismIdentifier, unknownEntries, hashAlgorithm: null);

        return new PayloadResolution(unknownDetachedObjects, unknownPayload.AsReadOnlyMemory(), unknownPayload);
    }


    /// <summary>
    /// Resolves the <see cref="Tag"/> and output byte length the registered digest delegate needs for
    /// <paramref name="identifier"/> — only SHA-256/384/512 resolve, matching
    /// <see cref="CBAdESHeaderRules"/>'s documented MD5-denylist coverage for every <c>hashAlg</c>-typed
    /// surface: MD5 (and any other unrecognized identifier) is refused here, before any dereferencing for
    /// the entry it would apply to.
    /// </summary>
    /// <param name="identifier">The <c>hashM</c> digest-algorithm identifier.</param>
    /// <returns>The digest tag and output byte length.</returns>
    /// <exception cref="NotSupportedException"><paramref name="identifier"/> is not SHA-256/384/512.</exception>
    private static (Tag DigestTag, int OutputByteLength) ResolveDigestParameters(AdESDigestAlgorithmIdentifier identifier) => identifier switch
    {
        AdESDigestAlgorithmIntegerIdentifier { Value: WellKnownCoseAlgorithms.Sha256 } => (CryptoTags.Sha256Digest, 32),
        AdESDigestAlgorithmIntegerIdentifier { Value: WellKnownCoseAlgorithms.Sha384 } => (CryptoTags.Sha384Digest, 48),
        AdESDigestAlgorithmIntegerIdentifier { Value: WellKnownCoseAlgorithms.Sha512 } => (CryptoTags.Sha512Digest, 64),
        AdESDigestAlgorithmTextIdentifier text when WellKnownHashAlgorithms.IsSha256(text.Value) => (CryptoTags.Sha256Digest, 32),
        AdESDigestAlgorithmTextIdentifier text when WellKnownHashAlgorithms.IsSha384(text.Value) => (CryptoTags.Sha384Digest, 48),
        AdESDigestAlgorithmTextIdentifier text when WellKnownHashAlgorithms.IsSha512(text.Value) => (CryptoTags.Sha512Digest, 64),
        _ => throw new NotSupportedException(
            $"Digest algorithm '{identifier}' is not supported for sigD hashV computation (ETSI TS 119 " +
            "152-1 V1.1.1, clause 5.2.8.1; clause 6.2.1, CB-6.2.1-02 -- only SHA-256/384/512 resolve " +
            "through the registered digest delegate).")
    };


    /// <summary>
    /// Returns <paramref name="existing"/> with <paramref name="label"/> appended, unless it is already
    /// present (record equality), per CB-5.1.10-04 (creation
    /// auto-adds <c>sigD</c>'s label to <c>crit</c>).
    /// </summary>
    /// <param name="existing">The caller-supplied <c>crit</c> labels, or <see langword="null"/>.</param>
    /// <param name="label">The label to ensure is present.</param>
    /// <returns>A list containing every entry of <paramref name="existing"/> plus <paramref name="label"/> if absent.</returns>
    private static IReadOnlyList<CoseHeaderLabel> MergeCriticalLabel(IReadOnlyList<CoseHeaderLabel>? existing, CoseHeaderLabel label)
    {
        if(existing is null)
        {
            return [label];
        }

        for(int i = 0; i < existing.Count; ++i)
        {
            if(existing[i].Equals(label))
            {
                return existing;
            }
        }

        var merged = new CoseHeaderLabel[existing.Count + 1];
        for(int i = 0; i < existing.Count; ++i)
        {
            merged[i] = existing[i];
        }

        merged[^1] = label;

        return merged;
    }


    /// <summary>
    /// Reconstructs <paramref name="original"/> with <paramref name="detachedObjects"/> and
    /// <paramref name="criticalLabels"/> substituted, every other member carried over unchanged (the
    /// "completed aggregate").
    /// </summary>
    /// <remarks>
    /// <strong>Not a <c>with</c> expression, recorded here.</strong> <see cref="CBAdESProtectedHeaders"/>'s
    /// members are plain get-only auto-properties assigned only through its explicit constructor —
    /// none carries an <c>init</c> accessor, so a <c>with</c> expression targeting
    /// <see cref="CBAdESProtectedHeaders.DetachedObjects"/>/<see cref="CBAdESProtectedHeaders.CriticalLabels"/>
    /// does not compile (CS0200: the property has no accessible setter). This helper calls the public
    /// constructor directly instead, which achieves the identical outcome — a new instance sharing every
    /// unchanged owned member's reference with <paramref name="original"/> (X5T, CertificateDigests,
    /// PayloadTimestamps, SignaturePolicyIdentifier) while owning the two substituted members — at the cost
    /// of enumerating all 16 constructor parameters. If a future change wants <c>with</c>-expression
    /// ergonomics on this type, that is an owner-level type-shape decision, not made unilaterally here.
    /// </remarks>
    /// <param name="original">The signed-header-set aggregate to reconstruct from.</param>
    /// <param name="detachedObjects">The completed <c>sigD</c> component.</param>
    /// <param name="criticalLabels">The merged <c>crit</c> labels.</param>
    /// <returns>A new <see cref="CBAdESProtectedHeaders"/> carrying every unchanged member of <paramref name="original"/>.</returns>
    private static CBAdESProtectedHeaders CompleteHeaders(
        CBAdESProtectedHeaders original,
        CBAdESDetachedObjects detachedObjects,
        IReadOnlyList<CoseHeaderLabel> criticalLabels) =>
        new(
            original.Algorithm,
            original.CwtClaims,
            original.ContentType,
            original.KeyId,
            original.X5U,
            original.X5T,
            original.X5Chain,
            original.CertificateDigests,
            original.SignerCommitments,
            original.SignatureProductionPlace,
            original.SignerAttributes,
            original.PayloadTimestamps,
            original.SignaturePolicyIdentifier,
            detachedObjects,
            criticalLabels,
            original.UnprofiledHeaders);


    /// <summary>
    /// Creates a CB-AdES-B-B signature over a <c>COSE_Sign</c> (multi-signer) structure — the multi-signer
    /// counterpart of <see cref="SignAsync(CBAdESProtectedHeaders, CBAdESSigningPayloadInput, CBAdESUnsignedHeaders?, EncodeCBAdESProtectedHeaderDelegate, EncodeCBAdESUnprotectedHeaderDelegate, BuildSigStructureDelegate, PrivateKeyMemory, CBAdESDetachedObjectDereferenceDelegate?, CBAdESDetachedObjectDereferenceContext?, CBAdESUnknownDetachedObjectMechanismDelegate?, BaseMemoryPool, CancellationToken)"/>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <strong>The B-B rule body runs once, reused, per signer — never forked.</strong> Each entry of
    /// <paramref name="signers"/> is checked through the IDENTICAL <see cref="CBAdESHeaderRules.EnsureConformant"/>
    /// call the <c>COSE_Sign1</c> overloads above run once for the whole message — clause 4.4's own permission
    /// ("CB-AdES signatures supported by a <c>COSE_Sign</c> structure... May include protected header
    /// parameters in both, the body layer and the signer layer") makes each signer layer the natural per-call
    /// unit for that rule body, since every clause-5.1/5.2 signed-header rule (<c>alg</c> mandatory, the MD5
    /// denylist, the <c>iat</c> presence rule, <c>crit</c>) is stated about a signer's OWN protected header,
    /// regardless of which COSE structure carries it.
    /// </para>
    /// <para>
    /// <strong><c>sigD</c>: one shared resolution, completing every signer alike.</strong> RFC
    /// 9052 §4.1 gives <c>COSE_Sign</c> exactly one <c>payload</c> field for however many signers, so
    /// <paramref name="payloadInput"/> is resolved ONCE, through the identical mechanism
    /// <see cref="SignAsync(CBAdESProtectedHeaders, CBAdESSigningPayloadInput, CBAdESUnsignedHeaders?, EncodeCBAdESProtectedHeaderDelegate, EncodeCBAdESUnprotectedHeaderDelegate, BuildSigStructureDelegate, PrivateKeyMemory, CBAdESDetachedObjectDereferenceDelegate?, CBAdESDetachedObjectDereferenceContext?, CBAdESUnknownDetachedObjectMechanismDelegate?, BaseMemoryPool, CancellationToken)"/>
    /// uses for <c>COSE_Sign1</c>, and the resulting completed <c>sigD</c> component is shared by reference
    /// into EVERY signer's own completed headers (idempotent <see cref="IDisposable.Dispose"/>, this library's
    /// own convention, makes that sharing safe — each signer's completed aggregate is disposed independently
    /// by <see cref="CBAdESCoseSignSignatureCreationResult.Dispose"/>, and only the first of those reaches the
    /// shared <c>sigD</c> component's own <c>Dispose</c>). This is the scoped design choice this overload
    /// makes among the several a genuinely per-signer-distinct <c>sigD</c> COULD support: every signer either
    /// shares the ONE resolved detached-object description or carries none, never a per-signer mix.
    /// </para>
    /// <para>
    /// This overload places NO content in the body layer (an empty protected header, no unprotected
    /// <c>uHeaders</c> — clause 4.4 bullet 2: "shall not contain the <c>uHeaders</c> unprotected header
    /// parameter in the body layer").
    /// </para>
    /// <para>
    /// Each signer's own protected/unprotected headers encode through the SAME <see cref="EncodeCBAdESProtectedHeaderDelegate"/>/
    /// <see cref="EncodeCBAdESUnprotectedHeaderDelegate"/> seams the <c>COSE_Sign1</c> path uses, and signing
    /// itself composes <see cref="CoseSign.SignAsync(EncodedCoseProtectedHeader, IReadOnlyDictionary{int, object}?, ReadOnlyMemory{byte}, IReadOnlyList{CoseSignerInput}, BuildCoseSignatureSigStructureDelegate, BaseMemoryPool, CryptoEventSink?, CancellationToken)"/>
    /// — never a parallel per-signer signing loop.
    /// </para>
    /// </remarks>
    /// <param name="payloadInput">The single COSE Payload every signer's Sig_structure covers; see <see cref="CBAdESSigningPayloadInput"/>.</param>
    /// <param name="signers">The per-signer inputs, in wire order. At least one is required. <see cref="CBAdESCoseSignSignerInput.Headers"/>.<see cref="CBAdESProtectedHeaders.DetachedObjects"/> shall be <see langword="null"/> — see the class remarks for why this orchestrator is the sole producer of that member.</param>
    /// <param name="encodeProtectedHeader">The protected-header CBOR encode seam.</param>
    /// <param name="encodeUnprotectedHeader">The unprotected-header (<c>uHeaders</c>) CBOR encode seam.</param>
    /// <param name="buildSigStructure">Delegate to build the <c>COSE_Signature</c> Sig_structure for signing.</param>
    /// <param name="pool">Memory pool every allocation this call performs is rented from.</param>
    /// <param name="dereference">
    /// The <c>sigD</c> URI-reference dereference delegate; required when <paramref name="payloadInput"/> is a
    /// <see cref="CBAdESDetachedSigDPayloadInput"/> selecting a built-in mechanism, otherwise unused.
    /// </param>
    /// <param name="dereferenceContext">
    /// The per-call caller state for <paramref name="dereference"/>/<paramref name="unknownMechanismHandler"/>;
    /// required whenever <paramref name="payloadInput"/> is a <see cref="CBAdESDetachedSigDPayloadInput"/>.
    /// </param>
    /// <param name="unknownMechanismHandler">
    /// The extension point for a third-party <c>mId</c>; see <see cref="CBAdESUnknownDetachedObjectMechanismDelegate"/>.
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The signature creation result. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException">Any required argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="signers"/> is empty; a signer's <see cref="CBAdESProtectedHeaders.DetachedObjects"/> was
    /// already non-null; or a <see cref="CBAdESDetachedSigDPayloadInput"/> was supplied with no
    /// <paramref name="dereferenceContext"/>.
    /// </exception>
    /// <exception cref="NotSupportedException">At least one signer's headers violate a B-B rule (<see cref="CBAdESHeaderRules.EnsureConformant"/>); or an unrecognized <c>mId</c> was supplied with no <paramref name="unknownMechanismHandler"/>.</exception>
    /// <exception cref="CBAdESDetachedObjectDereferenceException">A referenced detached object could not be dereferenced.</exception>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Every signerEffectiveHeaders CompleteHeaders builds shares every member but the " +
            "completed sigD/crit with its own signer's caller-owned Headers by reference (mirrors SignAsync's " +
            "own effectiveHeaders precedent); resolution.DetachedObjects -- the one internally-built member " +
            "every completed signer shares -- is disposed by the catch clause below on any failure, and " +
            "transfers into the returned CBAdESCoseSignSignatureCreationResult's SignerHeaders on success. " +
            "Roslyn tracks each locally-built signerEffectiveHeaders itself, not the fact that it is reachable " +
            "through effectiveHeaders/the returned result several statements later.")]
    public static async ValueTask<CBAdESCoseSignSignatureCreationResult> SignCoseSignAsync(
        CBAdESSigningPayloadInput payloadInput,
        IReadOnlyList<CBAdESCoseSignSignerInput> signers,
        EncodeCBAdESProtectedHeaderDelegate encodeProtectedHeader,
        EncodeCBAdESUnprotectedHeaderDelegate encodeUnprotectedHeader,
        BuildCoseSignatureSigStructureDelegate buildSigStructure,
        BaseMemoryPool pool,
        CBAdESDetachedObjectDereferenceDelegate? dereference = null,
        CBAdESDetachedObjectDereferenceContext? dereferenceContext = null,
        CBAdESUnknownDetachedObjectMechanismDelegate? unknownMechanismHandler = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(payloadInput);
        ArgumentNullException.ThrowIfNull(signers);
        ArgumentNullException.ThrowIfNull(encodeProtectedHeader);
        ArgumentNullException.ThrowIfNull(encodeUnprotectedHeader);
        ArgumentNullException.ThrowIfNull(buildSigStructure);
        ArgumentNullException.ThrowIfNull(pool);

        if(signers.Count == 0)
        {
            throw new ArgumentException("COSE_Sign requires at least one signer.", nameof(signers));
        }

        cancellationToken.ThrowIfCancellationRequested();

        bool payloadIsDetached = payloadInput switch
        {
            CBAdESAttachedPayloadInput => false,
            CBAdESDetachedExternalPayloadInput => true,
            CBAdESDetachedSigDPayloadInput => true,
            _ => throw new NotSupportedException($"Unrecognized {nameof(CBAdESSigningPayloadInput)} kind '{payloadInput.GetType().Name}'.")
        };

        //PASS 1 -- see CBAdESSignatureCreation's own class remarks for why this runs before any dereferencing
        //I/O, and why a second pass follows mechanism resolution; strictly before any encoding or signing too
        //(mirroring the COSE_Sign1 overloads' own PASS-1-before-any-I/O posture).
        for(int i = 0; i < signers.Count; ++i)
        {
            if(signers[i].Headers.DetachedObjects is not null)
            {
                throw new ArgumentException(
                    "This orchestrator is the sole producer of DetachedObjects (see the class remarks) -- " +
                    "supply the sigD reference set through payloadInput's CBAdESDetachedSigDPayloadInput arm " +
                    "instead of pre-populating a signer's Headers.DetachedObjects.",
                    nameof(signers));
            }

            CBAdESHeaderRules.EnsureConformant(signers[i].Headers, payloadIsDetached, signers[i].UnsignedHeaders);
        }

        PayloadResolution resolution = await ResolvePayloadAsync(
            payloadInput, dereference, dereferenceContext, unknownMechanismHandler, pool, cancellationToken).ConfigureAwait(false);

        EncodedCoseProtectedHeader bodyProtectedHeader = EncodedCoseProtectedHeader.FromBytes(ReadOnlySpan<byte>.Empty, pool);
        var coseSignerInputs = new List<CoseSignerInput>(signers.Count);
        var effectiveHeaders = new List<CBAdESProtectedHeaders>(signers.Count);
        try
        {
            for(int i = 0; i < signers.Count; ++i)
            {
                CBAdESProtectedHeaders signerEffectiveHeaders;
                if(resolution.DetachedObjects is null)
                {
                    signerEffectiveHeaders = signers[i].Headers;
                }
                else
                {
                    IReadOnlyList<CoseHeaderLabel> signerCriticalLabels = MergeCriticalLabel(signers[i].Headers.CriticalLabels, new CoseHeaderIntegerLabel(CBAdESHeaderParameters.SigD));
                    signerEffectiveHeaders = CompleteHeaders(signers[i].Headers, resolution.DetachedObjects, signerCriticalLabels);
                }

                effectiveHeaders.Add(signerEffectiveHeaders);

                //PASS 2 -- the final gate, now able to see the sigD-mechanism-digest-presence rules; still
                //strictly before any cryptographic signing call below.
                CBAdESHeaderRules.EnsureConformant(signerEffectiveHeaders, payloadIsDetached, signers[i].UnsignedHeaders);

                EncodedCoseProtectedHeader encodedSignerProtectedHeader = encodeProtectedHeader(signerEffectiveHeaders, pool);
                IReadOnlyDictionary<int, object>? unprotectedHeader = encodeUnprotectedHeader(signers[i].UnsignedHeaders, pool);

                coseSignerInputs.Add(new CoseSignerInput(encodedSignerProtectedHeader, unprotectedHeader, signers[i].PrivateKey));
            }

            CoseSignMessage signed = await CoseSign.SignAsync(
                bodyProtectedHeader, bodyUnprotectedHeader: null, resolution.SigningPayload, coseSignerInputs, buildSigStructure, pool,
                cancellationToken: cancellationToken).ConfigureAwait(false);

            //Ownership of bodyProtectedHeader and every signer's encoded protected header has transferred into
            //`signed` (CoseSign.SignAsync's own contract); any failure from here on disposes `signed`, never
            //those carriers directly (mirrors SignAsync's own detached wire-detach step above).
            try
            {
                if(payloadIsDetached)
                {
                    CoseSignMessage attached = signed;
                    signed = new CoseSignMessage(attached.ProtectedHeader, attached.UnprotectedHeader, ReadOnlyMemory<byte>.Empty, attached.Signatures);
                }

                return new CBAdESCoseSignSignatureCreationResult(signed, effectiveHeaders);
            }
            catch
            {
                signed.Dispose();
                throw;
            }
        }
        catch
        {
            //Metered custody: on ANY failure above (a mid-loop PASS-2/encode failure, or CoseSign.SignAsync's
            //own failure), dispose every carrier this call rented that has not been proven to have transferred
            //ownership elsewhere. bodyProtectedHeader and every already-encoded signer protected header are
            //disposed defensively -- idempotent Dispose (this library's own convention) makes a redundant
            //dispose of a carrier CoseSign.SignAsync's own internal catch already disposed harmless, and
            //CoseSign.SignAsync's own remarks state bodyProtectedHeader ownership transfers ONLY on its
            //success path, so this call must dispose it itself on any failure. resolution.DetachedObjects is
            //the ONE internally-built member every signerEffectiveHeaders sharing it does not already own
            //independently (shared across every signer here) -- disposed once here
            //regardless of how many signers' effectiveHeaders reference it.
            bodyProtectedHeader.Dispose();
            foreach(CoseSignerInput input in coseSignerInputs)
            {
                input.ProtectedHeader.Dispose();
            }

            resolution.DetachedObjects?.Dispose();

            throw;
        }
        finally
        {
            resolution.RentedSigningPayload?.Dispose();
        }
    }


    /// <summary>
    /// The internal outcome of resolving a <see cref="CBAdESSigningPayloadInput"/>: the completed
    /// <see cref="CBAdESDetachedObjects"/> (or <see langword="null"/> when the input carried no <c>sigD</c>),
    /// the bytes the Sig_structure covers, and which pool-rented buffer (if any) the caller must dispose.
    /// </summary>
    /// <param name="DetachedObjects">The completed <c>sigD</c> component, or <see langword="null"/>.</param>
    /// <param name="SigningPayload">The bytes the Sig_structure covers.</param>
    /// <param name="RentedSigningPayload">
    /// The pool-rented buffer backing <see cref="SigningPayload"/>, when this resolution rented one (the
    /// <see cref="CBAdESDetachedMechanisms.ObjectIdByURI"/> reconstruction, or an unknown-mechanism handler's
    /// result), or <see langword="null"/> when <see cref="SigningPayload"/> is caller-borrowed or empty.
    /// </param>
    private readonly record struct PayloadResolution(
        CBAdESDetachedObjects? DetachedObjects,
        ReadOnlyMemory<byte> SigningPayload,
        PooledMemory? RentedSigningPayload);
}
