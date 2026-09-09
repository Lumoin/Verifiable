using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;

namespace Verifiable.JCose;

/// <summary>
/// Names why an augmentation of a CB-AdES signature could not be performed.
/// </summary>
/// <remarks>
/// These are generator-side faults: an input the caller supplied that the level being reached cannot be built
/// from, mirroring <see cref="Verifiable.Cryptography.Pki.CAdESAugmentationFailureKind"/>'s own rationale.
/// They are deliberately not the indication/sub-indication vocabulary of a validation process, which describes
/// what a verifier concludes about a signature it did not make. A Table 14/Annex A level-rule violation raised
/// by <see cref="CBAdESLevelRules.EnsureConformant"/> is NOT re-classified into this enum — it propagates as
/// its own <see cref="ArgumentException"/> untouched (see the class remarks for why).
/// </remarks>
public enum CBAdESAugmentationFailureKind
{
    /// <summary>No failure has been classified.</summary>
    NotEvaluated = 0,

    /// <summary>The signature being augmented could not be parsed as a well-formed CB-AdES <c>COSE_Sign1</c>.</summary>
    MalformedEncoding = 1,

    /// <summary>
    /// A message-imprint-input builder reported failure (<see langword="false"/>) over this signature's own,
    /// already-successfully-parsed <c>uHeaders</c> bytes — an internal inconsistency between the parse step
    /// and the imprint builder, not a caller-supplied fault.
    /// </summary>
    MessageImprintInputMalformed = 2,

    /// <summary>
    /// A <c>sigRTst</c> or <c>rfsTst</c> element was requested with no <c>refs</c> element present in
    /// <c>uHeaders</c> (CB-A.1.2.1-03 / CB-A.1.2.2-03).
    /// </summary>
    ReferencesElementRequired = 3,

    /// <summary>
    /// A caller-supplied certificate to reference in <c>refs</c> is the CB-AdES signature's own signing
    /// certificate (CB-A.1.1-02).
    /// </summary>
    SigningCertificateReferenceRefused = 4,

    /// <summary>A supplied certificate, CRL, or OCSP response carrier is not of the kind the placement admits.</summary>
    UnsupportedValidationObject = 5,

    /// <summary>
    /// The caller-supplied signing certificate could not be read to check its validity window — either the
    /// carrier is not tagged as an X.509 certificate, or its DER encoding does not parse as one (both are
    /// checked before any Time-Stamping Authority round trip).
    /// </summary>
    SigningCertificateMalformed = 6,

    /// <summary>
    /// Table 14 additional requirement (d) is violated: the acquired <c>sigTst</c> token's generation time
    /// falls outside the signing certificate's validity window (before <c>notBefore</c> or after <c>notAfter</c>).
    /// </summary>
    SigningCertificateNotValidAtTimestamp = 7,

    /// <summary>
    /// Table 14 additional requirement (d) is violated: the acquired <c>sigTst</c> token's generation time
    /// falls at or after the caller-supplied instant the signing certificate is known to have been revoked.
    /// </summary>
    SigningCertificateRevokedBeforeTimestamp = 8,

    /// <summary>
    /// The raw-splice augmentation-encode seam (<see cref="TrySpliceCBAdESUnprotectedHeaderDelegate"/>) reported
    /// failure over this signature's own, already-successfully-parsed <c>uHeaders</c> bytes — an internal
    /// inconsistency between the parse step and the splice (the raw array's own element count did not match
    /// the decoded model's, or the raw bytes were otherwise malformed), not a caller-supplied fault.
    /// </summary>
    RawUnsignedHeadersSpliceMalformed = 9,

    /// <summary>
    /// <see cref="CBAdESSignatureAugmentation.AddSignatureTimestampAsync"/> was called with
    /// <see cref="CBAdESSignatureTimestampContext.TargetLevel"/> at <see cref="Verifiable.Cryptography.Pki.AdESBaselineLevel.BLT"/>
    /// or above — a new <c>sigTst</c> instance is appended only at B-B/B-T; the incremental-zero reading of
    /// CB-6.3-21's duplicated "B-LT, B-LTA: 0" Table 14 sub-line forbids a NEW
    /// <c>sigTst</c> instance from B-LT onward, and this is the orchestrator half of that obligation
    /// (<see cref="CBAdESLevelRules"/> cannot see a before/after delta from a single
    /// <c>uHeaders</c> snapshot, so the check belongs here). The gate refuses whenever the caller's DECLARED
    /// <see cref="CBAdESSignatureTimestampContext.TargetLevel"/> is B-LT or above; the declared level is the
    /// caller's own attestation throughout this API — the same convention
    /// <see cref="CBAdESStripReferencesContext.AnyTimestampTokenCarriesEmbeddedValidationMaterial"/> documents
    /// — so a call declaring B-T against a signature that already carries <c>valData</c> some other way is not
    /// detected by this gate. A repeated Time-Stamping Authority (Table 14 note 7, multi-TSA) is a repeated
    /// call at <see cref="Verifiable.Cryptography.Pki.AdESBaselineLevel.BT"/>, never a call at B-LT or above.
    /// </summary>
    SignatureTimestampNotPermittedAtTargetLevel = 10,

    /// <summary>
    /// <see cref="CBAdESSignatureAugmentation.AddArchiveTimestampAsync"/> was called with
    /// <see cref="CBAdESArchiveTimestampContext.TargetLevel"/> other than
    /// <see cref="Verifiable.Cryptography.Pki.AdESBaselineLevel.BLTA"/> — <c>arcTst</c> is the should-not
    /// <c>"*"</c> shape at B-B/B-T/B-LT (Table 14, CB-6.3-29) and this producer mints only the recommended,
    /// hard-mandatory B-LTA shape (write-strict). Checked immediately after the parse, before
    /// any digest computation, gap-fill incorporation, or Time-Stamping Authority round trip.
    /// </summary>
    ArchiveTimestampNotPermittedAtTargetLevel = 11,

    /// <summary>
    /// Table 14 additional requirement (k) is not satisfied before generating a new <c>arcTst</c>: either the
    /// caller has not attested completeness of validation material beyond this call's own structural, per-token
    /// check (<see cref="CBAdESArchiveTimestampContext.ChainCompletenessAttested"/>); an electronic time-stamp
    /// token already incorporated into the signature (<c>sigTst</c>/<c>adoTst</c>/<c>sigRTst</c>/<c>rfsTst</c>/
    /// a prior <c>arcTst</c> instance) could not itself be read, so its signer certificate cannot be verified at
    /// all; or a successfully-read such token has a signer certificate this call cannot resolve within
    /// <c>valData</c> or embedded in the token itself (additional requirement (h)'s disjunction) — the two
    /// token-level arms are distinct conditions, worded to name which one actually failed. Checked before any
    /// Time-Stamping Authority round trip.
    /// </summary>
    ArchiveTimestampValidationMaterialIncomplete = 12,

    /// <summary>
    /// <see cref="CBAdESSignatureAugmentation.AddArchiveTimestampAsync"/> was called against a signature that
    /// carries no <c>sigTst</c> instance yet — Table 14's cumulative <c>sigTst</c>-from-B-T-onward requirement
    /// (CB-6.3-21) is the B-LTA ladder's own prerequisite. Refused here, structurally, before any Time-Stamping
    /// Authority round trip, rather than deferred to <see cref="CBAdESLevelRules.EnsureConformant"/>'s own
    /// post-mint evaluation of the same rule: a doomed call never bills one.
    /// Refusing here also keeps <c>uHeaders</c> non-absent by the time the first <c>arcTst</c> instance's
    /// message imprint is built, making the generation/validation asymmetry (clause 5.3.5.3 steps 10/11's
    /// absent-<c>uHeaders</c> arm) unreachable through this verb.
    /// </summary>
    ArchiveTimestampSignatureTimestampPrerequisiteMissing = 13,

    /// <summary>
    /// <see cref="CBAdESSignatureAugmentation.AddArchiveTimestampAsync"/> was called against a signature that
    /// still carries a <c>refs</c>, <c>sigRTst</c>, or <c>rfsTst</c> element (<see cref="CBAdESRefsFamilyKind"/>)
    /// — Table 14 hard-forbids that whole family from B-LT onward (CB-6.3-23/-24/-25), and this call's own
    /// <see cref="ArchiveTimestampNotPermittedAtTargetLevel"/> gate above already fixes the declared level at
    /// B-LTA, so ANY such element still incorporated is forbidden outright, never conditionally. Refused here,
    /// structurally, before any Time-Stamping Authority round trip, rather than deferred to
    /// <see cref="CBAdESLevelRules.EnsureConformant"/>'s own post-mint evaluation of the same rule
    /// (<c>CBAdESRefsFamilyForbiddenViolation</c>) — a doomed call never bills one. The
    /// B-LT-upgrade choreography removes this family with
    /// <see cref="CBAdESSignatureAugmentation.StripReferencesForLongTerm"/> BEFORE a B-LT-or-above level is ever
    /// reached; a caller reaching this gate skipped that step. Checked AFTER the CB-A.1.1-30 resolution check
    /// (<see cref="CBAdESLevelRules.EnsureReferencesResolveToValidationDataAsync"/>) runs, so an unresolvable
    /// <c>refs</c> entry still surfaces its own, more specific CB-A.1.1-30 <see cref="ArgumentException"/>
    /// first; a resolvable one then hits this refusal — both gates independently provable.
    /// </summary>
    ArchiveTimestampReferencesFamilyElementPresent = 14,

    /// <summary>
    /// CB-5.3.5.1-02 is not satisfied before generating a new <c>arcTst</c>: the signature incorporates a
    /// <c>uHeaders</c> counter-signature element (label 11 or 12) whose validation material this call cannot
    /// confirm is complete — either no decode delegate or no material-completeness resolver was supplied
    /// (<see cref="CBAdESSignatureAugmentation.AddArchiveTimestampAsync"/>'s own
    /// <c>parseCounterSignatureHeaderValue</c>/<c>isCounterSignatureMaterialComplete</c> parameters are both
    /// opt-in), an element failed to decode, or the resolver reported incompleteness for one. Checked before
    /// any Time-Stamping Authority round trip.
    /// </summary>
    ArchiveTimestampCounterSignatureMaterialIncomplete = 15
}


/// <summary>
/// Resolves whether a decoded <c>uHeaders</c> counter-signature element's validation material is already
/// incorporated into the CB-AdES signature — CB-5.3.5.1-02's material-completeness half,
/// invoked by <see cref="CBAdESSignatureAugmentation.AddArchiveTimestampAsync"/> before generating a new
/// <c>arcTst</c> whenever a counter-signature element is present.
/// </summary>
/// <remarks>
/// Mirrors <see cref="CBAdESResolveCounterSignaturePublicKeyDelegate"/>'s own certificate-path-neutral scope:
/// <see cref="CBAdESSignatureAugmentation"/> never itself builds or verifies a certificate chain, so the
/// caller resolves completeness by whatever means it trusts (an embedded <c>x5chain</c> in the
/// countersignature's own protected header, an identity match against the signature's own <c>valData</c>
/// certificates, or an external trust store). <see cref="CounterSignature0V2"/>'s abbreviated form carries no
/// protected headers of its own (RFC 9338 §3.2: "no provision for any protected attributes"), so a resolver
/// necessarily has less to decode for that arm than for a full <see cref="CounterSignatureV2"/> — an honest
/// depth difference the contract's own trap calls out, not a gap this delegate's caller papers over.
/// </remarks>
/// <param name="counterSignature">
/// The decoded countersignature to resolve completeness for. BORROWED for the duration of this call only —
/// the caller retains ownership (a <c>using CoseCounterSignatureParseResult</c> it disposes once this call
/// returns); an implementation must not dispose it or retain a reference past the call returning.
/// </param>
/// <returns>
/// <see langword="true"/> when the countersignature's own validation material is already incorporated into
/// the signature; otherwise <see langword="false"/>.
/// </returns>
public delegate bool CBAdESIsCounterSignatureMaterialCompleteDelegate(CoseCounterSignature counterSignature);


/// <summary>
/// The generator-side fault of a CB-AdES augmentation.
/// </summary>
/// <remarks>
/// Creation and augmentation report faults as exceptions, following the signing surfaces already in this
/// library, because a generator handing in material a level cannot be built from is a composition fault of
/// the caller rather than an adversarial input to be classified and reported. Mirrors
/// <see cref="Verifiable.Cryptography.Pki.CAdESAugmentationException"/>'s shape exactly.
/// </remarks>
[DebuggerDisplay("CBAdESAugmentationException({FailureKind}): {Message}")]
public sealed class CBAdESAugmentationException: Exception
{
    /// <summary>Gets what could not be done.</summary>
    public CBAdESAugmentationFailureKind FailureKind { get; }


    /// <summary>Initializes a new <see cref="CBAdESAugmentationException"/> with an unclassified malformed input.</summary>
    public CBAdESAugmentationException(): this(CBAdESAugmentationFailureKind.MalformedEncoding, "The CB-AdES signature could not be augmented.")
    {
    }


    /// <summary>Initializes a new <see cref="CBAdESAugmentationException"/> with an unclassified malformed input.</summary>
    /// <param name="message">The message describing the fault.</param>
    public CBAdESAugmentationException(string message): this(CBAdESAugmentationFailureKind.MalformedEncoding, message)
    {
    }


    /// <summary>Initializes a new <see cref="CBAdESAugmentationException"/> with an unclassified malformed input.</summary>
    /// <param name="message">The message describing the fault.</param>
    /// <param name="innerException">The exception that caused it.</param>
    public CBAdESAugmentationException(string message, Exception innerException): this(CBAdESAugmentationFailureKind.MalformedEncoding, message, innerException)
    {
    }


    /// <summary>Initializes a new <see cref="CBAdESAugmentationException"/>.</summary>
    /// <param name="failureKind">What could not be done.</param>
    /// <param name="message">The message describing the fault.</param>
    public CBAdESAugmentationException(CBAdESAugmentationFailureKind failureKind, string message): base(message)
    {
        FailureKind = failureKind;
    }


    /// <summary>Initializes a new <see cref="CBAdESAugmentationException"/>.</summary>
    /// <param name="failureKind">What could not be done.</param>
    /// <param name="message">The message describing the fault.</param>
    /// <param name="innerException">The exception that caused it.</param>
    public CBAdESAugmentationException(CBAdESAugmentationFailureKind failureKind, string message, Exception innerException): base(message, innerException)
    {
        FailureKind = failureKind;
    }
}


/// <summary>
/// The validation material a <see cref="CBAdESSignatureAugmentation.AddValidationDataAsync"/> call places into a
/// signature's <c>valData</c> — clause 5.3.4's certificate and revocation values, mirroring
/// <see cref="Verifiable.Cryptography.Pki.CAdESValidationMaterial"/>'s own shape and ownership rule exactly.
/// </summary>
/// <remarks>
/// The carriers belong to the caller for the whole call and are not disposed by anything here: an
/// augmentation borrows the octets it places for the duration of the call — long enough to serialize them
/// into the augmented signature's own wire bytes — and never takes ownership of what it was shown.
/// </remarks>
public sealed class CBAdESValidationMaterial
{
    /// <summary>Gets the certificates to place, each a DER-encoded X.509 certificate.</summary>
    public IReadOnlyList<PkiCertificateMemory> Certificates { get; init; } = [];

    /// <summary>Gets the certificate revocation lists to place, each a DER-encoded <c>CertificateList</c>.</summary>
    public IReadOnlyList<PkiCertificateMemory> CertificateRevocationLists { get; init; } = [];

    /// <summary>Gets the OCSP responses to place, each a DER-encoded <c>OCSPResponse</c>.</summary>
    public IReadOnlyList<PkiCertificateMemory> OcspResponses { get; init; } = [];

    /// <summary>Gets whether this material names nothing to place.</summary>
    public bool IsEmpty => Certificates.Count == 0 && CertificateRevocationLists.Count == 0 && OcspResponses.Count == 0;

    /// <summary>Gets material naming nothing to place.</summary>
    public static CBAdESValidationMaterial None { get; } = new();
}


/// <summary>
/// What one <see cref="CBAdESSignatureAugmentation.AddSignatureTimestampAsync"/> call needs: the signature,
/// the algorithm the message imprint is computed under, how to reach a Time-Stamping Authority, and the
/// Table 14 additional-requirement-(d) signing-certificate-validity triple — mirroring
/// <see cref="Verifiable.Cryptography.Pki.CAdESSignatureTimestampContext"/>'s own shape exactly.
/// </summary>
[DebuggerDisplay("CBAdESSignatureTimestampContext(TargetLevel={TargetLevel})")]
public sealed class CBAdESSignatureTimestampContext
{
    /// <summary>Gets the CB-AdES <c>COSE_Sign1</c> wire bytes to augment. Not modified; the result is new wire bytes.</summary>
    public required ReadOnlyMemory<byte> WireBytes { get; init; }

    /// <summary>Gets the algorithm the message imprint is computed under, which the authority echoes in its token.</summary>
    public required PkiDigestAlgorithm MessageImprintAlgorithm { get; init; }

    /// <summary>Gets the Time-Stamping Authority to contact, in whatever form the transport delegate understands.</summary>
    [SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
        Justification = "Forwarded verbatim into TimestampFetchContext.TsaUri, which is deliberately a string for the reason that property gives: the transport delegate owns URI parsing and scheme policy.")]
    public required string TsaUri { get; init; }

    /// <summary>Gets the transport the request is sent through and the response read from.</summary>
    public required FetchTimestampResponseAsyncDelegate FetchResponse { get; init; }

    /// <summary>Gets the time-stamp policy the request asks for, or <see langword="null"/> to state none.</summary>
    public string? ReqPolicyOid { get; init; }

    /// <summary>Gets the nonce length in octets the request carries.</summary>
    public int NonceByteLength { get; init; } = 32;

    /// <summary>Gets whether the request carries a nonce.</summary>
    public bool IncludeNonce { get; init; } = true;

    /// <summary>
    /// Gets the signer's own certificate, whose validity window Table 14 additional requirement (d) checks the
    /// acquired token's generation time against. Required when <see cref="EnforceSigningCertificateValidity"/>
    /// is <see langword="true"/> (the default).
    /// </summary>
    public PkiCertificateMemory? SigningCertificate { get; init; }

    /// <summary>
    /// Gets the instant the signing certificate is known to have been revoked, or <see langword="null"/> when
    /// none is known. When supplied, requirement (d) additionally requires the acquired token's generation
    /// time to precede it.
    /// </summary>
    public DateTimeOffset? SigningCertificateRevokedAt { get; init; }

    /// <summary>
    /// Gets whether the acquired token's generation time is checked against <see cref="SigningCertificate"/>'s
    /// validity window and <see cref="SigningCertificateRevokedAt"/> (Table 14 additional requirement (d)).
    /// Default <see langword="true"/> — the secure default; a caller opts out explicitly.
    /// </summary>
    public bool EnforceSigningCertificateValidity { get; init; } = true;

    /// <summary>
    /// Gets the level this call is raising the signature to (or holding it at, for a repeated multi-TSA call)
    /// — the level <see cref="CBAdESLevelRules.EnsureConformant"/> checks the augmented <c>uHeaders</c> against.
    /// </summary>
    public required AdESBaselineLevel TargetLevel { get; init; }
}


/// <summary>
/// The three-way source union for <see cref="CBAdESSignatureAugmentation.AcquirePayloadTimestampAsync"/> — the
/// caller-visible mirror of <see cref="CBAdESPayloadTimestampImprintSource"/> that additionally carries the
/// RAW, not-yet-dereferenced <c>sigD.pars</c> references for its third arm, since this orchestrator (not the
/// caller) composes the dereference reconstruction. A DU-ready closed sum: no external type may derive from it.
/// </summary>
/// <remarks>
/// <strong>Same-payload invariant with <see cref="CBAdESSigningPayloadInput"/>.</strong> An
/// instance of this sum and the <see cref="CBAdESSigningPayloadInput"/> the caller later supplies to
/// <see cref="CBAdESSignatureCreation.SignAsync(CBAdESProtectedHeaders, CBAdESSigningPayloadInput, CBAdESUnsignedHeaders?, EncodeCBAdESProtectedHeaderDelegate, EncodeCBAdESUnprotectedHeaderDelegate, BuildSigStructureDelegate, PrivateKeyMemory, CBAdESDetachedObjectDereferenceDelegate?, CBAdESDetachedObjectDereferenceContext?, CBAdESUnknownDetachedObjectMechanismDelegate?, BaseMemoryPool, CancellationToken)"/>
/// must describe the SAME payload — neither call cross-checks the other's, so a caller-side mismatch is never
/// caught at creation time; it surfaces only at validation, as a <see cref="CBAdESTimestampTokenBindingViolation"/>
/// naming <see cref="CBAdESTimestampTokenBindingKind.PayloadTimestamp"/> and
/// <see cref="CBAdESTimestampTokenBindingFailureReason.ImprintMismatch"/>. The two sums stay deliberately
/// separate types, a recorded design call rather than an oversight: this one is
/// the pre-sign ACQUISITION-time union (with its raw <c>sigD.pars</c> third arm), the other creation's
/// SIGN-time union of already-resolved bytes — see <see cref="CBAdESSigningPayloadInput"/>'s own remarks for
/// the identical cross-reference from the other side.
/// </remarks>
public abstract class CBAdESPayloadTimestampAcquisitionSource
{
    /// <summary>Restricts direct subtyping to the sibling types declared in this file.</summary>
    private protected CBAdESPayloadTimestampAcquisitionSource()
    {
    }
}


/// <summary>The attached-payload arm: the COSE Payload field is present, and <see cref="PayloadBytes"/> is its content.</summary>
[DebuggerDisplay("CBAdESAttachedPayloadTimestampAcquisitionSource: {PayloadBytes.Length} bytes")]
public sealed class CBAdESAttachedPayloadTimestampAcquisitionSource : CBAdESPayloadTimestampAcquisitionSource
{
    /// <summary>Initializes a new <see cref="CBAdESAttachedPayloadTimestampAcquisitionSource"/>.</summary>
    /// <param name="payloadBytes">The COSE Payload field's content bytes. <strong>Borrowed</strong> view — the caller owns the underlying memory.</param>
    public CBAdESAttachedPayloadTimestampAcquisitionSource(ReadOnlyMemory<byte> payloadBytes)
    {
        PayloadBytes = payloadBytes;
    }

    /// <summary>The COSE Payload field's content bytes. <strong>Borrowed</strong> view — the caller owns the underlying memory.</summary>
    public ReadOnlyMemory<byte> PayloadBytes { get; }
}


/// <summary>The detached-and-unreferenced arm: the caller already holds the out-of-band detached COSE Payload bytes.</summary>
[DebuggerDisplay("CBAdESDetachedPayloadTimestampAcquisitionSource: {PayloadBytes.Length} bytes")]
public sealed class CBAdESDetachedPayloadTimestampAcquisitionSource : CBAdESPayloadTimestampAcquisitionSource
{
    /// <summary>Initializes a new <see cref="CBAdESDetachedPayloadTimestampAcquisitionSource"/>.</summary>
    /// <param name="payloadBytes">The out-of-band detached COSE Payload bytes. <strong>Borrowed</strong> view — the caller owns the underlying memory.</param>
    public CBAdESDetachedPayloadTimestampAcquisitionSource(ReadOnlyMemory<byte> payloadBytes)
    {
        PayloadBytes = payloadBytes;
    }

    /// <summary>The out-of-band detached COSE Payload bytes. <strong>Borrowed</strong> view — the caller owns the underlying memory.</summary>
    public ReadOnlyMemory<byte> PayloadBytes { get; }
}


/// <summary>
/// The <c>sigD</c>-present arm: <see cref="References"/> are the raw, not-yet-dereferenced <c>sigD.pars</c>
/// URI-references. <see cref="CBAdESSignatureAugmentation.AcquirePayloadTimestampAsync"/> composes
/// <see cref="CBAdESDetachedObjectDereferencing.ReconstructObjectIdByURIPayloadAsync"/> — the CB-5.2.8.2.3-07
/// reconstruction path — to turn this arm into the processed bytes the imprint builder needs.
/// </summary>
[DebuggerDisplay("CBAdESSigDReferencedPayloadTimestampAcquisitionSource: {References.Count} reference(s)")]
public sealed class CBAdESSigDReferencedPayloadTimestampAcquisitionSource: CBAdESPayloadTimestampAcquisitionSource
{
    /// <summary>Initializes a new <see cref="CBAdESSigDReferencedPayloadTimestampAcquisitionSource"/>.</summary>
    /// <param name="references">The <c>sigD.pars</c> URI-references, in wire order.</param>
    /// <exception cref="ArgumentNullException"><paramref name="references"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="references"/> is empty (CB-5.2.8-06).</exception>
    public CBAdESSigDReferencedPayloadTimestampAcquisitionSource(IReadOnlyList<string> references)
    {
        ArgumentNullException.ThrowIfNull(references);
        if(references.Count == 0)
        {
            throw new ArgumentException(
                "sigD shall reference one or more detached data objects (ETSI TS 119 152-1 V1.1.1, clause 5.2.8.1, CB-5.2.8-06).",
                nameof(references));
        }

        References = references;
    }


    /// <summary>Gets the <c>sigD.pars</c> URI-references, in wire order.</summary>
    public IReadOnlyList<string> References { get; }
}


/// <summary>
/// What one <see cref="CBAdESSignatureAugmentation.AcquirePayloadTimestampAsync"/> call needs: the pre-sign
/// payload source, how to reach a Time-Stamping Authority, and — only for the <c>sigD</c>-referenced arm —
/// the dereference seam.
/// </summary>
[DebuggerDisplay("CBAdESPayloadTimestampAcquisitionContext({Source})")]
public sealed record CBAdESPayloadTimestampAcquisitionContext
{
    /// <summary>Gets the three-way payload contribution source; see <see cref="CBAdESPayloadTimestampAcquisitionSource"/>.</summary>
    public required CBAdESPayloadTimestampAcquisitionSource Source { get; init; }

    /// <summary>
    /// Gets the <c>sigD</c> URI-reference dereference delegate; required when <see cref="Source"/> is a
    /// <see cref="CBAdESSigDReferencedPayloadTimestampAcquisitionSource"/>, otherwise unused.
    /// </summary>
    public CBAdESDetachedObjectDereferenceDelegate? Dereference { get; init; }

    /// <summary>Gets the per-call caller state for <see cref="Dereference"/>; required whenever <see cref="Dereference"/> is used.</summary>
    public CBAdESDetachedObjectDereferenceContext? DereferenceContext { get; init; }

    /// <summary>Gets the algorithm the message imprint is computed under, which the authority echoes in its token.</summary>
    public required PkiDigestAlgorithm MessageImprintAlgorithm { get; init; }

    /// <summary>Gets the Time-Stamping Authority to contact, in whatever form the transport delegate understands.</summary>
    [SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
        Justification = "Forwarded verbatim into TimestampFetchContext.TsaUri, which is deliberately a string for the reason that property gives: the transport delegate owns URI parsing and scheme policy.")]
    public required string TsaUri { get; init; }

    /// <summary>Gets the transport the request is sent through and the response read from.</summary>
    public required FetchTimestampResponseAsyncDelegate FetchResponse { get; init; }

    /// <summary>Gets the time-stamp policy the request asks for, or <see langword="null"/> to state none.</summary>
    public string? ReqPolicyOid { get; init; }

    /// <summary>Gets the nonce length in octets the request carries.</summary>
    public int NonceByteLength { get; init; } = 32;

    /// <summary>Gets whether the request carries a nonce.</summary>
    public bool IncludeNonce { get; init; } = true;
}


/// <summary>
/// What one <see cref="CBAdESSignatureAugmentation.AddValidationDataAsync"/> call needs: the signature, the
/// certificates/CRLs/OCSP responses to place, the dedup default, and the level being reached.
/// </summary>
[DebuggerDisplay("CBAdESValidationDataContext(TargetLevel={TargetLevel})")]
public sealed class CBAdESValidationDataContext
{
    /// <summary>Gets the CB-AdES <c>COSE_Sign1</c> wire bytes to augment. Not modified; the result is new wire bytes.</summary>
    public required ReadOnlyMemory<byte> WireBytes { get; init; }

    /// <summary>Gets the validation material to place; see <see cref="CBAdESValidationMaterial"/>.</summary>
    public required CBAdESValidationMaterial Material { get; init; }

    /// <summary>
    /// Gets whether a candidate is skipped when it byte-equals (DER) a certificate/CRL/OCSP response already
    /// present in an earlier <c>valData</c> element of this signature (Table 14 additional requirements (e)/(f),
    /// both SHOULD). Default <see langword="true"/>; a caller opts out explicitly.
    /// </summary>
    public bool DeduplicateAgainstExisting { get; init; } = true;

    /// <summary>
    /// Gets the level this call is raising the signature to — B-LT, following a prior
    /// <see cref="CBAdESSignatureAugmentation.StripReferencesForLongTerm"/> call (typically targeting B-T)
    /// that already removed the B-LT-forbidden <c>refs</c>/<c>sigRTst</c>/<c>rfsTst</c> family
    /// (CB-6.3-23/-24/-25); the alternative one-step choreography — stripping directly to B-LT with
    /// <see cref="CBAdESStripReferencesContext.AnyTimestampTokenCarriesEmbeddedValidationMaterial"/> attested —
    /// needs no separate call to this verb at all (see that member's own remarks).
    /// </summary>
    public required AdESBaselineLevel TargetLevel { get; init; }
}


/// <summary>
/// What one <see cref="CBAdESSignatureAugmentation.AddSignatureAndReferencesTimestampAsync"/> or
/// <see cref="CBAdESSignatureAugmentation.AddReferencesTimestampAsync"/> call needs — identical shape for both
/// (Annex A.1.2.1.2 and A.1.2.2.2 differ only in whether the signature value contributes, which the imprint
/// builder delegate the caller supplies already encodes).
/// </summary>
[DebuggerDisplay("CBAdESReferencesFamilyTimestampContext(TargetLevel={TargetLevel})")]
public sealed class CBAdESReferencesFamilyTimestampContext
{
    /// <summary>Gets the CB-AdES <c>COSE_Sign1</c> wire bytes to augment. Not modified; the result is new wire bytes.</summary>
    public required ReadOnlyMemory<byte> WireBytes { get; init; }

    /// <summary>Gets the algorithm the message imprint is computed under, which the authority echoes in its token.</summary>
    public required PkiDigestAlgorithm MessageImprintAlgorithm { get; init; }

    /// <summary>Gets the Time-Stamping Authority to contact, in whatever form the transport delegate understands.</summary>
    [SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
        Justification = "Forwarded verbatim into TimestampFetchContext.TsaUri, which is deliberately a string for the reason that property gives: the transport delegate owns URI parsing and scheme policy.")]
    public required string TsaUri { get; init; }

    /// <summary>Gets the transport the request is sent through and the response read from.</summary>
    public required FetchTimestampResponseAsyncDelegate FetchResponse { get; init; }

    /// <summary>Gets the time-stamp policy the request asks for, or <see langword="null"/> to state none.</summary>
    public string? ReqPolicyOid { get; init; }

    /// <summary>Gets the nonce length in octets the request carries.</summary>
    public int NonceByteLength { get; init; } = 32;

    /// <summary>Gets whether the request carries a nonce.</summary>
    public bool IncludeNonce { get; init; } = true;

    /// <summary>Gets the level this call is raising the signature to — B-B or B-T (both families are hard-forbidden from B-LT).</summary>
    public required AdESBaselineLevel TargetLevel { get; init; }
}


/// <summary>
/// One Time-Stamping Authority leg <see cref="CBAdESSignatureAugmentation.AddArchiveTimestampAsync"/> contacts.
/// Additional requirement (j) ("Each <c>arcTst</c> may contain more than one electronic time-stamp issued by
/// different TSAs") is modeled as ONE OR MORE entries of this type on a single call: the call
/// mints exactly ONE new <c>arcTst</c> instance carrying one token per configured leg, all over the SAME
/// message imprint, orthogonal to Table 14's own instance-count cardinality (CB-6.2.2-09).
/// </summary>
[DebuggerDisplay("CBAdESArchiveTimestampTsaLeg({TsaUri})")]
public sealed record CBAdESArchiveTimestampTsaLeg
{
    /// <summary>Gets the Time-Stamping Authority to contact, in whatever form the transport delegate understands.</summary>
    [SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
        Justification = "Forwarded verbatim into TimestampFetchContext.TsaUri, which is deliberately a string for the reason that property gives: the transport delegate owns URI parsing and scheme policy.")]
    public required string TsaUri { get; init; }

    /// <summary>Gets the transport the request is sent through and the response read from.</summary>
    public required FetchTimestampResponseAsyncDelegate FetchResponse { get; init; }

    /// <summary>Gets the time-stamp policy the request asks for, or <see langword="null"/> to state none.</summary>
    public string? ReqPolicyOid { get; init; }

    /// <summary>Gets the nonce length in octets the request carries.</summary>
    public int NonceByteLength { get; init; } = 32;

    /// <summary>Gets whether the request carries a nonce.</summary>
    public bool IncludeNonce { get; init; } = true;
}


/// <summary>
/// What one <see cref="CBAdESSignatureAugmentation.AddArchiveTimestampAsync"/> call needs (clause 5.3.5.2's
/// five generation steps): the signature, the imprint algorithm, the declared target level (B-LTA only, write
/// strict), the externally supplied data step 5 binds, one or more Time-Stamping Authority legs
/// (additional requirement (j)), optional gap-fill validation material for step 1, the signing certificate,
/// and the additional-requirement-(k) completeness attestation.
/// </summary>
/// <remarks>
/// <strong>The honest depth split.</strong> This call structurally enforces, before any
/// Time-Stamping Authority round trip, that every electronic time-stamp token already incorporated into the
/// signature has a signer certificate resolvable within <c>valData</c> or embedded in the token itself
/// (additional requirement (h)'s disjunction, identity-matched by issuer-and-serial-number/subject-key-identifier)
/// — see
/// <see cref="CBAdESSignatureAugmentation.AddArchiveTimestampAsync"/>'s own remarks. What it CANNOT itself
/// check — a full certificate chain and revocation status for the signing certificate, any counter-signature
/// signing certificate (moot: this substrate is COSE_Sign1-only), and any attribute
/// certificate/signed assertion — is the caller's own responsibility, attested through
/// <see cref="ChainCompletenessAttested"/> (the no-chain-building/no-HTTP library doctrine).
/// </remarks>
[DebuggerDisplay("CBAdESArchiveTimestampContext(TargetLevel={TargetLevel})")]
public sealed class CBAdESArchiveTimestampContext
{
    /// <summary>Gets the CB-AdES <c>COSE_Sign1</c> wire bytes to augment. Not modified; the result is new wire bytes.</summary>
    public required ReadOnlyMemory<byte> WireBytes { get; init; }

    /// <summary>
    /// Gets the algorithm the message imprint is computed under — ONE digest, shared by every
    /// <see cref="TsaLegs"/> entry (additional requirement (j): several tokens issued over the SAME imprint).
    /// </summary>
    public required PkiDigestAlgorithm MessageImprintAlgorithm { get; init; }

    /// <summary>
    /// Gets the externally supplied application data clause 5.3.5.3 step 5 binds into the message imprint;
    /// empty when the application supplies none (the zero-length <c>bstr</c> step 5 calls for in that case).
    /// </summary>
    /// <remarks>
    /// Read as the SIGNATURE's own externally-supplied data — one value
    /// per signature, constant across every <c>arcTst</c> renewal (step 5's "at the time of generating"
    /// qualifier snapshots <c>uHeaders</c>, not the application data); a caller varying this value between
    /// successive <see cref="CBAdESSignatureAugmentation.AddArchiveTimestampAsync"/> calls against the SAME
    /// signature departs from that reading.
    /// </remarks>
    public ReadOnlyMemory<byte> ExternallySuppliedData { get; init; }

    /// <summary>
    /// Gets the one-or-more Time-Stamping Authority legs this call contacts (additional requirement (j)):
    /// a new <c>arcTst</c> instance carries one token per configured leg, all over the SAME
    /// message imprint. Must be non-empty.
    /// </summary>
    public required IReadOnlyList<CBAdESArchiveTimestampTsaLeg> TsaLegs { get; init; }

    /// <summary>
    /// Gets the validation material to gap-fill into a new <c>valData</c> element BEFORE the message imprint
    /// is computed (clause 5.3.5.2 step 1) when the signature misses certificates/revocation data required for
    /// validating its signed objects, or <see langword="null"/>/<see cref="CBAdESValidationMaterial.None"/> to
    /// gap-fill nothing. Composed through the SAME building blocks
    /// <see cref="CBAdESSignatureAugmentation.AddValidationDataAsync"/> uses — never duplicated; see
    /// <see cref="CBAdESSignatureAugmentation.AddArchiveTimestampAsync"/>'s remarks for why this incorporation
    /// happens strictly before the imprint is built (the imprint then covers it — order is normative).
    /// </summary>
    public CBAdESValidationMaterial? GapFillValidationMaterial { get; init; }

    /// <summary>
    /// Gets the CB-AdES signature's own signing certificate, whose readability this call checks before
    /// contacting any Time-Stamping Authority — the same locally-derivable-failure-first precedent every
    /// pre-TSA validity check in this augmentation follows (<see cref="ReadSigningCertificateValidityOrThrow"/>).
    /// </summary>
    public required PkiCertificateMemory SigningCertificate { get; init; }

    /// <summary>
    /// Gets whether the caller attests that every validation-material completeness need additional requirement
    /// (k) imposes, BEYOND this call's own structural, digest-matched per-token check over every electronic
    /// time-stamp token already incorporated into the signature, is satisfied elsewhere — chiefly the signing
    /// certificate's own full chain and revocation status. This call cannot itself build or verify a
    /// certificate chain (the no-chain-building/no-HTTP library doctrine). Defaults to
    /// <see langword="false"/> (fail-closed): an unattested call refuses before contacting any Time-Stamping
    /// Authority, citing CB-6.3-k.
    /// </summary>
    public bool ChainCompletenessAttested { get; init; }

    /// <summary>Gets the <c>sigD</c> URI-reference dereference delegate; required when the COSE Payload is detached and referenced via <c>sigD</c>.</summary>
    public CBAdESDetachedObjectDereferenceDelegate? Dereference { get; init; }

    /// <summary>Gets the per-call caller state for <see cref="Dereference"/>; required whenever <see cref="Dereference"/> is used.</summary>
    public CBAdESDetachedObjectDereferenceContext? DereferenceContext { get; init; }

    /// <summary>Gets the caller-supplied out-of-band detached payload; used only when the COSE Payload is detached and <c>sigD</c> is absent.</summary>
    public ReadOnlyMemory<byte>? ExternalDetachedPayload { get; init; }

    /// <summary>Gets the unknown-<c>sigD.mId</c> handler; used only when <c>sigD</c> selects a mechanism neither built-in mechanism identifies.</summary>
    public CBAdESUnknownDetachedObjectMechanismDelegate? UnknownMechanismHandler { get; init; }

    /// <summary>
    /// Gets the level this call is raising the signature to — shall be
    /// <see cref="Verifiable.Cryptography.Pki.AdESBaselineLevel.BLTA"/> (a typed refusal
    /// otherwise, checked before any Time-Stamping Authority round trip).
    /// </summary>
    public required AdESBaselineLevel TargetLevel { get; init; }
}


/// <summary>
/// One OCSP response to reference within <see cref="CBAdESReferencesContext.OcspResponsesToReference"/>: the
/// response itself plus the mandatory <c>ocspId</c> identifier <see cref="CBAdESOcspIdentifier"/> requires.
/// </summary>
/// <remarks>
/// <see cref="CBAdESOcspIdentifier"/>'s <c>responderId</c>/<c>producedAt</c> members are not derivable from the
/// response's DER bytes without a dedicated OCSP ASN.1 reader — the caller, who already parsed or produced
/// the response, supplies them directly.
/// </remarks>
[DebuggerDisplay("CBAdESOcspReferenceInput: {Identifier}")]
public sealed class CBAdESOcspReferenceInput
{
    /// <summary>Initializes a new <see cref="CBAdESOcspReferenceInput"/>.</summary>
    /// <param name="response">The DER-encoded <c>OCSPResponse</c> being referenced.</param>
    /// <param name="identifier">The mandatory <c>ocspId</c> identifier (CB-A.1.1-21/25).</param>
    public CBAdESOcspReferenceInput(PkiCertificateMemory response, CBAdESOcspIdentifier identifier)
    {
        Response = response;
        Identifier = identifier;
    }

    /// <summary>The DER-encoded <c>OCSPResponse</c> being referenced.</summary>
    public PkiCertificateMemory Response { get; }

    /// <summary>The mandatory <c>ocspId</c> identifier (CB-A.1.1-21/25).</summary>
    public CBAdESOcspIdentifier Identifier { get; }
}


/// <summary>
/// What one <see cref="CBAdESSignatureAugmentation.AddReferencesAsync"/> call needs: the signature, the
/// signing certificate the builder refuses to reference, the material to reference, the digest algorithm, and
/// the level being reached.
/// </summary>
/// <remarks>
/// The carriers belong to the caller for the whole call and are not disposed by anything here — a
/// <see cref="CBAdESValidationMaterial"/>-matching ownership rule; only the DIGESTS this call computes over
/// them are new, owned material, which flows into the returned wire bytes.
/// </remarks>
[DebuggerDisplay("CBAdESReferencesContext(TargetLevel={TargetLevel})")]
public sealed class CBAdESReferencesContext
{
    /// <summary>Gets the CB-AdES <c>COSE_Sign1</c> wire bytes to augment. Not modified; the result is new wire bytes.</summary>
    public required ReadOnlyMemory<byte> WireBytes { get; init; }

    /// <summary>
    /// Gets the CB-AdES signature's own signing certificate — <see cref="CBAdESSignatureAugmentation.AddReferencesAsync"/>
    /// refuses (CB-A.1.1-02) any <see cref="CertificatesToReference"/> entry that byte-equals it.
    /// </summary>
    public required PkiCertificateMemory SigningCertificate { get; init; }

    /// <summary>Gets the certificates to reference (<c>xRefs</c>), or <see langword="null"/>/empty to omit that member.</summary>
    public IReadOnlyList<PkiCertificateMemory>? CertificatesToReference { get; init; }

    /// <summary>Gets the CRLs to reference (<c>rRefs.crlRefs</c>), or <see langword="null"/>/empty to omit that member.</summary>
    public IReadOnlyList<PkiCertificateMemory>? CrlsToReference { get; init; }

    /// <summary>Gets the OCSP responses to reference (<c>rRefs.ocspRefs</c>), or <see langword="null"/>/empty to omit that member.</summary>
    public IReadOnlyList<CBAdESOcspReferenceInput>? OcspResponsesToReference { get; init; }

    /// <summary>Gets the digest algorithm every <c>x5t</c>/CRL/OCSP reference digest is computed under.</summary>
    public required PkiDigestAlgorithm MessageImprintAlgorithm { get; init; }

    /// <summary>Gets the level this call is raising the signature to — B-B or B-T (<c>refs</c> is hard-forbidden from B-LT).</summary>
    public required AdESBaselineLevel TargetLevel { get; init; }
}


/// <summary>
/// What one <see cref="CBAdESSignatureAugmentation.StripReferencesForLongTerm"/> call needs: the signature, the
/// level being reached, and — only for the one-step direct-to-B-LT choreography — the caller-attested
/// embedded-material fact; see <see cref="TargetLevel"/>'s own remarks for the two choreographies this call
/// fits into.
/// </summary>
[DebuggerDisplay("CBAdESStripReferencesContext(TargetLevel={TargetLevel})")]
public sealed class CBAdESStripReferencesContext
{
    /// <summary>Gets the CB-AdES <c>COSE_Sign1</c> wire bytes to augment. Not modified; the result is new wire bytes.</summary>
    public required ReadOnlyMemory<byte> WireBytes { get; init; }

    /// <summary>
    /// Gets the level this call is raising the signature to. In the two-step choreography (this call, then
    /// <see cref="CBAdESSignatureAugmentation.AddValidationDataAsync"/>), this is B-T — placing <c>valData</c>
    /// and actually reaching B-LT is <see cref="CBAdESSignatureAugmentation.AddValidationDataAsync"/>'s own
    /// job, never this call's (the strip verb's own doc comment already calls B-T the level that only PREPARES
    /// the B-LT transition). B-LT is the correct value here ONLY for the one-step choreography, where
    /// <see cref="AnyTimestampTokenCarriesEmbeddedValidationMaterial"/> is attested <see langword="true"/> —
    /// this call never places <c>valData</c> itself, so without that attestation Table 14 additional
    /// requirement (h)'s validation-data-for-time-stamps service (CB-6.3-26) is left unsatisfied and
    /// <see cref="CBAdESLevelRules.EnsureConformant"/> refuses the result.
    /// </summary>
    public required AdESBaselineLevel TargetLevel { get; init; }

    /// <summary>
    /// Gets whether at least one electronic time-stamp token elsewhere in the signature is caller-attested to
    /// carry its own embedded certificate/revocation validation material — the CB-6.3-26/h "embedded in the
    /// electronic time-stamp itself" SPO, threaded verbatim into
    /// <see cref="CBAdESLevelRuleContext.AnyTimestampTokenCarriesEmbeddedValidationMaterial"/>, which documents
    /// the same app-owned-state convention this field follows: this call is SYNCHRONOUS and never inspects a
    /// token's own CMS content to derive the fact itself (only the ASYNC validation orchestrator's CMS probe
    /// can do that), so the caller supplies whatever it already knows. Defaults to <see langword="false"/> —
    /// the fail-closed default (an unattested signature is assumed to carry no embedded material); reaching
    /// B-LT through this call ALONE therefore requires either this fact attested <see langword="true"/> or a
    /// <c>valData</c> element the caller places some other way, per <see cref="TargetLevel"/>'s own remarks.
    /// </summary>
    public bool AnyTimestampTokenCarriesEmbeddedValidationMaterial { get; init; }
}


/// <summary>
/// Raises an existing CB-AdES-B-B signature to B-T/B-LT (and prepares the B-LT transition) per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1</see>: <c>sigTst</c> (clause 5.3.3), <c>adoTst</c> acquisition (clause 5.2.6, a
/// pre-sign component this class only ACQUIRES — the caller places it), <c>valData</c> (clause 5.3.4), the
/// B-LT strip rule for the B-B/B-T-only <c>refs</c>/<c>sigRTst</c>/<c>rfsTst</c> family (Table 14, CB-6.3-23/
/// -24/-25), and that family's own <c>sigRTst</c>/<c>rfsTst</c>/<c>refs</c> components (Annex A.1.1/A.1.2).
/// </summary>
/// <remarks>
/// <para>
/// <strong>The level ladder, verb by verb.</strong> Creation (<see cref="CBAdESSignatureCreation.SignAsync(CBAdESProtectedHeaders, CBAdESSigningPayloadInput, CBAdESUnsignedHeaders?, EncodeCBAdESProtectedHeaderDelegate, EncodeCBAdESUnprotectedHeaderDelegate, BuildSigStructureDelegate, PrivateKeyMemory, CBAdESDetachedObjectDereferenceDelegate?, CBAdESDetachedObjectDereferenceContext?, CBAdESUnknownDetachedObjectMechanismDelegate?, BaseMemoryPool, CancellationToken)"/>,
/// a different class entirely) produces B-B; <see cref="AddSignatureTimestampAsync"/> raises B-B to B-T by
/// attaching <c>sigTst</c>; reaching B-LT from there is the ONE step this class splits into two composable
/// verbs — <see cref="StripReferencesForLongTerm"/> removes the B-LT-forbidden <c>refs</c>/<c>sigRTst</c>/
/// <c>rfsTst</c> family (Table 14, CB-6.3-23/-24/-25), and <see cref="AddValidationDataAsync"/> places
/// <c>valData</c> — normally called in that order (strip at B-T, then <see cref="AddValidationDataAsync"/> at
/// B-LT), though <see cref="StripReferencesForLongTerm"/> alone can reach B-LT directly when
/// <see cref="CBAdESStripReferencesContext.AnyTimestampTokenCarriesEmbeddedValidationMaterial"/> is attested
/// (see that member's own remarks for why). The refs-family verbs themselves
/// (<see cref="AddReferencesAsync"/>, <see cref="AddSignatureAndReferencesTimestampAsync"/>,
/// <see cref="AddReferencesTimestampAsync"/>) live at B-B/B-T only, ahead of the strip, never after it.
/// </para>
/// <para>
/// <strong>Every step parses, appends, re-serializes; nothing is mutated in place.</strong> Each verb parses
/// the caller-supplied wire bytes through <see cref="ParseCBAdESSign1Delegate"/> (fail-closed; a parse failure
/// here is a CALLER composition fault, not untrusted input, so it is reported as
/// <see cref="CBAdESAugmentationException"/> rather than collected — this library's "creation/augmentation throw on
/// caller error" half), builds the new <c>uHeaders</c> element(s) it needs, appends through
/// <see cref="CBAdESUnsignedHeaders.Append"/> or rebuilds via <c>new CBAdESUnsignedHeaders(...)</c> (for the
/// decoded model level-rule checking needs), and re-serializes through <see cref="SerializeCBAdESSign1Delegate"/>
/// into a brand-new <see cref="EncodedCoseSign1"/>: the protected header and signature value are carried
/// through byte-for-byte (unsigned-header augmentation never re-signs).
/// </para>
/// <para>
/// <strong>The precise splice guarantee — canonical-on-create, preserve-on-augment.</strong>
/// The input wire bytes themselves are of course never mutated (a fresh <see cref="EncodedCoseSign1"/> is
/// always returned), and no retained element's own WIRE BYTES change across an augmentation call either:
/// every verb below composes its new <c>uHeaders</c> unprotected-header dictionary through
/// <see cref="TrySpliceCBAdESUnprotectedHeaderDelegate"/>, copying every retained element CONTENT-verbatim
/// from <see cref="CBAdESSign1ParseResult.RawUnsignedHeaders"/> — the raw wire bytes captured at parse — and
/// freshly encoding only the genuinely NEW element this call itself builds, never re-encoding a retained
/// element from its DECODED model
/// (<see cref="EncodeCBAdESUnprotectedHeaderDelegate"/>). A decoded-model re-encode of a retained element
/// would be lossy for at least one CDDL union arm (<see cref="CBAdESSerialization.WriteTDate"/>'s
/// whole-second, forced-<c>Z</c> writer collapses a sub-second or non-<c>Z</c>-offset wire <c>tdate</c>, and
/// an opaque <see cref="Verifiable.Cryptography.Pki.CBAdESUnsignedHeaderElementUnknown"/> element is never
/// modeled precisely enough to reproduce byte-for-byte from its decoded form at all) — the reason the splice
/// delegate, not the encode delegate, carries every retained element here.
/// <see cref="EncodeCBAdESUnprotectedHeaderDelegate"/> remains exactly right for CREATION
/// (<see cref="CBAdESSignatureCreation.SignAsync(CBAdESProtectedHeaders, CBAdESSigningPayloadInput, CBAdESUnsignedHeaders?, EncodeCBAdESProtectedHeaderDelegate, EncodeCBAdESUnprotectedHeaderDelegate, BuildSigStructureDelegate, PrivateKeyMemory, CBAdESDetachedObjectDereferenceDelegate?, CBAdESDetachedObjectDereferenceContext?, CBAdESUnknownDetachedObjectMechanismDelegate?, BaseMemoryPool, CancellationToken)"/>
/// builds <c>uHeaders</c> fresh every time — that path has no prior wire bytes to lose, so re-encoding from
/// the decoded model it itself just constructed is not lossy) and is untouched by this change.
/// </para>
/// <para>
/// <strong>One rule implementation, throw posture.</strong> After building the candidate new <c>uHeaders</c>
/// state, every verb calls <see cref="CBAdESLevelRules.EnsureConformant"/> — the SAME rule surface the
/// validation orchestrator calls in collect posture — over that candidate state at
/// the caller-declared <see cref="AdESBaselineLevel"/>. This is not merely a final sanity check: because that
/// rule surface is POSITIONAL (e.g. <c>CBAdESReferencesTimestampGenerationGateViolation</c> looks for a
/// <c>refs</c> element strictly before the position under check), running it AFTER appending the new element
/// naturally implements the CB-A.1.2.1-03/CB-A.1.2.2-03 "<c>refs</c> must already be present" generation gate
/// for <see cref="AddSignatureAndReferencesTimestampAsync"/>/<see cref="AddReferencesTimestampAsync"/> for free
/// — no separate, potentially-drifting gate check is written here (an EXPLICIT, cheap pre-check still runs
/// before the Time-Stamping-Authority round trip for those two verbs specifically, so a doomed call never
/// bills a TSA — see their own remarks). A resulting rule violation propagates as
/// <see cref="EnsureConformant"/>'s own <see cref="ArgumentException"/> UNCHANGED — it is not re-wrapped into
/// <see cref="CBAdESAugmentationException"/>, mirroring how <see cref="CBAdESSignatureCreation"/> lets
/// <see cref="CBAdESHeaderRules.EnsureConformant"/>'s exception propagate on the B-B side.
/// </para>
/// <para>
/// <strong>Ownership discipline: never dispose the abandoned source <c>uHeaders</c> container directly.</strong>
/// Every verb that rebuilds <c>uHeaders</c> (whether by <see cref="CBAdESUnsignedHeaders.Append"/>, which
/// SHARES every prior element's object reference with the new container, or by
/// <see cref="StripReferencesForLongTerm"/>'s partial rebuild) follows one rule: the elements the caller's
/// PARSED signature already carried are disposed EXACTLY ONCE, either because they are reachable through the
/// newly-built <c>uHeaders</c> (disposed once, when that container is disposed) or because they were dropped
/// and are disposed individually right there (the strip verb's refs-family elements) — the ORIGINAL
/// <see cref="CBAdESSign1ParseResult.UnsignedHeaders"/> container itself is NEVER separately disposed once its
/// elements have been accounted for this way (that would double-dispose whatever is shared). See
/// <see cref="DisposeAugmentationArtifacts"/>'s own remarks for the exact mechanism (a
/// <c>bool unsignedHeaderElementsTransferred</c> flag threaded through every verb's <c>finally</c>), and
/// <see cref="StripReferencesForLongTerm"/>'s remarks for the double-dispose/leak hazard this discipline exists
/// to close.
/// </para>
/// <para>
/// <strong>A token is verified before it is attached, and copied when it must outlive the call.</strong>
/// Acquisition goes through <see cref="Verifiable.Cryptography.Pki.TimestampAcquisition.AcquireAsync"/>, the
/// ONLY acquisition path: per-call nonce via the entropy seam, NO in-library replay/freshness state
/// (<see href="https://www.rfc-editor.org/rfc/rfc3161">RFC 3161</see> genTime acceptance-window policy is a
/// later stage's, matching the app-owned-freshness convention this library's <c>JtiReplayPolicy</c> documents
/// for the analogous JWT case). <see cref="AddSignatureTimestampAsync"/>,
/// <see cref="AddSignatureAndReferencesTimestampAsync"/>, and <see cref="AddReferencesTimestampAsync"/> consume
/// the acquired token's DER bytes as a BORROWED view directly from the still-alive
/// <see cref="Verifiable.Cryptography.Pki.AcquiredTimestampToken"/> (disposed only in this call's own
/// <c>finally</c>, after re-serialization has already copied the bytes into the returned
/// <see cref="EncodedCoseSign1"/>). <see cref="AcquirePayloadTimestampAsync"/> is the one exception: it returns
/// a DECODED MODEL (<see cref="CBAdESPayloadTimestamp"/>) the caller may hold arbitrarily long before
/// <c>SignAsync</c>, and <see cref="AdESTimestampToken.Val"/> is a borrowed view with
/// <see cref="AdESTimestampContainer.Dispose"/> currently a no-op (that type's own remarks) — so that method
/// copies the token's DER bytes to a GC-owned array BEFORE disposing the acquired token, rather than handing
/// back a view into memory this call is about to return to the pool. Flagged for a later stage that introduces
/// an owned, pooled <c>Val</c> carrier on <see cref="AdESTimestampToken"/>.
/// </para>
/// <para>
/// <strong>No registry-resolved/explicit-delegate overload pair, by design (a deliberate departure from the
/// pairing every other CB-AdES orchestrator uses, with grounds).</strong> Every other CB-AdES orchestrator
/// (<see cref="CBAdESSignatureCreation"/>/<see cref="CBAdESSignatureValidation"/>) offers that pair because a
/// <see cref="PrivateKeyMemory"/>/<see cref="PublicKeyMemory"/>'s <see cref="Tag"/> resolves a signing or
/// verification function through <see cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}"/>. NONE
/// of the seven verbs here perform a private-key cryptographic operation at all: the Time-Stamping Authority
/// signs (via RFC 3161), and every digest crosses the registered digest delegate (a single ambient
/// registration, not a per-call choice with two flavors to offer). There is consequently nothing to resolve
/// from a key's tag, and the two-overload split has no natural target here — every verb
/// below is a single method taking every delegate explicitly.
/// </para>
/// </remarks>
public static class CBAdESSignatureAugmentation
{
    /// <summary>
    /// Raises a signature to CB-AdES-B-T (or holds it there for a repeated multi-TSA call, Table 14 note 7):
    /// obtains a time-stamp token over the COSE signature value from the caller's Time-Stamping Authority,
    /// verifies it, and incorporates it as a new <c>sigTst</c> element of <c>uHeaders</c>.
    /// </summary>
    /// <param name="context">The signature, the imprint algorithm, the authority to contact, and the target level.</param>
    /// <param name="parse">The fail-closed CBOR parse seam.</param>
    /// <param name="serialize">The CBOR re-serialization seam.</param>
    /// <param name="spliceUnprotectedHeader">The <c>uHeaders</c> unprotected-header raw-splice seam.</param>
    /// <param name="pool">The memory pool every carrier is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The augmented signature's new wire bytes. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException">When a required argument is <see langword="null"/>.</exception>
    /// <exception cref="CBAdESAugmentationException">
    /// When <paramref name="context"/>'s wire bytes cannot be parsed (<see cref="CBAdESAugmentationFailureKind.MalformedEncoding"/>);
    /// when <see cref="CBAdESSignatureTimestampContext.TargetLevel"/> is at
    /// <see cref="Verifiable.Cryptography.Pki.AdESBaselineLevel.BLT"/> or above
    /// (<see cref="CBAdESAugmentationFailureKind.SignatureTimestampNotPermittedAtTargetLevel"/>, checked BEFORE
    /// any Time-Stamping Authority round trip so a doomed call never bills one — see the class remarks); when
    /// <see cref="CBAdESSignatureTimestampContext.SigningCertificate"/> is not readable as an X.509 certificate
    /// (<see cref="CBAdESAugmentationFailureKind.SigningCertificateMalformed"/>, likewise checked BEFORE any
    /// Time-Stamping Authority round trip); or Table 14 additional requirement (d) is not
    /// satisfied by the acquired token, which necessarily follows the round trip
    /// (<see cref="CBAdESAugmentationFailureKind.SigningCertificateNotValidAtTimestamp"/>/
    /// <see cref="CBAdESAugmentationFailureKind.SigningCertificateRevokedBeforeTimestamp"/>).
    /// </exception>
    /// <exception cref="Verifiable.Cryptography.Pki.TimestampAcquisitionException">
    /// When the authority could not be reached, or the token it returned does not verify.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// When the resulting <c>uHeaders</c> fails <see cref="CBAdESLevelRules.EnsureConformant"/> at
    /// <see cref="CBAdESSignatureTimestampContext.TargetLevel"/> — see the class remarks.
    /// </exception>
    /// <remarks>
    /// <para>
    /// CB-6.3-c ("each <c>sigTst</c> shall contain only one electronic time-stamp") holds by construction: this
    /// call always builds a <see cref="AdESTimestampContainer"/> with exactly one
    /// <see cref="AdESTimestampToken"/>; a second Time-Stamping Authority is a second call AT
    /// <see cref="Verifiable.Cryptography.Pki.AdESBaselineLevel.BT"/>, appending a second,
    /// sibling <c>sigTst</c> element (Table 14 note 7), never a second token inside one container.
    /// </para>
    /// <para>
    /// <strong>Enforced.</strong> <see cref="CBAdESSignatureTimestampContext.TargetLevel"/>
    /// shall be <see cref="Verifiable.Cryptography.Pki.AdESBaselineLevel.BB"/> or
    /// <see cref="Verifiable.Cryptography.Pki.AdESBaselineLevel.BT"/> — a call at
    /// <see cref="Verifiable.Cryptography.Pki.AdESBaselineLevel.BLT"/> or above throws
    /// <see cref="CBAdESAugmentationException"/> naming
    /// <see cref="CBAdESAugmentationFailureKind.SignatureTimestampNotPermittedAtTargetLevel"/>, after the parse,
    /// before any digest computation or Time-Stamping Authority round trip: CB-6.3-21's duplicated "B-LT,
    /// B-LTA: 0" Table 14 sub-line reads as zero NEW <c>sigTst</c> instances from
    /// B-LT onward. The gate enforces the caller's DECLARED
    /// <see cref="CBAdESSignatureTimestampContext.TargetLevel"/> — the same context-attested-fact convention
    /// <see cref="CBAdESStripReferencesContext.AnyTimestampTokenCarriesEmbeddedValidationMaterial"/> documents —
    /// so a call declaring B-T against a signature that already carries <c>valData</c> some other way is not
    /// detected here; <see cref="CBAdESLevelRules"/> cannot itself enforce the incremental obligation from a
    /// single <c>uHeaders</c> snapshot (no before/after delta is visible there), so this orchestrator enforces
    /// the declared-level half of it directly.
    /// </para>
    /// <para>
    /// <strong>Signing-certificate readability, checked before the Time-Stamping Authority.</strong> Immediately
    /// after the level gate above — still before any digest computation or Time-Stamping
    /// Authority round trip — <see cref="CBAdESSignatureTimestampContext.SigningCertificate"/>'s validity
    /// window (Table 14 additional requirement (d)) is read via <see cref="ReadSigningCertificateValidityOrThrow"/>:
    /// a wrong-kind carrier or an unparseable DER encoding throws
    /// <see cref="CBAdESAugmentationFailureKind.SigningCertificateMalformed"/> there, rather than after a
    /// doomed round trip has already been billed. The read validity window is carried forward to the genTime
    /// comparison <see cref="EnsureSigningCertificateValidAtTimestamp"/> performs below, which stays
    /// post-acquisition because it needs the acquired token itself.
    /// </para>
    /// <para>
    /// <strong>Manual disposal, not a <see langword="using"/> declaration.</strong> <c>token</c> is declared
    /// <see langword="null"/> before the try body and assigned only after the digest is computed inside it
    /// (a <see langword="using"/> declaration accepts only a single assignment, at its own declaration); the
    /// <see langword="finally"/> below disposes it on every exit path, including a throw from the
    /// Time-Stamping Authority round trip itself.
    /// </para>
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "container is wrapped into a new CBAdESSignatureTimestamp, then a new " +
            "CBAdESUnsignedHeaderElementSignatureTimestamp (`element`), which becomes finalUnsignedHeaders via " +
            "Append/the array constructor; finalUnsignedHeaders is disposed in the finally below through " +
            "DisposeAugmentationArtifacts once `transferred` is true, cascading over every element it reaches, " +
            "including this one. Roslyn tracks the locally-constructed container/element themselves, not the " +
            "fact that they are reachable through finalUnsignedHeaders three constructor calls later -- and in " +
            "any case AdESTimestampContainer.Dispose is currently a no-op (see that type's own remarks), so " +
            "there is nothing to leak regardless of which container in the chain a caller happens to dispose.")]
    public static async ValueTask<EncodedCoseSign1> AddSignatureTimestampAsync(
        CBAdESSignatureTimestampContext context,
        ParseCBAdESSign1Delegate parse,
        SerializeCBAdESSign1Delegate serialize,
        TrySpliceCBAdESUnprotectedHeaderDelegate spliceUnprotectedHeader,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(parse);
        ArgumentNullException.ThrowIfNull(serialize);
        ArgumentNullException.ThrowIfNull(spliceUnprotectedHeader);
        ArgumentNullException.ThrowIfNull(pool);

        CBAdESSign1ParseResult parseResult = ParseOrThrow(parse, context.WireBytes, pool);

        //STRICT: a new sigTst instance is appended only at B-B/B-T -- checked before any
        //digest computation or Time-Stamping Authority round trip so a doomed call never bills one, mirroring
        //AddSignatureAndReferencesTimestampAsync/AddReferencesTimestampAsync's own ReferencesElementRequired
        //pre-check. Multi-TSA (Table 14 note 7) is a repeated call at TargetLevel=BT, never a call at B-LT+.
        if(context.TargetLevel >= AdESBaselineLevel.BLT)
        {
            parseResult.Dispose();
            throw new CBAdESAugmentationException(
                CBAdESAugmentationFailureKind.SignatureTimestampNotPermittedAtTargetLevel,
                "A new sigTst instance shall be appended only at level B-B or B-T; CB-6.3-21's duplicated " +
                "'B-LT, B-LTA: 0' Table 14 sub-line reads as zero new sigTst instances from B-LT onward (ETSI " +
                "TS 119 152-1 V1.1.1, clause 6.3, Table 14, CB-6.3-21).");
        }

        //Table 14 additional requirement (d): the signing certificate's own validity
        //window is read here -- still before any digest computation or Time-Stamping Authority round trip --
        //so a wrong-kind or unparseable carrier refuses before a doomed round trip is billed. The genTime
        //comparison itself stays post-acquisition (EnsureSigningCertificateValidAtTimestamp below), since it
        //needs the acquired token.
        CertificateValidityPeriod? signingCertificateValidity = ReadSigningCertificateValidityOrThrow(
            parseResult, context.SigningCertificate, context.EnforceSigningCertificateValidity);

        CBAdESUnsignedHeaders? finalUnsignedHeaders = null;
        bool transferred = false;
        AcquiredTimestampToken? token = null;
        try
        {
            PkiDigestAlgorithm algorithm = context.MessageImprintAlgorithm;
            ReadOnlyMemory<byte> signatureValue = parseResult.Signature!.AsReadOnlyMemory();

            using DigestValue imprint = await CryptographicKeyEvents.ComputeDigestAsync(
                signatureValue, algorithm.OutputByteLength, algorithm.DigestTag, pool, cancellationToken: cancellationToken).ConfigureAwait(false);

            token = await TimestampAcquisition.AcquireAsync(
                imprint, context.TsaUri, context.FetchResponse, pool,
                context.ReqPolicyOid, context.NonceByteLength, context.IncludeNonce, cancellationToken).ConfigureAwait(false);

            EnsureSigningCertificateValidAtTimestamp(token, signingCertificateValidity, context.SigningCertificateRevokedAt);

            var container = new AdESTimestampContainer([new AdESTimestampToken { Val = token.Token.AsReadOnlyMemory() }]);
            var element = new CBAdESUnsignedHeaderElementSignatureTimestamp(new CBAdESSignatureTimestamp(container));

            finalUnsignedHeaders = parseResult.UnsignedHeaders is null
                ? new CBAdESUnsignedHeaders([element])
                : parseResult.UnsignedHeaders.Append(element);
            transferred = true;

            CBAdESLevelRules.EnsureConformant(new CBAdESLevelRuleContext
            {
                Level = context.TargetLevel,
                UnsignedHeaders = finalUnsignedHeaders,
                PayloadTimestamps = parseResult.ProtectedHeaders!.PayloadTimestamps
            });

            return EncodeAndSerialize(parseResult, skipDecodedIndexes: null, newElement: element, spliceUnprotectedHeader, serialize, pool);
        }
        finally
        {
            token?.Dispose();
            DisposeAugmentationArtifacts(parseResult, finalUnsignedHeaders, transferred);
        }
    }


    /// <summary>
    /// Acquires an <c>adoTst</c> pre-sign time-stamp component over the COSE Payload (clause 5.2.6) — a
    /// PRE-SIGN operation: no existing signature is parsed or re-serialized, since <c>adoTst</c> is a SIGNED
    /// header parameter the caller places into <see cref="CBAdESProtectedHeaders.PayloadTimestamps"/> before
    /// calling <see cref="CBAdESSignatureCreation.SignAsync(CBAdESProtectedHeaders, CBAdESSigningPayloadInput, CBAdESUnsignedHeaders?, EncodeCBAdESProtectedHeaderDelegate, EncodeCBAdESUnprotectedHeaderDelegate, BuildSigStructureDelegate, PrivateKeyMemory, CBAdESDetachedObjectDereferenceDelegate?, CBAdESDetachedObjectDereferenceContext?, CBAdESUnknownDetachedObjectMechanismDelegate?, BaseMemoryPool, CancellationToken)"/>.
    /// </summary>
    /// <remarks>
    /// <strong>Same-payload invariant with <see cref="CBAdESSigningPayloadInput"/>.</strong>
    /// <paramref name="context"/>'s <see cref="CBAdESPayloadTimestampAcquisitionContext.Source"/> and the
    /// <c>payloadInput</c> the eventual <see cref="CBAdESSignatureCreation.SignAsync(CBAdESProtectedHeaders, CBAdESSigningPayloadInput, CBAdESUnsignedHeaders?, EncodeCBAdESProtectedHeaderDelegate, EncodeCBAdESUnprotectedHeaderDelegate, BuildSigStructureDelegate, PrivateKeyMemory, CBAdESDetachedObjectDereferenceDelegate?, CBAdESDetachedObjectDereferenceContext?, CBAdESUnknownDetachedObjectMechanismDelegate?, BaseMemoryPool, CancellationToken)"/>
    /// call supplies must describe the SAME payload: this method computes the <c>adoTst</c> message imprint
    /// over whatever <see cref="CBAdESPayloadTimestampAcquisitionSource"/> resolves to, and creation later signs
    /// over whatever <see cref="CBAdESSigningPayloadInput"/> resolves to, but nothing in either call cross-checks
    /// the two against each other. A caller-side mismatch is never caught at creation time — it surfaces only
    /// at validation, as a <see cref="CBAdESTimestampTokenBindingViolation"/> naming
    /// <see cref="CBAdESTimestampTokenBindingKind.PayloadTimestamp"/> and
    /// <see cref="CBAdESTimestampTokenBindingFailureReason.ImprintMismatch"/>. The two sums stay deliberately
    /// separate types — a recorded design call, not an oversight: one is the
    /// pre-sign acquisition-time union (this type, which additionally carries raw <c>sigD.pars</c> references
    /// for its third arm, since this orchestrator composes their reconstruction), the other creation's sign-time
    /// union of already-resolved bytes; see <see cref="CBAdESSigningPayloadInput"/>'s own remarks for the
    /// identical cross-reference from the other side.
    /// </remarks>
    /// <param name="context">The payload source, the imprint algorithm, and the authority to contact.</param>
    /// <param name="buildPayloadTimestampMessageImprintInput">The <c>adoTst</c> message-imprint-input seam (Verifiable.Cbor, m2).</param>
    /// <param name="pool">The memory pool every carrier is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>
    /// The <c>adoTst</c> component, encapsulating exactly one time-stamp token. The caller owns and disposes
    /// it. Multiple Time-Stamping Authorities (Table 14 note 6) are multiple calls; combining several results
    /// into one <c>tstContainer</c> is the caller's own concern, matching <see cref="AddSignatureTimestampAsync"/>'s
    /// identical per-call cardinality.
    /// </returns>
    /// <exception cref="ArgumentNullException">When a required argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When <see cref="CBAdESPayloadTimestampAcquisitionContext.Source"/> is a <see cref="CBAdESSigDReferencedPayloadTimestampAcquisitionSource"/> and <see cref="CBAdESPayloadTimestampAcquisitionContext.Dereference"/> or <see cref="CBAdESPayloadTimestampAcquisitionContext.DereferenceContext"/> is <see langword="null"/>.</exception>
    /// <exception cref="CBAdESDetachedObjectDereferenceException">When a referenced detached object could not be dereferenced.</exception>
    /// <exception cref="Verifiable.Cryptography.Pki.TimestampAcquisitionException">When the authority could not be reached, or the token it returned does not verify.</exception>
    /// <remarks>
    /// <strong>Manual disposal, not a <see langword="using"/> declaration.</strong> <c>reconstructedSigDPayload</c>
    /// is assigned only inside the <c>sigD</c>-referenced switch arm, and <c>token</c> only after the message
    /// imprint is computed — both declared <see langword="null"/> ahead of the try body, since a
    /// <see langword="using"/> declaration accepts only a single assignment at its own declaration; the
    /// <see langword="finally"/> below disposes whichever of the two is non-null on every exit path.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "container is wrapped into the returned new CBAdESPayloadTimestamp(container); the " +
            "method's own doc comment states the caller owns and disposes the returned component. Roslyn tracks " +
            "the locally-constructed container itself, not the fact that it is reachable through the returned " +
            "CBAdESPayloadTimestamp one constructor call later -- and in any case AdESTimestampContainer.Dispose " +
            "is currently a no-op (see that type's own remarks), so there is nothing to leak regardless.")]
    public static async ValueTask<CBAdESPayloadTimestamp> AcquirePayloadTimestampAsync(
        CBAdESPayloadTimestampAcquisitionContext context,
        BuildPayloadTimestampMessageImprintInputDelegate buildPayloadTimestampMessageImprintInput,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(context.Source);
        ArgumentNullException.ThrowIfNull(buildPayloadTimestampMessageImprintInput);
        ArgumentNullException.ThrowIfNull(pool);

        PooledMemory? reconstructedSigDPayload = null;
        AcquiredTimestampToken? token = null;
        try
        {
            CBAdESPayloadTimestampImprintSource imprintSource;
            switch(context.Source)
            {
                case CBAdESAttachedPayloadTimestampAcquisitionSource attached:
                    imprintSource = new CBAdESAttachedPayloadTimestampImprintSource(attached.PayloadBytes);
                    break;

                case CBAdESDetachedPayloadTimestampAcquisitionSource detached:
                    imprintSource = new CBAdESDetachedPayloadTimestampImprintSource(detached.PayloadBytes);
                    break;

                case CBAdESSigDReferencedPayloadTimestampAcquisitionSource sigD:
                    if(context.Dereference is null || context.DereferenceContext is null)
                    {
                        throw new ArgumentException(
                            "A sigD-referenced payload source requires a non-null Dereference delegate and DereferenceContext (ETSI TS 119 152-1 V1.1.1, clause 5.2.8.2.1).",
                            nameof(context));
                    }

                    reconstructedSigDPayload = await CBAdESDetachedObjectDereferencing.ReconstructObjectIdByURIPayloadAsync(
                        sigD.References, context.Dereference, context.DereferenceContext, pool, cancellationToken).ConfigureAwait(false);
                    imprintSource = new CBAdESSigDProcessedPayloadTimestampImprintSource([reconstructedSigDPayload.AsReadOnlyMemory()]);
                    break;

                default:
                    throw new NotSupportedException($"Unrecognized {nameof(CBAdESPayloadTimestampAcquisitionSource)} kind '{context.Source.GetType().Name}'.");
            }

            using PooledMemory imprintInput = buildPayloadTimestampMessageImprintInput(imprintSource, pool);

            PkiDigestAlgorithm algorithm = context.MessageImprintAlgorithm;
            using DigestValue imprint = await CryptographicKeyEvents.ComputeDigestAsync(
                imprintInput.AsReadOnlyMemory(), algorithm.OutputByteLength, algorithm.DigestTag, pool, cancellationToken: cancellationToken).ConfigureAwait(false);

            token = await TimestampAcquisition.AcquireAsync(
                imprint, context.TsaUri, context.FetchResponse, pool,
                context.ReqPolicyOid, context.NonceByteLength, context.IncludeNonce, cancellationToken).ConfigureAwait(false);

            //AdESTimestampToken.Val is a borrowed view and AdESTimestampContainer.Dispose is a no-op today
            //(see that type's own remarks) -- this result crosses the method boundary as a decoded model the
            //caller may hold arbitrarily long before SignAsync, so the token's DER bytes are copied to a
            //GC-owned array here, before the pool-rented token is disposed in the finally below, rather than
            //left as a dangling borrowed view into a buffer this method is about to return to the pool.
            byte[] tokenBytes = token.Token.AsReadOnlySpan().ToArray();

            var container = new AdESTimestampContainer([new AdESTimestampToken { Val = tokenBytes }]);

            return new CBAdESPayloadTimestamp(container);
        }
        finally
        {
            token?.Dispose();
            reconstructedSigDPayload?.Dispose();
        }
    }


    /// <summary>
    /// Raises a signature to CB-AdES-B-LT: places the caller's validation material into a new <c>valData</c>
    /// element of <c>uHeaders</c>, deduplicating against material already present in an earlier <c>valData</c>
    /// element by default (Table 14 additional requirements (e)/(f)), and re-checks CB-A.1.1-30 cross-component
    /// consistency against the result.
    /// </summary>
    /// <param name="context">The signature, the material to place, the dedup default, and the target level.</param>
    /// <param name="parse">The fail-closed CBOR parse seam.</param>
    /// <param name="serialize">The CBOR re-serialization seam.</param>
    /// <param name="spliceUnprotectedHeader">The <c>uHeaders</c> unprotected-header raw-splice seam.</param>
    /// <param name="pool">The memory pool every carrier is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The augmented signature's new wire bytes. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException">When a required argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When <see cref="CBAdESValidationDataContext.Material"/> names nothing to place.</exception>
    /// <exception cref="CBAdESAugmentationException">
    /// When <paramref name="context"/>'s wire bytes cannot be parsed, or a supplied object is not of the kind
    /// <c>valData</c> admits (<see cref="CBAdESAugmentationFailureKind.UnsupportedValidationObject"/>).
    /// </exception>
    /// <exception cref="ArgumentException">
    /// When the resulting <c>uHeaders</c> fails <see cref="CBAdESLevelRules.EnsureConformant"/> at
    /// <see cref="CBAdESValidationDataContext.TargetLevel"/>, or a <c>refs</c> entry fails to resolve to
    /// <c>valData</c> material (CB-A.1.1-30) — see the class remarks.
    /// </exception>
    /// <remarks>
    /// <strong>Dedup scope, recorded here.</strong> This call deduplicates only against material already
    /// present in an EARLIER <c>valData</c> element of THIS signature's own <c>uHeaders</c> — the CAdES
    /// exemplar's own scope for its analogous check. It does not scan <c>x5chain</c>, the signed <c>x5t</c>/
    /// <c>x5ts</c>, or <c>refs</c> for a matching certificate; a caller supplying material already reachable
    /// through one of those signed components places a certificate <c>valData</c> also carries, which is
    /// legal (Table 14 requirements (e)/(f) are SHOULDs) but outside this method's dedup scope.
    /// </remarks>
    public static async ValueTask<EncodedCoseSign1> AddValidationDataAsync(
        CBAdESValidationDataContext context,
        ParseCBAdESSign1Delegate parse,
        SerializeCBAdESSign1Delegate serialize,
        TrySpliceCBAdESUnprotectedHeaderDelegate spliceUnprotectedHeader,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(context.Material);
        ArgumentNullException.ThrowIfNull(parse);
        ArgumentNullException.ThrowIfNull(serialize);
        ArgumentNullException.ThrowIfNull(spliceUnprotectedHeader);
        ArgumentNullException.ThrowIfNull(pool);
        if(context.Material.IsEmpty)
        {
            throw new ArgumentException(
                "Placing validation data places at least one certificate, certificate revocation list, or OCSP response.",
                nameof(context));
        }

        CBAdESSign1ParseResult parseResult = ParseOrThrow(parse, context.WireBytes, pool);
        CBAdESUnsignedHeaders? finalUnsignedHeaders = null;
        bool transferred = false;
        try
        {
            (List<CBAdESX509OrOtherCertificate>? certificateValues, CBAdESRevocationValues? revocationValues) =
                BuildValidationDataMembers(context.Material, parseResult.UnsignedHeaders, context.DeduplicateAgainstExisting);

            CBAdESUnsignedHeaderElement? newElement = null;
            if(certificateValues is null && revocationValues is null)
            {
                //Every candidate was already present in an earlier valData element (requirements (e)/(f)
                //dedup) -- the signature stands as it was; the round trip through parse/serialize keeps the
                //ownership contract identical either way (the splice below retains every raw element verbatim
                //and appends nothing new, reproducing the identical wire bytes).
                finalUnsignedHeaders = parseResult.UnsignedHeaders;
            }
            else
            {
                newElement = new CBAdESUnsignedHeaderElementValidationData(new CBAdESValidationData(certificateValues, revocationValues));
                finalUnsignedHeaders = parseResult.UnsignedHeaders is null
                    ? new CBAdESUnsignedHeaders([newElement])
                    : parseResult.UnsignedHeaders.Append(newElement);
            }

            transferred = true;

            CBAdESLevelRules.EnsureConformant(new CBAdESLevelRuleContext
            {
                Level = context.TargetLevel,
                UnsignedHeaders = finalUnsignedHeaders,
                PayloadTimestamps = parseResult.ProtectedHeaders!.PayloadTimestamps
            });

            await CBAdESLevelRules.EnsureReferencesResolveToValidationDataAsync(finalUnsignedHeaders, pool, cancellationToken).ConfigureAwait(false);

            return EncodeAndSerialize(parseResult, skipDecodedIndexes: null, newElement, spliceUnprotectedHeader, serialize, pool);
        }
        finally
        {
            DisposeAugmentationArtifacts(parseResult, finalUnsignedHeaders, transferred);
        }
    }


    /// <summary>
    /// Prepares the B-LT transition by rebuilding <c>uHeaders</c> WITHOUT any <c>refs</c>/<c>sigRTst</c>/
    /// <c>rfsTst</c> element (Table 14, CB-6.3-23/-24/-25: the whole family is hard-forbidden from B-LT on).
    /// Synchronous — a pure structural rebuild, no digest or Time-Stamping Authority involved, matching
    /// <see cref="Verifiable.Cryptography.Pki.CAdESSignatureAugmentation.AddValidationData"/>'s own
    /// "synchronous where nothing cryptographic happens" precedent.
    /// </summary>
    /// <param name="context">
    /// The signature, the target level, and (for the one-step direct-to-B-LT choreography) the caller-attested
    /// embedded-material fact; see <see cref="CBAdESStripReferencesContext.TargetLevel"/>'s own remarks for the
    /// two choreographies this call fits into.
    /// </param>
    /// <param name="parse">The fail-closed CBOR parse seam.</param>
    /// <param name="serialize">The CBOR re-serialization seam.</param>
    /// <param name="spliceUnprotectedHeader">The <c>uHeaders</c> unprotected-header raw-splice seam.</param>
    /// <param name="pool">The memory pool every carrier is rented from.</param>
    /// <returns>The stripped signature's new wire bytes. The caller owns and disposes it. Absent every retained element, the result carries no <c>uHeaders</c> member at all.</returns>
    /// <exception cref="ArgumentNullException">When a required argument is <see langword="null"/>.</exception>
    /// <exception cref="CBAdESAugmentationException">When <paramref name="context"/>'s wire bytes cannot be parsed.</exception>
    /// <exception cref="ArgumentException">
    /// When the resulting <c>uHeaders</c> fails <see cref="CBAdESLevelRules.EnsureConformant"/> at
    /// <see cref="CBAdESStripReferencesContext.TargetLevel"/> — most commonly because
    /// <see cref="Verifiable.Cryptography.Pki.AdESBaselineLevel.BLT"/> was targeted directly (the one-step
    /// choreography) without <see cref="CBAdESStripReferencesContext.AnyTimestampTokenCarriesEmbeddedValidationMaterial"/>
    /// attested and no <c>valData</c> otherwise present (CB-6.3-26); every other rule this
    /// surface checks should not occur by construction over an already-conformant input, kept as defense in depth.
    /// </exception>
    /// <remarks>
    /// <para>
    /// <strong>Design call: a standalone strip verb, not folded into a "RaiseToLongTerm" step.</strong>
    /// <see cref="AddValidationDataAsync"/> already performs
    /// the OTHER B-LT-transition act (placing <c>valData</c>) as its own call; keeping the strip act separate
    /// mirrors CAdES's own granular verb style (many small composable operations, never one monolithic
    /// "raise the level" method) and lets a caller strip and place validation data in whichever order its own
    /// material-gathering flow prefers, strip alone when <c>valData</c> is already present from an earlier
    /// <c>AddValidationDataAsync</c> call at B-T, or reach B-LT in this call alone when
    /// <see cref="CBAdESStripReferencesContext.AnyTimestampTokenCarriesEmbeddedValidationMaterial"/> is attested
    /// — see that member's own remarks for the fail-closed default this choice carries.
    /// </para>
    /// <para>
    /// <strong>The double-dispose/leak hazard this discipline exists to close.</strong> <c>refs</c>,
    /// <c>sigRTst</c>, and <c>rfsTst</c> elements own real <see cref="DigestValue"/> carriers (certificate/CRL/
    /// OCSP thumbprints); every RETAINED element (e.g. <c>sigTst</c>, <c>valData</c>) is the exact SAME object
    /// reference the caller's parsed <see cref="CBAdESSign1ParseResult.UnsignedHeaders"/> already holds. This
    /// method therefore: (1) walks the parsed elements ONCE, splitting them into "retained" and "refs-family";
    /// (2) disposes ONLY the refs-family elements, individually, right there; (3) builds the new container from
    /// the retained list ALONE — never touching the elements it just disposed; (4) NEVER calls
    /// <c>parseResult.UnsignedHeaders.Dispose()</c> — every one of its elements is now accounted for exactly
    /// once (either disposed in step 2, or reachable through the new container from step 3, which
    /// <see cref="DisposeAugmentationArtifacts"/> disposes in this method's <c>finally</c>). Reversing this —
    /// disposing the abandoned source container as a whole — would double-dispose every retained element's own
    /// digests once the new container is later disposed too.
    /// </para>
    /// </remarks>
    public static EncodedCoseSign1 StripReferencesForLongTerm(
        CBAdESStripReferencesContext context,
        ParseCBAdESSign1Delegate parse,
        SerializeCBAdESSign1Delegate serialize,
        TrySpliceCBAdESUnprotectedHeaderDelegate spliceUnprotectedHeader,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(parse);
        ArgumentNullException.ThrowIfNull(serialize);
        ArgumentNullException.ThrowIfNull(spliceUnprotectedHeader);
        ArgumentNullException.ThrowIfNull(pool);

        CBAdESSign1ParseResult parseResult = ParseOrThrow(parse, context.WireBytes, pool);
        CBAdESUnsignedHeaders? finalUnsignedHeaders = null;
        bool transferred = false;
        HashSet<int>? skipDecodedIndexes = null;
        try
        {
            if(parseResult.UnsignedHeaders is not null)
            {
                List<CBAdESUnsignedHeaderElement> retained = [];
                for(int i = 0; i < parseResult.UnsignedHeaders.Count; ++i)
                {
                    CBAdESUnsignedHeaderElement element = parseResult.UnsignedHeaders[i];
                    if(IsReferencesFamilyElement(element))
                    {
                        //Classified by DECODED-MODEL index, for the raw-splice seam below to skip the matching
                        //raw array entry verbatim -- never a re-encode of what is retained.
                        skipDecodedIndexes ??= [];
                        skipDecodedIndexes.Add(i);

                        if(element is IDisposable disposable)
                        {
                            disposable.Dispose();
                        }
                    }
                    else
                    {
                        retained.Add(element);
                    }
                }

                finalUnsignedHeaders = retained.Count > 0 ? new CBAdESUnsignedHeaders(retained) : null;
            }

            //Every element parseResult.UnsignedHeaders held is now accounted for: retained elements moved into
            //finalUnsignedHeaders, refs-family elements disposed above. The abandoned source container itself
            //is never cascade-disposed (see this method's own remarks).
            transferred = true;

            CBAdESLevelRules.EnsureConformant(new CBAdESLevelRuleContext
            {
                Level = context.TargetLevel,
                UnsignedHeaders = finalUnsignedHeaders,
                AnyTimestampTokenCarriesEmbeddedValidationMaterial = context.AnyTimestampTokenCarriesEmbeddedValidationMaterial,
                PayloadTimestamps = parseResult.ProtectedHeaders!.PayloadTimestamps
            });

            return EncodeAndSerialize(parseResult, skipDecodedIndexes, newElement: null, spliceUnprotectedHeader, serialize, pool);
        }
        finally
        {
            DisposeAugmentationArtifacts(parseResult, finalUnsignedHeaders, transferred);
        }
    }


    /// <summary>
    /// Adds a <c>sigRTst</c> element (Annex A.1.2.1): a time-stamp over the COSE signature value, the
    /// signature time-stamp (if present), and the certificate/revocation references — gated on a <c>refs</c>
    /// element already being present (CB-A.1.2.1-03).
    /// </summary>
    /// <param name="context">The signature, the imprint algorithm, the authority to contact, and the target level (B-B or B-T).</param>
    /// <param name="parse">The fail-closed CBOR parse seam.</param>
    /// <param name="serialize">The CBOR re-serialization seam.</param>
    /// <param name="spliceUnprotectedHeader">The <c>uHeaders</c> unprotected-header raw-splice seam.</param>
    /// <param name="buildImprintInput">The <c>sigRTst</c> message-imprint-input seam (Verifiable.Cbor, m2).</param>
    /// <param name="pool">The memory pool every carrier is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The augmented signature's new wire bytes. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException">When a required argument is <see langword="null"/>.</exception>
    /// <exception cref="CBAdESAugmentationException">
    /// When <paramref name="context"/>'s wire bytes cannot be parsed; when no <c>refs</c> element precedes the
    /// would-be <c>sigRTst</c> element (<see cref="CBAdESAugmentationFailureKind.ReferencesElementRequired"/>,
    /// checked BEFORE any Time-Stamping Authority round trip so a doomed call never bills one); or when the
    /// imprint builder cannot build the input from this signature's own <c>uHeaders</c>
    /// (<see cref="CBAdESAugmentationFailureKind.MessageImprintInputMalformed"/>).
    /// </exception>
    /// <exception cref="ArgumentException">
    /// When the resulting <c>uHeaders</c> fails <see cref="CBAdESLevelRules.EnsureConformant"/> at
    /// <see cref="CBAdESReferencesFamilyTimestampContext.TargetLevel"/> — see the class remarks.
    /// </exception>
    /// <exception cref="Verifiable.Cryptography.Pki.TimestampAcquisitionException">When the authority could not be reached, or the token it returned does not verify.</exception>
    public static async ValueTask<EncodedCoseSign1> AddSignatureAndReferencesTimestampAsync(
        CBAdESReferencesFamilyTimestampContext context,
        ParseCBAdESSign1Delegate parse,
        SerializeCBAdESSign1Delegate serialize,
        TrySpliceCBAdESUnprotectedHeaderDelegate spliceUnprotectedHeader,
        TryBuildSignatureAndReferencesTimestampMessageImprintInputDelegate buildImprintInput,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(buildImprintInput);
        ArgumentNullException.ThrowIfNull(parse);
        ArgumentNullException.ThrowIfNull(serialize);
        ArgumentNullException.ThrowIfNull(spliceUnprotectedHeader);
        ArgumentNullException.ThrowIfNull(pool);

        CBAdESSign1ParseResult parseResult = ParseOrThrow(parse, context.WireBytes, pool);
        PooledMemory imprintInput;
        try
        {
            if(!HasReferencesElement(parseResult.UnsignedHeaders))
            {
                parseResult.Dispose();
                throw new CBAdESAugmentationException(
                    CBAdESAugmentationFailureKind.ReferencesElementRequired,
                    "If the component refs is not present, the sigRTst CBOR map shall not be generated (ETSI TS 119 152-1 V1.1.1, Annex A.1.2.1.1, CB-A.1.2.1-03).");
            }

            ReadOnlyMemory<byte>? uHeadersEncodedArray = parseResult.RawUnsignedHeaders?.AsReadOnlyMemory();
            //Generation always builds the imprint over the pre-append snapshot -- every element parseResult.UnsignedHeaders
            //already held -- which is already the correct prefix, so uHeadersSliceBound is null here.
            if(!buildImprintInput(parseResult.Signature!.AsReadOnlyMemory(), uHeadersEncodedArray, uHeadersSliceBound: null, pool, out PooledMemory? builtImprintInput) || builtImprintInput is null)
            {
                parseResult.Dispose();
                throw new CBAdESAugmentationException(
                    CBAdESAugmentationFailureKind.MessageImprintInputMalformed,
                    "The sigRTst message-imprint input could not be built from this signature's own uHeaders (ETSI TS 119 152-1 V1.1.1, Annex A.1.2.1.2).");
            }

            imprintInput = builtImprintInput;
        }
        catch(CBAdESAugmentationException)
        {
            //parseResult is already disposed by the branch that threw, above.
            throw;
        }
        catch
        {
            //An unexpected failure reading parseResult's own carriers or from buildImprintInput, before
            //ownership of parseResult reaches AppendReferencesFamilyTimestampAsync below (which disposes
            //it in its own finally on every path once called) — parseResult is otherwise unowned here.
            parseResult.Dispose();

            throw;
        }

        return await AppendReferencesFamilyTimestampAsync(
            context, parseResult, imprintInput, CBAdESReferencesFamilyTimestampKind.SignatureAndReferences,
            spliceUnprotectedHeader, serialize, pool, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Adds an <c>rfsTst</c> element (Annex A.1.2.2): a time-stamp over the signature time-stamp (if present)
    /// and the certificate/revocation references, OMITTING the COSE signature value — gated on a <c>refs</c>
    /// element already being present (CB-A.1.2.2-03).
    /// </summary>
    /// <param name="context">The signature, the imprint algorithm, the authority to contact, and the target level (B-B or B-T).</param>
    /// <param name="parse">The fail-closed CBOR parse seam.</param>
    /// <param name="serialize">The CBOR re-serialization seam.</param>
    /// <param name="spliceUnprotectedHeader">The <c>uHeaders</c> unprotected-header raw-splice seam.</param>
    /// <param name="buildImprintInput">The <c>rfsTst</c> message-imprint-input seam (Verifiable.Cbor, m2).</param>
    /// <param name="pool">The memory pool every carrier is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The augmented signature's new wire bytes. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException">When a required argument is <see langword="null"/>.</exception>
    /// <exception cref="CBAdESAugmentationException">
    /// When <paramref name="context"/>'s wire bytes cannot be parsed; when no <c>refs</c> element precedes the
    /// would-be <c>rfsTst</c> element (<see cref="CBAdESAugmentationFailureKind.ReferencesElementRequired"/>,
    /// checked BEFORE any Time-Stamping Authority round trip); or when the imprint builder cannot build the
    /// input from this signature's own <c>uHeaders</c> (<see cref="CBAdESAugmentationFailureKind.MessageImprintInputMalformed"/>).
    /// </exception>
    /// <exception cref="ArgumentException">
    /// When the resulting <c>uHeaders</c> fails <see cref="CBAdESLevelRules.EnsureConformant"/> at
    /// <see cref="CBAdESReferencesFamilyTimestampContext.TargetLevel"/> — see the class remarks.
    /// </exception>
    /// <exception cref="Verifiable.Cryptography.Pki.TimestampAcquisitionException">When the authority could not be reached, or the token it returned does not verify.</exception>
    public static async ValueTask<EncodedCoseSign1> AddReferencesTimestampAsync(
        CBAdESReferencesFamilyTimestampContext context,
        ParseCBAdESSign1Delegate parse,
        SerializeCBAdESSign1Delegate serialize,
        TrySpliceCBAdESUnprotectedHeaderDelegate spliceUnprotectedHeader,
        TryBuildReferencesOnlyTimestampMessageImprintInputDelegate buildImprintInput,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(buildImprintInput);
        ArgumentNullException.ThrowIfNull(parse);
        ArgumentNullException.ThrowIfNull(serialize);
        ArgumentNullException.ThrowIfNull(spliceUnprotectedHeader);
        ArgumentNullException.ThrowIfNull(pool);

        CBAdESSign1ParseResult parseResult = ParseOrThrow(parse, context.WireBytes, pool);
        PooledMemory imprintInput;
        try
        {
            if(!HasReferencesElement(parseResult.UnsignedHeaders))
            {
                parseResult.Dispose();
                throw new CBAdESAugmentationException(
                    CBAdESAugmentationFailureKind.ReferencesElementRequired,
                    "If the component refs is not present, the rfsTst CBOR map shall not be generated (ETSI TS 119 152-1 V1.1.1, Annex A.1.2.2.1, CB-A.1.2.2-03).");
            }

            ReadOnlyMemory<byte>? uHeadersEncodedArray = parseResult.RawUnsignedHeaders?.AsReadOnlyMemory();
            //Generation always builds the imprint over the pre-append snapshot -- the correct prefix already --
            //so uHeadersSliceBound is null here; see AddSignatureAndReferencesTimestampAsync's identical remark.
            if(!buildImprintInput(uHeadersEncodedArray, uHeadersSliceBound: null, pool, out PooledMemory? builtImprintInput) || builtImprintInput is null)
            {
                parseResult.Dispose();
                throw new CBAdESAugmentationException(
                    CBAdESAugmentationFailureKind.MessageImprintInputMalformed,
                    "The rfsTst message-imprint input could not be built from this signature's own uHeaders (ETSI TS 119 152-1 V1.1.1, Annex A.1.2.2.2).");
            }

            imprintInput = builtImprintInput;
        }
        catch(CBAdESAugmentationException)
        {
            //parseResult is already disposed by the branch that threw, above.
            throw;
        }
        catch
        {
            //An unexpected failure reading parseResult's own carriers or from buildImprintInput, before
            //ownership of parseResult reaches AppendReferencesFamilyTimestampAsync below (which disposes
            //it in its own finally on every path once called) — parseResult is otherwise unowned here.
            parseResult.Dispose();

            throw;
        }

        return await AppendReferencesFamilyTimestampAsync(
            context, parseResult, imprintInput, CBAdESReferencesFamilyTimestampKind.ReferencesOnly,
            spliceUnprotectedHeader, serialize, pool, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Adds a <c>refs</c> element (Annex A.1.1): certificate and revocation-data references built from
    /// caller-supplied material, each digest computed via the registered digest delegate, refusing to
    /// reference the signature's own signing certificate (CB-A.1.1-02) and omitting <c>kid</c> by default
    /// (additional requirement (g)).
    /// </summary>
    /// <param name="context">The signature, the signing certificate, the material to reference, the digest algorithm, and the target level.</param>
    /// <param name="parse">The fail-closed CBOR parse seam.</param>
    /// <param name="serialize">The CBOR re-serialization seam.</param>
    /// <param name="spliceUnprotectedHeader">The <c>uHeaders</c> unprotected-header raw-splice seam.</param>
    /// <param name="pool">The memory pool every carrier is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The augmented signature's new wire bytes. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException">When a required argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">
    /// When neither <c>xRefs</c> nor <c>rRefs</c> ends up with any entry (<see cref="CBAdESReferences"/>'s own
    /// constructor invariant), or when the resulting <c>uHeaders</c> fails
    /// <see cref="CBAdESLevelRules.EnsureConformant"/> at <see cref="CBAdESReferencesContext.TargetLevel"/>.
    /// </exception>
    /// <exception cref="CBAdESAugmentationException">
    /// When <paramref name="context"/>'s wire bytes cannot be parsed; when a supplied object is not of the kind
    /// <c>refs</c> admits (<see cref="CBAdESAugmentationFailureKind.UnsupportedValidationObject"/>); or when a
    /// candidate certificate byte-equals <see cref="CBAdESReferencesContext.SigningCertificate"/>
    /// (<see cref="CBAdESAugmentationFailureKind.SigningCertificateReferenceRefused"/>).
    /// </exception>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Each per-entry AdESCertificateThumbprint/CBAdESRevocationReferences/CBAdESReferences/ " +
            "CBAdESUnsignedHeaderElementReferences this method constructs is either (a) reachable through " +
            "finalUnsignedHeaders once `transferred` is true -- disposed in the finally below through " +
            "DisposeAugmentationArtifacts -- or (b) disposed explicitly by the catch clause's DisposeEntries " +
            "calls over certificateReferences/crlReferences/ocspReferences on any failure before `transferred` " +
            "is set (see that catch clause's own remarks for the exact ownership split). Roslyn tracks each " +
            "locally-constructed carrier itself, not the fact that the two-way disposal split above already " +
            "accounts for every path.")]
    public static async ValueTask<EncodedCoseSign1> AddReferencesAsync(
        CBAdESReferencesContext context,
        ParseCBAdESSign1Delegate parse,
        SerializeCBAdESSign1Delegate serialize,
        TrySpliceCBAdESUnprotectedHeaderDelegate spliceUnprotectedHeader,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(context.SigningCertificate);
        ArgumentNullException.ThrowIfNull(parse);
        ArgumentNullException.ThrowIfNull(serialize);
        ArgumentNullException.ThrowIfNull(spliceUnprotectedHeader);
        ArgumentNullException.ThrowIfNull(pool);

        CBAdESSign1ParseResult parseResult = ParseOrThrow(parse, context.WireBytes, pool);
        CBAdESUnsignedHeaders? finalUnsignedHeaders = null;
        bool transferred = false;
        List<CBAdESCertificateReference>? certificateReferences = null;
        List<CBAdESCrlReference>? crlReferences = null;
        List<CBAdESOcspReference>? ocspReferences = null;
        try
        {
            AdESDigestAlgorithmIdentifier wireAlgorithm = ToWireDigestAlgorithm(context.MessageImprintAlgorithm);
            PkiDigestAlgorithm algorithm = context.MessageImprintAlgorithm;

            if(context.CertificatesToReference is { Count: > 0 } certificatesToReference)
            {
                certificateReferences = new List<CBAdESCertificateReference>(certificatesToReference.Count);
                for(int i = 0; i < certificatesToReference.Count; ++i)
                {
                    PkiCertificateMemory candidate = certificatesToReference[i];
                    EnsureKind(
                        candidate.IsX509Certificate,
                        CBAdESAugmentationFailureKind.UnsupportedValidationObject,
                        "A certificate referenced in refs is a DER-encoded X.509 certificate (ETSI TS 119 152-1 V1.1.1, Annex A.1.1).");

                    if(candidate.AsReadOnlySpan().SequenceEqual(context.SigningCertificate.AsReadOnlySpan()))
                    {
                        throw new CBAdESAugmentationException(
                            CBAdESAugmentationFailureKind.SigningCertificateReferenceRefused,
                            "The refs CBOR map shall not contain the signing certificate of the CB-AdES signature itself (ETSI TS 119 152-1 V1.1.1, Annex A.1.1, CB-A.1.1-02).");
                    }

                    DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
                        candidate.AsReadOnlyMemory(), algorithm.OutputByteLength, algorithm.DigestTag, pool, cancellationToken: cancellationToken).ConfigureAwait(false);
                    certificateReferences.Add(new CBAdESCertificateReference(new AdESCertificateThumbprint(wireAlgorithm, digest)));
                }
            }

            if(context.CrlsToReference is { Count: > 0 } crlsToReference)
            {
                crlReferences = new List<CBAdESCrlReference>(crlsToReference.Count);
                for(int i = 0; i < crlsToReference.Count; ++i)
                {
                    PkiCertificateMemory candidate = crlsToReference[i];
                    EnsureKind(
                        candidate.IsCrl,
                        CBAdESAugmentationFailureKind.UnsupportedValidationObject,
                        "A certificate revocation list referenced in refs is a DER-encoded CertificateList (ETSI TS 119 152-1 V1.1.1, Annex A.1.1, CB-A.1.1-12).");

                    DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
                        candidate.AsReadOnlyMemory(), algorithm.OutputByteLength, algorithm.DigestTag, pool, cancellationToken: cancellationToken).ConfigureAwait(false);
                    crlReferences.Add(new CBAdESCrlReference(wireAlgorithm, digest));
                }
            }

            if(context.OcspResponsesToReference is { Count: > 0 } ocspResponsesToReference)
            {
                ocspReferences = new List<CBAdESOcspReference>(ocspResponsesToReference.Count);
                for(int i = 0; i < ocspResponsesToReference.Count; ++i)
                {
                    CBAdESOcspReferenceInput input = ocspResponsesToReference[i];
                    EnsureKind(
                        input.Response.IsOcspResponse,
                        CBAdESAugmentationFailureKind.UnsupportedValidationObject,
                        "An OCSP response referenced in refs is a DER-encoded OCSPResponse (ETSI TS 119 152-1 V1.1.1, Annex A.1.1, CB-A.1.1-28).");

                    DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
                        input.Response.AsReadOnlyMemory(), algorithm.OutputByteLength, algorithm.DigestTag, pool, cancellationToken: cancellationToken).ConfigureAwait(false);
                    ocspReferences.Add(new CBAdESOcspReference(wireAlgorithm, digest, input.Identifier));
                }
            }

            CBAdESRevocationReferences? revocationReferences = crlReferences is not null || ocspReferences is not null
                ? new CBAdESRevocationReferences(crlReferences, ocspReferences)
                : null;

            var referencesElement = new CBAdESReferences(certificateReferences, revocationReferences);
            var element = new CBAdESUnsignedHeaderElementReferences(referencesElement);

            finalUnsignedHeaders = parseResult.UnsignedHeaders is null
                ? new CBAdESUnsignedHeaders([element])
                : parseResult.UnsignedHeaders.Append(element);
            transferred = true;

            CBAdESLevelRules.EnsureConformant(new CBAdESLevelRuleContext
            {
                Level = context.TargetLevel,
                UnsignedHeaders = finalUnsignedHeaders,
                PayloadTimestamps = parseResult.ProtectedHeaders!.PayloadTimestamps
            });

            return EncodeAndSerialize(parseResult, skipDecodedIndexes: null, newElement: element, spliceUnprotectedHeader, serialize, pool);
        }
        catch
        {
            //Ownership of certificateReferences/crlReferences/ocspReferences has not transferred anywhere yet
            //(the referencesElement that would own them was never reached, or `transferred` is still false
            //because the failure happened before/while building it) -- every DigestValue already computed for
            //a partial list must be disposed here, or its pool rental leaks. Once `transferred` is true, these
            //same lists are reachable through finalUnsignedHeaders (disposed in the finally below via
            //DisposeAugmentationArtifacts), so disposing them again here would double-dispose.
            if(!transferred)
            {
                DisposeEntries(certificateReferences);
                DisposeEntries(crlReferences);
                DisposeEntries(ocspReferences);
            }

            throw;
        }
        finally
        {
            DisposeAugmentationArtifacts(parseResult, finalUnsignedHeaders, transferred);
        }
    }


    /// <summary>
    /// Raises a signature to CB-AdES-B-LTA (or extends it with a new, later <c>arcTst</c> instance — a genuine
    /// renewal, or Table 14 note 7's multi-Time-Stamping-Authority pattern applied across separate calls):
    /// computes the clause 5.3.5.3 message imprint over every already-incorporated <c>uHeaders</c> element,
    /// requests one electronic time-stamp token per configured Time-Stamping Authority leg (additional
    /// requirement (j)), and incorporates all of them into ONE new <c>arcTst</c> element appended last.
    /// </summary>
    /// <param name="context">The signature, the imprint algorithm, the TSA legs, the declared target level, and the additional-requirement-(k) inputs.</param>
    /// <param name="parse">The fail-closed CBOR parse seam.</param>
    /// <param name="serialize">The CBOR re-serialization seam.</param>
    /// <param name="spliceUnprotectedHeader">The <c>uHeaders</c> unprotected-header raw-splice seam.</param>
    /// <param name="buildImprintInput">The <c>arcTst</c> GENERATION-mode message-imprint-input seam (clause 5.3.5.3), implemented in <c>Verifiable.Cbor</c>.</param>
    /// <param name="pool">The memory pool every carrier is rented from.</param>
    /// <param name="parseCounterSignatureHeaderValue">
    /// Decodes a counter-signature element's raw value bytes for CB-5.3.5.1-02's material-completeness check,
    /// or <see langword="null"/> to refuse outright whenever <c>uHeaders</c> already incorporates one.
    /// </param>
    /// <param name="isCounterSignatureMaterialComplete">
    /// The caller-supplied completeness resolver for CB-5.3.5.1-02, or <see langword="null"/> to refuse
    /// outright whenever <c>uHeaders</c> already incorporates a counter-signature element — this call never
    /// itself builds or verifies a certificate chain.
    /// </param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The augmented signature's new wire bytes. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException">When a required argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When <see cref="CBAdESArchiveTimestampContext.TsaLegs"/> is empty.</exception>
    /// <exception cref="CBAdESAugmentationException">
    /// When <paramref name="context"/>'s wire bytes cannot be parsed
    /// (<see cref="CBAdESAugmentationFailureKind.MalformedEncoding"/>); when
    /// <see cref="CBAdESArchiveTimestampContext.TargetLevel"/> is not
    /// <see cref="Verifiable.Cryptography.Pki.AdESBaselineLevel.BLTA"/>
    /// (<see cref="CBAdESAugmentationFailureKind.ArchiveTimestampNotPermittedAtTargetLevel"/>, checked before
    /// any Time-Stamping Authority round trip); when
    /// <see cref="CBAdESArchiveTimestampContext.SigningCertificate"/> is not readable as an X.509 certificate
    /// (<see cref="CBAdESAugmentationFailureKind.SigningCertificateMalformed"/>, likewise checked before any
    /// Time-Stamping Authority round trip); when no <c>sigTst</c> instance is incorporated yet
    /// (<see cref="CBAdESAugmentationFailureKind.ArchiveTimestampSignatureTimestampPrerequisiteMissing"/>,
    /// checked before any Time-Stamping Authority round trip — CB-6.3-21); when
    /// additional requirement (k) is not satisfied
    /// (<see cref="CBAdESAugmentationFailureKind.ArchiveTimestampValidationMaterialIncomplete"/>, also checked
    /// before any Time-Stamping Authority round trip — the two token-level arms worded distinctly
    /// to name which one actually failed); when a <c>refs</c>/<c>sigRTst</c>/<c>rfsTst</c> element is still incorporated
    /// (<see cref="CBAdESAugmentationFailureKind.ArchiveTimestampReferencesFamilyElementPresent"/>, checked
    /// AFTER the CB-A.1.1-30 resolution check below but still before any Time-Stamping Authority round trip —
    /// CB-6.3-23/-24/-25); or when the message-imprint input cannot be built, or its
    /// payload contribution cannot be resolved (<see cref="CBAdESAugmentationFailureKind.MessageImprintInputMalformed"/>).
    /// </exception>
    /// <exception cref="Verifiable.Cryptography.Pki.TimestampAcquisitionException">
    /// When a configured authority could not be reached, or the token it returned does not verify.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// When a <c>refs</c> entry already incorporated into the signature fails to resolve to <c>valData</c> or
    /// <c>arcTst</c>-embedded material (CB-A.1.1-30 — checked pre-append,
    /// before this call's own new <c>arcTst</c> element is ever built and before the
    /// <see cref="CBAdESAugmentationFailureKind.ArchiveTimestampReferencesFamilyElementPresent"/> refusal above),
    /// or the resulting <c>uHeaders</c> fails <see cref="CBAdESLevelRules.EnsureConformant"/> at
    /// <see cref="CBAdESArchiveTimestampContext.TargetLevel"/> — see the class remarks.
    /// </exception>
    /// <remarks>
    /// <para>
    /// <strong>Clause 5.3.5.2, all five steps, in call order.</strong> Step 1: when
    /// <see cref="CBAdESArchiveTimestampContext.GapFillValidationMaterial"/> is supplied, a new <c>valData</c>
    /// element is spliced in and the signature is RE-PARSED from that staged result (<see cref="StageGapFillValidationData"/>)
    /// — never a decoded-model re-encode of the RETAINED elements, a defect this whole file avoids —
    /// before anything past this point runs, so the imprint computed in step 2 genuinely covers the gap-filled
    /// element (order is normative). Additional requirement (k)'s structural precheck
    /// (<see cref="EnsureArchiveTimestampValidationMaterialCompleteAsync"/>) then runs over that (possibly
    /// gap-filled) state, before any Time-Stamping Authority round trip. Steps 2-5: the message imprint is
    /// built via <paramref name="buildImprintInput"/> over EVERY <c>uHeaders</c> element already present; one
    /// token is acquired per <see cref="CBAdESArchiveTimestampContext.TsaLegs"/> entry, ALL over that SAME
    /// imprint (additional requirement (j)); every acquired token is encapsulated in ONE new
    /// <c>arcTst</c> element, appended last through the byte-verbatim splice seam.
    /// </para>
    /// <para>
    /// <strong>The gate ladder, mirroring <see cref="AddSignatureTimestampAsync"/>'s own shape.</strong> In
    /// order, all before any Time-Stamping Authority round trip: (1) the declared
    /// <see cref="CBAdESArchiveTimestampContext.TargetLevel"/> must be
    /// <see cref="Verifiable.Cryptography.Pki.AdESBaselineLevel.BLTA"/> (write-strict); (2)
    /// <see cref="CBAdESArchiveTimestampContext.SigningCertificate"/> must be readable
    /// (<see cref="ReadSigningCertificateValidityOrThrow"/> — arcTst has no requirement-(d)-shaped
    /// genTime comparison of its own, so the returned validity window is read for readability alone and
    /// otherwise discarded); (3) <see cref="CBAdESArchiveTimestampContext.ChainCompletenessAttested"/> must be
    /// <see langword="true"/>; (4) at least one <c>sigTst</c> instance must already be incorporated (CB-6.3-21,
    /// the B-LTA ladder's own prerequisite — the generation/validation asymmetry relies on this gate to keep
    /// <c>uHeaders</c> non-absent by the time the first <c>arcTst</c>'s imprint is built); (5) every electronic
    /// time-stamp token already incorporated into the signature must itself be READABLE at all — an unreadable
    /// token's material is unverifiable and refuses fail-closed before this call ever asks whether a signer
    /// certificate resolves — and, distinctly, every successfully-read such token must have a resolvable signer
    /// certificate (CB-6.3-k/h; the two conditions are worded apart); (6) every
    /// <c>refs</c> entry already incorporated must resolve to <c>valData</c> or <c>arcTst</c>-embedded material
    /// (CB-A.1.1-30 — the <see cref="AddValidationDataAsync"/> precedent,
    /// over this call's own possibly gap-filled state, so this producer never mints what the validator's own
    /// widened trigger/candidate set would reject); (7) no <c>refs</c>, <c>sigRTst</c>, or <c>rfsTst</c> element
    /// may still be incorporated (CB-6.3-23/-24/-25 — Table 14 hard-forbids that whole
    /// family once the declared level is B-LT or above, and gate (1) above already fixes it at B-LTA here; the
    /// upgrade choreography's own <see cref="StripReferencesForLongTerm"/> step must already have run). Gate
    /// (7) runs strictly AFTER gate (6): an unresolvable <c>refs</c> entry surfaces its own, more specific
    /// CB-A.1.1-30 failure before this gate is ever reached; only a resolvable one (or a signature with no
    /// <c>refs</c>/<c>valData</c>/<c>arcTst</c> disjunction at all) can reach gate (7)'s own refusal — the two
    /// gates are independently provable. A doomed call never bills a Time-Stamping Authority.
    /// </para>
    /// <para>
    /// <strong>Manual disposal, not a <see langword="using"/> declaration.</strong> <c>payloadRented</c> is
    /// bound by a tuple deconstruction from <see cref="CBAdESSignatureValidation.ResolvePayloadTimestampImprintSourceAsync"/>
    /// (a <see langword="using"/> declaration accepts only a single simple declaration, never a deconstruction
    /// target), and <c>acquiredTokens</c> is a per-leg <see cref="List{T}"/> of tokens rather than one
    /// disposable value; the <see langword="finally"/> below disposes both on every exit path, including a
    /// throw from any leg's own Time-Stamping Authority round trip.
    /// </para>
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "container is wrapped into a new CBAdESArchiveTimestamp, then a new " +
            "CBAdESUnsignedHeaderElementArchiveTimestamp (`element`), which becomes finalUnsignedHeaders via " +
            "Append/the array constructor; finalUnsignedHeaders is disposed in the finally below through " +
            "DisposeAugmentationArtifacts once `transferred` is true, cascading over every element it reaches, " +
            "including this one. Roslyn tracks the locally-constructed container/element themselves, not the " +
            "fact that they are reachable through finalUnsignedHeaders three constructor calls later -- and in " +
            "any case AdESTimestampContainer.Dispose is currently a no-op (see that type's own remarks), so " +
            "there is nothing to leak regardless of which container in the chain a caller happens to dispose.")]
    public static async ValueTask<EncodedCoseSign1> AddArchiveTimestampAsync(
        CBAdESArchiveTimestampContext context,
        ParseCBAdESSign1Delegate parse,
        SerializeCBAdESSign1Delegate serialize,
        TrySpliceCBAdESUnprotectedHeaderDelegate spliceUnprotectedHeader,
        TryBuildArchiveTimestampGenerationMessageImprintInputDelegate buildImprintInput,
        BaseMemoryPool pool,
        ParseCounterSignatureHeaderValueDelegate? parseCounterSignatureHeaderValue = null,
        CBAdESIsCounterSignatureMaterialCompleteDelegate? isCounterSignatureMaterialComplete = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(context.SigningCertificate);
        ArgumentNullException.ThrowIfNull(context.TsaLegs);
        ArgumentNullException.ThrowIfNull(parse);
        ArgumentNullException.ThrowIfNull(serialize);
        ArgumentNullException.ThrowIfNull(spliceUnprotectedHeader);
        ArgumentNullException.ThrowIfNull(buildImprintInput);
        ArgumentNullException.ThrowIfNull(pool);
        if(context.TsaLegs.Count == 0)
        {
            throw new ArgumentException(
                "Additional requirement (j) grounds arcTst's own token plurality on one or more configured " +
                "Time-Stamping Authorities; supply at least one leg (ETSI TS 119 152-1 V1.1.1, clause 6.3, " +
                "additional requirement (j)).",
                nameof(context));
        }

        CBAdESSign1ParseResult parseResult = ParseOrThrow(parse, context.WireBytes, pool);

        //Write-strict: a new arcTst instance is generated only when the declared level is B-LTA -- arcTst
        //is the should-not "*" shape below it (Table 14, CB-6.3-29). Checked before any digest computation,
        //gap-fill incorporation, or Time-Stamping Authority round trip, mirroring AddSignatureTimestampAsync's
        //own target-level gate.
        if(context.TargetLevel != AdESBaselineLevel.BLTA)
        {
            parseResult.Dispose();
            throw new CBAdESAugmentationException(
                CBAdESAugmentationFailureKind.ArchiveTimestampNotPermittedAtTargetLevel,
                "A new arcTst instance is generated only when the declared TargetLevel is B-LTA (ETSI TS 119 " +
                "152-1 V1.1.1, clause 6.3, Table 14, CB-6.3-29).");
        }

        //Signing-certificate readability: checked before any
        //digest computation or Time-Stamping Authority round trip. arcTst has no requirement-(d)-shaped genTime
        //comparison of its own, so the validity window this returns is read for readability alone and
        //otherwise unused.
        _ = ReadSigningCertificateValidityOrThrow(parseResult, context.SigningCertificate, enforce: true);

        EncodedCoseSign1? gapFillStagedWireBytes = null;
        if(context.GapFillValidationMaterial is { IsEmpty: false } gapFillMaterial)
        {
            //parseResult (and everything it owns) is fully accounted for inside StageGapFillValidationData's
            //own finally, regardless of outcome -- it must never be touched again past this call.
            gapFillStagedWireBytes = StageGapFillValidationData(parseResult, gapFillMaterial, spliceUnprotectedHeader, serialize, pool);
        }

        CBAdESSign1ParseResult activeParseResult;
        if(gapFillStagedWireBytes is not null)
        {
            using(gapFillStagedWireBytes)
            {
                activeParseResult = ParseOrThrow(parse, gapFillStagedWireBytes.AsReadOnlyMemory(), pool);
            }
        }
        else
        {
            activeParseResult = parseResult;
        }

        CBAdESUnsignedHeaders? finalUnsignedHeaders = null;
        bool transferred = false;
        PooledMemory? payloadRented = null;
        var acquiredTokens = new List<AcquiredTimestampToken>(context.TsaLegs.Count);
        try
        {
            //The caller attestation half of additional requirement (k) -- a cheap, synchronous gate run
            //ahead of the async per-token structural check below, still before any Time-Stamping Authority
            //round trip.
            if(!context.ChainCompletenessAttested)
            {
                throw new CBAdESAugmentationException(
                    CBAdESAugmentationFailureKind.ArchiveTimestampValidationMaterialIncomplete,
                    "Additional requirement (k) requires all the validation material required for validating " +
                    "the CB-AdES signature to be included before generating a new arcTst; this call cannot " +
                    "itself build or verify a certificate chain, so the caller must attest that completeness " +
                    "beyond this call's own structural per-token check is satisfied elsewhere (ETSI TS 119 " +
                    "152-1 V1.1.1, clause 6.3, additional requirement (k); set ChainCompletenessAttested = " +
                    "true once confirmed).");
            }

            //Table 14's B-LTA ladder prerequisite (CB-6.3-21) -- at least one sigTst instance must
            //already be incorporated before a new arcTst is minted, checked structurally here, before any
            //Time-Stamping Authority round trip, so a doomed call never bills one. This also keeps uHeaders
            //non-absent by the time the first arcTst's message imprint is built, making the
            //absent-uHeaders generation/validation asymmetry unreachable through this verb.
            if(!HasSignatureTimestampInstance(activeParseResult.UnsignedHeaders))
            {
                throw new CBAdESAugmentationException(
                    CBAdESAugmentationFailureKind.ArchiveTimestampSignatureTimestampPrerequisiteMissing,
                    "A new arcTst instance is generated only once the signature already carries at least one " +
                    "sigTst instance (ETSI TS 119 152-1 V1.1.1, clause 6.3, Table 14, CB-6.3-21).");
            }

            //CB-5.3.5.1-02: "If the CB-AdES signature incorporates a counter signature
            //element, all required material for validating the counter signature shall be incorporated before
            //generating the first arcTst CBOR map." Existence half mirrors HasSignatureTimestampInstance's own
            //shape immediately above -- a cheap, synchronous pattern match needing no decode delegate at all.
            //The material-completeness half only runs when a counter-signature element is actually present,
            //and asks the CALLER to confirm completeness (parseCounterSignatureHeaderValue decodes; ISN'T told
            //HOW to resolve completeness -- isCounterSignatureMaterialComplete is, mirroring
            //CBAdESResolveCounterSignaturePublicKeyDelegate's own certificate-path-neutral posture at
            //CBAdESSignatureValidation): this call never itself builds or verifies a certificate chain. Checked
            //before any Time-Stamping Authority round trip -- a doomed call never bills one.
            if(HasCounterSignatureElement(activeParseResult.UnsignedHeaders))
            {
                EnsureCounterSignatureMaterialComplete(
                    activeParseResult.UnsignedHeaders, parseCounterSignatureHeaderValue, isCounterSignatureMaterialComplete, pool);
            }

            //Additional requirement (k)'s structural precheck, over the (possibly gap-filled)
            //state -- still before any Time-Stamping Authority round trip. Every token opened here is the same
            //choke point HasEmbeddedCertificates is observable through, so its OR-reduction doubles as the
            //CB-6.3-26 service fact the final EnsureConformant call below needs -- no second, redundant
            //token-opening pass.
            IReadOnlyList<AdESPkiObject> validationDataCertificates =
                CBAdESLevelRules.CollectValidationDataCertificateCandidates(activeParseResult.UnsignedHeaders);

            bool anyEmbeddedValidationMaterial = await EnsureArchiveTimestampValidationMaterialCompleteAsync(
                activeParseResult, validationDataCertificates, pool, cancellationToken).ConfigureAwait(false);

            //The SAME async refs-resolution check AddValidationDataAsync already runs (CB-A.1.1-30),
            //over this call's own (possibly gap-filled) state -- pre-append, before the new
            //arcTst element is ever built or the wire bytes re-encoded, and before any Time-Stamping Authority
            //round trip -- so this producer never mints a signature the validator's own widened CB-A.1.1-30
            //trigger/candidate set would reject.
            await CBAdESLevelRules.EnsureReferencesResolveToValidationDataAsync(
                activeParseResult.UnsignedHeaders, pool, cancellationToken).ConfigureAwait(false);

            //Table 14 hard-forbids the refs/sigRTst/rfsTst family from B-LT onward
            //(CB-6.3-23/-24/-25); the TargetLevel gate at the top of this call already fixes the declared level
            //at B-LTA, so ANY such element still incorporated at this point is forbidden outright -- the
            //B-LT-upgrade choreography (StripReferencesForLongTerm) must have already run. Checked AFTER the
            //CB-A.1.1-30 resolution check immediately above, never before it: an unresolvable refs entry must
            //still surface its own, more specific CB-A.1.1-30 failure first; only a RESOLVABLE refs entry (or
            //no refs/valData/arcTst disjunction at all) reaches this refusal -- both gates independently
            //provable. Checked before any Time-Stamping Authority round trip, rather than deferred to
            //CBAdESLevelRules.EnsureConformant's own post-mint evaluation of the same rule -- a doomed call
            //never bills one.
            if(HasReferencesFamilyElement(activeParseResult.UnsignedHeaders))
            {
                throw new CBAdESAugmentationException(
                    CBAdESAugmentationFailureKind.ArchiveTimestampReferencesFamilyElementPresent,
                    "A new arcTst instance is generated only once the refs/sigRTst/rfsTst family has been " +
                    "removed via StripReferencesForLongTerm; Table 14 hard-forbids that family from B-LT " +
                    "onward (ETSI TS 119 152-1 V1.1.1, clause 6.3, CB-6.3-23/-24/-25).");
            }

            //Steps 2-5.
            (bool payloadResolved, payloadRented, CBAdESPayloadTimestampImprintSource? payloadSource, string? payloadFailureReason) =
                await CBAdESSignatureValidation.ResolvePayloadTimestampImprintSourceAsync(
                    activeParseResult.ProtectedHeaders!,
                    !activeParseResult.PayloadIsPresent,
                    activeParseResult.Payload,
                    context.Dereference,
                    context.DereferenceContext,
                    context.ExternalDetachedPayload,
                    context.UnknownMechanismHandler,
                    CBAdESTimestampTokenBindingKind.ArchiveTimestamp,
                    pool,
                    cancellationToken).ConfigureAwait(false);

            if(!payloadResolved || payloadSource is null)
            {
                throw new CBAdESAugmentationException(
                    CBAdESAugmentationFailureKind.MessageImprintInputMalformed,
                    payloadFailureReason ?? "The arcTst message-imprint input's payload contribution (clause " +
                        "5.3.5.3 steps 6/7) could not be resolved.");
            }

            bool built = buildImprintInput(
                CBAdESImprintCoseSign1StructureContext.Instance,
                activeParseResult.RawProtectedHeader!.AsReadOnlyMemory(),
                signerProtectedHeader: null,
                context.ExternallySuppliedData,
                payloadSource,
                countersignatureOtherFields: null,
                activeParseResult.Signature!.AsReadOnlyMemory(),
                activeParseResult.RawUnsignedHeaders?.AsReadOnlyMemory(),
                pool,
                out PooledMemory? imprintInput);

            if(!built || imprintInput is null)
            {
                throw new CBAdESAugmentationException(
                    CBAdESAugmentationFailureKind.MessageImprintInputMalformed,
                    "The arcTst message-imprint input could not be built from this signature's own uHeaders " +
                    "(ETSI TS 119 152-1 V1.1.1, clause 5.3.5.3).");
            }

            PkiDigestAlgorithm algorithm = context.MessageImprintAlgorithm;
            DigestValue imprint;
            using(imprintInput)
            {
                imprint = await CryptographicKeyEvents.ComputeDigestAsync(
                    imprintInput.AsReadOnlyMemory(), algorithm.OutputByteLength, algorithm.DigestTag, pool, cancellationToken: cancellationToken).ConfigureAwait(false);
            }

            var tokens = new List<AdESTimestampToken>(context.TsaLegs.Count);
            using(imprint)
            {
                for(int legIndex = 0; legIndex < context.TsaLegs.Count; ++legIndex)
                {
                    CBAdESArchiveTimestampTsaLeg leg = context.TsaLegs[legIndex];
                    AcquiredTimestampToken acquired = await TimestampAcquisition.AcquireAsync(
                        imprint, leg.TsaUri, leg.FetchResponse, pool,
                        leg.ReqPolicyOid, leg.NonceByteLength, leg.IncludeNonce, cancellationToken).ConfigureAwait(false);

                    acquiredTokens.Add(acquired);
                    tokens.Add(new AdESTimestampToken { Val = acquired.Token.AsReadOnlyMemory() });
                }
            }

            //Letter (j): every acquired token, one per configured leg, is encapsulated in the SAME new arcTst
            //instance -- never narrowed to one token the way CB-6.3-c narrows sigTst.
            var container = new AdESTimestampContainer(tokens);
            var element = new CBAdESUnsignedHeaderElementArchiveTimestamp(new CBAdESArchiveTimestamp(container));

            finalUnsignedHeaders = activeParseResult.UnsignedHeaders is null
                ? new CBAdESUnsignedHeaders([element])
                : activeParseResult.UnsignedHeaders.Append(element);
            transferred = true;

            CBAdESLevelRules.EnsureConformant(new CBAdESLevelRuleContext
            {
                Level = context.TargetLevel,
                UnsignedHeaders = finalUnsignedHeaders,
                AnyTimestampTokenCarriesEmbeddedValidationMaterial = anyEmbeddedValidationMaterial,
                PayloadTimestamps = activeParseResult.ProtectedHeaders!.PayloadTimestamps
            });

            return EncodeAndSerialize(activeParseResult, skipDecodedIndexes: null, newElement: element, spliceUnprotectedHeader, serialize, pool);
        }
        finally
        {
            foreach(AcquiredTimestampToken acquired in acquiredTokens)
            {
                acquired.Dispose();
            }

            payloadRented?.Dispose();
            DisposeAugmentationArtifacts(activeParseResult, finalUnsignedHeaders, transferred);
        }

        /// <summary>
        /// Determines whether <paramref name="unsignedHeaders"/> carries at least one <c>sigTst</c> instance —
        /// Table 14's B-LTA ladder prerequisite (CB-6.3-21), checked structurally here rather than deferred to
        /// <see cref="CBAdESLevelRules.EnsureConformant"/>'s own post-mint evaluation of the same rule.
        /// </summary>
        /// <param name="unsignedHeaders">The decoded <c>uHeaders</c> set, or <see langword="null"/> when absent.</param>
        /// <returns><see langword="true"/> when at least one <c>sigTst</c> element is present.</returns>
        static bool HasSignatureTimestampInstance(CBAdESUnsignedHeaders? unsignedHeaders)
        {
            if(unsignedHeaders is null)
            {
                return false;
            }

            for(int i = 0; i < unsignedHeaders.Count; ++i)
            {
                if(unsignedHeaders[i] is CBAdESUnsignedHeaderElementSignatureTimestamp)
                {
                    return true;
                }
            }

            return false;
        }


        /// <summary>
        /// Determines whether <paramref name="unsignedHeaders"/> carries at least one <c>uHeaders</c>
        /// counter-signature element (label 11 or 12) — CB-5.3.5.1-02's existence half,
        /// mirroring <see cref="HasSignatureTimestampInstance"/>'s own shape.
        /// </summary>
        /// <param name="unsignedHeaders">The decoded <c>uHeaders</c> set, or <see langword="null"/> when absent.</param>
        /// <returns><see langword="true"/> when at least one counter-signature element is present.</returns>
        static bool HasCounterSignatureElement(CBAdESUnsignedHeaders? unsignedHeaders)
        {
            if(unsignedHeaders is null)
            {
                return false;
            }

            for(int i = 0; i < unsignedHeaders.Count; ++i)
            {
                if(unsignedHeaders[i] is CBAdESUnsignedHeaderElementFullCounterSignature or CBAdESUnsignedHeaderElementAbbreviatedCounterSignature)
                {
                    return true;
                }
            }

            return false;
        }


        /// <summary>
        /// CB-5.3.5.1-02's material-completeness half: every <c>uHeaders</c>
        /// counter-signature element already incorporated must decode, and the caller must confirm its
        /// signer material is already incorporated, before this call proceeds. Fail-closed — refuses whenever
        /// completeness cannot be CONFIRMED, never only when it is disproven, since an unconfirmable state is
        /// exactly what the requirement forbids reaching a new <c>arcTst</c> with.
        /// </summary>
        /// <param name="unsignedHeaders">The decoded <c>uHeaders</c> set (non-null; the caller already confirmed at least one element via <see cref="HasCounterSignatureElement"/>).</param>
        /// <param name="parseCounterSignatureHeaderValue">
        /// Decodes a counter-signature element's raw value bytes, or <see langword="null"/> to refuse outright
        /// — with no decode delegate this call cannot confirm the element is even well-formed, let alone that
        /// its material is complete.
        /// </param>
        /// <param name="isCounterSignatureMaterialComplete">
        /// The caller-supplied completeness resolver, or <see langword="null"/> to refuse outright — this call
        /// never itself builds or verifies a certificate chain (mirroring
        /// <see cref="CBAdESResolveCounterSignaturePublicKeyDelegate"/>'s own certificate-path-neutral posture
        /// at <see cref="CBAdESSignatureValidation"/>). Countersignature0V2's abbreviated form carries no
        /// protected headers of its own (RFC 9338 §3.2), so a resolver has structurally less to decode for
        /// that arm than for a full <see cref="CounterSignatureV2"/> — an honest depth difference, not a gap
        /// this call papers over.
        /// </param>
        /// <param name="pool">Memory pool the decode buffers rent from.</param>
        /// <exception cref="CBAdESAugmentationException">
        /// <see cref="CBAdESAugmentationFailureKind.ArchiveTimestampCounterSignatureMaterialIncomplete"/> when
        /// either delegate is <see langword="null"/>, an element fails to decode, or the resolver reports
        /// incompleteness for any element.
        /// </exception>
        static void EnsureCounterSignatureMaterialComplete(
            CBAdESUnsignedHeaders? unsignedHeaders,
            ParseCounterSignatureHeaderValueDelegate? parseCounterSignatureHeaderValue,
            CBAdESIsCounterSignatureMaterialCompleteDelegate? isCounterSignatureMaterialComplete,
            BaseMemoryPool pool)
        {
            if(parseCounterSignatureHeaderValue is null || isCounterSignatureMaterialComplete is null)
            {
                throw new CBAdESAugmentationException(
                    CBAdESAugmentationFailureKind.ArchiveTimestampCounterSignatureMaterialIncomplete,
                    "The signature incorporates a counter-signature element (uHeaders label 11 or 12), so " +
                    "CB-5.3.5.1-02 requires its validation material to be confirmed complete before generating " +
                    "a new arcTst; this call cannot confirm that without both a counter-signature decode " +
                    "delegate and a material-completeness resolver (ETSI TS 119 152-1 V1.1.1, clause 5.3.5.1, " +
                    "CB-5.3.5.1-02; fail-closed).");
            }

            for(int i = 0; i < unsignedHeaders!.Count; ++i)
            {
                (int label, ReadOnlyMemory<byte> valueBytes) = unsignedHeaders[i] switch
                {
                    CBAdESUnsignedHeaderElementFullCounterSignature full => (CoseHeaderParameters.CounterSignatureVersion2, full.Value),
                    CBAdESUnsignedHeaderElementAbbreviatedCounterSignature abbreviated => (CoseHeaderParameters.Countersignature0Version2, abbreviated.Value),
                    _ => (0, ReadOnlyMemory<byte>.Empty)
                };

                if(label == 0)
                {
                    continue;
                }

                using CoseCounterSignatureParseResult parseResult = parseCounterSignatureHeaderValue(label, valueBytes, pool);
                if(!parseResult.IsSuccess || parseResult.CounterSignature is null)
                {
                    throw new CBAdESAugmentationException(
                        CBAdESAugmentationFailureKind.ArchiveTimestampCounterSignatureMaterialIncomplete,
                        $"The counter-signature element at uHeaders position {i} does not decode into a " +
                        "well-formed RFC 9338 version 2 countersignature, so CB-5.3.5.1-02's material-" +
                        "completeness requirement cannot be confirmed for it (ETSI TS 119 152-1 V1.1.1, clause " +
                        "5.3.5.1, CB-5.3.5.1-02; fail-closed).");
                }

                if(!isCounterSignatureMaterialComplete(parseResult.CounterSignature))
                {
                    throw new CBAdESAugmentationException(
                        CBAdESAugmentationFailureKind.ArchiveTimestampCounterSignatureMaterialIncomplete,
                        $"The counter-signature element at uHeaders position {i} does not have all required " +
                        "validation material incorporated into the signature (ETSI TS 119 152-1 V1.1.1, clause " +
                        "5.3.5.1, CB-5.3.5.1-02).");
                }
            }
        }
    }


    /// <summary>
    /// The shared core behind <see cref="AddSignatureAndReferencesTimestampAsync"/> and
    /// <see cref="AddReferencesTimestampAsync"/> — acquires the token over an already-built imprint input and
    /// appends the resulting <c>sigRTst</c>/<c>rfsTst</c> element. <paramref name="kind"/> is plain data (not a
    /// captured delegate), so the two callers' distinct imprint-input signatures never need a closure to unify
    /// here (no closure capture, per this library's own convention).
    /// </summary>
    /// <param name="context">The signature, the authority to contact, and the target level.</param>
    /// <param name="parseResult">The already-successful parse of <paramref name="context"/>'s wire bytes. Ownership transfers to this call.</param>
    /// <param name="imprintInput">The already-built message-imprint input. Ownership transfers to this call.</param>
    /// <param name="kind">Which of the two sibling elements to build.</param>
    /// <param name="spliceUnprotectedHeader">The <c>uHeaders</c> unprotected-header raw-splice seam.</param>
    /// <param name="serialize">The CBOR re-serialization seam.</param>
    /// <param name="pool">The memory pool every carrier is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The augmented signature's new wire bytes. The caller owns and disposes it.</returns>
    /// <remarks>
    /// <strong>Manual disposal, not a <see langword="using"/> declaration.</strong> <c>token</c> is declared
    /// <see langword="null"/> ahead of the try body and assigned only after the digest is computed inside it
    /// (a <see langword="using"/> declaration accepts only a single assignment at its own declaration); the
    /// <see langword="finally"/> below disposes it on every exit path.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "container is wrapped into whichever sibling wrapper `kind` selects (a new " +
            "CBAdESSignatureAndReferencesTimestamp or CBAdESReferencesTimestamp), then into the matching " +
            "CBAdESUnsignedHeaderElement* (`element`), which becomes finalUnsignedHeaders via Append/the array " +
            "constructor; finalUnsignedHeaders is disposed in the finally below through " +
            "DisposeAugmentationArtifacts once `transferred` is true, cascading over every element it reaches. " +
            "Roslyn tracks the locally-constructed container/wrapper/element themselves, not the fact that they " +
            "are reachable through finalUnsignedHeaders several constructor calls later -- and in any case " +
            "AdESTimestampContainer.Dispose is currently a no-op (see that type's own remarks), so there is " +
            "nothing to leak regardless of which container in the chain a caller happens to dispose.")]
    private static async ValueTask<EncodedCoseSign1> AppendReferencesFamilyTimestampAsync(
        CBAdESReferencesFamilyTimestampContext context,
        CBAdESSign1ParseResult parseResult,
        PooledMemory imprintInput,
        CBAdESReferencesFamilyTimestampKind kind,
        TrySpliceCBAdESUnprotectedHeaderDelegate spliceUnprotectedHeader,
        SerializeCBAdESSign1Delegate serialize,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        CBAdESUnsignedHeaders? finalUnsignedHeaders = null;
        bool transferred = false;
        AcquiredTimestampToken? token = null;
        try
        {
            PkiDigestAlgorithm algorithm = context.MessageImprintAlgorithm;
            DigestValue imprint;
            using(imprintInput)
            {
                imprint = await CryptographicKeyEvents.ComputeDigestAsync(
                    imprintInput.AsReadOnlyMemory(), algorithm.OutputByteLength, algorithm.DigestTag, pool, cancellationToken: cancellationToken).ConfigureAwait(false);
            }

            using(imprint)
            {
                token = await TimestampAcquisition.AcquireAsync(
                    imprint, context.TsaUri, context.FetchResponse, pool,
                    context.ReqPolicyOid, context.NonceByteLength, context.IncludeNonce, cancellationToken).ConfigureAwait(false);
            }

            var container = new AdESTimestampContainer([new AdESTimestampToken { Val = token.Token.AsReadOnlyMemory() }]);

            CBAdESUnsignedHeaderElement element = kind switch
            {
                CBAdESReferencesFamilyTimestampKind.SignatureAndReferences =>
                    new CBAdESUnsignedHeaderElementSignatureAndReferencesTimestamp(new CBAdESSignatureAndReferencesTimestamp(container)),
                CBAdESReferencesFamilyTimestampKind.ReferencesOnly =>
                    new CBAdESUnsignedHeaderElementReferencesTimestamp(new CBAdESReferencesTimestamp(container)),
                _ => throw new NotSupportedException($"Unknown {nameof(CBAdESReferencesFamilyTimestampKind)} value '{kind}'.")
            };

            finalUnsignedHeaders = parseResult.UnsignedHeaders is null
                ? new CBAdESUnsignedHeaders([element])
                : parseResult.UnsignedHeaders.Append(element);
            transferred = true;

            CBAdESLevelRules.EnsureConformant(new CBAdESLevelRuleContext
            {
                Level = context.TargetLevel,
                UnsignedHeaders = finalUnsignedHeaders,
                PayloadTimestamps = parseResult.ProtectedHeaders!.PayloadTimestamps
            });

            return EncodeAndSerialize(parseResult, skipDecodedIndexes: null, newElement: element, spliceUnprotectedHeader, serialize, pool);
        }
        finally
        {
            token?.Dispose();
            DisposeAugmentationArtifacts(parseResult, finalUnsignedHeaders, transferred);
        }
    }


    /// <summary>Which sibling element <see cref="AppendReferencesFamilyTimestampAsync"/> builds.</summary>
    private enum CBAdESReferencesFamilyTimestampKind
    {
        /// <summary>Builds a <c>sigRTst</c> element (Annex A.1.2.1).</summary>
        SignatureAndReferences,

        /// <summary>Builds an <c>rfsTst</c> element (Annex A.1.2.2).</summary>
        ReferencesOnly
    }


    /// <summary>
    /// Parses <paramref name="wireBytes"/> through <paramref name="parse"/> and refuses a structurally
    /// unsuccessful result. A malformed input signature is a CALLER composition fault for an augmentation call
    /// (the caller is supposed to be handing in a signature it already produced or already validated), never
    /// untrusted content to collect violations over — mirroring every catch-and-rethrow site in
    /// <see cref="Verifiable.Cryptography.Pki.CAdESSignatureAugmentation"/>.
    /// </summary>
    /// <param name="parse">The fail-closed CBOR parse seam.</param>
    /// <param name="wireBytes">The candidate CB-AdES <c>COSE_Sign1</c> wire bytes.</param>
    /// <param name="pool">The memory pool the parse result's carriers are rented from.</param>
    /// <returns>The successful parse result. The caller owns and disposes it.</returns>
    /// <exception cref="CBAdESAugmentationException">When the parse is unsuccessful or incomplete.</exception>
    private static CBAdESSign1ParseResult ParseOrThrow(ParseCBAdESSign1Delegate parse, ReadOnlyMemory<byte> wireBytes, BaseMemoryPool pool)
    {
        CBAdESSign1ParseResult result = parse(wireBytes, pool);
        if(!result.IsSuccess || result.ProtectedHeaders is null || result.RawProtectedHeader is null || result.Signature is null)
        {
            result.Dispose();
            throw new CBAdESAugmentationException(
                CBAdESAugmentationFailureKind.MalformedEncoding,
                "The CB-AdES signature being augmented could not be parsed as a well-formed COSE_Sign1 (ETSI TS 119 152-1 V1.1.1).");
        }

        return result;
    }


    /// <summary>
    /// Splices <paramref name="parseResult"/>'s raw, retained <c>uHeaders</c> elements together with
    /// <paramref name="newElement"/> (see <see cref="TrySpliceCBAdESUnprotectedHeaderDelegate"/>) into the
    /// unprotected-header dictionary and re-serializes the whole message around <paramref name="parseResult"/>'s
    /// ORIGINAL protected header, payload, and signature carriers — the byte-preserving splice every
    /// augmentation verb performs.
    /// </summary>
    /// <param name="parseResult">The parsed signature being augmented. Not disposed here; the caller's own <c>finally</c> owns that.</param>
    /// <param name="skipDecodedIndexes">The decoded-model indexes whose raw <c>uHeaders</c> entry is dropped (the strip verb's refs-family elements), or <see langword="null"/>/empty to retain every element.</param>
    /// <param name="newElement">The freshly-built element to append last, or <see langword="null"/> to append nothing new.</param>
    /// <param name="spliceUnprotectedHeader">The <c>uHeaders</c> unprotected-header raw-splice seam.</param>
    /// <param name="serialize">The CBOR re-serialization seam.</param>
    /// <param name="pool">The memory pool the splice/serialize steps rent from.</param>
    /// <returns>The augmented signature's new wire bytes. The caller owns and disposes it.</returns>
    /// <exception cref="CBAdESAugmentationException">
    /// When <paramref name="spliceUnprotectedHeader"/> reports an internal inconsistency between the parse step
    /// and the splice (<see cref="CBAdESAugmentationFailureKind.RawUnsignedHeadersSpliceMalformed"/>).
    /// </exception>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "message shares parseResult's own RawProtectedHeader/Payload/Signature carriers " +
            "verbatim -- it borrows them to hand serialize a read-only view, matching Cose.VerifyAsync's own " +
            "relationship to a CoseSign1Message it did not construct ownership of -- rather than allocating new " +
            "disposables of its own. parseResult remains the sole owner of every one of those carriers, disposed " +
            "in the calling verb's own finally via DisposeAugmentationArtifacts; message.Dispose() is never " +
            "called here, since that would double-dispose the same carriers. Roslyn tracks the locally- " +
            "constructed CoseSign1Message itself, not the fact that its constituent IDisposable members are " +
            "owned and disposed one level up.")]
    private static EncodedCoseSign1 EncodeAndSerialize(
        CBAdESSign1ParseResult parseResult,
        IReadOnlySet<int>? skipDecodedIndexes,
        CBAdESUnsignedHeaderElement? newElement,
        TrySpliceCBAdESUnprotectedHeaderDelegate spliceUnprotectedHeader,
        SerializeCBAdESSign1Delegate serialize,
        BaseMemoryPool pool)
    {
        int decodedElementCount = parseResult.UnsignedHeaders?.Count ?? 0;
        if(!spliceUnprotectedHeader(
            parseResult.RawUnsignedHeaders, decodedElementCount, skipDecodedIndexes, newElement, pool, out IReadOnlyDictionary<int, object>? unprotectedHeader))
        {
            throw new CBAdESAugmentationException(
                CBAdESAugmentationFailureKind.RawUnsignedHeadersSpliceMalformed,
                "The raw uHeaders splice reported an internal inconsistency between the parse step and this " +
                "signature's own already-successfully-parsed uHeaders bytes (ETSI TS 119 152-1 V1.1.1, clause " +
                "5.3.1).");
        }

        var message = new CoseSign1Message(parseResult.RawProtectedHeader!, unprotectedHeader, parseResult.Payload, parseResult.Signature!);

        //serialize reads message's carriers to produce brand-new, independently-copied wire bytes; it neither
        //takes ownership of `message` nor of the RawProtectedHeader/Signature carriers it borrows from
        //parseResult, matching Cose.VerifyAsync's own read-only relationship to a CoseSign1Message it did not
        //construct ownership of -- message.Dispose() is therefore never called (it would double-dispose the
        //same carriers parseResult's own finally-block Dispose already owns).
        return serialize(message, !parseResult.PayloadIsPresent, pool);
    }


    /// <summary>
    /// Disposes every carrier <paramref name="parseResult"/> owns that has not already been accounted for
    /// elsewhere, plus <paramref name="finalUnsignedHeaders"/> itself.
    /// </summary>
    /// <param name="parseResult">The parsed signature being augmented.</param>
    /// <param name="finalUnsignedHeaders">
    /// The complete, post-operation <c>uHeaders</c> set built by the caller, or <see langword="null"/> when
    /// none was built (either because <paramref name="unsignedHeaderElementsTransferred"/> is
    /// <see langword="false"/> — nothing was built at all — or because a rebuild legitimately produced no
    /// elements, e.g. <see cref="StripReferencesForLongTerm"/> stripping away everything that existed).
    /// </param>
    /// <param name="unsignedHeaderElementsTransferred">
    /// <see langword="true"/> once every element <paramref name="parseResult"/>.<see cref="CBAdESSign1ParseResult.UnsignedHeaders"/>
    /// held has been accounted for — either because it is reachable through <paramref name="finalUnsignedHeaders"/>
    /// (disposed here, cascading over it), or because it was dropped and disposed individually by the caller
    /// already (<see cref="StripReferencesForLongTerm"/>'s refs-family elements). While <see langword="false"/>
    /// (a failure before or while building the new state), <paramref name="parseResult"/>'s ORIGINAL
    /// <see cref="CBAdESSign1ParseResult.UnsignedHeaders"/> is disposed here instead, since nothing else owns
    /// it yet. See the class remarks for why <see cref="CBAdESSign1ParseResult.UnsignedHeaders"/> is NEVER
    /// disposed when this flag is <see langword="true"/> — every one of its elements is either shared with
    /// <paramref name="finalUnsignedHeaders"/> (would double-dispose) or already gone.
    /// </param>
    private static void DisposeAugmentationArtifacts(
        CBAdESSign1ParseResult parseResult, CBAdESUnsignedHeaders? finalUnsignedHeaders, bool unsignedHeaderElementsTransferred)
    {
        finalUnsignedHeaders?.Dispose();
        if(!unsignedHeaderElementsTransferred)
        {
            parseResult.UnsignedHeaders?.Dispose();
        }

        parseResult.ProtectedHeaders?.Dispose();
        parseResult.RawProtectedHeader?.Dispose();
        parseResult.Signature?.Dispose();
        parseResult.RawUnsignedHeaders?.Dispose();
    }


    /// <summary>
    /// Stages clause 5.3.5.2 step 1 for <see cref="AddArchiveTimestampAsync"/>: builds a new <c>valData</c>
    /// element from <paramref name="gapFillMaterial"/> through the SAME building blocks
    /// <see cref="AddValidationDataAsync"/> uses (<see cref="BuildValidationDataMembers"/>), appends it, and
    /// re-serializes — producing brand-new, self-contained wire bytes the caller re-parses to obtain a working
    /// state whose OWN raw <c>uHeaders</c> wire bytes genuinely include this new element. This never re-encodes
    /// the RETAINED elements from their decoded model (a lossy-reencode defect this whole file avoids);
    /// the byte-verbatim splice seam copies them across unchanged, and only the new element is freshly encoded.
    /// </summary>
    /// <param name="parseResult">
    /// The already-successful parse being staged. Fully disposed here, in every case (success or exception) —
    /// the caller must never touch it again once this call returns or throws.
    /// </param>
    /// <param name="gapFillMaterial">The validation material to place; must not be empty.</param>
    /// <param name="spliceUnprotectedHeader">The <c>uHeaders</c> unprotected-header raw-splice seam.</param>
    /// <param name="serialize">The CBOR re-serialization seam.</param>
    /// <param name="pool">The memory pool every carrier is rented from.</param>
    /// <returns>
    /// The staged wire bytes, carrying the new <c>valData</c> element as the last entry of their own
    /// <c>uHeaders</c> array. The caller owns and disposes it.
    /// </returns>
    /// <exception cref="CBAdESAugmentationException">
    /// When a candidate is not of the kind <c>valData</c> admits, or the raw-splice seam reports an internal
    /// inconsistency.
    /// </exception>
    private static EncodedCoseSign1 StageGapFillValidationData(
        CBAdESSign1ParseResult parseResult,
        CBAdESValidationMaterial gapFillMaterial,
        TrySpliceCBAdESUnprotectedHeaderDelegate spliceUnprotectedHeader,
        SerializeCBAdESSign1Delegate serialize,
        BaseMemoryPool pool)
    {
        CBAdESUnsignedHeaders? finalUnsignedHeaders = null;
        bool transferred = false;
        try
        {
            (List<CBAdESX509OrOtherCertificate>? certificateValues, CBAdESRevocationValues? revocationValues) =
                BuildValidationDataMembers(gapFillMaterial, parseResult.UnsignedHeaders, dedupe: true);

            CBAdESUnsignedHeaderElement? newElement = null;
            if(certificateValues is null && revocationValues is null)
            {
                //Every candidate already byte-equals material an earlier valData element carries (requirements
                //(e)/(f) dedup) -- nothing new to gap-fill; the signature stands as it was, matching
                //AddValidationDataAsync's own identical branch.
                finalUnsignedHeaders = parseResult.UnsignedHeaders;
            }
            else
            {
                newElement = new CBAdESUnsignedHeaderElementValidationData(new CBAdESValidationData(certificateValues, revocationValues));
                finalUnsignedHeaders = parseResult.UnsignedHeaders is null
                    ? new CBAdESUnsignedHeaders([newElement])
                    : parseResult.UnsignedHeaders.Append(newElement);
            }

            transferred = true;

            return EncodeAndSerialize(parseResult, skipDecodedIndexes: null, newElement, spliceUnprotectedHeader, serialize, pool);
        }
        finally
        {
            DisposeAugmentationArtifacts(parseResult, finalUnsignedHeaders, transferred);
        }
    }


    /// <summary>
    /// Enforces additional requirement (k)'s checkable structural half over
    /// <paramref name="parseResult"/>'s current state, before <see cref="AddArchiveTimestampAsync"/> contacts
    /// any Time-Stamping Authority: opens every electronic time-stamp token already incorporated into the
    /// signature — <c>sigTst</c>/<c>adoTst</c>/<c>sigRTst</c>/<c>rfsTst</c>/any prior <c>arcTst</c> instance,
    /// EVERY token per instance (letter (j) never narrows <c>arcTst</c>'s own per-instance token
    /// count the way letter (c) narrows <c>sigTst</c>'s) — and checks each one's signer certificate is
    /// resolvable (<see cref="CBAdESLevelRules.IsTimestampTokenSignerCertificateResolvedAsync"/>).
    /// </summary>
    /// <param name="parseResult">The signature state to check (possibly gap-filled by <see cref="StageGapFillValidationData"/>).</param>
    /// <param name="validationDataCertificates">The signature's own <c>valData</c> certificate candidates (<see cref="CBAdESLevelRules.CollectValidationDataCertificateCandidates"/>).</param>
    /// <param name="pool">The memory pool the token and digest buffers rent from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>
    /// Whether at least one opened token carries <see cref="TimestampTokenInfo.HasEmbeddedCertificates"/> — the
    /// same fact the validation orchestrator's own OR-reduction produces, reused here so
    /// <see cref="AddArchiveTimestampAsync"/> can satisfy CB-6.3-26's validation-data-for-time-stamps service
    /// check without a second, redundant token-opening pass.
    /// </returns>
    /// <exception cref="CBAdESAugmentationException">
    /// Both arms are <see cref="CBAdESAugmentationFailureKind.ArchiveTimestampValidationMaterialIncomplete"/>,
    /// worded to name which condition actually failed: when a token cannot be read at
    /// all, its material is therefore unverifiable and this call refuses fail-closed, before ever asking
    /// whether a signer certificate resolves (citing CB-6.3-k alone — letter h's disjunction cannot even be
    /// evaluated over unread material); or, distinctly, when a successfully-read token's signer certificate is
    /// not resolvable within <c>valData</c> or embedded in the token itself (citing CB-6.3-k/h).
    /// </exception>
    private static async ValueTask<bool> EnsureArchiveTimestampValidationMaterialCompleteAsync(
        CBAdESSign1ParseResult parseResult,
        IReadOnlyList<AdESPkiObject> validationDataCertificates,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        bool anyEmbedded = false;

        if(parseResult.ProtectedHeaders!.PayloadTimestamps is { } adoTst)
        {
            anyEmbedded |= await EnsureContainerTokensResolvedAsync(
                adoTst.TimestampContainer, validationDataCertificates, pool, cancellationToken).ConfigureAwait(false);
        }

        CBAdESUnsignedHeaders? unsignedHeaders = parseResult.UnsignedHeaders;
        if(unsignedHeaders is not null)
        {
            for(int i = 0; i < unsignedHeaders.Count; ++i)
            {
                AdESTimestampContainer? container = unsignedHeaders[i] switch
                {
                    CBAdESUnsignedHeaderElementSignatureTimestamp sigTst => sigTst.SignatureTimestamp.TimestampContainer,
                    CBAdESUnsignedHeaderElementArchiveTimestamp arcTst => arcTst.ArchiveTimestamp.TimestampContainer,
                    CBAdESUnsignedHeaderElementSignatureAndReferencesTimestamp sigRTst => sigRTst.SignatureAndReferencesTimestamp.TimestampContainer,
                    CBAdESUnsignedHeaderElementReferencesTimestamp rfsTst => rfsTst.ReferencesTimestamp.TimestampContainer,
                    _ => null
                };

                if(container is not null)
                {
                    anyEmbedded |= await EnsureContainerTokensResolvedAsync(
                        container, validationDataCertificates, pool, cancellationToken).ConfigureAwait(false);
                }
            }
        }

        return anyEmbedded;

        /// <summary>
        /// Opens every token of <paramref name="container"/> and throws the first time one is unreadable or its
        /// signer certificate is unresolvable — the two conditions named distinctly,
        /// mirroring <see cref="CBAdESSignatureValidation"/>'s own <c>VerifyOneTimestampTokenAsync</c> split
        /// between an unreadable token (a different rule entirely on that side, CB-6.3-i) and an unresolved
        /// signer (CB-6.3-h) — this throw posture reports both as the SAME
        /// <see cref="CBAdESAugmentationFailureKind.ArchiveTimestampValidationMaterialIncomplete"/> kind, since
        /// there is no separate binding check on the augmentation side to attribute the former to.
        /// </summary>
        /// <param name="container">The <c>tstContainer</c> to check.</param>
        /// <param name="validationDataCertificates">The signature's own <c>valData</c> certificate candidates.</param>
        /// <param name="pool">The memory pool the token and digest buffers rent from.</param>
        /// <param name="cancellationToken">A cancellation token.</param>
        /// <returns>Whether at least one token in <paramref name="container"/> carries <see cref="TimestampTokenInfo.HasEmbeddedCertificates"/>.</returns>
        static async ValueTask<bool> EnsureContainerTokensResolvedAsync(
            AdESTimestampContainer container,
            IReadOnlyList<AdESPkiObject> validationDataCertificates,
            BaseMemoryPool pool,
            CancellationToken cancellationToken)
        {
            bool anyEmbeddedInContainer = false;
            for(int t = 0; t < container.TstTokens.Count; ++t)
            {
                using PkiCertificateMemory tokenMemory = CBAdESSignatureValidation.RentTimestampTokenMemory(container.TstTokens[t].Val, pool);
                using TimestampTokenInfo tokenInfo = await TimestampTokenInfo.ReadFromTokenAsync(tokenMemory, pool, cancellationToken).ConfigureAwait(false);

                if(!tokenInfo.IsRead)
                {
                    throw new CBAdESAugmentationException(
                        CBAdESAugmentationFailureKind.ArchiveTimestampValidationMaterialIncomplete,
                        "Additional requirement (k) cannot confirm the validation material for an electronic " +
                        "time-stamp token already incorporated into the signature is complete: the token " +
                        $"itself could not be read (status: {tokenInfo.Status}), so its signer certificate " +
                        "cannot be verified at all (ETSI TS 119 152-1 V1.1.1, clause 6.3, additional " +
                        "requirement (k); fail-closed).");
                }

                bool signerCertificateResolved = await CBAdESLevelRules.IsTimestampTokenSignerCertificateResolvedAsync(
                    tokenInfo, validationDataCertificates, pool, cancellationToken).ConfigureAwait(false);

                if(!signerCertificateResolved)
                {
                    throw new CBAdESAugmentationException(
                        CBAdESAugmentationFailureKind.ArchiveTimestampValidationMaterialIncomplete,
                        "Additional requirement (k) requires the validation material for validating every " +
                        "electronic time-stamp token already incorporated into the signature to be included " +
                        $"before generating a new arcTst; {DescribeUnresolvedSignerCondition(tokenInfo)} " +
                        "(ETSI TS 119 152-1 V1.1.1, clause 6.3, additional requirements (k)/(h)).");
                }

                anyEmbeddedInContainer |= tokenInfo.HasEmbeddedCertificates;
            }

            return anyEmbeddedInContainer;

            /// <summary>
            /// Names the actual condition <see cref="CBAdESLevelRules.IsTimestampTokenSignerCertificateResolvedAsync"/>
            /// found unresolvable, mirroring <see cref="CBAdESSignatureValidation"/>'s own identically-purposed
            /// classifier so this exception never carries a generic message a
            /// reader cannot act on.
            /// </summary>
            /// <param name="tokenInfo">The token the coverage check ran against.</param>
            /// <returns>A human-readable statement of why the signer certificate did not resolve.</returns>
            static string DescribeUnresolvedSignerCondition(TimestampTokenInfo tokenInfo) => tokenInfo.EmbeddedMaterialStatus switch
            {
                CmsEmbeddedMaterialStatus.Malformed =>
                    "the token's own embedded certificate/CRL material could not be read (status: Malformed), so its signer identity cannot be confirmed",
                _ =>
                    "the token's own signer identity matches neither an embedded certificate nor any valData certificate candidate"
            };
        }
    }


    /// <summary>
    /// Reads the signing certificate's validity window for Table 14 additional requirement (d) BEFORE
    /// <see cref="AddSignatureTimestampAsync"/> contacts a Time-Stamping Authority — a
    /// wrong-kind carrier or an unparseable DER encoding refuses here, rather than after a doomed round trip
    /// has already been billed. Reads through the PUBLIC <see cref="CertificateValidityPeriod.TryRead"/> reader
    /// rather than a platform <c>X509Certificate2</c> read — <c>Verifiable.JCose</c> never
    /// calls the banned <c>System.Security.Cryptography.X509Certificates</c> surface directly. The returned
    /// value is carried forward to <see cref="EnsureSigningCertificateValidAtTimestamp"/>, which performs the
    /// genTime comparison once the token is acquired.
    /// </summary>
    /// <param name="parseResult">The already-parsed signature, disposed here on every throwing path (nothing else owns it yet at this point in the call).</param>
    /// <param name="signingCertificate">The signer's own certificate, or <see langword="null"/> when <paramref name="enforce"/> is <see langword="false"/>.</param>
    /// <param name="enforce">Whether the check runs at all.</param>
    /// <returns>The certificate's validity window, or <see langword="null"/> when <paramref name="enforce"/> is <see langword="false"/> (the check does not run).</returns>
    /// <exception cref="ArgumentException">When <paramref name="enforce"/> is <see langword="true"/> and <paramref name="signingCertificate"/> is <see langword="null"/>.</exception>
    /// <exception cref="CBAdESAugmentationException">
    /// When <paramref name="signingCertificate"/> is not tagged as an X.509 certificate, or its DER encoding
    /// does not parse (<see cref="CBAdESAugmentationFailureKind.SigningCertificateMalformed"/>).
    /// </exception>
    private static CertificateValidityPeriod? ReadSigningCertificateValidityOrThrow(
        CBAdESSign1ParseResult parseResult, PkiCertificateMemory? signingCertificate, bool enforce)
    {
        if(!enforce)
        {
            return null;
        }

        if(signingCertificate is null)
        {
            parseResult.Dispose();
            throw new ArgumentException(
                "Requirement (d) enforcement requires the signing certificate to check the acquired token's generation time against (ETSI TS 119 152-1 V1.1.1, clause 6.3, additional requirement (d)); supply SigningCertificate or set EnforceSigningCertificateValidity = false explicitly.",
                nameof(signingCertificate));
        }

        if(!signingCertificate.IsX509Certificate)
        {
            parseResult.Dispose();
            throw new CBAdESAugmentationException(
                CBAdESAugmentationFailureKind.SigningCertificateMalformed,
                "The signing certificate could not be read to check its validity window (ETSI TS 119 152-1 V1.1.1, clause 6.3, additional requirement (d)).");
        }

        if(!CertificateValidityPeriod.TryRead(signingCertificate, out CertificateValidityPeriod? validityPeriod))
        {
            parseResult.Dispose();
            throw new CBAdESAugmentationException(
                CBAdESAugmentationFailureKind.SigningCertificateMalformed,
                "The signing certificate could not be read to check its validity window (ETSI TS 119 152-1 V1.1.1, clause 6.3, additional requirement (d)).");
        }

        return validityPeriod;
    }


    /// <summary>
    /// Enforces Table 14 additional requirement (d)'s genTime half — "the electronic time-stamp encapsulated
    /// within <c>sigTst</c> shall be created before the signing certificate has been revoked or has expired" —
    /// against an acquired token before <see cref="AddSignatureTimestampAsync"/> attaches it. The certificate's
    /// own readability was already checked, before the Time-Stamping Authority round trip, by
    /// <see cref="ReadSigningCertificateValidityOrThrow"/>; this half runs after, because
    /// it needs the acquired token's generation time. Mirrors
    /// <see cref="Verifiable.Cryptography.Pki.CAdESSignatureAugmentation"/>'s requirement-m implementation (the
    /// CAdES analogue) exactly, secure by default.
    /// </summary>
    /// <param name="token">The already-verified token.</param>
    /// <param name="validityPeriod">The signing certificate's validity window, or <see langword="null"/> when the check is disabled.</param>
    /// <param name="revokedAt">The instant the certificate is known revoked, or <see langword="null"/> when none is known.</param>
    /// <exception cref="CBAdESAugmentationException">
    /// When the token's generation time falls outside <paramref name="validityPeriod"/> or at/after <paramref name="revokedAt"/>.
    /// </exception>
    private static void EnsureSigningCertificateValidAtTimestamp(
        AcquiredTimestampToken token, CertificateValidityPeriod? validityPeriod, DateTimeOffset? revokedAt)
    {
        if(validityPeriod is null)
        {
            return;
        }

        DateTimeOffset generationTime = token.Info.GenerationTime;
        if(generationTime < validityPeriod.NotBefore || generationTime > validityPeriod.NotAfter)
        {
            throw new CBAdESAugmentationException(
                CBAdESAugmentationFailureKind.SigningCertificateNotValidAtTimestamp,
                $"The acquired time-stamp token was generated at {generationTime:O}, outside the signing certificate's validity window {validityPeriod.NotBefore:O} to {validityPeriod.NotAfter:O} (ETSI TS 119 152-1 V1.1.1, clause 6.3, additional requirement (d)).");
        }

        if(revokedAt is { } revocationInstant && generationTime >= revocationInstant)
        {
            throw new CBAdESAugmentationException(
                CBAdESAugmentationFailureKind.SigningCertificateRevokedBeforeTimestamp,
                $"The acquired time-stamp token was generated at {generationTime:O}, at or after the signing certificate's revocation instant {revocationInstant:O} (ETSI TS 119 152-1 V1.1.1, clause 6.3, additional requirement (d)).");
        }
    }


    /// <summary>
    /// Builds the caller-supplied validation material into <c>valData</c>'s two members, skipping any
    /// candidate that byte-equals (DER) material already present in an earlier <c>valData</c> element of
    /// <paramref name="existing"/> when <paramref name="dedupe"/> is <see langword="true"/> (Table 14
    /// additional requirements (e)/(f)).
    /// </summary>
    /// <param name="material">The certificates/CRLs/OCSP responses to place.</param>
    /// <param name="existing">The signature's current <c>uHeaders</c> set, or <see langword="null"/> when absent.</param>
    /// <param name="dedupe">Whether byte-equal duplicates of already-present material are skipped.</param>
    /// <returns>The <c>xVals</c>/<c>rVals</c> members to place, or <see langword="null"/> for each member with nothing new to add.</returns>
    /// <exception cref="CBAdESAugmentationException">When a supplied object is not of the kind <c>valData</c> admits.</exception>
    private static (List<CBAdESX509OrOtherCertificate>? CertificateValues, CBAdESRevocationValues? RevocationValues) BuildValidationDataMembers(
        CBAdESValidationMaterial material, CBAdESUnsignedHeaders? existing, bool dedupe)
    {
        (List<ReadOnlyMemory<byte>> knownCertificates, List<ReadOnlyMemory<byte>> knownCrls, List<ReadOnlyMemory<byte>> knownOcsp) =
            dedupe ? CollectExistingValidationData(existing) : ([], [], []);

        List<CBAdESX509OrOtherCertificate>? certificateValues = null;
        if(material.Certificates.Count > 0)
        {
            List<CBAdESX509OrOtherCertificate> selected = [];
            for(int i = 0; i < material.Certificates.Count; ++i)
            {
                PkiCertificateMemory candidate = material.Certificates[i];
                EnsureKind(
                    candidate.IsX509Certificate,
                    CBAdESAugmentationFailureKind.UnsupportedValidationObject,
                    "A certificate placed as validation material is a DER-encoded X.509 certificate (ETSI TS 119 152-1 V1.1.1, clause 5.3.4, CB-5.3.4-04).");

                if(!dedupe || !ContainsBytes(knownCertificates, candidate.AsReadOnlySpan()))
                {
                    selected.Add(new CBAdESX509Certificate(new AdESPkiObject { Val = candidate.AsReadOnlyMemory() }));
                }
            }

            certificateValues = selected.Count > 0 ? selected : null;
        }

        List<AdESPkiObject>? crlValues = null;
        if(material.CertificateRevocationLists.Count > 0)
        {
            List<AdESPkiObject> selected = [];
            for(int i = 0; i < material.CertificateRevocationLists.Count; ++i)
            {
                PkiCertificateMemory candidate = material.CertificateRevocationLists[i];
                EnsureKind(
                    candidate.IsCrl,
                    CBAdESAugmentationFailureKind.UnsupportedValidationObject,
                    "A certificate revocation list placed as validation material is a DER-encoded CertificateList (ETSI TS 119 152-1 V1.1.1, clause 5.3.4, CB-5.3.4-06/07).");

                if(!dedupe || !ContainsBytes(knownCrls, candidate.AsReadOnlySpan()))
                {
                    selected.Add(new AdESPkiObject { Val = candidate.AsReadOnlyMemory() });
                }
            }

            crlValues = selected.Count > 0 ? selected : null;
        }

        List<AdESPkiObject>? ocspValues = null;
        if(material.OcspResponses.Count > 0)
        {
            List<AdESPkiObject> selected = [];
            for(int i = 0; i < material.OcspResponses.Count; ++i)
            {
                PkiCertificateMemory candidate = material.OcspResponses[i];
                EnsureKind(
                    candidate.IsOcspResponse,
                    CBAdESAugmentationFailureKind.UnsupportedValidationObject,
                    "An OCSP response placed as validation material is a DER-encoded OCSPResponse (ETSI TS 119 152-1 V1.1.1, clause 5.3.4, CB-5.3.4-09/10).");

                if(!dedupe || !ContainsBytes(knownOcsp, candidate.AsReadOnlySpan()))
                {
                    selected.Add(new AdESPkiObject { Val = candidate.AsReadOnlyMemory() });
                }
            }

            ocspValues = selected.Count > 0 ? selected : null;
        }

        CBAdESRevocationValues? revocationValues = crlValues is not null || ocspValues is not null
            ? new CBAdESRevocationValues(crlValues, ocspValues)
            : null;

        return (certificateValues, revocationValues);
    }


    /// <summary>
    /// Collects the DER bytes of every certificate/CRL/OCSP response reachable through an EARLIER <c>valData</c>
    /// element of <paramref name="unsignedHeaders"/> — the "already present" set
    /// <see cref="BuildValidationDataMembers"/> dedupes new candidates against.
    /// </summary>
    /// <param name="unsignedHeaders">The signature's current <c>uHeaders</c> set, or <see langword="null"/> when absent.</param>
    /// <returns>Three lists of borrowed DER byte views: certificates, CRLs, and OCSP responses.</returns>
    private static (List<ReadOnlyMemory<byte>> Certificates, List<ReadOnlyMemory<byte>> Crls, List<ReadOnlyMemory<byte>> Ocsp) CollectExistingValidationData(
        CBAdESUnsignedHeaders? unsignedHeaders)
    {
        List<ReadOnlyMemory<byte>> certificates = [];
        List<ReadOnlyMemory<byte>> crls = [];
        List<ReadOnlyMemory<byte>> ocsp = [];
        if(unsignedHeaders is not null)
        {
            for(int i = 0; i < unsignedHeaders.Count; ++i)
            {
                if(unsignedHeaders[i] is not CBAdESUnsignedHeaderElementValidationData valDataElement)
                {
                    continue;
                }

                CBAdESValidationData valData = valDataElement.ValidationData;
                if(valData.CertificateValues is not null)
                {
                    for(int c = 0; c < valData.CertificateValues.Count; ++c)
                    {
                        if(valData.CertificateValues[c] is CBAdESX509Certificate x509)
                        {
                            certificates.Add(x509.Certificate.Val);
                        }
                    }
                }

                if(valData.RevocationValues?.CrlValues is not null)
                {
                    for(int c = 0; c < valData.RevocationValues.CrlValues.Count; ++c)
                    {
                        crls.Add(valData.RevocationValues.CrlValues[c].Val);
                    }
                }

                if(valData.RevocationValues?.OcspValues is not null)
                {
                    for(int c = 0; c < valData.RevocationValues.OcspValues.Count; ++c)
                    {
                        ocsp.Add(valData.RevocationValues.OcspValues[c].Val);
                    }
                }
            }
        }

        return (certificates, crls, ocsp);
    }


    /// <summary>Determines whether <paramref name="known"/> contains an entry byte-equal to <paramref name="candidate"/>.</summary>
    /// <param name="known">The already-known byte views.</param>
    /// <param name="candidate">The candidate to look for.</param>
    /// <returns><see langword="true"/> when found.</returns>
    private static bool ContainsBytes(List<ReadOnlyMemory<byte>> known, ReadOnlySpan<byte> candidate)
    {
        for(int i = 0; i < known.Count; ++i)
        {
            if(known[i].Span.SequenceEqual(candidate))
            {
                return true;
            }
        }

        return false;
    }


    /// <summary>Determines whether <paramref name="unsignedHeaders"/> carries a <c>refs</c> element anywhere.</summary>
    /// <param name="unsignedHeaders">The decoded <c>uHeaders</c> set, or <see langword="null"/> when absent.</param>
    /// <returns><see langword="true"/> when a <c>refs</c> element is present.</returns>
    private static bool HasReferencesElement(CBAdESUnsignedHeaders? unsignedHeaders)
    {
        if(unsignedHeaders is null)
        {
            return false;
        }

        for(int i = 0; i < unsignedHeaders.Count; ++i)
        {
            if(unsignedHeaders[i] is CBAdESUnsignedHeaderElementReferences)
            {
                return true;
            }
        }

        return false;
    }


    /// <summary>
    /// Determines whether <paramref name="element"/> is one of the three B-B/B-T-only refs-family kinds Table
    /// 14 hard-forbids from B-LT on (<c>refs</c>, <c>sigRTst</c>, <c>rfsTst</c>).
    /// </summary>
    /// <param name="element">The element to classify.</param>
    /// <returns><see langword="true"/> when <paramref name="element"/> is a refs-family element.</returns>
    private static bool IsReferencesFamilyElement(CBAdESUnsignedHeaderElement element) => element switch
    {
        CBAdESUnsignedHeaderElementReferences => true,
        CBAdESUnsignedHeaderElementSignatureAndReferencesTimestamp => true,
        CBAdESUnsignedHeaderElementReferencesTimestamp => true,
        _ => false
    };


    /// <summary>
    /// Determines whether <paramref name="unsignedHeaders"/> carries at least one refs-family element
    /// (<see cref="IsReferencesFamilyElement"/>) — <see cref="AddArchiveTimestampAsync"/>'s own pre-Time-Stamping-Authority
    /// refusal gate for CB-6.3-23/-24/-25.
    /// </summary>
    /// <param name="unsignedHeaders">The decoded <c>uHeaders</c> set, or <see langword="null"/> when absent.</param>
    /// <returns><see langword="true"/> when at least one of <c>refs</c>, <c>sigRTst</c>, or <c>rfsTst</c> is present.</returns>
    private static bool HasReferencesFamilyElement(CBAdESUnsignedHeaders? unsignedHeaders)
    {
        if(unsignedHeaders is null)
        {
            return false;
        }

        for(int i = 0; i < unsignedHeaders.Count; ++i)
        {
            if(IsReferencesFamilyElement(unsignedHeaders[i]))
            {
                return true;
            }
        }

        return false;
    }


    /// <summary>
    /// Maps a <see cref="PkiDigestAlgorithm"/> to its CB-AdES wire identifier — the <c>int</c> arm of the
    /// <c>hashAlg: (int / tstr)</c> CDDL union, recognizing only the three algorithms clause 6.2.1 names
    /// (SHA-256/384/512).
    /// </summary>
    /// <param name="algorithm">The digest algorithm to map.</param>
    /// <returns>The CB-AdES wire digest-algorithm identifier.</returns>
    /// <exception cref="NotSupportedException"><paramref name="algorithm"/> is not SHA-256/384/512.</exception>
    private static AdESDigestAlgorithmIntegerIdentifier ToWireDigestAlgorithm(PkiDigestAlgorithm algorithm) => algorithm.Identifier.Oid switch
    {
        var oid when string.Equals(oid, AlgorithmIdentifier.Sha256.Oid, StringComparison.Ordinal) => new AdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256),
        var oid when string.Equals(oid, AlgorithmIdentifier.Sha384.Oid, StringComparison.Ordinal) => new AdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha384),
        var oid when string.Equals(oid, AlgorithmIdentifier.Sha512.Oid, StringComparison.Ordinal) => new AdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha512),
        _ => throw new NotSupportedException($"Digest algorithm '{algorithm.Identifier.Oid}' has no CB-AdES wire identifier mapping (ETSI TS 119 152-1 V1.1.1, clause 6.2.1 names only SHA-256/384/512).")
    };


    /// <summary>Refuses a supplied object that is not of the kind a placement admits.</summary>
    /// <param name="isOfKind">Whether the object is of the kind.</param>
    /// <param name="kind">The failure kind to classify the refusal as.</param>
    /// <param name="message">The message naming what the placement admits.</param>
    /// <exception cref="CBAdESAugmentationException">When the object is not of the kind.</exception>
    private static void EnsureKind(bool isOfKind, CBAdESAugmentationFailureKind kind, string message)
    {
        if(!isOfKind)
        {
            throw new CBAdESAugmentationException(kind, message);
        }
    }


    /// <summary>Disposes every entry of <paramref name="entries"/>, tolerating a <see langword="null"/> list.</summary>
    /// <typeparam name="T">The disposable entry type.</typeparam>
    /// <param name="entries">The list whose entries to dispose, or <see langword="null"/>.</param>
    private static void DisposeEntries<T>(List<T>? entries) where T: IDisposable
    {
        if(entries is null)
        {
            return;
        }

        for(int i = 0; i < entries.Count; ++i)
        {
            entries[i].Dispose();
        }
    }
}
