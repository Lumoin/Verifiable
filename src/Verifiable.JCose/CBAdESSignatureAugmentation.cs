using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
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

    /// <summary>The caller-supplied signing certificate could not be read to check its validity window.</summary>
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
    /// the decoded model's, or the raw bytes were otherwise malformed), not a caller-supplied fault (wavecb S4
    /// FX-A).
    /// </summary>
    RawUnsignedHeadersSpliceMalformed = 9
}


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
/// The validation material a <see cref="CBAdESSignatureAugmentation.AddValidationData"/> call places into a
/// signature's <c>valData</c> — clause 5.3.4's certificate and revocation values, mirroring
/// <see cref="Verifiable.Cryptography.Pki.CAdESValidationMaterial"/>'s own shape and ownership rule exactly.
/// </summary>
/// <remarks>
/// The carriers belong to the caller for the whole call and are not disposed by anything here: an
/// augmentation borrows the octets it places for the duration of the call — long enough to serialize them
/// into the augmented signature's own wire bytes — and never takes ownership of what it was shown.
/// </remarks>
public sealed record CBAdESValidationMaterial
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
public sealed record CBAdESSignatureTimestampContext
{
    /// <summary>Gets the CB-AdES <c>COSE_Sign1</c> wire bytes to augment. Not modified; the result is new wire bytes.</summary>
    public required ReadOnlyMemory<byte> WireBytes { get; init; }

    /// <summary>Gets the algorithm the message imprint is computed under, which the authority echoes in its token.</summary>
    public required PkiDigestAlgorithm MessageImprintAlgorithm { get; init; }

    /// <summary>Gets the Time-Stamping Authority to contact, in whatever form the transport delegate understands.</summary>
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
    public required CBAdESBaselineLevel TargetLevel { get; init; }
}


/// <summary>
/// The three-way source union for <see cref="CBAdESSignatureAugmentation.AcquirePayloadTimestampAsync"/> — the
/// caller-visible mirror of <see cref="CBAdESPayloadTimestampImprintSource"/> that additionally carries the
/// RAW, not-yet-dereferenced <c>sigD.pars</c> references for its third arm, since this orchestrator (not the
/// caller) composes the dereference reconstruction. A DU-ready closed sum: no external type may derive from it.
/// </summary>
public abstract record CBAdESPayloadTimestampAcquisitionSource
{
    /// <summary>Restricts direct subtyping to the sibling records declared in this file.</summary>
    private protected CBAdESPayloadTimestampAcquisitionSource()
    {
    }
}


/// <summary>The attached-payload arm: the COSE Payload field is present, and <see cref="PayloadBytes"/> is its content.</summary>
/// <param name="PayloadBytes">The COSE Payload field's content bytes. <strong>Borrowed</strong> view — the caller owns the underlying memory.</param>
[DebuggerDisplay("CBAdESAttachedPayloadTimestampAcquisitionSource: {PayloadBytes.Length} bytes")]
public sealed record CBAdESAttachedPayloadTimestampAcquisitionSource(ReadOnlyMemory<byte> PayloadBytes)
    : CBAdESPayloadTimestampAcquisitionSource;


/// <summary>The detached-and-unreferenced arm: the caller already holds the out-of-band detached COSE Payload bytes.</summary>
/// <param name="PayloadBytes">The out-of-band detached COSE Payload bytes. <strong>Borrowed</strong> view — the caller owns the underlying memory.</param>
[DebuggerDisplay("CBAdESDetachedPayloadTimestampAcquisitionSource: {PayloadBytes.Length} bytes")]
public sealed record CBAdESDetachedPayloadTimestampAcquisitionSource(ReadOnlyMemory<byte> PayloadBytes)
    : CBAdESPayloadTimestampAcquisitionSource;


/// <summary>
/// The <c>sigD</c>-present arm: <see cref="References"/> are the raw, not-yet-dereferenced <c>sigD.pars</c>
/// URI-references. <see cref="CBAdESSignatureAugmentation.AcquirePayloadTimestampAsync"/> composes
/// <see cref="CBAdESDetachedObjectDereferencing.ReconstructObjectIdByURIPayloadAsync"/> — the CB-5.2.8.2.3-07
/// reconstruction path — to turn this arm into the processed bytes the imprint builder needs.
/// </summary>
[DebuggerDisplay("CBAdESSigDReferencedPayloadTimestampAcquisitionSource: {References.Count} reference(s)")]
public sealed record CBAdESSigDReferencedPayloadTimestampAcquisitionSource: CBAdESPayloadTimestampAcquisitionSource
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
/// What one <see cref="CBAdESSignatureAugmentation.AddValidationData"/> call needs: the signature, the
/// certificates/CRLs/OCSP responses to place, the dedup default, and the level being reached.
/// </summary>
[DebuggerDisplay("CBAdESValidationDataContext(TargetLevel={TargetLevel})")]
public sealed record CBAdESValidationDataContext
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

    /// <summary>Gets the level this call is raising the signature to — typically B-LT.</summary>
    public required CBAdESBaselineLevel TargetLevel { get; init; }
}


/// <summary>
/// What one <see cref="CBAdESSignatureAugmentation.AddSignatureAndReferencesTimestampAsync"/> or
/// <see cref="CBAdESSignatureAugmentation.AddReferencesTimestampAsync"/> call needs — identical shape for both
/// (Annex A.1.2.1.2 and A.1.2.2.2 differ only in whether the signature value contributes, which the imprint
/// builder delegate the caller supplies already encodes).
/// </summary>
[DebuggerDisplay("CBAdESReferencesFamilyTimestampContext(TargetLevel={TargetLevel})")]
public sealed record CBAdESReferencesFamilyTimestampContext
{
    /// <summary>Gets the CB-AdES <c>COSE_Sign1</c> wire bytes to augment. Not modified; the result is new wire bytes.</summary>
    public required ReadOnlyMemory<byte> WireBytes { get; init; }

    /// <summary>Gets the algorithm the message imprint is computed under, which the authority echoes in its token.</summary>
    public required PkiDigestAlgorithm MessageImprintAlgorithm { get; init; }

    /// <summary>Gets the Time-Stamping Authority to contact, in whatever form the transport delegate understands.</summary>
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
    public required CBAdESBaselineLevel TargetLevel { get; init; }
}


/// <summary>
/// One OCSP response to reference within <see cref="CBAdESReferencesContext.OcspResponsesToReference"/>: the
/// response itself plus the mandatory <c>ocspId</c> identifier <see cref="CBAdESOcspIdentifier"/> requires.
/// </summary>
/// <remarks>
/// <see cref="CBAdESOcspIdentifier"/>'s <c>responderId</c>/<c>producedAt</c> members are not derivable from the
/// response's DER bytes without a dedicated OCSP ASN.1 reader this stage does not build (out of the task's
/// explicit scope) — the caller, who already parsed or produced the response, supplies them directly.
/// </remarks>
/// <param name="Response">The DER-encoded <c>OCSPResponse</c> being referenced.</param>
/// <param name="Identifier">The mandatory <c>ocspId</c> identifier (CB-A.1.1-21/25).</param>
[DebuggerDisplay("CBAdESOcspReferenceInput: {Identifier}")]
public sealed record CBAdESOcspReferenceInput(PkiCertificateMemory Response, CBAdESOcspIdentifier Identifier);


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
public sealed record CBAdESReferencesContext
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
    public required CBAdESBaselineLevel TargetLevel { get; init; }
}


/// <summary>
/// What one <see cref="CBAdESSignatureAugmentation.StripReferencesForLongTerm"/> call needs: the signature and
/// the level being reached (typically B-LT).
/// </summary>
[DebuggerDisplay("CBAdESStripReferencesContext(TargetLevel={TargetLevel})")]
public sealed record CBAdESStripReferencesContext
{
    /// <summary>Gets the CB-AdES <c>COSE_Sign1</c> wire bytes to augment. Not modified; the result is new wire bytes.</summary>
    public required ReadOnlyMemory<byte> WireBytes { get; init; }

    /// <summary>Gets the level this call is raising the signature to — typically B-LT.</summary>
    public required CBAdESBaselineLevel TargetLevel { get; init; }
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
/// <strong>Every step parses, appends, re-serializes; nothing is mutated in place.</strong> Each verb parses
/// the caller-supplied wire bytes through <see cref="ParseCBAdESSign1Delegate"/> (fail-closed; a parse failure
/// here is a CALLER composition fault, not untrusted input, so it is reported as
/// <see cref="CBAdESAugmentationException"/> rather than collected — R-5's "creation/augmentation throw on
/// caller error" half), builds the new <c>uHeaders</c> element(s) it needs, appends through
/// <see cref="CBAdESUnsignedHeaders.Append"/> or rebuilds via <c>new CBAdESUnsignedHeaders(...)</c> (for the
/// decoded model level-rule checking needs), and re-serializes through <see cref="SerializeCBAdESSign1Delegate"/>
/// into a brand-new <see cref="EncodedCoseSign1"/>: the protected header and signature value are carried
/// through byte-for-byte (unsigned-header augmentation never re-signs).
/// </para>
/// <para>
/// <strong>The precise splice guarantee (wavecb S4 FX-A) — canonical-on-create, preserve-on-augment.</strong>
/// The input wire bytes themselves are of course never mutated (a fresh <see cref="EncodedCoseSign1"/> is
/// always returned), but an EARLIER revision of this remark additionally claimed no retained element's WIRE
/// BYTES could ever change across an augmentation call — that claim was false: every verb below used to
/// re-encode the WHOLE <c>uHeaders</c> array from the DECODED model
/// (<see cref="EncodeCBAdESUnprotectedHeaderDelegate"/>), and a decoded-model re-encode is provably lossy for
/// at least one retained CDDL union arm (<see cref="CBAdESSerialization.WriteTDate"/>'s whole-second,
/// forced-<c>Z</c> writer collapses a sub-second or non-<c>Z</c>-offset wire <c>tdate</c>, and an opaque
/// <see cref="Verifiable.Cryptography.Pki.CBAdESUnsignedHeaderElementUnknown"/> element is never modeled
/// precisely enough to reproduce byte-for-byte from its decoded form at all). Every verb below now composes its
/// new <c>uHeaders</c> unprotected-header dictionary through <see cref="TrySpliceCBAdESUnprotectedHeaderDelegate"/>
/// instead: retained elements are copied CONTENT-verbatim from <see cref="CBAdESSign1ParseResult.RawUnsignedHeaders"/>
/// — the raw wire bytes captured at parse — and only the genuinely NEW element this call itself builds is
/// freshly encoded. <see cref="EncodeCBAdESUnprotectedHeaderDelegate"/> remains exactly right for CREATION
/// (<see cref="CBAdESSignatureCreation.SignAsync(CBAdESProtectedHeaders, CBAdESSigningPayloadInput, CBAdESUnsignedHeaders?, EncodeCBAdESProtectedHeaderDelegate, EncodeCBAdESUnprotectedHeaderDelegate, BuildSigStructureDelegate, PrivateKeyMemory, CBAdESDetachedObjectDereferenceDelegate?, CBAdESDetachedObjectDereferenceContext?, CBAdESUnknownDetachedObjectMechanismDelegate?, BaseMemoryPool, CancellationToken)"/>
/// builds <c>uHeaders</c> fresh every time — that path has no prior wire bytes to lose, so re-encoding from
/// the decoded model it itself just constructed is not lossy) and is untouched by this change.
/// </para>
/// <para>
/// <strong>One rule implementation, throw posture.</strong> After building the candidate new <c>uHeaders</c>
/// state, every verb calls <see cref="CBAdESLevelRules.EnsureConformant"/> — the SAME rule surface the
/// validation orchestrator calls in collect posture (S4 coordinator ruling (5)) — over that candidate state at
/// the caller-declared <see cref="CBAdESBaselineLevel"/>. This is not merely a final sanity check: because that
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
/// to close (S4 coordinator ruling (4)).
/// </para>
/// <para>
/// <strong>A token is verified before it is attached, and copied when it must outlive the call.</strong>
/// Acquisition goes through <see cref="Verifiable.Cryptography.Pki.TimestampAcquisition.AcquireAsync"/>, the
/// ONLY acquisition path (R-2): per-call nonce via the entropy seam, NO in-library replay/freshness state
/// (<see href="https://www.rfc-editor.org/rfc/rfc3161">RFC 3161</see> genTime acceptance-window policy is a
/// later stage's, matching the app-owned-freshness convention this library's <c>JtiReplayPolicy</c> documents
/// for the analogous JWT case). <see cref="AddSignatureTimestampAsync"/>,
/// <see cref="AddSignatureAndReferencesTimestampAsync"/>, and <see cref="AddReferencesTimestampAsync"/> consume
/// the acquired token's DER bytes as a BORROWED view directly from the still-alive
/// <see cref="Verifiable.Cryptography.Pki.AcquiredTimestampToken"/> (disposed only in this call's own
/// <c>finally</c>, after re-serialization has already copied the bytes into the returned
/// <see cref="EncodedCoseSign1"/>). <see cref="AcquirePayloadTimestampAsync"/> is the one exception: it returns
/// a DECODED MODEL (<see cref="CBAdESPayloadTimestamp"/>) the caller may hold arbitrarily long before
/// <c>SignAsync</c>, and <see cref="CBAdESTimestampToken.Val"/> is a borrowed view with
/// <see cref="CBAdESTimestampContainer.Dispose"/> currently a no-op (that type's own remarks) — so that method
/// copies the token's DER bytes to a GC-owned array BEFORE disposing the acquired token, rather than handing
/// back a view into memory this call is about to return to the pool. Flagged for a later stage that introduces
/// an owned, pooled <c>Val</c> carrier on <see cref="CBAdESTimestampToken"/>.
/// </para>
/// <para>
/// <strong>No registry-resolved/explicit-delegate overload pair, recorded loudly (a deviation from the task's
/// literal instruction, with grounds).</strong> Every other CB-AdES orchestrator in this stage (S3's
/// <see cref="CBAdESSignatureCreation"/>/<see cref="CBAdESSignatureValidation"/>) offers that pair because a
/// <see cref="PrivateKeyMemory"/>/<see cref="PublicKeyMemory"/>'s <see cref="Tag"/> resolves a signing or
/// verification function through <see cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}"/>. NONE
/// of the seven verbs here perform a private-key cryptographic operation at all: the Time-Stamping Authority
/// signs (via RFC 3161), and every digest crosses the registered digest delegate (a single ambient
/// registration, not a per-call choice with two flavors to offer). There is consequently nothing to resolve
/// from a key's tag, and the two-overload split this task asked for has no natural target here — every verb
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
    /// <param name="spliceUnprotectedHeader">The <c>uHeaders</c> unprotected-header raw-splice seam (wavecb S4 FX-A).</param>
    /// <param name="pool">The memory pool every carrier is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The augmented signature's new wire bytes. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException">When a required argument is <see langword="null"/>.</exception>
    /// <exception cref="CBAdESAugmentationException">
    /// When <paramref name="context"/>'s wire bytes cannot be parsed (<see cref="CBAdESAugmentationFailureKind.MalformedEncoding"/>),
    /// or Table 14 additional requirement (d) is not satisfied by the acquired token
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
    /// CB-6.3-c ("each <c>sigTst</c> shall contain only one electronic time-stamp") holds by construction: this
    /// call always builds a <see cref="CBAdESTimestampContainer"/> with exactly one
    /// <see cref="CBAdESTimestampToken"/>; a second Time-Stamping Authority is a second call, appending a
    /// second, sibling <c>sigTst</c> element (Table 14 note 7), never a second token inside one container.
    /// </remarks>
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

            EnsureSigningCertificateValidAtTimestamp(
                token, context.SigningCertificate, context.SigningCertificateRevokedAt, context.EnforceSigningCertificateValidity);

            var container = new CBAdESTimestampContainer
            {
                TstTokens = [new CBAdESTimestampToken { Val = token.Token.AsReadOnlyMemory() }]
            };
            var element = new CBAdESUnsignedHeaderElementSignatureTimestamp(new CBAdESSignatureTimestamp(container));

            finalUnsignedHeaders = parseResult.UnsignedHeaders is null
                ? new CBAdESUnsignedHeaders([element])
                : parseResult.UnsignedHeaders.Append(element);
            transferred = true;

            CBAdESLevelRules.EnsureConformant(new CBAdESLevelRuleContext
            {
                Level = context.TargetLevel,
                UnsignedHeaders = finalUnsignedHeaders
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

            //CBAdESTimestampToken.Val is a borrowed view and CBAdESTimestampContainer.Dispose is a no-op today
            //(see that type's own remarks) -- this result crosses the method boundary as a decoded model the
            //caller may hold arbitrarily long before SignAsync, so the token's DER bytes are copied to a
            //GC-owned array here, before the pool-rented token is disposed in the finally below, rather than
            //left as a dangling borrowed view into a buffer this method is about to return to the pool.
            byte[] tokenBytes = token.Token.AsReadOnlySpan().ToArray();

            var container = new CBAdESTimestampContainer
            {
                TstTokens = [new CBAdESTimestampToken { Val = tokenBytes }]
            };

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
    /// <param name="spliceUnprotectedHeader">The <c>uHeaders</c> unprotected-header raw-splice seam (wavecb S4 FX-A).</param>
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
    /// <strong>Dedup scope, recorded loudly.</strong> This call deduplicates only against material already
    /// present in an EARLIER <c>valData</c> element of THIS signature's own <c>uHeaders</c> — the CAdES
    /// exemplar's own scope for its analogous check. It does not scan <c>x5chain</c>, the signed <c>x5t</c>/
    /// <c>x5ts</c>, or <c>refs</c> for a matching certificate; a caller supplying material already reachable
    /// through one of those signed components places a certificate <c>valData</c> also carries, which is
    /// legal (Table 14 requirements (e)/(f) are SHOULDs) but outside this method's dedup scope.
    /// </remarks>
    public static async ValueTask<EncodedCoseSign1> AddValidationData(
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
                UnsignedHeaders = finalUnsignedHeaders
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
    /// <param name="context">The signature and the target level (typically B-LT).</param>
    /// <param name="parse">The fail-closed CBOR parse seam.</param>
    /// <param name="serialize">The CBOR re-serialization seam.</param>
    /// <param name="spliceUnprotectedHeader">The <c>uHeaders</c> unprotected-header raw-splice seam (wavecb S4 FX-A).</param>
    /// <param name="pool">The memory pool every carrier is rented from.</param>
    /// <returns>The stripped signature's new wire bytes. The caller owns and disposes it. Absent every retained element, the result carries no <c>uHeaders</c> member at all.</returns>
    /// <exception cref="ArgumentNullException">When a required argument is <see langword="null"/>.</exception>
    /// <exception cref="CBAdESAugmentationException">When <paramref name="context"/>'s wire bytes cannot be parsed.</exception>
    /// <exception cref="ArgumentException">When the resulting <c>uHeaders</c> fails <see cref="CBAdESLevelRules.EnsureConformant"/> at <see cref="CBAdESStripReferencesContext.TargetLevel"/> — should not occur by construction, kept as defense in depth.</exception>
    /// <remarks>
    /// <para>
    /// <strong>Design call, recorded per the task's explicit invitation to record it: a standalone strip verb,
    /// not folded into a "RaiseToLongTerm" step.</strong> <see cref="AddValidationData"/> already performs the
    /// OTHER B-LT-transition act (placing <c>valData</c>) as its own call; keeping the strip act separate
    /// mirrors CAdES's own granular verb style (many small composable operations, never one monolithic
    /// "raise the level" method) and lets a caller strip and place validation data in whichever order its own
    /// material-gathering flow prefers, or strip alone when <c>valData</c> is already present from an earlier
    /// <c>AddValidationData</c> call at B-T.
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
                        //raw array entry verbatim (wavecb S4 FX-A) -- never a re-encode of what is retained.
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
            //is never cascade-disposed (S4 coordinator ruling (4); see this method's own remarks).
            transferred = true;

            CBAdESLevelRules.EnsureConformant(new CBAdESLevelRuleContext
            {
                Level = context.TargetLevel,
                UnsignedHeaders = finalUnsignedHeaders
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
    /// <param name="spliceUnprotectedHeader">The <c>uHeaders</c> unprotected-header raw-splice seam (wavecb S4 FX-A).</param>
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
        if(!HasReferencesElement(parseResult.UnsignedHeaders))
        {
            parseResult.Dispose();
            throw new CBAdESAugmentationException(
                CBAdESAugmentationFailureKind.ReferencesElementRequired,
                "If the component refs is not present, the sigRTst CBOR map shall not be generated (ETSI TS 119 152-1 V1.1.1, Annex A.1.2.1.1, CB-A.1.2.1-03).");
        }

        ReadOnlyMemory<byte>? uHeadersEncodedArray = parseResult.RawUnsignedHeaders?.AsReadOnlyMemory();
        //Generation always builds the imprint over the pre-append snapshot -- every element parseResult.UnsignedHeaders
        //already held -- which is already the correct prefix (D15), so uHeadersSliceBound is null here.
        if(!buildImprintInput(parseResult.Signature!.AsReadOnlyMemory(), uHeadersEncodedArray, uHeadersSliceBound: null, pool, out PooledMemory? imprintInput) || imprintInput is null)
        {
            parseResult.Dispose();
            throw new CBAdESAugmentationException(
                CBAdESAugmentationFailureKind.MessageImprintInputMalformed,
                "The sigRTst message-imprint input could not be built from this signature's own uHeaders (ETSI TS 119 152-1 V1.1.1, Annex A.1.2.1.2).");
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
    /// <param name="spliceUnprotectedHeader">The <c>uHeaders</c> unprotected-header raw-splice seam (wavecb S4 FX-A).</param>
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
        if(!HasReferencesElement(parseResult.UnsignedHeaders))
        {
            parseResult.Dispose();
            throw new CBAdESAugmentationException(
                CBAdESAugmentationFailureKind.ReferencesElementRequired,
                "If the component refs is not present, the rfsTst CBOR map shall not be generated (ETSI TS 119 152-1 V1.1.1, Annex A.1.2.2.1, CB-A.1.2.2-03).");
        }

        ReadOnlyMemory<byte>? uHeadersEncodedArray = parseResult.RawUnsignedHeaders?.AsReadOnlyMemory();
        //Generation always builds the imprint over the pre-append snapshot -- the correct prefix already (D15) --
        //so uHeadersSliceBound is null here; see AddSignatureAndReferencesTimestampAsync's identical remark.
        if(!buildImprintInput(uHeadersEncodedArray, uHeadersSliceBound: null, pool, out PooledMemory? imprintInput) || imprintInput is null)
        {
            parseResult.Dispose();
            throw new CBAdESAugmentationException(
                CBAdESAugmentationFailureKind.MessageImprintInputMalformed,
                "The rfsTst message-imprint input could not be built from this signature's own uHeaders (ETSI TS 119 152-1 V1.1.1, Annex A.1.2.2.2).");
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
    /// <param name="spliceUnprotectedHeader">The <c>uHeaders</c> unprotected-header raw-splice seam (wavecb S4 FX-A).</param>
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
            CBAdESDigestAlgorithmIdentifier wireAlgorithm = ToWireDigestAlgorithm(context.MessageImprintAlgorithm);
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
                    certificateReferences.Add(new CBAdESCertificateReference(new CBAdESCertificateThumbprint(wireAlgorithm, digest)));
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
                UnsignedHeaders = finalUnsignedHeaders
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
    /// <param name="spliceUnprotectedHeader">The <c>uHeaders</c> unprotected-header raw-splice seam (wavecb S4 FX-A).</param>
    /// <param name="serialize">The CBOR re-serialization seam.</param>
    /// <param name="pool">The memory pool every carrier is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The augmented signature's new wire bytes. The caller owns and disposes it.</returns>
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

            var container = new CBAdESTimestampContainer
            {
                TstTokens = [new CBAdESTimestampToken { Val = token.Token.AsReadOnlyMemory() }]
            };

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
                UnsignedHeaders = finalUnsignedHeaders
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
    /// augmentation verb performs (wavecb S4 FX-A).
    /// </summary>
    /// <param name="parseResult">The parsed signature being augmented. Not disposed here; the caller's own <c>finally</c> owns that.</param>
    /// <param name="skipDecodedIndexes">The decoded-model indexes whose raw <c>uHeaders</c> entry is dropped (the strip verb's refs-family elements), or <see langword="null"/>/empty to retain every element.</param>
    /// <param name="newElement">The freshly-built element to append last, or <see langword="null"/> to append nothing new.</param>
    /// <param name="spliceUnprotectedHeader">The <c>uHeaders</c> unprotected-header raw-splice seam (wavecb S4 FX-A).</param>
    /// <param name="serialize">The CBOR re-serialization seam.</param>
    /// <param name="pool">The memory pool the splice/serialize steps rent from.</param>
    /// <returns>The augmented signature's new wire bytes. The caller owns and disposes it.</returns>
    /// <exception cref="CBAdESAugmentationException">
    /// When <paramref name="spliceUnprotectedHeader"/> reports an internal inconsistency between the parse step
    /// and the splice (<see cref="CBAdESAugmentationFailureKind.RawUnsignedHeadersSpliceMalformed"/>).
    /// </exception>
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
                "5.3.1; wavecb S4 FX-A).");
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
    /// Enforces Table 14 additional requirement (d) — "the electronic time-stamp encapsulated within
    /// <c>sigTst</c> shall be created before the signing certificate has been revoked or has expired" — against
    /// an acquired token before <see cref="AddSignatureTimestampAsync"/> attaches it. Mirrors
    /// <see cref="Verifiable.Cryptography.Pki.CAdESSignatureAugmentation"/>'s requirement-m implementation
    /// (the CAdES analogue) exactly, secure by default.
    /// </summary>
    /// <param name="token">The already-verified token.</param>
    /// <param name="signingCertificate">The signer's own certificate, or <see langword="null"/> when <paramref name="enforce"/> is <see langword="false"/>.</param>
    /// <param name="revokedAt">The instant the certificate is known revoked, or <see langword="null"/> when none is known.</param>
    /// <param name="enforce">Whether the check runs at all.</param>
    /// <exception cref="ArgumentException">When <paramref name="enforce"/> is <see langword="true"/> and <paramref name="signingCertificate"/> is <see langword="null"/>.</exception>
    /// <exception cref="CBAdESAugmentationException">
    /// When <paramref name="signingCertificate"/> could not be read
    /// (<see cref="CBAdESAugmentationFailureKind.SigningCertificateMalformed"/>), or the token's generation
    /// time falls outside the certificate's validity window or at/after <paramref name="revokedAt"/>.
    /// </exception>
    private static void EnsureSigningCertificateValidAtTimestamp(
        AcquiredTimestampToken token, PkiCertificateMemory? signingCertificate, DateTimeOffset? revokedAt, bool enforce)
    {
        if(!enforce)
        {
            return;
        }

        if(signingCertificate is null)
        {
            throw new ArgumentException(
                "Requirement (d) enforcement requires the signing certificate to check the acquired token's generation time against (ETSI TS 119 152-1 V1.1.1, clause 6.3, additional requirement (d)); supply SigningCertificate or set EnforceSigningCertificateValidity = false explicitly.",
                nameof(signingCertificate));
        }

        X509Certificate2 certificate;
        try
        {
            certificate = X509CertificateLoader.LoadCertificate(signingCertificate.AsReadOnlySpan());
        }
        catch(CryptographicException exception)
        {
            throw new CBAdESAugmentationException(
                CBAdESAugmentationFailureKind.SigningCertificateMalformed,
                "The signing certificate could not be read to check its validity window (ETSI TS 119 152-1 V1.1.1, clause 6.3, additional requirement (d)).",
                exception);
        }

        using(certificate)
        {
            DateTimeOffset notBefore = new(certificate.NotBefore);
            DateTimeOffset notAfter = new(certificate.NotAfter);
            DateTimeOffset generationTime = token.Info.GenerationTime;
            if(generationTime < notBefore || generationTime > notAfter)
            {
                throw new CBAdESAugmentationException(
                    CBAdESAugmentationFailureKind.SigningCertificateNotValidAtTimestamp,
                    $"The acquired time-stamp token was generated at {generationTime:O}, outside the signing certificate's validity window {notBefore:O} to {notAfter:O} (ETSI TS 119 152-1 V1.1.1, clause 6.3, additional requirement (d)).");
            }

            if(revokedAt is { } revocationInstant && generationTime >= revocationInstant)
            {
                throw new CBAdESAugmentationException(
                    CBAdESAugmentationFailureKind.SigningCertificateRevokedBeforeTimestamp,
                    $"The acquired time-stamp token was generated at {generationTime:O}, at or after the signing certificate's revocation instant {revocationInstant:O} (ETSI TS 119 152-1 V1.1.1, clause 6.3, additional requirement (d)).");
            }
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
                    selected.Add(new CBAdESX509Certificate(new CBAdESPkiObject { Val = candidate.AsReadOnlyMemory() }));
                }
            }

            certificateValues = selected.Count > 0 ? selected : null;
        }

        List<CBAdESPkiObject>? crlValues = null;
        if(material.CertificateRevocationLists.Count > 0)
        {
            List<CBAdESPkiObject> selected = [];
            for(int i = 0; i < material.CertificateRevocationLists.Count; ++i)
            {
                PkiCertificateMemory candidate = material.CertificateRevocationLists[i];
                EnsureKind(
                    candidate.IsCrl,
                    CBAdESAugmentationFailureKind.UnsupportedValidationObject,
                    "A certificate revocation list placed as validation material is a DER-encoded CertificateList (ETSI TS 119 152-1 V1.1.1, clause 5.3.4, CB-5.3.4-06/07).");

                if(!dedupe || !ContainsBytes(knownCrls, candidate.AsReadOnlySpan()))
                {
                    selected.Add(new CBAdESPkiObject { Val = candidate.AsReadOnlyMemory() });
                }
            }

            crlValues = selected.Count > 0 ? selected : null;
        }

        List<CBAdESPkiObject>? ocspValues = null;
        if(material.OcspResponses.Count > 0)
        {
            List<CBAdESPkiObject> selected = [];
            for(int i = 0; i < material.OcspResponses.Count; ++i)
            {
                PkiCertificateMemory candidate = material.OcspResponses[i];
                EnsureKind(
                    candidate.IsOcspResponse,
                    CBAdESAugmentationFailureKind.UnsupportedValidationObject,
                    "An OCSP response placed as validation material is a DER-encoded OCSPResponse (ETSI TS 119 152-1 V1.1.1, clause 5.3.4, CB-5.3.4-09/10).");

                if(!dedupe || !ContainsBytes(knownOcsp, candidate.AsReadOnlySpan()))
                {
                    selected.Add(new CBAdESPkiObject { Val = candidate.AsReadOnlyMemory() });
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
    /// Maps a <see cref="PkiDigestAlgorithm"/> to its CB-AdES wire identifier — the <c>int</c> arm of the
    /// <c>hashAlg: (int / tstr)</c> CDDL union, recognizing only the three algorithms clause 6.2.1 names
    /// (SHA-256/384/512).
    /// </summary>
    /// <param name="algorithm">The digest algorithm to map.</param>
    /// <returns>The CB-AdES wire digest-algorithm identifier.</returns>
    /// <exception cref="NotSupportedException"><paramref name="algorithm"/> is not SHA-256/384/512.</exception>
    private static CBAdESDigestAlgorithmIdentifier ToWireDigestAlgorithm(PkiDigestAlgorithm algorithm) => algorithm.Identifier.Oid switch
    {
        var oid when string.Equals(oid, AlgorithmIdentifier.Sha256.Oid, StringComparison.Ordinal) => new CBAdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256),
        var oid when string.Equals(oid, AlgorithmIdentifier.Sha384.Oid, StringComparison.Ordinal) => new CBAdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha384),
        var oid when string.Equals(oid, AlgorithmIdentifier.Sha512.Oid, StringComparison.Ordinal) => new CBAdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha512),
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
