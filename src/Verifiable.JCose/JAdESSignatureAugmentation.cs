using System.Buffers;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Text;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;

namespace Verifiable.JCose;

/// <summary>
/// Names why an augmentation of a JAdES signature could not be performed.
/// </summary>
/// <remarks>
/// These are generator-side faults: an input the caller supplied that the level being reached cannot be built
/// from, mirroring <see cref="Verifiable.JCose.CBAdESAugmentationFailureKind"/>'s own rationale. A Table 1/Annex A
/// level-rule violation raised by
/// <see cref="JAdESLevelRules.EnsureConformant"/> is NOT re-classified into this enum — it propagates as its own
/// <see cref="ArgumentException"/> untouched, exactly like <see cref="JAdESHeaderRules.EnsureConformant"/>'s own
/// posture at creation.
/// </remarks>
public enum JAdESAugmentationFailureKind
{
    /// <summary>No failure has been classified.</summary>
    NotEvaluated = 0,

    /// <summary>The signature being augmented could not be parsed as a well-formed JAdES message, or its protected header/<c>etsiU</c> could not be decoded.</summary>
    MalformedEncoding = 1,

    //2 (formerly UnsupportedIncorporationMode) is RETIRED:
    //every verb now mints its new element in the CONTAINER'S OWN mode -- clear-JSON or base64url alike -- so no
    //verb refuses augmentation on an already-base64url-incorporated etsiU any longer. Not reused, to keep every
    //historical reference to this value's old meaning unambiguous.

    /// <summary>
    /// A caller-supplied certificate could not be read to check its validity window — either the carrier is not
    /// tagged as an X.509 certificate, or its DER encoding does not parse as one.
    /// </summary>
    SigningCertificateMalformed = 3,

    /// <summary>
    /// Additional requirement (d) is violated: the acquired <c>sigTst</c> token's generation time falls outside
    /// the signing certificate's validity window (before <c>notBefore</c> or after <c>notAfter</c>).
    /// </summary>
    SigningCertificateNotValidAtTimestamp = 4,

    /// <summary>
    /// Additional requirement (d) is violated: the acquired <c>sigTst</c> token's generation time falls at or
    /// after the caller-supplied instant the signing certificate is known to have been revoked.
    /// </summary>
    SigningCertificateRevokedBeforeTimestamp = 5,

    /// <summary>A supplied certificate, CRL, or OCSP response carrier is not of the kind the placement admits.</summary>
    UnsupportedValidationObject = 6,

    /// <summary>
    /// A caller-supplied certificate to reference in <c>xRefs</c> is the JAdES signature's own signing
    /// certificate (JA-A.1.1-02).
    /// </summary>
    SigningCertificateReferenceRefused = 7,

    /// <summary>
    /// A <c>sigRTst</c> or <c>rfsTst</c> element was requested with none of <c>xRefs</c>/<c>rRefs</c>/
    /// <c>axRefs</c>/<c>arRefs</c> present in <c>etsiU</c> (JA-A.1.5.1.1-04/JA-A.1.5.2.1-04).
    /// </summary>
    ReferencesElementRequired = 8,

    /// <summary>
    /// <see cref="JAdESSignatureAugmentation.AddReferencesAsync"/>,
    /// <see cref="JAdESSignatureAugmentation.AddSignatureAndReferencesTimestampAsync"/>, or
    /// <see cref="JAdESSignatureAugmentation.AddReferencesTimestampAsync"/> was called with a declared
    /// <c>TargetLevel</c> of <see cref="Verifiable.Cryptography.Pki.AdESBaselineLevel.BLT"/> or above — the whole
    /// <c>xRefs</c>/<c>rRefs</c>/<c>axRefs</c>/<c>arRefs</c>/<c>sigRTst</c>/<c>rfsTst</c> family is hard-forbidden
    /// from B-LT on (JA-6.3-29/-31/-33/-35/-36/-37), checked before any digest computation or Time-Stamping
    /// Authority round trip so a doomed call never bills one.
    /// </summary>
    ReferencesFamilyNotPermittedAtTargetLevel = 9,

    /// <summary>
    /// <see cref="JAdESSignatureAugmentation.AddArchiveTimestampAsync"/> was called with a declared
    /// <c>TargetLevel</c> other than <see cref="Verifiable.Cryptography.Pki.AdESBaselineLevel.BLTA"/> — <c>arcTst</c>
    /// is the should-not <c>"*"</c> shape at B-B/B-T/B-LT (JA-6.3-42) and this producer mints only the
    /// hard-mandatory B-LTA shape (write-strict). Checked immediately after the parse, before any digest
    /// computation or Time-Stamping Authority round trip.
    /// </summary>
    ArchiveTimestampNotPermittedAtTargetLevel = 10,

    /// <summary>
    /// Additional requirement (m) (JA-6.3-m1/m2) is not satisfied before generating a new <c>arcTst</c>: the
    /// caller has not attested completeness of the validation material required for validating the signing
    /// certificate, any countersignature, any attribute certificate/signed assertion, or any prior electronic
    /// time-stamp's signing certificate (<see cref="Verifiable.JCose.JAdESArchiveTimestampContext.ChainCompletenessAttested"/>).
    /// This call cannot itself build or verify a certificate chain (the no-chain-building/no-HTTP library
    /// doctrine). Letter (k) (JA-6.3-k, "validation data should not be embedded in the electronic time-stamp
    /// itself") is a DIFFERENT, SHOULD-NOT placement preference over WHERE validation data lives, not this gate's
    /// completeness-before-arcTst SHALL — see <see cref="JAdESValidationDataContext.Placement"/>'s own remarks
    /// for that preference's write-side home.
    /// </summary>
    ArchiveTimestampValidationMaterialIncomplete = 11,

    /// <summary>
    /// <see cref="JAdESSignatureAugmentation.AddArchiveTimestampAsync"/> was called against a signature that
    /// carries no <c>sigTst</c> instance yet — Table 1's cumulative <c>sigTst</c>-from-B-T-onward requirement
    /// (JA-6.3-26) is the B-LTA ladder's own prerequisite. Refused here, structurally, before any Time-Stamping
    /// Authority round trip.
    /// </summary>
    ArchiveTimestampSignatureTimestampPrerequisiteMissing = 12,

    /// <summary>
    /// <see cref="JAdESSignatureAugmentation.AddArchiveTimestampAsync"/> was called against a signature that
    /// still carries an <c>xRefs</c>, <c>rRefs</c>, <c>axRefs</c>, <c>arRefs</c>, <c>sigRTst</c>, or <c>rfsTst</c>
    /// element — Table 1 hard-forbids the whole family from B-LT onward (JA-6.3-29/-31/-33/-35/-36/-37), and this
    /// call's own <see cref="ArchiveTimestampNotPermittedAtTargetLevel"/> gate above already fixes the declared
    /// level at B-LTA, so any such element still incorporated is forbidden outright. Refused here, structurally,
    /// before any Time-Stamping Authority round trip.
    /// </summary>
    ArchiveTimestampReferencesFamilyElementPresent = 13
}


/// <summary>
/// The generator-side fault of a JAdES augmentation.
/// </summary>
/// <remarks>
/// Creation and augmentation report faults as exceptions, following the signing surfaces already in this
/// library, because a generator handing in material a level cannot be built from is a composition fault of the
/// caller rather than an adversarial input to be classified and reported. Mirrors
/// <see cref="Verifiable.JCose.CBAdESAugmentationException"/>'s shape exactly.
/// </remarks>
[DebuggerDisplay("JAdESAugmentationException({FailureKind}): {Message}")]
public sealed class JAdESAugmentationException: Exception
{
    /// <summary>Gets what could not be done.</summary>
    public JAdESAugmentationFailureKind FailureKind { get; }


    /// <summary>Initializes a new <see cref="JAdESAugmentationException"/> with an unclassified malformed input.</summary>
    public JAdESAugmentationException(): this(JAdESAugmentationFailureKind.MalformedEncoding, "The JAdES signature could not be augmented.")
    {
    }


    /// <summary>Initializes a new <see cref="JAdESAugmentationException"/> with an unclassified malformed input.</summary>
    /// <param name="message">The message describing the fault.</param>
    public JAdESAugmentationException(string message): this(JAdESAugmentationFailureKind.MalformedEncoding, message)
    {
    }


    /// <summary>Initializes a new <see cref="JAdESAugmentationException"/> with an unclassified malformed input.</summary>
    /// <param name="message">The message describing the fault.</param>
    /// <param name="innerException">The exception that caused it.</param>
    public JAdESAugmentationException(string message, Exception innerException): this(JAdESAugmentationFailureKind.MalformedEncoding, message, innerException)
    {
    }


    /// <summary>Initializes a new <see cref="JAdESAugmentationException"/>.</summary>
    /// <param name="failureKind">What could not be done.</param>
    /// <param name="message">The message describing the fault.</param>
    public JAdESAugmentationException(JAdESAugmentationFailureKind failureKind, string message): base(message)
    {
        FailureKind = failureKind;
    }


    /// <summary>Initializes a new <see cref="JAdESAugmentationException"/>.</summary>
    /// <param name="failureKind">What could not be done.</param>
    /// <param name="message">The message describing the fault.</param>
    /// <param name="innerException">The exception that caused it.</param>
    public JAdESAugmentationException(JAdESAugmentationFailureKind failureKind, string message, Exception innerException): base(message, innerException)
    {
        FailureKind = failureKind;
    }
}


/// <summary>
/// The validation material a <see cref="JAdESSignatureAugmentation.AddValidationDataAsync"/> call (or an
/// <see cref="JAdESArchiveTimestampContext.GapFillValidationMaterial"/> gap-fill) places into a signature's
/// <c>xVals</c>/<c>rVals</c>/<c>anyValData</c> — clause 5.3.5.2-5.3.5.6's certificate and revocation values,
/// mirroring <see cref="Verifiable.JCose.CBAdESValidationMaterial"/>'s own shape and ownership rule exactly.
/// </summary>
/// <remarks>
/// The carriers belong to the caller for the whole call and are not disposed by anything here: an augmentation
/// borrows the octets it places for the duration of the call — long enough to serialize them into the augmented
/// signature's own wire bytes — and never takes ownership of what it was shown.
/// </remarks>
public sealed class JAdESValidationMaterial
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
    public static JAdESValidationMaterial None { get; } = new();
}


/// <summary>
/// Which <c>etsiU</c> container <see cref="JAdESSignatureAugmentation.AddValidationDataAsync"/> places validation
/// material into — clause 5.3.5.1 NOTE 2's own "use-case or policy dependent" disjunction between the
/// per-purpose containers and the unified one.
/// </summary>
/// <remarks>
/// <strong>Letter (k)'s write-side preference (JA-6.3-k, SHOULD NOT).</strong> "The validation data for
/// electronic time-stamps should not be embedded in the electronic time-stamp itself" — a placement preference
/// FOR this type's own two arms (<c>tstVD</c> via <see cref="SeparateXValsAndRVals"/>'s companion tstVD verb, or
/// <see cref="AnyValData"/>) OVER letting a time-stamp token's own embedded certificate/revocation material be
/// the sole carrier (<see cref="JAdESValidationDataContext.AnyTimestampTokenCarriesEmbeddedValidationMaterial"/>'s
/// fallback). Never enforced as a violation (<see cref="JAdESLevelRules"/>'s own disclosed-not-enforced posture
/// for this letter) — a caller choosing to rely solely on embedded material is conformant, merely against the
/// SHOULD-NOT. Not to be confused with letter (m)'s unrelated pre-<c>arcTst</c> completeness SHALL (JA-6.3-m1/m2,
/// <see cref="JAdESArchiveTimestampContext.ChainCompletenessAttested"/>) — the two letters cite different
/// obligations over different subject matter and are never combined.
/// </remarks>
public enum JAdESValidationDataPlacement
{
    /// <summary>Places certificates in a new <c>xVals</c> element and revocation data in a new <c>rVals</c> element (clauses 5.3.5.2/5.3.5.3).</summary>
    SeparateXValsAndRVals,

    /// <summary>
    /// Places both certificates and revocation data together in a single new <c>anyValData</c> element (clause
    /// 5.3.5.6). Also satisfies the "Incorporation of validation data for electronic time-stamps" service
    /// (JA-6.3-38/j) by construction, since <see cref="JAdESLevelRules.Check"/> recognizes an <c>anyValData</c>
    /// element as satisfying that service.
    /// </summary>
    AnyValData
}


/// <summary>
/// What one <see cref="JAdESSignatureAugmentation.AddSignatureTimestampAsync"/> call needs: the signature, how to
/// reach a Time-Stamping Authority, and the additional-requirement-(d) signing-certificate-validity triple —
/// mirroring <see cref="Verifiable.JCose.CBAdESSignatureTimestampContext"/>'s own shape. Unlike its CB-AdES
/// sibling, no message-imprint ALGORITHM travels here: JA-5.3.4-04 states the imprint input is the base64url-
/// encoded JWS Signature Value TEXT itself, not a digest this call computes under a caller-chosen algorithm —
/// the digest <see cref="TsaUri"/>'s authority is asked to compute is the Time-Stamping Authority's own concern
/// (RFC 3161's <c>messageImprint</c>), mirrored here only via the registered digest delegate
/// <see cref="TimestampAcquisition.AcquireAsync"/> itself resolves from the acquired token — this context still
/// names an algorithm below for THAT purpose (the octets this call hashes before asking the authority to
/// time-stamp them).
/// </summary>
[DebuggerDisplay("JAdESSignatureTimestampContext(TargetLevel={TargetLevel})")]
public sealed class JAdESSignatureTimestampContext
{
    /// <summary>Gets the JAdES wire bytes to augment (any of the three JWS serializations). Not modified; the result is new wire bytes.</summary>
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
    /// Gets the signer's own certificate, whose validity window additional requirement (d) checks the acquired
    /// token's generation time against. Required when <see cref="EnforceSigningCertificateValidity"/> is
    /// <see langword="true"/> (the default).
    /// </summary>
    public PkiCertificateMemory? SigningCertificate { get; init; }

    /// <summary>
    /// Gets the instant the signing certificate is known to have been revoked, or <see langword="null"/> when
    /// none is known. When supplied, requirement (d) additionally requires the acquired token's generation time
    /// to precede it.
    /// </summary>
    public DateTimeOffset? SigningCertificateRevokedAt { get; init; }

    /// <summary>
    /// Gets whether the acquired token's generation time is checked against <see cref="SigningCertificate"/>'s
    /// validity window and <see cref="SigningCertificateRevokedAt"/> (additional requirement (d)). Default
    /// <see langword="true"/> — the secure default; a caller opts out explicitly.
    /// </summary>
    public bool EnforceSigningCertificateValidity { get; init; } = true;

    /// <summary>
    /// Gets the level this call is raising the signature to (or holding it at, for a repeated multi-TSA call,
    /// Table 1 NOTE 7). Unlike CB-AdES's own duplicated-zero-sub-line reading at B-LT/B-LTA, Table 1's
    /// <c>sigTst</c> row (JA-6.3-26) states its cardinality as a single two-part cell — "B-B: ≥ 0 /
    /// B-T,B-LT,B-LTA: ≥ 1" — a cumulative floor, never a duplicated zero sub-line at B-LT/B-LTA (see
    /// <see cref="Verifiable.Cryptography.Pki.JAdESBaselineLevelTable.SigTst"/>'s own remarks, independently
    /// corroborating this reading): the specification text supplies no basis for a gate forbidding a new
    /// <c>sigTst</c> instance once the declared level reaches B-LT the way CB-AdES's own reading forbids one,
    /// so this context carries no such gate.
    /// </summary>
    public required AdESBaselineLevel TargetLevel { get; init; }
}


/// <summary>
/// What one <see cref="JAdESSignatureAugmentation.AddValidationDataAsync"/> call needs: the signature, the
/// certificates/CRLs/OCSP responses to place, which container to place them in, the dedup default, the
/// caller-attested embedded-material fact letter j/JA-6.3-38 needs when <see cref="Placement"/> does not itself
/// satisfy that service, and the level being reached.
/// </summary>
[DebuggerDisplay("JAdESValidationDataContext(TargetLevel={TargetLevel})")]
public sealed class JAdESValidationDataContext
{
    /// <summary>Gets the JAdES wire bytes to augment. Not modified; the result is new wire bytes.</summary>
    public required ReadOnlyMemory<byte> WireBytes { get; init; }

    /// <summary>Gets the validation material to place; see <see cref="JAdESValidationMaterial"/>.</summary>
    public required JAdESValidationMaterial Material { get; init; }

    /// <summary>
    /// Gets whether a candidate is skipped when it byte-equals (DER) a certificate/CRL/OCSP response already
    /// present in an earlier <c>xVals</c>/<c>rVals</c>/<c>anyValData</c> element of this signature (letters e/i,
    /// both SHOULD). Default <see langword="true"/>; a caller opts out explicitly.
    /// </summary>
    public bool DeduplicateAgainstExisting { get; init; } = true;

    /// <summary>Gets which container the new material is placed in; see <see cref="JAdESValidationDataPlacement"/>.</summary>
    public JAdESValidationDataPlacement Placement { get; init; } = JAdESValidationDataPlacement.SeparateXValsAndRVals;

    /// <summary>
    /// Gets whether at least one electronic time-stamp token elsewhere in the signature is caller-attested to
    /// carry its own embedded certificate/revocation validation material — the JA-6.3-38/j "embedded in the
    /// electronic time-stamp itself" SPO. This call never inspects a token's own encoding to derive this fact
    /// itself. Irrelevant when <see cref="Placement"/> is <see cref="JAdESValidationDataPlacement.AnyValData"/>,
    /// which already satisfies the service by construction. Defaults to <see langword="false"/>.
    /// </summary>
    public bool AnyTimestampTokenCarriesEmbeddedValidationMaterial { get; init; }

    /// <summary>
    /// Gets the level this call is raising the signature to — typically B-LT, after the <c>xRefs</c>/<c>rRefs</c>/
    /// <c>axRefs</c>/<c>arRefs</c>/<c>sigRTst</c>/<c>rfsTst</c> family has already been removed (that family is
    /// hard-forbidden from B-LT on, JA-6.3-29/-31/-33/-35/-36/-37) — this call never removes it itself.
    /// </summary>
    public required AdESBaselineLevel TargetLevel { get; init; }
}


/// <summary>
/// What one <see cref="JAdESSignatureAugmentation.AddReferencesAsync"/> call needs: the signature, the signing
/// certificate the builder refuses to reference, the material to reference, the digest algorithm, and the level
/// being reached.
/// </summary>
/// <remarks>
/// The carriers belong to the caller for the whole call and are not disposed by anything here — a
/// <see cref="JAdESValidationMaterial"/>-matching ownership rule; only the DIGESTS this call computes over them
/// are new, owned material, which flows into the returned wire bytes.
/// </remarks>
[DebuggerDisplay("JAdESReferencesContext(TargetLevel={TargetLevel})")]
public sealed class JAdESReferencesContext
{
    /// <summary>Gets the JAdES wire bytes to augment. Not modified; the result is new wire bytes.</summary>
    public required ReadOnlyMemory<byte> WireBytes { get; init; }

    /// <summary>
    /// Gets the JAdES signature's own signing certificate —
    /// <see cref="JAdESSignatureAugmentation.AddReferencesAsync"/> refuses (JA-A.1.1-02) any
    /// <see cref="CertificatesToReference"/> entry that byte-equals it.
    /// </summary>
    public required PkiCertificateMemory SigningCertificate { get; init; }

    /// <summary>Gets the certificates to reference (<c>xRefs</c>), or <see langword="null"/>/empty to omit that member.</summary>
    public IReadOnlyList<PkiCertificateMemory>? CertificatesToReference { get; init; }

    /// <summary>Gets the CRLs to reference (<c>rRefs.crlRefs</c>), or <see langword="null"/>/empty to omit that member.</summary>
    public IReadOnlyList<PkiCertificateMemory>? CrlsToReference { get; init; }

    /// <summary>Gets the OCSP responses to reference (<c>rRefs.ocspRefs</c>), or <see langword="null"/>/empty to omit that member.</summary>
    public IReadOnlyList<PkiCertificateMemory>? OcspResponsesToReference { get; init; }

    /// <summary>Gets the digest algorithm every reference digest is computed under.</summary>
    public required PkiDigestAlgorithm MessageImprintAlgorithm { get; init; }

    /// <summary>Gets the level this call is raising the signature to — B-B or B-T (the whole family is hard-forbidden from B-LT).</summary>
    public required AdESBaselineLevel TargetLevel { get; init; }
}


/// <summary>
/// What one <see cref="JAdESSignatureAugmentation.AddSignatureAndReferencesTimestampAsync"/> or
/// <see cref="JAdESSignatureAugmentation.AddReferencesTimestampAsync"/> call needs — identical shape for both
/// (Annex A.1.5.1.2 and A.1.5.2.2 differ only in whether the signature value contributes).
/// </summary>
[DebuggerDisplay("JAdESReferencesFamilyTimestampContext(TargetLevel={TargetLevel})")]
public sealed class JAdESReferencesFamilyTimestampContext
{
    /// <summary>Gets the JAdES wire bytes to augment. Not modified; the result is new wire bytes.</summary>
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
    /// Gets the canonicalization-algorithm identifier this new element declares — required (JA-5.3.1-14, since
    /// every element built here is clear-JSON incorporated) because <c>sigRTst</c>/<c>rfsTst</c> are not
    /// the <c>sigTst</c>-only exception that clause carves out.
    /// </summary>
    public required string CanonAlg { get; init; }

    /// <summary>Gets the registered canonicalization delegate for building the message-imprint input over the qualifying prefix elements.</summary>
    public required JAdESCanonicalizeUnsignedElementDelegate Canonicalize { get; init; }

    /// <summary>Gets the level this call is raising the signature to — B-B or B-T (<c>sigRTst</c>/<c>rfsTst</c> are hard-forbidden from B-LT).</summary>
    public required AdESBaselineLevel TargetLevel { get; init; }
}


/// <summary>
/// One Time-Stamping Authority leg <see cref="JAdESSignatureAugmentation.AddArchiveTimestampAsync"/> contacts.
/// Letter l ("Each <c>arcTst</c> may contain more than one electronic time-stamp issued by different TSAs") is
/// modeled as ONE OR MORE entries of this type on a single call: the call mints exactly ONE new <c>arcTst</c>
/// instance carrying one token per configured leg, all over the SAME message imprint.
/// </summary>
[DebuggerDisplay("JAdESArchiveTimestampTsaLeg({TsaUri})")]
public sealed record JAdESArchiveTimestampTsaLeg
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
/// What one <see cref="JAdESSignatureAugmentation.AddArchiveTimestampAsync"/> call needs (clause 5.3.6.2.3's
/// message-imprint steps, composing <see cref="JAdESMessageImprints.BuildArchiveTimestampGenerationMessageImprintInputAsync"/>):
/// the signature, the imprint algorithm, the already-resolved payload contribution, the declared target level
/// (B-LTA only — write-strict), one or more Time-Stamping Authority legs (letter l), optional gap-fill validation
/// material, the signing certificate, and the additional-requirement-(m) completeness attestation.
/// </summary>
/// <remarks>
/// <strong>What this call CANNOT itself check.</strong> A full certificate chain and revocation status for the
/// signing certificate, any countersignature signing certificate, and any attribute certificate/signed assertion
/// is the caller's own responsibility, attested through <see cref="ChainCompletenessAttested"/> (the
/// no-chain-building/no-HTTP library doctrine) — this call performs no CMS-signer-certificate extraction over
/// already-incorporated time-stamp tokens (a disclosed limitation narrower than
/// <see cref="Verifiable.JCose.CBAdESSignatureAugmentation.AddArchiveTimestampAsync"/>'s own per-token structural
/// check, since JAdES's own text supplies no additional per-token wording beyond letter m's compound SHALL that
/// <see cref="ChainCompletenessAttested"/> already covers in full).
/// </remarks>
[DebuggerDisplay("JAdESArchiveTimestampContext(TargetLevel={TargetLevel})")]
public sealed class JAdESArchiveTimestampContext
{
    /// <summary>Gets the JAdES wire bytes to augment. Not modified; the result is new wire bytes.</summary>
    public required ReadOnlyMemory<byte> WireBytes { get; init; }

    /// <summary>
    /// Gets the algorithm the message imprint is computed under — ONE digest, shared by every
    /// <see cref="TsaLegs"/> entry (letter l: several tokens issued over the SAME imprint).
    /// </summary>
    public required PkiDigestAlgorithm MessageImprintAlgorithm { get; init; }

    /// <summary>Gets the already-resolved payload contribution (clause 5.3.6.2.3 steps 1-2); see <see cref="JAdESArchiveTimestampPayloadSource"/>.</summary>
    public required JAdESArchiveTimestampPayloadSource PayloadSource { get; init; }

    /// <summary>
    /// Gets the one-or-more Time-Stamping Authority legs this call contacts (letter l): a new <c>arcTst</c>
    /// instance carries one token per configured leg, all over the SAME message imprint. Must be non-empty.
    /// </summary>
    public required IReadOnlyList<JAdESArchiveTimestampTsaLeg> TsaLegs { get; init; }

    /// <summary>
    /// Gets the validation material to gap-fill into a new <c>xVals</c>/<c>rVals</c> element BEFORE the message
    /// imprint is computed when the signature misses certificates/revocation data required for validating its
    /// signed objects, or <see langword="null"/>/<see cref="JAdESValidationMaterial.None"/> to gap-fill nothing.
    /// Composed through the SAME building blocks <see cref="JAdESSignatureAugmentation.AddValidationDataAsync"/>
    /// uses — never duplicated.
    /// </summary>
    public JAdESValidationMaterial? GapFillValidationMaterial { get; init; }

    /// <summary>
    /// Gets the JAdES signature's own signing certificate, whose readability this call checks before contacting
    /// any Time-Stamping Authority.
    /// </summary>
    public required PkiCertificateMemory SigningCertificate { get; init; }

    /// <summary>
    /// Gets whether the caller attests that every validation-material completeness need letter (m) (JA-6.3-m1/m2)
    /// imposes is satisfied — the signing certificate's own full chain and revocation status, any countersignature
    /// signing certificate, any attribute certificate/signed assertion, and any previously-incorporated electronic
    /// time-stamp's own signing certificate. Defaults to <see langword="false"/> (fail-closed): an unattested
    /// call refuses before contacting any Time-Stamping Authority, citing letter m. (Letter (k)'s own SHOULD-NOT
    /// preference against embedding validation data in the token is unrelated — see
    /// <see cref="JAdESValidationDataPlacement"/>'s own remarks.)
    /// </summary>
    public bool ChainCompletenessAttested { get; init; }

    /// <summary>Gets the canonicalization-algorithm identifier this new <c>arcTst</c> element declares (JA-5.3.1-14).</summary>
    public required string CanonAlg { get; init; }

    /// <summary>Gets the registered canonicalization delegate for building the message-imprint input over every already-incorporated <c>etsiU</c> element.</summary>
    public required JAdESCanonicalizeUnsignedElementDelegate Canonicalize { get; init; }

    /// <summary>
    /// Gets whether at least one electronic time-stamp token elsewhere in the signature is caller-attested to
    /// carry its own embedded certificate/revocation validation material — the JA-6.3-38/j "embedded in the
    /// electronic time-stamp itself" SPO. Irrelevant when a <c>tstVD</c>/<c>anyValData</c> element is already
    /// present (that satisfies the service by construction); consulted only as the fallback
    /// <see cref="JAdESLevelRules.EnsureConformant"/> checks when neither is present. Defaults to
    /// <see langword="false"/> — the fail-closed default.
    /// </summary>
    public bool AnyTimestampTokenCarriesEmbeddedValidationMaterial { get; init; }

    /// <summary>
    /// Gets the level this call is raising the signature to — shall be
    /// <see cref="Verifiable.Cryptography.Pki.AdESBaselineLevel.BLTA"/> (write-strict; a typed refusal
    /// otherwise, checked before any Time-Stamping Authority round trip).
    /// </summary>
    public required AdESBaselineLevel TargetLevel { get; init; }
}


/// <summary>
/// Raises an existing JAdES-B-B signature to B-T/B-LT/B-LTA per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
/// ETSI TS 119 182-1 V1.2.1</see>: <c>sigTst</c> (clause 5.3.4), <c>xVals</c>/<c>rVals</c>/<c>anyValData</c>
/// (clauses 5.3.5.2/5.3.5.3/5.3.5.6), <c>xRefs</c>/<c>rRefs</c> (Annex A.1.1/A.1.2), <c>sigRTst</c>/<c>rfsTst</c>
/// (Annex A.1.5.1/A.1.5.2), and <c>arcTst</c> (clause 5.3.6.2) — the augmentation half of the level-aware surface, mirroring
/// <see cref="Verifiable.JCose.CBAdESSignatureAugmentation"/>'s gate-ladder discipline one document over.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Every verb parses, appends to the DECODED model, and re-serializes; nothing is mutated in place.</strong>
/// Unlike <see cref="Verifiable.JCose.CBAdESSignatureAugmentation"/>'s CBOR substrate, JAdES's dual-mode
/// <c>etsiU</c> carrier (<see cref="JAdESOpaqueUnsignedValue{TValue}"/>) already gives byte-exact preservation of
/// RETAINED base64url-incorporated elements on re-encode, since the opaque arm holds the element's own wire TEXT
/// verbatim rather than a decoded-then-re-encoded value — no raw-splice seam analogous to
/// <c>TrySpliceCBAdESUnprotectedHeaderDelegate</c> is needed here. Every verb below therefore: parses the
/// caller-supplied wire bytes through <see cref="TryParseJAdESMessageDelegate"/>/<see cref="DecodeJAdESProtectedHeaderDelegate"/>/
/// <see cref="TryParseJAdESEtsiUDelegate"/> (fail-closed; a parse failure here is a CALLER composition fault, not
/// untrusted input, so it is reported as <see cref="JAdESAugmentationException"/> rather than collected); builds
/// the new <c>etsiU</c> element it needs; appends through <see cref="JAdESUnsignedHeaders.Append"/> (or a fresh
/// container when none existed); and re-serializes via <see cref="JwsSerialization.Serialize"/> into brand-new
/// wire bytes: the protected header text and JWS Signature Value are carried through byte-for-byte (unsigned-
/// header augmentation never re-signs). A Compact-serialized input is promoted to Flattened JSON on the way out,
/// since a non-empty JWS Unprotected Header forbids Compact serialization (JA-4-05) and every verb here adds one.
/// </para>
/// <para>
/// <strong>Mode-neutral augmentation.</strong> Every verb
/// below mints its NEW element in the CONTAINER'S own mode (an existing <c>etsiU</c>'s <see cref="JAdESUnsignedHeaders.Mode"/>,
/// or <see cref="JAdESEtsiUIncorporationMode.ClearJson"/> when bootstrapping the very first element of a fresh
/// container — no established mode to inherit). Under <see cref="JAdESEtsiUIncorporationMode.ClearJson"/> the new
/// element wraps its decoded value directly (<see cref="JAdESClearUnsignedValue{TValue}"/>); under
/// <see cref="JAdESEtsiUIncorporationMode.Base64Url"/> it is built as a <see cref="JAdESOpaqueUnsignedValue{TValue}"/>
/// whose wire text is produced by routing a throwaway single-element clear-JSON probe container through the
/// ALREADY-REGISTERED <c>encodeUnprotectedHeader</c>/<c>jsonSerializer</c>/<c>base64UrlEncoder</c> seams (this
/// class has no leaf-crossing access of its own to <c>Verifiable.Json</c>'s per-kind JSON codecs, this library's
/// firewall) — see <see cref="BuildElementInMode{TValue}"/>. Retained elements are never touched: they stay
/// verbatim through <see cref="JAdESUnsignedHeaders.Append"/>'s own object-sharing (byte-exact by construction).
/// No verb below refuses augmentation on an already-base64url-incorporated <c>etsiU</c> any longer.
/// </para>
/// <para>
/// <strong>Ownership discipline across <see cref="JAdESUnsignedHeaders.Append"/>.</strong>
/// <see cref="JAdESUnsignedHeaders.Append"/> SHARES every prior element's object reference with the new
/// container it returns. Every verb below therefore tracks exactly ONE "working" container variable, reassigned
/// to each successively-built container as the verb proceeds, and disposes only that LATEST reference in its
/// <c>finally</c> block — disposing an earlier, now-superseded reference in addition would double-dispose the
/// shared elements (a real hazard here: several element kinds own real pooled <c>PooledMemory</c>/<c>DigestValue</c>
/// carriers through their dual-mode carriage).
/// </para>
/// <para>
/// <strong>One rule implementation, throw posture.</strong> After building the candidate new <c>etsiU</c> state,
/// every verb calls <see cref="JAdESLevelRules.EnsureConformant"/> — the SAME rule surface a validation
/// orchestrator would call in collect posture — over that candidate state at the caller-declared
/// <see cref="AdESBaselineLevel"/>. A resulting rule violation propagates as <see cref="JAdESLevelRules.EnsureConformant"/>'s
/// own <see cref="ArgumentException"/> UNCHANGED — it is not re-wrapped into <see cref="JAdESAugmentationException"/>.
/// </para>
/// </remarks>
public static class JAdESSignatureAugmentation
{
    /// <summary>
    /// Raises a signature to JAdES-B-T (or holds it there for a repeated multi-TSA call, Table 1 NOTE 7):
    /// obtains a time-stamp token over the base64url-encoded JWS Signature Value from the caller's Time-Stamping
    /// Authority (JA-5.3.4-04), verifies it, and incorporates it as a new <c>sigTst</c> element of <c>etsiU</c>.
    /// </summary>
    /// <param name="context">The signature, the imprint algorithm, the authority to contact, and the target level.</param>
    /// <param name="parse">The fail-closed JAdES message parse seam (any of the three JWS serializations).</param>
    /// <param name="decodeProtectedHeader">The JAdES-typed protected-header decode seam.</param>
    /// <param name="parseEtsiU">The <c>etsiU</c> unsigned-header decode seam.</param>
    /// <param name="encodeUnprotectedHeader">The <c>etsiU</c> unprotected-header projection seam.</param>
    /// <param name="base64UrlDecoder">Delegate for base64url-decoding.</param>
    /// <param name="base64UrlEncoder">Delegate for base64url-encoding.</param>
    /// <param name="jsonSerializer">Delegate for serializing the JSON forms.</param>
    /// <param name="pool">The memory pool every carrier is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The augmented signature's new wire bytes.</returns>
    /// <exception cref="ArgumentNullException">When a required argument is <see langword="null"/>.</exception>
    /// <exception cref="JAdESAugmentationException">
    /// When <paramref name="context"/>'s wire bytes cannot be parsed
    /// (<see cref="JAdESAugmentationFailureKind.MalformedEncoding"/>); when
    /// <see cref="JAdESSignatureTimestampContext.SigningCertificate"/> is not readable as an X.509 certificate
    /// (<see cref="JAdESAugmentationFailureKind.SigningCertificateMalformed"/>, likewise checked first); or
    /// additional requirement (d) is not satisfied by the acquired token, which necessarily follows the round trip
    /// (<see cref="JAdESAugmentationFailureKind.SigningCertificateNotValidAtTimestamp"/>/
    /// <see cref="JAdESAugmentationFailureKind.SigningCertificateRevokedBeforeTimestamp"/>).
    /// </exception>
    /// <exception cref="Verifiable.Cryptography.Pki.TimestampAcquisitionException">
    /// When the authority could not be reached, or the token it returned does not verify.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// When the resulting <c>etsiU</c> fails <see cref="JAdESLevelRules.EnsureConformant"/> at
    /// <see cref="JAdESSignatureTimestampContext.TargetLevel"/>.
    /// </exception>
    /// <remarks>
    /// Letter c ("each <c>sigTst</c> shall contain only one electronic time-stamp") holds by construction: this
    /// call always builds a <see cref="AdESTimestampContainer"/> with exactly one <see cref="AdESTimestampToken"/>;
    /// a second Time-Stamping Authority is a second call (Table 1 NOTE 7, multi-TSA), appending a second, sibling
    /// <c>sigTst</c> element, never a second token inside one container.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "container/element become reachable through workingUnsignedHeaders once appended (or " +
            "the fresh single-element container built when none existed), disposed in the finally below via " +
            "workingUnsignedHeaders?.Dispose(), cascading over every element it reaches. Roslyn cannot trace " +
            "ownership through AppendOne/the array-literal constructor to that later disposal -- and " +
            "AdESTimestampContainer.Dispose is currently a no-op regardless (see that type's own remarks).")]
    public static async ValueTask<byte[]> AddSignatureTimestampAsync(
        JAdESSignatureTimestampContext context,
        TryParseJAdESMessageDelegate parse,
        DecodeJAdESProtectedHeaderDelegate decodeProtectedHeader,
        TryParseJAdESEtsiUDelegate parseEtsiU,
        EncodeJAdESUnprotectedHeaderDelegate encodeUnprotectedHeader,
        DecodeDelegate base64UrlDecoder,
        EncodeDelegate base64UrlEncoder,
        Func<object, byte[]> jsonSerializer,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(encodeUnprotectedHeader);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(jsonSerializer);
        ArgumentNullException.ThrowIfNull(pool);

        AugmentationParseResult parsed = ParseForAugmentation(context.WireBytes, parse, decodeProtectedHeader, parseEtsiU, base64UrlDecoder, pool);
        using UnverifiedJAdESMessage message = parsed.Message;
        using JAdESProtectedHeaders headers = parsed.ProtectedHeaders;
        JAdESUnsignedHeaders? workingUnsignedHeaders = parsed.UnsignedHeaders;

        CertificateValidityPeriod? signingCertificateValidity = ReadSigningCertificateValidityOrThrow(
            context.SigningCertificate, context.EnforceSigningCertificateValidity);

        AcquiredTimestampToken? token = null;
        try
        {
            UnverifiedJwsSignature signature = message.Wire.Signatures[0];
            string signatureValueBase64Url = base64UrlEncoder(signature.SignatureBytes.Memory.Span);
            using PooledMemory signatureValueBytes = RentAsciiBytes(signatureValueBase64Url, CryptoTags.JoseEncodedSignatureValue, pool);

            using DigestValue imprint = await CryptographicKeyEvents.ComputeDigestAsync(
                signatureValueBytes.AsReadOnlyMemory(), context.MessageImprintAlgorithm.OutputByteLength,
                context.MessageImprintAlgorithm.DigestTag, pool, cancellationToken: cancellationToken).ConfigureAwait(false);

            token = await TimestampAcquisition.AcquireAsync(
                imprint, context.TsaUri, context.FetchResponse, pool,
                context.ReqPolicyOid, context.NonceByteLength, context.IncludeNonce, cancellationToken).ConfigureAwait(false);

            EnsureSigningCertificateValidAtTimestamp(token, signingCertificateValidity, context.SigningCertificateRevokedAt);

            var container = new AdESTimestampContainer([new AdESTimestampToken { Val = token.Token.AsReadOnlyMemory() }]);
            JAdESEtsiUIncorporationMode mode = TargetMode(workingUnsignedHeaders);
            JAdESUnsignedHeaderElement element = BuildElementInMode(
                mode,
                static carriage => new JAdESUnsignedHeaderElementSignatureTimestamp(carriage),
                probeValue: container, finalValue: container,
                encodeUnprotectedHeader, base64UrlEncoder, jsonSerializer, pool);

            workingUnsignedHeaders = workingUnsignedHeaders is null
                ? new JAdESUnsignedHeaders(mode, [element])
                : workingUnsignedHeaders.Append(element);

            JAdESLevelRules.EnsureConformant(new JAdESLevelRuleContext
            {
                Level = context.TargetLevel,
                UnsignedHeaders = workingUnsignedHeaders,
                ProtectedHeaders = headers
            });

            return SerializeAugmented(message, workingUnsignedHeaders, encodeUnprotectedHeader, base64UrlEncoder, jsonSerializer, pool);
        }
        finally
        {
            token?.Dispose();
            workingUnsignedHeaders?.Dispose();
        }
    }


    /// <summary>
    /// Raises a signature to JAdES-B-LT: places caller-supplied certificates/revocation data into a new
    /// <c>xVals</c>/<c>rVals</c> pair or a new <c>anyValData</c> element (clauses 5.3.5.2/5.3.5.3/5.3.5.6),
    /// skipping candidates already present elsewhere in the signature (letters e/i).
    /// </summary>
    /// <param name="context">The signature, the material to place, the placement choice, and the target level.</param>
    /// <param name="parse">The fail-closed JAdES message parse seam.</param>
    /// <param name="decodeProtectedHeader">The JAdES-typed protected-header decode seam.</param>
    /// <param name="parseEtsiU">The <c>etsiU</c> unsigned-header decode seam.</param>
    /// <param name="encodeUnprotectedHeader">The <c>etsiU</c> unprotected-header projection seam.</param>
    /// <param name="base64UrlDecoder">Delegate for base64url-decoding.</param>
    /// <param name="base64UrlEncoder">Delegate for base64url-encoding.</param>
    /// <param name="jsonSerializer">Delegate for serializing the JSON forms.</param>
    /// <param name="pool">The memory pool every carrier is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The augmented signature's new wire bytes.</returns>
    /// <exception cref="ArgumentNullException">When a required argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">
    /// When <paramref name="context"/>.<see cref="JAdESValidationDataContext.Material"/> names nothing to place,
    /// or the resulting <c>etsiU</c> fails <see cref="JAdESLevelRules.EnsureConformant"/> at
    /// <see cref="JAdESValidationDataContext.TargetLevel"/>.
    /// </exception>
    /// <exception cref="JAdESAugmentationException">
    /// When <paramref name="context"/>'s wire bytes cannot be parsed; or when a supplied object is not of the
    /// kind the placement admits (<see cref="JAdESAugmentationFailureKind.UnsupportedValidationObject"/>).
    /// </exception>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Each xVals/rVals/anyValData element AppendOne builds becomes reachable through the " +
            "returned workingUnsignedHeaders, disposed in the finally below. Roslyn cannot trace ownership " +
            "through AppendOne's own return-a-new-container shape to that later disposal.")]
    public static async ValueTask<byte[]> AddValidationDataAsync(
        JAdESValidationDataContext context,
        TryParseJAdESMessageDelegate parse,
        DecodeJAdESProtectedHeaderDelegate decodeProtectedHeader,
        TryParseJAdESEtsiUDelegate parseEtsiU,
        EncodeJAdESUnprotectedHeaderDelegate encodeUnprotectedHeader,
        DecodeDelegate base64UrlDecoder,
        EncodeDelegate base64UrlEncoder,
        Func<object, byte[]> jsonSerializer,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(context.Material);
        ArgumentNullException.ThrowIfNull(encodeUnprotectedHeader);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(jsonSerializer);
        ArgumentNullException.ThrowIfNull(pool);
        if(context.Material.IsEmpty)
        {
            throw new ArgumentException(
                "Placing validation data places at least one certificate, certificate revocation list, or OCSP response.",
                nameof(context));
        }

        cancellationToken.ThrowIfCancellationRequested();

        AugmentationParseResult parsed = ParseForAugmentation(context.WireBytes, parse, decodeProtectedHeader, parseEtsiU, base64UrlDecoder, pool);
        using UnverifiedJAdESMessage message = parsed.Message;
        using JAdESProtectedHeaders headers = parsed.ProtectedHeaders;
        JAdESUnsignedHeaders? workingUnsignedHeaders = parsed.UnsignedHeaders;

        JAdESEtsiUIncorporationMode mode = TargetMode(workingUnsignedHeaders);

        try
        {
            (JAdESCertificateValues? certificateValues, JAdESRevocationValues? revocationValues) =
                BuildValidationDataMembers(context.Material, workingUnsignedHeaders, context.DeduplicateAgainstExisting);

            if(certificateValues is not null || revocationValues is not null)
            {
                if(context.Placement == JAdESValidationDataPlacement.AnyValData)
                {
                    var anyValData = new JAdESValidationData(certificateValues, revocationValues);
                    workingUnsignedHeaders = AppendOne(workingUnsignedHeaders, BuildElementInMode(
                        mode,
                        static carriage => new JAdESUnsignedHeaderElementAnyValidationData(carriage),
                        probeValue: anyValData, finalValue: anyValData,
                        encodeUnprotectedHeader, base64UrlEncoder, jsonSerializer, pool));
                }
                else
                {
                    //Separate placement (JA-5.3.1-03 append-at-end order): xVals first, then rVals, each only
                    //when this call actually built one.
                    if(certificateValues is not null)
                    {
                        workingUnsignedHeaders = AppendOne(workingUnsignedHeaders, BuildElementInMode(
                            mode,
                            static carriage => new JAdESUnsignedHeaderElementCertificateValues(carriage),
                            probeValue: certificateValues, finalValue: certificateValues,
                            encodeUnprotectedHeader, base64UrlEncoder, jsonSerializer, pool));
                    }

                    if(revocationValues is not null)
                    {
                        workingUnsignedHeaders = AppendOne(workingUnsignedHeaders, BuildElementInMode(
                            mode,
                            static carriage => new JAdESUnsignedHeaderElementRevocationValues(carriage),
                            probeValue: revocationValues, finalValue: revocationValues,
                            encodeUnprotectedHeader, base64UrlEncoder, jsonSerializer, pool));
                    }
                }
            }

            //JAdESLevelRules.Check scans workingUnsignedHeaders itself for a tstVD/anyValData element (which the
            //AnyValData placement arm above just appended, when chosen) -- no need to duplicate that scan here;
            //only the embedded-in-token fact this call cannot derive on its own is threaded through.
            JAdESLevelRules.EnsureConformant(new JAdESLevelRuleContext
            {
                Level = context.TargetLevel,
                UnsignedHeaders = workingUnsignedHeaders,
                ProtectedHeaders = headers,
                AnyTimestampTokenCarriesEmbeddedValidationMaterial = context.AnyTimestampTokenCarriesEmbeddedValidationMaterial
            });

            //Producer symmetry (per the CB-A.1.1-30 precedent): the SAME async refs-resolution
            //check a validator's own widened JA-A.1.1-12/-A.1.2-35/-A.1.3-08/-A.1.4-10 trigger/candidate set
            //would apply, run here over this call's own (possibly gap-filled) state -- pre-serialize, so this
            //producer never mints a signature whose refs entries the validator would reject as unresolved.
            await JAdESLevelRules.EnsureReferencesResolveToValidationDataAsync(workingUnsignedHeaders, pool, cancellationToken).ConfigureAwait(false);

            //workingUnsignedHeaders is provably non-null here: context.Material is non-empty (checked above), and
            //when the parsed etsiU started null nothing could have been deduped away (there was nothing to dedupe
            //against), so at least one of certificateValues/revocationValues above was non-null and got appended.
            byte[] result = SerializeAugmented(message, workingUnsignedHeaders!, encodeUnprotectedHeader, base64UrlEncoder, jsonSerializer, pool);

            return result;
        }
        finally
        {
            workingUnsignedHeaders?.Dispose();
        }
    }


    /// <summary>
    /// Adds an <c>xRefs</c>/<c>rRefs</c> pair (Annex A.1.1/A.1.2): certificate and revocation-data digest
    /// references built from caller-supplied material, each digest computed via the registered digest delegate,
    /// refusing to reference the signature's own signing certificate (JA-A.1.1-02).
    /// </summary>
    /// <param name="context">The signature, the signing certificate, the material to reference, the digest algorithm, and the target level.</param>
    /// <param name="parse">The fail-closed JAdES message parse seam.</param>
    /// <param name="decodeProtectedHeader">The JAdES-typed protected-header decode seam.</param>
    /// <param name="parseEtsiU">The <c>etsiU</c> unsigned-header decode seam.</param>
    /// <param name="encodeUnprotectedHeader">The <c>etsiU</c> unprotected-header projection seam.</param>
    /// <param name="base64UrlDecoder">Delegate for base64url-decoding.</param>
    /// <param name="base64UrlEncoder">Delegate for base64url-encoding.</param>
    /// <param name="jsonSerializer">Delegate for serializing the JSON forms.</param>
    /// <param name="pool">The memory pool every carrier is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The augmented signature's new wire bytes.</returns>
    /// <exception cref="ArgumentNullException">When a required argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">
    /// When neither <c>xRefs</c> nor <c>rRefs</c> ends up with any entry, or the resulting <c>etsiU</c> fails
    /// <see cref="JAdESLevelRules.EnsureConformant"/> at <see cref="JAdESReferencesContext.TargetLevel"/>.
    /// </exception>
    /// <exception cref="JAdESAugmentationException">
    /// When <paramref name="context"/>'s wire bytes cannot be parsed; when the declared
    /// <see cref="JAdESReferencesContext.TargetLevel"/> is B-LT or above
    /// (<see cref="JAdESAugmentationFailureKind.ReferencesFamilyNotPermittedAtTargetLevel"/>, checked
    /// before any digest computation); when a supplied object is not of the kind <c>xRefs</c>/<c>rRefs</c>
    /// admits (<see cref="JAdESAugmentationFailureKind.UnsupportedValidationObject"/>); or when a candidate
    /// certificate byte-equals <see cref="JAdESReferencesContext.SigningCertificate"/>
    /// (<see cref="JAdESAugmentationFailureKind.SigningCertificateReferenceRefused"/>).
    /// </exception>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Each per-entry AdESCertificateThumbprint/collection/element this method constructs is " +
            "either (a) reachable through workingUnsignedHeaders once `transferred` is true -- disposed in the " +
            "finally below -- or (b) disposed explicitly by the catch clause's DisposeThumbprints calls over " +
            "certificateThumbprints/crlThumbprints/ocspThumbprints on any failure before `transferred` is set. " +
            "Roslyn cannot trace that two-way disposal split.")]
    public static async ValueTask<byte[]> AddReferencesAsync(
        JAdESReferencesContext context,
        TryParseJAdESMessageDelegate parse,
        DecodeJAdESProtectedHeaderDelegate decodeProtectedHeader,
        TryParseJAdESEtsiUDelegate parseEtsiU,
        EncodeJAdESUnprotectedHeaderDelegate encodeUnprotectedHeader,
        DecodeDelegate base64UrlDecoder,
        EncodeDelegate base64UrlEncoder,
        Func<object, byte[]> jsonSerializer,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(context.SigningCertificate);
        ArgumentNullException.ThrowIfNull(encodeUnprotectedHeader);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(jsonSerializer);
        ArgumentNullException.ThrowIfNull(pool);

        AugmentationParseResult parsed = ParseForAugmentation(context.WireBytes, parse, decodeProtectedHeader, parseEtsiU, base64UrlDecoder, pool);
        using UnverifiedJAdESMessage message = parsed.Message;
        using JAdESProtectedHeaders headers = parsed.ProtectedHeaders;
        JAdESUnsignedHeaders? workingUnsignedHeaders = parsed.UnsignedHeaders;

        EnsureReferencesFamilyPermittedAtTargetLevel(context.TargetLevel);

        JAdESEtsiUIncorporationMode mode = TargetMode(workingUnsignedHeaders);
        List<AdESCertificateThumbprint>? certificateThumbprints = null;
        List<AdESCertificateThumbprint>? crlThumbprints = null;
        List<AdESCertificateThumbprint>? ocspThumbprints = null;
        bool transferred = false;
        try
        {
            var digAlg = new AdESDigestAlgorithmTextIdentifier(ToDigAlgName(context.MessageImprintAlgorithm));

            if(context.CertificatesToReference is { Count: > 0 } certificatesToReference)
            {
                certificateThumbprints = new List<AdESCertificateThumbprint>(certificatesToReference.Count);
                for(int i = 0; i < certificatesToReference.Count; ++i)
                {
                    PkiCertificateMemory candidate = certificatesToReference[i];
                    EnsureKind(candidate.IsX509Certificate, JAdESAugmentationFailureKind.UnsupportedValidationObject,
                        "A certificate referenced in xRefs is a DER-encoded X.509 certificate (ETSI TS 119 182-1 V1.2.1, Annex A.1.1).");

                    if(candidate.AsReadOnlySpan().SequenceEqual(context.SigningCertificate.AsReadOnlySpan()))
                    {
                        throw new JAdESAugmentationException(
                            JAdESAugmentationFailureKind.SigningCertificateReferenceRefused,
                            "xRefs shall not contain the reference to the signing certificate (ETSI TS 119 182-1 V1.2.1, Annex A.1.1, JA-A.1.1-02).");
                    }

                    DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
                        candidate.AsReadOnlyMemory(), context.MessageImprintAlgorithm.OutputByteLength, context.MessageImprintAlgorithm.DigestTag,
                        pool, cancellationToken: cancellationToken).ConfigureAwait(false);
                    certificateThumbprints.Add(new AdESCertificateThumbprint(digAlg, digest));
                }
            }

            if(context.CrlsToReference is { Count: > 0 } crlsToReference)
            {
                crlThumbprints = new List<AdESCertificateThumbprint>(crlsToReference.Count);
                for(int i = 0; i < crlsToReference.Count; ++i)
                {
                    PkiCertificateMemory candidate = crlsToReference[i];
                    EnsureKind(candidate.IsCrl, JAdESAugmentationFailureKind.UnsupportedValidationObject,
                        "A certificate revocation list referenced in rRefs is a DER-encoded CertificateList (ETSI TS 119 182-1 V1.2.1, Annex A.1.2).");

                    DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
                        candidate.AsReadOnlyMemory(), context.MessageImprintAlgorithm.OutputByteLength, context.MessageImprintAlgorithm.DigestTag,
                        pool, cancellationToken: cancellationToken).ConfigureAwait(false);
                    crlThumbprints.Add(new AdESCertificateThumbprint(digAlg, digest));
                }
            }

            if(context.OcspResponsesToReference is { Count: > 0 } ocspResponsesToReference)
            {
                ocspThumbprints = new List<AdESCertificateThumbprint>(ocspResponsesToReference.Count);
                for(int i = 0; i < ocspResponsesToReference.Count; ++i)
                {
                    PkiCertificateMemory candidate = ocspResponsesToReference[i];
                    EnsureKind(candidate.IsOcspResponse, JAdESAugmentationFailureKind.UnsupportedValidationObject,
                        "An OCSP response referenced in rRefs is a DER-encoded OCSPResponse (ETSI TS 119 182-1 V1.2.1, Annex A.1.2).");

                    DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
                        candidate.AsReadOnlyMemory(), context.MessageImprintAlgorithm.OutputByteLength, context.MessageImprintAlgorithm.DigestTag,
                        pool, cancellationToken: cancellationToken).ConfigureAwait(false);
                    ocspThumbprints.Add(new AdESCertificateThumbprint(digAlg, digest));
                }
            }

            if(certificateThumbprints is null && crlThumbprints is null && ocspThumbprints is null)
            {
                throw new ArgumentException(
                    "AddReferencesAsync places at least one certificate or revocation-data reference.", nameof(context));
            }

            if(certificateThumbprints is not null)
            {
                var certificateReferences = new JAdESCertificateReferenceCollection(certificateThumbprints);
                workingUnsignedHeaders = AppendOne(workingUnsignedHeaders, BuildElementInMode(
                    mode,
                    static carriage => new JAdESUnsignedHeaderElementCertificateReferences(carriage),
                    probeValue: certificateReferences, finalValue: certificateReferences,
                    encodeUnprotectedHeader, base64UrlEncoder, jsonSerializer, pool));
            }

            if(crlThumbprints is not null || ocspThumbprints is not null)
            {
                var revocationReferences = new JAdESRevocationReferenceCollection(crlThumbprints, ocspThumbprints);
                workingUnsignedHeaders = AppendOne(workingUnsignedHeaders, BuildElementInMode(
                    mode,
                    static carriage => new JAdESUnsignedHeaderElementRevocationReferences(carriage),
                    probeValue: revocationReferences, finalValue: revocationReferences,
                    encodeUnprotectedHeader, base64UrlEncoder, jsonSerializer, pool));
            }

            transferred = true;

            JAdESLevelRules.EnsureConformant(new JAdESLevelRuleContext
            {
                Level = context.TargetLevel,
                UnsignedHeaders = workingUnsignedHeaders,
                ProtectedHeaders = headers
            });

            return SerializeAugmented(message, workingUnsignedHeaders!, encodeUnprotectedHeader, base64UrlEncoder, jsonSerializer, pool);
        }
        catch
        {
            //Ownership of certificateThumbprints/crlThumbprints/ocspThumbprints has not transferred anywhere yet
            //when `transferred` is still false (the failure happened before/while building the referencing
            //elements) -- every DigestValue already computed for a partial list must be disposed here, or its
            //pool rental leaks. Once `transferred` is true, these same lists are reachable through
            //workingUnsignedHeaders (disposed in the finally below), so disposing them again here would
            //double-dispose.
            if(!transferred)
            {
                DisposeThumbprints(certificateThumbprints);
                DisposeThumbprints(crlThumbprints);
                DisposeThumbprints(ocspThumbprints);
            }

            throw;
        }
        finally
        {
            workingUnsignedHeaders?.Dispose();
        }
    }


    /// <summary>Disposes every <see cref="AdESCertificateThumbprint"/> in <paramref name="thumbprints"/>, when supplied.</summary>
    private static void DisposeThumbprints(List<AdESCertificateThumbprint>? thumbprints)
    {
        if(thumbprints is null)
        {
            return;
        }

        for(int i = 0; i < thumbprints.Count; ++i)
        {
            thumbprints[i].Dispose();
        }
    }


    /// <summary>
    /// Adds a <c>sigRTst</c> element (Annex A.1.5.1): a time-stamp over the JWS Signature Value plus every
    /// qualifying reference-family <c>etsiU</c> element that PRECEDES this new element's own position — gated on
    /// at least one <c>xRefs</c>/<c>rRefs</c>/<c>axRefs</c>/<c>arRefs</c> already being present
    /// (JA-A.1.5.1.1-04). Generation and the not-yet-incorporated element's own prefix coincide by construction.
    /// </summary>
    /// <param name="context">The signature, the authority to contact, the canonicalization inputs, and the target level.</param>
    /// <param name="parse">The fail-closed JAdES message parse seam.</param>
    /// <param name="decodeProtectedHeader">The JAdES-typed protected-header decode seam.</param>
    /// <param name="parseEtsiU">The <c>etsiU</c> unsigned-header decode seam.</param>
    /// <param name="encodeUnprotectedHeader">The <c>etsiU</c> unprotected-header projection seam.</param>
    /// <param name="base64UrlDecoder">Delegate for base64url-decoding.</param>
    /// <param name="base64UrlEncoder">Delegate for base64url-encoding.</param>
    /// <param name="jsonSerializer">Delegate for serializing the JSON forms.</param>
    /// <param name="pool">The memory pool every carrier is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The augmented signature's new wire bytes.</returns>
    /// <exception cref="ArgumentNullException">When a required argument is <see langword="null"/>.</exception>
    /// <exception cref="JAdESAugmentationException">
    /// When <paramref name="context"/>'s wire bytes cannot be parsed; when the declared target level is B-LT or
    /// above (<see cref="JAdESAugmentationFailureKind.ReferencesFamilyNotPermittedAtTargetLevel"/>); or when no
    /// reference-family element precedes the would-be <c>sigRTst</c> element
    /// (<see cref="JAdESAugmentationFailureKind.ReferencesElementRequired"/>) — both checked before any
    /// Time-Stamping Authority round trip.
    /// </exception>
    /// <exception cref="Verifiable.Cryptography.Pki.TimestampAcquisitionException">When the authority could not be reached, or the token it returned does not verify.</exception>
    /// <exception cref="ArgumentException">When the resulting <c>etsiU</c> fails <see cref="JAdESLevelRules.EnsureConformant"/> at the declared target level.</exception>
    public static ValueTask<byte[]> AddSignatureAndReferencesTimestampAsync(
        JAdESReferencesFamilyTimestampContext context,
        TryParseJAdESMessageDelegate parse,
        DecodeJAdESProtectedHeaderDelegate decodeProtectedHeader,
        TryParseJAdESEtsiUDelegate parseEtsiU,
        EncodeJAdESUnprotectedHeaderDelegate encodeUnprotectedHeader,
        DecodeDelegate base64UrlDecoder,
        EncodeDelegate base64UrlEncoder,
        Func<object, byte[]> jsonSerializer,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(encodeUnprotectedHeader);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(jsonSerializer);
        ArgumentNullException.ThrowIfNull(pool);

        return AppendReferencesFamilyTimestampAsync(
            context, includeSignatureValue: true, parse, decodeProtectedHeader, parseEtsiU, encodeUnprotectedHeader,
            base64UrlDecoder, base64UrlEncoder, jsonSerializer, pool, cancellationToken);
    }


    /// <summary>
    /// Adds an <c>rfsTst</c> element (Annex A.1.5.2): identical to
    /// <see cref="AddSignatureAndReferencesTimestampAsync"/> minus the leading JWS Signature Value — the
    /// message imprint covers only the qualifying reference-family <c>etsiU</c> elements that PRECEDE this new
    /// element's own position (JA-A.1.5.2.1-04's identical gate).
    /// </summary>
    /// <param name="context">See <see cref="AddSignatureAndReferencesTimestampAsync"/>.</param>
    /// <param name="parse">See <see cref="AddSignatureAndReferencesTimestampAsync"/>.</param>
    /// <param name="decodeProtectedHeader">See <see cref="AddSignatureAndReferencesTimestampAsync"/>.</param>
    /// <param name="parseEtsiU">See <see cref="AddSignatureAndReferencesTimestampAsync"/>.</param>
    /// <param name="encodeUnprotectedHeader">See <see cref="AddSignatureAndReferencesTimestampAsync"/>.</param>
    /// <param name="base64UrlDecoder">See <see cref="AddSignatureAndReferencesTimestampAsync"/>.</param>
    /// <param name="base64UrlEncoder">See <see cref="AddSignatureAndReferencesTimestampAsync"/>.</param>
    /// <param name="jsonSerializer">See <see cref="AddSignatureAndReferencesTimestampAsync"/>.</param>
    /// <param name="pool">See <see cref="AddSignatureAndReferencesTimestampAsync"/>.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The augmented signature's new wire bytes.</returns>
    public static ValueTask<byte[]> AddReferencesTimestampAsync(
        JAdESReferencesFamilyTimestampContext context,
        TryParseJAdESMessageDelegate parse,
        DecodeJAdESProtectedHeaderDelegate decodeProtectedHeader,
        TryParseJAdESEtsiUDelegate parseEtsiU,
        EncodeJAdESUnprotectedHeaderDelegate encodeUnprotectedHeader,
        DecodeDelegate base64UrlDecoder,
        EncodeDelegate base64UrlEncoder,
        Func<object, byte[]> jsonSerializer,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(encodeUnprotectedHeader);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(jsonSerializer);
        ArgumentNullException.ThrowIfNull(pool);

        return AppendReferencesFamilyTimestampAsync(
            context, includeSignatureValue: false, parse, decodeProtectedHeader, parseEtsiU, encodeUnprotectedHeader,
            base64UrlDecoder, base64UrlEncoder, jsonSerializer, pool, cancellationToken);
    }


    /// <summary>
    /// Raises a signature to JAdES-B-LTA (or extends it with a new, later <c>arcTst</c> instance — a genuine
    /// renewal, or Table 1 letter l's multi-Time-Stamping-Authority pattern applied across separate calls):
    /// computes the clause 5.3.6.2.3 message imprint over every already-incorporated <c>etsiU</c> element,
    /// requests one electronic time-stamp token per configured Time-Stamping Authority leg (letter l), and
    /// incorporates all of them into ONE new <c>arcTst</c> element appended last.
    /// </summary>
    /// <param name="context">The signature, the imprint algorithm, the TSA legs, the declared target level, and the letter-(m) inputs.</param>
    /// <param name="parse">The fail-closed JAdES message parse seam.</param>
    /// <param name="decodeProtectedHeader">The JAdES-typed protected-header decode seam.</param>
    /// <param name="parseEtsiU">The <c>etsiU</c> unsigned-header decode seam.</param>
    /// <param name="encodeUnprotectedHeader">The <c>etsiU</c> unprotected-header projection seam.</param>
    /// <param name="base64UrlDecoder">Delegate for base64url-decoding.</param>
    /// <param name="base64UrlEncoder">Delegate for base64url-encoding.</param>
    /// <param name="jsonSerializer">Delegate for serializing the JSON forms.</param>
    /// <param name="pool">The memory pool every carrier is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The augmented signature's new wire bytes.</returns>
    /// <exception cref="ArgumentNullException">When a required argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When <see cref="JAdESArchiveTimestampContext.TsaLegs"/> is empty.</exception>
    /// <exception cref="JAdESAugmentationException">
    /// When <paramref name="context"/>'s wire bytes cannot be parsed; when the declared target level is not B-LTA
    /// (<see cref="JAdESAugmentationFailureKind.ArchiveTimestampNotPermittedAtTargetLevel"/>, checked before any
    /// Time-Stamping Authority round trip); when the signing certificate is not readable
    /// (<see cref="JAdESAugmentationFailureKind.SigningCertificateMalformed"/>); when no <c>sigTst</c> instance
    /// is incorporated yet (<see cref="JAdESAugmentationFailureKind.ArchiveTimestampSignatureTimestampPrerequisiteMissing"/>);
    /// when letter (m) is not attested
    /// (<see cref="JAdESAugmentationFailureKind.ArchiveTimestampValidationMaterialIncomplete"/>); or when a
    /// reference-family element is still incorporated
    /// (<see cref="JAdESAugmentationFailureKind.ArchiveTimestampReferencesFamilyElementPresent"/>) — every one
    /// of these checked before any Time-Stamping Authority round trip.
    /// </exception>
    /// <exception cref="Verifiable.Cryptography.Pki.TimestampAcquisitionException">When a configured authority could not be reached, or the token it returned does not verify.</exception>
    /// <exception cref="ArgumentException">When the resulting <c>etsiU</c> fails <see cref="JAdESLevelRules.EnsureConformant"/> at B-LTA.</exception>
    /// <remarks>
    /// <para>
    /// <strong>The gate ladder (transposed from <see cref="Verifiable.JCose.CBAdESSignatureAugmentation.AddArchiveTimestampAsync"/>'s
    /// seven-gate shape; only what JAdES's own text supports; the now-retired base64url-incorporation refusal
    /// is not one of these five).</strong> In order, all before any Time-Stamping Authority round trip:
    /// (1) the declared <see cref="JAdESArchiveTimestampContext.TargetLevel"/> must be
    /// <see cref="Verifiable.Cryptography.Pki.AdESBaselineLevel.BLTA"/> (JA-6.3-42); (2)
    /// <see cref="JAdESArchiveTimestampContext.SigningCertificate"/> must be readable — arcTst has no
    /// requirement-(d)-shaped genTime comparison of its own, so the returned validity window is read for
    /// readability alone and otherwise discarded; (3)
    /// <see cref="JAdESArchiveTimestampContext.ChainCompletenessAttested"/> must be <see langword="true"/>
    /// (letter m, JA-6.3-m1/m2); (4) at least one <c>sigTst</c> instance must already be incorporated (JA-6.3-26, the B-LTA
    /// ladder's own cumulative prerequisite); (5) no <c>xRefs</c>/<c>rRefs</c>/<c>axRefs</c>/<c>arRefs</c>/
    /// <c>sigRTst</c>/<c>rfsTst</c> element may still be incorporated (JA-6.3-29/-31/-33/-35/-36/-37 hard-forbid
    /// that whole family once the declared level is B-LT or above, and gate (1) above already fixes it at B-LTA).
    /// The new <c>arcTst</c> element itself mints in <c>etsiU</c>'s own existing mode — clear-JSON or
    /// base64url alike.
    /// </para>
    /// <para>
    /// <strong>Step 1's gap-fill.</strong> When <see cref="JAdESArchiveTimestampContext.GapFillValidationMaterial"/>
    /// is supplied, a new <c>xVals</c>/<c>rVals</c> element is appended to the working <c>etsiU</c> BEFORE the
    /// message imprint is built (reusing <see cref="BuildValidationDataMembers"/>, the same core
    /// <see cref="AddValidationDataAsync"/> uses), so the imprint genuinely covers it — order is normative.
    /// </para>
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Every gap-fill xVals/rVals element and the final container/element built from " +
            "acquiredTokens become reachable through workingUnsignedHeaders once appended, disposed in the " +
            "finally below. Roslyn cannot trace ownership through AppendOne to that later disposal -- and " +
            "AdESTimestampContainer.Dispose is currently a no-op regardless.")]
    public static async ValueTask<byte[]> AddArchiveTimestampAsync(
        JAdESArchiveTimestampContext context,
        TryParseJAdESMessageDelegate parse,
        DecodeJAdESProtectedHeaderDelegate decodeProtectedHeader,
        TryParseJAdESEtsiUDelegate parseEtsiU,
        EncodeJAdESUnprotectedHeaderDelegate encodeUnprotectedHeader,
        DecodeDelegate base64UrlDecoder,
        EncodeDelegate base64UrlEncoder,
        Func<object, byte[]> jsonSerializer,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(context.SigningCertificate);
        ArgumentNullException.ThrowIfNull(context.TsaLegs);
        ArgumentNullException.ThrowIfNull(encodeUnprotectedHeader);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(jsonSerializer);
        ArgumentNullException.ThrowIfNull(pool);
        if(context.TsaLegs.Count == 0)
        {
            throw new ArgumentException(
                "Letter l grounds arcTst's own token plurality on one or more configured Time-Stamping " +
                "Authorities; supply at least one leg (ETSI TS 119 182-1 V1.2.1, clause 6.3, additional requirement l).",
                nameof(context));
        }

        AugmentationParseResult parsed = ParseForAugmentation(context.WireBytes, parse, decodeProtectedHeader, parseEtsiU, base64UrlDecoder, pool);
        using UnverifiedJAdESMessage message = parsed.Message;
        using JAdESProtectedHeaders headers = parsed.ProtectedHeaders;
        JAdESUnsignedHeaders? workingUnsignedHeaders = parsed.UnsignedHeaders;

        //Gate (1): write-strict, checked immediately, before any digest computation or Time-Stamping Authority
        //round trip.
        if(context.TargetLevel != AdESBaselineLevel.BLTA)
        {
            workingUnsignedHeaders?.Dispose();
            throw new JAdESAugmentationException(
                JAdESAugmentationFailureKind.ArchiveTimestampNotPermittedAtTargetLevel,
                "A new arcTst instance is generated only when the declared TargetLevel is B-LTA (ETSI TS 119 182-1 V1.2.1, clause 6.3, Table 1, JA-6.3-42).");
        }

        JAdESEtsiUIncorporationMode mode = TargetMode(workingUnsignedHeaders);

        try
        {
            //Gate (2): readability alone -- arcTst has no requirement-(d)-shaped genTime comparison of its own.
            _ = ReadSigningCertificateValidityOrThrow(context.SigningCertificate, enforce: true);

            //Gate (3): letter (m) (JA-6.3-m1/m2), the caller-attested half -- this call cannot itself
            //build/verify a chain. Letter (k)'s own SHOULD-NOT preference (validation data should not be
            //embedded in the token itself) is a different, unenforced placement preference -- see
            //JAdESValidationDataPlacement's own remarks -- never this gate's completeness SHALL.
            if(!context.ChainCompletenessAttested)
            {
                throw new JAdESAugmentationException(
                    JAdESAugmentationFailureKind.ArchiveTimestampValidationMaterialIncomplete,
                    "Letter (m) requires all the validation material required for validating the JAdES " +
                    "signature to be included before generating a new arcTst; this call cannot itself build or " +
                    "verify a certificate chain, so the caller must attest that completeness is satisfied " +
                    "elsewhere (ETSI TS 119 182-1 V1.2.1, clause 6.3, additional requirement m, JA-6.3-m1/m2; set " +
                    "ChainCompletenessAttested = true once confirmed).");
            }

            //Step 1: the gap-fill, appended BEFORE the imprint is built so the imprint covers it (order is normative).
            if(context.GapFillValidationMaterial is { IsEmpty: false } gapFillMaterial)
            {
                (JAdESCertificateValues? gapFillCertificateValues, JAdESRevocationValues? gapFillRevocationValues) =
                    BuildValidationDataMembers(gapFillMaterial, workingUnsignedHeaders, dedupe: true);

                if(gapFillCertificateValues is not null)
                {
                    workingUnsignedHeaders = AppendOne(workingUnsignedHeaders, BuildElementInMode(
                        mode,
                        static carriage => new JAdESUnsignedHeaderElementCertificateValues(carriage),
                        probeValue: gapFillCertificateValues, finalValue: gapFillCertificateValues,
                        encodeUnprotectedHeader, base64UrlEncoder, jsonSerializer, pool));
                }

                if(gapFillRevocationValues is not null)
                {
                    workingUnsignedHeaders = AppendOne(workingUnsignedHeaders, BuildElementInMode(
                        mode,
                        static carriage => new JAdESUnsignedHeaderElementRevocationValues(carriage),
                        probeValue: gapFillRevocationValues, finalValue: gapFillRevocationValues,
                        encodeUnprotectedHeader, base64UrlEncoder, jsonSerializer, pool));
                }
            }

            //Gate (4): JA-6.3-26's cumulative prerequisite.
            if(!HasSignatureTimestampInstance(workingUnsignedHeaders))
            {
                throw new JAdESAugmentationException(
                    JAdESAugmentationFailureKind.ArchiveTimestampSignatureTimestampPrerequisiteMissing,
                    "A new arcTst instance is generated only once the signature already carries at least one " +
                    "sigTst instance (ETSI TS 119 182-1 V1.2.1, clause 6.3, Table 1, JA-6.3-26).");
            }

            //Gate (5): the whole reference family is hard-forbidden once the declared level is B-LTA.
            if(AnyReferencesFamilyElementPresent(workingUnsignedHeaders))
            {
                throw new JAdESAugmentationException(
                    JAdESAugmentationFailureKind.ArchiveTimestampReferencesFamilyElementPresent,
                    "xRefs/rRefs/axRefs/arRefs/sigRTst/rfsTst shall not be present at level B-LT or above (ETSI " +
                    "TS 119 182-1 V1.2.1, clause 6.3, Table 1, JA-6.3-29/-31/-33/-35/-36/-37).");
            }

            //Gate (6) (producer symmetry per the CB-A.1.1-30 precedent): the SAME async refs-resolution
            //check AddValidationDataAsync already runs, over this call's own (possibly gap-filled) state --
            //pre-imprint, before any Time-Stamping Authority round trip -- so this producer never mints a
            //signature the validator's own widened JA-A.1.1-12/-A.1.2-35/-A.1.3-08/-A.1.4-10 trigger/candidate
            //set would reject. Gate (5) above already guarantees the refs family itself is absent at this
            //point, so in practice this only fires when a PRIOR augmentation left an unresolved refs entry
            //behind under a differently-shaped state -- still checked, never assumed.
            await JAdESLevelRules.EnsureReferencesResolveToValidationDataAsync(workingUnsignedHeaders, pool, cancellationToken).ConfigureAwait(false);

            JAdESUnsignedHeaders etsiUForImprint = workingUnsignedHeaders!;

            UnverifiedJwsSignature signature = message.Wire.Signatures[0];
            string signatureValueBase64Url = base64UrlEncoder(signature.SignatureBytes.Memory.Span);
            using PooledMemory protectedHeaderBytes = RentAsciiBytes(signature.Protected, CryptoTags.JoseEncodedProtectedHeader, pool);
            using PooledMemory signatureValueBytes = RentAsciiBytes(signatureValueBase64Url, CryptoTags.JoseEncodedSignatureValue, pool);

            //Under Base64Url mode, JAdESMessageImprints' own ValidateCanonicalizationArguments fail-closed rejects
            //a non-null CanonAlg/Canonicalize (JA-5.3.1-15) -- the imprint context nulls both out precisely when
            //the container's own mode says so, regardless of what context.CanonAlg the caller supplied (still
            //required syntactically, but consulted only under ClearJson).
            var imprintContext = new JAdESArchiveTimestampImprintContext
            {
                PayloadSource = context.PayloadSource,
                ProtectedHeaderBase64Url = protectedHeaderBytes.AsReadOnlyMemory(),
                SignatureValueBase64Url = signatureValueBytes.AsReadOnlyMemory(),
                CanonAlg = mode == JAdESEtsiUIncorporationMode.ClearJson ? context.CanonAlg : null,
                Canonicalize = mode == JAdESEtsiUIncorporationMode.ClearJson ? context.Canonicalize : null
            };

            using PooledMemory imprintInput = await JAdESMessageImprints.BuildArchiveTimestampGenerationMessageImprintInputAsync(
                imprintContext, etsiUForImprint, pool, cancellationToken).ConfigureAwait(false);

            using DigestValue imprint = await CryptographicKeyEvents.ComputeDigestAsync(
                imprintInput.AsReadOnlyMemory(), context.MessageImprintAlgorithm.OutputByteLength, context.MessageImprintAlgorithm.DigestTag,
                pool, cancellationToken: cancellationToken).ConfigureAwait(false);

            var acquiredTokens = new List<AcquiredTimestampToken>(context.TsaLegs.Count);
            try
            {
                for(int i = 0; i < context.TsaLegs.Count; ++i)
                {
                    JAdESArchiveTimestampTsaLeg leg = context.TsaLegs[i];
                    AcquiredTimestampToken token = await TimestampAcquisition.AcquireAsync(
                        imprint, leg.TsaUri, leg.FetchResponse, pool,
                        leg.ReqPolicyOid, leg.NonceByteLength, leg.IncludeNonce, cancellationToken).ConfigureAwait(false);
                    acquiredTokens.Add(token);
                }

                var tokens = new List<AdESTimestampToken>(acquiredTokens.Count);
                for(int i = 0; i < acquiredTokens.Count; ++i)
                {
                    tokens.Add(new AdESTimestampToken { Val = acquiredTokens[i].Token.AsReadOnlyMemory() });
                }

                //The probe always carries context.CanonAlg (satisfies JAdESUnsignedHeaders' own clear-mode
                //JA-5.3.1-14 gate when BuildElementInMode routes through its throwaway probe container); the
                //FINAL stored container carries it only under ClearJson -- under Base64Url the wire text (and
                //this decoded view) must not, per JA-5.3.1-15.
                var probeContainer = new AdESTimestampContainer(tokens, context.CanonAlg);
                AdESTimestampContainer finalContainer = mode == JAdESEtsiUIncorporationMode.ClearJson
                    ? probeContainer
                    : new AdESTimestampContainer(tokens, canonAlg: null);

                JAdESUnsignedHeaderElement element = BuildElementInMode(
                    mode,
                    static carriage => new JAdESUnsignedHeaderElementArchiveTimestamp(carriage),
                    probeValue: probeContainer, finalValue: finalContainer,
                    encodeUnprotectedHeader, base64UrlEncoder, jsonSerializer, pool);

                workingUnsignedHeaders = AppendOne(etsiUForImprint, element);

                JAdESLevelRules.EnsureConformant(new JAdESLevelRuleContext
                {
                    Level = context.TargetLevel,
                    UnsignedHeaders = workingUnsignedHeaders,
                    ProtectedHeaders = headers,
                    AnyTimestampTokenCarriesEmbeddedValidationMaterial = context.AnyTimestampTokenCarriesEmbeddedValidationMaterial
                });

                return SerializeAugmented(message, workingUnsignedHeaders, encodeUnprotectedHeader, base64UrlEncoder, jsonSerializer, pool);
            }
            finally
            {
                for(int i = 0; i < acquiredTokens.Count; ++i)
                {
                    acquiredTokens[i].Dispose();
                }
            }
        }
        finally
        {
            workingUnsignedHeaders?.Dispose();
        }
    }


    /// <summary>
    /// The shared core behind <see cref="AddSignatureAndReferencesTimestampAsync"/> and
    /// <see cref="AddReferencesTimestampAsync"/> — Annex A.1.5.1 and A.1.5.2 are identical except for the leading
    /// JWS Signature Value segment.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "finalContainer/element become reachable through workingUnsignedHeaders once appended, " +
            "disposed in the finally below. Roslyn cannot trace ownership through AppendOne to that later " +
            "disposal -- and AdESTimestampContainer.Dispose is currently a no-op regardless; probeContainer is " +
            "never reachable through workingUnsignedHeaders (a throwaway BuildElementInMode input) and owns no " +
            "resource of its own for the identical reason.")]
    private static async ValueTask<byte[]> AppendReferencesFamilyTimestampAsync(
        JAdESReferencesFamilyTimestampContext context,
        bool includeSignatureValue,
        TryParseJAdESMessageDelegate parse,
        DecodeJAdESProtectedHeaderDelegate decodeProtectedHeader,
        TryParseJAdESEtsiUDelegate parseEtsiU,
        EncodeJAdESUnprotectedHeaderDelegate encodeUnprotectedHeader,
        DecodeDelegate base64UrlDecoder,
        EncodeDelegate base64UrlEncoder,
        Func<object, byte[]> jsonSerializer,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(context.CanonAlg);
        ArgumentNullException.ThrowIfNull(context.Canonicalize);
        ArgumentNullException.ThrowIfNull(pool);

        AugmentationParseResult parsed = ParseForAugmentation(context.WireBytes, parse, decodeProtectedHeader, parseEtsiU, base64UrlDecoder, pool);
        using UnverifiedJAdESMessage message = parsed.Message;
        using JAdESProtectedHeaders headers = parsed.ProtectedHeaders;
        JAdESUnsignedHeaders? workingUnsignedHeaders = parsed.UnsignedHeaders;

        EnsureReferencesFamilyPermittedAtTargetLevel(context.TargetLevel);

        JAdESEtsiUIncorporationMode mode = TargetMode(workingUnsignedHeaders);

        //The generation gate (JA-A.1.5.1.1-04/JA-A.1.5.2.1-04): checked before any Time-Stamping Authority round
        //trip so a doomed call never bills one.
        if(!AnyReferenceKindElementPresent(workingUnsignedHeaders))
        {
            workingUnsignedHeaders?.Dispose();
            throw new JAdESAugmentationException(
                JAdESAugmentationFailureKind.ReferencesElementRequired,
                "If none of xRefs/rRefs/axRefs/arRefs is present, this time-stamp element shall not be generated " +
                $"(ETSI TS 119 182-1 V1.2.1, {(includeSignatureValue ? "JA-A.1.5.1.1-04" : "JA-A.1.5.2.1-04")}).");
        }

        AcquiredTimestampToken? token = null;
        try
        {
            JAdESUnsignedHeaders etsiUForImprint = workingUnsignedHeaders!;

            UnverifiedJwsSignature signature = message.Wire.Signatures[0];
            using PooledMemory? signatureValueBytes = includeSignatureValue
                ? RentAsciiBytes(base64UrlEncoder(signature.SignatureBytes.Memory.Span), CryptoTags.JoseEncodedSignatureValue, pool)
                : null;

            //Under Base64Url mode, JAdESMessageImprints' own ValidateCanonicalizationArguments fail-closed
            //rejects a non-null CanonAlg/Canonicalize (JA-5.3.1-15) -- nulled out precisely when the container's
            //own mode says so, regardless of what context.CanonAlg/Canonicalize the caller supplied (still
            //required syntactically, but consulted only under ClearJson).
            string? imprintCanonAlg = mode == JAdESEtsiUIncorporationMode.ClearJson ? context.CanonAlg : null;
            JAdESCanonicalizeUnsignedElementDelegate? imprintCanonicalize = mode == JAdESEtsiUIncorporationMode.ClearJson ? context.Canonicalize : null;

            using PooledMemory imprintInput = includeSignatureValue
                ? await JAdESMessageImprints.BuildSignatureAndReferencesTimestampGenerationMessageImprintInputAsync(
                    signatureValueBytes!.AsReadOnlyMemory(), etsiUForImprint, imprintCanonAlg, imprintCanonicalize, pool, cancellationToken).ConfigureAwait(false)
                : await JAdESMessageImprints.BuildReferencesOnlyTimestampGenerationMessageImprintInputAsync(
                    etsiUForImprint, imprintCanonAlg, imprintCanonicalize, pool, cancellationToken).ConfigureAwait(false);

            using DigestValue imprint = await CryptographicKeyEvents.ComputeDigestAsync(
                imprintInput.AsReadOnlyMemory(), context.MessageImprintAlgorithm.OutputByteLength, context.MessageImprintAlgorithm.DigestTag,
                pool, cancellationToken: cancellationToken).ConfigureAwait(false);

            token = await TimestampAcquisition.AcquireAsync(
                imprint, context.TsaUri, context.FetchResponse, pool,
                context.ReqPolicyOid, context.NonceByteLength, context.IncludeNonce, cancellationToken).ConfigureAwait(false);

            var tokens = new[] { new AdESTimestampToken { Val = token.Token.AsReadOnlyMemory() } };

            //The probe always carries context.CanonAlg (satisfies JAdESUnsignedHeaders' own clear-mode
            //JA-5.3.1-14 gate when BuildElementInMode routes through its throwaway probe container); the FINAL
            //stored container carries it only under ClearJson -- under Base64Url the wire text (and this
            //decoded view) must not, per JA-5.3.1-15.
            var probeContainer = new AdESTimestampContainer(tokens, context.CanonAlg);
            AdESTimestampContainer finalContainer = mode == JAdESEtsiUIncorporationMode.ClearJson
                ? probeContainer
                : new AdESTimestampContainer(tokens, canonAlg: null);

            JAdESUnsignedHeaderElement element = includeSignatureValue
                ? BuildElementInMode(
                    mode, static carriage => new JAdESUnsignedHeaderElementSignatureAndReferencesTimestamp(carriage),
                    probeValue: probeContainer, finalValue: finalContainer,
                    encodeUnprotectedHeader, base64UrlEncoder, jsonSerializer, pool)
                : BuildElementInMode(
                    mode, static carriage => new JAdESUnsignedHeaderElementReferencesTimestamp(carriage),
                    probeValue: probeContainer, finalValue: finalContainer,
                    encodeUnprotectedHeader, base64UrlEncoder, jsonSerializer, pool);

            workingUnsignedHeaders = AppendOne(etsiUForImprint, element);

            JAdESLevelRules.EnsureConformant(new JAdESLevelRuleContext
            {
                Level = context.TargetLevel,
                UnsignedHeaders = workingUnsignedHeaders,
                ProtectedHeaders = headers
            });

            return SerializeAugmented(message, workingUnsignedHeaders, encodeUnprotectedHeader, base64UrlEncoder, jsonSerializer, pool);
        }
        finally
        {
            token?.Dispose();
            workingUnsignedHeaders?.Dispose();
        }
    }


    /// <summary>The decoded facts <see cref="ParseForAugmentation"/> hands every verb: the parsed message, the decoded protected headers, and the decoded (possibly absent) <c>etsiU</c> set.</summary>
    private readonly record struct AugmentationParseResult(
        UnverifiedJAdESMessage Message, JAdESProtectedHeaders ProtectedHeaders, JAdESUnsignedHeaders? UnsignedHeaders);


    /// <summary>
    /// Parses <paramref name="wireBytes"/> into every decoded fact an augmentation verb needs: the message
    /// (owned by the caller, kept alive for its own <c>Payload</c>/<c>Protected</c>/<c>SignatureBytes</c>), the
    /// decoded protected headers, and the decoded <c>etsiU</c> set when present. Fail-closed: any parse/decode
    /// failure throws <see cref="JAdESAugmentationException"/> naming <see cref="JAdESAugmentationFailureKind.MalformedEncoding"/> —
    /// a caller composition fault for this trusted-input surface, not adversarial input to collect.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The UnverifiedJAdESMessage/JAdESUnsignedHeaders ParseMessageOrThrow/ParseEtsiUOrThrow " +
            "return are returned onward inside the AugmentationParseResult on success, owned by the calling " +
            "verb from there; the surrounding catch blocks dispose them on every failure path (message on any " +
            "failure, headers additionally on the etsiU-decode failure path).")]
    private static AugmentationParseResult ParseForAugmentation(
        ReadOnlyMemory<byte> wireBytes,
        TryParseJAdESMessageDelegate parse,
        DecodeJAdESProtectedHeaderDelegate decodeProtectedHeader,
        TryParseJAdESEtsiUDelegate parseEtsiU,
        DecodeDelegate base64UrlDecoder,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(parse);
        ArgumentNullException.ThrowIfNull(decodeProtectedHeader);
        ArgumentNullException.ThrowIfNull(parseEtsiU);
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);

        UnverifiedJAdESMessage message = ParseMessageOrThrow(wireBytes, parse, base64UrlDecoder, pool);
        try
        {
            UnverifiedJwsSignature signature = message.Wire.Signatures[0];
            JAdESProtectedHeaders headers;
            using(IMemoryOwner<byte> protectedJsonBytes = DecodeBase64UrlOrThrow(signature.Protected, base64UrlDecoder, pool))
            {
                JAdESProtectedHeaders? decoded = decodeProtectedHeader(protectedJsonBytes.Memory.Span, base64UrlDecoder, pool);
                if(decoded is null)
                {
                    throw new JAdESAugmentationException(
                        JAdESAugmentationFailureKind.MalformedEncoding,
                        "The JWS Protected Header could not be decoded for augmentation.");
                }

                headers = decoded;
            }

            try
            {
                JAdESUnsignedHeaders? unsignedHeaders = ParseEtsiUOrThrow(message, parseEtsiU, base64UrlDecoder, pool);

                return new AugmentationParseResult(message, headers, unsignedHeaders);
            }
            catch
            {
                headers.Dispose();
                throw;
            }
        }
        catch
        {
            message.Dispose();
            throw;
        }
    }


    /// <summary>Parses <paramref name="wireBytes"/> into an <see cref="UnverifiedJAdESMessage"/>, fail-closed.</summary>
    private static UnverifiedJAdESMessage ParseMessageOrThrow(
        ReadOnlyMemory<byte> wireBytes, TryParseJAdESMessageDelegate parse, DecodeDelegate base64UrlDecoder, BaseMemoryPool pool)
    {
        bool parsed;
        UnverifiedJAdESMessage? message;
        try
        {
            parsed = parse(wireBytes.Span, base64UrlDecoder, pool, out message, out _);
        }
        catch(Exception ex) when(IsFailClosedParseException(ex))
        {
            throw new JAdESAugmentationException(
                JAdESAugmentationFailureKind.MalformedEncoding, "The JAdES signature could not be parsed for augmentation.", ex);
        }

        if(!parsed || message is null)
        {
            throw new JAdESAugmentationException(
                JAdESAugmentationFailureKind.MalformedEncoding, "The JAdES signature could not be parsed for augmentation.");
        }

        return message;
    }


    /// <summary>Decodes <paramref name="message"/>'s own <c>etsiU</c> raw bytes into a <see cref="JAdESUnsignedHeaders"/>, fail-closed, or returns <see langword="null"/> when absent.</summary>
    private static JAdESUnsignedHeaders? ParseEtsiUOrThrow(
        UnverifiedJAdESMessage message, TryParseJAdESEtsiUDelegate parseEtsiU, DecodeDelegate base64UrlDecoder, BaseMemoryPool pool)
    {
        if(message.EtsiURawBytes is not { } etsiURawBytes)
        {
            return null;
        }

        bool parsed;
        JAdESUnsignedHeaders? unsignedHeaders;
        try
        {
            parsed = parseEtsiU(etsiURawBytes.AsReadOnlySpan(), base64UrlDecoder, pool, out unsignedHeaders);
        }
        catch(Exception ex) when(IsFailClosedParseException(ex))
        {
            throw new JAdESAugmentationException(
                JAdESAugmentationFailureKind.MalformedEncoding, "The etsiU header parameter could not be decoded for augmentation.", ex);
        }

        if(!parsed || unsignedHeaders is null)
        {
            throw new JAdESAugmentationException(
                JAdESAugmentationFailureKind.MalformedEncoding, "The etsiU header parameter could not be decoded for augmentation.");
        }

        return unsignedHeaders;
    }


    /// <summary>Decodes a base64url segment, fail-closed.</summary>
    private static IMemoryOwner<byte> DecodeBase64UrlOrThrow(string base64Url, DecodeDelegate base64UrlDecoder, BaseMemoryPool pool)
    {
        try
        {
            return base64UrlDecoder(base64Url, pool);
        }
        catch(Exception ex) when(IsFailClosedParseException(ex))
        {
            throw new JAdESAugmentationException(
                JAdESAugmentationFailureKind.MalformedEncoding, "The JWS Protected Header could not be base64url-decoded for augmentation.", ex);
        }
    }


    //Mirrors JAdESSignatureValidation's own IsFailClosedParseException set (FormatException/ArgumentException/
    //InvalidOperationException/OverflowException -- never JsonException, the STJ-body firewall).
    private static bool IsFailClosedParseException(Exception exception) =>
        exception is FormatException or ArgumentException or InvalidOperationException or OverflowException;


    /// <summary>Gets the mode a new element being appended to <paramref name="current"/> mints in: the existing container's own <see cref="JAdESUnsignedHeaders.Mode"/>, or <see cref="JAdESEtsiUIncorporationMode.ClearJson"/> when bootstrapping the first element of a fresh container (no established mode to inherit).</summary>
    private static JAdESEtsiUIncorporationMode TargetMode(JAdESUnsignedHeaders? current) =>
        current?.Mode ?? JAdESEtsiUIncorporationMode.ClearJson;


    /// <summary>
    /// Builds a NEW <c>etsiU</c> element in <paramref name="targetMode"/> — the mode-neutral augmentation
    /// discipline replacing the old blanket base64url refusal.
    /// Under <see cref="JAdESEtsiUIncorporationMode.ClearJson"/>, wraps <paramref name="finalValue"/> directly.
    /// Under <see cref="JAdESEtsiUIncorporationMode.Base64Url"/>, this class has no leaf-crossing access of its
    /// own to <c>Verifiable.Json</c>'s per-kind JSON codecs (the serialization firewall), so the element's own
    /// <c>{Kind: value}</c> JSON is instead produced by routing a THROWAWAY single-element clear-JSON probe
    /// container through the ALREADY-REGISTERED <paramref name="encodeUnprotectedHeader"/> seam (the same one
    /// every verb already threads through to <see cref="SerializeAugmented"/>), then serialized via
    /// <paramref name="jsonSerializer"/> and base64url-encoded via <paramref name="base64UrlEncoder"/> — the
    /// resulting wire text and <paramref name="finalValue"/> (the decoded view) are wrapped together
    /// into a <see cref="JAdESOpaqueUnsignedValue{TValue}"/>. The probe container is never disposed (its wrapper
    /// shells — the probe element/carriage/container — own no resource of their own; only the wrapped value
    /// does, and that is <paramref name="finalValue"/>'s concern, disposed exactly once when the REAL working
    /// container is eventually disposed).
    /// </summary>
    /// <param name="probeValue">
    /// The value used ONLY to satisfy <see cref="JAdESUnsignedHeaders"/>'s own clear-mode JA-5.3.1-14 canonAlg
    /// gate when the throwaway probe container is built under <see cref="JAdESEtsiUIncorporationMode.Base64Url"/>
    /// — it never reaches the wire (any <c>canonAlg</c> JSON member the probe's projection carries is stripped
    /// before serializing, since JA-5.3.1-15 forbids one on a base64url-incorporated <c>tstContainer</c>). For
    /// every kind with no <c>canonAlg</c> member, and for the <see cref="JAdESEtsiUIncorporationMode.ClearJson"/>
    /// arm (never probed), this is the SAME reference as <paramref name="finalValue"/>.
    /// </param>
    /// <param name="finalValue">The value the returned element's carriage actually carries as its decoded view.</param>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The ClearJson arm's returned element becomes reachable through whatever workingUnsignedHeaders " +
            "the caller appends it into, disposed there eventually -- Roslyn cannot trace that far. Under Base64Url, " +
            "probeElement/probeContainer are throwaway shells over probeValue (never disposed by design -- see the " +
            "method remarks: they own no resource of their own, only probeValue does, and probeValue is either the " +
            "SAME reference as finalValue, disposed once via the real returned element, or -- for the canonAlg-split " +
            "callers -- a AdESTimestampContainer, whose Dispose is a no-op regardless); wireText/the final Opaque " +
            "element are reachable through the returned element the same way the ClearJson arm's is.")]
    private static JAdESUnsignedHeaderElement BuildElementInMode<TValue>(
        JAdESEtsiUIncorporationMode targetMode,
        Func<JAdESUnsignedValue<TValue>, JAdESUnsignedHeaderElement> constructElement,
        TValue probeValue,
        TValue finalValue,
        EncodeJAdESUnprotectedHeaderDelegate encodeUnprotectedHeader,
        EncodeDelegate base64UrlEncoder,
        Func<object, byte[]> jsonSerializer,
        BaseMemoryPool pool)
    {
        if(targetMode == JAdESEtsiUIncorporationMode.ClearJson)
        {
            return constructElement(new JAdESClearUnsignedValue<TValue>(finalValue));
        }

        JAdESUnsignedHeaderElement probeElement = constructElement(new JAdESClearUnsignedValue<TValue>(probeValue));
        var probeContainer = new JAdESUnsignedHeaders(JAdESEtsiUIncorporationMode.ClearJson, [probeElement]);

        IReadOnlyDictionary<string, object>? projected = encodeUnprotectedHeader(probeContainer);
        var etsiUArray = (IReadOnlyList<object>)projected![WellKnownJAdESHeaderNames.EtsiU];
        var elementDict = (Dictionary<string, object>)etsiUArray[0];
        if(elementDict[probeElement.Kind] is Dictionary<string, object> innerDict)
        {
            innerDict.Remove(JAdESWireNames.TimestampContainerCanonAlg);
        }

        byte[] jsonBytes = jsonSerializer(elementDict);
        string base64UrlWireText = base64UrlEncoder(jsonBytes);
        PooledMemory wireText = RentAsciiBytes(base64UrlWireText, CryptoTags.JoseEncodedUnsignedHeaderElement, pool);

        return constructElement(new JAdESOpaqueUnsignedValue<TValue>(wireText, finalValue));
    }


    /// <summary>Refuses <c>xRefs</c>/<c>rRefs</c>/<c>sigRTst</c>/<c>rfsTst</c> generation once the declared level reaches B-LT, before any digest computation or Time-Stamping Authority round trip.</summary>
    private static void EnsureReferencesFamilyPermittedAtTargetLevel(AdESBaselineLevel targetLevel)
    {
        if(targetLevel >= AdESBaselineLevel.BLT)
        {
            throw new JAdESAugmentationException(
                JAdESAugmentationFailureKind.ReferencesFamilyNotPermittedAtTargetLevel,
                "xRefs/rRefs/axRefs/arRefs/sigRTst/rfsTst shall not be present at level B-LT or above (ETSI TS " +
                "119 182-1 V1.2.1, clause 6.3, Table 1, JA-6.3-29/-31/-33/-35/-36/-37).");
        }
    }


    /// <summary>Appends <paramref name="element"/> onto <paramref name="current"/> (or creates a fresh clear-JSON container when none existed), returning the new working container.</summary>
    private static JAdESUnsignedHeaders AppendOne(JAdESUnsignedHeaders? current, JAdESUnsignedHeaderElement element) =>
        current is null
            ? new JAdESUnsignedHeaders(JAdESEtsiUIncorporationMode.ClearJson, [element])
            : current.Append(element);


    /// <summary>
    /// Builds the caller-supplied validation material into <c>xVals</c>/<c>rVals</c> members, skipping any
    /// candidate that byte-equals (DER) material already present in an earlier <c>xVals</c>/<c>rVals</c>/
    /// <c>anyValData</c> element of <paramref name="existing"/> when <paramref name="dedupe"/> is
    /// <see langword="true"/> (letters e/i).
    /// </summary>
    /// <param name="material">The certificates/CRLs/OCSP responses to place.</param>
    /// <param name="existing">The signature's current <c>etsiU</c> set, or <see langword="null"/> when absent.</param>
    /// <param name="dedupe">Whether byte-equal duplicates of already-present material are skipped.</param>
    /// <returns>The <c>xVals</c>/<c>rVals</c> members to place, or <see langword="null"/> for each member with nothing new to add.</returns>
    /// <exception cref="JAdESAugmentationException">When a supplied object is not of the kind admitted.</exception>
    private static (JAdESCertificateValues? CertificateValues, JAdESRevocationValues? RevocationValues) BuildValidationDataMembers(
        JAdESValidationMaterial material, JAdESUnsignedHeaders? existing, bool dedupe)
    {
        (List<ReadOnlyMemory<byte>> knownCertificates, List<ReadOnlyMemory<byte>> knownCrls, List<ReadOnlyMemory<byte>> knownOcsp) =
            dedupe ? CollectExistingValidationData(existing) : ([], [], []);

        List<JAdESCertificateChoice>? certificateItems = null;
        if(material.Certificates.Count > 0)
        {
            List<JAdESCertificateChoice> selected = [];
            for(int i = 0; i < material.Certificates.Count; ++i)
            {
                PkiCertificateMemory candidate = material.Certificates[i];
                EnsureKind(candidate.IsX509Certificate, JAdESAugmentationFailureKind.UnsupportedValidationObject,
                    "A certificate placed as validation material is a DER-encoded X.509 certificate (ETSI TS 119 182-1 V1.2.1, clause 5.3.5.2, JA-5.3.5.2-14).");

                if(!dedupe || !ContainsBytes(knownCertificates, candidate.AsReadOnlySpan()))
                {
                    selected.Add(new JAdESX509Certificate(new AdESPkiObject { Val = candidate.AsReadOnlyMemory() }));
                }
            }

            certificateItems = selected.Count > 0 ? selected : null;
        }

        List<AdESPkiObject>? crlItems = null;
        if(material.CertificateRevocationLists.Count > 0)
        {
            List<AdESPkiObject> selected = [];
            for(int i = 0; i < material.CertificateRevocationLists.Count; ++i)
            {
                PkiCertificateMemory candidate = material.CertificateRevocationLists[i];
                EnsureKind(candidate.IsCrl, JAdESAugmentationFailureKind.UnsupportedValidationObject,
                    "A certificate revocation list placed as validation material is a DER-encoded X.509 CRL (ETSI TS 119 182-1 V1.2.1, clause 5.3.5.3, JA-5.3.5.3-13/-14).");

                if(!dedupe || !ContainsBytes(knownCrls, candidate.AsReadOnlySpan()))
                {
                    selected.Add(new AdESPkiObject { Val = candidate.AsReadOnlyMemory() });
                }
            }

            crlItems = selected.Count > 0 ? selected : null;
        }

        List<AdESPkiObject>? ocspItems = null;
        if(material.OcspResponses.Count > 0)
        {
            List<AdESPkiObject> selected = [];
            for(int i = 0; i < material.OcspResponses.Count; ++i)
            {
                PkiCertificateMemory candidate = material.OcspResponses[i];
                EnsureKind(candidate.IsOcspResponse, JAdESAugmentationFailureKind.UnsupportedValidationObject,
                    "An OCSP response placed as validation material is a DER-encoded OCSPResponse (ETSI TS 119 182-1 V1.2.1, clause 5.3.5.3, JA-5.3.5.3-16/-17).");

                if(!dedupe || !ContainsBytes(knownOcsp, candidate.AsReadOnlySpan()))
                {
                    selected.Add(new AdESPkiObject { Val = candidate.AsReadOnlyMemory() });
                }
            }

            ocspItems = selected.Count > 0 ? selected : null;
        }

        JAdESCertificateValues? certificateValues = certificateItems is not null ? new JAdESCertificateValues(certificateItems) : null;
        JAdESRevocationValues? revocationValues = crlItems is not null || ocspItems is not null
            ? new JAdESRevocationValues(crlItems, ocspItems)
            : null;

        return (certificateValues, revocationValues);
    }


    /// <summary>
    /// Collects the DER bytes of every certificate/CRL/OCSP response reachable through an EARLIER <c>xVals</c>/
    /// <c>rVals</c>/<c>anyValData</c> element of <paramref name="unsignedHeaders"/> — the "already present" set
    /// <see cref="BuildValidationDataMembers"/> dedupes new candidates against. Reads either carriage arm's own
    /// decoded view (<see cref="JAdESClearUnsignedValue{TValue}.Value"/> or
    /// <see cref="JAdESOpaqueUnsignedValue{TValue}.DecodedValue"/>) — dedup works identically under
    /// either incorporation mode, since this call never re-encodes what it scans (byte-exact preservation is about the
    /// WIRE TEXT, never about inspection).
    /// </summary>
    private static (List<ReadOnlyMemory<byte>> Certificates, List<ReadOnlyMemory<byte>> Crls, List<ReadOnlyMemory<byte>> Ocsp) CollectExistingValidationData(
        JAdESUnsignedHeaders? unsignedHeaders)
    {
        List<ReadOnlyMemory<byte>> certificates = [];
        List<ReadOnlyMemory<byte>> crls = [];
        List<ReadOnlyMemory<byte>> ocsp = [];
        if(unsignedHeaders is not null)
        {
            for(int i = 0; i < unsignedHeaders.Count; ++i)
            {
                JAdESCertificateValues? certificateValues = null;
                JAdESRevocationValues? revocationValues = null;

                switch(unsignedHeaders[i])
                {
                    case JAdESUnsignedHeaderElementCertificateValues e:
                        certificateValues = DecodedCertificateValuesOf(e.Carriage);
                        break;

                    case JAdESUnsignedHeaderElementRevocationValues e:
                        revocationValues = DecodedRevocationValuesOf(e.Carriage);
                        break;

                    case JAdESUnsignedHeaderElementAnyValidationData e:
                        JAdESValidationData? validationData = e.Carriage switch
                        {
                            JAdESClearUnsignedValue<JAdESValidationData> clear => clear.Value,
                            JAdESOpaqueUnsignedValue<JAdESValidationData> opaque => opaque.DecodedValue,
                            _ => null
                        };
                        certificateValues = validationData?.CertificateValues;
                        revocationValues = validationData?.RevocationValues;
                        break;
                }

                CollectCertificateValues(certificateValues, certificates);
                CollectRevocationValues(revocationValues, crls, ocsp);
            }
        }

        return (certificates, crls, ocsp);

        static JAdESCertificateValues? DecodedCertificateValuesOf(JAdESUnsignedValue<JAdESCertificateValues> carriage) => carriage switch
        {
            JAdESClearUnsignedValue<JAdESCertificateValues> clear => clear.Value,
            JAdESOpaqueUnsignedValue<JAdESCertificateValues> opaque => opaque.DecodedValue,
            _ => null
        };

        static JAdESRevocationValues? DecodedRevocationValuesOf(JAdESUnsignedValue<JAdESRevocationValues> carriage) => carriage switch
        {
            JAdESClearUnsignedValue<JAdESRevocationValues> clear => clear.Value,
            JAdESOpaqueUnsignedValue<JAdESRevocationValues> opaque => opaque.DecodedValue,
            _ => null
        };


        static void CollectCertificateValues(JAdESCertificateValues? values, List<ReadOnlyMemory<byte>> certificates)
        {
            if(values is null)
            {
                return;
            }

            for(int c = 0; c < values.Items.Count; ++c)
            {
                if(values.Items[c] is JAdESX509Certificate x509)
                {
                    certificates.Add(x509.Certificate.Val);
                }
            }
        }

        static void CollectRevocationValues(JAdESRevocationValues? values, List<ReadOnlyMemory<byte>> crls, List<ReadOnlyMemory<byte>> ocsp)
        {
            if(values is null)
            {
                return;
            }

            if(values.CrlValues is not null)
            {
                for(int c = 0; c < values.CrlValues.Count; ++c)
                {
                    crls.Add(values.CrlValues[c].Val);
                }
            }

            if(values.OcspValues is not null)
            {
                for(int c = 0; c < values.OcspValues.Count; ++c)
                {
                    ocsp.Add(values.OcspValues[c].Val);
                }
            }
        }
    }


    /// <summary>Determines whether <paramref name="known"/> contains an entry byte-equal to <paramref name="candidate"/>.</summary>
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


    /// <summary>Determines whether <paramref name="unsignedHeaders"/> carries at least one <c>sigTst</c> instance (JA-6.3-26's cumulative prerequisite).</summary>
    private static bool HasSignatureTimestampInstance(JAdESUnsignedHeaders? unsignedHeaders)
    {
        if(unsignedHeaders is null)
        {
            return false;
        }

        for(int i = 0; i < unsignedHeaders.Count; ++i)
        {
            if(unsignedHeaders[i] is JAdESUnsignedHeaderElementSignatureTimestamp)
            {
                return true;
            }
        }

        return false;
    }


    /// <summary>Determines whether <paramref name="unsignedHeaders"/> carries at least one of the four <c>refs</c>-family VALUE kinds (<c>xRefs</c>/<c>rRefs</c>/<c>axRefs</c>/<c>arRefs</c>) — the <c>sigRTst</c>/<c>rfsTst</c> generation gate's own trigger (JA-A.1.5.1.1-04/JA-A.1.5.2.1-04).</summary>
    private static bool AnyReferenceKindElementPresent(JAdESUnsignedHeaders? unsignedHeaders)
    {
        if(unsignedHeaders is null)
        {
            return false;
        }

        for(int i = 0; i < unsignedHeaders.Count; ++i)
        {
            switch(unsignedHeaders[i])
            {
                case JAdESUnsignedHeaderElementCertificateReferences:
                case JAdESUnsignedHeaderElementRevocationReferences:
                case JAdESUnsignedHeaderElementAttributeCertificateReferences:
                case JAdESUnsignedHeaderElementAttributeRevocationReferences:
                    return true;
            }
        }

        return false;
    }


    /// <summary>Determines whether <paramref name="unsignedHeaders"/> carries any of the SIX <c>refs</c>-family kinds Table 1 hard-forbids from B-LT onward (JA-6.3-29/-31/-33/-35/-36/-37) — <see cref="AddArchiveTimestampAsync"/>'s own gate (6).</summary>
    private static bool AnyReferencesFamilyElementPresent(JAdESUnsignedHeaders? unsignedHeaders)
    {
        if(unsignedHeaders is null)
        {
            return false;
        }

        for(int i = 0; i < unsignedHeaders.Count; ++i)
        {
            switch(unsignedHeaders[i])
            {
                case JAdESUnsignedHeaderElementCertificateReferences:
                case JAdESUnsignedHeaderElementRevocationReferences:
                case JAdESUnsignedHeaderElementAttributeCertificateReferences:
                case JAdESUnsignedHeaderElementAttributeRevocationReferences:
                case JAdESUnsignedHeaderElementSignatureAndReferencesTimestamp:
                case JAdESUnsignedHeaderElementReferencesTimestamp:
                    return true;
            }
        }

        return false;
    }


    /// <summary>Maps a registered <see cref="PkiDigestAlgorithm"/> to its JAdES <c>digAlg</c> name (the IANA "Named Information Hash Algorithm Registry", JA-A.1.1-08).</summary>
    /// <exception cref="NotSupportedException">When <paramref name="algorithm"/> is not SHA-256/384/512.</exception>
    private static string ToDigAlgName(PkiDigestAlgorithm algorithm) => algorithm.Identifier.Oid switch
    {
        WellKnownOids.Sha256 => WellKnownHashAlgorithms.Sha256Iana,
        WellKnownOids.Sha384 => WellKnownHashAlgorithms.Sha384Iana,
        WellKnownOids.Sha512 => WellKnownHashAlgorithms.Sha512Iana,
        _ => throw new NotSupportedException(
            $"Digest algorithm OID '{algorithm.Identifier.Oid}' has no registered JAdES digAlg name (ETSI TS 119 182-1 V1.2.1, Annex A.1.1, JA-A.1.1-08; IANA Named Information Hash Algorithm Registry).")
    };


    /// <summary>Reads a signing certificate's validity window, fail-closed against caller composition faults; skipped entirely when <paramref name="enforce"/> is <see langword="false"/>.</summary>
    /// <exception cref="ArgumentNullException"><paramref name="certificate"/> is <see langword="null"/> and <paramref name="enforce"/> is <see langword="true"/>.</exception>
    /// <exception cref="JAdESAugmentationException">The carrier is not an X.509 certificate, or its DER encoding does not parse as one.</exception>
    private static CertificateValidityPeriod? ReadSigningCertificateValidityOrThrow(PkiCertificateMemory? certificate, bool enforce)
    {
        if(!enforce)
        {
            return null;
        }

        if(certificate is null)
        {
            throw new ArgumentNullException(
                nameof(certificate),
                "Additional requirement (d) enforcement requires the signing certificate to check the acquired token's generation time against (ETSI TS 119 182-1 V1.2.1, clause 6.3, additional requirement d); supply SigningCertificate or set EnforceSigningCertificateValidity = false explicitly.");
        }

        if(!certificate.IsX509Certificate || !CertificateValidityPeriod.TryRead(certificate, out CertificateValidityPeriod? validityPeriod))
        {
            throw new JAdESAugmentationException(
                JAdESAugmentationFailureKind.SigningCertificateMalformed,
                "The signing certificate could not be read to check its validity window (ETSI TS 119 182-1 V1.2.1, clause 6.3, additional requirement d).");
        }

        return validityPeriod;
    }


    /// <summary>Enforces additional requirement (d)'s genTime half against an acquired token.</summary>
    /// <exception cref="JAdESAugmentationException">The token's generation time falls outside <paramref name="validityPeriod"/> or at/after <paramref name="revokedAt"/>.</exception>
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
            throw new JAdESAugmentationException(
                JAdESAugmentationFailureKind.SigningCertificateNotValidAtTimestamp,
                $"The acquired time-stamp token was generated at {generationTime:O}, outside the signing certificate's validity window {validityPeriod.NotBefore:O} to {validityPeriod.NotAfter:O} (ETSI TS 119 182-1 V1.2.1, clause 6.3, additional requirement d).");
        }

        if(revokedAt is { } revocationInstant && generationTime >= revocationInstant)
        {
            throw new JAdESAugmentationException(
                JAdESAugmentationFailureKind.SigningCertificateRevokedBeforeTimestamp,
                $"The acquired time-stamp token was generated at {generationTime:O}, at or after the signing certificate's revocation instant {revocationInstant:O} (ETSI TS 119 182-1 V1.2.1, clause 6.3, additional requirement d).");
        }
    }


    /// <summary>Rents a pooled buffer and writes <paramref name="text"/> as ASCII octets — the wire-text-preservation carrier <see cref="CryptoTags.JoseEncodedProtectedHeader"/>/<see cref="CryptoTags.JoseEncodedSignatureValue"/> label (no naked intermediate array).</summary>
    private static PooledMemory RentAsciiBytes(string text, Tag tag, BaseMemoryPool pool)
    {
        IMemoryOwner<byte> owner = pool.Rent(Math.Max(text.Length, 1));
        try
        {
            Encoding.ASCII.GetBytes(text, owner.Memory.Span);

            return new PooledMemory(owner, text.Length, tag);
        }
        catch
        {
            owner.Dispose();
            throw;
        }
    }


    /// <summary>
    /// Builds the augmented <see cref="JwsMessage"/> from <paramref name="message"/>'s own already-verified wire
    /// facts (the protected header's own base64url TEXT, a fresh COPY of the JWS Signature Value bytes, the
    /// payload, and the attachment state) plus <paramref name="finalUnsignedHeaders"/>'s projection, and
    /// serializes it. A Compact-serialized input is promoted to Flattened JSON, since a non-empty JWS
    /// Unprotected Header forbids Compact serialization (JA-4-05) and every augmentation verb adds one.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "signatureCopy is immediately wrapped into component, then newMessage, which is disposed " +
            "by the 'using var newMessage' below (cascading Signature.Dispose) once JwsSerialization.Serialize " +
            "has already produced the returned, fully independent byte[]. Roslyn does not trace ownership " +
            "through the two intermediate constructor calls to that using declaration.")]
    private static byte[] SerializeAugmented(
        UnverifiedJAdESMessage message,
        JAdESUnsignedHeaders finalUnsignedHeaders,
        EncodeJAdESUnprotectedHeaderDelegate encodeUnprotectedHeader,
        EncodeDelegate base64UrlEncoder,
        Func<object, byte[]> jsonSerializer,
        BaseMemoryPool pool)
    {
        UnverifiedJwsSignature originalSignature = message.Wire.Signatures[0];
        Signature signatureCopy = originalSignature.SignatureBytes.Memory.Span.ToSignature(CryptoTags.AlgorithmAgnosticSignature, pool);

        IReadOnlyDictionary<string, object>? unprotectedHeader = encodeUnprotectedHeader(finalUnsignedHeaders);
        var component = new JwsSignatureComponent(originalSignature.Protected, EmptyProtectedHeaderDictionary, signatureCopy, unprotectedHeader);
        using var newMessage = new JwsMessage(message.Wire.Payload, component, message.Wire.IsDetachedPayload);

        JoseSerializationFormat format = message.Format == JoseSerializationFormat.Compact
            ? JoseSerializationFormat.FlattenedJson
            : message.Format;

        return JwsSerialization.Serialize(newMessage, format, base64UrlEncoder, jsonSerializer);
    }


    //Never read by JwsSerialization -- JwsSignatureComponent.Protected is the wire truth for every serialization
    //form (never a re-derived encoding of the decoded model). Shared, never mutated.
    private static readonly Dictionary<string, object> EmptyProtectedHeaderDictionary = [];


    /// <summary>Throws a typed <see cref="JAdESAugmentationException"/> naming <paramref name="failureKind"/> when <paramref name="isOfKind"/> is <see langword="false"/>.</summary>
    private static void EnsureKind(bool isOfKind, JAdESAugmentationFailureKind failureKind, string message)
    {
        if(!isOfKind)
        {
            throw new JAdESAugmentationException(failureKind, message);
        }
    }
}
