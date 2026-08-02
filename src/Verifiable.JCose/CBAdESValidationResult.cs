using System.Diagnostics;
using Verifiable.Cryptography.Pki;

namespace Verifiable.JCose;

/// <summary>
/// The outcome of validating a CB-AdES <c>COSE_Sign1</c> structure — the decoded facts when
/// <see cref="IsValid"/> is <see langword="true"/>, or a closed-sum failure detail otherwise. Produced by
/// <see cref="CBAdESSignatureValidation"/>'s <c>ValidateAsync</c> overloads, the CB-AdES counterpart of
/// <see cref="Verifiable.Cbor.CoseVerificationResult"/> (mint-only pattern) and
/// <c>Verifiable.Cryptography.Pki.SignatureValidationOutcome</c> (owns disposable carriers).
/// </summary>
/// <remarks>
/// <para>
/// <strong>Mint-only.</strong> The constructor and the <see cref="Success"/>/<see cref="Failed"/> factories
/// are <see langword="internal"/>, so a result with <see cref="IsValid"/> <see langword="true"/> can only
/// originate from <see cref="CBAdESSignatureValidation"/> — application code cannot fabricate a "valid"
/// result. This mirrors <see cref="Verifiable.Cbor.CoseVerificationResult"/>'s mint-only shape; the
/// difference — a sealed class rather than a readonly record struct — follows from ownership: this result
/// carries <see cref="Headers"/> and <see cref="UnsignedHeaders"/>, both of which own pool-rented carriers
/// (S1/S2 component models such as <see cref="CBAdESCertificateThumbprint"/>/<see cref="CBAdESDetachedObjects"/>),
/// so the result itself must be <see cref="IDisposable"/> — a value-type record struct cannot express that.
/// </para>
/// <para>
/// <strong>Scope boundary (wavecb-contract.md stage list; S3 coordinator ruling (6)).</strong> This is the
/// structural-conformance-plus-cryptographic-verification verdict for the B-B baseline level only: every
/// clause-5 signed/unsigned header rule this stage's <see cref="CBAdESHeaderRules"/> enforces, plus the COSE
/// signature-value check itself, over caller-provided key material. It is NOT an
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf">
/// ETSI EN 319 102-1</see> Indication/SubIndication conclusion — certificate-path trust, revocation, and
/// time-stamp validation (B-T/B-LT/B-LTA) are later stages (S4/S7), and mapping this B-B verdict onto the
/// EN 319 102-1 vocabulary is stage S7's job, not this type's.
/// </para>
/// <para>
/// <strong>Decoded facts are success-only.</strong> On every failure arm — including
/// <see cref="CBAdESRuleViolationsFailure"/>, <see cref="CBAdESSignatureInvalidFailure"/>,
/// <see cref="CBAdESDetachedObjectUnresolvableFailure"/>, and <see cref="CBAdESDetachedObjectDigestMismatchFailure"/>,
/// all of which are reached only after the wire bytes parsed successfully — <see cref="Headers"/> and
/// <see cref="UnsignedHeaders"/> are <see langword="null"/>. Whatever the orchestrator decoded before hitting
/// the failure is disposed internally rather than handed to the caller, so a failed result never leaks a
/// half-owned carrier the caller has no reference to.
/// </para>
/// <para>
/// <strong>Ownership.</strong> On success, this instance owns <see cref="Headers"/> and
/// <see cref="UnsignedHeaders"/> (when present); <see cref="Dispose"/> disposes both. The verified payload
/// bytes and the underlying <see cref="CoseSign1Message"/> are NOT carried by this result — the orchestrator
/// disposes its own <see cref="CoseSign1Message"/> before returning, since neither this stage's contract nor
/// its task charter asks for the payload bytes to survive the call; a later stage that needs them composes
/// its own read of the same wire bytes rather than this type growing an unrequested member.
/// </para>
/// </remarks>
[DebuggerDisplay("CBAdESValidationResult: IsValid={IsValid}")]
public sealed class CBAdESValidationResult: IDisposable
{
    /// <summary>Whether <see cref="Dispose"/> has already run.</summary>
    private bool disposed;


    /// <summary>
    /// Initializes a new <see cref="CBAdESValidationResult"/>. Internal — see the type remarks for the
    /// mint-only rationale.
    /// </summary>
    /// <param name="isValid">See <see cref="IsValid"/>.</param>
    /// <param name="headers">See <see cref="Headers"/>. Ownership transfers to this instance when supplied.</param>
    /// <param name="payloadIsDetached">See <see cref="PayloadIsDetached"/>.</param>
    /// <param name="unsignedHeaders">See <see cref="UnsignedHeaders"/>. Ownership transfers to this instance when supplied.</param>
    /// <param name="failure">See <see cref="Failure"/>.</param>
    internal CBAdESValidationResult(
        bool isValid,
        CBAdESProtectedHeaders? headers,
        bool payloadIsDetached,
        CBAdESUnsignedHeaders? unsignedHeaders,
        CBAdESValidationFailure? failure)
    {
        IsValid = isValid;
        Headers = headers;
        PayloadIsDetached = payloadIsDetached;
        UnsignedHeaders = unsignedHeaders;
        Failure = failure;
    }


    /// <summary>Whether the CB-AdES signature is structurally conformant and cryptographically valid.</summary>
    public bool IsValid { get; }

    /// <summary>
    /// Gets the decoded signed-header-set aggregate when <see cref="IsValid"/> is <see langword="true"/>;
    /// otherwise <see langword="null"/> (see the type remarks). Owned by this instance when non-null;
    /// disposed via <see cref="Dispose"/>.
    /// </summary>
    public CBAdESProtectedHeaders? Headers { get; }

    /// <summary>
    /// Gets whether the COSE Payload this signature covers is detached (clause 4.5), valid only when
    /// <see cref="IsValid"/> is <see langword="true"/> — <see langword="false"/> on every failure arm,
    /// carrying no meaning there.
    /// </summary>
    public bool PayloadIsDetached { get; }

    /// <summary>
    /// Gets the decoded <c>uHeaders</c> unsigned-header set when <see cref="IsValid"/> is <see langword="true"/>
    /// and the signature incorporates one; <see langword="null"/> when valid but no <c>uHeaders</c> was
    /// present, or on any failure arm (see the type remarks). Owned by this instance when non-null; disposed
    /// via <see cref="Dispose"/>.
    /// </summary>
    public CBAdESUnsignedHeaders? UnsignedHeaders { get; }

    /// <summary>
    /// Gets the failure detail when <see cref="IsValid"/> is <see langword="false"/>; otherwise
    /// <see langword="null"/>.
    /// </summary>
    public CBAdESValidationFailure? Failure { get; }


    /// <summary>
    /// Mints a successful result, transferring ownership of <paramref name="headers"/> and
    /// <paramref name="unsignedHeaders"/> (when supplied) to the returned instance. Internal so only
    /// <see cref="CBAdESSignatureValidation"/> can produce one.
    /// </summary>
    /// <param name="headers">The decoded signed-header-set aggregate.</param>
    /// <param name="payloadIsDetached">Whether the COSE Payload this signature covers is detached.</param>
    /// <param name="unsignedHeaders">The decoded <c>uHeaders</c> set, or <see langword="null"/> when absent.</param>
    /// <returns>A valid result.</returns>
    internal static CBAdESValidationResult Success(
        CBAdESProtectedHeaders headers,
        bool payloadIsDetached,
        CBAdESUnsignedHeaders? unsignedHeaders) =>
        new(true, headers, payloadIsDetached, unsignedHeaders, null);


    /// <summary>
    /// Mints a failed result carrying no decoded facts. Internal so only <see cref="CBAdESSignatureValidation"/>
    /// can produce one.
    /// </summary>
    /// <param name="failure">The failure detail.</param>
    /// <returns>An invalid result.</returns>
    internal static CBAdESValidationResult Failed(CBAdESValidationFailure failure) =>
        new(false, null, false, null, failure);


    /// <summary>
    /// Disposes <see cref="Headers"/> and <see cref="UnsignedHeaders"/> when present.
    /// </summary>
    public void Dispose()
    {
        if(disposed)
        {
            return;
        }

        Headers?.Dispose();
        UnsignedHeaders?.Dispose();
        disposed = true;
    }
}


/// <summary>
/// Why a <see cref="CBAdESValidationResult"/> failed — a DU-ready closed sum: no external type may derive
/// from it.
/// </summary>
public abstract record CBAdESValidationFailure
{
    /// <summary>Restricts direct subtyping to the sibling records declared in this file.</summary>
    private protected CBAdESValidationFailure()
    {
    }


    /// <summary>Gets a human-readable statement of the failure.</summary>
    public abstract string Message { get; }
}


/// <summary>
/// The wire bytes are not a well-formed CB-AdES <c>COSE_Sign1</c> structure — the parse seam either returned
/// failure or raised one of the fail-closed exception types <see cref="CBAdESSignatureValidation"/> catches
/// (R-5: parsing of untrusted bytes never throws out of the validation orchestrator).
/// </summary>
[DebuggerDisplay("CBAdESMalformedEncodingFailure")]
public sealed record CBAdESMalformedEncodingFailure: CBAdESValidationFailure
{
    /// <inheritdoc/>
    public override string Message => "The wire bytes do not decode as a well-formed CB-AdES COSE_Sign1 structure.";
}


/// <summary>
/// The wire bytes decoded successfully, but at least one B-B conformance rule
/// (<see cref="CBAdESHeaderRules.Check"/>) is violated.
/// </summary>
/// <param name="Violations">Every violation found, in rule-declaration order. Never empty.</param>
[DebuggerDisplay("CBAdESRuleViolationsFailure: {Violations.Count} violation(s)")]
public sealed record CBAdESRuleViolationsFailure(IReadOnlyList<CBAdESRuleViolation> Violations): CBAdESValidationFailure
{
    /// <inheritdoc/>
    public override string Message => $"{Violations.Count} B-B conformance rule violation(s); see {nameof(Violations)}.";
}


/// <summary>
/// Every B-B conformance rule holds and the verification payload resolved successfully, but the COSE signature
/// value does not verify over it (<see href="https://www.rfc-editor.org/rfc/rfc9052#section-4.4">IETF RFC
/// 9052 §4.4</see>).
/// </summary>
[DebuggerDisplay("CBAdESSignatureInvalidFailure")]
public sealed record CBAdESSignatureInvalidFailure: CBAdESValidationFailure
{
    /// <inheritdoc/>
    public override string Message => "The COSE signature value does not verify over the resolved payload.";
}


/// <summary>
/// The verification payload could not be resolved — the caller supplied no external payload for a detached,
/// unreferenced COSE Payload; a <c>sigD</c> mechanism's dereference delegate reported failure; or <c>sigD</c>
/// named a mechanism this document does not define (CB-5.2.6-07/CB-5.2.8-08) and either no
/// caller-supplied mechanism handler was provided, or the handler reported failure.
/// </summary>
/// <param name="Reference">
/// The <c>pars</c> reference whose dereference failed, or <see langword="null"/> when the failure is not tied
/// to a single reference (an out-of-band detached payload with no caller-supplied bytes; an unknown
/// mechanism with no handler).
/// </param>
/// <param name="Reason">A human-readable statement of why the payload could not be resolved.</param>
[DebuggerDisplay("CBAdESDetachedObjectUnresolvableFailure: {Reference}")]
public sealed record CBAdESDetachedObjectUnresolvableFailure(string? Reference, string Reason): CBAdESValidationFailure
{
    /// <inheritdoc/>
    public override string Message => Reason;
}


/// <summary>
/// Under the <c>ObjectIdByURIHash</c> mechanism, the dereferenced object's digest (computed via the registered
/// digest delegate over the algorithm identified by <c>hashM</c>) does not match the signed <c>hashV</c> entry
/// at the same position (<see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1, clause 5.2.8.2.3</see>, CB-5.2.8.2.3-05).
/// </summary>
/// <param name="Reference">The <c>pars</c> reference whose digest did not match.</param>
[DebuggerDisplay("CBAdESDetachedObjectDigestMismatchFailure: {Reference}")]
public sealed record CBAdESDetachedObjectDigestMismatchFailure(string Reference): CBAdESValidationFailure
{
    /// <inheritdoc/>
    public override string Message =>
        $"The digest of the detached object referenced by '{Reference}' does not match its signed hashV " +
        "entry (ETSI TS 119 152-1 V1.1.1, clause 5.2.8.2.3, CB-5.2.8.2.3-05).";
}
