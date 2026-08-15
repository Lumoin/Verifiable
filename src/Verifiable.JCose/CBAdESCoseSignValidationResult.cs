using System.Diagnostics;
using Verifiable.Cryptography.Pki;

namespace Verifiable.JCose;

/// <summary>
/// One signer's own outcome within a <see cref="CBAdESCoseSignValidationResult"/> — the <c>COSE_Sign</c>
/// (multi-signer) counterpart of <see cref="CBAdESValidationResult"/>'s single-signer facts, scoped per signer
/// layer.
/// </summary>
/// <remarks>
/// <strong>Ownership.</strong> Owns <see cref="Headers"/> and <see cref="UnsignedHeaders"/> when present;
/// <see cref="Dispose"/> disposes both. Mint-only (internal constructor/factories) — mirrors
/// <see cref="CBAdESValidationResult"/>'s own mint-only rationale.
/// </remarks>
[DebuggerDisplay("CBAdESCoseSignSignerValidationResult: IsValid={IsValid}")]
public sealed class CBAdESCoseSignSignerValidationResult: IDisposable
{
    private bool disposed;


    /// <summary>
    /// Initializes a new <see cref="CBAdESCoseSignSignerValidationResult"/>. Internal — see the type remarks
    /// for the mint-only rationale.
    /// </summary>
    /// <param name="isValid">See <see cref="IsValid"/>.</param>
    /// <param name="headers">See <see cref="Headers"/>. Ownership transfers to this instance when supplied.</param>
    /// <param name="unsignedHeaders">See <see cref="UnsignedHeaders"/>. Ownership transfers to this instance when supplied.</param>
    /// <param name="violations">See <see cref="Violations"/>.</param>
    /// <param name="signatureVerified">See <see cref="SignatureVerified"/>.</param>
    internal CBAdESCoseSignSignerValidationResult(
        bool isValid,
        CBAdESProtectedHeaders? headers,
        CBAdESUnsignedHeaders? unsignedHeaders,
        IReadOnlyList<CBAdESRuleViolation> violations,
        bool signatureVerified)
    {
        IsValid = isValid;
        Headers = headers;
        UnsignedHeaders = unsignedHeaders;
        Violations = violations;
        SignatureVerified = signatureVerified;
    }


    /// <summary>Whether this signer's own protected header is structurally conformant, level-conformant, and cryptographically valid.</summary>
    public bool IsValid { get; }

    /// <summary>
    /// Gets whether this signer's own protected header decoded at all — <see langword="false"/> means the
    /// signer-layer bytes did not decode into a well-formed <see cref="CBAdESProtectedHeaders"/> aggregate, and
    /// every other member below carries no meaning.
    /// </summary>
    public bool HeaderDecoded => Headers is not null;

    /// <summary>
    /// Gets this signer's own decoded signed-header-set aggregate, or <see langword="null"/> when it failed to
    /// decode. Owned by this instance when non-null; disposed via <see cref="Dispose"/>.
    /// </summary>
    public CBAdESProtectedHeaders? Headers { get; }

    /// <summary>
    /// Gets this signer's own decoded <c>uHeaders</c> set, or <see langword="null"/> when absent or the header
    /// failed to decode. Owned by this instance when non-null; disposed via <see cref="Dispose"/>.
    /// </summary>
    public CBAdESUnsignedHeaders? UnsignedHeaders { get; }

    /// <summary>
    /// Gets every B-B (<see cref="CBAdESHeaderRules"/>) and level-scoped (<see cref="CBAdESLevelRules"/>)
    /// conformance violation found for this signer, in rule-declaration order; empty when the header decoded
    /// and is fully conformant.
    /// </summary>
    public IReadOnlyList<CBAdESRuleViolation> Violations { get; }

    /// <summary>
    /// Gets whether this signer's own COSE signature value cryptographically verifies — meaningful only when
    /// <see cref="HeaderDecoded"/> is <see langword="true"/> and <see cref="Violations"/> is empty (this
    /// orchestrator does not attempt cryptographic verification once a structural/level violation is already
    /// known, mirroring <see cref="CBAdESSignatureValidation"/>'s own B-B-rules-before-crypto ordering).
    /// </summary>
    public bool SignatureVerified { get; }


    /// <summary>Mints a successful signer result. Ownership of <paramref name="headers"/>/<paramref name="unsignedHeaders"/> transfers.</summary>
    internal static CBAdESCoseSignSignerValidationResult Success(CBAdESProtectedHeaders headers, CBAdESUnsignedHeaders? unsignedHeaders) =>
        new(true, headers, unsignedHeaders, [], true);


    /// <summary>Mints a failed signer result whose header did not decode.</summary>
    internal static CBAdESCoseSignSignerValidationResult MalformedHeader() =>
        new(false, null, null, [], false);


    /// <summary>Mints a failed signer result carrying one or more conformance violations.</summary>
    /// <param name="headers">The decoded (but non-conformant) aggregate. Ownership transfers.</param>
    /// <param name="unsignedHeaders">The decoded <c>uHeaders</c> set, or <see langword="null"/>. Ownership transfers when supplied.</param>
    /// <param name="violations">The collected violations. Never empty.</param>
    internal static CBAdESCoseSignSignerValidationResult RuleViolations(
        CBAdESProtectedHeaders headers, CBAdESUnsignedHeaders? unsignedHeaders, IReadOnlyList<CBAdESRuleViolation> violations) =>
        new(false, headers, unsignedHeaders, violations, false);


    /// <summary>Mints a failed signer result whose header/level rules hold but whose signature does not verify.</summary>
    internal static CBAdESCoseSignSignerValidationResult SignatureInvalid(CBAdESProtectedHeaders headers, CBAdESUnsignedHeaders? unsignedHeaders) =>
        new(false, headers, unsignedHeaders, [], false);


    /// <summary>Disposes <see cref="Headers"/> and <see cref="UnsignedHeaders"/> when present.</summary>
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
/// The outcome of validating a CB-AdES <c>COSE_Sign</c> (multi-signer) structure —
/// <see cref="CBAdESSignatureValidation.ValidateCoseSignAsync"/>'s own result type, the multi-signer
/// counterpart of <see cref="CBAdESValidationResult"/>.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Scope, matching <see cref="CBAdESSignatureCreation.SignCoseSignAsync"/>'s own recorded decision.</strong>
/// This validates the SAME shape that creation path produces: an attached payload, an empty body layer, one
/// or more signers each checked through the identical <see cref="CBAdESHeaderRules"/>/<see cref="CBAdESLevelRules"/>
/// rule bodies the <c>COSE_Sign1</c> path uses. Timestamp-token CONTENT verification (opening and
/// message-imprint-binding a <c>sigTst</c>/<c>valData</c>/<c>refs</c>/<c>arcTst</c> element's own material) is
/// NOT replicated here — <see cref="CBAdESCoseSignSignerValidationResult.Violations"/> reports Table 14
/// presence/cardinality conformance (<see cref="CBAdESLevelRules"/>) for whichever <paramref name="level"/> was
/// declared, not content-level token verification; a caller needing that depth for a specific signer composes
/// it separately, the same way the message-imprint threading test proves the underlying
/// <c>TryBuildArchiveTimestampValidationMessageImprintInput</c> seam already accepts a <c>COSE_Sign</c> signer's
/// own protected header (steps 2/4/10).
/// </para>
/// <para>
/// <strong>Ownership.</strong> Owns every entry of <see cref="Signers"/>; <see cref="Dispose"/> disposes all
/// of them.
/// </para>
/// </remarks>
[DebuggerDisplay("CBAdESCoseSignValidationResult: IsValid={IsValid}, signers={Signers.Count}")]
public sealed class CBAdESCoseSignValidationResult: IDisposable
{
    private bool disposed;


    /// <summary>
    /// Initializes a new <see cref="CBAdESCoseSignValidationResult"/>. Internal — mirrors
    /// <see cref="CBAdESValidationResult"/>'s own mint-only rationale. Ownership of every entry of
    /// <paramref name="signers"/> transfers to this instance.
    /// </summary>
    /// <param name="isValid">See <see cref="IsValid"/>.</param>
    /// <param name="isMalformed">See <see cref="IsMalformed"/>.</param>
    /// <param name="signers">See <see cref="Signers"/>.</param>
    /// <param name="bodyLayerViolations">See <see cref="BodyLayerViolations"/>.</param>
    internal CBAdESCoseSignValidationResult(
        bool isValid,
        bool isMalformed,
        IReadOnlyList<CBAdESCoseSignSignerValidationResult> signers,
        IReadOnlyList<CBAdESRuleViolation>? bodyLayerViolations = null)
    {
        ArgumentNullException.ThrowIfNull(signers);

        IsValid = isValid;
        IsMalformed = isMalformed;
        Signers = signers;
        BodyLayerViolations = bodyLayerViolations ?? [];
    }


    /// <summary>Whether the wire bytes decoded as a well-formed CB-AdES <c>COSE_Sign</c> structure AND every signer is individually valid AND the body layer carries no misplaced signer-layer-only component.</summary>
    public bool IsValid { get; }

    /// <summary>
    /// Gets whether the wire bytes failed to decode as a well-formed CB-AdES <c>COSE_Sign</c> structure at all
    /// (clause 4.4's own structural checks, <see cref="CBAdESSignatureSerialization.ParseCBAdESSign"/>) —
    /// when <see langword="true"/>, <see cref="Signers"/> is empty and no per-signer fact exists.
    /// </summary>
    public bool IsMalformed { get; }

    /// <summary>
    /// Gets every signer's own outcome, in wire order — empty only when <see cref="IsMalformed"/> is
    /// <see langword="true"/>. Owned by this instance; disposed via <see cref="Dispose"/>.
    /// </summary>
    public IReadOnlyList<CBAdESCoseSignSignerValidationResult> Signers { get; }

    /// <summary>
    /// Gets every <see cref="CBAdESCoseSignBodyLayerPlacementViolation"/> found on the body layer's own
    /// decoded protected header — a signer-layer-only component (clause 4.4/clauses 5.1-5.2's "shall be
    /// placed at the signer layer" MUSTs) present where it must not be. Empty when the body layer's protected
    /// header does not decode at all (no <c>alg</c>, the ordinary conformant empty-body-layer case — see
    /// <see cref="CBAdESSignatureValidation.ValidateCoseSignAsync"/>'s own remarks) or decodes with no
    /// signer-layer-only component present.
    /// </summary>
    public IReadOnlyList<CBAdESRuleViolation> BodyLayerViolations { get; }


    /// <summary>Mints a result for a well-formed message whose per-signer outcomes are already known.</summary>
    /// <param name="signers">Every signer's own outcome, in wire order. Ownership transfers.</param>
    /// <param name="bodyLayerViolations">See <see cref="BodyLayerViolations"/>.</param>
    /// <returns>
    /// A result whose <see cref="IsValid"/> is the AND-reduction of every signer's own
    /// <see cref="CBAdESCoseSignSignerValidationResult.IsValid"/> AND <paramref name="bodyLayerViolations"/> being empty.
    /// </returns>
    internal static CBAdESCoseSignValidationResult FromSigners(
        IReadOnlyList<CBAdESCoseSignSignerValidationResult> signers, IReadOnlyList<CBAdESRuleViolation>? bodyLayerViolations = null)
    {
        bool allValid = signers.Count > 0 && (bodyLayerViolations is null || bodyLayerViolations.Count == 0);
        for(int i = 0; i < signers.Count; ++i)
        {
            allValid &= signers[i].IsValid;
        }

        return new CBAdESCoseSignValidationResult(allValid, false, signers, bodyLayerViolations);
    }


    /// <summary>Mints a result for wire bytes that failed to decode as a well-formed <c>COSE_Sign</c> structure at all.</summary>
    internal static CBAdESCoseSignValidationResult Malformed() => new(false, true, []);


    /// <summary>Disposes every entry of <see cref="Signers"/>.</summary>
    public void Dispose()
    {
        if(disposed)
        {
            return;
        }

        foreach(CBAdESCoseSignSignerValidationResult signer in Signers)
        {
            signer.Dispose();
        }

        disposed = true;
    }
}
