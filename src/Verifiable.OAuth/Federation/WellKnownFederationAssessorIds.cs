using System.Diagnostics;
using Verifiable.Cryptography.Text;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// Assessor identifier strings emitted by the Federation library's
/// validators and gate hooks. Each value is the <c>AssessorId</c> on the
/// <see cref="Verifiable.Core.Assessment.AssessmentResult"/> the
/// corresponding library function returns. URN-shaped per the project
/// identifier convention; consumed downstream by audit, telemetry, and
/// W3C Trace Context propagation.
/// </summary>
[DebuggerDisplay("WellKnownFederationAssessorIds")]
public static class WellKnownFederationAssessorIds
{
    /// <summary>The UTF-8 source literal of <see cref="ValidateEntityStatement"/>.</summary>
    public static ReadOnlySpan<byte> ValidateEntityStatementUtf8 => "urn:verifiable:assessor:federation:validate_entity_statement"u8;

    /// <summary>
    /// Emitted by the Entity Statement validator per Federation §3.2's
    /// 27 validation steps.
    /// </summary>
    public static readonly string ValidateEntityStatement = Utf8Constants.ToInternedString(ValidateEntityStatementUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ValidateTrustChain"/>.</summary>
    public static ReadOnlySpan<byte> ValidateTrustChainUtf8 => "urn:verifiable:assessor:federation:validate_trust_chain"u8;

    /// <summary>
    /// Emitted by the inline trust chain validator per Federation §4.3.
    /// </summary>
    public static readonly string ValidateTrustChain = Utf8Constants.ToInternedString(ValidateTrustChainUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ApplyMetadataPolicy"/>.</summary>
    public static ReadOnlySpan<byte> ApplyMetadataPolicyUtf8 => "urn:verifiable:assessor:federation:apply_metadata_policy"u8;

    /// <summary>
    /// Emitted by the metadata policy merger and applicator per
    /// Federation §6.1.4.
    /// </summary>
    public static readonly string ApplyMetadataPolicy = Utf8Constants.ToInternedString(ApplyMetadataPolicyUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ApproveParty"/>.</summary>
    public static ReadOnlySpan<byte> ApprovePartyUtf8 => "urn:verifiable:assessor:federation:approve_party"u8;

    /// <summary>
    /// Emitted by the <c>ApprovePartyDelegate</c> default implementation
    /// after a chain has resolved to a trust anchor.
    /// </summary>
    public static readonly string ApproveParty = Utf8Constants.ToInternedString(ApprovePartyUtf8);

    /// <summary>The UTF-8 source literal of <see cref="VerifyTrustMark"/>.</summary>
    public static ReadOnlySpan<byte> VerifyTrustMarkUtf8 => "urn:verifiable:assessor:federation:verify_trust_mark"u8;

    /// <summary>
    /// Emitted by the Trust Mark validator per Federation §7.3.
    /// </summary>
    public static readonly string VerifyTrustMark = Utf8Constants.ToInternedString(VerifyTrustMarkUtf8);
}
