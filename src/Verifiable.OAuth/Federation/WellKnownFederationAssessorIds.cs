using System.Diagnostics;

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
    /// <summary>
    /// Emitted by the Entity Statement validator per Federation §3.2's
    /// 27 validation steps.
    /// </summary>
    public static readonly string ValidateEntityStatement =
        "urn:verifiable:assessor:federation:validate_entity_statement";

    /// <summary>
    /// Emitted by the inline trust chain validator per Federation §4.3.
    /// </summary>
    public static readonly string ValidateTrustChain =
        "urn:verifiable:assessor:federation:validate_trust_chain";

    /// <summary>
    /// Emitted by the metadata policy merger and applicator per
    /// Federation §6.1.4.
    /// </summary>
    public static readonly string ApplyMetadataPolicy =
        "urn:verifiable:assessor:federation:apply_metadata_policy";

    /// <summary>
    /// Emitted by the <c>ApprovePartyDelegate</c> default implementation
    /// after a chain has resolved to a trust anchor.
    /// </summary>
    public static readonly string ApproveParty =
        "urn:verifiable:assessor:federation:approve_party";

    /// <summary>
    /// Emitted by the Trust Mark validator per Federation §7.3.
    /// </summary>
    public static readonly string VerifyTrustMark =
        "urn:verifiable:assessor:federation:verify_trust_mark";
}
