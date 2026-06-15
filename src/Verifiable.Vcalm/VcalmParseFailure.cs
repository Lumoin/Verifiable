namespace Verifiable.Vcalm;

/// <summary>
/// Why a VCALM 1.0 verify request body failed STRICT parsing, distinguishing the §2.4 MUSTs the
/// endpoint maps to distinct HTTP outcomes. <see cref="None"/> means the body parsed.
/// </summary>
/// <remarks>
/// §2.4 splits two rejection reasons the endpoint answers differently. A body that is not a
/// well-formed JSON object, or carries an unrecognized TOP-LEVEL member, is a malformed request →
/// HTTP 400 (§3.3.1 "invalid input!"). A body whose <c>options</c> object carries an unrecognized
/// member is the §2.4 unknown-option MUST → HTTP 400 with the §3.8
/// <see cref="VcalmProblemTypes.UnknownOptionProvided"/> problem type. Keeping them distinct lets
/// the endpoint emit the spec-required problem type for the latter while answering a plain 400 for
/// the former.
/// </remarks>
public enum VcalmParseFailure
{
    /// <summary>No failure; the body parsed into a verify request.</summary>
    None = 0,

    /// <summary>
    /// The body is not a well-formed JSON object, is missing the REQUIRED credential / presentation
    /// member, carries an unrecognized top-level member, or carries a credential / presentation that
    /// is not a recognized secured shape. The §2.4 / §3.3.1 malformed-input → HTTP 400 case.
    /// </summary>
    Malformed,

    /// <summary>
    /// The <c>options</c> object carried a member the verifier does not understand. The §2.4
    /// unknown-option MUST → HTTP 400 with the §3.8
    /// <see cref="VcalmProblemTypes.UnknownOptionProvided"/> problem type.
    /// </summary>
    UnknownOption
}
