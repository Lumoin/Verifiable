namespace Verifiable.Fido2;

/// <summary>
/// Classifies why a <see cref="Fido2FormatException"/> was thrown, at the granularity CTAP 2.3
/// section 8's status-code table distinguishes: a genuinely non-conformant CBOR encoding versus a
/// conformant encoding whose decoded structure or value does not satisfy a Required member. CTAP
/// command decode boundaries (<see cref="Fido2FormatException.FailureKind"/>) use this to choose
/// between <c>CTAP2_ERR_INVALID_CBOR</c>, <c>CTAP2_ERR_CBOR_UNEXPECTED_TYPE</c>, and
/// <c>CTAP2_ERR_MISSING_PARAMETER</c> rather than collapsing every decode failure onto one status
/// byte.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#error-responses">
/// CTAP 2.3, section 8.2: Status codes</see>. See
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#message-encoding">
/// section 8: Message Encoding</see>, lines 8775-8783, for the two SHOULDs this enum's first two
/// members realize.
/// </remarks>
public enum Fido2FormatFailureKind
{
    /// <summary>
    /// The bytes fail to parse as CTAP2 canonical CBOR at all: a syntax error, a truncated buffer,
    /// a tagged value (CBOR major type 6, forbidden by snapshot line 8750), a non-canonical integer
    /// or length encoding, or a duplicate map key. Snapshot lines 8775-8776's SHOULD names
    /// <c>CTAP2_ERR_INVALID_CBOR</c> for this case.
    /// </summary>
    MalformedCbor,

    /// <summary>
    /// The bytes parse as well-formed CTAP2 canonical CBOR, but a nested or extension-map member
    /// carries a value of the wrong CBOR major type for what its key requires (for example, an
    /// <c>rp</c> entity's <c>id</c> present as something other than a text string, or a boolean-typed
    /// extension key carrying an integer), or a required member nested inside such a structure is
    /// absent. Snapshot lines 8777-8783's SHOULD names <c>CTAP2_ERR_CBOR_UNEXPECTED_TYPE</c> for this
    /// case.
    /// </summary>
    UnexpectedStructure,

    /// <summary>
    /// A Required TOP-LEVEL command parameter (for example, <c>authenticatorMakeCredential</c>'s
    /// <c>clientDataHash</c>, <c>authenticatorGetAssertion</c>'s <c>rpId</c>, or
    /// <c>authenticatorClientPIN</c>/<c>authenticatorConfig</c>/<c>authenticatorCredentialManagement</c>'s
    /// <c>subCommand</c>) is absent from an otherwise well-formed request map. CTAP 2.3 section 8.2's
    /// <c>CTAP2_ERR_MISSING_PARAMETER</c> row ("Missing non-optional parameter") governs this case;
    /// <c>authenticatorConfig</c>'s own section 6.11 additionally names it by MUST at snapshot line
    /// 7953 for its own <c>subCommand</c> member.
    /// </summary>
    MissingRequiredParameter
}
