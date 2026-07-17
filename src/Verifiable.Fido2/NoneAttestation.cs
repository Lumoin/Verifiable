namespace Verifiable.Fido2;

/// <summary>
/// Builds the <c>none</c> attestation statement format's verification procedure.
/// </summary>
/// <remarks>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-none-attestation">W3C Web Authentication Level 3, section 8.7: None Attestation Statement Format.</see>
/// The format's syntax fixes <c>attStmt</c> to the empty CBOR map, so the only thing to verify
/// is that the wire bytes are exactly that map — no CBOR decoder dependency is needed to check
/// it.
/// </remarks>
public static class NoneAttestation
{
    /// <summary>
    /// The single-byte CTAP2 canonical CBOR encoding of the empty map (major type 5, 0
    /// elements): <c>0xA0</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-conforming-all-classes">W3C Web Authentication Level 3, section 2.4: All Conformance Classes.</see>
    /// "All CBOR encoding performed by the members of the above conformance classes MUST be done
    /// using the CTAP2 canonical CBOR encoding form."
    /// </para>
    /// <para>
    /// <see href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#message-encoding">
    /// Client to Authenticator Protocol (CTAP) specification, section 8: Message Encoding.</see>
    /// defines that canonical form: the length of a major-type-5 (map) item MUST be expressed as
    /// short as possible, so an authenticator emitting the empty map for <c>none</c> attestation
    /// per <see href="https://www.w3.org/TR/webauthn-3/#sctn-none-attestation">section 8.7</see>
    /// produces exactly this one byte, with no map-header length variant and no entries. A
    /// verifier accordingly accepts only this exact byte rather than decoding CBOR to confirm the
    /// map is empty, since any other encoding of an empty map is already non-canonical and
    /// therefore itself a fail-closed rejection.
    /// </para>
    /// <para>
    /// Exposed (not <see langword="private"/>) so a CTAP2 <c>authenticatorMakeCredential</c>
    /// response writer emitting a <c>fmt=none</c> attestation statement can reuse this exact
    /// literal for its <c>attStmt</c> member instead of duplicating the byte.
    /// </para>
    /// </remarks>
    public static byte CanonicalEmptyMap => 0xA0;


    /// <summary>
    /// Builds the <c>none</c> attestation statement format's <see cref="AttestationVerifyDelegate"/>.
    /// </summary>
    /// <returns>
    /// A delegate that accepts an <c>attStmt</c> of exactly the single byte
    /// <see cref="CanonicalEmptyMap"/> as <see cref="NoneAttestationResult"/>, and rejects
    /// anything else with <see cref="Fido2AttestationErrors.StatementNotEmpty"/>.
    /// </returns>
    public static AttestationVerifyDelegate Build() => VerifyAsync;


    /// <summary>
    /// Verifies a <c>none</c> attestation statement per
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-none-attestation">W3C Web Authentication Level 3, section 8.7</see>.
    /// </summary>
    private static ValueTask<AttestationResult> VerifyAsync(AttestationVerificationRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        bool isCanonicalEmptyMap = request.AttestationStatement.Length == 1
            && request.AttestationStatement.Span[0] == CanonicalEmptyMap;

        AttestationResult result = isCanonicalEmptyMap
            ? new NoneAttestationResult()
            : new RejectedAttestationResult(Fido2AttestationErrors.StatementNotEmpty);

        return ValueTask.FromResult(result);
    }
}
