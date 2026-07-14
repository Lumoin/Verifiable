namespace Verifiable.Fido2.Ctap.Authenticator.Automata;

/// <summary>
/// The attestation statement shape an <c>authenticatorMakeCredential</c> effect must produce, resolved by
/// the pure transition from the request's <c>attestationFormatsPreference</c>.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorMakeCredential">
/// CTAP 2.3, section 6.1.2</see>, step 17. This simulator supports exactly three attestation statement
/// shapes: <c>packed</c> self-attestation, <c>packed</c> certified (enterprise) attestation, and
/// <c>none</c>. <see cref="PackedCertified"/> is never a direct product of this step's own
/// <c>attestationFormatsPreference</c> resolution — it is <see cref="PackedSelf"/>'s resolution UPGRADED
/// by mc Step 9's enterprise-attestation grant (waveep R6/R8: a granted request whose preference
/// resolution is <see cref="PackedSelf"/> upgrades to this member; a none-family resolution never does).
/// </remarks>
public enum CtapAttestationFormatChoice
{
    /// <summary>
    /// Mint and sign a packed self-attestation statement — the authenticator's own default choice when
    /// <c>attestationFormatsPreference</c> is absent or empty ("generate an attestation statement for the
    /// newly-created credential"), and also the fallback ("the authenticator may select a format by any
    /// other means") when a supplied preference list names no format this authenticator supports.
    /// </summary>
    PackedSelf,

    /// <summary>
    /// Mint and sign a packed CERTIFIED (enterprise) attestation statement: the signature is over
    /// <c>authData ‖ clientDataHash</c> with the SEEDED enterprise attestation private key — never the
    /// credential private key (CTAP 2.3 §7.1, waveep R7, trap 11) — and the attStmt carries the seeded
    /// <c>x5c</c> chain. Reached only when mc Step 9 grants an enterprise attestation (waveep R6) AND the
    /// request's own <c>attestationFormatsPreference</c> resolution is <see cref="PackedSelf"/> (waveep
    /// R8: a none-family resolution declines the grant instead). The response's <c>epAtt</c> member is
    /// <see langword="true"/> exactly when this member is chosen (waveep R9) — never a second, separately
    /// computed flag.
    /// </summary>
    PackedCertified,

    /// <summary>
    /// Emit <c>fmt=none</c> with the standard section 8.7 empty-map <c>attStmt</c> present on the wire —
    /// the outcome when a supplied <c>attestationFormatsPreference</c> list's lowest-index supported entry
    /// is <c>none</c>, but the list is not the single-entry <c>["none"]</c> case that resolves to
    /// <see cref="NoneOmitted"/> instead.
    /// </summary>
    NoneWithStatement,

    /// <summary>
    /// Emit <c>fmt=none</c> with <c>attStmt</c> omitted entirely from the CTAP wire response — step 17's
    /// "If attestationFormatsPreference is present and contains only one entry with the value none, omit
    /// attestation from the output," worded independently of whether this authenticator supports more
    /// than one format.
    /// </summary>
    NoneOmitted
}
