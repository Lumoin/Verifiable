using Verifiable.Cryptography;
using Verifiable.Tpm.Spec.Algorithms;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Automata;

/// <summary>
/// The members a resolved authorization-area slot's session exposes regardless of kind — an
/// <see cref="HmacSessionState"/> or a <see cref="PolicySessionState"/> — read by the shared session ladder
/// (<c>TryResolveCommandSession</c>, <c>TryRefuseAuthorizationArea</c>), the command-HMAC verification queue
/// (<c>TpmPendingSessionVerification</c>, already session-kind-erased), and the response framer
/// (<c>RealResponseSession</c>). TPM 2.0 Library Part 1, Table 12 footnote [2] admits either kind at a decrypt
/// or encrypt companion slot ("an HMAC authorization session can also be used for encryption, decryption, and
/// audit and a policy authorization session can also be used for encryption and decryption"), and clause 18
/// keys both alike on <c>sessionKey</c> alone when the slot is not being used for authorization ("If the
/// session is not being used for authorization, sessionValue is sessionKey") — so every member a companion's
/// command HMAC, response HMAC, and parameter encryption/decryption need is common to both kinds and lives
/// here. Members meaningful only to an HMAC session (<see cref="HmacSessionState.IsAudit"/>,
/// <see cref="HmacSessionState.BoundEntity"/>, <see cref="HmacSessionState.AuditDigest"/> — audit is
/// "restricted to HMAC sessions," Part 1, clause 15.6.4) stay on <see cref="HmacSessionState"/> and are read
/// through a type pattern where an authorizing slot's bind-omission logic needs them.
/// </summary>
public interface IAuthSessionState
{
    /// <summary>
    /// Gets the session's handle (TPM 2.0 Library Part 2, clause 7.2), widened to the generic
    /// <see cref="TpmHandle"/> shape since an <see cref="HmacSessionState"/>'s <c>TPMI_SH_HMAC</c> handle and a
    /// <see cref="PolicySessionState"/>'s <c>TPMI_SH_POLICY</c> handle are otherwise distinct types.
    /// </summary>
    TpmHandle Handle { get; }

    /// <summary>
    /// Gets the session's hash algorithm — the <c>authHash</c> supplied at <c>TPM2_StartAuthSession()</c> —
    /// which drives the command- and response-HMAC width and the KDFa derivations (TPM 2.0 Library Part 1,
    /// clause 16.6.5).
    /// </summary>
    TpmiAlgHash SessionAlg { get; }

    /// <summary>
    /// Gets the session key: the HMAC key term and the parameter-encryption key seed
    /// (TPM 2.0 Library Part 1, clause 16.6.10 equation 20, or the shared Empty-Buffer carrier when the session
    /// is neither bound nor salted, clause 16.6.9).
    /// </summary>
    SymmetricKeyMemory SessionKey { get; }

    /// <summary>
    /// Gets the symmetric definition negotiated at <c>TPM2_StartAuthSession()</c> (XOR obfuscation or
    /// AES-CFB), which keys parameter encryption when this session claims <c>decrypt</c> or <c>encrypt</c>
    /// (TPM 2.0 Library Part 1, clause 18.1).
    /// </summary>
    TpmtSymDef Symmetric { get; }

    /// <summary>
    /// Gets the session's current nonceTPM (TPM 2.0 Library Part 2, clause 10.3.4, Table 92), rolled to a fresh
    /// value on each command response (TPM 2.0 Library Part 1, clause 16.6.5).
    /// </summary>
    Tpm2bNonce NonceTpm { get; }

    /// <summary>
    /// Gets whether the entity this session is bound to receives dictionary-attack protection, captured once at
    /// <c>TPM2_StartAuthSession()</c> (TPM 2.0 Library Part 1, clause 16.6.10: "The noDA attribute of the bind
    /// entity is recorded in the session context").
    /// </summary>
    bool IsBoundEntityDaProtected { get; }

    /// <summary>
    /// Gets whether the bind entity is <c>TPM_RH_LOCKOUT</c>, the one permanent entity whose authValue is
    /// dictionary-attack protected (TPM 2.0 Library Part 1, clause 16.8.1).
    /// </summary>
    bool IsBoundToLockout { get; }
}
