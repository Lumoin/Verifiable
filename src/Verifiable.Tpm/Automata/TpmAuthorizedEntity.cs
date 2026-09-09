using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Automata;

/// <summary>
/// The entity one authorizing slot of a command's authorization area speaks for, as the shared session ladder
/// needs it (TPM 2.0 Library Part 3, clause 5.6): its cpHash Name term, the Name the session's bind is tested
/// against, the authValue folded into the command and response HMACs, its dictionary-attack standing, and
/// whether the USER-role attribute gate (<c>userWithAuth</c>, Part 1, clause 16.6.17) applies to it.
/// </summary>
/// <remarks>
/// Every reference is a BORROW of a carrier the durable state owns — a loaded key's or an open sequence's —
/// valid for the whole of the command that resolved it; nothing here is disposed. A sequence object is the one
/// entity whose Name is the Empty Buffer (Part 1, clause 29.4.6; <see cref="TpmHandleName.EmptyBuffer"/>), whose
/// authValue is exempt from dictionary-attack protection ("A sequence is exempt from dictionary attack protection
/// and authorization failures will not cause the TPM to enter lockout"), and which carries no
/// <c>userWithAuth</c> attribute at all.
/// </remarks>
/// <param name="Name">The entity's cpHash Name term (Part 1, clause 15.7 equation 15).</param>
/// <param name="BindName">The Name a session's bound entity is compared against for equation 22's bind omission (Part 1, clause 16.6.10) — the same octets as <paramref name="Name"/> for an object; the Empty Buffer for a sequence, to which no session's bound-entity value can resolve, so the omission never applies and the sequence's authValue is always folded.</param>
/// <param name="AuthValue">The entity's authorization value, folded into the HMAC key when the bind does not omit it (equation 17).</param>
/// <param name="IsDaProtected">Whether a mismatch against this entity charges <c>failedTries</c> (Part 3, clause 5.6; Part 1, clause 16.8.1) — always <see langword="false"/> for a sequence.</param>
/// <param name="IsUserWithAuthGated">Whether the entity carries the <c>userWithAuth</c> attribute at all — a loaded object does, a sequence does not.</param>
/// <param name="IsUserWithAuthSet">Whether that attribute is SET, so a password or HMAC session may authorize the USER role (Part 1, clause 16.6.17); meaningful only when <paramref name="IsUserWithAuthGated"/> is set.</param>
internal readonly record struct TpmAuthorizedEntity(
    TpmHandleName Name,
    Tpm2bName BindName,
    Tpm2bAuth AuthValue,
    bool IsDaProtected,
    bool IsUserWithAuthGated,
    bool IsUserWithAuthSet)
{
    /// <summary>
    /// Describes a loaded asymmetric key (<see cref="TransientKeyState"/>) as an authorized entity.
    /// </summary>
    /// <param name="key">The loaded key.</param>
    /// <returns>The entity description.</returns>
    public static TpmAuthorizedEntity ForTransientKey(TransientKeyState key) =>
        new(TpmHandleName.FromName(key.Name), key.Name, key.AuthValue, key.IsDaProtected,
            IsUserWithAuthGated: true, IsUserWithAuthSet: (key.Attributes & TpmaObject.USER_WITH_AUTH) != 0);

    /// <summary>
    /// Describes a loaded KEYEDHASH object (<see cref="KeyedHashObjectState"/>) as an authorized entity.
    /// </summary>
    /// <param name="key">The loaded object.</param>
    /// <returns>The entity description.</returns>
    public static TpmAuthorizedEntity ForKeyedHashObject(KeyedHashObjectState key) =>
        new(TpmHandleName.FromName(key.Name), key.Name, key.UserAuth, key.IsDaProtected,
            IsUserWithAuthGated: true, IsUserWithAuthSet: key.UserWithAuth);

    /// <summary>
    /// Describes an open sequence context (<see cref="SequenceObjectState"/>) as an authorized entity: the
    /// Empty-Buffer Name (TPM 2.0 Library Part 1, clause 29.4.6; Part 3, clause 17.7.1), its own authValue,
    /// dictionary-attack exempt, and ungated by <c>userWithAuth</c>.
    /// </summary>
    /// <param name="sequence">The open sequence.</param>
    /// <returns>The entity description.</returns>
    public static TpmAuthorizedEntity ForSequence(SequenceObjectState sequence) =>
        new(TpmHandleName.EmptyBuffer, Tpm2bName.Empty, sequence.AuthValue, IsDaProtected: false,
            IsUserWithAuthGated: false, IsUserWithAuthSet: false);
}
