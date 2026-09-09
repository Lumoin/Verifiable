using Verifiable.Core.StatusList;
using Verifiable.OAuth.Server;

namespace Verifiable.OAuth.Oid4Vp.Server;

/// <summary>
/// The three outcomes of <see cref="VpTokenCredentialStatus.CheckAsync"/>: nothing to check, a determinable
/// status to record, or an undeterminable status that fails the presentation closed.
/// </summary>
internal enum CredentialStatusCheckKind
{
    /// <summary>
    /// There is no status for this verifier to check: the credential carried no status claim, or it carried
    /// one naming only mechanisms this verifier does not evaluate and the caller chose
    /// <see cref="Verifiable.Core.StatusList.UnsupportedStatusMechanismDisposition.Surface"/> for that case,
    /// leaving the mechanism names on the verified credential instead.
    /// </summary>
    NotReferenced,

    /// <summary>The credential's status was read successfully and should be recorded, not refused here.</summary>
    Determined,

    /// <summary>
    /// The credential's status could not be determined (subject mismatch, expired list, out-of-range index, or
    /// a status claim naming only mechanisms this verifier does not evaluate under
    /// <see cref="Verifiable.Core.StatusList.UnsupportedStatusMechanismDisposition.Refuse"/>); the presentation
    /// fails closed with the carried refusal.
    /// </summary>
    Undeterminable
}


/// <summary>
/// The result of checking one presented credential's IETF Token Status List entry through
/// <see cref="VpTokenCredentialStatus.CheckAsync"/>: a discriminated union over
/// <see cref="CredentialStatusCheckKind"/>, constructed only through its factories so exactly one payload is
/// ever populated for a given <see cref="Kind"/>.
/// </summary>
internal readonly record struct CredentialStatusCheck
{
    /// <summary>Which of the three outcomes this instance carries.</summary>
    public CredentialStatusCheckKind Kind { get; }

    /// <summary>The outcome to record. Populated only when <see cref="Kind"/> is <see cref="CredentialStatusCheckKind.Determined"/>.</summary>
    public CredentialStatusOutcome? Outcome { get; }

    /// <summary>
    /// The fail-closed refusal. Populated only when <see cref="Kind"/> is
    /// <see cref="CredentialStatusCheckKind.Undeterminable"/>.
    /// </summary>
    public VerifierFlowRefusal? Refusal { get; }

    /// <summary>
    /// The server-side log reason for the undeterminable status, naming the credential query and either the
    /// underlying exception message or the mechanisms that could not be evaluated. Populated only when
    /// <see cref="Kind"/> is
    /// <see cref="CredentialStatusCheckKind.Undeterminable"/>.
    /// </summary>
    public string? LogReason { get; }

    /// <summary>Populates every field; called only by the factories below.</summary>
    private CredentialStatusCheck(
        CredentialStatusCheckKind kind,
        CredentialStatusOutcome? outcome,
        VerifierFlowRefusal? refusal,
        string? logReason)
    {
        Kind = kind;
        Outcome = outcome;
        Refusal = refusal;
        LogReason = logReason;
    }

    /// <summary>There is no status for this verifier to check — with or without a resolver wired.</summary>
    public static CredentialStatusCheck NotReferenced() =>
        new(CredentialStatusCheckKind.NotReferenced, outcome: null, refusal: null, logReason: null);

    /// <summary>The credential's status was read successfully; the caller records <paramref name="outcome"/>.</summary>
    public static CredentialStatusCheck Determined(CredentialStatusOutcome outcome) =>
        new(CredentialStatusCheckKind.Determined, outcome, refusal: null, logReason: null);

    /// <summary>
    /// The credential's status could not be determined; the caller fails the presentation closed with
    /// <paramref name="refusal"/> and logs <paramref name="logReason"/> server-side.
    /// </summary>
    public static CredentialStatusCheck Undeterminable(
        VerifierFlowRefusal refusal, string logReason) =>
        new(CredentialStatusCheckKind.Undeterminable, outcome: null, refusal, logReason);
}
