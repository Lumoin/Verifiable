using Verifiable.Core.Dcql;

namespace Verifiable.Core.StatusList;

/// <summary>
/// One presented credential a <see cref="CredentialStatusPolicy"/> refuses on its Token Status List status:
/// which DCQL credential query it answered, and the outcome the gate read for it.
/// </summary>
public sealed record RefusedCredentialStatus
{
    /// <summary>The DCQL credential query identifier the refused credential was presented under.</summary>
    public required CredentialQueryId CredentialQueryId { get; init; }

    /// <summary>The outcome the gate read for this credential (never <see cref="CredentialStatusOutcome.IsValid"/>).</summary>
    public required CredentialStatusOutcome Outcome { get; init; }

    /// <summary>The relying party's reading of <see cref="Outcome"/>'s <see cref="CredentialStatusOutcome.Status"/>.</summary>
    public CredentialStatusDisposition Disposition => Outcome.Status switch
    {
        StatusTypes.Invalid => CredentialStatusDisposition.Revoked,
        StatusTypes.Suspended => CredentialStatusDisposition.Suspended,
        _ => CredentialStatusDisposition.ApplicationSpecific
    };

    /// <summary>The word <see cref="Disposition"/> reads as inside <see cref="CredentialStatusRefusal.Description"/>.</summary>
    public string DispositionName => Disposition switch
    {
        CredentialStatusDisposition.Revoked => "revoked",
        CredentialStatusDisposition.Suspended => "suspended",
        _ => "application-specific"
    };
}
