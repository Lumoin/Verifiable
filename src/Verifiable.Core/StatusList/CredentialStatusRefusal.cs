using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.Text;

namespace Verifiable.Core.StatusList;

/// <summary>
/// A relying party's <see cref="CredentialStatusPolicy"/> refusal of a presentation on credential status: every
/// presented credential whose IETF Token Status List entry the policy read as not acceptable, and a composed,
/// human-readable reason.
/// </summary>
/// <remarks>
/// <see cref="Description"/> is log/state text — the query id, the raw status, and its disposition. It is never
/// the OID4VP wire <c>error_description</c>: <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-15.9">
/// OID4VP 1.0 §15.9</see> keeps the wire description generic, so this typed detail rides
/// <c>VerifierFlowFailedState.CredentialStatusRefusal</c> beside the log-only reason instead.
/// </remarks>
public sealed record CredentialStatusRefusal
{
    /// <summary>
    /// The machine-readable code that opens <see cref="Description"/>, so a reader of the failed flow state can
    /// tell a status-policy refusal from another refusal kind without parsing prose.
    /// </summary>
    public const string ReasonCode = "credential_status_not_valid";

    /// <summary>
    /// Backing store for <see cref="Credentials"/>, validated non-empty by its <c>init</c> accessor. A
    /// field because an <c>init</c> accessor may assign a sibling field of its own declaring type outside
    /// a constructor, but never a get-only auto-property's compiler-generated backing field, which only a
    /// constructor of the declaring type may assign.
    /// </summary>
    private readonly IReadOnlyList<RefusedCredentialStatus> credentials = [];

    /// <summary>
    /// The refused credentials, in the order their DCQL queries were verified. Never empty. A snapshot
    /// taken at construction — mutating a list the policy handed in afterward never changes this or
    /// <see cref="Description"/>.
    /// </summary>
    public required IReadOnlyList<RefusedCredentialStatus> Credentials
    {
        get => credentials;
        init
        {
            ArgumentNullException.ThrowIfNull(value);

            if(value.Count == 0)
            {
                throw new ArgumentException(
                    "A credential status refusal must name at least one refused credential.",
                    nameof(value));
            }

            //Freeze after validation: a policy that retains its own list (or array) must not be able to
            //mutate a refusal already riding a failed flow state out from under it.
            credentials = value is ReadOnlyCollection<RefusedCredentialStatus> frozen
                ? frozen
                : new ReadOnlyCollection<RefusedCredentialStatus>([.. value]);
        }
    }

    /// <summary>
    /// <see cref="ReasonCode"/>, then each refused credential's query identifier, raw status value and
    /// disposition — e.g. <c>"credential_status_not_valid: credential query 'pid' reads status 0x01 (revoked)"</c>.
    /// </summary>
    public string Description
    {
        get
        {
            StringBuilder description = new(ReasonCode);
            description.Append(':');

            for(int i = 0; i < Credentials.Count; i++)
            {
                RefusedCredentialStatus credential = Credentials[i];
                description.Append(i == 0 ? " " : "; ");
                description.Append("credential query '").Append(credential.CredentialQueryId.Value)
                    .Append("' reads status 0x").Append(credential.Outcome.Status.ToString("X2", CultureInfo.InvariantCulture))
                    .Append(" (").Append(credential.DispositionName).Append(')');
            }

            return description.ToString();
        }
    }
}
