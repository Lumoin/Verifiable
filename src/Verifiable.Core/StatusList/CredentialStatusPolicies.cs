using System.Collections.Generic;
using Verifiable.Core.Dcql;

namespace Verifiable.Core.StatusList;

/// <summary>
/// The library's own <see cref="CredentialStatusPolicy"/> implementations.
/// </summary>
public static class CredentialStatusPolicies
{
    /// <summary>
    /// Never refuses. Every determinable status — valid, revoked, suspended, or application-specific — is
    /// merely surfaced on the verified state for the relying party to read; this is the shipped default per
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-18.html">SD-JWT VC -18</see>'s
    /// "Verifier policy decides whether to reject or accept."
    /// </summary>
    public static CredentialStatusPolicy Surface { get; } = static _ => null;

    /// <summary>
    /// Refuses every credential whose <see cref="CredentialStatusOutcome.IsValid"/> is <see langword="false"/>
    /// — revoked, suspended, or any application-specific non-zero status. Token Status List §8.3 step 7 checks
    /// the status value against §7, where <c>0x00</c> alone is "valid, correct or legal" — this policy treats
    /// every other value as a status it will not accept.
    /// </summary>
    public static CredentialStatusPolicy RefuseNotValid { get; } = static statuses =>
    {
        List<RefusedCredentialStatus>? refused = null;

        foreach(KeyValuePair<CredentialQueryId, CredentialStatusOutcome> status in statuses)
        {
            if(status.Value.IsValid)
            {
                continue;
            }

            refused ??= [];
            refused.Add(new RefusedCredentialStatus
            {
                CredentialQueryId = status.Key,
                Outcome = status.Value
            });
        }

        return refused is null ? null : new CredentialStatusRefusal { Credentials = refused };
    };
}
