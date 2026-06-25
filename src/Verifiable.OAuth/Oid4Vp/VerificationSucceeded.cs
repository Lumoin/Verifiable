using System;
using System.Collections.Generic;
using System.Diagnostics;
using Verifiable.Core.StatusList;
using Verifiable.OAuth;

namespace Verifiable.OAuth.Oid4Vp;

/// <summary>
/// Carries the verified claims extracted from the vp_token.
/// Transitions from <see cref="ResponseReceived"/> to <see cref="PresentationVerified"/>.
/// </summary>
/// <param name="Claims">
/// The verified and extracted claims, keyed by DCQL credential query identifier.
/// </param>
/// <param name="VerifiedAt">The UTC instant verification completed.</param>
/// <param name="RedirectUri">
/// The URI to include in the HTTP 200 response body so the Wallet can resume the
/// user's browser session. Required in the same-device flow per OID4VP 1.0 §8.2;
/// <see langword="null"/> in the cross-device flow.
/// </param>
[DebuggerDisplay("VerificationSucceeded VerifiedAt={VerifiedAt}")]
public sealed record VerificationSucceeded(
    IReadOnlyDictionary<string, IReadOnlyDictionary<string, string>> Claims,
    DateTimeOffset VerifiedAt,
    Uri? RedirectUri = null): FlowInput
{
    /// <summary>
    /// The IETF Token Status List outcomes for the presented credentials, keyed by DCQL credential
    /// query identifier, or <see langword="null"/> when none of the presented credentials carried a
    /// <c>status.status_list</c> reference (so there was nothing to check). A credential that
    /// <em>does</em> reference a status list is either checked — and recorded here — or, when the
    /// verifier executor was constructed without a <see cref="ResolveVerifiedStatusListTokenDelegate"/>,
    /// fails the presentation closed before this result is produced.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A valid issuer signature only proves a credential was genuinely issued; this carries the
    /// "is it still valid <em>now</em>?" answer the verifier-agnostic
    /// <see cref="CredentialStatusGate"/> read after signature and holder-binding verification, so a
    /// relying party can act on revocation/suspension without re-parsing the verified vp_token. An
    /// entry's <see cref="CredentialStatusOutcome.IsValid"/> is <see langword="false"/> for a revoked
    /// (<c>0x01</c>) or suspended (<c>0x02</c>) credential; the raw
    /// <see cref="CredentialStatusOutcome.Status"/> distinguishes those and application-specific values.
    /// </para>
    /// <para>
    /// An <em>undeterminable</em> status (a status list whose subject does not match the reference URI,
    /// an expired list, or an out-of-range index) fails the presentation closed at the executor — it
    /// never reaches this surface as a "valid" outcome.
    /// </para>
    /// </remarks>
    public IReadOnlyDictionary<string, CredentialStatusOutcome>? CredentialStatuses { get; init; }

    /// <inheritdoc/>
    public bool Equals(VerificationSucceeded? other)
    {
        if(other is null)
        {
            return false;
        }

        if(ReferenceEquals(this, other))
        {
            return true;
        }

        return VerifiedAt == other.VerifiedAt
            && ReferenceEquals(Claims, other.Claims)
            && ReferenceEquals(CredentialStatuses, other.CredentialStatuses)
            && RedirectUri == other.RedirectUri;
    }

    /// <inheritdoc/>
    public override int GetHashCode() => HashCode.Combine(Claims, VerifiedAt, RedirectUri, CredentialStatuses);
}
