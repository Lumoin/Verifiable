using System.Collections.Generic;
using Verifiable.Core.Dcql;

namespace Verifiable.Core.StatusList;

/// <summary>
/// A relying party's verdict over a verified presentation's surfaced Token Status List outcomes.
/// </summary>
/// <remarks>
/// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-18.html">SD-JWT VC -18</see>: "If
/// status is present in the verified payload of the SD-JWT, the status SHOULD be checked. Verifier policy
/// decides whether to reject or accept a presentation of a SD-JWT VC based on the status of the Verifiable
/// Digital Credential." This delegate is that policy seam. A verifier executor applies it once, over the
/// complete outcome map of a presentation, after every presented credential has already verified — a
/// determinable revoked or suspended status is recorded, not failed, until the policy runs.
/// </remarks>
/// <param name="statuses">
/// The per-credential outcomes the executor surfaced, keyed by DCQL credential query identifier. Never empty
/// when invoked — an executor calls the policy only when at least one presented credential carried a status.
/// </param>
/// <returns>
/// A <see cref="CredentialStatusRefusal"/> naming every credential the policy refuses, or
/// <see langword="null"/> to let the presentation stand.
/// </returns>
public delegate CredentialStatusRefusal? CredentialStatusPolicy(
    IReadOnlyDictionary<CredentialQueryId, CredentialStatusOutcome> statuses);
