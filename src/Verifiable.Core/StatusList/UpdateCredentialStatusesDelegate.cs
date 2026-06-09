using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Core.StatusList;

/// <summary>
/// The outcome of applying a set of credential status changes.
/// </summary>
public enum CredentialStatusUpdateOutcome
{
    /// <summary>All changes were applied and the affected lists republished.</summary>
    Updated,

    /// <summary>One or more referenced entries did not match a known status list.</summary>
    NotFound,

    /// <summary>The change was not permitted by issuer policy.</summary>
    Rejected
}


/// <summary>
/// A single status change: the value to write at a <see cref="BitstringStatusListEntry"/>'s index.
/// </summary>
/// <param name="Entry">The status-list entry whose status changes.</param>
/// <param name="NewStatus">
/// The value to write at the entry's index: <c>0</c> for valid/unset, or a non-zero value (per the
/// entry's purpose and size) for revoked, suspended, or a message status.
/// </param>
public readonly record struct CredentialStatusChange(BitstringStatusListEntry Entry, byte NewStatus);


/// <summary>
/// Applies a set of status changes — revocations, suspensions, or message statuses — as one logical
/// operation. The seam is batch-shaped because a single verifiable credential may carry several
/// <see cref="BitstringStatusListEntry"/> references across one or more lists (W3C Bitstring Status
/// List §A.3, §A.4), so one issuer action commonly touches more than one bit.
/// </summary>
/// <remarks>
/// <para>
/// An application composes its own fan-out behind this seam: it groups the changes by status list,
/// flips each list's bits, re-encodes and re-signs each affected list <strong>exactly once</strong>,
/// republishes them (the pull channel), and optionally emits a CAEP <c>credential-change</c> event
/// per affected subject (the push channel). Grouping by list and re-encoding once per list avoids
/// publishing a half-applied intermediate a verifier could fetch mid-batch.
/// </para>
/// <para>
/// The library defines the contract only; it neither invokes the delegate nor performs any
/// transport, keeping the operation transport- and policy-agnostic. This is the credential-side
/// counterpart of the OAuth global token-revocation seam.
/// </para>
/// </remarks>
/// <param name="changes">The status changes to apply; a single revocation is a batch of one.</param>
/// <param name="cancellationToken">A cancellation token.</param>
/// <returns>The outcome of the update.</returns>
public delegate ValueTask<CredentialStatusUpdateOutcome> UpdateCredentialStatusesDelegate(
    IReadOnlyList<CredentialStatusChange> changes,
    CancellationToken cancellationToken);
