using System.Collections.Generic;
using System.Diagnostics;
using Verifiable.Core;
using Verifiable.Core.Model.Common;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.Model.DataIntegrity;
using Verifiable.Core.StatusList;

namespace Verifiable.Vcalm;

/// <summary>
/// The VCALM 1.0 §C.1 status-list composition: it builds a NEW W3C Bitstring Status List verifiable
/// credential — a <c>BitstringStatusListCredential</c> whose <c>credentialSubject</c> is a
/// <c>BitstringStatusList</c> carrying the GZIP+base64url <c>encodedList</c> of an all-zero
/// <see cref="StatusList"/> — and secures it through the issuance seam
/// (<see cref="VcalmCredentialIssuanceService.IssueAsync"/>, composing the library's tested Data
/// Integrity signer). It does not re-roll cryptography or the bitstring codec.
/// </summary>
/// <remarks>
/// §C.1: "A status list is itself a verifiable credential that contains status information for
/// multiple credentials." §C.1 note: "the status list credential typically uses the same securing
/// mechanism … as the verifiable credentials it will be linked to." The bitstring core (create,
/// most-significant-first packing, GZIP+Multibase encode, the 131072-entry herd-privacy minimum) is
/// the existing <see cref="StatusList"/> / <see cref="BitstringStatusListCodec"/> surface.
/// </remarks>
[DebuggerDisplay("VcalmStatusListService")]
public static class VcalmStatusListService
{
    /// <summary>
    /// Composes and secures a new §C.1 status-list credential for the given purpose and id, with all
    /// entries initially unset (every referenced credential starts valid).
    /// </summary>
    /// <param name="statusListId">The status-list credential id (and its <c>credentialSubject.id</c> base).</param>
    /// <param name="statusPurpose">The §C.1 <c>statusPurpose</c> the list tracks (e.g. <c>revocation</c>).</param>
    /// <param name="entryCount">The number of entries the list holds (≥ the herd-privacy minimum).</param>
    /// <param name="issuance">The §C.1 signing configuration (reuse of the issuer's <see cref="VcalmCredentialIssuance"/>).</param>
    /// <param name="proofCreated">The timestamp written into the proof's <c>created</c> member.</param>
    /// <param name="context">The per-request context threaded to the canonicalizer.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The secured status-list credential.</returns>
    public static async ValueTask<DataIntegritySecuredCredential> CreateAsync(
        string statusListId,
        string statusPurpose,
        int entryCount,
        VcalmCredentialIssuance issuance,
        DateTime proofCreated,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(statusListId);
        ArgumentException.ThrowIfNullOrEmpty(statusPurpose);
        ArgumentNullException.ThrowIfNull(issuance);
        ArgumentNullException.ThrowIfNull(context);

        //The W3C Bitstring Status List bit core: an all-zero (every credential valid) list packed
        //most-significant-first, GZIP-compressed, and Multibase base64url-encoded into encodedList.
        string encodedList;
        using(StatusList list = StatusList.Create(
            entryCount, StatusListBitSize.OneBit, issuance.MemoryPool, BitOrder.MostSignificantFirst))
        {
            encodedList = BitstringStatusListCodec.EncodeList(list);
        }

        VerifiableCredential statusListCredential = BuildStatusListCredential(
            statusListId, statusPurpose, encodedList, issuance.ConfiguredIssuer);

        //§C.1: secure the list with the same issuance seam the credential issuer uses. A
        //status-list credential carries no caller proof, so the existing-proof case never applies.
        VcalmIssuanceResult result = await VcalmCredentialIssuanceService.IssueAsync(
            statusListCredential,
            hasExistingProof: false,
            issuance,
            proofCreated,
            context,
            cancellationToken).ConfigureAwait(false);

        //IssueAsync only fails on a rejected caller proof; a freshly built list has none, so this is
        //always a success. The non-null assertion documents that invariant.
        return result.SecuredCredential!;
    }


    /// <summary>
    /// Applies status changes to an existing §C.1 status list and re-secures it: sets the given
    /// entries to their new status values, re-encodes the bitstring, rebuilds the status-list
    /// credential, and signs it again with the issuer's configuration. This is the issuer's
    /// revoke / suspend / restore operation — a credential is revoked by setting its
    /// <see cref="BitstringStatusListEntry.StatusListIndex"/> to a non-zero status and re-publishing
    /// the returned credential.
    /// </summary>
    /// <param name="statusListId">The status-list credential id (unchanged across updates).</param>
    /// <param name="statusPurpose">The §C.1 <c>statusPurpose</c> the list tracks (unchanged across updates).</param>
    /// <param name="statusList">
    /// The current, decoded status list — typically obtained via
    /// <see cref="BitstringStatusListCodec.DecodeList"/> from the published credential's
    /// <c>encodedList</c>. It is mutated in place by the requested updates; the caller owns its pooled
    /// memory and disposes it after this call.
    /// </param>
    /// <param name="statusUpdates">
    /// The entries to change, keyed by <c>statusListIndex</c> with the new status value (for a one-bit
    /// list, <c>1</c> sets and <c>0</c> clears the status). An empty set re-secures the list unchanged.
    /// </param>
    /// <param name="issuance">The §C.1 signing configuration (the same as the list was created with).</param>
    /// <param name="proofCreated">The timestamp written into the new proof's <c>created</c> member.</param>
    /// <param name="context">The per-request context threaded to the canonicalizer.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The re-secured status-list credential carrying the updated bitstring.</returns>
    public static async ValueTask<DataIntegritySecuredCredential> UpdateAsync(
        string statusListId,
        string statusPurpose,
        StatusList statusList,
        IReadOnlyDictionary<int, byte> statusUpdates,
        VcalmCredentialIssuance issuance,
        DateTime proofCreated,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(statusListId);
        ArgumentException.ThrowIfNullOrEmpty(statusPurpose);
        ArgumentNullException.ThrowIfNull(statusList);
        ArgumentNullException.ThrowIfNull(statusUpdates);
        ArgumentNullException.ThrowIfNull(issuance);
        ArgumentNullException.ThrowIfNull(context);

        foreach(KeyValuePair<int, byte> update in statusUpdates)
        {
            statusList.Set(update.Key, update.Value);
        }

        string encodedList = BitstringStatusListCodec.EncodeList(statusList);

        VerifiableCredential statusListCredential = BuildStatusListCredential(
            statusListId, statusPurpose, encodedList, issuance.ConfiguredIssuer);

        //§C.1: re-secure with the same issuance seam create uses. A status-list credential carries no
        //caller proof, so the existing-proof case never applies.
        VcalmIssuanceResult result = await VcalmCredentialIssuanceService.IssueAsync(
            statusListCredential,
            hasExistingProof: false,
            issuance,
            proofCreated,
            context,
            cancellationToken).ConfigureAwait(false);

        return result.SecuredCredential!;
    }


    //Builds the unsecured BitstringStatusListCredential: a VC-DM 2.0 credential typed
    //BitstringStatusListCredential whose credentialSubject is a BitstringStatusList carrying the
    //statusPurpose and the encodedList (W3C Bitstring Status List §2.2).
    private static VerifiableCredential BuildStatusListCredential(
        string statusListId, string statusPurpose, string encodedList, string issuerId) =>
        new()
        {
            Context = new Context { Contexts = [Context.Credentials20] },
            Id = statusListId,
            Type = [CredentialConstants.VerifiableCredentialType, BitstringStatusListConstants.CredentialType],
            Issuer = new Issuer { Id = issuerId },
            CredentialSubject =
            [
                new CredentialSubject
                {
                    Id = $"{statusListId}#list",
                    AdditionalData = new Dictionary<string, object>(StringComparer.Ordinal)
                    {
                        [VcalmParameterNames.Type] = BitstringStatusListConstants.SubjectType,
                        [BitstringStatusListConstants.StatusPurposeProperty] = statusPurpose,
                        [BitstringStatusListConstants.EncodedListProperty] = encodedList
                    }
                }
            ]
        };
}
