using System;
using System.Collections.Generic;

namespace Verifiable.Core.StatusList;

/// <summary>
/// Verifier-side validation for the W3C Bitstring Status List, implementing the status-reading
/// portion of the Validate Algorithm (§3.2). This is the W3C analog of
/// <see cref="StatusListValidation"/>.
/// </summary>
/// <remarks>
/// <para>
/// Retrieval of the status list credential and verification of its proof(s) happen upstream — the
/// library is transport- and proof-agnostic, so the caller dereferences the
/// <c>statusListCredential</c> URL, verifies it via the existing credential surface, and decodes
/// its <c>encodedList</c> with <see cref="BitstringStatusListCodec.DecodeList"/> before calling
/// <see cref="GetStatus"/>. This mirrors how the IETF
/// <see cref="StatusListValidation.GetStatus(StatusListToken, StatusListReference, DateTimeOffset)"/>
/// operates on an already-parsed token.
/// </para>
/// </remarks>
public static class BitstringStatusListValidation
{
    /// <summary>
    /// Reads the status of a credential from a resolved, proof-verified, and decoded status list,
    /// performing the purpose, validity-period, length, and range checks of §3.2.
    /// </summary>
    /// <param name="entry">The credential's <c>BitstringStatusListEntry</c>.</param>
    /// <param name="statusList">
    /// The decoded status list (most-significant-first), obtained from the status list credential's
    /// <c>encodedList</c> via <see cref="BitstringStatusListCodec.DecodeList"/>.
    /// </param>
    /// <param name="listPurposes">
    /// The <c>statusPurpose</c> value(s) declared by the status list credential. A single list MAY
    /// carry multiple purposes.
    /// </param>
    /// <param name="currentTime">The current time for the validity-period check.</param>
    /// <param name="validFrom">The status list credential's <c>validFrom</c>, when present.</param>
    /// <param name="validUntil">The status list credential's <c>validUntil</c>, when present.</param>
    /// <returns>The status, validity, purpose, and (for <c>message</c> purpose) the mapped message.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="entry"/>, <paramref name="statusList"/>, or
    /// <paramref name="listPurposes"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="BitstringStatusListException">
    /// Thrown when the validity period, purpose, length, or range checks fail.
    /// </exception>
    public static BitstringStatusListStatus GetStatus(
        BitstringStatusListEntry entry,
        StatusList statusList,
        IReadOnlyCollection<string> listPurposes,
        DateTimeOffset currentTime,
        DateTimeOffset? validFrom = null,
        DateTimeOffset? validUntil = null)
    {
        ArgumentNullException.ThrowIfNull(entry);
        ArgumentNullException.ThrowIfNull(statusList);
        ArgumentNullException.ThrowIfNull(listPurposes);

        //Validity period of the status list credential (§7.2): a list outside its window is not trusted.
        if(validFrom.HasValue && currentTime < validFrom.Value)
        {
            throw new BitstringStatusListException(
                BitstringStatusListErrorType.StatusVerification,
                $"Status list credential is not yet valid; validFrom is {validFrom.Value:O}.");
        }

        if(validUntil.HasValue && currentTime > validUntil.Value)
        {
            throw new BitstringStatusListException(
                BitstringStatusListErrorType.StatusVerification,
                $"Status list credential has expired; validUntil was {validUntil.Value:O}.");
        }

        //§3.2: the entry purpose must match a purpose declared by the status list credential.
        if(!Contains(listPurposes, entry.StatusPurpose))
        {
            throw new BitstringStatusListException(
                BitstringStatusListErrorType.StatusVerification,
                $"Status purpose '{entry.StatusPurpose}' is not declared by the status list credential.");
        }

        //§3.2: length divided by statusSize (the entry count) must meet the herd-privacy minimum.
        if(statusList.Capacity < BitstringStatusListCodec.MinimumEntries)
        {
            throw new BitstringStatusListException(
                BitstringStatusListErrorType.StatusListLength,
                $"Status list holds {statusList.Capacity} entries; the minimum is {BitstringStatusListCodec.MinimumEntries}.");
        }

        //§3.2: index * size must fall within the bitstring.
        if(entry.StatusListIndex < 0 || entry.StatusListIndex >= statusList.Capacity)
        {
            throw new BitstringStatusListException(
                BitstringStatusListErrorType.Range,
                $"Status list index {entry.StatusListIndex} is out of range for a list of {statusList.Capacity} entries.");
        }

        byte status = statusList.Get(entry.StatusListIndex);
        bool isValid = status == 0;

        string? message = null;
        if(string.Equals(entry.StatusPurpose, BitstringStatusListConstants.MessagePurpose, StringComparison.Ordinal) && entry.StatusMessages is not null)
        {
            message = ResolveMessage(entry.StatusMessages, status);
        }

        return new BitstringStatusListStatus
        {
            Status = status,
            IsValid = isValid,
            Purpose = entry.StatusPurpose,
            Message = message
        };
    }


    private static bool Contains(IReadOnlyCollection<string> purposes, string purpose)
    {
        foreach(string candidate in purposes)
        {
            if(string.Equals(candidate, purpose, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }


    private static string? ResolveMessage(IReadOnlyList<BitstringStatusMessage> messages, byte status)
    {
        string hex = $"0x{status:x}";
        foreach(BitstringStatusMessage candidate in messages)
        {
            if(string.Equals(candidate.Status, hex, StringComparison.OrdinalIgnoreCase))
            {
                return candidate.Message;
            }
        }

        return null;
    }
}
