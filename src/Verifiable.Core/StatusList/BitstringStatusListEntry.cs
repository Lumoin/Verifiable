using System.Collections.Generic;

namespace Verifiable.Core.StatusList;

/// <summary>
/// A single status message an issuer commits to for a <c>message</c>-purpose entry: a
/// hexadecimal status value and the developer-facing message it maps to (§2.1).
/// </summary>
/// <param name="Status">The hexadecimal status value, prefixed with <c>0x</c> (e.g. <c>0x1</c>).</param>
/// <param name="Message">
/// A developer-facing message used to assist debugging; per the specification it SHOULD NOT be
/// displayed to end users.
/// </param>
public sealed record BitstringStatusMessage(string Status, string Message);


/// <summary>
/// A typed view of a W3C <c>BitstringStatusListEntry</c> — the <c>credentialStatus</c> reference a
/// credential carries to point at its position in a status list (§2.1). This is the W3C analog of
/// the IETF <see cref="StatusListReference"/>.
/// </summary>
/// <remarks>
/// See <see href="https://www.w3.org/TR/vc-bitstring-status-list/#bitstringstatuslistentry">
/// W3C Bitstring Status List §2.1</see>.
/// </remarks>
public sealed record BitstringStatusListEntry
{
    /// <summary>
    /// An optional identifier for the status entry. It MUST NOT be the URL of the status list and
    /// is not used during verification (§2.1).
    /// </summary>
    public string? Id { get; init; }

    /// <summary>
    /// The purpose of the status entry, one of <see cref="BitstringStatusListConstants.RefreshPurpose"/>,
    /// <see cref="BitstringStatusListConstants.RevocationPurpose"/>,
    /// <see cref="BitstringStatusListConstants.SuspensionPurpose"/>, or
    /// <see cref="BitstringStatusListConstants.MessagePurpose"/>.
    /// </summary>
    public required string StatusPurpose { get; init; }

    /// <summary>
    /// The position of this credential's status within the bitstring, indexing entries of
    /// <see cref="StatusSize"/> bits each (§2.1).
    /// </summary>
    public required int StatusListIndex { get; init; }

    /// <summary>
    /// The URL of the verifiable credential that carries the status list (§2.1).
    /// </summary>
    public required string StatusListCredential { get; init; }

    /// <summary>
    /// The size of the status entry in bits. Absent <c>statusSize</c> is processed as <c>1</c>;
    /// when greater than <c>1</c>, <see cref="StatusMessages"/> MUST be present (§2.1).
    /// </summary>
    public int StatusSize { get; init; } = 1;

    /// <summary>
    /// The status messages the issuer commits to for a <c>message</c>-purpose entry, one per
    /// possible status value (§2.1).
    /// </summary>
    public IReadOnlyList<BitstringStatusMessage>? StatusMessages { get; init; }

    /// <summary>
    /// Optional URL(s) dereferencing to material related to the status (§2.1).
    /// </summary>
    public IReadOnlyList<string>? StatusReference { get; init; }
}
