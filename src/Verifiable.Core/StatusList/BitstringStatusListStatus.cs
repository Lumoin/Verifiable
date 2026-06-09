namespace Verifiable.Core.StatusList;

/// <summary>
/// The result of reading a credential's status from a W3C Bitstring Status List, mirroring the
/// <c>result</c> map returned by the Validate Algorithm (§3.2).
/// </summary>
public sealed record BitstringStatusListStatus
{
    /// <summary>
    /// The raw status value read from the bitstring at the entry's index.
    /// </summary>
    public required byte Status { get; init; }

    /// <summary>
    /// Whether the status indicates a valid credential. Per §3.2 this is <see langword="true"/>
    /// when <see cref="Status"/> is <c>0</c> and <see langword="false"/> otherwise.
    /// </summary>
    public required bool IsValid { get; init; }

    /// <summary>
    /// The status purpose this result was evaluated against (e.g. <c>revocation</c>).
    /// </summary>
    public required string Purpose { get; init; }

    /// <summary>
    /// For a <c>message</c>-purpose entry, the message mapped to <see cref="Status"/> by the
    /// entry's <c>statusMessage</c> array; otherwise <see langword="null"/>.
    /// </summary>
    public string? Message { get; init; }
}
