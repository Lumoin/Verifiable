namespace Verifiable.Core.StatusList;

/// <summary>
/// The order in which status entries are packed within each byte of a status-list bitstring.
/// </summary>
/// <remarks>
/// <para>
/// The two status-list standards differ only here in the bit core: the IETF Token Status List
/// (<see href="https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/">draft-ietf-oauth-status-list</see>)
/// packs the first index at the least-significant bit, while the W3C Bitstring Status List
/// (<see href="https://www.w3.org/TR/vc-bitstring-status-list/">W3C VC Bitstring Status List</see>)
/// requires the first index at the left-most (most-significant) bit. Everything else about the
/// packed bitstring — capacity, get/set by index, pooled storage — is shared.
/// </para>
/// </remarks>
public enum BitOrder
{
    /// <summary>
    /// The first index occupies the least-significant bit of each byte (IETF Token Status List).
    /// </summary>
    LeastSignificantFirst,

    /// <summary>
    /// The first index occupies the most-significant, left-most bit of each byte
    /// (W3C Bitstring Status List).
    /// </summary>
    MostSignificantFirst
}
