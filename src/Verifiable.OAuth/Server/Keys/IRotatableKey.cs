namespace Verifiable.OAuth.Server.Keys;

/// <summary>
/// Minimal contract for key types stored in <see cref="KeySet{TKey}"/>.
/// Slot management needs to identify keys by kid for selection,
/// transitions, and publication.
/// </summary>
public interface IRotatableKey
{
    /// <summary>Stable kid identifying this key in the rotation set and on the wire.</summary>
    string Kid { get; }
}
