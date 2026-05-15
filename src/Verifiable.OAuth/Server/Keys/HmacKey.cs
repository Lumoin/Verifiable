using System.Diagnostics;
using Verifiable.Cryptography;

namespace Verifiable.OAuth.Server.Keys;

/// <summary>
/// A symmetric HMAC key paired with its kid, suitable for storage in
/// <see cref="KeySet{TKey}"/>. Used for DPoP nonce HMACs, future HS256
/// access-token signing, COSE_Mac0 / SD-CWT-MAC, back-channel logout
/// tokens with symmetric secrets, and any other MAC-based primitive
/// the library composes.
/// </summary>
[DebuggerDisplay("HmacKey Kid={Kid,nq}")]
public sealed record HmacKey: IRotatableKey
{
    /// <summary>Stable kid identifying this key in the rotation set and on the wire.</summary>
    public required string Kid { get; init; }

    /// <summary>The HMAC key material. Carries its own <c>Tag</c> describing the algorithm.</summary>
    public required SymmetricKey Material { get; init; }
}
