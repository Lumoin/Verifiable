using System.Diagnostics;
using Verifiable.Cryptography;

namespace Verifiable.OAuth.Server;

/// <summary>
/// The result returned by <see cref="ResolveServerHmacKeyDelegate"/>: an
/// HMAC key and the kid that identifies it. The kid is always set even
/// when the resolver was called with a null kid (meaning "give me the
/// current key for new issuance") — the resolver tells the caller which
/// kid it chose so the caller can embed it in the produced artefact.
/// </summary>
/// <remarks>
/// Key rotation patterns rely on the kid being part of the returned
/// resolution: producers embed it into the wire artefact, consumers
/// extract it from the artefact and pass it back into the resolver to
/// look up the same key. The resolver holds the rotation policy; the
/// library's wire-format code stays rotation-agnostic.
/// </remarks>
[DebuggerDisplay("HmacKeyResolution Kid={Kid,nq}")]
public sealed record HmacKeyResolution
{
    /// <summary>The HMAC key material. Carries its own Tag describing the algorithm.</summary>
    public required SymmetricKey Key { get; init; }

    /// <summary>The kid identifying this key in the application's rotation set.</summary>
    public required string Kid { get; init; }
}
