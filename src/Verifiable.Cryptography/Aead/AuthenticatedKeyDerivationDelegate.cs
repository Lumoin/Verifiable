using System.Buffers;

namespace Verifiable.Cryptography.Aead;

/// <summary>
/// Delegate for key derivation from an ECDH-1PU shared secret, including the
/// authentication tag commitment required by
/// <see href="https://datatracker.ietf.org/doc/html/draft-madden-jose-ecdh-1pu-04#section-2.3">draft-madden-jose-ecdh-1pu-04 §2.3</see>
/// in Key Agreement with Key Wrapping mode.
/// </summary>
/// <remarks>
/// <para>
/// Identical to <see cref="KeyDerivationDelegate"/> except for the
/// <c>committedTag</c> input: in Key Agreement with Key Wrapping mode the JWE
/// Authentication Tag is appended to the KDF SuppPubInfo as a length-prefixed octet
/// string (cctag), binding the wrapped key to the already-encrypted content. This is
/// what prevents one recipient of a multi-recipient message from re-encrypting
/// altered content to another recipient. Pass an empty span for Direct Key Agreement
/// mode, where cctag is the empty octet string.
/// </para>
/// <para>
/// The tag commitment implies the encrypt-side order of operations: content is
/// encrypted first with a randomly generated content encryption key, and the
/// resulting tag then feeds this derivation before the content encryption key is
/// wrapped.
/// </para>
/// <para>
/// This delegate is synchronous because key derivation is pure deterministic
/// mathematics with no I/O and no hardware boundary.
/// </para>
/// </remarks>
/// <param name="sharedSecret">
/// The shared secret Z = Ze || Zs from ECDH-1PU key agreement. Not disposed by this
/// delegate — the caller retains ownership and must zero and dispose it after the call.
/// </param>
/// <param name="algorithmId">
/// The algorithm identifier string used as the AlgorithmID input to the KDF. In Key
/// Agreement with Key Wrapping mode this is the JWE <c>alg</c> value, e.g.
/// <c>ECDH-1PU+A256KW</c>; in Direct Key Agreement mode the JWE <c>enc</c> value.
/// </param>
/// <param name="partyUInfo">
/// Producer info bytes — the base64url-decoded JWE <c>apu</c> value, or empty when absent.
/// </param>
/// <param name="partyVInfo">
/// Recipient info bytes — the base64url-decoded JWE <c>apv</c> value, or empty when absent.
/// </param>
/// <param name="keydataLenBits">
/// The required output key length in bits — the key wrap algorithm key size in Key
/// Agreement with Key Wrapping mode (256 for <c>ECDH-1PU+A256KW</c>), the <c>enc</c>
/// key size in Direct Key Agreement mode.
/// </param>
/// <param name="committedTag">
/// The JWE Authentication Tag octets to commit into the derivation, or empty in
/// Direct Key Agreement mode.
/// </param>
/// <param name="pool">Memory pool for the output key allocation.</param>
/// <returns>
/// The derived key of exactly <paramref name="keydataLenBits"/> / 8 bytes — a key
/// encryption key in Key Agreement with Key Wrapping mode, a content encryption key
/// in Direct Key Agreement mode. The caller must dispose it immediately after use.
/// </returns>
public delegate ContentEncryptionKey AuthenticatedKeyDerivationDelegate(
    SharedSecret sharedSecret,
    string algorithmId,
    ReadOnlySpan<byte> partyUInfo,
    ReadOnlySpan<byte> partyVInfo,
    int keydataLenBits,
    ReadOnlySpan<byte> committedTag,
    MemoryPool<byte> pool);
