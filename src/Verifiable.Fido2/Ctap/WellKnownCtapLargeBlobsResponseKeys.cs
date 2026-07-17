namespace Verifiable.Fido2.Ctap;

/// <summary>
/// The integer CBOR map keys of the <c>authenticatorLargeBlobs</c> response structure's top-level members.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorLargeBlobs">
/// CTAP 2.3, section 6.10.2: Reading and writing serialised data</see>, the response structure table
/// (lines 7688-7697). This response has exactly ONE member — the smallest response shape this library
/// models. A <c>set</c> outcome (continuation or commit) carries no response map at all (a bare
/// <c>CTAP2_OK</c>), so no key exists for it.
/// </remarks>
public static class WellKnownCtapLargeBlobsResponseKeys
{
    /// <summary>The <c>config</c> member (<c>0x01</c>, Byte String, Required): the requested substring of the stored serialized large-blob array.</summary>
    public const int Config = 0x01;


    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="Config"/>.</summary>
    /// <param name="key">The response map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>config</c> key.</returns>
    public static bool IsConfig(int key) => key == Config;
}
