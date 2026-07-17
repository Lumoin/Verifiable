namespace Verifiable.Fido2.Ctap;

/// <summary>
/// The integer CBOR map keys of the <c>authenticatorLargeBlobs</c> request structure's top-level members.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorLargeBlobs">
/// CTAP 2.3, section 6.10.2: Reading and writing serialised data</see>, the input parameter table (lines
/// 7549-7583). A flat six-key envelope with NO <c>subCommand</c> — the first subcommand-less
/// parameterized CTAP command in this library. <strong>The pinUvAuth pair is REVERSED relative to
/// <see cref="WellKnownCtapAuthenticatorConfigRequestKeys"/>/<see cref="WellKnownCtapCredentialManagementRequestKeys"/>:</strong>
/// those two put <c>pinUvAuthProtocol</c> before <c>pinUvAuthParam</c> (<c>0x03</c>/<c>0x04</c>); here
/// <see cref="PinUvAuthParam"/> (<c>0x05</c>) precedes <see cref="PinUvAuthProtocol"/> (<c>0x06</c>) on
/// the wire — copy-renaming either sibling keys file silently swaps the two.
/// </remarks>
public static class WellKnownCtapLargeBlobsRequestKeys
{
    /// <summary>The <c>get</c> parameter (<c>0x01</c>, Unsigned integer, Optional): the number of bytes requested to read. MUST NOT be present if <c>set</c> is present.</summary>
    public const int Get = 0x01;

    /// <summary>The <c>set</c> parameter (<c>0x02</c>, Byte String, Optional): a fragment to write. MUST NOT be present if <c>get</c> is present.</summary>
    public const int Set = 0x02;

    /// <summary>The <c>offset</c> parameter (<c>0x03</c>, Unsigned integer, Required by spec): the byte offset at which to read/write.</summary>
    public const int Offset = 0x03;

    /// <summary>The <c>length</c> parameter (<c>0x04</c>, Unsigned integer, Optional): the total length of a write operation. Present if, and only if, <c>set</c> is present and <c>offset</c> is zero.</summary>
    public const int Length = 0x04;

    /// <summary>The <c>pinUvAuthParam</c> parameter (<c>0x05</c>, Byte String, Optional): the output of calling <c>authenticate</c> on the per-fragment verify message. Note the reversed wire order relative to <see cref="PinUvAuthProtocol"/>.</summary>
    public const int PinUvAuthParam = 0x05;

    /// <summary>The <c>pinUvAuthProtocol</c> parameter (<c>0x06</c>, Unsigned integer, Optional): the PIN/UV auth protocol version the platform selected.</summary>
    public const int PinUvAuthProtocol = 0x06;


    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="Get"/>.</summary>
    /// <param name="key">The request map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>get</c> key.</returns>
    public static bool IsGet(int key) => key == Get;

    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="Set"/>.</summary>
    /// <param name="key">The request map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>set</c> key.</returns>
    public static bool IsSet(int key) => key == Set;

    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="Offset"/>.</summary>
    /// <param name="key">The request map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>offset</c> key.</returns>
    public static bool IsOffset(int key) => key == Offset;

    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="Length"/>.</summary>
    /// <param name="key">The request map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>length</c> key.</returns>
    public static bool IsLength(int key) => key == Length;

    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="PinUvAuthParam"/>.</summary>
    /// <param name="key">The request map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>pinUvAuthParam</c> key.</returns>
    public static bool IsPinUvAuthParam(int key) => key == PinUvAuthParam;

    /// <summary>Gets a value indicating whether <paramref name="key"/> is <see cref="PinUvAuthProtocol"/>.</summary>
    /// <param name="key">The request map key to check.</param>
    /// <returns><see langword="true"/> if <paramref name="key"/> is the <c>pinUvAuthProtocol</c> key.</returns>
    public static bool IsPinUvAuthProtocol(int key) => key == PinUvAuthProtocol;
}
