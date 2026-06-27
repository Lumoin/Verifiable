namespace Verifiable.Apdu.Lds;

/// <summary>
/// The Secure Messaging cipher a Chip Authentication run establishes, decoded from the final arc of
/// the ChipAuthenticationInfo protocol object identifier (BSI TR-03110 §A.1.1.2 / ICAO Doc 9303
/// Part 11 §6.2).
/// </summary>
public enum ChipAuthenticationCipher
{
    /// <summary>Two-key Triple-DES in CBC mode (<c>id-CA-*-3DES-CBC-CBC</c>); keys derived with the SHA-1 KDF.</summary>
    TripleDes,

    /// <summary>AES-128 in CBC mode with AES-CMAC (<c>id-CA-*-AES-CBC-CMAC-128</c>); keys derived with the SHA-1 KDF.</summary>
    Aes128,

    /// <summary>AES-192 in CBC mode with AES-CMAC (<c>id-CA-*-AES-CBC-CMAC-192</c>); keys derived with the SHA-256 KDF.</summary>
    Aes192,

    /// <summary>AES-256 in CBC mode with AES-CMAC (<c>id-CA-*-AES-CBC-CMAC-256</c>); keys derived with the SHA-256 KDF.</summary>
    Aes256
}


/// <summary>
/// A parsed ChipAuthenticationInfo from EF.DG14 — one Chip Authentication protocol the chip offers:
/// its key-agreement family, the Secure Messaging cipher it establishes, the protocol version, and the
/// optional key identifier that pairs it with a <see cref="ChipAuthenticationPublicKeyInfo"/>.
/// </summary>
/// <remarks>
/// <para>
/// Chip Authentication (BSI TR-03110 / ICAO Doc 9303 Part 11 §6.2) is the anti-cloning step: the
/// terminal agrees an ephemeral–static (EC)DH secret with the chip's static key from DG14 and re-keys
/// Secure Messaging, proving the chip holds the matching private key. This object carries the protocol
/// parameters; <see cref="ChipAuthenticationPublicKeyInfo"/> carries the static public key.
/// </para>
/// </remarks>
public sealed class ChipAuthenticationInfo
{
    /// <summary>
    /// Initialises a new <see cref="ChipAuthenticationInfo"/>.
    /// </summary>
    /// <param name="isEllipticCurve">Whether the key agreement is ECDH (<see langword="false"/> for plain DH).</param>
    /// <param name="cipher">The Secure Messaging cipher the protocol establishes.</param>
    /// <param name="version">The Chip Authentication protocol version.</param>
    /// <param name="keyId">The key identifier, or <see langword="null"/> when the chip offers a single key.</param>
    internal ChipAuthenticationInfo(bool isEllipticCurve, ChipAuthenticationCipher cipher, int version, int? keyId)
    {
        IsEllipticCurve = isEllipticCurve;
        Cipher = cipher;
        Version = version;
        KeyId = keyId;
    }


    /// <summary>Gets whether the key agreement is elliptic-curve Diffie–Hellman (ECDH); <see langword="false"/> for plain DH.</summary>
    public bool IsEllipticCurve { get; }

    /// <summary>Gets the Secure Messaging cipher this protocol establishes.</summary>
    public ChipAuthenticationCipher Cipher { get; }

    /// <summary>Gets the Chip Authentication protocol version (1 for EACv1, 2 for EACv2).</summary>
    public int Version { get; }

    /// <summary>Gets the key identifier pairing this info with its public key, or <see langword="null"/> when the chip offers a single key.</summary>
    public int? KeyId { get; }
}
