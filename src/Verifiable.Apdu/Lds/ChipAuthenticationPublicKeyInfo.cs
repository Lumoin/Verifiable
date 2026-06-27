using System;
using Verifiable.Cryptography;

namespace Verifiable.Apdu.Lds;

/// <summary>
/// A parsed ChipAuthenticationPublicKeyInfo from EF.DG14 — the chip's static Chip Authentication
/// public key (BSI TR-03110 / ICAO Doc 9303 Part 11 §6.2) and the optional key identifier that pairs
/// it with a <see cref="ChipAuthenticationInfo"/>.
/// </summary>
/// <remarks>
/// <para>
/// The key is an elliptic-curve point (<c>id-PK-ECDH</c>) carried in a SubjectPublicKeyInfo whose
/// domain parameters identify the curve — most eMRTDs encode them explicitly rather than by named-curve
/// OID. The terminal agrees an ephemeral–static ECDH secret against this point during Chip
/// Authentication. Only ECDH keys are extracted; plain Diffie–Hellman keys (<c>id-PK-DH</c>) are not.
/// </para>
/// </remarks>
public sealed class ChipAuthenticationPublicKeyInfo: IDisposable
{
    private bool disposed;


    /// <summary>
    /// Initialises a new <see cref="ChipAuthenticationPublicKeyInfo"/>, taking ownership of the public-key carrier.
    /// </summary>
    /// <param name="publicKey">The chip's static Chip Authentication public key, tagged with its curve.</param>
    /// <param name="keyId">The key identifier, or <see langword="null"/> when the chip offers a single key.</param>
    internal ChipAuthenticationPublicKeyInfo(EncodedEcPoint publicKey, int? keyId)
    {
        PublicKey = publicKey;
        KeyId = keyId;
    }


    /// <summary>Gets the chip's static Chip Authentication public key (SEC1 uncompressed, tagged with its curve). Owned by this info.</summary>
    public EncodedEcPoint PublicKey { get; }

    /// <summary>Gets the key identifier pairing this key with its info, or <see langword="null"/> when the chip offers a single key.</summary>
    public int? KeyId { get; }


    /// <inheritdoc/>
    public void Dispose()
    {
        if(!disposed)
        {
            PublicKey.Dispose();
            disposed = true;
        }
    }
}
