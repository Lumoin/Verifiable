using System;

namespace Verifiable.Apdu.Eac;

/// <summary>
/// The Terminal Authentication protocol object identifiers (BSI TR-03110-3 Tables 17 and 18): the
/// <c>id-TA-ECDSA-*</c> and <c>id-TA-RSA-*</c> identifiers that name the signature scheme and hash a terminal
/// uses for Terminal Authentication. The terminal sends the identifier of its scheme in the MSE:Set AT
/// cryptographic-mechanism reference (DO'80'), and the chip checks it matches the terminal certificate it
/// imported (ICAO Doc 9303 Part 11 §7.1.5).
/// </summary>
/// <remarks>
/// The value bytes are the encoded object identifier after the <c>0x06</c> tag and length, the form the
/// MSE:Set AT DO'80' carries and the CV-certificate public-key object identifier (<c>id-TA-*</c>) embeds.
/// </remarks>
public static class TerminalAuthenticationObjectIdentifier
{
    //id-TA-ECDSA = 0.4.0.127.0.7.2.2.2.2.{hash}, id-TA-RSA = 0.4.0.127.0.7.2.2.2.1.{scheme}.
    private static readonly byte[] EcdsaSha1 = [0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x02, 0x02, 0x01];
    private static readonly byte[] EcdsaSha224 = [0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x02, 0x02, 0x02];
    private static readonly byte[] EcdsaSha256 = [0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x02, 0x02, 0x03];
    private static readonly byte[] EcdsaSha384 = [0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x02, 0x02, 0x04];
    private static readonly byte[] EcdsaSha512 = [0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x02, 0x02, 0x05];
    private static readonly byte[] RsaPkcs1Sha1 = [0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x02, 0x01, 0x01];
    private static readonly byte[] RsaPkcs1Sha256 = [0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x02, 0x01, 0x02];
    private static readonly byte[] RsaPkcs1Sha512 = [0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x02, 0x01, 0x05];
    private static readonly byte[] RsaPssSha1 = [0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x02, 0x01, 0x03];
    private static readonly byte[] RsaPssSha256 = [0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x02, 0x01, 0x04];
    private static readonly byte[] RsaPssSha512 = [0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x02, 0x01, 0x06];


    /// <summary>
    /// The Terminal Authentication object identifier value bytes of a CV-certificate signature scheme.
    /// </summary>
    /// <param name="scheme">The signature scheme of the terminal certificate's public key.</param>
    /// <returns>The object identifier value bytes (after the <c>0x06</c> tag and length).</returns>
    public static ReadOnlySpan<byte> ValueBytes(CvcSignatureScheme scheme) => scheme switch
    {
        CvcSignatureScheme.EcdsaSha1 => EcdsaSha1,
        CvcSignatureScheme.EcdsaSha224 => EcdsaSha224,
        CvcSignatureScheme.EcdsaSha256 => EcdsaSha256,
        CvcSignatureScheme.EcdsaSha384 => EcdsaSha384,
        CvcSignatureScheme.EcdsaSha512 => EcdsaSha512,
        CvcSignatureScheme.RsaPkcs1Sha1 => RsaPkcs1Sha1,
        CvcSignatureScheme.RsaPkcs1Sha256 => RsaPkcs1Sha256,
        CvcSignatureScheme.RsaPkcs1Sha512 => RsaPkcs1Sha512,
        CvcSignatureScheme.RsaPssSha1 => RsaPssSha1,
        CvcSignatureScheme.RsaPssSha256 => RsaPssSha256,
        CvcSignatureScheme.RsaPssSha512 => RsaPssSha512,
        _ => throw new ArgumentOutOfRangeException(nameof(scheme), scheme, "Unknown CV-certificate signature scheme.")
    };
}
