using Verifiable.Cryptography;

namespace Verifiable.Apdu.SecureMessaging;

/// <summary>
/// The cipher-specific parameters of an ICAO Doc 9303 Secure Messaging session: which block cipher
/// and MAC it uses, the block size that drives padding and the send-sequence counter, and how the
/// per-message initialization vector is formed. One <see cref="SecureMessagingSession"/> engine
/// serves both the 3DES profile (BAC) and the AES profile (PACE) through this.
/// </summary>
/// <remarks>
/// <para>
/// The two profiles differ in exactly three ways (Doc 9303 §9.8): the 3DES profile uses an 8-byte
/// block, the ISO/IEC 9797-1 Retail MAC, and a zero IV for every operation; the AES profile uses a
/// 16-byte block, AES-CMAC, and a fresh IV computed as <c>E(KSenc, SSC)</c> before each cipher
/// operation. Everything else — the data-object framing, the method 2 padding, and the SSC-prefixed
/// MAC input — is identical.
/// </para>
/// </remarks>
public sealed class SecureMessagingProfile
{
    /// <summary>The cipher block size in bytes — the alignment unit for padding and the SSC width.</summary>
    public int BlockSize { get; }

    /// <summary>The MAC (DO'8E') length in bytes.</summary>
    public int MacLength { get; }

    /// <summary>The tag selecting the CBC cipher for the cryptogram and (in the AES profile) the IV.</summary>
    public Tag CipherTag { get; }

    /// <summary>The tag for the decrypted response content.</summary>
    public Tag DecryptedContentTag { get; }

    /// <summary>The tag selecting the block-cipher MAC.</summary>
    public Tag MacTag { get; }

    /// <summary>
    /// Whether the per-message IV is the send-sequence counter encrypted under KSenc (<see langword="true"/>,
    /// the AES profile) rather than a fixed zero IV (<see langword="false"/>, the 3DES profile).
    /// </summary>
    public bool EncryptsSequenceCounterForIv { get; }


    private SecureMessagingProfile(
        int blockSize, int macLength, Tag cipherTag, Tag decryptedContentTag, Tag macTag, bool encryptsSequenceCounterForIv)
    {
        BlockSize = blockSize;
        MacLength = macLength;
        CipherTag = cipherTag;
        DecryptedContentTag = decryptedContentTag;
        MacTag = macTag;
        EncryptsSequenceCounterForIv = encryptsSequenceCounterForIv;
    }


    /// <summary>
    /// The 3DES profile (BAC): two-key Triple-DES CBC with a zero IV and the ISO/IEC 9797-1 Retail MAC.
    /// </summary>
    public static SecureMessagingProfile TripleDes { get; } = new(
        blockSize: 8,
        macLength: 8,
        cipherTag: CryptoTags.TripleDesCbc,
        decryptedContentTag: CryptoTags.TripleDesCbcDecryptedContent,
        macTag: CryptoTags.RetailMac,
        encryptsSequenceCounterForIv: false);


    /// <summary>
    /// The AES-128 profile (PACE): AES-128 CBC with the IV computed as <c>E(KSenc, SSC)</c> and AES-CMAC.
    /// </summary>
    public static SecureMessagingProfile Aes128 { get; } = new(
        blockSize: 16,
        macLength: 8,
        cipherTag: CryptoTags.Aes128Cbc,
        decryptedContentTag: CryptoTags.Aes128CbcDecryptedContent,
        macTag: CryptoTags.Aes128Cmac,
        encryptsSequenceCounterForIv: true);
}
