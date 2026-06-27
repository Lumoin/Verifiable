using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Aead;

namespace Verifiable.Apdu.Pace;

/// <summary>
/// The cryptographic steps of ICAO Doc 9303 Part 11 PACE with Generic Mapping (ECDH): mapping the
/// nonce to an ephemeral group generator, agreeing the shared secret over that generator, and
/// computing the mutual-authentication tokens. These compose the EC point arithmetic seam, the PACE
/// key derivation, and AES-CMAC; the transport (MSE:Set AT, GENERAL AUTHENTICATE) drives them.
/// </summary>
/// <remarks>
/// <para>
/// Generic Mapping derives a fresh generator <c>Ĝ = s·G + H</c>, where <c>s</c> is the decrypted
/// nonce and <c>H</c> is an ECDH shared point from a first ephemeral exchange. Key agreement then
/// runs over <c>Ĝ</c>: each side's ephemeral public key is <c>SK·Ĝ</c>, and the shared secret is the
/// X-coordinate of <c>SK·PK</c>. The session keys come from the PACE KDF, and each authentication
/// token is an AES-CMAC over the BER-TLV encoding of the <em>other</em> party's ephemeral public key
/// together with the protocol OID.
/// </para>
/// </remarks>
public static class PaceGenericMapping
{
    /// <summary>BER-TLV context tag for an ephemeral public key inside the authentication-token input (DO'86').</summary>
    private const byte EphemeralPublicKeyTag = 0x86;

    /// <summary>BER-TLV universal tag for an OBJECT IDENTIFIER.</summary>
    private const byte ObjectIdentifierTag = 0x06;

    /// <summary>The length of the PACE authentication token in bytes (a truncated AES-CMAC).</summary>
    private const int TokenLength = 8;


    /// <summary>
    /// Maps the nonce to the ephemeral group generator: <c>Ĝ = s·G + (mappingPrivateKey · peerMappingPublicKey)</c>.
    /// </summary>
    /// <remarks>
    /// Direction-neutral: both the terminal and the chip compute the same Ĝ by passing their own mapping
    /// private key and the other party's mapping public key (the ECDH term <c>SK·PK</c> is symmetric).
    /// </remarks>
    /// <param name="nonce">The decrypted nonce s as unsigned big-endian bytes.</param>
    /// <param name="mappingPrivateKey">This party's mapping ephemeral private key.</param>
    /// <param name="peerMappingPublicKey">The other party's mapping ephemeral public key (SEC1 uncompressed).</param>
    /// <param name="curve">A tag carrying the curve <see cref="Verifiable.Cryptography.Context.CryptoAlgorithm"/>.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The mapped generator Ĝ as an <see cref="EncodedEcPoint"/>. The caller disposes it.</returns>
    public static async ValueTask<EncodedEcPoint> MapNonceAsync(
        ReadOnlyMemory<byte> nonce,
        ReadOnlyMemory<byte> mappingPrivateKey,
        ReadOnlyMemory<byte> peerMappingPublicKey,
        Tag curve,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        EcMultiplyGeneratorDelegate multiplyGenerator = Resolve<EcMultiplyGeneratorDelegate>();
        EcMultiplyPointDelegate multiplyPoint = Resolve<EcMultiplyPointDelegate>();
        EcAddPointsDelegate addPoints = Resolve<EcAddPointsDelegate>();

        using EncodedEcPoint nonceTimesGenerator = await multiplyGenerator(nonce, curve, pool, cancellationToken).ConfigureAwait(false);
        using EncodedEcPoint sharedPoint = await multiplyPoint(mappingPrivateKey, peerMappingPublicKey, curve, pool, cancellationToken).ConfigureAwait(false);

        return await addPoints(nonceTimesGenerator.AsReadOnlyMemory(), sharedPoint.AsReadOnlyMemory(), curve, pool, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Agrees the PACE shared secret: the X-coordinate of <c>privateKey · peerPublicKey</c>.
    /// </summary>
    /// <remarks>
    /// Direction-neutral: both the terminal and the chip agree the same secret by passing their own
    /// key-agreement private key and the other party's key-agreement public key.
    /// </remarks>
    /// <param name="privateKey">This party's key-agreement ephemeral private key.</param>
    /// <param name="peerPublicKey">The other party's key-agreement ephemeral public key (SEC1 uncompressed).</param>
    /// <param name="curve">A tag carrying the curve <see cref="Verifiable.Cryptography.Context.CryptoAlgorithm"/>.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The shared secret K (the X-coordinate) as a <see cref="SharedSecret"/>. The caller disposes it.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the rented buffer transfers to the returned SharedSecret, which the caller disposes.")]
    public static async ValueTask<SharedSecret> AgreeSharedSecretAsync(
        ReadOnlyMemory<byte> privateKey,
        ReadOnlyMemory<byte> peerPublicKey,
        Tag curve,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(pool);

        EcMultiplyPointDelegate multiplyPoint = Resolve<EcMultiplyPointDelegate>();
        using EncodedEcPoint agreed = await multiplyPoint(privateKey, peerPublicKey, curve, pool, cancellationToken).ConfigureAwait(false);

        //SEC1 uncompressed is 0x04 || X || Y; the shared secret is X — sensitive, held in pinned memory.
        ReadOnlySpan<byte> encoded = agreed.AsReadOnlySpan();
        int fieldSize = (encoded.Length - 1) / 2;
        IMemoryOwner<byte> owner = pool.Rent(fieldSize, AllocationKind.Pinned);
        encoded.Slice(1, fieldSize).CopyTo(owner.Memory.Span);

        return new SharedSecret(owner, curve);
    }


    /// <summary>
    /// Computes a PACE mutual-authentication token: AES-CMAC over the BER-TLV encoding of the peer's
    /// ephemeral public key and the protocol OID, truncated to 8 bytes.
    /// </summary>
    /// <param name="macKey">The session MAC key KSmac.</param>
    /// <param name="peerEphemeralPublicKey">The other party's ephemeral public key (SEC1 uncompressed).</param>
    /// <param name="objectIdentifier">The PACE protocol OID value bytes (without the outer 0x06 tag).</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The 8-byte authentication token as a <see cref="MacValue"/> (a truncated AES-CMAC). The caller disposes it.</returns>
    public static async ValueTask<MacValue> ComputeAuthenticationTokenAsync(
        SymmetricKeyMemory macKey,
        ReadOnlyMemory<byte> peerEphemeralPublicKey,
        ReadOnlyMemory<byte> objectIdentifier,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(macKey);
        ArgumentNullException.ThrowIfNull(pool);

        //The token input is public (the peer's ephemeral public key and the protocol OID).
        using IMemoryOwner<byte> input = pool.Rent(TokenInputLength(objectIdentifier.Length, peerEphemeralPublicKey.Length));
        WriteTokenInput(objectIdentifier.Span, peerEphemeralPublicKey.Span, input.Memory.Span);

        ComputeBlockCipherMacDelegate computeMac = Resolve<ComputeBlockCipherMacDelegate>();
        (MacValue token, _) = await computeMac(
            input.Memory, macKey.AsReadOnlyMemory(), TokenLength, CryptoTags.Aes128Cmac, pool, null, cancellationToken).ConfigureAwait(false);

        return token;
    }


    /// <summary>
    /// The encoded length of the token input <c>7F49 ‖ {06 ‖ OID} ‖ {86 ‖ ephemeral public key}</c>.
    /// </summary>
    private static int TokenInputLength(int objectIdentifierLength, int publicKeyLength)
    {
        int oidObjectLength = 1 + BerLengthSize(objectIdentifierLength) + objectIdentifierLength;
        int keyObjectLength = 1 + BerLengthSize(publicKeyLength) + publicKeyLength;
        int innerLength = oidObjectLength + keyObjectLength;

        return 2 + BerLengthSize(innerLength) + innerLength;
    }


    /// <summary>
    /// Writes the token input <c>7F49 ‖ {06 ‖ OID} ‖ {86 ‖ ephemeral public key}</c> into <paramref name="buffer"/>.
    /// </summary>
    private static void WriteTokenInput(ReadOnlySpan<byte> objectIdentifier, ReadOnlySpan<byte> publicKey, Span<byte> buffer)
    {
        int oidObjectLength = 1 + BerLengthSize(objectIdentifier.Length) + objectIdentifier.Length;
        int keyObjectLength = 1 + BerLengthSize(publicKey.Length) + publicKey.Length;
        int innerLength = oidObjectLength + keyObjectLength;
        int offset = 0;

        buffer[offset++] = 0x7F;
        buffer[offset++] = 0x49;
        offset += WriteBerLength(innerLength, buffer[offset..]);

        buffer[offset++] = ObjectIdentifierTag;
        offset += WriteBerLength(objectIdentifier.Length, buffer[offset..]);
        objectIdentifier.CopyTo(buffer[offset..]);
        offset += objectIdentifier.Length;

        buffer[offset++] = EphemeralPublicKeyTag;
        offset += WriteBerLength(publicKey.Length, buffer[offset..]);
        publicKey.CopyTo(buffer[offset..]);
    }


    /// <summary>
    /// The number of bytes a BER-TLV definite length field occupies for <paramref name="length"/>.
    /// </summary>
    private static int BerLengthSize(int length) =>
        length <= 0x7F ? 1 : length <= 0xFF ? 2 : 3;


    /// <summary>
    /// Writes a BER-TLV definite length field for <paramref name="length"/> into <paramref name="destination"/>.
    /// </summary>
    private static int WriteBerLength(int length, Span<byte> destination)
    {
        if(length <= 0x7F)
        {
            destination[0] = (byte)length;
            return 1;
        }

        if(length <= 0xFF)
        {
            destination[0] = 0x81;
            destination[1] = (byte)length;
            return 2;
        }

        destination[0] = 0x82;
        destination[1] = (byte)(length >> 8);
        destination[2] = (byte)length;
        return 3;
    }


    /// <summary>
    /// Resolves a registered delegate or throws.
    /// </summary>
    private static TDelegate Resolve<TDelegate>() where TDelegate: Delegate =>
        CryptographicKeyFactory.GetFunction<TDelegate>(typeof(TDelegate))
            ?? throw new InvalidOperationException($"No {typeof(TDelegate).Name} has been registered.");
}
