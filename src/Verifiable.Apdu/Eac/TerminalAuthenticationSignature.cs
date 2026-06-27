using System;
using System.Buffers;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Apdu.Lds;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;

namespace Verifiable.Apdu.Eac;

/// <summary>
/// The Terminal Authentication signature (ICAO Doc 9303 Part 11 §7.1.2): the terminal proves possession of
/// the private key matching the public key in the terminal (Inspection System) certificate it presented, by
/// signing the chip's challenge bound to the Secure Messaging key that the access protocol established.
/// </summary>
/// <remarks>
/// <para>
/// The signed message is <c>ID_IC ‖ r_IC ‖ Comp(PK_DH,IFD)</c> (§7.1.2):
/// </para>
/// <list type="bullet">
/// <item><description>
/// <c>ID_IC</c> is the chip identifier. After Basic Access Control it is the MRZ document number including
/// its check digit; after PACE it is <c>Comp()</c> of the chip's PACE ephemeral public key. It is derived by
/// the access protocol, so this primitive takes it as a ready value.
/// </description></item>
/// <item><description><c>r_IC</c> is the challenge the chip issued in the GET CHALLENGE step.</description></item>
/// <item><description>
/// <c>Comp(PK_DH,IFD)</c> binds the terminal's ephemeral public key from Chip Authentication (or PACE Chip
/// Authentication Mapping) — the key that established the current Secure Messaging session. <c>Comp()</c> of an
/// elliptic-curve point is its x-coordinate at field width (§7.1.4); for an uncompressed SEC1 point
/// <c>0x04 ‖ X ‖ Y</c> that is the <c>X</c> half, so no curve domain knowledge is needed to extract it.
/// </description></item>
/// </list>
/// <para>
/// An elliptic-curve terminal signs with the registered ECDSA signing function for its curve and the chip
/// verifies with the registered verification function for the same curve, both hashing the message internally
/// with the curve-appropriate hash (SHA-256 for P-256) and using the plain <c>r ‖ s</c> signature encoding
/// (TR-03111), the same convention the card-verifiable certificate chain uses. An RSA terminal signs with the
/// registered RSA signing function for the certificate's <c>id-TA-RSA-*</c> scheme (the padding and hash the
/// public-key object identifier fixes) and the chip verifies with the matching verification function; the
/// message construction is identical, so <see cref="SignWithRsaAsync"/> and <see cref="VerifyWithRsaAsync"/>
/// mirror the elliptic-curve methods. The SHA-1 RSA schemes are not served — TR-03110 marks them as not to be used.
/// </para>
/// </remarks>
public static class TerminalAuthenticationSignature
{
    /// <summary>
    /// Signs the Terminal Authentication message with the terminal's private key (the terminal side).
    /// </summary>
    /// <param name="terminalPrivateKey">The terminal's Terminal Authentication private key (unsigned big-endian scalar on <paramref name="curve"/>, matching the terminal certificate's public key). Borrowed.</param>
    /// <param name="curve">A tag carrying the curve <see cref="CryptoAlgorithm"/>, from the terminal certificate's public key.</param>
    /// <param name="chipIdentifier">The chip identifier <c>ID_IC</c> the access protocol produced.</param>
    /// <param name="chipChallenge">The chip's challenge <c>r_IC</c> from GET CHALLENGE.</param>
    /// <param name="terminalEphemeralPublicKey">The terminal's ephemeral public key <c>PK_DH,IFD</c> (uncompressed SEC1) from Chip Authentication or PACE Chip Authentication Mapping.</param>
    /// <param name="pool">The memory pool for the message and signature buffers.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The terminal's signature <c>s_IFD</c>. The caller owns and disposes it.</returns>
    /// <exception cref="InvalidOperationException">Thrown when the curve tag carries no algorithm, or no signing function is registered for it.</exception>
    public static async ValueTask<Signature> SignAsync(
        ReadOnlyMemory<byte> terminalPrivateKey,
        Tag curve,
        ReadOnlyMemory<byte> chipIdentifier,
        ReadOnlyMemory<byte> chipChallenge,
        ReadOnlyMemory<byte> terminalEphemeralPublicKey,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(curve);
        ArgumentNullException.ThrowIfNull(pool);

        if(!curve.TryGet(out CryptoAlgorithm algorithm))
        {
            throw new InvalidOperationException("The Terminal Authentication key tag must carry a curve algorithm.");
        }

        SigningDelegate sign = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveSigning(algorithm, Purpose.Signing);

        using IMemoryOwner<byte> message = BuildSignedMessage(chipIdentifier.Span, chipChallenge.Span, terminalEphemeralPublicKey.Span, pool, out int messageLength);

        return await sign(terminalPrivateKey, message.Memory[..messageLength], pool, null, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Verifies the terminal's Terminal Authentication signature against the terminal certificate's public key
    /// (the chip side).
    /// </summary>
    /// <param name="terminalPublicKey">The terminal's public key from the verified terminal certificate (uncompressed SEC1, tagged with its curve). Borrowed.</param>
    /// <param name="signature">The terminal's signature <c>s_IFD</c> from EXTERNAL AUTHENTICATE.</param>
    /// <param name="chipIdentifier">The chip identifier <c>ID_IC</c> the chip derives from the access protocol.</param>
    /// <param name="chipChallenge">The challenge <c>r_IC</c> the chip issued in GET CHALLENGE.</param>
    /// <param name="terminalEphemeralPublicKey">The terminal's ephemeral public key <c>PK_DH,IFD</c> (uncompressed SEC1) the chip retained from Chip Authentication or PACE Chip Authentication Mapping.</param>
    /// <param name="pool">The memory pool for the message buffer.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns><see langword="true"/> when the signature verifies; otherwise <see langword="false"/> (including a public key whose tag carries no algorithm).</returns>
    public static async ValueTask<bool> VerifyAsync(
        EncodedEcPoint terminalPublicKey,
        ReadOnlyMemory<byte> signature,
        ReadOnlyMemory<byte> chipIdentifier,
        ReadOnlyMemory<byte> chipChallenge,
        ReadOnlyMemory<byte> terminalEphemeralPublicKey,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(terminalPublicKey);
        ArgumentNullException.ThrowIfNull(pool);

        if(!terminalPublicKey.Tag.TryGet(out CryptoAlgorithm algorithm))
        {
            return false;
        }

        VerificationDelegate verify = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveVerification(algorithm, Purpose.Verification);

        using IMemoryOwner<byte> message = BuildSignedMessage(chipIdentifier.Span, chipChallenge.Span, terminalEphemeralPublicKey.Span, pool, out int messageLength);

        return await verify(message.Memory[..messageLength], signature, terminalPublicKey.AsReadOnlyMemory(), null, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Signs the Terminal Authentication message with the terminal's RSA private key (the terminal side), for a
    /// terminal certificate whose public key is an <c>id-TA-RSA-*</c> key.
    /// </summary>
    /// <param name="terminalPrivateKey">The terminal's RSA Terminal Authentication private key (a PKCS#1 DER <c>RSAPrivateKey</c> matching the terminal certificate's public key). Borrowed.</param>
    /// <param name="scheme">The RSA signature scheme (padding and hash) from the terminal certificate's public-key object identifier.</param>
    /// <param name="chipIdentifier">The chip identifier <c>ID_IC</c> the access protocol produced.</param>
    /// <param name="chipChallenge">The chip's challenge <c>r_IC</c> from GET CHALLENGE.</param>
    /// <param name="terminalEphemeralPublicKey">The terminal's ephemeral public key <c>PK_DH,IFD</c> (uncompressed SEC1) from Chip Authentication or PACE Chip Authentication Mapping.</param>
    /// <param name="pool">The memory pool for the message and signature buffers.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The terminal's signature <c>s_IFD</c>. The caller owns and disposes it.</returns>
    /// <exception cref="InvalidOperationException">Thrown when the scheme is not a supported RSA signing scheme, or no signing function is registered for it.</exception>
    public static async ValueTask<Signature> SignWithRsaAsync(
        ReadOnlyMemory<byte> terminalPrivateKey,
        CvcSignatureScheme scheme,
        ReadOnlyMemory<byte> chipIdentifier,
        ReadOnlyMemory<byte> chipChallenge,
        ReadOnlyMemory<byte> terminalEphemeralPublicKey,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(pool);

        CryptoAlgorithm algorithm = CardVerifiableCertificatePublicKey.ResolveRsaAlgorithm(scheme)
            ?? throw new InvalidOperationException($"The Terminal Authentication scheme '{scheme}' is not a supported RSA signing scheme.");

        SigningDelegate sign = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveSigning(algorithm, Purpose.Signing);

        using IMemoryOwner<byte> message = BuildSignedMessage(chipIdentifier.Span, chipChallenge.Span, terminalEphemeralPublicKey.Span, pool, out int messageLength);

        return await sign(terminalPrivateKey, message.Memory[..messageLength], pool, null, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Verifies the terminal's RSA Terminal Authentication signature against the terminal certificate's RSA
    /// public key (the chip side), for a terminal certificate whose public key is an <c>id-TA-RSA-*</c> key.
    /// </summary>
    /// <param name="terminalPublicKey">The terminal's RSA public key from the verified terminal certificate (a DER <c>RSAPublicKey</c>). Borrowed.</param>
    /// <param name="scheme">The RSA signature scheme (padding and hash) from the terminal certificate's public-key object identifier.</param>
    /// <param name="signature">The terminal's signature <c>s_IFD</c> from EXTERNAL AUTHENTICATE.</param>
    /// <param name="chipIdentifier">The chip identifier <c>ID_IC</c> the chip derives from the access protocol.</param>
    /// <param name="chipChallenge">The challenge <c>r_IC</c> the chip issued in GET CHALLENGE.</param>
    /// <param name="terminalEphemeralPublicKey">The terminal's ephemeral public key <c>PK_DH,IFD</c> (uncompressed SEC1) the chip retained from Chip Authentication or PACE Chip Authentication Mapping.</param>
    /// <param name="pool">The memory pool for the message buffer.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns><see langword="true"/> when the signature verifies; otherwise <see langword="false"/> (including a scheme that is not a supported RSA scheme).</returns>
    public static async ValueTask<bool> VerifyWithRsaAsync(
        RsaPublicKey terminalPublicKey,
        CvcSignatureScheme scheme,
        ReadOnlyMemory<byte> signature,
        ReadOnlyMemory<byte> chipIdentifier,
        ReadOnlyMemory<byte> chipChallenge,
        ReadOnlyMemory<byte> terminalEphemeralPublicKey,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(terminalPublicKey);
        ArgumentNullException.ThrowIfNull(pool);

        if(CardVerifiableCertificatePublicKey.ResolveRsaAlgorithm(scheme) is not CryptoAlgorithm algorithm)
        {
            return false;
        }

        VerificationDelegate verify = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveVerification(algorithm, Purpose.Verification);

        using IMemoryOwner<byte> message = BuildSignedMessage(chipIdentifier.Span, chipChallenge.Span, terminalEphemeralPublicKey.Span, pool, out int messageLength);

        return await verify(message.Memory[..messageLength], signature, terminalPublicKey.AsReadOnlyMemory(), null, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// <c>Comp()</c> of an elliptic-curve public key (Doc 9303 Part 11 §7.1.4, BSI TR-03110-3 §A.2.2.3): its
    /// x-coordinate at field width. After PACE the chip identifier <c>ID_IC</c> is <c>Comp()</c> of the chip's
    /// PACE ephemeral public key, which both the chip and the terminal feed to the Terminal Authentication
    /// signature; this exposes that compression for the access protocol to derive the identifier.
    /// </summary>
    /// <param name="point">An uncompressed SEC1 elliptic-curve point <c>0x04 ‖ X ‖ Y</c>.</param>
    /// <returns>The x-coordinate of the point — a view into <paramref name="point"/>'s own memory, not a copy.</returns>
    /// <exception cref="InvalidOperationException">Thrown when <paramref name="point"/> is not an uncompressed SEC1 point.</exception>
    public static ReadOnlyMemory<byte> Compress(EncodedEcPoint point)
    {
        ArgumentNullException.ThrowIfNull(point);

        ReadOnlyMemory<byte> memory = point.AsReadOnlyMemory();
        ReadOnlySpan<byte> span = memory.Span;
        if(span.Length < 3 || span[0] != 0x04 || (span.Length - 1) % 2 != 0)
        {
            throw new InvalidOperationException("Comp() requires an uncompressed SEC1 elliptic-curve point (0x04 || X || Y).");
        }

        int fieldWidth = (span.Length - 1) / 2;

        return memory.Slice(1, fieldWidth);
    }


    /// <summary>
    /// Builds the signed message <c>ID_IC ‖ r_IC ‖ Comp(PK_DH,IFD)</c> into a pooled buffer, taking
    /// <c>Comp()</c> of the terminal's ephemeral public key as its x-coordinate (the field-width first half of
    /// the uncompressed SEC1 point). The message is public material, so a managed buffer suffices.
    /// </summary>
    private static IMemoryOwner<byte> BuildSignedMessage(
        ReadOnlySpan<byte> chipIdentifier, ReadOnlySpan<byte> chipChallenge, ReadOnlySpan<byte> terminalEphemeralPublicKey, MemoryPool<byte> pool, out int length)
    {
        ReadOnlySpan<byte> compressedEphemeralKey = CompressPoint(terminalEphemeralPublicKey);
        length = chipIdentifier.Length + chipChallenge.Length + compressedEphemeralKey.Length;

        IMemoryOwner<byte> owner = pool.Rent(length);
        try
        {
            Span<byte> span = owner.Memory.Span;
            chipIdentifier.CopyTo(span);
            chipChallenge.CopyTo(span[chipIdentifier.Length..]);
            compressedEphemeralKey.CopyTo(span[(chipIdentifier.Length + chipChallenge.Length)..]);

            return owner;
        }
        catch
        {
            owner.Dispose();

            throw;
        }
    }


    /// <summary>
    /// <c>Comp()</c> of an elliptic-curve point (Doc 9303 Part 11 §7.1.4): its x-coordinate. For an
    /// uncompressed SEC1 point <c>0x04 ‖ X ‖ Y</c>, where <c>X</c> and <c>Y</c> are each the field width, that
    /// is the <c>X</c> half.
    /// </summary>
    private static ReadOnlySpan<byte> CompressPoint(ReadOnlySpan<byte> point)
    {
        if(point.Length < 3 || point[0] != 0x04 || (point.Length - 1) % 2 != 0)
        {
            throw new InvalidOperationException("Comp() requires an uncompressed SEC1 elliptic-curve point (0x04 || X || Y).");
        }

        int fieldWidth = (point.Length - 1) / 2;

        return point.Slice(1, fieldWidth);
    }
}
