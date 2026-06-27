using System;
using System.Buffers;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Apdu.SecureMessaging;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;

namespace Verifiable.Apdu.Lds;

/// <summary>
/// ICAO Doc 9303 Part 11 §6.1 Active Authentication: the anti-cloning step in which the terminal sends a
/// random challenge in an INTERNAL AUTHENTICATE command and verifies the chip's signature over it against
/// the public key from EF.DG15, proving the chip holds the matching private key.
/// </summary>
/// <remarks>
/// <para>
/// The terminal generates a challenge RND.IFD, sends it in INTERNAL AUTHENTICATE (INS <c>0x88</c>), and
/// verifies the returned signature against the DG15 public key. A clone that copied the DG15 file but could
/// not extract the private key signs with the wrong key and fails verification.
/// </para>
/// <para>
/// Active Authentication can run before any access protocol (in the clear) or, as it usually does in an
/// eMRTD inspection, over the Basic Access Control or PACE Secure Messaging session; each key type has a
/// plaintext and a Secure Messaging overload. EF.DG15 carries either an elliptic-curve (ECDSA) or an RSA
/// (ISO/IEC 9796-2) Active Authentication key, and both are handled — the elliptic-curve overloads take the
/// DG15 <see cref="EncodedEcPoint"/>, the RSA overloads take the DG15 <see cref="RsaPublicKey"/>.
/// </para>
/// <para>
/// <strong>Elliptic-curve keys.</strong> The challenge is sent in the clear and the chip's signing and the
/// terminal's verification hash it internally with the curve-appropriate hash. EF.DG15 stores the public key
/// as an uncompressed SEC1 point (<c>0x04 ‖ X ‖ Y</c>); the registered verification functions accept either
/// SEC1 encoding, so the terminal passes the DG15 point straight to verification with no re-encoding.
/// </para>
/// <para>
/// <strong>RSA keys.</strong> RSA Active Authentication uses ISO/IEC 9796-2 Digital Signature scheme 1 with
/// message recovery: the chip signs <c>M1 ‖ RND.IFD</c>, where <c>M1</c> is a random block it produces to
/// fill the key's recoverable capacity, and the terminal recovers <c>M1</c> and checks the embedded
/// <c>Hash(M1 ‖ RND.IFD)</c>. The hash is identified by the signature trailer, so the terminal need not be
/// told it in advance.
/// </para>
/// </remarks>
public static class ActiveAuthentication
{
    /// <summary>The class byte of the INTERNAL AUTHENTICATE command.</summary>
    private const byte ActiveAuthenticationClass = 0x00;

    /// <summary>The expected response length: a short Le of 256 (encoded <c>0x00</c>) accommodates any Active Authentication signature.</summary>
    private const int MaxResponseLength = 256;


    /// <summary>
    /// Runs elliptic-curve Active Authentication in the clear: sends the challenge in INTERNAL AUTHENTICATE
    /// and verifies the chip's signature against the EF.DG15 elliptic-curve public key.
    /// </summary>
    /// <param name="device">The card device. Borrowed, not disposed.</param>
    /// <param name="activeAuthenticationPublicKey">The chip's Active Authentication public key from EF.DG15 (SEC1 uncompressed, tagged with its curve). Borrowed.</param>
    /// <param name="challenge">The terminal's challenge RND.IFD (eMRTD uses 8 bytes).</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns><see langword="true"/> when the chip's signature verifies; otherwise <see langword="false"/> (including a card or transport error, or a chip refusal).</returns>
    public static async ValueTask<bool> AuthenticateAsync(
        ApduDevice device,
        EncodedEcPoint activeAuthenticationPublicKey,
        ReadOnlyMemory<byte> challenge,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(device);
        ArgumentNullException.ThrowIfNull(activeAuthenticationPublicKey);
        ArgumentNullException.ThrowIfNull(pool);

        using CommandApdu command = BuildInternalAuthenticate(challenge, pool);
        ApduResult<ApduResponse> result = await ApduExecutor.ExecuteAsync(
            device, command.AsReadOnlyMemory(), pool, cancellationToken).ConfigureAwait(false);
        if(result.IsTransportError)
        {
            return false;
        }

        using ApduResponse response = result.Value;
        if(!response.StatusWord.IsSuccess || response.DataLength == 0)
        {
            return false;
        }

        return await VerifyEllipticCurveAsync(
            activeAuthenticationPublicKey, challenge, response.AsReadOnlyMemory()[..response.DataLength], cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Runs elliptic-curve Active Authentication over an established Secure Messaging session.
    /// </summary>
    /// <param name="device">The card device. Borrowed, not disposed.</param>
    /// <param name="session">The Basic Access Control or PACE Secure Messaging session the command runs over. Borrowed, not disposed.</param>
    /// <param name="activeAuthenticationPublicKey">The chip's Active Authentication public key from EF.DG15 (SEC1 uncompressed, tagged with its curve). Borrowed.</param>
    /// <param name="challenge">The terminal's challenge RND.IFD (eMRTD uses 8 bytes).</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns><see langword="true"/> when the chip's signature verifies; otherwise <see langword="false"/> (including a card or transport error, or a chip refusal).</returns>
    public static async ValueTask<bool> AuthenticateAsync(
        ApduDevice device,
        SecureMessagingSession session,
        EncodedEcPoint activeAuthenticationPublicKey,
        ReadOnlyMemory<byte> challenge,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(device);
        ArgumentNullException.ThrowIfNull(session);
        ArgumentNullException.ThrowIfNull(activeAuthenticationPublicKey);
        ArgumentNullException.ThrowIfNull(pool);

        using SecureMessagingResponse? unprotected = await SendProtectedChallengeAsync(device, session, challenge, pool, cancellationToken).ConfigureAwait(false);
        if(unprotected is null || !unprotected.StatusWord.IsSuccess || unprotected.Length == 0)
        {
            return false;
        }

        //The decrypted signature is exposed only as a span; copy it into pooled memory to verify across the
        //(synchronous-completing) await. The signature is public material.
        using IMemoryOwner<byte> signature = pool.Rent(unprotected.Length);
        unprotected.Data.CopyTo(signature.Memory.Span);

        return await VerifyEllipticCurveAsync(
            activeAuthenticationPublicKey, challenge, signature.Memory[..unprotected.Length], cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Runs RSA (ISO/IEC 9796-2) Active Authentication in the clear: sends the challenge in INTERNAL
    /// AUTHENTICATE and verifies the chip's message-recovery signature against the EF.DG15 RSA public key.
    /// </summary>
    /// <param name="device">The card device. Borrowed, not disposed.</param>
    /// <param name="activeAuthenticationPublicKey">The chip's RSA Active Authentication public key from EF.DG15 (DER <c>RSAPublicKey</c>). Borrowed.</param>
    /// <param name="challenge">The terminal's challenge RND.IFD (eMRTD uses 8 bytes).</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns><see langword="true"/> when the chip's signature verifies; otherwise <see langword="false"/> (including a card or transport error, or a chip refusal).</returns>
    public static async ValueTask<bool> AuthenticateAsync(
        ApduDevice device,
        RsaPublicKey activeAuthenticationPublicKey,
        ReadOnlyMemory<byte> challenge,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(device);
        ArgumentNullException.ThrowIfNull(activeAuthenticationPublicKey);
        ArgumentNullException.ThrowIfNull(pool);

        using CommandApdu command = BuildInternalAuthenticate(challenge, pool);
        ApduResult<ApduResponse> result = await ApduExecutor.ExecuteAsync(
            device, command.AsReadOnlyMemory(), pool, cancellationToken).ConfigureAwait(false);
        if(result.IsTransportError)
        {
            return false;
        }

        using ApduResponse response = result.Value;
        if(!response.StatusWord.IsSuccess || response.DataLength == 0)
        {
            return false;
        }

        return await VerifyRsaAsync(
            activeAuthenticationPublicKey, challenge, response.AsReadOnlyMemory()[..response.DataLength], cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Runs RSA (ISO/IEC 9796-2) Active Authentication over an established Secure Messaging session.
    /// </summary>
    /// <param name="device">The card device. Borrowed, not disposed.</param>
    /// <param name="session">The Basic Access Control or PACE Secure Messaging session the command runs over. Borrowed, not disposed.</param>
    /// <param name="activeAuthenticationPublicKey">The chip's RSA Active Authentication public key from EF.DG15 (DER <c>RSAPublicKey</c>). Borrowed.</param>
    /// <param name="challenge">The terminal's challenge RND.IFD (eMRTD uses 8 bytes).</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns><see langword="true"/> when the chip's signature verifies; otherwise <see langword="false"/> (including a card or transport error, or a chip refusal).</returns>
    public static async ValueTask<bool> AuthenticateAsync(
        ApduDevice device,
        SecureMessagingSession session,
        RsaPublicKey activeAuthenticationPublicKey,
        ReadOnlyMemory<byte> challenge,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(device);
        ArgumentNullException.ThrowIfNull(session);
        ArgumentNullException.ThrowIfNull(activeAuthenticationPublicKey);
        ArgumentNullException.ThrowIfNull(pool);

        using SecureMessagingResponse? unprotected = await SendProtectedChallengeAsync(device, session, challenge, pool, cancellationToken).ConfigureAwait(false);
        if(unprotected is null || !unprotected.StatusWord.IsSuccess || unprotected.Length == 0)
        {
            return false;
        }

        //The decrypted signature is exposed only as a span; copy it into pooled memory to verify across the
        //(synchronous-completing) await. The signature is public material.
        using IMemoryOwner<byte> signature = pool.Rent(unprotected.Length);
        unprotected.Data.CopyTo(signature.Memory.Span);

        return await VerifyRsaAsync(
            activeAuthenticationPublicKey, challenge, signature.Memory[..unprotected.Length], cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Builds the plaintext INTERNAL AUTHENTICATE command carrying the challenge (a Case 4 short command with a
    /// short Le that accommodates any Active Authentication signature).
    /// </summary>
    private static CommandApdu BuildInternalAuthenticate(ReadOnlyMemory<byte> challenge, BaseMemoryPool pool) =>
        CommandApdu.BuildCase4(
            ActiveAuthenticationClass, InstructionCode.InternalAuthenticate.Code, 0x00, 0x00,
            challenge.Span, MaxResponseLength, pool);


    /// <summary>
    /// Sends the challenge in a Secure-Messaging-protected INTERNAL AUTHENTICATE and unprotects the response,
    /// or returns <see langword="null"/> on a transport error or an unsuccessful protected status word.
    /// </summary>
    private static async ValueTask<SecureMessagingResponse?> SendProtectedChallengeAsync(
        ApduDevice device,
        SecureMessagingSession session,
        ReadOnlyMemory<byte> challenge,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        using ProtectedCommandApdu protectedCommand = await session.ProtectCommandAsync(
            ActiveAuthenticationClass, InstructionCode.InternalAuthenticate.Code, 0x00, 0x00,
            challenge, MaxResponseLength, pool, cancellationToken).ConfigureAwait(false);

        ApduResult<ApduResponse> result = await ApduExecutor.ExecuteAsync(
            device, protectedCommand.AsReadOnlyMemory(), pool, cancellationToken).ConfigureAwait(false);
        if(result.IsTransportError)
        {
            return null;
        }

        using ApduResponse response = result.Value;
        if(!response.StatusWord.IsSuccess)
        {
            return null;
        }

        return await session.UnprotectResponseAsync(response.AsReadOnlyMemory(), pool, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Verifies the chip's ECDSA signature over the challenge against the DG15 elliptic-curve public key.
    /// </summary>
    private static async ValueTask<bool> VerifyEllipticCurveAsync(
        EncodedEcPoint activeAuthenticationPublicKey,
        ReadOnlyMemory<byte> challenge,
        ReadOnlyMemory<byte> signature,
        CancellationToken cancellationToken)
    {
        if(!activeAuthenticationPublicKey.Tag.TryGet(out CryptoAlgorithm algorithm))
        {
            return false;
        }

        //The DG15 key's tag declares Purpose.Exchange (it shares the uncompressed SEC1 encoding ECDH uses), so the
        //verification function is resolved by algorithm with Purpose.Verification. The registered verifiers accept
        //the uncompressed point as-is, so the key passes straight through.
        VerificationDelegate verify = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveVerification(algorithm, Purpose.Verification);

        return await verify(challenge, signature, activeAuthenticationPublicKey.AsReadOnlyMemory(), null, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Verifies the chip's ISO/IEC 9796-2 message-recovery signature over the challenge against the DG15 RSA
    /// public key — the terminal supplies the challenge as the non-recovered part M2, and the registered
    /// verifier recovers M1 and checks the embedded hash.
    /// </summary>
    private static async ValueTask<bool> VerifyRsaAsync(
        RsaPublicKey activeAuthenticationPublicKey,
        ReadOnlyMemory<byte> challenge,
        ReadOnlyMemory<byte> signature,
        CancellationToken cancellationToken)
    {
        RecoverableVerificationDelegate verify = RecoverableSignatureFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveVerification(
            CryptoAlgorithm.RsaIso9796d2, Purpose.Verification);

        return await verify(challenge, signature, activeAuthenticationPublicKey.AsReadOnlyMemory(), null, cancellationToken).ConfigureAwait(false);
    }
}
