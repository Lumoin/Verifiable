using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Fido2.Ctap.Authenticator.Automata;

/// <summary>
/// The state-aware <c>verify</c> composition that adds CTAP 2.3's token-in-use precondition on top of
/// <see cref="CtapPinUvAuthProtocol.VerifyAsync"/>'s crypto-only operation.
/// </summary>
/// <remarks>
/// CTAP 2.3 attaches an additional precondition to <c>verify</c> that the crypto-only protocol record
/// deliberately does not implement (see <see cref="CtapPinUvAuthProtocol.VerifyAsync"/>'s remark):
/// "If the key parameter value is the current pinUvAuthToken and it is not in use, then return error"
/// (CTAP 2.3 §6.5.6, line 6210-6214, and §6.5.7, line 6270-6274 — both protocols identically). This
/// composition lives here, at the state/automata layer, because the check depends on
/// <see cref="CtapPinUvAuthTokenState.IsInUse"/> — lifecycle state <see cref="CtapPinUvAuthProtocol"/>
/// has no access to.
/// </remarks>
[SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "The analyzer is not up to date with the latest syntax.")]
[SuppressMessage("Naming", "CA1708:Identifiers should differ by more than case", Justification = "The analyzer is not up to date with the latest syntax.")]
public static class CtapPinUvAuthTokenVerificationExtensions
{
    extension(CtapPinUvAuthProtocol protocol)
    {
        /// <summary>
        /// Verifies <paramref name="signature"/> the same way <see cref="CtapPinUvAuthProtocol.VerifyAsync"/>
        /// does, but first rejects when <paramref name="key"/> is <paramref name="tokenState"/>'s
        /// current <see cref="CtapPinUvAuthTokenState.Token"/> and that token is not in use.
        /// </summary>
        /// <param name="tokenState">The pinUvAuthToken lifecycle state <paramref name="key"/> is checked against.</param>
        /// <param name="key">The HMAC key presented for verification — the shared secret or a pinUvAuthToken.</param>
        /// <param name="message">The message the signature was computed over.</param>
        /// <param name="signature">The signature to verify.</param>
        /// <param name="pool">The memory pool for every allocation this call makes.</param>
        /// <param name="cancellationToken">A token observed across the HMAC computation.</param>
        /// <returns><see langword="true"/> when verification succeeds; otherwise <see langword="false"/>.</returns>
        public async ValueTask<bool> VerifyPinUvAuthTokenAsync(
            CtapPinUvAuthTokenState tokenState,
            ReadOnlyMemory<byte> key,
            ReadOnlyMemory<byte> message,
            ReadOnlyMemory<byte> signature,
            MemoryPool<byte> pool,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(tokenState);
            ArgumentNullException.ThrowIfNull(pool);

            if(IsCurrentTokenNotInUse(tokenState, key))
            {
                return false;
            }

            return await protocol.VerifyAsync(key, message, signature, pool, cancellationToken).ConfigureAwait(false);
        }
    }


    /// <summary>
    /// Evaluates CTAP 2.3's "key parameter value is the current pinUvAuthToken and it is not in use"
    /// test (line 6210-6214/6270-6274): a constant-time byte comparison against
    /// <paramref name="tokenState"/>'s current token, gated on <see cref="CtapPinUvAuthTokenState.IsInUse"/>.
    /// </summary>
    /// <param name="tokenState">The pinUvAuthToken lifecycle state to check against.</param>
    /// <param name="key">The HMAC key presented for verification.</param>
    /// <returns><see langword="true"/> when <paramref name="key"/> is the current, not-in-use token.</returns>
    private static bool IsCurrentTokenNotInUse(CtapPinUvAuthTokenState tokenState, ReadOnlyMemory<byte> key)
    {
        ReadOnlySpan<byte> tokenBytes = tokenState.Token.AsReadOnlySpan();
        if(key.Length != tokenBytes.Length)
        {
            return false;
        }

        bool isCurrentToken = CryptographicOperations.FixedTimeEquals(tokenBytes, key.Span);

        return isCurrentToken && !tokenState.IsInUse;
    }
}
