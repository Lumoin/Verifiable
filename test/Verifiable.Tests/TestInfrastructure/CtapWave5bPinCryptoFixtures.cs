using System;
using System.Buffers;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cbor.Ctap;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Aead;
using Verifiable.Cryptography.Context;
using Verifiable.Fido2.Ctap;
using Verifiable.Fido2.Ctap.Authenticator.Automata;
using Verifiable.JCose;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Builds a platform-side <c>authenticatorClientPIN</c> cryptographic session for the wave-5b PIN-path
/// subcommand tests, driven through the exact same <see cref="CtapPinUvAuthProtocol"/> operations the
/// authenticator itself uses (<c>getPublicKey</c>/<c>decapsulate</c>/<c>encrypt</c>/<c>decrypt</c>/
/// <c>authenticate</c>) rather than a test-only crypto reimplementation, per the wave-5b contract's
/// decision 10. ECDH is symmetric: calling <see cref="CtapPinUvAuthProtocol.DecapsulateAsync"/> with the
/// platform's own private key and the authenticator's public key derives the identical shared secret the
/// authenticator computes the other way around.
/// </summary>
internal static class CtapWave5bPinCryptoFixtures
{
    /// <summary>The exact byte length a <c>paddedNewPin</c>/<c>paddedPin</c> must be (CTAP 2.3, lines 5555/5580/5694).</summary>
    private const int PaddedPinLength = 64;


    /// <summary>
    /// Establishes a platform-side session for <paramref name="protocolId"/>: fetches the authenticator's
    /// key-agreement public key via <c>getKeyAgreement</c>, mints a fresh platform key pair, and
    /// decapsulates the shared secret both sides will use for the rest of the session.
    /// </summary>
    /// <param name="transceive">The transport-neutral CTAP2 request/response exchange.</param>
    /// <param name="protocolId">Which PIN/UV auth protocol to establish a session for.</param>
    /// <param name="pool">The memory pool every allocation in the session uses.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The established session. The caller owns it and must dispose it.</returns>
    public static async Task<CtapWave5bPlatformPinSession> EstablishSessionAsync(
        Ctap2TransceiveDelegate transceive, CtapPinUvAuthProtocolId protocolId, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        CtapPinUvAuthProtocol protocol = CtapPinUvAuthProtocol.CreateDefault(protocolId);

        var keyAgreementRequest = new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.GetKeyAgreement, PinUvAuthProtocol: (int)protocolId);
        CtapClientPinResponse keyAgreementResponse = await CtapAuthenticatorClientPinClient.ClientPinAsync(
            transceive, CtapClientPinRequestCborWriter.Write, keyAgreementRequest, CtapClientPinResponseCborReader.Read, pool, cancellationToken)
            .ConfigureAwait(false);

        CoseKey authenticatorPublicKey = keyAgreementResponse.KeyAgreement
            ?? throw new InvalidOperationException("getKeyAgreement did not return a keyAgreement member.");

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> platformKeys =
            CryptographicKeyEvents.CreateKeyPair(CryptoAlgorithm.P256, Purpose.Exchange, pool);

        IMemoryOwner<byte> sharedSecret;
        try
        {
            sharedSecret = await protocol.DecapsulateAsync(platformKeys.PrivateKey, authenticatorPublicKey, pool, cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            platformKeys.PrivateKey.Dispose();
            platformKeys.PublicKey.Dispose();
            throw;
        }

        CoseKey platformPublicKeyCose = protocol.GetPublicKey(platformKeys.PublicKey);

        return new CtapWave5bPlatformPinSession(protocol, sharedSecret, platformKeys.PrivateKey, platformKeys.PublicKey, platformPublicKeyCose, pool);
    }


    /// <summary>Right-pads <paramref name="pin"/>'s UTF-8 bytes with <c>0x00</c> to <see cref="PaddedPinLength"/> bytes (CTAP 2.3, line 5555).</summary>
    /// <param name="pin">The plaintext PIN, at most 63 UTF-8 bytes.</param>
    /// <returns>The 64-byte padded PIN.</returns>
    public static byte[] BuildPaddedPin(string pin)
    {
        byte[] pinBytes = Encoding.UTF8.GetBytes(pin);
        if(pinBytes.Length >= PaddedPinLength)
        {
            throw new ArgumentException($"The PIN's UTF-8 encoding must be shorter than {PaddedPinLength} bytes to leave at least one padding byte.", nameof(pin));
        }

        byte[] padded = new byte[PaddedPinLength];
        pinBytes.CopyTo(padded, 0);

        return padded;
    }


    /// <summary>
    /// A <c>pinHashEnc</c> byte string that fails to DECRYPT under either PIN/UV auth protocol, as
    /// opposed to one that decrypts but mismatches the stored PIN hash: protocol two's <c>decrypt</c>
    /// requires at least a 16-byte IV prefix (CTAP 2.3 §6.5.7, throws below that length), and protocol
    /// one's block-cipher <c>decrypt</c> requires an exact multiple of the AES block size (throws for a
    /// non-block-aligned length). Exercises the "if an error results" branch of the current-PIN
    /// decrypt/compare step (CTAP 2.3 lines 5671/5883/5985) rather than a decodable mismatch.
    /// </summary>
    /// <returns>A 5-byte value too short for protocol two and not block-aligned for protocol one.</returns>
    public static byte[] BuildMalformedPinHashEnc() => [0x01, 0x02, 0x03, 0x04, 0x05];
}


/// <summary>
/// One platform-side <c>authenticatorClientPIN</c> cryptographic session: the shared secret and the
/// <see cref="CtapPinUvAuthProtocol"/> operations the wave-5b PIN-path subcommand tests drive the
/// platform role with — building <c>newPinEnc</c>/<c>pinHashEnc</c>/<c>pinUvAuthParam</c> request
/// members and decrypting a returned <c>pinUvAuthToken</c>.
/// </summary>
internal sealed class CtapWave5bPlatformPinSession: IDisposable
{
    /// <summary>The stored PIN hash length in bytes: <c>LEFT(SHA-256(pin), 16)</c> (CTAP 2.3, lines 5592/5641).</summary>
    private const int PinHashLength = 16;

    /// <summary>The full SHA-256 digest length in bytes, before truncation to <see cref="PinHashLength"/>.</summary>
    private const int Sha256Length = 32;

    /// <summary>This session's PIN/UV auth protocol operations.</summary>
    private CtapPinUvAuthProtocol Protocol { get; }

    /// <summary>The established shared secret: 32 bytes for protocol one, 64 bytes for protocol two.</summary>
    private IMemoryOwner<byte> SharedSecret { get; }

    /// <summary>The platform's own ephemeral key-agreement private key, disposed with the session.</summary>
    private PrivateKeyMemory PlatformPrivateKey { get; }

    /// <summary>The platform's own ephemeral key-agreement public key, disposed with the session.</summary>
    private PublicKeyMemory PlatformPublicKey { get; }

    /// <summary>The memory pool every operation this session performs allocates from.</summary>
    private MemoryPool<byte> Pool { get; }

    /// <summary>Guards against redundant disposal.</summary>
    private bool disposed;

    /// <summary>The platform's own key-agreement public key, as the COSE_Key a request's <c>keyAgreement</c> parameter carries.</summary>
    public CoseKey PlatformPublicKeyCose { get; }


    /// <summary>Initializes an already-established session. Use <see cref="CtapWave5bPinCryptoFixtures.EstablishSessionAsync"/>.</summary>
    internal CtapWave5bPlatformPinSession(
        CtapPinUvAuthProtocol protocol,
        IMemoryOwner<byte> sharedSecret,
        PrivateKeyMemory platformPrivateKey,
        PublicKeyMemory platformPublicKey,
        CoseKey platformPublicKeyCose,
        MemoryPool<byte> pool)
    {
        Protocol = protocol;
        SharedSecret = sharedSecret;
        PlatformPrivateKey = platformPrivateKey;
        PlatformPublicKey = platformPublicKey;
        PlatformPublicKeyCose = platformPublicKeyCose;
        Pool = pool;
    }


    /// <summary>
    /// Builds <c>setPIN</c>'s <c>newPinEnc</c>/<c>pinUvAuthParam</c> request members for
    /// <paramref name="newPin"/> (CTAP 2.3 §6.5.5.5, lines 5555/5572).
    /// </summary>
    /// <param name="newPin">The plaintext new PIN.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The encrypted new PIN and the signature over it.</returns>
    public async Task<(byte[] NewPinEnc, byte[] PinUvAuthParam)> BuildSetPinMessagesAsync(string newPin, CancellationToken cancellationToken)
    {
        byte[] paddedPin = CtapWave5bPinCryptoFixtures.BuildPaddedPin(newPin);

        byte[] newPinEnc;
        using(Ciphertext ciphertext = await Protocol.EncryptAsync(SharedSecret.Memory, paddedPin, Pool, cancellationToken).ConfigureAwait(false))
        {
            newPinEnc = ciphertext.AsReadOnlySpan().ToArray();
        }

        byte[] pinUvAuthParam = await AuthenticateAsync(newPinEnc, cancellationToken).ConfigureAwait(false);

        return (newPinEnc, pinUvAuthParam);
    }


    /// <summary>
    /// Builds a <c>newPinEnc</c> from an arbitrary block-aligned <paramref name="plaintext"/> (not
    /// necessarily the standard 64-byte padded shape) together with a correctly verifying
    /// <c>pinUvAuthParam</c> over it — exercises the decrypted-length check (CTAP 2.3, lines 5580/5694)
    /// independently of the minimum-length policy check.
    /// </summary>
    /// <param name="plaintext">The block-aligned (multiple-of-16-byte) plaintext to encrypt as <c>newPinEnc</c>.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The encrypted message and its verifying signature.</returns>
    public async Task<(byte[] NewPinEnc, byte[] PinUvAuthParam)> BuildCustomVerifiedMessageAsync(byte[] plaintext, CancellationToken cancellationToken)
    {
        byte[] newPinEnc;
        using(Ciphertext ciphertext = await Protocol.EncryptAsync(SharedSecret.Memory, plaintext, Pool, cancellationToken).ConfigureAwait(false))
        {
            newPinEnc = ciphertext.AsReadOnlySpan().ToArray();
        }

        byte[] pinUvAuthParam = await AuthenticateAsync(newPinEnc, cancellationToken).ConfigureAwait(false);

        return (newPinEnc, pinUvAuthParam);
    }


    /// <summary>
    /// Builds <c>changePIN</c>'s <c>newPinEnc</c>/<c>pinHashEnc</c>/<c>pinUvAuthParam</c> request members
    /// (CTAP 2.3 §6.5.5.6, lines 5641-5645): the signature covers <c>newPinEnc || pinHashEnc</c>.
    /// </summary>
    /// <param name="newPin">The plaintext new PIN.</param>
    /// <param name="currentPin">The plaintext current PIN, proving knowledge of it.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The three request members.</returns>
    public async Task<(byte[] NewPinEnc, byte[] PinHashEnc, byte[] PinUvAuthParam)> BuildChangePinMessagesAsync(
        string newPin, string currentPin, CancellationToken cancellationToken)
    {
        byte[] pinHashEnc = await BuildPinHashEncAsync(currentPin, cancellationToken).ConfigureAwait(false);
        (byte[] newPinEnc, byte[] pinUvAuthParam) =
            await BuildChangePinMessagesWithExplicitPinHashEncAsync(newPin, pinHashEnc, cancellationToken).ConfigureAwait(false);

        return (newPinEnc, pinHashEnc, pinUvAuthParam);
    }


    /// <summary>
    /// Builds changePIN's newPinEnc/pinUvAuthParam request members exactly like
    /// <see cref="BuildChangePinMessagesAsync"/>, but signs over a CALLER-SUPPLIED
    /// <paramref name="pinHashEnc"/> instead of one computed from a plaintext current PIN, letting a test
    /// drive a pinHashEnc that fails to DECRYPT (<see cref="CtapWave5bPinCryptoFixtures.BuildMalformedPinHashEnc"/>)
    /// while still presenting a pinUvAuthParam that verifies, simulating a platform that holds the
    /// shared secret and can compute a valid signature over any bytes it chooses.
    /// </summary>
    /// <param name="newPin">The plaintext new PIN.</param>
    /// <param name="pinHashEnc">The (possibly malformed) pinHashEnc bytes to sign over verbatim.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The encrypted new PIN and a pinUvAuthParam that verifies over it and <paramref name="pinHashEnc"/>.</returns>
    public async Task<(byte[] NewPinEnc, byte[] PinUvAuthParam)> BuildChangePinMessagesWithExplicitPinHashEncAsync(
        string newPin, byte[] pinHashEnc, CancellationToken cancellationToken)
    {
        byte[] paddedNewPin = CtapWave5bPinCryptoFixtures.BuildPaddedPin(newPin);

        byte[] newPinEnc;
        using(Ciphertext newPinCiphertext = await Protocol.EncryptAsync(SharedSecret.Memory, paddedNewPin, Pool, cancellationToken).ConfigureAwait(false))
        {
            newPinEnc = newPinCiphertext.AsReadOnlySpan().ToArray();
        }

        byte[] verifyMessage = new byte[newPinEnc.Length + pinHashEnc.Length];
        newPinEnc.CopyTo(verifyMessage, 0);
        pinHashEnc.CopyTo(verifyMessage, newPinEnc.Length);

        byte[] pinUvAuthParam = await AuthenticateAsync(verifyMessage, cancellationToken).ConfigureAwait(false);

        return (newPinEnc, pinUvAuthParam);
    }


    /// <summary>
    /// Builds <c>getPinToken</c>/<c>getPinUvAuthTokenUsingPinWithPermissions</c>'s <c>pinHashEnc</c>
    /// request member: <c>encrypt(sharedSecret, LEFT(SHA-256(currentPin), 16))</c> (CTAP 2.3, lines
    /// 5641/5854).
    /// </summary>
    /// <param name="currentPin">The plaintext current PIN.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The encrypted PIN hash.</returns>
    public async Task<byte[]> BuildPinHashEncAsync(string currentPin, CancellationToken cancellationToken)
    {
        byte[] currentPinBytes = Encoding.UTF8.GetBytes(currentPin);
        using DigestValue fullDigest = CryptographicKeyEvents.ComputeDigest(currentPinBytes, Sha256Length, CryptoTags.Sha256Digest, Pool);

        using Ciphertext ciphertext = await Protocol.EncryptAsync(
            SharedSecret.Memory, fullDigest.AsReadOnlyMemory()[..PinHashLength], Pool, cancellationToken).ConfigureAwait(false);

        return ciphertext.AsReadOnlySpan().ToArray();
    }


    /// <summary>
    /// Builds a <c>pinHashEnc</c> that intentionally does not match a stored PIN — encrypts a fixed,
    /// distinguishable 16-byte pattern rather than any real PIN's hash — for the wrong-current-PIN
    /// negative paths.
    /// </summary>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The encrypted, deliberately wrong PIN hash.</returns>
    public async Task<byte[]> BuildWrongPinHashEncAsync(CancellationToken cancellationToken)
    {
        byte[] wrongHash = new byte[PinHashLength];
        for(int i = 0; i < wrongHash.Length; i++)
        {
            wrongHash[i] = (byte)(0xEE ^ i);
        }

        using Ciphertext ciphertext = await Protocol.EncryptAsync(SharedSecret.Memory, wrongHash, Pool, cancellationToken).ConfigureAwait(false);

        return ciphertext.AsReadOnlySpan().ToArray();
    }


    /// <summary>Decrypts a returned <c>pinUvAuthToken</c> under this session's shared secret.</summary>
    /// <param name="encryptedToken">The response's encrypted <c>pinUvAuthToken</c> bytes.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The decrypted token bytes.</returns>
    public async Task<byte[]> DecryptTokenAsync(ReadOnlyMemory<byte> encryptedToken, CancellationToken cancellationToken)
    {
        using DecryptedContent decrypted = await Protocol.DecryptAsync(SharedSecret.Memory, encryptedToken, Pool, cancellationToken).ConfigureAwait(false);

        return decrypted.AsReadOnlySpan().ToArray();
    }


    /// <summary>Computes <c>authenticate(sharedSecret, message)</c> and copies the result out as a plain array.</summary>
    private async Task<byte[]> AuthenticateAsync(ReadOnlyMemory<byte> message, CancellationToken cancellationToken)
    {
        using IMemoryOwner<byte> signature = await Protocol.AuthenticateAsync(SharedSecret.Memory, message, Pool, cancellationToken).ConfigureAwait(false);

        return signature.Memory.Span.ToArray();
    }


    /// <summary>
    /// Builds the platform-side <c>hmac-secret</c> ga request members (CTAP 2.3 §12.7, snapshot lines
    /// 13228-13248, contract R13): <c>saltEnc = encrypt(sharedSecret, salt1 [|| salt2])</c>,
    /// <c>saltAuth = authenticate(sharedSecret, saltEnc)</c> — this session's own established shared
    /// secret and <see cref="CtapPinUvAuthProtocol"/> operations, the exact same crypto the authenticator
    /// side runs, never a test-only reimplementation.
    /// </summary>
    /// <param name="salt1">The 32-byte first salt.</param>
    /// <param name="salt2">The 32-byte second salt for a two-salt request, or <see langword="null"/> for a one-salt request.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The encrypted salt(s) and the signature over them.</returns>
    public async Task<(byte[] SaltEnc, byte[] SaltAuth)> BuildHmacSecretSaltsAsync(byte[] salt1, byte[]? salt2, CancellationToken cancellationToken)
    {
        byte[] plaintext;
        if(salt2 is null)
        {
            plaintext = salt1;
        }
        else
        {
            plaintext = new byte[salt1.Length + salt2.Length];
            salt1.CopyTo(plaintext, 0);
            salt2.CopyTo(plaintext, salt1.Length);
        }

        byte[] saltEnc;
        using(Ciphertext ciphertext = await Protocol.EncryptAsync(SharedSecret.Memory, plaintext, Pool, cancellationToken).ConfigureAwait(false))
        {
            saltEnc = ciphertext.AsReadOnlySpan().ToArray();
        }

        byte[] saltAuth = await AuthenticateAsync(saltEnc, cancellationToken).ConfigureAwait(false);

        return (saltEnc, saltAuth);
    }


    /// <summary>
    /// Builds a <c>saltEnc</c> that fails to DECRYPT under either PIN/UV auth protocol together with a
    /// <c>saltAuth</c> that still verifies over it — exercises the decrypt-failure branch (CTAP 2.3 §12.7,
    /// snapshot line 13307) independently of the verify-failure branch, mirroring
    /// <see cref="CtapWave5bPinCryptoFixtures.BuildMalformedPinHashEnc"/>'s own shape: protocol two's
    /// <c>decrypt</c> requires at least a 16-byte IV prefix, and protocol one's block-cipher <c>decrypt</c>
    /// requires an exact multiple of the AES block size.
    /// </summary>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>A too-short <c>saltEnc</c> and a <c>saltAuth</c> that verifies over it.</returns>
    public async Task<(byte[] SaltEnc, byte[] SaltAuth)> BuildMalformedHmacSecretSaltsAsync(CancellationToken cancellationToken)
    {
        byte[] saltEnc = [0x01, 0x02, 0x03, 0x04, 0x05];
        byte[] saltAuth = await AuthenticateAsync(saltEnc, cancellationToken).ConfigureAwait(false);

        return (saltEnc, saltAuth);
    }


    /// <summary>Decrypts a returned <c>hmac-secret</c> authData output under this session's shared secret.</summary>
    /// <param name="encryptedOutput">The decoded authData extensions map's <c>hmac-secret</c> byte string.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The decrypted output1 (and, for a two-salt request, output2) bytes.</returns>
    public async Task<byte[]> DecryptHmacSecretOutputAsync(ReadOnlyMemory<byte> encryptedOutput, CancellationToken cancellationToken)
    {
        using DecryptedContent decrypted = await Protocol.DecryptAsync(SharedSecret.Memory, encryptedOutput, Pool, cancellationToken).ConfigureAwait(false);

        return decrypted.AsReadOnlySpan().ToArray();
    }


    /// <summary>Releases the shared secret and the platform's own ephemeral key pair. Idempotent.</summary>
    public void Dispose()
    {
        if(disposed)
        {
            return;
        }

        disposed = true;

        SharedSecret.Memory.Span.Clear();
        SharedSecret.Dispose();
        PlatformPrivateKey.Dispose();
        PlatformPublicKey.Dispose();
    }
}
