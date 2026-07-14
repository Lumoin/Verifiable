using System;
using System.Buffers;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Aead;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;

namespace Verifiable.Fido2.Ctap.Authenticator.Automata;

/// <summary>
/// The authenticator-side operations of a CTAP PIN/UV auth protocol (CTAP 2.3 §6.5.4/§6.5.6/§6.5.7):
/// <c>getPublicKey</c>, <c>decapsulate</c>, <c>encrypt</c>, <c>decrypt</c>, <c>authenticate</c>, and
/// <c>verify</c>, with <c>kdf</c> composed internally by <c>decapsulate</c>.
/// </summary>
/// <remarks>
/// <para>
/// A seam-bundle record mirroring <see cref="CtapCredentialSigningBackend"/>'s role: every
/// cryptographic primitive the protocol needs is an injected delegate field, and every operation is
/// a pure function over those delegates plus the arguments passed to it - key-agreement key material
/// always arrives as a method parameter, never captured, matching the key material's true home on
/// <c>CtapAuthenticatorState</c>. Protocol one and protocol two share this single type because CTAP
/// 2.3 §6.5.7 defines protocol two as "inherits Protocol One entirely and overrides exactly" its
/// <c>kdf</c>, <c>resetPinUvAuthToken</c>, <c>encrypt</c>, <c>decrypt</c>, and
/// <c>authenticate</c>/<c>verify</c> functions (line 6219-6229) - <see cref="Id"/> switches between
/// the two shapes at the points where they actually differ, rather than duplicating the identical
/// <see cref="GetPublicKey"/> and <see cref="DecapsulateAsync"/> logic across two types.
/// </para>
/// <para>
/// <strong>Protocol one</strong> (CTAP 2.3 §6.5.6): <c>kdf(Z) = SHA-256(Z)</c>, a single 32-byte
/// shared secret used directly as both the AES-256 key and the HMAC-SHA-256 key; <c>encrypt</c>/
/// <c>decrypt</c> use AES-256-CBC with an all-zero IV and no padding; <c>authenticate</c>/
/// <c>verify</c> use the first 16 bytes of HMAC-SHA-256.
/// </para>
/// <para>
/// <strong>Protocol two</strong> (CTAP 2.3 §6.5.7): <c>kdf(Z)</c> is <em>two separate</em>
/// <see cref="Cryptography.Hkdf"/> calls concatenated - <c>HKDF-SHA-256(salt=32 zero bytes, IKM=Z,
/// L=32, info="CTAP2 HMAC key")</c> then the same with <c>info="CTAP2 AES key"</c> - never a single
/// <c>L=64</c> call (line 6229's explicit warning that the two constructions are not equivalent);
/// the resulting 64-byte value splits into bytes <c>[0,32)</c> (the HMAC key) and <c>[32,64)</c> (the
/// AES key); <c>encrypt</c> prefixes a fresh random 16-byte IV to the AES-256-CBC ciphertext;
/// <c>authenticate</c>/<c>verify</c> use the full, untruncated 32-byte HMAC-SHA-256 output.
/// </para>
/// </remarks>
/// <param name="Id">Which protocol (one or two) this instance implements.</param>
/// <param name="PerformKeyAgreement">
/// The raw ECDH step (P-256 scalar multiplication, raw big-endian x-coordinate output) that
/// <see cref="DecapsulateAsync"/> composes with the protocol-specific <c>kdf</c>.
/// </param>
/// <param name="ComputeDigest">The digest primitive protocol one's <c>kdf</c> uses (SHA-256).</param>
/// <param name="ComputeHmac">The HMAC-SHA-256 primitive <see cref="AuthenticateAsync"/> uses.</param>
/// <param name="EncryptCbc">The unauthenticated AES-256-CBC encrypt primitive <see cref="EncryptAsync"/> uses.</param>
/// <param name="DecryptCbc">The unauthenticated AES-256-CBC decrypt primitive <see cref="DecryptAsync"/> uses.</param>
/// <param name="GenerateNonce">The entropy source protocol two's <see cref="EncryptAsync"/> uses for its random IV.</param>
public sealed record CtapPinUvAuthProtocol(
    CtapPinUvAuthProtocolId Id,
    KeyAgreementDecryptDelegate PerformKeyAgreement,
    ComputeDigestDelegate ComputeDigest,
    ComputeHmacDelegate ComputeHmac,
    SymmetricEncryptDelegate EncryptCbc,
    SymmetricDecryptDelegate DecryptCbc,
    GenerateNonceDelegate GenerateNonce)
{
    /// <summary>Every hash/HMAC/HKDF round in both protocols is SHA-256 (CTAP 2.3 §6.5.6/§6.5.7).</summary>
    private const int Sha256DigestLength = 32;

    /// <summary>The AES block size - the IV length for both protocols' AES-256-CBC (CTAP 2.3 §6.5.6/§6.5.7).</summary>
    private const int AesBlockLength = 16;

    /// <summary>Protocol two's <c>kdf(Z)</c> output splits into two 32-byte halves (CTAP 2.3 §6.5.7, line 6224-6229).</summary>
    private const int ProtocolTwoHmacKeyLength = 32;

    /// <summary>Protocol two's <c>kdf(Z)</c> produces this many bytes total: <c>[0,32)</c> HMAC key, <c>[32,64)</c> AES key.</summary>
    private const int ProtocolTwoSharedSecretLength = ProtocolTwoHmacKeyLength + Sha256DigestLength;

    /// <summary>Protocol one truncates <c>authenticate</c>/<c>verify</c>'s HMAC-SHA-256 output to its first 16 bytes (CTAP 2.3 §6.5.6, line 6207-6217).</summary>
    private const int ProtocolOneAuthenticateLength = 16;

    /// <summary>
    /// The COSE <c>alg</c> value CTAP 2.3 mandates for <see cref="GetPublicKey"/>'s COSE_Key: <c>-25</c>,
    /// which the specification itself calls out as "not the algorithm actually used" (CTAP 2.3 §6.5.6,
    /// line 6182) - a spec-mandated cosmetic wire constant, not a claim that either protocol's <c>kdf</c>
    /// performs ECDH-ES+HKDF-256 (protocol one hashes once with SHA-256; protocol two runs two independent
    /// HKDF-SHA-256 calls - see <see cref="KdfProtocolOneAsync"/>/<see cref="KdfProtocolTwoAsync"/>).
    /// Written as a literal rather than <see cref="WellKnownCoseAlgorithms.EcdhEsHkdf256"/> so this value
    /// is anchored directly to the CTAP text, not derived from that COSE registration's semantics.
    /// </summary>
    private const int GetPublicKeyCoseAlgorithm = -25;

    /// <summary>The ASCII/UTF-8 HKDF <c>info</c> label selecting protocol two's HMAC-key half (CTAP 2.3 §6.5.7, line 6224-6229).</summary>
    private static ReadOnlyMemory<byte> ProtocolTwoHmacKeyInfo { get; } = "CTAP2 HMAC key"u8.ToArray();

    /// <summary>The ASCII/UTF-8 HKDF <c>info</c> label selecting protocol two's AES-key half (CTAP 2.3 §6.5.7, line 6224-6229).</summary>
    private static ReadOnlyMemory<byte> ProtocolTwoAesKeyInfo { get; } = "CTAP2 AES key"u8.ToArray();


    /// <summary>
    /// Builds a protocol instance whose six crypto delegates are resolved from the process-wide
    /// crypto provider registries rather than supplied by the caller. This is the default composition
    /// <see cref="CtapAuthenticatorSimulator"/> uses so <c>getKeyAgreement</c> (the only operation this
    /// wave calls, itself independent of every injected delegate - see <see cref="GetPublicKey"/>) works
    /// without every composition root having to hand-wire all six delegates itself; a caller needing a
    /// customized composition (deterministic KATs, a non-default provider) still constructs
    /// <see cref="CtapPinUvAuthProtocol"/> directly.
    /// </summary>
    /// <remarks>
    /// The key-agreement delegate resolves through <see cref="KeyAgreementFunctionRegistry{TDiscriminator1, TDiscriminator2}"/>
    /// keyed by (<see cref="CryptoAlgorithm.P256"/>, <see cref="Purpose.Exchange"/>) - the same
    /// algorithm/purpose-keyed registry <c>PrivateKeyMemory.AgreementDecryptAsync</c>'s registry
    /// overload uses - since more than one curve's implementation can be registered at once. The
    /// remaining five delegates resolve through <see cref="CryptographicKeyFactory.GetFunction{TFunction}"/>,
    /// a single-slot-per-delegate-type registry (no algorithm/purpose discriminator needed for a digest,
    /// HMAC, symmetric cipher, or nonce generator in this profile).
    /// </remarks>
    /// <param name="id">Which protocol (one or two) the returned instance implements.</param>
    /// <returns>A fully composed instance backed by the registered production primitives.</returns>
    /// <exception cref="InvalidOperationException">
    /// One of the six required delegate types has no registered implementation.
    /// </exception>
    public static CtapPinUvAuthProtocol CreateDefault(CtapPinUvAuthProtocolId id) =>
        new(
            id,
            KeyAgreementFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveAgreementDecrypt(CryptoAlgorithm.P256, Purpose.Exchange),
            Resolve<ComputeDigestDelegate>(),
            Resolve<ComputeHmacDelegate>(),
            Resolve<SymmetricEncryptDelegate>(),
            Resolve<SymmetricDecryptDelegate>(),
            Resolve<GenerateNonceDelegate>());


    /// <summary>Resolves a registered crypto delegate of type <typeparamref name="TFunction"/> by its own type as the registry key.</summary>
    private static TFunction Resolve<TFunction>() where TFunction: Delegate =>
        CryptographicKeyFactory.GetFunction<TFunction>(typeof(TFunction))
            ?? throw new InvalidOperationException(
                $"No {typeof(TFunction).Name} has been registered. Call CryptographicKeyFactory.RegisterFunction during application startup.");


    /// <summary>
    /// Returns this protocol's public key as a COSE_Key (CTAP 2.3 §6.5.6, line 6175-6189): <c>kty=2</c>
    /// (EC2), <c>crv=1</c> (P-256), <c>x</c>/<c>y</c> the 32-byte big-endian coordinates of the
    /// authenticator's key-agreement public key, and the literal <see cref="GetPublicKeyCoseAlgorithm"/>.
    /// </summary>
    /// <param name="ownPublicKey">The authenticator's P-256 key-agreement public key.</param>
    /// <returns>The COSE_Key view <c>getKeyAgreement</c> returns to the platform.</returns>
    public CoseKey GetPublicKey(PublicKeyMemory ownPublicKey)
    {
        ArgumentNullException.ThrowIfNull(ownPublicKey);
        EnsureSupportedId();

        CryptoAlgorithm curve = ownPublicKey.Tag.Get<CryptoAlgorithm>();
        byte[] uncompressed = EllipticCurveUtilities.NormalizeToUncompressed(
            ownPublicKey.AsReadOnlySpan(), EllipticCurveUtilities.CurveTypeFor(curve));

        return new CoseKey(
            kty: CoseKeyTypes.Ec2,
            alg: GetPublicKeyCoseAlgorithm,
            curve: CoseKeyCurves.P256,
            x: EllipticCurveUtilities.SliceXCoordinate(uncompressed).ToArray(),
            y: EllipticCurveUtilities.SliceYCoordinate(uncompressed).ToArray());
    }


    /// <summary>
    /// Performs <c>decapsulate</c> (CTAP 2.3 §6.5.6, line 6190-6200): raw ECDH between
    /// <paramref name="ownPrivateKey"/> and <paramref name="peerKeyAgreementKey"/>, followed by this
    /// protocol's internal <c>kdf</c>.
    /// </summary>
    /// <param name="ownPrivateKey">The authenticator's P-256 key-agreement private key.</param>
    /// <param name="peerKeyAgreementKey">The platform's ephemeral P-256 public key (the request's <c>keyAgreement</c> parameter).</param>
    /// <param name="pool">The memory pool for every allocation this call makes.</param>
    /// <param name="cancellationToken">A token observed across the ECDH and <c>kdf</c> computations.</param>
    /// <returns>
    /// A pool-owned buffer holding the derived shared secret: 32 bytes for protocol one, 64 bytes for
    /// protocol two. Ownership transfers to the caller, which must zero and dispose it.
    /// </returns>
    public async ValueTask<IMemoryOwner<byte>> DecapsulateAsync(
        PrivateKeyMemory ownPrivateKey,
        CoseKey peerKeyAgreementKey,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(ownPrivateKey);
        ArgumentNullException.ThrowIfNull(peerKeyAgreementKey);
        ArgumentNullException.ThrowIfNull(pool);

        using PublicKeyMemory peerPublicKey = peerKeyAgreementKey.ToPublicKeyMemory(pool);
        using SharedSecret z = await ownPrivateKey.AgreementDecryptAsync(
            peerPublicKey, PerformKeyAgreement, pool, cancellationToken).ConfigureAwait(false);

        return await KdfAsync(z.AsReadOnlyMemory(), pool, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Encrypts <paramref name="plaintext"/> under the shared secret <paramref name="key"/>
    /// (CTAP 2.3 §6.5.6 line 6201-6203 / §6.5.7 line 6238-6249).
    /// </summary>
    /// <param name="key">
    /// The shared secret from <see cref="DecapsulateAsync"/> (or, for protocol two, any key of at
    /// least 64 bytes whose bytes <c>[32,64)</c> are the AES key).
    /// </param>
    /// <param name="plaintext">The block-aligned plaintext to encrypt. No padding is added.</param>
    /// <param name="pool">The memory pool for every allocation this call makes.</param>
    /// <param name="cancellationToken">A token observed across the encryption.</param>
    /// <returns>
    /// For protocol one, the raw AES-256-CBC ciphertext (zero IV, not carried in the output). For
    /// protocol two, <c>iv (16 bytes) || AES-256-CBC(plaintext, aesKey, iv)</c>.
    /// </returns>
    public ValueTask<Ciphertext> EncryptAsync(
        ReadOnlyMemory<byte> key,
        ReadOnlyMemory<byte> plaintext,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(pool);

        return Id switch
        {
            CtapPinUvAuthProtocolId.One => EncryptProtocolOneAsync(key, plaintext, pool, cancellationToken),
            CtapPinUvAuthProtocolId.Two => EncryptProtocolTwoAsync(key, plaintext, pool, cancellationToken),
            _ => throw new NotSupportedException($"Unsupported CTAP PIN/UV auth protocol id '{Id}'.")
        };
    }


    /// <summary>
    /// Decrypts <paramref name="ciphertext"/> under the shared secret <paramref name="key"/>
    /// (CTAP 2.3 §6.5.6 line 6204-6206 / §6.5.7 line 6250-6261).
    /// </summary>
    /// <param name="key">The shared secret from <see cref="DecapsulateAsync"/>.</param>
    /// <param name="ciphertext">
    /// For protocol one, the raw block-aligned AES-256-CBC ciphertext. For protocol two,
    /// <c>iv (16 bytes) || AES-256-CBC ciphertext</c>, at least 16 bytes.
    /// </param>
    /// <param name="pool">The memory pool for every allocation this call makes.</param>
    /// <param name="cancellationToken">A token observed across the decryption.</param>
    /// <returns>The still-padded plaintext (the caller strips any application-level padding).</returns>
    public ValueTask<DecryptedContent> DecryptAsync(
        ReadOnlyMemory<byte> key,
        ReadOnlyMemory<byte> ciphertext,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(pool);

        return Id switch
        {
            CtapPinUvAuthProtocolId.One => DecryptProtocolOneAsync(key, ciphertext, pool, cancellationToken),
            CtapPinUvAuthProtocolId.Two => DecryptProtocolTwoAsync(key, ciphertext, pool, cancellationToken),
            _ => throw new NotSupportedException($"Unsupported CTAP PIN/UV auth protocol id '{Id}'.")
        };
    }


    /// <summary>
    /// Computes <c>authenticate(key, message)</c> (CTAP 2.3 §6.5.6 line 6207-6209 / §6.5.7 line 6262-6269):
    /// the first 16 bytes of HMAC-SHA-256 for protocol one, the full untruncated 32 bytes for protocol two.
    /// </summary>
    /// <param name="key">
    /// The HMAC key: the shared secret (protocol one) or a key whose leading 32 bytes are protocol
    /// two's HMAC-key half (a <c>pinUvAuthToken</c> already is exactly that half - CTAP 2.3 §6.5.7,
    /// line 6262-6269, "a no-op when key already is the 32-byte pinUvAuthToken").
    /// </param>
    /// <param name="message">The message to authenticate.</param>
    /// <param name="pool">The memory pool for every allocation this call makes.</param>
    /// <param name="cancellationToken">A token observed across the HMAC computation.</param>
    /// <returns>A pool-owned buffer holding the signature: 16 bytes for protocol one, 32 bytes for protocol two.</returns>
    public async ValueTask<IMemoryOwner<byte>> AuthenticateAsync(
        ReadOnlyMemory<byte> key,
        ReadOnlyMemory<byte> message,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(pool);

        ReadOnlyMemory<byte> hmacKey = Id == CtapPinUvAuthProtocolId.Two && key.Length > ProtocolTwoHmacKeyLength
            ? key[..ProtocolTwoHmacKeyLength]
            : key;

        (HmacValue fullMac, CryptoEvent? hmacEvent) = await ComputeHmac(
            new ReadOnlySequence<byte>(message), hmacKey, Sha256DigestLength, CryptoTags.HmacSha256Value, pool,
            cancellationToken: cancellationToken).ConfigureAwait(false);
        EmitIfPresent(hmacEvent);

        using(fullMac)
        {
            int outputLength = Id switch
            {
                CtapPinUvAuthProtocolId.One => ProtocolOneAuthenticateLength,
                CtapPinUvAuthProtocolId.Two => Sha256DigestLength,
                _ => throw new NotSupportedException($"Unsupported CTAP PIN/UV auth protocol id '{Id}'.")
            };

            IMemoryOwner<byte> signature = pool.Rent(outputLength);
            fullMac.AsReadOnlySpan()[..outputLength].CopyTo(signature.Memory.Span);

            return signature;
        }
    }


    /// <summary>
    /// Computes <c>verify(key, message, signature)</c> (CTAP 2.3 §6.5.6 line 6210-6217 / §6.5.7 line 6270-6279):
    /// success iff <paramref name="signature"/> is the exact expected length and equals
    /// <see cref="AuthenticateAsync"/>'s output, compared in constant time.
    /// </summary>
    /// <param name="key">The HMAC key - see <see cref="AuthenticateAsync"/>.</param>
    /// <param name="message">The message the signature was computed over.</param>
    /// <param name="signature">The signature to verify.</param>
    /// <param name="pool">The memory pool for every allocation this call makes.</param>
    /// <param name="cancellationToken">A token observed across the HMAC computation.</param>
    /// <returns><see langword="true"/> when <paramref name="signature"/> matches; otherwise <see langword="false"/>.</returns>
    /// <remarks>
    /// This intentionally does not implement the token-in-use check CTAP 2.3 attaches to <c>verify</c>
    /// (line 6210-6214/6270-6274) - that check depends on <c>pinUvAuthToken</c> lifecycle state that
    /// lives on <c>CtapAuthenticatorState</c>, outside this crypto-only seam's scope.
    /// <see cref="CtapPinUvAuthTokenVerificationExtensions.VerifyPinUvAuthTokenAsync"/> composes that
    /// check with this method at the state/automata layer.
    /// </remarks>
    public async ValueTask<bool> VerifyAsync(
        ReadOnlyMemory<byte> key,
        ReadOnlyMemory<byte> message,
        ReadOnlyMemory<byte> signature,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(pool);

        int expectedLength = Id switch
        {
            CtapPinUvAuthProtocolId.One => ProtocolOneAuthenticateLength,
            CtapPinUvAuthProtocolId.Two => Sha256DigestLength,
            _ => throw new NotSupportedException($"Unsupported CTAP PIN/UV auth protocol id '{Id}'.")
        };

        if(signature.Length != expectedLength)
        {
            return false;
        }

        using IMemoryOwner<byte> expected = await AuthenticateAsync(key, message, pool, cancellationToken).ConfigureAwait(false);

        bool isValid = CryptographicOperations.FixedTimeEquals(expected.Memory.Span[..expectedLength], signature.Span);
        expected.Memory.Span.Clear();

        return isValid;
    }


    /// <summary>
    /// Dispatches to this protocol's <c>kdf(Z)</c> (CTAP 2.3 §6.5.6 line 6154-6156 / §6.5.7 line 6224-6229).
    /// </summary>
    private ValueTask<IMemoryOwner<byte>> KdfAsync(ReadOnlyMemory<byte> z, MemoryPool<byte> pool, CancellationToken cancellationToken) =>
        Id switch
        {
            CtapPinUvAuthProtocolId.One => KdfProtocolOneAsync(z, pool, cancellationToken),
            CtapPinUvAuthProtocolId.Two => KdfProtocolTwoAsync(z, pool, cancellationToken),
            _ => throw new NotSupportedException($"Unsupported CTAP PIN/UV auth protocol id '{Id}'.")
        };


    /// <summary>Protocol one's <c>kdf(Z) = SHA-256(Z)</c> (CTAP 2.3 §6.5.6, line 6154-6156): a single hash, the whole 32-byte output is the shared secret.</summary>
    private async ValueTask<IMemoryOwner<byte>> KdfProtocolOneAsync(ReadOnlyMemory<byte> z, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        (DigestValue digest, CryptoEvent? digestEvent) = await ComputeDigest(
            new ReadOnlySequence<byte>(z), Sha256DigestLength, CryptoTags.Sha256Digest, pool,
            cancellationToken: cancellationToken).ConfigureAwait(false);
        EmitIfPresent(digestEvent);

        using(digest)
        {
            IMemoryOwner<byte> sharedSecret = pool.Rent(Sha256DigestLength);
            digest.AsReadOnlySpan().CopyTo(sharedSecret.Memory.Span);

            return sharedSecret;
        }
    }


    /// <summary>
    /// Protocol two's <c>kdf(Z)</c> (CTAP 2.3 §6.5.7, line 6224-6229): two <em>separate</em> HKDF-SHA-256
    /// calls (salt = 32 zero bytes, L = 32 each) - never a single <c>L=64</c> call, per the spec's explicit
    /// warning that the two constructions are not equivalent - concatenated into a 64-byte value: bytes
    /// <c>[0,32)</c> from the <c>"CTAP2 HMAC key"</c> info label, bytes <c>[32,64)</c> from
    /// <c>"CTAP2 AES key"</c>.
    /// </summary>
    private static async ValueTask<IMemoryOwner<byte>> KdfProtocolTwoAsync(ReadOnlyMemory<byte> z, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        using IMemoryOwner<byte> zeroSalt = pool.Rent(Sha256DigestLength);
        zeroSalt.Memory.Span[..Sha256DigestLength].Clear();
        ReadOnlyMemory<byte> salt = zeroSalt.Memory[..Sha256DigestLength];

        //Two independent HKDF-Expand chains over the same PRK derivation inputs (salt, Z) - not two
        //32-byte blocks of one L=64 HKDF-Expand round, which would chain T(1) into T(2)'s input.
        IMemoryOwner<byte> hmacKeyHalf = await Cryptography.Hkdf.DeriveAsync(
            HashAlgorithmName.SHA256, salt, z, ProtocolTwoHmacKeyInfo, ProtocolTwoHmacKeyLength, pool, cancellationToken).ConfigureAwait(false);
        try
        {
            IMemoryOwner<byte> aesKeyHalf = await Cryptography.Hkdf.DeriveAsync(
                HashAlgorithmName.SHA256, salt, z, ProtocolTwoAesKeyInfo, Sha256DigestLength, pool, cancellationToken).ConfigureAwait(false);
            try
            {
                IMemoryOwner<byte> sharedSecret = pool.Rent(ProtocolTwoSharedSecretLength);
                hmacKeyHalf.Memory.Span[..ProtocolTwoHmacKeyLength].CopyTo(sharedSecret.Memory.Span);
                aesKeyHalf.Memory.Span[..Sha256DigestLength].CopyTo(sharedSecret.Memory.Span[ProtocolTwoHmacKeyLength..]);

                return sharedSecret;
            }
            finally
            {
                aesKeyHalf.Memory.Span.Clear();
                aesKeyHalf.Dispose();
            }
        }
        finally
        {
            hmacKeyHalf.Memory.Span.Clear();
            hmacKeyHalf.Dispose();
        }
    }


    /// <summary>Protocol one's <c>encrypt</c> (CTAP 2.3 §6.5.6, line 6201-6203): AES-256-CBC with an all-zero IV, no padding.</summary>
    private async ValueTask<Ciphertext> EncryptProtocolOneAsync(ReadOnlyMemory<byte> key, ReadOnlyMemory<byte> plaintext, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        using IMemoryOwner<byte> zeroIv = pool.Rent(AesBlockLength);
        zeroIv.Memory.Span[..AesBlockLength].Clear();

        (Ciphertext result, CryptoEvent? cipherEvent) = await EncryptCbc(
            plaintext, key, zeroIv.Memory[..AesBlockLength], CryptoTags.AesCbcHmacCiphertext, pool,
            cancellationToken: cancellationToken).ConfigureAwait(false);
        EmitIfPresent(cipherEvent);

        return result;
    }


    /// <summary>
    /// Protocol two's <c>encrypt</c> (CTAP 2.3 §6.5.7, line 6238-6249): discards <paramref name="key"/>'s
    /// leading 32 bytes to select the AES-key half, generates a fresh random 16-byte IV, and returns
    /// <c>iv || AES-256-CBC(plaintext, aesKey, iv)</c>.
    /// </summary>
    private async ValueTask<Ciphertext> EncryptProtocolTwoAsync(ReadOnlyMemory<byte> key, ReadOnlyMemory<byte> plaintext, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        ReadOnlyMemory<byte> aesKey = key[ProtocolTwoHmacKeyLength..];

        (Nonce iv, CryptoEvent? nonceEvent) = GenerateNonce(AesBlockLength, CryptoTags.AesCbcHmacIv, pool);
        EmitIfPresent(nonceEvent);

        using(iv)
        {
            //Marks the IV as consumed for its one intended protocol use: embedding it in the encrypt output.
            _ = iv.UseNonce();
            ReadOnlyMemory<byte> ivMemory = iv.AsReadOnlyMemory();

            (Ciphertext ciphertext, CryptoEvent? cipherEvent) = await EncryptCbc(
                plaintext, aesKey, ivMemory, CryptoTags.AesCbcHmacCiphertext, pool,
                cancellationToken: cancellationToken).ConfigureAwait(false);
            EmitIfPresent(cipherEvent);

            using(ciphertext)
            {
                IMemoryOwner<byte> combined = pool.Rent(AesBlockLength + ciphertext.Length);
                ivMemory.Span.CopyTo(combined.Memory.Span);
                ciphertext.AsReadOnlySpan().CopyTo(combined.Memory.Span[AesBlockLength..]);

                return new Ciphertext(combined, CryptoTags.AesCbcHmacCiphertext);
            }
        }
    }


    /// <summary>Protocol one's <c>decrypt</c> (CTAP 2.3 §6.5.6, line 6204-6206): AES-256-CBC with an all-zero IV.</summary>
    private async ValueTask<DecryptedContent> DecryptProtocolOneAsync(ReadOnlyMemory<byte> key, ReadOnlyMemory<byte> ciphertext, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        using IMemoryOwner<byte> zeroIv = pool.Rent(AesBlockLength);
        zeroIv.Memory.Span[..AesBlockLength].Clear();

        (DecryptedContent result, CryptoEvent? cipherEvent) = await DecryptCbc(
            ciphertext, key, zeroIv.Memory[..AesBlockLength], CryptoTags.AesCbcHmacDecryptedContent, pool,
            cancellationToken: cancellationToken).ConfigureAwait(false);
        EmitIfPresent(cipherEvent);

        return result;
    }


    /// <summary>
    /// Protocol two's <c>decrypt</c> (CTAP 2.3 §6.5.7, line 6250-6261): splits <paramref name="ciphertext"/>
    /// into its leading 16-byte IV and the remaining AES-256-CBC ciphertext, discards <paramref name="key"/>'s
    /// leading 32 bytes to select the AES-key half.
    /// </summary>
    /// <exception cref="ArgumentException">Thrown when <paramref name="ciphertext"/> is shorter than 16 bytes.</exception>
    private async ValueTask<DecryptedContent> DecryptProtocolTwoAsync(ReadOnlyMemory<byte> key, ReadOnlyMemory<byte> ciphertext, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        if(ciphertext.Length < AesBlockLength)
        {
            throw new ArgumentException(
                $"Protocol two ciphertext must be at least {AesBlockLength} bytes (the prefixed IV) but was {ciphertext.Length}.",
                nameof(ciphertext));
        }

        ReadOnlyMemory<byte> aesKey = key[ProtocolTwoHmacKeyLength..];
        ReadOnlyMemory<byte> iv = ciphertext[..AesBlockLength];
        ReadOnlyMemory<byte> innerCiphertext = ciphertext[AesBlockLength..];

        (DecryptedContent result, CryptoEvent? cipherEvent) = await DecryptCbc(
            innerCiphertext, aesKey, iv, CryptoTags.AesCbcHmacDecryptedContent, pool,
            cancellationToken: cancellationToken).ConfigureAwait(false);
        EmitIfPresent(cipherEvent);

        return result;
    }


    /// <summary>Throws when <see cref="Id"/> is not a recognized CTAP PIN/UV auth protocol id.</summary>
    private void EnsureSupportedId()
    {
        if(Id is not (CtapPinUvAuthProtocolId.One or CtapPinUvAuthProtocolId.Two))
        {
            throw new NotSupportedException($"Unsupported CTAP PIN/UV auth protocol id '{Id}'.");
        }
    }


    /// <summary>
    /// Forwards a directly-invoked delegate's <see cref="CryptoEvent"/> to
    /// <see cref="CryptographicKeyEvents.DefaultSink"/>, mirroring how every call site that resolves
    /// and invokes a delegate directly (rather than through a <see cref="CryptographicKeyEvents"/>
    /// choke point) publishes to the same observable stream.
    /// </summary>
    private static void EmitIfPresent(CryptoEvent? cryptoEvent)
    {
        if(cryptoEvent is not null)
        {
            CryptographicKeyEvents.DefaultSink(cryptoEvent);
        }
    }
}
