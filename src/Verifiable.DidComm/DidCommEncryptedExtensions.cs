using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;
using Verifiable.Core;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Resolvers;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Aead;
using Verifiable.Cryptography.Context;
using Verifiable.Foundation;
using Verifiable.JCose;

namespace Verifiable.DidComm;

/// <summary>
/// Pack and unpack for DIDComm encrypted messages — a multi-recipient JWE over the plaintext JWM, per
/// <see href="https://identity.foundation/didcomm-messaging/spec/v2.1/#didcomm-encrypted-messages">DIDComm Messaging v2.1 §DIDComm Encrypted Messages</see>.
/// </summary>
/// <remarks>
/// <para>
/// This class covers both DIDComm encryption modes. <em>Anoncrypt</em> — Anonymous Sender Encryption —
/// uses ECDH-ES key wrapping (<c>ECDH-ES+A*KW</c>) and provides confidentiality and integrity without
/// authenticating the sender to the recipients (DIDComm v2.1 §ECDH-ES key wrapping and common protected
/// headers). <em>Authcrypt</em> — Authenticated Sender Encryption — uses ECDH-1PU key wrapping
/// (<c>ECDH-1PU+A*KW</c>) over the AES_CBC_HMAC_SHA2 content family and authenticates the sender to the
/// recipients by binding the sender's static key into the per-recipient key derivation (DIDComm v2.1
/// §ECDH-1PU key wrapping and common protected headers). One Content Encryption Key encrypts the
/// plaintext once; the CEK is wrapped once per recipient under a key derived from that recipient's ECDH
/// agreement against a single shared ephemeral key carried in the protected header. The orchestration of
/// the JWE itself lives in <see cref="GeneralJweEncryptionExtensions"/> and
/// <see cref="GeneralJweDecryptionExtensions"/>; this class applies the DIDComm profile around it —
/// which keys, which common protected headers, and the addressing-consistency checks.
/// </para>
/// <para>
/// <strong>Authcrypt addressing consistency.</strong> Authcrypt binds the plaintext sender to the
/// encryption-layer sender: the producer requires the plaintext <c>from</c> and refuses to emit a
/// message whose <c>skid</c> DID disagrees with it, and the consumer enforces the same MUST after
/// decryption — "The from attribute in the plaintext message MUST match the skid attribute in the
/// encryption layer." (DIDComm v2.1 §Message Layer Addressing Consistency). The <c>skid</c> identifies
/// the sender key; <c>apu</c> carries <c>base64url(skid)</c>; and a consumer MUST be able to recover the
/// sender <c>kid</c> from <c>apu</c> when <c>skid</c> is absent (DIDComm v2.1 §ECDH-1PU key wrapping).
/// The sender's public key is resolved from that DID's <c>keyAgreement</c> relationship via the app-side
/// <see cref="DidResolver"/> seam, never from attacker-controlled envelope material.
/// </para>
/// <para>
/// <strong>Common protected headers (anoncrypt).</strong> Per the spec the protected JWE section MUST
/// carry common <c>epk</c>, <c>apv</c>, and <c>alg</c> headers for all recipients, and the envelope
/// media type <c>application/didcomm-encrypted+json</c> SHOULD be set in the <c>typ</c> property
/// (DIDComm v2.1 §DIDComm Encrypted Messages, §ECDH-ES key wrapping and common protected headers).
/// <c>epk</c>, <c>enc</c>, and <c>alg</c> are written by the JWE layer; this class adds <c>apv</c>
/// (the SHA-256 over the sorted recipient <c>kid</c> list) and <c>typ</c>. The spec is explicit that
/// <c>apu</c> is NOT present for ECDH-ES (anoncrypt has no sender identifier).
/// </para>
/// <para>
/// <strong>Unpack is fail-closed.</strong> Every failure path returns a
/// <see cref="DidCommEncryptedUnpackResult"/> whose <see cref="DidCommEncryptedUnpackResult.IsUnpacked"/>
/// is <see langword="false"/> and carries no plaintext; a successful result can only be minted by this
/// library's unpack path.
/// </para>
/// </remarks>
public static class DidCommEncryptedExtensions
{
    /// <summary>
    /// Anoncrypts <paramref name="message"/> for <paramref name="recipients"/> using explicit delegates
    /// for every cryptographic and serialization step.
    /// </summary>
    /// <param name="message">The plaintext message to encrypt. Validated structurally before encryption.</param>
    /// <param name="recipients">The recipients, each with a <c>keyAgreement</c> public key and its <c>kid</c>. At least one is required.</param>
    /// <param name="keyManagementAlgorithm">The <c>alg</c> — an ECDH-ES key-wrapping algorithm, e.g. <see cref="WellKnownJweAlgorithms.EcdhEsA256Kw"/>.</param>
    /// <param name="contentEncryptionAlgorithm">The <c>enc</c>, e.g. <c>A256CBC-HS512</c> or <c>A256GCM</c>; any valid content encryption algorithm MAY be used for anoncrypt.</param>
    /// <param name="ephemeralKey">The shared ephemeral key pair, which MUST be of the same type and curve as all recipient keys (DIDComm v2.1 §ECDH-ES key wrapping: the <c>epk</c>).</param>
    /// <param name="plaintextSerializer">Serializer producing the <c>application/didcomm-plain+json</c> payload.</param>
    /// <param name="headerSerializer">Serializer producing the protected header's UTF-8 JSON bytes.</param>
    /// <param name="base64UrlEncoder">Base64Url encoder for the agreement info and the JWE envelope members.</param>
    /// <param name="tagToCrvConverter">Delegate mapping the ephemeral key's tag to a JWK curve name.</param>
    /// <param name="generateContentEncryptionKey">Entropy delegate producing the random CEK bytes.</param>
    /// <param name="agreementDelegate">The multi-recipient ECDH-ES agreement delegate.</param>
    /// <param name="keyDerivationDelegate">The Concat KDF delegate (no tag commitment for ECDH-ES).</param>
    /// <param name="keyWrapDelegate">The RFC 3394 key wrap delegate.</param>
    /// <param name="aeadEncryptDelegate">The content encryption delegate matching <paramref name="contentEncryptionAlgorithm"/>.</param>
    /// <param name="memoryPool">Memory pool for transient buffers and the returned artifact.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The encrypted message wire artifact. The caller owns and disposes it.</returns>
    /// <exception cref="FormatException">Thrown when <paramref name="message"/> violates a §Message Headers structural requirement.</exception>
    public static async ValueTask<DidCommEncryptedMessage> PackAnoncryptAsync(
        this DidCommMessage message,
        IReadOnlyList<GeneralJweRecipientInput> recipients,
        string keyManagementAlgorithm,
        string contentEncryptionAlgorithm,
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> ephemeralKey,
        DidCommMessageSerializer plaintextSerializer,
        JwtHeaderSerializer headerSerializer,
        EncodeDelegate base64UrlEncoder,
        TagToEpkCrvDelegate tagToCrvConverter,
        GenerateNonceDelegate generateContentEncryptionKey,
        MultiRecipientKeyAgreementEncryptDelegate agreementDelegate,
        KeyDerivationDelegate keyDerivationDelegate,
        KeyWrapDelegate keyWrapDelegate,
        AeadEncryptDelegate aeadEncryptDelegate,
        MemoryPool<byte> memoryPool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(message);
        ArgumentNullException.ThrowIfNull(recipients);
        ArgumentException.ThrowIfNullOrWhiteSpace(keyManagementAlgorithm);
        ArgumentException.ThrowIfNullOrWhiteSpace(contentEncryptionAlgorithm);
        ArgumentNullException.ThrowIfNull(ephemeralKey);
        ArgumentNullException.ThrowIfNull(plaintextSerializer);
        ArgumentNullException.ThrowIfNull(headerSerializer);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(tagToCrvConverter);
        ArgumentNullException.ThrowIfNull(generateContentEncryptionKey);
        ArgumentNullException.ThrowIfNull(agreementDelegate);
        ArgumentNullException.ThrowIfNull(keyDerivationDelegate);
        ArgumentNullException.ThrowIfNull(keyWrapDelegate);
        ArgumentNullException.ThrowIfNull(aeadEncryptDelegate);
        ArgumentNullException.ThrowIfNull(memoryPool);

        if(recipients.Count == 0)
        {
            throw new ArgumentException("At least one recipient is required to anoncrypt a message.", nameof(recipients));
        }

        //Validate the §Message Headers structure and produce the application/didcomm-plain+json bytes
        //the JWE encrypts verbatim. For anoncrypt `from` is OPTIONAL (DIDComm v2.1 §Message Headers);
        //PackPlaintext validates its shape when present.
        using DidCommPlaintextMessage plaintext = message.PackPlaintext(plaintextSerializer, memoryPool);

        return await EncryptAndSerializeAnoncryptAsync(
            plaintext.AsReadOnlyMemory(),
            recipients,
            keyManagementAlgorithm,
            contentEncryptionAlgorithm,
            ephemeralKey,
            headerSerializer,
            base64UrlEncoder,
            tagToCrvConverter,
            generateContentEncryptionKey,
            agreementDelegate,
            keyDerivationDelegate,
            keyWrapDelegate,
            aeadEncryptDelegate,
            memoryPool,
            cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Anoncrypts <paramref name="message"/>, resolving the cryptographic functions from the
    /// <see cref="KeyAgreementFunctionRegistry{TAlgorithm, TPurpose}"/> using the ephemeral key's
    /// <see cref="SensitiveData.Tag"/>. The delegate-taking overload above does the work after resolution.
    /// </summary>
    /// <remarks>
    /// The registry maps a key-agreement key to AES-GCM content encryption, so this overload supports the
    /// AES-GCM content family and <c>ECDH-ES+A256KW</c> wrapping. For the AES_CBC_HMAC_SHA2 family (the C.3
    /// <c>A256CBC-HS512</c> vectors), call the delegate-taking overload with an explicit
    /// <see cref="AeadEncryptDelegate"/>. This mirrors <c>JweMessageExtensions</c>'s registry overload,
    /// whose AEAD is likewise resolved from the key tag.
    /// </remarks>
    /// <inheritdoc cref="PackAnoncryptAsync(DidCommMessage, IReadOnlyList{GeneralJweRecipientInput}, string, string, PublicPrivateKeyMaterial{PublicKeyMemory, PrivateKeyMemory}, DidCommMessageSerializer, JwtHeaderSerializer, EncodeDelegate, TagToEpkCrvDelegate, GenerateNonceDelegate, MultiRecipientKeyAgreementEncryptDelegate, KeyDerivationDelegate, KeyWrapDelegate, AeadEncryptDelegate, MemoryPool{byte}, CancellationToken)"/>
    /// <exception cref="NotSupportedException">Thrown when <paramref name="contentEncryptionAlgorithm"/> is in neither the AES-GCM nor the XChaCha20-Poly1305 (XC20P) family.</exception>
    public static ValueTask<DidCommEncryptedMessage> PackAnoncryptAsync(
        this DidCommMessage message,
        IReadOnlyList<GeneralJweRecipientInput> recipients,
        string keyManagementAlgorithm,
        string contentEncryptionAlgorithm,
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> ephemeralKey,
        DidCommMessageSerializer plaintextSerializer,
        JwtHeaderSerializer headerSerializer,
        EncodeDelegate base64UrlEncoder,
        TagToEpkCrvDelegate tagToCrvConverter,
        GenerateNonceDelegate generateContentEncryptionKey,
        MemoryPool<byte> memoryPool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(ephemeralKey);
        ArgumentException.ThrowIfNullOrWhiteSpace(contentEncryptionAlgorithm);

        if(JweContentEncryption.FromWellKnownName(contentEncryptionAlgorithm)
            is not { Family: JweContentEncryptionFamily.AesGcm or JweContentEncryptionFamily.XChaCha20Poly1305 })
        {
            throw new NotSupportedException(
                $"The registry-resolving anoncrypt pack overload resolves the content AEAD from the key-agreement " +
                $"registry by the content algorithm. It supports the AES-GCM and XChaCha20-Poly1305 (XC20P) families " +
                $"anoncrypt uses; content encryption '{contentEncryptionAlgorithm}' is in neither. Use the delegate-taking " +
                $"overload with an explicit AeadEncryptDelegate (for example for the AES_CBC_HMAC_SHA2 family).");
        }

        CryptoAlgorithm curve = ephemeralKey.PublicKey.Tag.Get<CryptoAlgorithm>();
        Purpose purpose = ephemeralKey.PublicKey.Tag.Get<Purpose>();

        MultiRecipientKeyAgreementEncryptDelegate agreementDelegate =
            KeyAgreementFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveMultiRecipientAgreementEncrypt(curve, purpose);
        KeyDerivationDelegate keyDerivationDelegate =
            KeyAgreementFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveKeyDerivation(curve, purpose);
        KeyWrapDelegate keyWrapDelegate =
            KeyAgreementFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveKeyWrap(CryptoAlgorithm.Aes256, Purpose.Encryption);
        AeadEncryptDelegate aeadEncryptDelegate =
            KeyAgreementFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveAeadEncrypt(curve, purpose, qualifier: contentEncryptionAlgorithm);

        return message.PackAnoncryptAsync(
            recipients,
            keyManagementAlgorithm,
            contentEncryptionAlgorithm,
            ephemeralKey,
            plaintextSerializer,
            headerSerializer,
            base64UrlEncoder,
            tagToCrvConverter,
            generateContentEncryptionKey,
            agreementDelegate,
            keyDerivationDelegate,
            keyWrapDelegate,
            aeadEncryptDelegate,
            memoryPool,
            cancellationToken);
    }


    /// <summary>
    /// Authcrypts <paramref name="message"/> for <paramref name="recipients"/> using explicit delegates
    /// for every cryptographic and serialization step. The sender is authenticated to the recipients via
    /// ECDH-1PU key wrapping over the AES_CBC_HMAC_SHA2 content family.
    /// </summary>
    /// <remarks>
    /// The common protected header carries <c>apv</c>, <c>skid</c> (the sender key id), <c>apu</c>
    /// (<c>base64url</c> of the <c>skid</c> value), and the encrypted media <c>typ</c>, in addition to the
    /// <c>epk</c>, <c>enc</c>, and <c>alg</c> the JWE layer writes (DIDComm v2.1 §ECDH-1PU key wrapping
    /// and common protected headers). The plaintext <c>from</c> MUST be present and its DID MUST equal
    /// <paramref name="senderKeyId"/>'s DID; the producer refuses to emit an inconsistent message
    /// (DIDComm v2.1 §Message Layer Addressing Consistency). The 1PU draft mandates the AES_CBC_HMAC_SHA2
    /// content family, so <see cref="GeneralJweEncryptionExtensions.EncryptAuthcryptAsync"/> rejects any
    /// other <paramref name="contentEncryptionAlgorithm"/>.
    /// </remarks>
    /// <param name="message">The plaintext message to encrypt. Validated structurally before encryption; MUST carry <c>from</c>.</param>
    /// <param name="recipients">The recipients, each with a <c>keyAgreement</c> public key and its <c>kid</c>. At least one is required.</param>
    /// <param name="senderKeyId">The sender's <c>skid</c> — a DID URL into the sender's <c>keyAgreement</c> whose DID MUST equal the message <c>from</c>.</param>
    /// <param name="senderStaticPrivateKey">The sender's static <c>keyAgreement</c> private key for the authenticating agreement (Zs).</param>
    /// <param name="keyManagementAlgorithm">The <c>alg</c> — an ECDH-1PU key-wrapping algorithm, e.g. <see cref="WellKnownJweAlgorithms.Ecdh1PuA256Kw"/>.</param>
    /// <param name="contentEncryptionAlgorithm">The <c>enc</c> — MUST be in the AES_CBC_HMAC_SHA2 family, e.g. <c>A256CBC-HS512</c> (1PU §2.1).</param>
    /// <param name="ephemeralKey">The shared ephemeral key pair, which MUST be of the same type and curve as all recipient keys and the sender static key (DIDComm v2.1 §ECDH-1PU key wrapping: the <c>epk</c>).</param>
    /// <param name="plaintextSerializer">Serializer producing the <c>application/didcomm-plain+json</c> payload.</param>
    /// <param name="headerSerializer">Serializer producing the protected header's UTF-8 JSON bytes.</param>
    /// <param name="base64UrlEncoder">Base64Url encoder for the agreement info, the <c>apu</c>, and the JWE envelope members.</param>
    /// <param name="tagToCrvConverter">Delegate mapping the ephemeral key's tag to a JWK curve name.</param>
    /// <param name="generateContentEncryptionKey">Entropy delegate producing the random CEK bytes.</param>
    /// <param name="agreementDelegate">The multi-recipient ECDH-1PU agreement delegate.</param>
    /// <param name="keyDerivationDelegate">The tag-committed Concat KDF delegate.</param>
    /// <param name="keyWrapDelegate">The RFC 3394 key wrap delegate.</param>
    /// <param name="aeadEncryptDelegate">The AES_CBC_HMAC_SHA2 content encryption delegate.</param>
    /// <param name="memoryPool">Memory pool for transient buffers and the returned artifact.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The encrypted message wire artifact. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="message"/> lacks <c>from</c>, when <paramref name="senderKeyId"/>'s DID disagrees with it, or when <paramref name="contentEncryptionAlgorithm"/> is not AES_CBC_HMAC_SHA2.</exception>
    /// <exception cref="FormatException">Thrown when <paramref name="message"/> violates a §Message Headers structural requirement.</exception>
    public static async ValueTask<DidCommEncryptedMessage> PackAuthcryptAsync(
        this DidCommMessage message,
        IReadOnlyList<GeneralJweRecipientInput> recipients,
        string senderKeyId,
        PrivateKeyMemory senderStaticPrivateKey,
        string keyManagementAlgorithm,
        string contentEncryptionAlgorithm,
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> ephemeralKey,
        DidCommMessageSerializer plaintextSerializer,
        JwtHeaderSerializer headerSerializer,
        EncodeDelegate base64UrlEncoder,
        TagToEpkCrvDelegate tagToCrvConverter,
        GenerateNonceDelegate generateContentEncryptionKey,
        MultiRecipientAuthenticatedKeyAgreementEncryptDelegate agreementDelegate,
        AuthenticatedKeyDerivationDelegate keyDerivationDelegate,
        KeyWrapDelegate keyWrapDelegate,
        AeadEncryptDelegate aeadEncryptDelegate,
        MemoryPool<byte> memoryPool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(message);
        ArgumentNullException.ThrowIfNull(recipients);
        ArgumentException.ThrowIfNullOrWhiteSpace(senderKeyId);
        ArgumentNullException.ThrowIfNull(senderStaticPrivateKey);
        ArgumentException.ThrowIfNullOrWhiteSpace(keyManagementAlgorithm);
        ArgumentException.ThrowIfNullOrWhiteSpace(contentEncryptionAlgorithm);
        ArgumentNullException.ThrowIfNull(ephemeralKey);
        ArgumentNullException.ThrowIfNull(plaintextSerializer);
        ArgumentNullException.ThrowIfNull(headerSerializer);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(tagToCrvConverter);
        ArgumentNullException.ThrowIfNull(generateContentEncryptionKey);
        ArgumentNullException.ThrowIfNull(agreementDelegate);
        ArgumentNullException.ThrowIfNull(keyDerivationDelegate);
        ArgumentNullException.ThrowIfNull(keyWrapDelegate);
        ArgumentNullException.ThrowIfNull(aeadEncryptDelegate);
        ArgumentNullException.ThrowIfNull(memoryPool);

        if(recipients.Count == 0)
        {
            throw new ArgumentException("At least one recipient is required to authcrypt a message.", nameof(recipients));
        }

        //Addressing-consistency at the producer: authcrypt authenticates the sender, so the plaintext
        //`from` MUST be present and MUST match the skid's DID (DIDComm v2.1 §Message Layer Addressing
        //Consistency). Enforcing it here keeps the sender from emitting a message every conformant
        //recipient would reject after decryption.
        if(string.IsNullOrEmpty(message.From))
        {
            throw new ArgumentException(
                "An authcrypt message MUST carry a 'from' header matching the skid (DIDComm v2.1 §Message Layer Addressing Consistency).",
                nameof(message));
        }

        if(!DidUrl.TryParse(senderKeyId, out DidUrl? senderKeyIdUrl) || senderKeyIdUrl.BaseDid is not string senderKeyIdDid)
        {
            throw new ArgumentException("The senderKeyId (skid) MUST be a DID URL carrying a base DID.", nameof(senderKeyId));
        }

        if(!string.Equals(senderKeyIdDid, BaseDidOf(message.From), StringComparison.Ordinal))
        {
            throw new ArgumentException(
                "The skid's DID MUST equal the message 'from' (DIDComm v2.1 §Message Layer Addressing Consistency).",
                nameof(senderKeyId));
        }

        //Validate the §Message Headers structure and produce the application/didcomm-plain+json bytes the
        //JWE encrypts verbatim.
        using DidCommPlaintextMessage plaintext = message.PackPlaintext(plaintextSerializer, memoryPool);

        return await EncryptAndSerializeAuthcryptAsync(
            plaintext.AsReadOnlyMemory(),
            recipients,
            senderKeyId,
            senderStaticPrivateKey,
            keyManagementAlgorithm,
            contentEncryptionAlgorithm,
            ephemeralKey,
            headerSerializer,
            base64UrlEncoder,
            tagToCrvConverter,
            generateContentEncryptionKey,
            agreementDelegate,
            keyDerivationDelegate,
            keyWrapDelegate,
            aeadEncryptDelegate,
            memoryPool,
            cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Authcrypts <paramref name="message"/>, resolving the cryptographic functions from the
    /// <see cref="KeyAgreementFunctionRegistry{TAlgorithm, TPurpose}"/> using the ephemeral key's
    /// <see cref="SensitiveData.Tag"/> for the curve and the content algorithm name to disambiguate the
    /// AEAD. The delegate-taking overload above does the work after resolution.
    /// </summary>
    /// <remarks>
    /// Authcrypt mandates the AES_CBC_HMAC_SHA2 content family (1PU §2.1), which the curve-keyed registry
    /// cannot distinguish from AES-GCM by curve alone; the content algorithm is therefore passed as the
    /// AEAD resolution qualifier so the application can wire the AES_CBC_HMAC_SHA2 delegate. A GCM
    /// <paramref name="contentEncryptionAlgorithm"/> is rejected by the delegate-taking overload.
    /// </remarks>
    /// <inheritdoc cref="PackAuthcryptAsync(DidCommMessage, IReadOnlyList{GeneralJweRecipientInput}, string, PrivateKeyMemory, string, string, PublicPrivateKeyMaterial{PublicKeyMemory, PrivateKeyMemory}, DidCommMessageSerializer, JwtHeaderSerializer, EncodeDelegate, TagToEpkCrvDelegate, GenerateNonceDelegate, MultiRecipientAuthenticatedKeyAgreementEncryptDelegate, AuthenticatedKeyDerivationDelegate, KeyWrapDelegate, AeadEncryptDelegate, MemoryPool{byte}, CancellationToken)"/>
    public static ValueTask<DidCommEncryptedMessage> PackAuthcryptAsync(
        this DidCommMessage message,
        IReadOnlyList<GeneralJweRecipientInput> recipients,
        string senderKeyId,
        PrivateKeyMemory senderStaticPrivateKey,
        string keyManagementAlgorithm,
        string contentEncryptionAlgorithm,
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> ephemeralKey,
        DidCommMessageSerializer plaintextSerializer,
        JwtHeaderSerializer headerSerializer,
        EncodeDelegate base64UrlEncoder,
        TagToEpkCrvDelegate tagToCrvConverter,
        GenerateNonceDelegate generateContentEncryptionKey,
        MemoryPool<byte> memoryPool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(ephemeralKey);
        ArgumentException.ThrowIfNullOrWhiteSpace(contentEncryptionAlgorithm);

        CryptoAlgorithm curve = ephemeralKey.PublicKey.Tag.Get<CryptoAlgorithm>();
        Purpose purpose = ephemeralKey.PublicKey.Tag.Get<Purpose>();

        MultiRecipientAuthenticatedKeyAgreementEncryptDelegate agreementDelegate =
            KeyAgreementFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveMultiRecipientAuthenticatedAgreementEncrypt(curve, purpose);
        AuthenticatedKeyDerivationDelegate keyDerivationDelegate =
            KeyAgreementFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveAuthenticatedKeyDerivation(curve, purpose);
        KeyWrapDelegate keyWrapDelegate =
            KeyAgreementFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveKeyWrap(CryptoAlgorithm.Aes256, Purpose.Encryption);
        AeadEncryptDelegate aeadEncryptDelegate =
            KeyAgreementFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveAeadEncrypt(curve, purpose, qualifier: contentEncryptionAlgorithm);

        return message.PackAuthcryptAsync(
            recipients,
            senderKeyId,
            senderStaticPrivateKey,
            keyManagementAlgorithm,
            contentEncryptionAlgorithm,
            ephemeralKey,
            plaintextSerializer,
            headerSerializer,
            base64UrlEncoder,
            tagToCrvConverter,
            generateContentEncryptionKey,
            agreementDelegate,
            keyDerivationDelegate,
            keyWrapDelegate,
            aeadEncryptDelegate,
            memoryPool,
            cancellationToken);
    }


    /// <summary>
    /// Anoncrypts an already-signed <paramref name="signedMessage"/> for <paramref name="recipients"/> —
    /// the <c>anoncrypt(sign(plaintext))</c> nesting — using explicit delegates for every cryptographic step.
    /// </summary>
    /// <remarks>
    /// This is the sign-then-encrypt nesting the spec mandates: "If a message is signed and encrypted to add
    /// non-repudiation, it MUST be signed prior to encryption. This is known as a nested JWM." (DIDComm v2.1
    /// §Message Signing). Produce <paramref name="signedMessage"/> first with
    /// <see cref="DidCommSignedExtensions.PackSignedAsync(DidCommMessage, PrivateKeyMemory, string, DidCommMessageSerializer, JwtPartEncoder{JwtHeader}, JwsMessageSerializer, EncodeDelegate, MemoryPool{byte}, JoseSerializationFormat, CancellationToken)"/>;
    /// its bytes (a JWS JSON serialization) are encrypted verbatim as the JWE content. The inner signed JWM
    /// MUST carry a <c>to</c> header (DIDComm v2.1 §DIDComm Signed Messages: the surreptitious-forwarding
    /// defense), which the consumer enforces on unpack. The outer envelope is an ordinary anoncrypt JWE — a
    /// recipient discovers the nesting by inspecting the decrypted content's shape, so no nesting marker is
    /// written to the protected header.
    /// </remarks>
    /// <param name="signedMessage">The signed JWM to encrypt verbatim as the JWE content. The caller owns and disposes it.</param>
    /// <param name="recipients">The recipients, each with a <c>keyAgreement</c> public key and its <c>kid</c>. At least one is required.</param>
    /// <param name="keyManagementAlgorithm">The <c>alg</c> — an ECDH-ES key-wrapping algorithm, e.g. <see cref="WellKnownJweAlgorithms.EcdhEsA256Kw"/>.</param>
    /// <param name="contentEncryptionAlgorithm">The <c>enc</c>, e.g. <c>A256CBC-HS512</c> or <c>A256GCM</c>.</param>
    /// <param name="ephemeralKey">The shared ephemeral key pair, which MUST be of the same type and curve as all recipient keys.</param>
    /// <param name="headerSerializer">Serializer producing the protected header's UTF-8 JSON bytes.</param>
    /// <param name="base64UrlEncoder">Base64Url encoder for the agreement info and the JWE envelope members.</param>
    /// <param name="tagToCrvConverter">Delegate mapping the ephemeral key's tag to a JWK curve name.</param>
    /// <param name="generateContentEncryptionKey">Entropy delegate producing the random CEK bytes.</param>
    /// <param name="agreementDelegate">The multi-recipient ECDH-ES agreement delegate.</param>
    /// <param name="keyDerivationDelegate">The Concat KDF delegate (no tag commitment for ECDH-ES).</param>
    /// <param name="keyWrapDelegate">The RFC 3394 key wrap delegate.</param>
    /// <param name="aeadEncryptDelegate">The content encryption delegate matching <paramref name="contentEncryptionAlgorithm"/>.</param>
    /// <param name="memoryPool">Memory pool for transient buffers and the returned artifact.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The encrypted message wire artifact wrapping the signed JWM. The caller owns and disposes it.</returns>
    public static async ValueTask<DidCommEncryptedMessage> PackAnoncryptAsync(
        this DidCommSignedMessage signedMessage,
        IReadOnlyList<GeneralJweRecipientInput> recipients,
        string keyManagementAlgorithm,
        string contentEncryptionAlgorithm,
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> ephemeralKey,
        JwtHeaderSerializer headerSerializer,
        EncodeDelegate base64UrlEncoder,
        TagToEpkCrvDelegate tagToCrvConverter,
        GenerateNonceDelegate generateContentEncryptionKey,
        MultiRecipientKeyAgreementEncryptDelegate agreementDelegate,
        KeyDerivationDelegate keyDerivationDelegate,
        KeyWrapDelegate keyWrapDelegate,
        AeadEncryptDelegate aeadEncryptDelegate,
        MemoryPool<byte> memoryPool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(signedMessage);
        ArgumentNullException.ThrowIfNull(recipients);
        ArgumentException.ThrowIfNullOrWhiteSpace(keyManagementAlgorithm);
        ArgumentException.ThrowIfNullOrWhiteSpace(contentEncryptionAlgorithm);
        ArgumentNullException.ThrowIfNull(ephemeralKey);
        ArgumentNullException.ThrowIfNull(headerSerializer);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(tagToCrvConverter);
        ArgumentNullException.ThrowIfNull(generateContentEncryptionKey);
        ArgumentNullException.ThrowIfNull(agreementDelegate);
        ArgumentNullException.ThrowIfNull(keyDerivationDelegate);
        ArgumentNullException.ThrowIfNull(keyWrapDelegate);
        ArgumentNullException.ThrowIfNull(aeadEncryptDelegate);
        ArgumentNullException.ThrowIfNull(memoryPool);

        if(recipients.Count == 0)
        {
            throw new ArgumentException("At least one recipient is required to anoncrypt a message.", nameof(recipients));
        }

        return await EncryptAndSerializeAnoncryptAsync(
            signedMessage.AsReadOnlyMemory(),
            recipients,
            keyManagementAlgorithm,
            contentEncryptionAlgorithm,
            ephemeralKey,
            headerSerializer,
            base64UrlEncoder,
            tagToCrvConverter,
            generateContentEncryptionKey,
            agreementDelegate,
            keyDerivationDelegate,
            keyWrapDelegate,
            aeadEncryptDelegate,
            memoryPool,
            cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Anoncrypts an already-signed <paramref name="signedMessage"/> (the <c>anoncrypt(sign(plaintext))</c>
    /// nesting), resolving the cryptographic functions from the
    /// <see cref="KeyAgreementFunctionRegistry{TAlgorithm, TPurpose}"/> using the ephemeral key's
    /// <see cref="SensitiveData.Tag"/>. The delegate-taking overload above does the work after resolution.
    /// </summary>
    /// <inheritdoc cref="PackAnoncryptAsync(DidCommSignedMessage, IReadOnlyList{GeneralJweRecipientInput}, string, string, PublicPrivateKeyMaterial{PublicKeyMemory, PrivateKeyMemory}, JwtHeaderSerializer, EncodeDelegate, TagToEpkCrvDelegate, GenerateNonceDelegate, MultiRecipientKeyAgreementEncryptDelegate, KeyDerivationDelegate, KeyWrapDelegate, AeadEncryptDelegate, MemoryPool{byte}, CancellationToken)"/>
    /// <exception cref="NotSupportedException">Thrown when <paramref name="contentEncryptionAlgorithm"/> is in neither the AES-GCM nor the XChaCha20-Poly1305 (XC20P) family.</exception>
    public static ValueTask<DidCommEncryptedMessage> PackAnoncryptAsync(
        this DidCommSignedMessage signedMessage,
        IReadOnlyList<GeneralJweRecipientInput> recipients,
        string keyManagementAlgorithm,
        string contentEncryptionAlgorithm,
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> ephemeralKey,
        JwtHeaderSerializer headerSerializer,
        EncodeDelegate base64UrlEncoder,
        TagToEpkCrvDelegate tagToCrvConverter,
        GenerateNonceDelegate generateContentEncryptionKey,
        MemoryPool<byte> memoryPool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(ephemeralKey);
        ArgumentException.ThrowIfNullOrWhiteSpace(contentEncryptionAlgorithm);

        if(JweContentEncryption.FromWellKnownName(contentEncryptionAlgorithm)
            is not { Family: JweContentEncryptionFamily.AesGcm or JweContentEncryptionFamily.XChaCha20Poly1305 })
        {
            throw new NotSupportedException(
                $"The registry-resolving anoncrypt pack overload resolves the content AEAD from the key-agreement " +
                $"registry by the content algorithm. It supports the AES-GCM and XChaCha20-Poly1305 (XC20P) families " +
                $"anoncrypt uses; content encryption '{contentEncryptionAlgorithm}' is in neither. Use the delegate-taking " +
                $"overload with an explicit AeadEncryptDelegate (for example for the AES_CBC_HMAC_SHA2 family).");
        }

        CryptoAlgorithm curve = ephemeralKey.PublicKey.Tag.Get<CryptoAlgorithm>();
        Purpose purpose = ephemeralKey.PublicKey.Tag.Get<Purpose>();

        MultiRecipientKeyAgreementEncryptDelegate agreementDelegate =
            KeyAgreementFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveMultiRecipientAgreementEncrypt(curve, purpose);
        KeyDerivationDelegate keyDerivationDelegate =
            KeyAgreementFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveKeyDerivation(curve, purpose);
        KeyWrapDelegate keyWrapDelegate =
            KeyAgreementFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveKeyWrap(CryptoAlgorithm.Aes256, Purpose.Encryption);
        AeadEncryptDelegate aeadEncryptDelegate =
            KeyAgreementFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveAeadEncrypt(curve, purpose, qualifier: contentEncryptionAlgorithm);

        return signedMessage.PackAnoncryptAsync(
            recipients,
            keyManagementAlgorithm,
            contentEncryptionAlgorithm,
            ephemeralKey,
            headerSerializer,
            base64UrlEncoder,
            tagToCrvConverter,
            generateContentEncryptionKey,
            agreementDelegate,
            keyDerivationDelegate,
            keyWrapDelegate,
            aeadEncryptDelegate,
            memoryPool,
            cancellationToken);
    }


    /// <summary>
    /// Authcrypts an already-signed <paramref name="signedMessage"/> for <paramref name="recipients"/> —
    /// the <c>authcrypt(sign(plaintext))</c> nesting — using explicit delegates for every cryptographic step.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <strong>This combination SHOULD NOT be emitted.</strong> "Adds no useful guarantees over [anoncrypt(sign)],
    /// and is slightly more expensive, so this wrapping combination SHOULD NOT be emitted by conforming
    /// implementations." (DIDComm v2.1 §Message Types). It is provided for completeness and for the consumer
    /// path that MAY accept it. When you do emit it, the inner signer MUST be the same party as
    /// <paramref name="senderKeyId"/> (their DIDs MUST match): a recipient MUST reject a message whose inner
    /// signer differs from the authcrypt sender (DIDComm v2.1 §Message Types). Prefer
    /// <see cref="PackAnoncryptAsync(DidCommSignedMessage, IReadOnlyList{GeneralJweRecipientInput}, string, string, PublicPrivateKeyMaterial{PublicKeyMemory, PrivateKeyMemory}, JwtHeaderSerializer, EncodeDelegate, TagToEpkCrvDelegate, GenerateNonceDelegate, MultiRecipientKeyAgreementEncryptDelegate, KeyDerivationDelegate, KeyWrapDelegate, AeadEncryptDelegate, MemoryPool{byte}, CancellationToken)"/>.
    /// </para>
    /// <para>
    /// Produce <paramref name="signedMessage"/> first (sign-before-encrypt, DIDComm v2.1 §Message Signing);
    /// its bytes are encrypted verbatim. The inner signed JWM MUST carry a <c>to</c> header, enforced by the
    /// consumer. The producer-side <c>from</c>↔<c>skid</c> and signer↔sender bindings are enforced by the
    /// consumer on unpack (they live inside the signed payload this overload does not parse).
    /// </para>
    /// </remarks>
    /// <param name="signedMessage">The signed JWM to encrypt verbatim as the JWE content. The caller owns and disposes it.</param>
    /// <param name="recipients">The recipients, each with a <c>keyAgreement</c> public key and its <c>kid</c>. At least one is required.</param>
    /// <param name="senderKeyId">The sender's <c>skid</c> — a DID URL into the sender's <c>keyAgreement</c> whose DID MUST equal the inner signed message's <c>from</c> and signer DID.</param>
    /// <param name="senderStaticPrivateKey">The sender's static <c>keyAgreement</c> private key for the authenticating agreement (Zs).</param>
    /// <param name="keyManagementAlgorithm">The <c>alg</c> — an ECDH-1PU key-wrapping algorithm, e.g. <see cref="WellKnownJweAlgorithms.Ecdh1PuA256Kw"/>.</param>
    /// <param name="contentEncryptionAlgorithm">The <c>enc</c> — MUST be in the AES_CBC_HMAC_SHA2 family, e.g. <c>A256CBC-HS512</c> (1PU §2.1).</param>
    /// <param name="ephemeralKey">The shared ephemeral key pair, which MUST be of the same type and curve as all recipient keys and the sender static key.</param>
    /// <param name="headerSerializer">Serializer producing the protected header's UTF-8 JSON bytes.</param>
    /// <param name="base64UrlEncoder">Base64Url encoder for the agreement info, the <c>apu</c>, and the JWE envelope members.</param>
    /// <param name="tagToCrvConverter">Delegate mapping the ephemeral key's tag to a JWK curve name.</param>
    /// <param name="generateContentEncryptionKey">Entropy delegate producing the random CEK bytes.</param>
    /// <param name="agreementDelegate">The multi-recipient ECDH-1PU agreement delegate.</param>
    /// <param name="keyDerivationDelegate">The tag-committed Concat KDF delegate.</param>
    /// <param name="keyWrapDelegate">The RFC 3394 key wrap delegate.</param>
    /// <param name="aeadEncryptDelegate">The AES_CBC_HMAC_SHA2 content encryption delegate.</param>
    /// <param name="memoryPool">Memory pool for transient buffers and the returned artifact.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The encrypted message wire artifact wrapping the signed JWM. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="senderKeyId"/> is not a DID URL carrying a base DID, or when <paramref name="contentEncryptionAlgorithm"/> is not AES_CBC_HMAC_SHA2.</exception>
    public static async ValueTask<DidCommEncryptedMessage> PackAuthcryptAsync(
        this DidCommSignedMessage signedMessage,
        IReadOnlyList<GeneralJweRecipientInput> recipients,
        string senderKeyId,
        PrivateKeyMemory senderStaticPrivateKey,
        string keyManagementAlgorithm,
        string contentEncryptionAlgorithm,
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> ephemeralKey,
        JwtHeaderSerializer headerSerializer,
        EncodeDelegate base64UrlEncoder,
        TagToEpkCrvDelegate tagToCrvConverter,
        GenerateNonceDelegate generateContentEncryptionKey,
        MultiRecipientAuthenticatedKeyAgreementEncryptDelegate agreementDelegate,
        AuthenticatedKeyDerivationDelegate keyDerivationDelegate,
        KeyWrapDelegate keyWrapDelegate,
        AeadEncryptDelegate aeadEncryptDelegate,
        MemoryPool<byte> memoryPool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(signedMessage);
        ArgumentNullException.ThrowIfNull(recipients);
        ArgumentException.ThrowIfNullOrWhiteSpace(senderKeyId);
        ArgumentNullException.ThrowIfNull(senderStaticPrivateKey);
        ArgumentException.ThrowIfNullOrWhiteSpace(keyManagementAlgorithm);
        ArgumentException.ThrowIfNullOrWhiteSpace(contentEncryptionAlgorithm);
        ArgumentNullException.ThrowIfNull(ephemeralKey);
        ArgumentNullException.ThrowIfNull(headerSerializer);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(tagToCrvConverter);
        ArgumentNullException.ThrowIfNull(generateContentEncryptionKey);
        ArgumentNullException.ThrowIfNull(agreementDelegate);
        ArgumentNullException.ThrowIfNull(keyDerivationDelegate);
        ArgumentNullException.ThrowIfNull(keyWrapDelegate);
        ArgumentNullException.ThrowIfNull(aeadEncryptDelegate);
        ArgumentNullException.ThrowIfNull(memoryPool);

        if(recipients.Count == 0)
        {
            throw new ArgumentException("At least one recipient is required to authcrypt a message.", nameof(recipients));
        }

        //The skid must be a DID URL carrying a base DID; the consumer binds it to the inner signed
        //message's from and signer (DIDComm v2.1 §Message Layer Addressing Consistency, §Message Types).
        if(!DidUrl.TryParse(senderKeyId, out DidUrl? senderKeyIdUrl) || senderKeyIdUrl.BaseDid is null)
        {
            throw new ArgumentException("The senderKeyId (skid) MUST be a DID URL carrying a base DID.", nameof(senderKeyId));
        }

        return await EncryptAndSerializeAuthcryptAsync(
            signedMessage.AsReadOnlyMemory(),
            recipients,
            senderKeyId,
            senderStaticPrivateKey,
            keyManagementAlgorithm,
            contentEncryptionAlgorithm,
            ephemeralKey,
            headerSerializer,
            base64UrlEncoder,
            tagToCrvConverter,
            generateContentEncryptionKey,
            agreementDelegate,
            keyDerivationDelegate,
            keyWrapDelegate,
            aeadEncryptDelegate,
            memoryPool,
            cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Authcrypts an already-signed <paramref name="signedMessage"/> (the <c>authcrypt(sign(plaintext))</c>
    /// nesting), resolving the cryptographic functions from the
    /// <see cref="KeyAgreementFunctionRegistry{TAlgorithm, TPurpose}"/> using the ephemeral key's
    /// <see cref="SensitiveData.Tag"/> and the content algorithm as the AEAD qualifier. The delegate-taking
    /// overload above does the work after resolution.
    /// </summary>
    /// <inheritdoc cref="PackAuthcryptAsync(DidCommSignedMessage, IReadOnlyList{GeneralJweRecipientInput}, string, PrivateKeyMemory, string, string, PublicPrivateKeyMaterial{PublicKeyMemory, PrivateKeyMemory}, JwtHeaderSerializer, EncodeDelegate, TagToEpkCrvDelegate, GenerateNonceDelegate, MultiRecipientAuthenticatedKeyAgreementEncryptDelegate, AuthenticatedKeyDerivationDelegate, KeyWrapDelegate, AeadEncryptDelegate, MemoryPool{byte}, CancellationToken)"/>
    public static ValueTask<DidCommEncryptedMessage> PackAuthcryptAsync(
        this DidCommSignedMessage signedMessage,
        IReadOnlyList<GeneralJweRecipientInput> recipients,
        string senderKeyId,
        PrivateKeyMemory senderStaticPrivateKey,
        string keyManagementAlgorithm,
        string contentEncryptionAlgorithm,
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> ephemeralKey,
        JwtHeaderSerializer headerSerializer,
        EncodeDelegate base64UrlEncoder,
        TagToEpkCrvDelegate tagToCrvConverter,
        GenerateNonceDelegate generateContentEncryptionKey,
        MemoryPool<byte> memoryPool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(ephemeralKey);
        ArgumentException.ThrowIfNullOrWhiteSpace(contentEncryptionAlgorithm);

        CryptoAlgorithm curve = ephemeralKey.PublicKey.Tag.Get<CryptoAlgorithm>();
        Purpose purpose = ephemeralKey.PublicKey.Tag.Get<Purpose>();

        MultiRecipientAuthenticatedKeyAgreementEncryptDelegate agreementDelegate =
            KeyAgreementFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveMultiRecipientAuthenticatedAgreementEncrypt(curve, purpose);
        AuthenticatedKeyDerivationDelegate keyDerivationDelegate =
            KeyAgreementFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveAuthenticatedKeyDerivation(curve, purpose);
        KeyWrapDelegate keyWrapDelegate =
            KeyAgreementFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveKeyWrap(CryptoAlgorithm.Aes256, Purpose.Encryption);
        AeadEncryptDelegate aeadEncryptDelegate =
            KeyAgreementFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveAeadEncrypt(curve, purpose, qualifier: contentEncryptionAlgorithm);

        return signedMessage.PackAuthcryptAsync(
            recipients,
            senderKeyId,
            senderStaticPrivateKey,
            keyManagementAlgorithm,
            contentEncryptionAlgorithm,
            ephemeralKey,
            headerSerializer,
            base64UrlEncoder,
            tagToCrvConverter,
            generateContentEncryptionKey,
            agreementDelegate,
            keyDerivationDelegate,
            keyWrapDelegate,
            aeadEncryptDelegate,
            memoryPool,
            cancellationToken);
    }


    /// <summary>
    /// Unpacks an anoncrypt (<c>ECDH-ES+A*KW</c>) DIDComm encrypted message using explicit delegates,
    /// returning the recovered plaintext on success.
    /// </summary>
    /// <remarks>
    /// The sequence is: peek the protected header for <c>alg</c>/<c>enc</c>/<c>typ</c>; reject a present
    /// <c>typ</c> that is not the encrypted media type and a non-ECDH-ES <c>alg</c>; parse the General
    /// JSON JWE (which also validates the RFC 7516 §5.2 header disjointness and parses the ephemeral key
    /// on its curve); select the recipient entry by <paramref name="recipientKeyId"/>, agree, derive,
    /// unwrap, and decrypt. When the decrypted content is itself a signed JWM (the
    /// <c>anoncrypt(sign(plaintext))</c> nesting) the inner signature is verified through
    /// <see cref="DidCommSignedExtensions.UnpackSignedAsync"/> against the signer's resolved DID document,
    /// the inner <c>to</c> header is required (DIDComm v2.1 §DIDComm Signed Messages — the
    /// surreptitious-forwarding defense), and the result's
    /// <see cref="DidCommEncryptedUnpackResult.IsSignedInner"/> is <see langword="true"/> with
    /// <see cref="DidCommEncryptedUnpackResult.SenderKeyId"/> the verified inner signer and
    /// <see cref="DidCommEncryptedUnpackResult.IsSenderAuthenticated"/> <see langword="true"/>. Otherwise
    /// the recovered <c>application/didcomm-plain+json</c> is validated and — anoncrypt not authenticating
    /// the sender — <see cref="DidCommEncryptedUnpackResult.IsSenderAuthenticated"/> is <see langword="false"/>
    /// with a <see langword="null"/> <see cref="DidCommEncryptedUnpackResult.SenderKeyId"/>.
    /// </remarks>
    /// <param name="encryptedMessage">The DIDComm encrypted message wire artifact.</param>
    /// <param name="recipientKeyId">The <c>kid</c> of the recipient entry to decrypt — the holder's own <c>keyAgreement</c> key id.</param>
    /// <param name="recipientPrivateKey">The recipient's static <c>keyAgreement</c> private key.</param>
    /// <param name="didResolver">Resolver for a nested signed message's signer DID. Used only when the decrypted content is a signed JWM.</param>
    /// <param name="exchangeContext">The per-operation exchange context threaded to nested-signature resolution.</param>
    /// <param name="plaintextParser">Parser producing the message from the decrypted plaintext bytes.</param>
    /// <param name="signedParser">Parser producing the unverified JWS message from a nested signed JWM's bytes.</param>
    /// <param name="base64UrlDecoder">Base64Url decoder for the protected header and envelope members.</param>
    /// <param name="base64UrlEncoder">Base64Url encoder, used to reconstruct a nested signed message's JWS signing input.</param>
    /// <param name="agreementDelegate">The decrypt-side ECDH-ES agreement delegate.</param>
    /// <param name="keyDerivationDelegate">The Concat KDF delegate (no tag commitment for ECDH-ES).</param>
    /// <param name="keyUnwrapDelegate">The RFC 3394 key unwrap delegate.</param>
    /// <param name="aeadDecryptDelegate">The content decryption delegate matching the message's <c>enc</c>.</param>
    /// <param name="memoryPool">Memory pool for transient buffers.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A fail-closed unpack result.</returns>
    public static async ValueTask<DidCommEncryptedUnpackResult> UnpackAnoncryptAsync(
        this DidCommEncryptedMessage encryptedMessage,
        string recipientKeyId,
        PrivateKeyMemory recipientPrivateKey,
        DidResolver didResolver,
        ExchangeContext exchangeContext,
        DidCommMessageParser plaintextParser,
        JwsMessageParser signedParser,
        DecodeDelegate base64UrlDecoder,
        EncodeDelegate base64UrlEncoder,
        KeyAgreementDecryptDelegate agreementDelegate,
        KeyDerivationDelegate keyDerivationDelegate,
        KeyUnwrapDelegate keyUnwrapDelegate,
        AeadDecryptDelegate aeadDecryptDelegate,
        MemoryPool<byte> memoryPool,
        JwtClaimsDeserializer? fromPriorPayloadDeserializer = null,
        Func<ReadOnlySpan<byte>, IReadOnlyDictionary<string, object>>? fromPriorHeaderDeserializer = null,
        DidCommEncryptedHeaderPolicy headerPolicy = DidCommEncryptedHeaderPolicy.Strict,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(encryptedMessage);
        ArgumentException.ThrowIfNullOrWhiteSpace(recipientKeyId);
        ArgumentNullException.ThrowIfNull(recipientPrivateKey);
        ArgumentNullException.ThrowIfNull(didResolver);
        ArgumentNullException.ThrowIfNull(exchangeContext);
        ArgumentNullException.ThrowIfNull(plaintextParser);
        ArgumentNullException.ThrowIfNull(signedParser);
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(agreementDelegate);
        ArgumentNullException.ThrowIfNull(keyDerivationDelegate);
        ArgumentNullException.ThrowIfNull(keyUnwrapDelegate);
        ArgumentNullException.ThrowIfNull(aeadDecryptDelegate);
        ArgumentNullException.ThrowIfNull(memoryPool);

        cancellationToken.ThrowIfCancellationRequested();

        ReadOnlySpan<byte> wire = encryptedMessage.AsReadOnlySpan();

        //Peek the integrity-protected alg/enc/typ before committing to a parse. The General JSON parser
        //takes alg+enc explicitly (it validates the wire matches), so they must be read from the wire
        //protected header first.
        if(!TryReadProtectedAlgorithms(wire, base64UrlDecoder, memoryPool, out string? algorithm, out string? encryption, out string? typ, out _, out _)
            || string.IsNullOrEmpty(algorithm)
            || string.IsNullOrEmpty(encryption))
        {
            return DidCommEncryptedUnpackResult.Failed(DidCommEncryptionMode.Anoncrypt, DidCommDecryptionError.MalformedEnvelope);
        }

        //The media type SHOULD be set in typ (DIDComm v2.1 §DIDComm Encrypted Messages). When present it
        //MUST identify a DIDComm encrypted message; its absence is permitted (SHOULD, not MUST).
        if(!string.IsNullOrEmpty(typ) && !DidCommMediaTypes.IsEncrypted(typ))
        {
            return DidCommEncryptedUnpackResult.Failed(DidCommEncryptionMode.Anoncrypt, DidCommDecryptionError.UnexpectedMediaType);
        }

        //This overload unpacks anoncrypt; an authcrypt (ECDH-1PU) or otherwise unrecognized alg is not
        //handled here.
        if(!IsAnoncryptKeyManagementAlgorithm(algorithm))
        {
            return DidCommEncryptedUnpackResult.Failed(DidCommEncryptionMode.Anoncrypt, DidCommDecryptionError.UnsupportedAlgorithm);
        }

        string generalJson = Encoding.UTF8.GetString(wire);

        AeadGeneralMessage parsed;
        try
        {
            parsed = GeneralJweParsing.ParseGeneralJson(generalJson, algorithm, encryption, base64UrlDecoder, memoryPool);
        }
        catch(Exception ex) when(ex is FormatException or ArgumentException or NotSupportedException)
        {
            //An unmapped epk `crv` makes the injected crv→tag converter throw NotSupportedException (the kty
            //gate does not constrain crv); a malformed envelope MUST fail closed, never escape the unpack.
            return DidCommEncryptedUnpackResult.Failed(DidCommEncryptionMode.Anoncrypt, DidCommDecryptionError.MalformedEnvelope);
        }

        using(parsed)
        {
            //Select the recipient by kid up front so the no-recipient case is reported precisely and any
            //exception from the crypto chain below is unambiguously a decryption failure rather than an
            //addressing miss (DIDComm v2.1 §Message Layer Addressing Consistency selects by kid).
            if(parsed.FindRecipient(recipientKeyId) is null)
            {
                return DidCommEncryptedUnpackResult.Failed(DidCommEncryptionMode.Anoncrypt, DidCommDecryptionError.NoMatchingRecipient);
            }

            //DIDComm recipient binding: the protected-header apv MUST equal SHA-256(sorted recipient kids) over
            //the wire recipients[] (DIDComm v2.1 §ECDH-ES key wrapping). The recipients array is NOT part of the
            //AEAD-protected header, so without this a tampered recipient set decrypts fine — the key derivation
            //binds the protected-header apv, not the actual recipients[]. A mismatch is a tampered or
            //non-conforming envelope, so fail closed. (Generic JWE allows any apv; this is the DIDComm profile.)
            if(!IsApvRecipientBindingValid(parsed, headerPolicy, base64UrlEncoder, memoryPool))
            {
                return DidCommEncryptedUnpackResult.Failed(DidCommEncryptionMode.Anoncrypt, DidCommDecryptionError.MalformedEnvelope);
            }

            DecryptedContent decrypted;
            try
            {
                decrypted = await parsed.DecryptAnoncryptAsync(
                    recipientKeyId,
                    recipientPrivateKey,
                    agreementDelegate,
                    keyDerivationDelegate,
                    keyUnwrapDelegate,
                    aeadDecryptDelegate,
                    memoryPool,
                    cancellationToken).ConfigureAwait(false);
            }
            catch(Exception ex) when(ex is CryptographicException or ArgumentException or FormatException)
            {
                //Fail closed: with the recipient already matched, any key-agreement, CEK-unwrap, AEAD, or
                //malformed-agreement-info failure yields no plaintext. AES key unwrap throws ArgumentException
                //for a misaligned wrapped key, and AES-GCM throws ArgumentException on a tag-length mismatch
                //(e.g. an AES_CBC_HMAC_SHA2 envelope decrypted via the registry overload's GCM AEAD); a
                //non-base64url apu/apv surfaces as FormatException. All are a decryption failure here.
                return DidCommEncryptedUnpackResult.Failed(DidCommEncryptionMode.Anoncrypt, DidCommDecryptionError.DecryptionFailed);
            }

            using(decrypted)
            {
                //When the decrypted content is itself a signed JWM, this is the anoncrypt(sign(plaintext))
                //nesting: verify the inner signature, enforce the inner `to` MUST, and surface the verified
                //signer (DIDComm v2.1 §Message Types, §DIDComm Signed Messages). A null return means the
                //content is not a signed JWM, so it is treated as a plaintext JWM below.
                DidCommEncryptedUnpackResult? nested = await TryUnpackNestedSignedAsync(
                    decrypted.AsReadOnlyMemory(),
                    DidCommEncryptionMode.Anoncrypt,
                    recipientKeyId,
                    authcryptSenderDid: null,
                    didResolver,
                    exchangeContext,
                    plaintextParser,
                    signedParser,
                    base64UrlDecoder,
                    base64UrlEncoder,
                    fromPriorPayloadDeserializer,
                    fromPriorHeaderDeserializer,
                    memoryPool,
                    cancellationToken).ConfigureAwait(false);

                if(nested is not null)
                {
                    return nested;
                }

                DidCommMessage plaintextMessage;
                try
                {
                    plaintextMessage = DidCommPlaintextExtensions.UnpackPlaintext(decrypted.AsReadOnlySpan(), plaintextParser);
                }
                catch(Exception ex) when(ex is FormatException or System.Text.Json.JsonException)
                {
                    //A structurally or wire-type-invalid plaintext (the leaf parser surfaces an
                    //integer/array/object wire-type violation as JsonException) fails closed; never throw.
                    return DidCommEncryptedUnpackResult.Failed(DidCommEncryptionMode.Anoncrypt, DidCommDecryptionError.InvalidPlaintext);
                }

                bool isRecipientAddressedInTo = IsRecipientAddressedInTo(plaintextMessage, recipientKeyId);

                //Anoncrypt does not authenticate the sender: no skid, no apu, no sender key id.
                return await BindFromPriorAsync(
                    plaintextMessage,
                    DidCommEncryptionMode.Anoncrypt,
                    senderKeyId: null,
                    isSenderAuthenticated: false,
                    isSignedInner: false,
                    isRecipientAddressedInTo,
                    didResolver,
                    exchangeContext,
                    fromPriorPayloadDeserializer,
                    fromPriorHeaderDeserializer,
                    base64UrlDecoder,
                    base64UrlEncoder,
                    memoryPool,
                    cancellationToken).ConfigureAwait(false);
            }
        }
    }


    /// <summary>
    /// Unpacks an anoncrypt DIDComm encrypted message, resolving the cryptographic functions from the
    /// <see cref="KeyAgreementFunctionRegistry{TAlgorithm, TPurpose}"/> using
    /// <paramref name="recipientPrivateKey"/>'s <see cref="SensitiveData.Tag"/>. The delegate-taking
    /// overload above does the work after resolution.
    /// </summary>
    /// <remarks>
    /// The content AEAD is resolved from the registry by the wire <c>enc</c> (peeked from the protected
    /// header), the same shape as the authcrypt registry overload, so this overload decrypts any content
    /// algorithm the registry is wired for — AES-GCM, AES_CBC_HMAC_SHA2, and XChaCha20-Poly1305 (XC20P).
    /// An <c>enc</c> the registry does not provide surfaces fail-closed as
    /// <see cref="DidCommDecryptionError.DecryptionFailed"/>; a missing or malformed protected header is
    /// <see cref="DidCommDecryptionError.MalformedEnvelope"/>.
    /// </remarks>
    /// <inheritdoc cref="UnpackAnoncryptAsync(DidCommEncryptedMessage, string, PrivateKeyMemory, DidResolver, ExchangeContext, DidCommMessageParser, JwsMessageParser, DecodeDelegate, EncodeDelegate, KeyAgreementDecryptDelegate, KeyDerivationDelegate, KeyUnwrapDelegate, AeadDecryptDelegate, MemoryPool{byte}, CancellationToken)"/>
    public static ValueTask<DidCommEncryptedUnpackResult> UnpackAnoncryptAsync(
        this DidCommEncryptedMessage encryptedMessage,
        string recipientKeyId,
        PrivateKeyMemory recipientPrivateKey,
        DidResolver didResolver,
        ExchangeContext exchangeContext,
        DidCommMessageParser plaintextParser,
        JwsMessageParser signedParser,
        DecodeDelegate base64UrlDecoder,
        EncodeDelegate base64UrlEncoder,
        MemoryPool<byte> memoryPool,
        JwtClaimsDeserializer? fromPriorPayloadDeserializer = null,
        Func<ReadOnlySpan<byte>, IReadOnlyDictionary<string, object>>? fromPriorHeaderDeserializer = null,
        DidCommEncryptedHeaderPolicy headerPolicy = DidCommEncryptedHeaderPolicy.Strict,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(encryptedMessage);
        ArgumentNullException.ThrowIfNull(recipientPrivateKey);
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(memoryPool);

        //The content AEAD is resolved by the wire enc (the registry's content matcher cannot tell the
        //content families apart by curve alone), so the enc is peeked before resolution — the same shape
        //as the authcrypt registry overload.
        ReadOnlySpan<byte> wire = encryptedMessage.AsReadOnlySpan();
        if(!TryReadProtectedAlgorithms(wire, base64UrlDecoder, memoryPool, out _, out string? encryption, out _, out _, out _)
            || string.IsNullOrEmpty(encryption))
        {
            return ValueTask.FromResult(
                DidCommEncryptedUnpackResult.Failed(DidCommEncryptionMode.Anoncrypt, DidCommDecryptionError.MalformedEnvelope));
        }

        CryptoAlgorithm curve = recipientPrivateKey.Tag.Get<CryptoAlgorithm>();
        Purpose purpose = recipientPrivateKey.Tag.Get<Purpose>();

        KeyAgreementDecryptDelegate agreementDelegate =
            KeyAgreementFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveAgreementDecrypt(curve, purpose);
        KeyDerivationDelegate keyDerivationDelegate =
            KeyAgreementFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveKeyDerivation(curve, purpose);
        KeyUnwrapDelegate keyUnwrapDelegate =
            KeyAgreementFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveKeyUnwrap(CryptoAlgorithm.Aes256, Purpose.Encryption);
        AeadDecryptDelegate aeadDecryptDelegate =
            KeyAgreementFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveAeadDecrypt(curve, purpose, qualifier: encryption);

        return encryptedMessage.UnpackAnoncryptAsync(
            recipientKeyId,
            recipientPrivateKey,
            didResolver,
            exchangeContext,
            plaintextParser,
            signedParser,
            base64UrlDecoder,
            base64UrlEncoder,
            agreementDelegate,
            keyDerivationDelegate,
            keyUnwrapDelegate,
            aeadDecryptDelegate,
            memoryPool,
            fromPriorPayloadDeserializer,
            fromPriorHeaderDeserializer,
            headerPolicy,
            cancellationToken);
    }


    /// <summary>
    /// Unpacks an authcrypt (<c>ECDH-1PU+A*KW</c>) DIDComm encrypted message using explicit delegates,
    /// returning the recovered plaintext and authenticated sender on success.
    /// </summary>
    /// <remarks>
    /// The sequence is: peek the protected header for <c>alg</c>/<c>enc</c>/<c>typ</c>/<c>skid</c>/<c>apu</c>;
    /// reject a present <c>typ</c> that is not the encrypted media type and a non-ECDH-1PU <c>alg</c>;
    /// determine the sender <c>kid</c> from <c>skid</c> or, when it is absent, by decoding <c>apu</c>
    /// (DIDComm v2.1 §ECDH-1PU key wrapping: a consumer MUST be able to recover the sender kid from
    /// <c>apu</c>); parse the General JSON JWE (which validates RFC 7516 §5.2 header disjointness and
    /// the on-curve epk check); select the recipient entry by <paramref name="recipientKeyId"/>; resolve
    /// the sender's public key from the <c>skid</c> DID's <c>keyAgreement</c> relationship via
    /// <paramref name="didResolver"/>; agree, derive (with the JWE tag committed), unwrap, and decrypt;
    /// validate the recovered <c>application/didcomm-plain+json</c>; enforce the plaintext <c>from</c> ↔
    /// <c>skid</c> addressing-consistency MUST; and surface whether the recipient is addressed in
    /// <c>to</c>. A successful decryption proves the message was produced by the holder of the
    /// <c>skid</c> private key (the 1PU tag-committed derivation), so the result's
    /// <see cref="DidCommEncryptedUnpackResult.IsSenderAuthenticated"/> is <see langword="true"/> and its
    /// <see cref="DidCommEncryptedUnpackResult.SenderKeyId"/> is the resolved <c>skid</c>. When the
    /// decrypted content is itself a signed JWM (the <c>authcrypt(sign(plaintext))</c> nesting — which
    /// conforming senders SHOULD NOT emit but a recipient MAY accept) the inner signature is verified, the
    /// inner <c>to</c> header is required, and the inner signer MUST share the sender's DID with the
    /// <c>skid</c> or the message is rejected (DIDComm v2.1 §Message Types); on success
    /// <see cref="DidCommEncryptedUnpackResult.IsSignedInner"/> is <see langword="true"/> and
    /// <see cref="DidCommEncryptedUnpackResult.SenderKeyId"/> is the verified inner signer.
    /// </remarks>
    /// <param name="encryptedMessage">The DIDComm encrypted message wire artifact.</param>
    /// <param name="recipientKeyId">The <c>kid</c> of the recipient entry to decrypt — the holder's own <c>keyAgreement</c> key id.</param>
    /// <param name="recipientPrivateKey">The recipient's static <c>keyAgreement</c> private key.</param>
    /// <param name="didResolver">Resolver for the sender (skid) DID and any nested signer DID. Reuses the app-side resolution seam.</param>
    /// <param name="exchangeContext">The per-operation exchange context threaded to resolution.</param>
    /// <param name="plaintextParser">Parser producing the message from the decrypted plaintext bytes.</param>
    /// <param name="signedParser">Parser producing the unverified JWS message from a nested signed JWM's bytes.</param>
    /// <param name="base64UrlDecoder">Base64Url decoder for the protected header, <c>apu</c>, and envelope members.</param>
    /// <param name="base64UrlEncoder">Base64Url encoder, used to reconstruct a nested signed message's JWS signing input.</param>
    /// <param name="agreementDelegate">The decrypt-side ECDH-1PU authenticated agreement delegate.</param>
    /// <param name="keyDerivationDelegate">The tag-committed Concat KDF delegate.</param>
    /// <param name="keyUnwrapDelegate">The RFC 3394 key unwrap delegate.</param>
    /// <param name="aeadDecryptDelegate">The AES_CBC_HMAC_SHA2 content decryption delegate matching the message's <c>enc</c>.</param>
    /// <param name="memoryPool">Memory pool for transient buffers.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A fail-closed unpack result.</returns>
    public static async ValueTask<DidCommEncryptedUnpackResult> UnpackAuthcryptAsync(
        this DidCommEncryptedMessage encryptedMessage,
        string recipientKeyId,
        PrivateKeyMemory recipientPrivateKey,
        DidResolver didResolver,
        ExchangeContext exchangeContext,
        DidCommMessageParser plaintextParser,
        JwsMessageParser signedParser,
        DecodeDelegate base64UrlDecoder,
        EncodeDelegate base64UrlEncoder,
        AuthenticatedKeyAgreementDecryptDelegate agreementDelegate,
        AuthenticatedKeyDerivationDelegate keyDerivationDelegate,
        KeyUnwrapDelegate keyUnwrapDelegate,
        AeadDecryptDelegate aeadDecryptDelegate,
        MemoryPool<byte> memoryPool,
        JwtClaimsDeserializer? fromPriorPayloadDeserializer = null,
        Func<ReadOnlySpan<byte>, IReadOnlyDictionary<string, object>>? fromPriorHeaderDeserializer = null,
        DidCommEncryptedHeaderPolicy headerPolicy = DidCommEncryptedHeaderPolicy.Strict,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(encryptedMessage);
        ArgumentException.ThrowIfNullOrWhiteSpace(recipientKeyId);
        ArgumentNullException.ThrowIfNull(recipientPrivateKey);
        ArgumentNullException.ThrowIfNull(didResolver);
        ArgumentNullException.ThrowIfNull(exchangeContext);
        ArgumentNullException.ThrowIfNull(plaintextParser);
        ArgumentNullException.ThrowIfNull(signedParser);
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(agreementDelegate);
        ArgumentNullException.ThrowIfNull(keyDerivationDelegate);
        ArgumentNullException.ThrowIfNull(keyUnwrapDelegate);
        ArgumentNullException.ThrowIfNull(aeadDecryptDelegate);
        ArgumentNullException.ThrowIfNull(memoryPool);

        cancellationToken.ThrowIfCancellationRequested();

        ReadOnlySpan<byte> wire = encryptedMessage.AsReadOnlySpan();

        //Peek the integrity-protected alg/enc/typ/skid/apu before committing to a parse. The General JSON
        //parser takes alg+enc explicitly (it validates the wire matches), so they must be read from the
        //wire protected header first.
        if(!TryReadProtectedAlgorithms(wire, base64UrlDecoder, memoryPool, out string? algorithm, out string? encryption, out string? typ, out string? skid, out string? apu)
            || string.IsNullOrEmpty(algorithm)
            || string.IsNullOrEmpty(encryption))
        {
            return DidCommEncryptedUnpackResult.Failed(DidCommEncryptionMode.Authcrypt, DidCommDecryptionError.MalformedEnvelope);
        }

        //The media type SHOULD be set in typ (DIDComm v2.1 §DIDComm Encrypted Messages). When present it
        //MUST identify a DIDComm encrypted message; its absence is permitted.
        if(!string.IsNullOrEmpty(typ) && !DidCommMediaTypes.IsEncrypted(typ))
        {
            return DidCommEncryptedUnpackResult.Failed(DidCommEncryptionMode.Authcrypt, DidCommDecryptionError.UnexpectedMediaType);
        }

        //This overload unpacks authcrypt; an anoncrypt (ECDH-ES) or otherwise unrecognized alg is not
        //handled here.
        if(!IsAuthcryptKeyManagementAlgorithm(algorithm))
        {
            return DidCommEncryptedUnpackResult.Failed(DidCommEncryptionMode.Authcrypt, DidCommDecryptionError.UnsupportedAlgorithm);
        }

        //Authcrypt mandates the compactly-committing AES_CBC_HMAC_SHA2 content family (1PU §2.1): the
        //committing property binds the ciphertext and tag to the protected header (recipients/skid/apv),
        //so a sender cannot be substituted by re-using the content under a different envelope. A
        //non-committing content family (AES-GCM, XChaCha20-Poly1305) MUST NOT be accepted on the authcrypt
        //consume path (DIDComm v2.1 §ECDH-1PU key wrapping); this mirrors the produce-side family gate.
        if(JweContentEncryption.FromWellKnownName(encryption) is not { Family: JweContentEncryptionFamily.AesCbcHmac })
        {
            return DidCommEncryptedUnpackResult.Failed(DidCommEncryptionMode.Authcrypt, DidCommDecryptionError.UnsupportedAlgorithm);
        }

        //apu is a MUST-present common protected header for authcrypt — it carries base64url(skid) (DIDComm
        //v2.1 §ECDH-1PU key wrapping and common protected headers). The strict (spec-compliant, default)
        //policy rejects an envelope that omits apu while still carrying skid — the sender is identifiable, but
        //the MUST header is absent — whereas the lenient interop policy falls back to that skid (below). An
        //envelope omitting BOTH skid and apu is the more fundamental "no sender identifier" case, rejected
        //under either policy as MissingSenderKeyId by TryDetermineSenderKeyId below. The KDF binds apu as
        //PartyUInfo, so a genuinely missing apu fails decryption anyway.
        if(headerPolicy == DidCommEncryptedHeaderPolicy.Strict && string.IsNullOrEmpty(apu) && !string.IsNullOrEmpty(skid))
        {
            return DidCommEncryptedUnpackResult.Failed(DidCommEncryptionMode.Authcrypt, DidCommDecryptionError.MalformedEnvelope);
        }

        //Determine the sender kid: prefer the explicit skid, otherwise recover it from apu. The 1PU draft
        //does not require skid, so authcrypt implementations MUST be able to resolve the sender kid from
        //apu when skid is absent (DIDComm v2.1 §ECDH-1PU key wrapping). apu carries base64url(skid).
        if(!TryDetermineSenderKeyId(skid, apu, base64UrlDecoder, memoryPool, out string? senderKeyId, out bool isMalformed))
        {
            return DidCommEncryptedUnpackResult.Failed(
                DidCommEncryptionMode.Authcrypt,
                isMalformed ? DidCommDecryptionError.MalformedEnvelope : DidCommDecryptionError.MissingSenderKeyId);
        }

        //The sender kid is a DID URL whose base DID names the sender; an unparseable one cannot be
        //resolved to a sender public key.
        if(!DidUrl.TryParse(senderKeyId, out DidUrl? senderKeyIdUrl) || senderKeyIdUrl.BaseDid is not string senderDid)
        {
            return DidCommEncryptedUnpackResult.Failed(DidCommEncryptionMode.Authcrypt, DidCommDecryptionError.SenderResolutionFailed);
        }

        string generalJson = Encoding.UTF8.GetString(wire);

        AeadGeneralMessage parsed;
        try
        {
            parsed = GeneralJweParsing.ParseGeneralJson(generalJson, algorithm, encryption, base64UrlDecoder, memoryPool);
        }
        catch(Exception ex) when(ex is FormatException or ArgumentException or NotSupportedException)
        {
            //An unmapped epk `crv` makes the injected crv→tag converter throw NotSupportedException (the kty
            //gate does not constrain crv); a malformed envelope MUST fail closed, never escape the unpack.
            return DidCommEncryptedUnpackResult.Failed(DidCommEncryptionMode.Authcrypt, DidCommDecryptionError.MalformedEnvelope);
        }

        using(parsed)
        {
            //Select the recipient by kid up front so the no-recipient case is reported precisely and any
            //exception from the crypto chain below is unambiguously a decryption failure.
            if(parsed.FindRecipient(recipientKeyId) is null)
            {
                return DidCommEncryptedUnpackResult.Failed(DidCommEncryptionMode.Authcrypt, DidCommDecryptionError.NoMatchingRecipient);
            }

            //DIDComm recipient binding: the protected-header apv MUST equal SHA-256(sorted recipient kids) over
            //the wire recipients[] (DIDComm v2.1 §ECDH-1PU key wrapping). The recipients array is NOT part of
            //the AEAD-protected header, so without this a tampered recipient set decrypts fine — the key
            //derivation binds the protected-header apv, not the actual recipients[]. A mismatch is a tampered
            //or non-conforming envelope, so fail closed. (Generic JWE allows any apv; this is the DIDComm profile.)
            if(!IsApvRecipientBindingValid(parsed, headerPolicy, base64UrlEncoder, memoryPool))
            {
                return DidCommEncryptedUnpackResult.Failed(DidCommEncryptionMode.Authcrypt, DidCommDecryptionError.MalformedEnvelope);
            }

            //Resolve the sender's public key from the skid DID's keyAgreement relationship before any
            //decryption — the 1PU agreement authenticates the message against this key (DIDComm v2.1:
            //"resolves the skid protected header value using [the sender's] DID document's keyAgreement").
            //Resolution failure, an unauthorized skid, or unusable key material all fail closed.
            DidResolutionResult resolution = await didResolver
                .ResolveAsync(senderDid, exchangeContext, options: null, cancellationToken)
                .ConfigureAwait(false);

            if(!resolution.IsSuccessful || resolution.Document is null)
            {
                return DidCommEncryptedUnpackResult.Failed(DidCommEncryptionMode.Authcrypt, DidCommDecryptionError.SenderResolutionFailed);
            }

            if(!TryResolveKeyAgreementKey(resolution.Document, senderKeyId, out VerificationMethod? senderMethod))
            {
                return DidCommEncryptedUnpackResult.Failed(DidCommEncryptionMode.Authcrypt, DidCommDecryptionError.SenderResolutionFailed);
            }

            //Convert the resolved verification method to key material. The sender DID document is reached
            //via the attacker-influenced skid, and a structurally malformed or unsupported keyAgreement
            //method makes the converter throw; map that to a fail-closed result rather than letting it
            //escape, honouring the contract that every unpack failure returns a result.
            (CryptoAlgorithm Algorithm, Purpose Purpose, EncodingScheme Scheme, IMemoryOwner<byte> KeyMaterial) senderKeyMaterial;
            try
            {
                senderKeyMaterial = VerificationMethodCryptoConversions.DefaultConverter(senderMethod!, memoryPool);
            }
            catch(Exception ex) when(ex is ArgumentException or FormatException or NotSupportedException or CryptographicException or IndexOutOfRangeException)
            {
                //A non-ASCII `publicKeyMultibase` makes the injected base58 decoder throw
                //IndexOutOfRangeException (SimpleBase), not FormatException; the sender-key resolution MUST
                //fail closed for any malformed key material, never escape the unpack.
                return DidCommEncryptedUnpackResult.Failed(DidCommEncryptionMode.Authcrypt, DidCommDecryptionError.SenderResolutionFailed);
            }

            //PublicKeyMemory takes ownership of the converter's key-material buffer, so disposing it via
            //this using returns the buffer to the pool exactly once — the buffer must NOT also be disposed
            //directly.
            using PublicKeyMemory senderPublicKey = new PublicKeyMemory(
                senderKeyMaterial.KeyMaterial,
                TagFor(senderKeyMaterial.Algorithm, senderKeyMaterial.Purpose, senderKeyMaterial.Scheme));

            return await DecryptAuthcryptAndBindAsync(
                parsed,
                recipientKeyId,
                recipientPrivateKey,
                senderPublicKey,
                senderKeyId,
                senderDid,
                didResolver,
                exchangeContext,
                plaintextParser,
                signedParser,
                base64UrlDecoder,
                base64UrlEncoder,
                agreementDelegate,
                keyDerivationDelegate,
                keyUnwrapDelegate,
                aeadDecryptDelegate,
                memoryPool,
                fromPriorPayloadDeserializer,
                fromPriorHeaderDeserializer,
                cancellationToken).ConfigureAwait(false);
        }
    }


    /// <summary>
    /// Unpacks an authcrypt DIDComm encrypted message, resolving the cryptographic functions from the
    /// <see cref="KeyAgreementFunctionRegistry{TAlgorithm, TPurpose}"/> using
    /// <paramref name="recipientPrivateKey"/>'s <see cref="SensitiveData.Tag"/> for the curve and the
    /// message's <c>enc</c> to disambiguate the AEAD. The delegate-taking overload above does the work
    /// after resolution.
    /// </summary>
    /// <remarks>
    /// The content AEAD is resolved with the wire <c>enc</c> as the qualifier so the application can wire
    /// the AES_CBC_HMAC_SHA2 delegate authcrypt mandates (1PU §2.1), which the curve-keyed registry
    /// cannot select by curve alone.
    /// </remarks>
    /// <inheritdoc cref="UnpackAuthcryptAsync(DidCommEncryptedMessage, string, PrivateKeyMemory, DidResolver, ExchangeContext, DidCommMessageParser, JwsMessageParser, DecodeDelegate, EncodeDelegate, AuthenticatedKeyAgreementDecryptDelegate, AuthenticatedKeyDerivationDelegate, KeyUnwrapDelegate, AeadDecryptDelegate, MemoryPool{byte}, CancellationToken)"/>
    public static ValueTask<DidCommEncryptedUnpackResult> UnpackAuthcryptAsync(
        this DidCommEncryptedMessage encryptedMessage,
        string recipientKeyId,
        PrivateKeyMemory recipientPrivateKey,
        DidResolver didResolver,
        ExchangeContext exchangeContext,
        DidCommMessageParser plaintextParser,
        JwsMessageParser signedParser,
        DecodeDelegate base64UrlDecoder,
        EncodeDelegate base64UrlEncoder,
        MemoryPool<byte> memoryPool,
        JwtClaimsDeserializer? fromPriorPayloadDeserializer = null,
        Func<ReadOnlySpan<byte>, IReadOnlyDictionary<string, object>>? fromPriorHeaderDeserializer = null,
        DidCommEncryptedHeaderPolicy headerPolicy = DidCommEncryptedHeaderPolicy.Strict,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(encryptedMessage);
        ArgumentNullException.ThrowIfNull(recipientPrivateKey);
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(memoryPool);

        //The content AEAD is resolved by the wire enc (the registry's content matcher cannot tell
        //AES_CBC_HMAC_SHA2 from AES-GCM by curve alone), so the enc must be peeked before resolution.
        ReadOnlySpan<byte> wire = encryptedMessage.AsReadOnlySpan();
        if(!TryReadProtectedAlgorithms(wire, base64UrlDecoder, memoryPool, out _, out string? encryption, out _, out _, out _)
            || string.IsNullOrEmpty(encryption))
        {
            return ValueTask.FromResult(
                DidCommEncryptedUnpackResult.Failed(DidCommEncryptionMode.Authcrypt, DidCommDecryptionError.MalformedEnvelope));
        }

        CryptoAlgorithm curve = recipientPrivateKey.Tag.Get<CryptoAlgorithm>();
        Purpose purpose = recipientPrivateKey.Tag.Get<Purpose>();

        AuthenticatedKeyAgreementDecryptDelegate agreementDelegate =
            KeyAgreementFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveAuthenticatedAgreementDecrypt(curve, purpose);
        AuthenticatedKeyDerivationDelegate keyDerivationDelegate =
            KeyAgreementFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveAuthenticatedKeyDerivation(curve, purpose);
        KeyUnwrapDelegate keyUnwrapDelegate =
            KeyAgreementFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveKeyUnwrap(CryptoAlgorithm.Aes256, Purpose.Encryption);
        AeadDecryptDelegate aeadDecryptDelegate =
            KeyAgreementFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveAeadDecrypt(curve, purpose, qualifier: encryption);

        return encryptedMessage.UnpackAuthcryptAsync(
            recipientKeyId,
            recipientPrivateKey,
            didResolver,
            exchangeContext,
            plaintextParser,
            signedParser,
            base64UrlDecoder,
            base64UrlEncoder,
            agreementDelegate,
            keyDerivationDelegate,
            keyUnwrapDelegate,
            aeadDecryptDelegate,
            memoryPool,
            fromPriorPayloadDeserializer,
            fromPriorHeaderDeserializer,
            headerPolicy,
            cancellationToken);
    }


    //Decrypts the selected authcrypt recipient with the resolved sender public key, validates the
    //recovered plaintext, and enforces the from↔skid addressing-consistency MUST. Split out so the
    //sender-key material owner and the parsed message are disposed deterministically by the caller.
    private static async ValueTask<DidCommEncryptedUnpackResult> DecryptAuthcryptAndBindAsync(
        AeadGeneralMessage parsed,
        string recipientKeyId,
        PrivateKeyMemory recipientPrivateKey,
        PublicKeyMemory senderPublicKey,
        string senderKeyId,
        string senderDid,
        DidResolver didResolver,
        ExchangeContext exchangeContext,
        DidCommMessageParser plaintextParser,
        JwsMessageParser signedParser,
        DecodeDelegate base64UrlDecoder,
        EncodeDelegate base64UrlEncoder,
        AuthenticatedKeyAgreementDecryptDelegate agreementDelegate,
        AuthenticatedKeyDerivationDelegate keyDerivationDelegate,
        KeyUnwrapDelegate keyUnwrapDelegate,
        AeadDecryptDelegate aeadDecryptDelegate,
        MemoryPool<byte> memoryPool,
        JwtClaimsDeserializer? fromPriorPayloadDeserializer,
        Func<ReadOnlySpan<byte>, IReadOnlyDictionary<string, object>>? fromPriorHeaderDeserializer,
        CancellationToken cancellationToken)
    {
        DecryptedContent decrypted;
        try
        {
            decrypted = await parsed.DecryptAuthcryptAsync(
                recipientKeyId,
                recipientPrivateKey,
                senderPublicKey,
                agreementDelegate,
                keyDerivationDelegate,
                keyUnwrapDelegate,
                aeadDecryptDelegate,
                memoryPool,
                cancellationToken).ConfigureAwait(false);
        }
        catch(Exception ex) when(ex is CryptographicException or ArgumentException or FormatException)
        {
            //Fail closed: with the recipient already matched and the sender key resolved, any
            //key-agreement, tag-committed-derivation, CEK-unwrap, AEAD, or malformed-agreement-info
            //failure yields no plaintext. A tampered JWE tag derives a wrong KEK and the RFC 3394 unwrap
            //throws here, so an insider-forgery attempt cannot produce a usable CEK (1PU §2.1).
            return DidCommEncryptedUnpackResult.Failed(DidCommEncryptionMode.Authcrypt, DidCommDecryptionError.DecryptionFailed);
        }

        using(decrypted)
        {
            //When the decrypted content is itself a signed JWM, this is the authcrypt(sign(plaintext))
            //nesting: verify the inner signature, enforce the inner `to` MUST, and — the authcrypt(sign)
            //MUST — require the inner signer to share the authcrypt sender's DID (DIDComm v2.1 §Message
            //Types: "MUST emit an error if the signer of the plaintext is different from the sender
            //identified by the authcrypt layer"). A null return means the content is a plaintext JWM,
            //handled below.
            DidCommEncryptedUnpackResult? nested = await TryUnpackNestedSignedAsync(
                decrypted.AsReadOnlyMemory(),
                DidCommEncryptionMode.Authcrypt,
                recipientKeyId,
                authcryptSenderDid: senderDid,
                didResolver,
                exchangeContext,
                plaintextParser,
                signedParser,
                base64UrlDecoder,
                base64UrlEncoder,
                fromPriorPayloadDeserializer,
                fromPriorHeaderDeserializer,
                memoryPool,
                cancellationToken).ConfigureAwait(false);

            if(nested is not null)
            {
                return nested;
            }

            DidCommMessage plaintextMessage;
            try
            {
                plaintextMessage = DidCommPlaintextExtensions.UnpackPlaintext(decrypted.AsReadOnlySpan(), plaintextParser);
            }
            catch(Exception ex) when(ex is FormatException or System.Text.Json.JsonException)
            {
                //A structurally or wire-type-invalid plaintext (the leaf parser surfaces an
                //integer/array/object wire-type violation as JsonException) fails closed; never throw.
                return DidCommEncryptedUnpackResult.Failed(DidCommEncryptionMode.Authcrypt, DidCommDecryptionError.InvalidPlaintext);
            }

            //The decryption authenticated the sender; bind the authenticated skid to the plaintext sender.
            if(string.IsNullOrEmpty(plaintextMessage.From))
            {
                return DidCommEncryptedUnpackResult.Failed(DidCommEncryptionMode.Authcrypt, DidCommDecryptionError.MissingFrom);
            }

            //Addressing-consistency MUST: the plaintext `from` must match the skid's DID (DIDComm v2.1
            //§Message Layer Addressing Consistency).
            if(!string.Equals(BaseDidOf(plaintextMessage.From), senderDid, StringComparison.Ordinal))
            {
                return DidCommEncryptedUnpackResult.Failed(DidCommEncryptionMode.Authcrypt, DidCommDecryptionError.FromSkidMismatch);
            }

            bool isRecipientAddressedInTo = IsRecipientAddressedInTo(plaintextMessage, recipientKeyId);

            //Authcrypt authenticates the sender via the 1PU tag-committed wrap: the resolved skid is the
            //authenticated sender key id.
            return await BindFromPriorAsync(
                plaintextMessage,
                DidCommEncryptionMode.Authcrypt,
                senderKeyId: senderKeyId,
                isSenderAuthenticated: true,
                isSignedInner: false,
                isRecipientAddressedInTo,
                didResolver,
                exchangeContext,
                fromPriorPayloadDeserializer,
                fromPriorHeaderDeserializer,
                base64UrlDecoder,
                base64UrlEncoder,
                memoryPool,
                cancellationToken).ConfigureAwait(false);
        }
    }


    //Encrypts the given inner payload (a plaintext JWM, or a signed JWM for the nested anoncrypt(sign)
    //combination) under ECDH-ES key wrapping and serializes the result to the named encrypted-message
    //artifact. Shared by the plaintext and nested anoncrypt pack overloads — the only difference between
    //non-nested and nested is which bytes are encrypted.
    private static async ValueTask<DidCommEncryptedMessage> EncryptAndSerializeAnoncryptAsync(
        ReadOnlyMemory<byte> innerPayload,
        IReadOnlyList<GeneralJweRecipientInput> recipients,
        string keyManagementAlgorithm,
        string contentEncryptionAlgorithm,
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> ephemeralKey,
        JwtHeaderSerializer headerSerializer,
        EncodeDelegate base64UrlEncoder,
        TagToEpkCrvDelegate tagToCrvConverter,
        GenerateNonceDelegate generateContentEncryptionKey,
        MultiRecipientKeyAgreementEncryptDelegate agreementDelegate,
        KeyDerivationDelegate keyDerivationDelegate,
        KeyWrapDelegate keyWrapDelegate,
        AeadEncryptDelegate aeadEncryptDelegate,
        MemoryPool<byte> memoryPool,
        CancellationToken cancellationToken)
    {
        IReadOnlyDictionary<string, object> protectedHeaderExtras = BuildAnoncryptProtectedHeaderExtras(
            recipients, base64UrlEncoder, memoryPool);

        using GeneralJweMessage jwe = await GeneralJweEncryptionExtensions.EncryptAnoncryptAsync(
            innerPayload,
            recipients,
            keyManagementAlgorithm,
            contentEncryptionAlgorithm,
            protectedHeaderExtras,
            ephemeralKey,
            headerSerializer,
            base64UrlEncoder,
            tagToCrvConverter,
            generateContentEncryptionKey,
            agreementDelegate,
            keyDerivationDelegate,
            keyWrapDelegate,
            aeadEncryptDelegate,
            memoryPool,
            cancellationToken).ConfigureAwait(false);

        return SerializeEncryptedMessage(jwe, base64UrlEncoder, memoryPool);
    }


    //Encrypts the given inner payload (a plaintext JWM, or a signed JWM for the nested authcrypt(sign)
    //combination) under ECDH-1PU key wrapping and serializes the result. Shared by the plaintext and
    //nested authcrypt pack overloads.
    private static async ValueTask<DidCommEncryptedMessage> EncryptAndSerializeAuthcryptAsync(
        ReadOnlyMemory<byte> innerPayload,
        IReadOnlyList<GeneralJweRecipientInput> recipients,
        string senderKeyId,
        PrivateKeyMemory senderStaticPrivateKey,
        string keyManagementAlgorithm,
        string contentEncryptionAlgorithm,
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> ephemeralKey,
        JwtHeaderSerializer headerSerializer,
        EncodeDelegate base64UrlEncoder,
        TagToEpkCrvDelegate tagToCrvConverter,
        GenerateNonceDelegate generateContentEncryptionKey,
        MultiRecipientAuthenticatedKeyAgreementEncryptDelegate agreementDelegate,
        AuthenticatedKeyDerivationDelegate keyDerivationDelegate,
        KeyWrapDelegate keyWrapDelegate,
        AeadEncryptDelegate aeadEncryptDelegate,
        MemoryPool<byte> memoryPool,
        CancellationToken cancellationToken)
    {
        IReadOnlyDictionary<string, object> protectedHeaderExtras = BuildAuthcryptProtectedHeaderExtras(
            recipients, senderKeyId, base64UrlEncoder, memoryPool);

        using GeneralJweMessage jwe = await GeneralJweEncryptionExtensions.EncryptAuthcryptAsync(
            innerPayload,
            recipients,
            keyManagementAlgorithm,
            contentEncryptionAlgorithm,
            protectedHeaderExtras,
            ephemeralKey,
            senderStaticPrivateKey,
            headerSerializer,
            base64UrlEncoder,
            tagToCrvConverter,
            generateContentEncryptionKey,
            agreementDelegate,
            keyDerivationDelegate,
            keyWrapDelegate,
            aeadEncryptDelegate,
            memoryPool,
            cancellationToken).ConfigureAwait(false);

        return SerializeEncryptedMessage(jwe, base64UrlEncoder, memoryPool);
    }


    //Verifies the DIDComm recipient binding on consume: the protected-header apv equals SHA-256(sorted
    //recipient kids) over the wire recipients[] — the same recipe the produce side stamps. The recipients
    //array is a top-level JWE member, NOT part of the AEAD-protected header, so a tampered recipient set is
    //otherwise undetected (the key derivation binds the protected-header apv, not the actual recipients[]).
    //Returns true when apv is absent (nothing to bind) or matches; false on a mismatch (DIDComm v2.1
    //§ECDH-ES / §ECDH-1PU key wrapping — the recipient binding). This is the DIDComm profile, so it lives at
    //this layer, not in the generic JWE decrypt where apv is an opaque octet string.
    private static bool IsApvRecipientBindingValid(AeadGeneralMessage parsed, DidCommEncryptedHeaderPolicy headerPolicy, EncodeDelegate base64UrlEncoder, MemoryPool<byte> memoryPool)
    {
        if(!parsed.Header.TryGetValue(WellKnownJoseHeaderNames.Apv, out object? apvValue)
            || apvValue is not string apv
            || apv.Length == 0)
        {
            //apv is a MUST-present common protected header for both ECDH-ES and ECDH-1PU (DIDComm v2.1
            //§ECDH-ES / §ECDH-1PU key wrapping). The strict (spec-compliant, default) policy rejects its
            //absence; the lenient interop policy validates apv only when present — the Concat KDF still binds
            //apv as PartyVInfo, so a genuinely tampered recipient set fails decryption regardless.
            return headerPolicy != DidCommEncryptedHeaderPolicy.Strict;
        }

        if(parsed.Recipients.Count == 0)
        {
            return false;
        }

        string[] kids = new string[parsed.Recipients.Count];
        for(int i = 0; i < parsed.Recipients.Count; ++i)
        {
            kids[i] = parsed.Recipients[i].KeyId;
        }

        string rederived = JweAgreementInfo.ComputeApvFromRecipientKeyIds(kids, base64UrlEncoder, memoryPool);

        return string.Equals(rederived, apv, StringComparison.Ordinal);
    }


    //Builds the anoncrypt common protected header parameters this layer owns: apv (the recipient
    //binding) and typ (the envelope media type). epk, enc, and alg are written by the JWE layer; apu is
    //intentionally absent for ECDH-ES (DIDComm v2.1 §ECDH-ES key wrapping and common protected headers:
    //"Note: apu will not be present when using ECDH-ES" — anoncrypt carries no sender identifier).
    private static Dictionary<string, object> BuildAnoncryptProtectedHeaderExtras(
        IReadOnlyList<GeneralJweRecipientInput> recipients,
        EncodeDelegate base64UrlEncoder,
        MemoryPool<byte> memoryPool)
    {
        string[] recipientKeyIds = new string[recipients.Count];
        for(int i = 0; i < recipients.Count; ++i)
        {
            recipientKeyIds[i] = recipients[i].KeyId;
        }

        //apv = base64url-nopad(SHA-256(sorted recipient kids joined with ".")) (DIDComm v2.1 §ECDH-ES).
        string agreementPartyVInfo = JweAgreementInfo.ComputeApvFromRecipientKeyIds(recipientKeyIds, base64UrlEncoder, memoryPool);

        return new Dictionary<string, object>(2)
        {
            [WellKnownJoseHeaderNames.Apv] = agreementPartyVInfo,
            [WellKnownJoseHeaderNames.Typ] = DidCommMediaTypes.Encrypted
        };
    }


    //Builds the authcrypt common protected header parameters this layer owns: apv (the recipient
    //binding), skid (the sender key id), apu (base64url-nopad of the skid value), and typ (the envelope
    //media type). epk, enc, and alg are written by the JWE layer. apu and skid identify the sender so the
    //recipient can resolve the sender public key; both are REQUIRED here to authenticate the sender via
    //ECDH-1PU (DIDComm v2.1 §ECDH-1PU key wrapping and common protected headers: "apu ... MUST contain
    //the skid value base64 RawURL (no padding) encoded").
    private static Dictionary<string, object> BuildAuthcryptProtectedHeaderExtras(
        IReadOnlyList<GeneralJweRecipientInput> recipients,
        string senderKeyId,
        EncodeDelegate base64UrlEncoder,
        MemoryPool<byte> memoryPool)
    {
        string[] recipientKeyIds = new string[recipients.Count];
        for(int i = 0; i < recipients.Count; ++i)
        {
            recipientKeyIds[i] = recipients[i].KeyId;
        }

        //apv = base64url-nopad(SHA-256(sorted recipient kids joined with ".")) (DIDComm v2.1 §ECDH-1PU).
        string agreementPartyVInfo = JweAgreementInfo.ComputeApvFromRecipientKeyIds(recipientKeyIds, base64UrlEncoder, memoryPool);

        //apu = base64url-nopad(UTF8(skid)) (DIDComm v2.1 §ECDH-1PU: "this is base64URL(skid value)").
        int skidByteCount = Encoding.UTF8.GetByteCount(senderKeyId);
        string agreementPartyUInfo;
        using(IMemoryOwner<byte> skidOwner = memoryPool.Rent(skidByteCount))
        {
            Encoding.UTF8.GetBytes(senderKeyId, skidOwner.Memory.Span);
            agreementPartyUInfo = base64UrlEncoder(skidOwner.Memory.Span[..skidByteCount]);
        }

        return new Dictionary<string, object>(4)
        {
            [WellKnownJoseHeaderNames.Apv] = agreementPartyVInfo,
            [WellKnownJoseHeaderNames.Skid] = senderKeyId,
            [WellKnownJoseHeaderNames.Apu] = agreementPartyUInfo,
            [WellKnownJoseHeaderNames.Typ] = DidCommMediaTypes.Encrypted
        };
    }


    //Serializes the produced JWE to its General JSON form and copies it into a pooled, named encrypted
    //message artifact. The transient JSON string is the General JSON Serialization (RFC 7516 §7.2.1).
    private static DidCommEncryptedMessage SerializeEncryptedMessage(
        GeneralJweMessage jwe,
        EncodeDelegate base64UrlEncoder,
        MemoryPool<byte> memoryPool)
    {
        string generalJson = jwe.ToGeneralJson(base64UrlEncoder);

        int byteCount = Encoding.UTF8.GetByteCount(generalJson);
        using IMemoryOwner<byte> jsonOwner = memoryPool.Rent(byteCount);
        Encoding.UTF8.GetBytes(generalJson, jsonOwner.Memory.Span);

        return DidCommEncryptedMessage.Create(jsonOwner.Memory.Span[..byteCount], BufferTags.Json, memoryPool);
    }


    //Reads alg, enc, typ, skid, and apu from the wire's base64url protected header without parsing the
    //whole JWE. skid/apu are meaningful only for authcrypt; anoncrypt callers discard them. Returns false
    //when the protected member is absent or not decodable base64url. Internal so the inbound classifier
    //(DidCommInbound) can peek alg to split anoncrypt from authcrypt on the shared encrypted media type.
    internal static bool TryReadProtectedAlgorithms(
        ReadOnlySpan<byte> wireJsonUtf8,
        DecodeDelegate base64UrlDecoder,
        MemoryPool<byte> memoryPool,
        out string? algorithm,
        out string? encryption,
        out string? typ,
        out string? senderKeyId,
        out string? agreementPartyUInfo)
    {
        algorithm = null;
        encryption = null;
        typ = null;
        senderKeyId = null;
        agreementPartyUInfo = null;

        string? protectedEncoded = JwkJsonReader.ExtractStringValue(wireJsonUtf8, "protected"u8);
        if(string.IsNullOrEmpty(protectedEncoded))
        {
            return false;
        }

        IMemoryOwner<byte> headerOwner;
        try
        {
            headerOwner = base64UrlDecoder(protectedEncoded, memoryPool);
        }
        catch(FormatException)
        {
            return false;
        }

        using(headerOwner)
        {
            ReadOnlySpan<byte> headerJson = headerOwner.Memory.Span;
            algorithm = JwkJsonReader.ExtractStringValue(headerJson, WellKnownJwkMemberNames.AlgUtf8);
            encryption = JwkJsonReader.ExtractStringValue(headerJson, WellKnownJoseHeaderNames.EncUtf8);
            typ = JwkJsonReader.ExtractStringValue(headerJson, WellKnownJoseHeaderNames.TypUtf8);
            senderKeyId = JwkJsonReader.ExtractStringValue(headerJson, WellKnownJoseHeaderNames.SkidUtf8);
            agreementPartyUInfo = JwkJsonReader.ExtractStringValue(headerJson, WellKnownJoseHeaderNames.ApuUtf8);
        }

        return true;
    }


    //An anoncrypt envelope uses an ECDH-ES key-wrapping algorithm (DIDComm v2.1 §ECDH-ES key wrapping).
    internal static bool IsAnoncryptKeyManagementAlgorithm(string algorithm) =>
        WellKnownJweAlgorithms.IsEcdhEsA256Kw(algorithm)
        || WellKnownJweAlgorithms.IsEcdhEsA192Kw(algorithm)
        || WellKnownJweAlgorithms.IsEcdhEsA128Kw(algorithm);


    //An authcrypt envelope uses an ECDH-1PU key-wrapping algorithm (DIDComm v2.1 §ECDH-1PU key wrapping).
    internal static bool IsAuthcryptKeyManagementAlgorithm(string algorithm) =>
        WellKnownJweAlgorithms.IsEcdh1PuA256Kw(algorithm)
        || WellKnownJweAlgorithms.IsEcdh1PuA192Kw(algorithm)
        || WellKnownJweAlgorithms.IsEcdh1PuA128Kw(algorithm);


    //Determines the sender kid from the protected header: the explicit skid when present, otherwise the
    //value recovered by base64url-decoding apu (DIDComm v2.1 §ECDH-1PU key wrapping: authcrypt
    //implementations MUST be able to resolve the sender kid from apu when skid is absent; apu MUST carry
    //base64url(skid)). When BOTH are present they MUST name the same key — a disagreement is rejected as a
    //malformed envelope (the spec's apu == base64url(skid) MUST enforced on consume), not silently resolved
    //against skid alone. Returns false when no usable sender identifier is present: isMalformed is set when
    //apu is present but undecodable/whitespace, or skid and apu disagree (a malformed envelope); it is
    //false when neither skid nor apu is present at all (a missing sender key id).
    private static bool TryDetermineSenderKeyId(
        string? skid,
        string? agreementPartyUInfo,
        DecodeDelegate base64UrlDecoder,
        MemoryPool<byte> memoryPool,
        [NotNullWhen(true)] out string? senderKeyId,
        out bool isMalformed)
    {
        senderKeyId = null;
        isMalformed = false;

        //Decode apu (the sender identifier carried as base64url) once, when present.
        string? agreementPartyUInfoValue = null;
        if(!string.IsNullOrEmpty(agreementPartyUInfo))
        {
            IMemoryOwner<byte> apuOwner;
            try
            {
                apuOwner = base64UrlDecoder(agreementPartyUInfo, memoryPool);
            }
            catch(FormatException)
            {
                isMalformed = true;

                return false;
            }

            using(apuOwner)
            {
                agreementPartyUInfoValue = Encoding.UTF8.GetString(apuOwner.Memory.Span);
            }

            if(string.IsNullOrWhiteSpace(agreementPartyUInfoValue))
            {
                isMalformed = true;

                return false;
            }
        }

        if(!string.IsNullOrWhiteSpace(skid))
        {
            //apu MUST contain the skid value base64url-encoded (DIDComm v2.1 §ECDH-1PU key wrapping). When
            //both are present they MUST name the same sender key; a disagreement is a malformed envelope.
            if(agreementPartyUInfoValue is not null && !string.Equals(agreementPartyUInfoValue, skid, StringComparison.Ordinal))
            {
                isMalformed = true;

                return false;
            }

            senderKeyId = skid;

            return true;
        }

        //skid absent: recover the sender kid from apu (the L653 MUST).
        if(agreementPartyUInfoValue is not null)
        {
            senderKeyId = agreementPartyUInfoValue;

            return true;
        }

        return false;
    }


    //Resolves the sender kid to a verification method authorized for the keyAgreement relationship,
    //honouring both embedded methods and references into the document's verificationMethod array. The kid
    //is an absolute DID URL by this point; relative reference ids (e.g. "#key-x25519-1") are normalized
    //against the document's own DID. Returns false — fail closed — when the kid is not present in the
    //keyAgreement relationship or its referenced method cannot be located (DIDComm v2.1: the unpacker
    //resolves the skid using the sender DID document's keyAgreement).
    private static bool TryResolveKeyAgreementKey(DidDocument document, string senderKeyId, out VerificationMethod? verificationMethod)
    {
        verificationMethod = null;

        if(document.KeyAgreement is null)
        {
            return false;
        }

        string? documentDid = document.Id?.Id;

        foreach(KeyAgreementMethod keyAgreement in document.KeyAgreement)
        {
            if(!IsSameVerificationMethodId(keyAgreement.Id, senderKeyId, documentDid))
            {
                continue;
            }

            //An embedded method is usable only for the relationship it appears in — keyAgreement here.
            if(keyAgreement.EmbeddedVerification is not null)
            {
                verificationMethod = keyAgreement.EmbeddedVerification;

                return true;
            }

            //A reference resolves against the document's verificationMethod array.
            if(document.VerificationMethod is not null)
            {
                foreach(VerificationMethod candidate in document.VerificationMethod)
                {
                    if(IsSameVerificationMethodId(candidate.Id, senderKeyId, documentDid))
                    {
                        verificationMethod = candidate;

                        return true;
                    }
                }
            }

            //The kid is authorized for keyAgreement but its verification method is not present.
            return false;
        }

        return false;
    }


    //Whether candidateId denotes the same verification method as the absolute kid, treating a leading
    //'#' as a reference relative to documentDid. Matching is exact — no suffix matching — so an entry
    //cannot be confused with a differently-scoped method that merely shares a fragment.
    private static bool IsSameVerificationMethodId(string? candidateId, string kid, string? documentDid)
    {
        if(string.IsNullOrEmpty(candidateId))
        {
            return false;
        }

        if(string.Equals(candidateId, kid, StringComparison.Ordinal))
        {
            return true;
        }

        if(candidateId.StartsWith('#') && documentDid is not null)
        {
            return string.Equals($"{documentDid}{candidateId}", kid, StringComparison.Ordinal);
        }

        return false;
    }


    //Builds the public-key tag from a verification method's resolved algorithm/purpose/encoding, mirroring
    //VerificationMethodExtensions.CreatePublicKeyFromVerificationMethod so the resolved sender key carries
    //the metadata the agreement delegate expects.
    private static Tag TagFor(CryptoAlgorithm algorithm, Purpose purpose, EncodingScheme scheme) =>
        Tag.Create(algorithm).With(purpose).With(scheme);


    //Detects whether the decrypted content is a nested signed JWM and, when so, verifies it as the
    //anoncrypt(sign(plaintext)) / authcrypt(sign(plaintext)) inner message. Returns null when the content
    //is NOT a signed JWM (the caller then treats it as a plaintext JWM); otherwise returns a terminal
    //unpack result — success when the inner signature verifies and every nested MUST holds, or a
    //fail-closed result. The inner signature is verified against the signer's resolved DID document by
    //DidCommSignedExtensions.UnpackSignedAsync, which itself enforces from↔signer-kid consistency and the
    //authentication relationship. This method adds the two nesting MUSTs: the inner signed JWM MUST carry
    //a `to` header (DIDComm v2.1 §DIDComm Signed Messages — the surreptitious-forwarding defense), and for
    //authcrypt(sign) the inner signer MUST share the authcrypt sender's DID (DIDComm v2.1 §Message Types).
    //A from_prior carried on the inner signed JWM is a non-repudiable DID Rotation (sign-then-encrypt is a
    //spec-permitted message type and a rotation MUST be encrypted): the caller's rotation deserializers are
    //threaded into the inner verify so the from_prior is VERIFIED (not force-rejected for want of
    //deserializers) and its rotation outcome surfaced, exactly as the non-nested path does (DIDComm v2.1
    //§DID Rotation).
    private static async ValueTask<DidCommEncryptedUnpackResult?> TryUnpackNestedSignedAsync(
        ReadOnlyMemory<byte> decryptedContent,
        DidCommEncryptionMode mode,
        string recipientKeyId,
        string? authcryptSenderDid,
        DidResolver didResolver,
        ExchangeContext exchangeContext,
        DidCommMessageParser plaintextParser,
        JwsMessageParser signedParser,
        DecodeDelegate base64UrlDecoder,
        EncodeDelegate base64UrlEncoder,
        JwtClaimsDeserializer? fromPriorPayloadDeserializer,
        Func<ReadOnlySpan<byte>, IReadOnlyDictionary<string, object>>? fromPriorHeaderDeserializer,
        MemoryPool<byte> memoryPool,
        CancellationToken cancellationToken)
    {
        if(!IsSignedInnerShape(decryptedContent.Span))
        {
            return null;
        }

        //Copy the decrypted signed JWM into a named artifact (Create copies synchronously, so the source
        //buffer need not outlive this call) and verify it through the signed-message path.
        using DidCommSignedMessage innerSigned = DidCommSignedMessage.Create(decryptedContent.Span, BufferTags.Json, memoryPool);

        DidCommSignedVerificationResult inner = await innerSigned.UnpackSignedAsync(
            didResolver,
            exchangeContext,
            plaintextParser,
            signedParser,
            base64UrlDecoder,
            base64UrlEncoder,
            memoryPool,
            fromPriorPayloadDeserializer,
            fromPriorHeaderDeserializer,
            cancellationToken).ConfigureAwait(false);

        if(!inner.IsVerified || inner.Message is null || string.IsNullOrEmpty(inner.SignerKid))
        {
            return DidCommEncryptedUnpackResult.Failed(mode, DidCommDecryptionError.NestedSignatureInvalid);
        }

        //The inner (signed) JWM MUST carry a `to` header when a message is both signed and encrypted
        //(DIDComm v2.1 §DIDComm Signed Messages: the surreptitious-forwarding defense).
        if(!inner.IsToHeaderPresent)
        {
            return DidCommEncryptedUnpackResult.Failed(mode, DidCommDecryptionError.NestedSignedMessageMissingTo);
        }

        //authcrypt(sign): the inner signer MUST be the same party as the authcrypt-layer sender (their
        //DIDs MUST match), else the message MUST be rejected (DIDComm v2.1 §Message Types). For
        //anoncrypt(sign) there is no authcrypt sender to bind against (authcryptSenderDid is null).
        if(authcryptSenderDid is not null
            && !string.Equals(BaseDidOf(inner.SignerKid!), authcryptSenderDid, StringComparison.Ordinal))
        {
            return DidCommEncryptedUnpackResult.Failed(mode, DidCommDecryptionError.SignerSenderMismatch);
        }

        bool isRecipientAddressedInTo = IsRecipientAddressedInTo(inner.Message!, recipientKeyId);

        //The verified inner signature authenticates the sender for both nestings; the non-repudiable
        //identity is the inner signer kid. A verified from_prior on the inner JWM is surfaced as the
        //rotation outcome so the recipient learns the prior DID (DIDComm v2.1 §DID Rotation), as on the
        //non-nested path.
        return DidCommEncryptedUnpackResult.Unpacked(
            inner.Message!,
            mode,
            senderKeyId: inner.SignerKid,
            isSenderAuthenticated: true,
            isSignedInner: true,
            isRecipientAddressedInTo,
            isRotation: inner.IsRotation,
            priorDid: inner.PriorDid,
            rotationIat: inner.RotationIat);
    }


    //Whether the decrypted content is a nested signed JWM — a JWS JSON serialization. Per RFC 7516 §9 /
    //RFC 7515 §7.2 a JWS JSON object carries a top-level `payload` and a `signatures` array (general) or a
    //top-level `signature` (flattened), while a JWE carries `ciphertext`. A DIDComm plaintext JWM carries
    //none of these top-level members, so their presence cleanly distinguishes a nested signed message from
    //a plaintext one. Members are matched at the top level only (depth 0), so a `payload`/`signature`
    //nested inside `body` or an attachment cannot trigger a false positive.
    private static bool IsSignedInnerShape(ReadOnlySpan<byte> content)
    {
        if(JwkJsonReader.ContainsKey(content, "ciphertext"u8))
        {
            return false;
        }

        bool hasPayload = JwkJsonReader.ContainsKey(content, "payload"u8);
        bool hasSignature = JwkJsonReader.ContainsKey(content, "signatures"u8)
            || JwkJsonReader.ContainsKey(content, "signature"u8);

        return hasPayload && hasSignature;
    }


    //Whether the decrypting recipient's DID appears in the plaintext `to` header. The recipient kid is a
    //DID URL whose base DID is compared against each `to` entry's base DID. Returns false when `to` is
    //absent or does not list the recipient — see DidCommEncryptedUnpackResult.IsRecipientAddressedInTo
    //for why this is advisory (DIDComm v2.1 §Message Layer Addressing Consistency vs §Message Headers).
    private static bool IsRecipientAddressedInTo(DidCommMessage message, string recipientKeyId)
    {
        if(message.To is not { Count: > 0 })
        {
            return false;
        }

        string recipientDid = BaseDidOf(recipientKeyId);
        foreach(string recipient in message.To)
        {
            if(string.Equals(BaseDidOf(recipient), recipientDid, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }


    //The base DID of a DID or DID URL, or the input unchanged when it does not parse as a DID URL.
    private static string BaseDidOf(string didOrDidUrl) =>
        DidUrl.TryParse(didOrDidUrl, out DidUrl? didUrl) && didUrl.BaseDid is string baseDid
            ? baseDid
            : didOrDidUrl;


    //Folds a verified from_prior DID Rotation into the successful unpack result. When the recovered
    //plaintext carries no from_prior, the message unpacks as a non-rotation result. When it does, the
    //rotation is verified (the spec MUST path: a rotation message MUST be encrypted, DIDComm v2.1 §DID
    //Rotation) and the prior DID is surfaced; a failed rotation rejects the whole message, fail closed —
    //including when no rotation deserializers were supplied, so a from_prior is never silently accepted.
    private static async ValueTask<DidCommEncryptedUnpackResult> BindFromPriorAsync(
        DidCommMessage plaintextMessage,
        DidCommEncryptionMode mode,
        string? senderKeyId,
        bool isSenderAuthenticated,
        bool isSignedInner,
        bool isRecipientAddressedInTo,
        DidResolver didResolver,
        ExchangeContext exchangeContext,
        JwtClaimsDeserializer? fromPriorPayloadDeserializer,
        Func<ReadOnlySpan<byte>, IReadOnlyDictionary<string, object>>? fromPriorHeaderDeserializer,
        DecodeDelegate base64UrlDecoder,
        EncodeDelegate base64UrlEncoder,
        MemoryPool<byte> memoryPool,
        CancellationToken cancellationToken)
    {
        if(string.IsNullOrEmpty(plaintextMessage.FromPrior))
        {
            return DidCommEncryptedUnpackResult.Unpacked(
                plaintextMessage, mode, senderKeyId, isSenderAuthenticated, isSignedInner, isRecipientAddressedInTo);
        }

        if(fromPriorPayloadDeserializer is null || fromPriorHeaderDeserializer is null)
        {
            return DidCommEncryptedUnpackResult.Failed(mode, DidCommDecryptionError.RotationJwtMalformed);
        }

        FromPriorVerificationOutcome rotation = await DidCommFromPriorExtensions.VerifyFromPriorAsync(
            plaintextMessage, didResolver, exchangeContext, fromPriorPayloadDeserializer, fromPriorHeaderDeserializer,
            base64UrlDecoder, base64UrlEncoder, memoryPool, cancellationToken).ConfigureAwait(false);

        if(!rotation.IsVerified)
        {
            return DidCommEncryptedUnpackResult.Failed(mode, MapRotationError(rotation.Error));
        }

        return DidCommEncryptedUnpackResult.Unpacked(
            plaintextMessage, mode, senderKeyId, isSenderAuthenticated, isSignedInner, isRecipientAddressedInTo,
            isRotation: true, priorDid: rotation.PriorDid, rotationIat: rotation.Iat);
    }


    //Maps the canonical rotation rejection reason onto the encrypted-unpack error enum.
    private static DidCommDecryptionError MapRotationError(DidCommRotationError error) => error switch
    {
        DidCommRotationError.RotationJwtMalformed => DidCommDecryptionError.RotationJwtMalformed,
        DidCommRotationError.RotationSubjectMismatch => DidCommDecryptionError.RotationSubjectMismatch,
        DidCommRotationError.RotationIssuerKidMismatch => DidCommDecryptionError.RotationIssuerKidMismatch,
        DidCommRotationError.PriorDidResolutionFailed => DidCommDecryptionError.PriorDidResolutionFailed,
        DidCommRotationError.RotationSignerNotAuthorized => DidCommDecryptionError.RotationSignerNotAuthorized,
        DidCommRotationError.RotationSignatureInvalid => DidCommDecryptionError.RotationSignatureInvalid,
        _ => DidCommDecryptionError.RotationJwtMalformed
    };
}
