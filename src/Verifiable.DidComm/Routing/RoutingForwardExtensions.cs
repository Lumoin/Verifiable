using System.Buffers;
using System.Collections.Generic;
using Verifiable.Core;
using Verifiable.Core.Model.Did;
using Verifiable.Core.OutboundFetch;
using Verifiable.Core.Resolvers;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Aead;
using Verifiable.Cryptography.Context;
using Verifiable.Foundation;
using Verifiable.JCose;

namespace Verifiable.DidComm.Routing;

/// <summary>
/// Build, wrap, and unpack for the DIDComm Routing Protocol 2.0 <c>forward</c> message — the onion of
/// anoncrypt envelopes a sender layers over a packed message so a chain of mediators can each peel one
/// layer and forward the rest, per
/// <see href="https://identity.foundation/didcomm-messaging/spec/v2.1/#routing-protocol-20">DIDComm Messaging v2.1 §Routing Protocol 2.0</see>.
/// </summary>
/// <remarks>
/// <para>
/// A forward is an ordinary <see cref="DidCommMessage"/> whose <c>type</c> is the forward Message Type
/// URI, carrying the next hop in <c>body.next</c> and the message being forwarded as its single
/// attachment's <c>data.base64</c> (DIDComm v2.1 §Routing Protocol 2.0 §Messages). The forwarded
/// message is a packed encrypted message — a <see cref="DidCommEncryptedMessage"/> — so it is carried
/// byte-faithfully as base64url with no JSON-object representation: <c>data.base64</c> is the spec's
/// "full power of DIDComm attachments". There is no parallel typed model: this mirrors
/// <see cref="OutOfBandInvitationExtensions"/>, reusing the message model, <see cref="Attachment"/>, and
/// the injected <see cref="DidCommMessageSerializer"/> / <see cref="DidCommMessageParser"/>.
/// </para>
/// <para>
/// Every wrapper is <em>anoncrypt</em>: the mediator never authenticates the sender (DIDComm v2.1
/// §Routing Protocol 2.0 §Roles). The wrap path (<see cref="WrapInForwardAsync(DidCommEncryptedMessage, string, IReadOnlyList{string}, DidResolver, ExchangeContext, EphemeralKeyPairFactory, string, string, string, DidCommMessageSerializer, JwtHeaderSerializer, EncodeDelegate, TagToEpkCrvDelegate, GenerateNonceDelegate, MemoryPool{byte}, CancellationToken)"/>)
/// is producer-side and MAY throw on bad caller args; the unpack path
/// (<see cref="UnpackForwardAsync(DidCommEncryptedMessage, string, PrivateKeyMemory, DidResolver, ExchangeContext, DidCommMessageParser, JwsMessageParser, DecodeDelegate, EncodeDelegate, MemoryPool{byte}, CancellationToken)"/>)
/// is the mediator over attacker-controlled wire input and is fail-closed — it never throws, returning a
/// typed <see cref="ForwardUnpackError"/> instead. The mediator MUST NOT decrypt the forwarded message
/// (it is "a blob"); it returns it as owned opaque bytes plus the next hop, and the transmit to that hop
/// is the application's transport concern — this project carries no <c>System.Net</c> (DIDComm v2.1
/// §Routing Protocol 2.0 §Mediator Process).
/// </para>
/// </remarks>
public static class RoutingForwardExtensions
{
    /// <summary>
    /// The hard upper bound on the length of the forwarded <c>data.base64</c> string the unpack path
    /// decodes into a pooled buffer. The forwarded message is attacker-controlled wire input, so this
    /// caps the allocation a hostile forward can drive — the bound is checked BEFORE decoding (mirrors
    /// <see cref="OutOfBandInvitationExtensions.MaximumOobValueLength"/>); it is well above any real
    /// packed DIDComm envelope.
    /// </summary>
    public const int MaximumForwardedMessageLength = 4 * 1024 * 1024;


    /// <summary>
    /// Builds a forward message as a <see cref="DidCommMessage"/> whose <c>type</c> is the forward Message
    /// Type URI, setting <c>body.next</c> to <paramref name="next"/> and attaching
    /// <paramref name="forwardedMessage"/> as the single attachment's <c>data.base64</c> (DIDComm v2.1
    /// §Routing Protocol 2.0 §Messages). The forwarded packed message is carried byte-faithfully as a
    /// base64url string.
    /// </summary>
    /// <param name="next">REQUIRED. The next hop — a DID or, for the last hop, a key. The party the attached message is sent to.</param>
    /// <param name="id">REQUIRED. The forward message id, unique to the sender (DIDComm v2.1 §Message Headers).</param>
    /// <param name="forwardedMessage">REQUIRED. The packed encrypted message being forwarded, carried byte-faithfully as the attachment's <c>data.base64</c>.</param>
    /// <param name="base64UrlEncoder">Base64Url encoder producing the <c>data.base64</c> string from the forwarded message's bytes.</param>
    /// <param name="to">OPTIONAL. The mediator the forward is addressed to, conveyed in the plaintext <c>to</c> header.</param>
    /// <param name="expiresTime">OPTIONAL. When the forward expires, in UTC epoch seconds (DIDComm v2.1 §Routing Protocol 2.0).</param>
    /// <returns>The forward message.</returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="next"/> is not a DID or DID URL — a producer-side guard.</exception>
    public static DidCommMessage CreateForward(
        string next,
        string id,
        DidCommEncryptedMessage forwardedMessage,
        EncodeDelegate base64UrlEncoder,
        string? to = null,
        long? expiresTime = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(next);
        ArgumentException.ThrowIfNullOrEmpty(id);
        ArgumentNullException.ThrowIfNull(forwardedMessage);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);

        //The next hop is a DID or DID URL — typically a DID, and for the last hop possibly a key id
        //(a DID URL with a fragment); both parse as a DID URL carrying a method and method-specific id
        //(DIDComm v2.1 §Routing Protocol 2.0 §Messages: "value of the next field is typically a DID …
        //may also be a key, for the last hop of a route").
        if(!IsDidOrDidUrl(next))
        {
            throw new ArgumentException(
                "The forward 'next' MUST be a DID or DID URL (DIDComm v2.1 §Routing Protocol 2.0 §Messages).",
                nameof(next));
        }

        //The forwarded message is a packed encrypted message; carry its bytes byte-faithfully as
        //data.base64 — no JSON-object representation is needed (DIDComm v2.1 §Routing Protocol 2.0
        //§Messages: the forward attachment may use "the full power of DIDComm attachments").
        var attachment = new Attachment
        {
            Data = new AttachmentData { Base64 = base64UrlEncoder(forwardedMessage.AsReadOnlySpan()) }
        };

        return new DidCommMessage
        {
            Id = id,
            Type = WellKnownRoutingNames.ForwardType,
            To = to is null ? null : [to],
            ExpiresTime = expiresTime,
            Body = new Dictionary<string, object> { [WellKnownRoutingNames.Next] = next },
            Attachments = [attachment]
        };
    }


    //The forward Message Type URI, parsed once for semver-compatible handler dispatch.
    private static readonly MessageTypeUri ForwardMessageType = MessageTypeUri.Parse(WellKnownRoutingNames.ForwardType);


    /// <summary>
    /// Whether <paramref name="message"/> is a forward message — its <c>type</c> names the forward
    /// Message Type URI (DIDComm v2.1 §Routing Protocol 2.0 §Messages). The comparison is the spec-mandated
    /// MTURI dispatch match (<see cref="MessageTypeUri.IsSameMessageType(MessageTypeUri?)"/>): protocol and
    /// message names ignoring case and punctuation, same major version (so a future <c>routing/2.x</c>
    /// forward still dispatches), under the same documentation URI.
    /// </summary>
    /// <param name="message">The message to test.</param>
    /// <returns><see langword="true"/> when the message is a forward.</returns>
    public static bool IsForward(this DidCommMessage message)
    {
        ArgumentNullException.ThrowIfNull(message);

        return MessageTypeUri.TryParse(message.Type, out MessageTypeUri? messageType)
            && messageType.IsSameMessageType(ForwardMessageType);
    }


    /// <summary>Reads the forward body <c>next</c> member, or <see langword="null"/> when absent.</summary>
    /// <param name="forward">The forward message.</param>
    /// <returns>The next hop, or <see langword="null"/>.</returns>
    public static string? GetForwardNext(this DidCommMessage forward)
    {
        ArgumentNullException.ThrowIfNull(forward);

        if(forward.Body is not null
            && forward.Body.TryGetValue(WellKnownRoutingNames.Next, out object? value)
            && value is string next)
        {
            return next;
        }

        return null;
    }


    /// <summary>
    /// Wraps <paramref name="innerPackedMessage"/> in a forward onion for <paramref name="routingKeys"/>,
    /// resolving the anoncrypt cryptographic functions from the key-agreement registry. The
    /// delegate-taking overload does the work after resolution.
    /// </summary>
    /// <remarks>
    /// Each wrapper anoncrypts with <see cref="WellKnownJweAlgorithms.EcdhEsA256Kw"/> over
    /// <see cref="WellKnownJweEncryptionAlgorithms.A256Gcm"/>, the registry-supported anoncrypt profile.
    /// </remarks>
    /// <inheritdoc cref="WrapInForwardAsync(DidCommEncryptedMessage, string, IReadOnlyList{string}, DidResolver, ExchangeContext, EphemeralKeyPairFactory, string, string, string, DidCommMessageSerializer, JwtHeaderSerializer, EncodeDelegate, TagToEpkCrvDelegate, GenerateNonceDelegate, MemoryPool{byte}, CancellationToken)"/>
    public static ValueTask<DidCommEncryptedMessage?> WrapInForwardAsync(
        this DidCommEncryptedMessage innerPackedMessage,
        string to,
        IReadOnlyList<string> routingKeys,
        DidResolver didResolver,
        ExchangeContext exchangeContext,
        EphemeralKeyPairFactory ephemeralKeyPairFactory,
        string forwardId,
        DidCommMessageSerializer plaintextSerializer,
        JwtHeaderSerializer headerSerializer,
        EncodeDelegate base64UrlEncoder,
        TagToEpkCrvDelegate tagToCrvConverter,
        GenerateNonceDelegate generateContentEncryptionKey,
        MemoryPool<byte> memoryPool,
        CancellationToken cancellationToken = default)
    {
        return innerPackedMessage.WrapInForwardAsync(
            to,
            routingKeys,
            didResolver,
            exchangeContext,
            ephemeralKeyPairFactory,
            forwardId,
            WellKnownJweAlgorithms.EcdhEsA256Kw,
            WellKnownJweEncryptionAlgorithms.A256Gcm,
            plaintextSerializer,
            headerSerializer,
            base64UrlEncoder,
            tagToCrvConverter,
            generateContentEncryptionKey,
            memoryPool,
            cancellationToken);
    }


    /// <summary>
    /// Wraps <paramref name="innerPackedMessage"/> in a forward onion for <paramref name="routingKeys"/>,
    /// anoncrypting each forward wrapper for its routing key with explicit key-management and
    /// content-encryption algorithms (DIDComm v2.1 §Routing Protocol 2.0 §Sender Process to Enable
    /// Forwarding).
    /// </summary>
    /// <remarks>
    /// The wrapping loops in REVERSE over <paramref name="routingKeys"/>: for index <c>i</c> from last to
    /// first, the forward's <c>next</c> is the following routing key (or <paramref name="to"/> for the
    /// last index), its attachment is the current packed message, and it is anoncrypted for
    /// <c>routingKeys[i]</c>; the result becomes the current packed message for the next round. The
    /// outermost forward returned is encrypted for the FIRST routing key — the mediator the sender
    /// transmits to. An empty <paramref name="routingKeys"/> means the forward protocol is not needed, and
    /// <see langword="null"/> is returned (the caller transmits the inner message directly), matching the
    /// reference implementations.
    /// </remarks>
    /// <param name="innerPackedMessage">The packed (encrypted) message for the final recipient — the innermost payload.</param>
    /// <param name="to">REQUIRED. The final recipient the innermost forward's <c>next</c> addresses.</param>
    /// <param name="routingKeys">The recipient's <c>serviceEndpoint.routingKeys</c>, in order; each a DID or key resolved to a keyAgreement key.</param>
    /// <param name="didResolver">Resolver for each routing key's DID, used to read its keyAgreement public key and absolute kid.</param>
    /// <param name="exchangeContext">The per-operation exchange context threaded to resolution.</param>
    /// <param name="ephemeralKeyPairFactory">Produces a fresh ephemeral key pair per hop; each is disposed after its wrapper.</param>
    /// <param name="forwardId">The id assigned to each forward message (DIDComm v2.1 §Message Headers).</param>
    /// <param name="keyManagementAlgorithm">The anoncrypt <c>alg</c> — an ECDH-ES key-wrapping algorithm.</param>
    /// <param name="contentEncryptionAlgorithm">The anoncrypt <c>enc</c>, e.g. <c>A256GCM</c>.</param>
    /// <param name="plaintextSerializer">Serializer producing each forward's <c>application/didcomm-plain+json</c> bytes.</param>
    /// <param name="headerSerializer">Serializer producing the protected header's UTF-8 JSON bytes.</param>
    /// <param name="base64UrlEncoder">Base64Url encoder for the JWE envelope members and the forward attachment's <c>data.base64</c>.</param>
    /// <param name="tagToCrvConverter">Delegate mapping the ephemeral key's tag to a JWK curve name.</param>
    /// <param name="generateContentEncryptionKey">Entropy delegate producing each wrapper's random CEK bytes.</param>
    /// <param name="memoryPool">Memory pool for transient buffers and the returned artifact.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The outermost forward encrypted for the first routing key, or <see langword="null"/> when <paramref name="routingKeys"/> is empty. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentException">Thrown when a routing key cannot be resolved to a keyAgreement key — a producer-side guard.</exception>
    public static async ValueTask<DidCommEncryptedMessage?> WrapInForwardAsync(
        this DidCommEncryptedMessage innerPackedMessage,
        string to,
        IReadOnlyList<string> routingKeys,
        DidResolver didResolver,
        ExchangeContext exchangeContext,
        EphemeralKeyPairFactory ephemeralKeyPairFactory,
        string forwardId,
        string keyManagementAlgorithm,
        string contentEncryptionAlgorithm,
        DidCommMessageSerializer plaintextSerializer,
        JwtHeaderSerializer headerSerializer,
        EncodeDelegate base64UrlEncoder,
        TagToEpkCrvDelegate tagToCrvConverter,
        GenerateNonceDelegate generateContentEncryptionKey,
        MemoryPool<byte> memoryPool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(innerPackedMessage);
        ArgumentException.ThrowIfNullOrEmpty(to);
        ArgumentNullException.ThrowIfNull(routingKeys);
        ArgumentNullException.ThrowIfNull(didResolver);
        ArgumentNullException.ThrowIfNull(exchangeContext);
        ArgumentNullException.ThrowIfNull(ephemeralKeyPairFactory);
        ArgumentException.ThrowIfNullOrEmpty(forwardId);
        ArgumentException.ThrowIfNullOrWhiteSpace(keyManagementAlgorithm);
        ArgumentException.ThrowIfNullOrWhiteSpace(contentEncryptionAlgorithm);
        ArgumentNullException.ThrowIfNull(plaintextSerializer);
        ArgumentNullException.ThrowIfNull(headerSerializer);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(tagToCrvConverter);
        ArgumentNullException.ThrowIfNull(generateContentEncryptionKey);
        ArgumentNullException.ThrowIfNull(memoryPool);

        //Empty routingKeys: the forward protocol is not needed (the recipient has no mediators). The
        //caller transmits the inner message directly — return null, matching didcomm-python/-rust.
        if(routingKeys.Count == 0)
        {
            return null;
        }

        //`packed` is the current innermost JWE, encrypted for the final recipient `to` to start; it is
        //replaced each round by the new forward wrapper. Only the wrappers this method mints are owned and
        //disposed here — the caller's innerPackedMessage is never disposed by this method.
        DidCommEncryptedMessage packed = innerPackedMessage;
        DidCommEncryptedMessage? ownedPrevious = null;

        try
        {
            for(int i = routingKeys.Count - 1; i >= 0; i--)
            {
                string encryptFor = routingKeys[i];
                string next = i == routingKeys.Count - 1 ? to : routingKeys[i + 1];

                //The current packed message becomes this forward's single data.base64 attachment,
                //carried byte-faithfully (it is a DidCommEncryptedMessage = a packed JWE).
                DidCommMessage forward = CreateForward(next, forwardId, packed, base64UrlEncoder);

                //Resolve the routing key to its keyAgreement recipients (each absolute kid + public key) and
                //anoncrypt the forward for all of them (multiplexed so any device can decrypt). A fresh
                //ephemeral key pair is used per hop and disposed; every resolved key is disposed after the pack.
                IReadOnlyList<(string Kid, PublicKeyMemory Key)> recipientKeys = await ResolveRoutingKeyRecipientsAsync(
                    encryptFor, didResolver, exchangeContext, memoryPool, cancellationToken).ConfigureAwait(false);

                DidCommEncryptedMessage wrapper;
                try
                {
                    var recipients = new List<GeneralJweRecipientInput>(recipientKeys.Count);
                    foreach((string kid, PublicKeyMemory key) in recipientKeys)
                    {
                        recipients.Add(new GeneralJweRecipientInput(kid, key));
                    }

                    PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> ephemeral = ephemeralKeyPairFactory(memoryPool);
                    using PublicKeyMemory ephemeralPublic = ephemeral.PublicKey;
                    using PrivateKeyMemory ephemeralPrivate = ephemeral.PrivateKey;

                    wrapper = await forward.PackAnoncryptAsync(
                        recipients,
                        keyManagementAlgorithm,
                        contentEncryptionAlgorithm,
                        new PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>(ephemeralPublic, ephemeralPrivate),
                        plaintextSerializer,
                        headerSerializer,
                        base64UrlEncoder,
                        tagToCrvConverter,
                        generateContentEncryptionKey,
                        memoryPool,
                        cancellationToken).ConfigureAwait(false);
                }
                finally
                {
                    foreach((string _, PublicKeyMemory key) in recipientKeys)
                    {
                        key.Dispose();
                    }
                }

                //Dispose the previous wrapper this loop owned; the caller's innerPackedMessage (the first
                //`packed`) is never owned here, so it is left intact.
                ownedPrevious?.Dispose();
                ownedPrevious = wrapper;
                packed = wrapper;
            }

            return ownedPrevious;
        }
        catch
        {
            ownedPrevious?.Dispose();
            throw;
        }
    }


    /// <summary>
    /// Unpacks a forward message a mediator received, resolving the anoncrypt cryptographic functions from
    /// the key-agreement registry. The delegate-taking overload does the work after resolution.
    /// </summary>
    /// <inheritdoc cref="UnpackForwardAsync(DidCommEncryptedMessage, string, PrivateKeyMemory, DidResolver, ExchangeContext, DidCommMessageParser, JwsMessageParser, DecodeDelegate, EncodeDelegate, MemoryPool{byte}, CancellationToken)"/>
    public static async ValueTask<ForwardUnpackResult> UnpackForwardAsync(
        this DidCommEncryptedMessage forwardEnvelope,
        string mediatorRecipientKeyId,
        PrivateKeyMemory mediatorPrivateKey,
        DidResolver didResolver,
        ExchangeContext exchangeContext,
        DidCommMessageParser plaintextParser,
        JwsMessageParser signedParser,
        DecodeDelegate base64UrlDecoder,
        EncodeDelegate base64UrlEncoder,
        MemoryPool<byte> memoryPool,
        OutboundTransportDelegate? transport = null,
        HashFunctionSelector? hashFunctionSelector = null,
        JsonValueSerializer? jsonValueSerializer = null,
        DecodeDelegate? hashBase58Decoder = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(forwardEnvelope);
        ArgumentException.ThrowIfNullOrWhiteSpace(mediatorRecipientKeyId);
        ArgumentNullException.ThrowIfNull(mediatorPrivateKey);
        ArgumentNullException.ThrowIfNull(didResolver);
        ArgumentNullException.ThrowIfNull(exchangeContext);
        ArgumentNullException.ThrowIfNull(plaintextParser);
        ArgumentNullException.ThrowIfNull(signedParser);
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(memoryPool);

        //The mediator decrypts the outer forward with the registry-resolving anoncrypt unpack — exactly
        //the seam the recipient path uses. Any envelope failure surfaces as a fail-closed result below.
        DidCommEncryptedUnpackResult unpacked = await forwardEnvelope.UnpackAnoncryptAsync(
            mediatorRecipientKeyId,
            mediatorPrivateKey,
            didResolver,
            exchangeContext,
            plaintextParser,
            signedParser,
            base64UrlDecoder,
            base64UrlEncoder,
            memoryPool,
            cancellationToken).ConfigureAwait(false);

        return await InterpretAsync(
            unpacked, exchangeContext, base64UrlDecoder, transport, hashFunctionSelector, jsonValueSerializer,
            hashBase58Decoder, memoryPool, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Unpacks a forward message a mediator received, using explicit anoncrypt delegates. Fail-closed: the
    /// forward is attacker-controlled wire input, so every malformed or non-conformant outcome is a typed
    /// <see cref="ForwardUnpackError"/> and never thrown (DIDComm v2.1 §Routing Protocol 2.0 §Mediator
    /// Process).
    /// </summary>
    /// <remarks>
    /// The sequence is: anoncrypt-decrypt the outer envelope; require the plaintext to be a forward
    /// message; read <c>body.next</c>; require exactly one attachment whose <c>data.base64</c> is
    /// non-empty; bound that <c>data.base64</c> string and decode it into an OWNED pooled buffer (the
    /// next-hop packed message the mediator re-transmits). The mediator MUST NOT decrypt the forwarded
    /// message — it is returned as owned opaque bytes for byte-for-byte re-transmission (DIDComm v2.1
    /// §Routing Protocol 2.0 §Roles).
    /// </remarks>
    /// <param name="forwardEnvelope">The outer forward envelope addressed to the mediator.</param>
    /// <param name="mediatorRecipientKeyId">The <c>kid</c> of the mediator's own keyAgreement key the forward is encrypted for.</param>
    /// <param name="mediatorPrivateKey">The mediator's keyAgreement private key.</param>
    /// <param name="didResolver">Resolver threaded to the anoncrypt unpack (used only for a nested signed inner — not the forward path).</param>
    /// <param name="exchangeContext">The per-operation exchange context threaded to resolution.</param>
    /// <param name="plaintextParser">Parser producing the forward message from the decrypted plaintext bytes.</param>
    /// <param name="signedParser">Parser producing an unverified JWS message from a nested signed JWM's bytes.</param>
    /// <param name="base64UrlDecoder">Base64Url decoder for the protected header, envelope members, and the forward attachment's <c>data.base64</c>.</param>
    /// <param name="base64UrlEncoder">Base64Url encoder, threaded to the anoncrypt unpack.</param>
    /// <param name="memoryPool">Memory pool for transient buffers and the owned forwarded message.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A fail-closed forward unpack result the caller disposes.</returns>
    public static async ValueTask<ForwardUnpackResult> UnpackForwardAsync(
        this DidCommEncryptedMessage forwardEnvelope,
        string mediatorRecipientKeyId,
        PrivateKeyMemory mediatorPrivateKey,
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
        OutboundTransportDelegate? transport = null,
        HashFunctionSelector? hashFunctionSelector = null,
        JsonValueSerializer? jsonValueSerializer = null,
        DecodeDelegate? hashBase58Decoder = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(forwardEnvelope);
        ArgumentException.ThrowIfNullOrWhiteSpace(mediatorRecipientKeyId);
        ArgumentNullException.ThrowIfNull(mediatorPrivateKey);
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

        DidCommEncryptedUnpackResult unpacked = await forwardEnvelope.UnpackAnoncryptAsync(
            mediatorRecipientKeyId,
            mediatorPrivateKey,
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
            cancellationToken).ConfigureAwait(false);

        return await InterpretAsync(
            unpacked, exchangeContext, base64UrlDecoder, transport, hashFunctionSelector, jsonValueSerializer,
            hashBase58Decoder, memoryPool, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Wraps <paramref name="innerPackedMessage"/> in a forward onion by first resolving the recipient's
    /// <c>DIDCommMessaging</c> service chain (its <c>routingKeys</c>) from <paramref name="to"/>'s DID
    /// document, then wrapping for those keys. Registry-resolving anoncrypt is used. When the recipient
    /// advertises no <c>didcomm/v2</c> service or no routing keys, the forward protocol is not needed and
    /// <see langword="null"/> is returned (DIDComm v2.1 §Routing Protocol 2.0 §Sender Process).
    /// </summary>
    /// <param name="innerPackedMessage">The packed message for the final recipient.</param>
    /// <param name="to">The final recipient DID whose service routingKeys are resolved.</param>
    /// <param name="didResolver">Resolver for the recipient (and any mediator-chain) DID documents and each routing key.</param>
    /// <param name="exchangeContext">The per-operation exchange context threaded to resolution.</param>
    /// <param name="ephemeralKeyPairFactory">Produces a fresh ephemeral key pair per hop.</param>
    /// <param name="forwardId">The id assigned to each forward message.</param>
    /// <param name="plaintextSerializer">Serializer producing each forward's plaintext bytes.</param>
    /// <param name="headerSerializer">Serializer producing the protected header's UTF-8 JSON bytes.</param>
    /// <param name="base64UrlEncoder">Base64Url encoder for the JWE envelope members and the forward attachment's <c>data.base64</c>.</param>
    /// <param name="tagToCrvConverter">Delegate mapping the ephemeral key's tag to a JWK curve name.</param>
    /// <param name="generateContentEncryptionKey">Entropy delegate producing each wrapper's random CEK bytes.</param>
    /// <param name="memoryPool">Memory pool for transient buffers and the returned artifact.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The outermost forward, or <see langword="null"/> when the recipient advertises no routing keys.</returns>
    public static async ValueTask<DidCommEncryptedMessage?> WrapInForwardAsync(
        this DidCommEncryptedMessage innerPackedMessage,
        string to,
        DidResolver didResolver,
        ExchangeContext exchangeContext,
        EphemeralKeyPairFactory ephemeralKeyPairFactory,
        string forwardId,
        DidCommMessageSerializer plaintextSerializer,
        JwtHeaderSerializer headerSerializer,
        EncodeDelegate base64UrlEncoder,
        TagToEpkCrvDelegate tagToCrvConverter,
        GenerateNonceDelegate generateContentEncryptionKey,
        MemoryPool<byte> memoryPool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(innerPackedMessage);
        ArgumentException.ThrowIfNullOrEmpty(to);
        ArgumentNullException.ThrowIfNull(didResolver);
        ArgumentNullException.ThrowIfNull(exchangeContext);

        IReadOnlyList<string> routingKeys = await ResolveRoutingKeysAsync(
            to, didResolver, exchangeContext, cancellationToken).ConfigureAwait(false);

        return await innerPackedMessage.WrapInForwardAsync(
            to,
            routingKeys,
            didResolver,
            exchangeContext,
            ephemeralKeyPairFactory,
            forwardId,
            plaintextSerializer,
            headerSerializer,
            base64UrlEncoder,
            tagToCrvConverter,
            generateContentEncryptionKey,
            memoryPool,
            cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Resolves the ordered <c>routingKeys</c> a sender wraps a message for — the routing keys of
    /// <paramref name="to"/>'s first <c>DIDCommMessaging</c> delivery target (DIDComm v2.1 §Service Endpoint).
    /// </summary>
    /// <remarks>
    /// Delegates to <see cref="DidCommServiceEndpointExtensions.ResolveDeliveryTargetsAsync"/> and returns the first
    /// target's <see cref="DidCommDeliveryTarget.RoutingKeys"/>: the recipient's <c>routingKeys</c>, with a
    /// mediator-DID endpoint resolved and the mediator DID PREPENDED so the outer forward is wrapped for the
    /// mediator's keyAgreement keys (DIDComm v2.1 §Service Endpoint §Using a DID as an endpoint). Resolution is
    /// fail-soft: an empty list means no <c>didcomm/v2</c> delivery target is resolvable, so the forward protocol is
    /// not needed.
    /// </remarks>
    /// <param name="to">The recipient DID whose service endpoints are resolved.</param>
    /// <param name="didResolver">Resolver for the recipient and any mediator DID documents.</param>
    /// <param name="exchangeContext">The per-operation exchange context threaded to resolution.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The ordered routing keys, or an empty list when no <c>didcomm/v2</c> delivery target is resolvable.</returns>
    public static async ValueTask<IReadOnlyList<string>> ResolveRoutingKeysAsync(
        string to,
        DidResolver didResolver,
        ExchangeContext exchangeContext,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(to);
        ArgumentNullException.ThrowIfNull(didResolver);
        ArgumentNullException.ThrowIfNull(exchangeContext);

        IReadOnlyList<DidCommDeliveryTarget> targets = await DidCommServiceEndpointExtensions
            .ResolveDeliveryTargetsAsync(to, didResolver, exchangeContext, cancellationToken)
            .ConfigureAwait(false);

        return targets.Count > 0 ? targets[0].RoutingKeys : [];
    }


    //Resolves a routing key (a DID or a key id) to its keyAgreement recipients: each recipient's absolute kid
    //and a pooled public key. A bare DID multiplexes across ALL of the document's keyAgreement methods, so any
    //of the recipient's devices can decrypt (DIDComm v2.1 §DID Document Keys: every key in the keyAgreement
    //section is a target key, encryption multiplexed); a key-id routing key selects that one method. A
    //producer-side guard — a routing key that cannot be resolved is a caller error.
    private static async ValueTask<IReadOnlyList<(string Kid, PublicKeyMemory Key)>> ResolveRoutingKeyRecipientsAsync(
        string routingKey,
        DidResolver didResolver,
        ExchangeContext exchangeContext,
        MemoryPool<byte> memoryPool,
        CancellationToken cancellationToken)
    {
        string did = BaseDidOf(routingKey);

        DidResolutionResult resolution = await didResolver
            .ResolveAsync(did, exchangeContext, options: null, cancellationToken)
            .ConfigureAwait(false);

        if(!resolution.IsSuccessful || resolution.Document is null)
        {
            throw new ArgumentException(
                $"The routing key '{routingKey}' could not be resolved to a DID document.", nameof(routingKey));
        }

        VerificationMethod[] methods = HasFragment(routingKey)
            ? resolution.Document.GetLocalKeyAgreementMethodById(routingKey) is VerificationMethod method ? [method] : []
            : resolution.Document.GetLocalKeyAgreementMethods();

        if(methods.Length == 0)
        {
            throw new ArgumentException(
                $"The routing key '{routingKey}' did not resolve to a keyAgreement verification method.", nameof(routingKey));
        }

        var recipients = new List<(string Kid, PublicKeyMemory Key)>(methods.Length);
        try
        {
            foreach(VerificationMethod keyAgreement in methods)
            {
                recipients.Add((AbsoluteKid(keyAgreement, did), keyAgreement.ToPublicKeyMemory(memoryPool)));
            }
        }
        catch
        {
            //ToPublicKeyMemory rents a pooled buffer per keyAgreement method; if a later method has an
            //unsupported key type and it throws mid-loop, dispose the buffers already rented for the earlier
            //methods before propagating — a partial rent must not leak pooled memory on the error path.
            foreach((_, PublicKeyMemory key) in recipients)
            {
                key.Dispose();
            }

            throw;
        }

        return recipients;
    }


    //Interprets an anoncrypt unpack outcome as a forward: enforce decrypt success, the forward type, a
    //present next, and exactly one attachment whose data object resolves to the next-hop packed message.
    //Every failure is a typed, fail-closed result; nothing throws.
    private static async ValueTask<ForwardUnpackResult> InterpretAsync(
        DidCommEncryptedUnpackResult unpacked,
        ExchangeContext exchangeContext,
        DecodeDelegate base64UrlDecoder,
        OutboundTransportDelegate? transport,
        HashFunctionSelector? hashFunctionSelector,
        JsonValueSerializer? jsonValueSerializer,
        DecodeDelegate? hashBase58Decoder,
        MemoryPool<byte> memoryPool,
        CancellationToken cancellationToken)
    {
        if(!unpacked.IsUnpacked || unpacked.Message is null)
        {
            return ForwardUnpackResult.Failed(ForwardUnpackError.EnvelopeUnpackFailed);
        }

        return await InterpretForwardAsync(
            unpacked.Message, exchangeContext, base64UrlDecoder, transport, hashFunctionSelector, jsonValueSerializer,
            hashBase58Decoder, memoryPool, cancellationToken).ConfigureAwait(false);
    }


    //Interprets a decrypted forward plaintext: enforce the forward type, a present next, and exactly one
    //attachment, then resolve that attachment's data object — by value (base64 inline, fetch-free; or the
    //data.json interop-in via the leaf seam) or by reference (links + hash, remote) — into the OWNED next-hop
    //bytes the mediator re-transmits WITHOUT decrypting (DIDComm v2.1 §Routing Protocol 2.0 §Messages: the
    //forward attachment may use "the full power of DIDComm attachments"). Internal so the bound (which a
    //multi-MiB envelope cannot be round-tripped to reach) is provable directly. Every failure is a typed,
    //fail-closed result; nothing throws. The base64 inline path stays fetch-free.
    internal static async ValueTask<ForwardUnpackResult> InterpretForwardAsync(
        DidCommMessage forward,
        ExchangeContext exchangeContext,
        DecodeDelegate base64UrlDecoder,
        OutboundTransportDelegate? transport,
        HashFunctionSelector? hashFunctionSelector,
        JsonValueSerializer? jsonValueSerializer,
        DecodeDelegate? hashBase58Decoder,
        MemoryPool<byte> memoryPool,
        CancellationToken cancellationToken)
    {
        if(!forward.IsForward())
        {
            return ForwardUnpackResult.Failed(ForwardUnpackError.NotAForwardMessage);
        }

        if(forward.GetForwardNext() is not string next || string.IsNullOrEmpty(next))
        {
            return ForwardUnpackResult.Failed(ForwardUnpackError.MissingNext);
        }

        if(forward.Attachments is not { Count: 1 } || forward.Attachments[0].Data is not AttachmentData attachmentData)
        {
            return ForwardUnpackResult.Failed(ForwardUnpackError.MissingForwardedMessage);
        }

        //Bound the untrusted base64url length BEFORE the resolver decodes it so a hostile inline value cannot
        //drive an unbounded pool allocation (the decoder rents proportional to the input; mirrors
        //OutOfBandInvitationExtensions). The general resolver also bounds inline/fetched lengths.
        if(attachmentData.Base64 is { Length: > 0 } forwardedBase64 && forwardedBase64.Length > MaximumForwardedMessageLength)
        {
            return ForwardUnpackResult.Failed(ForwardUnpackError.MalformedForwardedMessage);
        }

        //A hash over actual content (a hashed inline form, or the REQUIRED links integrity check) cannot be
        //verified without a hash-function selector; absent the selector such a forward fails closed. The
        //resolver itself fails closed on a null selector (it returns UnsupportedHashAlgorithm), but the gate
        //here keeps the forward-error distinction: a hashed INLINE without a selector is reported as
        //MalformedForwardedMessage (the content is present but unverifiable), whereas the resolver would
        //collapse it into the generic fetch-failed bucket. An unhashed inline base64 forward — the seam-free
        //deployment — never needs it, and a hash-only data object (no content) is left to the resolver to
        //report as missing.
        bool hasLinks = attachmentData.Links is { Count: > 0 };
        bool hasInline = attachmentData.Base64 is { Length: > 0 } || attachmentData.Json is not null;
        bool hasContentHash = attachmentData.Hash is { Length: > 0 } && hasInline;
        if((hasLinks || hasContentHash) && hashFunctionSelector is null)
        {
            return ForwardUnpackResult.Failed(
                hasLinks
                    ? ForwardUnpackError.ForwardedMessageFetchFailed
                    : ForwardUnpackError.MalformedForwardedMessage);
        }

        //The data.json serializer and base58 decoder are only reached on their respective branches; when a
        //seam is absent the resolver fails closed on that branch (the json stand-in throws -> MalformedInline,
        //surfacing as MalformedForwardedMessage). The base58 decoder defaults to the base64url decoder only as
        //a non-null placeholder; the gate above guarantees it is reached only when a hash-function selector —
        //and in real deployments a real base58 seam — is wired. The selector is threaded straight through; a
        //null selection inside the resolver fails the hashed path closed.
        DecodeDelegate base58Decoder = hashBase58Decoder ?? base64UrlDecoder;
        JsonValueSerializer jsonSerializer = jsonValueSerializer ?? NoJsonValue;

        using AttachmentResolutionResult resolution = await attachmentData.ResolveAsync(
            exchangeContext,
            transport,
            base64UrlDecoder,
            base58Decoder,
            hashFunctionSelector,
            jsonSerializer,
            memoryPool,
            cancellationToken).ConfigureAwait(false);

        if(resolution.IsResolved)
        {
            //The general resolver bounds a fetched (links) payload at its own larger cap; the forward path
            //applies its tighter MaximumForwardedMessageLength so a mediator does not buffer and relay a
            //forwarded blob larger than a forward is allowed to carry (the inline path is already bounded above).
            if(resolution.Payload.Length > MaximumForwardedMessageLength)
            {
                return ForwardUnpackResult.Failed(ForwardUnpackError.ForwardedMessageFetchFailed);
            }

            //COPY the resolved payload into an owned buffer the forwarded message disposes — the resolution
            //result owns the source buffer and disposes it on the using above.
            DidCommEncryptedMessage forwarded = DidCommEncryptedMessage.Create(resolution.Payload.Span, BufferTags.Json, memoryPool);

            return ForwardUnpackResult.Success(next, forwarded);
        }

        return ForwardUnpackResult.Failed(MapResolutionError(resolution.Error));
    }


    //Maps an attachment-resolution error onto a forward error: no usable form is MissingForwardedMessage; a
    //malformed inline or links-without-hash is MalformedForwardedMessage; the remote denied/failed/over-size/
    //hash-mismatch/no-transport cases collapse to the single ForwardedMessageFetchFailed.
    private static ForwardUnpackError MapResolutionError(AttachmentResolutionError error) => error switch
    {
        AttachmentResolutionError.MissingData => ForwardUnpackError.MissingForwardedMessage,
        AttachmentResolutionError.JwsResolutionNotSupported => ForwardUnpackError.MissingForwardedMessage,
        AttachmentResolutionError.MalformedInline => ForwardUnpackError.MalformedForwardedMessage,
        AttachmentResolutionError.HashMissingForLinks => ForwardUnpackError.MalformedForwardedMessage,
        _ => ForwardUnpackError.ForwardedMessageFetchFailed
    };


    //A json-value serializer stand-in used only to satisfy the resolver's non-null parameter when no json
    //seam is supplied; it fails closed (MalformedInline) so a data.json forward without the seam is rejected
    //rather than silently mishandled.
    private static IMemoryOwner<byte> NoJsonValue(object jsonValue, MemoryPool<byte> memoryPool) =>
        throw new FormatException("No JsonValueSerializer seam was supplied for a data.json attachment.");


    //Builds the absolute kid of a verification method: a fragment-only id is qualified with the DID, an
    //already-absolute id is used as-is (mirrors the test SingleKeyAgreement idiom).
    private static string AbsoluteKid(VerificationMethod method, string did)
    {
        string? id = method.Id;

        return id is not null && id.StartsWith('#') ? did + id : id ?? did;
    }


    //Whether the identifier parses as a DID or DID URL carrying a method and method-specific id. A key id
    //(a DID URL with a fragment) is allowed, unlike the no-fragment `to` recipient rule.
    private static bool IsDidOrDidUrl(string identifier)
    {
        return !string.IsNullOrEmpty(identifier)
            && DidUrl.TryParse(identifier, out DidUrl? didUrl)
            && didUrl.IsAbsolute
            && !string.IsNullOrEmpty(didUrl.Method)
            && !string.IsNullOrEmpty(didUrl.MethodSpecificId);
    }


    //Whether the identifier is a DID URL carrying a fragment (a key id rather than a bare DID).
    private static bool HasFragment(string identifier)
    {
        return DidUrl.TryParse(identifier, out DidUrl? didUrl) && !string.IsNullOrEmpty(didUrl.Fragment);
    }


    //The base DID of a DID or DID URL: the DID URL stripped of path/query/fragment, or the value verbatim
    //when it is already a bare DID.
    private static string BaseDidOf(string didOrDidUrl) =>
        DidUrl.TryParse(didOrDidUrl, out DidUrl? didUrl) && didUrl.BaseDid is string baseDid
            ? baseDid
            : didOrDidUrl;
}
