using Verifiable.Core;
using Verifiable.Cryptography;

namespace Verifiable.DidComm;

/// <summary>
/// Which encryption wrapping a DIDComm encrypted message used (DIDComm Messaging v2.1 §Message Encryption).
/// </summary>
public enum DidCommEncryptionMode
{
    /// <summary>Anonymous Sender Encryption (ECDH-ES+A*KW) — confidentiality only, no sender authentication.</summary>
    Anoncrypt,

    /// <summary>Authenticated Sender Encryption (ECDH-1PU+A*KW) — the sender is authenticated to the recipients.</summary>
    Authcrypt
}


/// <summary>
/// The reason a DIDComm encrypted message failed to unpack, or <see cref="None"/> when it unpacked.
/// </summary>
/// <remarks>
/// Fail-closed: every value other than <see cref="None"/> denotes a rejected message whose plaintext
/// MUST NOT be trusted (and, for a decryption failure, was never recovered).
/// </remarks>
public enum DidCommDecryptionError
{
    /// <summary>The message unpacked; its plaintext may be used.</summary>
    None = 0,

    /// <summary>The input is not a parseable General JSON JWE encrypted envelope.</summary>
    MalformedEnvelope,

    /// <summary>The protected <c>typ</c> is not <c>application/didcomm-encrypted+json</c>.</summary>
    UnexpectedMediaType,

    /// <summary>The key-management (<c>alg</c>) or content-encryption (<c>enc</c>) algorithm is not supported.</summary>
    UnsupportedAlgorithm,

    /// <summary>No <c>recipients</c> entry carries the caller's recipient <c>kid</c>.</summary>
    NoMatchingRecipient,

    /// <summary>Key agreement, CEK unwrap, or AEAD decryption failed (wrong key, or tampered ciphertext/tag).</summary>
    DecryptionFailed,

    /// <summary>The decrypted payload is not a structurally valid DIDComm plaintext message.</summary>
    InvalidPlaintext,

    /// <summary>An authcrypt message lacks the <c>skid</c>/<c>apu</c> needed to identify the sender.</summary>
    MissingSenderKeyId,

    /// <summary>The decrypted plaintext lacks a <c>from</c>, so it cannot be bound to the authenticated sender.</summary>
    MissingFrom,

    /// <summary>
    /// The plaintext <c>from</c> does not match the encryption-layer <c>skid</c> DID — the
    /// addressing-consistency MUST (DIDComm v2.1: "The from attribute in the plaintext message MUST
    /// match the skid attribute in the encryption layer.").
    /// </summary>
    FromSkidMismatch,

    /// <summary>The authcrypt sender DID (from <c>skid</c>) could not be resolved.</summary>
    SenderResolutionFailed,

    /// <summary>A nested signed message did not pass signature verification (see the inner result).</summary>
    NestedSignatureInvalid,

    /// <summary>
    /// A nested (signed-then-encrypted) message whose inner signed JWM lacks a <c>to</c> header — MUST be
    /// rejected (DIDComm v2.1 §DIDComm Signed Messages: "In the case where a message is both signed and
    /// encrypted, the inner (signed) JWM being signed MUST contain a to header"). This is the
    /// surreptitious-forwarding defense.
    /// </summary>
    NestedSignedMessageMissingTo,

    /// <summary>
    /// An <c>authcrypt(sign)</c> message whose inner signer differs from the authcrypt sender — MUST be
    /// rejected (DIDComm v2.1 §Message Types: authcrypt(sign) "MUST emit an error if the signer of the
    /// plaintext is different from the sender identified by the authcrypt layer").
    /// </summary>
    SignerSenderMismatch,

    /// <summary>
    /// The <c>from_prior</c> DID Rotation JWT is not a parseable compact JWS, its <c>typ</c> is not
    /// <c>JWT</c>, its <c>kid</c> is not a DID URL with a fragment, or its payload is malformed
    /// (DIDComm v2.1 §DID Rotation).
    /// </summary>
    RotationJwtMalformed,

    /// <summary>
    /// The <c>from_prior</c> JWT <c>sub</c> (the new DID) does not match the message <c>from</c>, or the
    /// rotate-to-nothing presence rule is violated (DIDComm v2.1 §DID Rotation / §Ending a Relationship).
    /// </summary>
    RotationSubjectMismatch,

    /// <summary>
    /// The <c>from_prior</c> <c>kid</c>'s base DID does not equal <c>iss</c>, or <c>iss</c> equals
    /// <c>sub</c> — a rotation MUST move to a different DID (DIDComm v2.1 §DID Rotation).
    /// </summary>
    RotationIssuerKidMismatch,

    /// <summary>The <c>from_prior</c> prior DID (<c>iss</c>) could not be resolved.</summary>
    PriorDidResolutionFailed,

    /// <summary>
    /// The <c>from_prior</c> <c>kid</c> is not authorized for the prior DID's <c>authentication</c>
    /// relationship, its verification method is missing, or its key type is unsupported
    /// (DIDComm v2.1 §DID Rotation: the kid MUST be authorized in the DID document of the prior DID).
    /// </summary>
    RotationSignerNotAuthorized,

    /// <summary>The <c>from_prior</c> signature did not verify against the resolved prior-DID key.</summary>
    RotationSignatureInvalid
}


/// <summary>
/// The outcome of unpacking a DIDComm encrypted message — the recovered plaintext and sender context
/// when <see cref="IsUnpacked"/> is <see langword="true"/>, or a <see cref="Error"/> reason otherwise.
/// </summary>
/// <remarks>
/// <para>
/// Mint-only: the constructor is <see langword="private"/> and the factories are
/// <see langword="internal"/>, so a successful result can only originate from this library's unpack
/// path. Mirrors <see cref="DidCommSignedVerificationResult"/>.
/// </para>
/// <para>
/// The trust and data axes are distinct here. <see cref="Message"/> is the recovered plaintext — present for
/// any successful unpack, including <see cref="DidCommEncryptionMode.Anoncrypt"/>, which gives confidentiality
/// but no sender authentication. <see cref="Verified"/> is the <em>authenticity</em> proof — a
/// <see cref="Verified{T}"/> minted only when the sender is cryptographically authenticated (authcrypt, or a
/// verified nested signature), and <see langword="null"/> for plain anoncrypt. So a consumer that requires an
/// authenticated message uses <see cref="Verified"/>, which the compiler guarantees is absent for anoncrypt;
/// <see cref="Message"/> alone is unauthenticated data.
/// </para>
/// </remarks>
public sealed class DidCommEncryptedUnpackResult
{
    private DidCommEncryptedUnpackResult(
        bool isUnpacked,
        DidCommMessage? message,
        Verified<DidCommMessage>? verified,
        DidCommEncryptionMode mode,
        string? senderKeyId,
        bool isSenderAuthenticated,
        bool isSignedInner,
        bool isRecipientAddressedInTo,
        bool isRotation,
        string? priorDid,
        long? rotationIat,
        DidCommDecryptionError error)
    {
        IsUnpacked = isUnpacked;
        Message = message;
        Verified = verified;
        Mode = mode;
        SenderKeyId = senderKeyId;
        IsSenderAuthenticated = isSenderAuthenticated;
        IsSignedInner = isSignedInner;
        IsRecipientAddressedInTo = isRecipientAddressedInTo;
        IsRotation = isRotation;
        PriorDid = priorDid;
        RotationIat = rotationIat;
        Error = error;
    }


    /// <summary>Whether the message decrypted and every addressing-consistency check passed.</summary>
    public bool IsUnpacked { get; }

    /// <summary>The recovered plaintext message, or <see langword="null"/> when unpack failed. Present for both anoncrypt and authcrypt; on its own it is unauthenticated data (see <see cref="Verified"/>).</summary>
    public DidCommMessage? Message { get; }

    /// <summary>
    /// The authenticity proof — the recovered message wrapped in a <see cref="Verified{T}"/> — when the sender is
    /// cryptographically authenticated (authcrypt or a verified nested signature), or <see langword="null"/> for
    /// plain anoncrypt, which authenticates no sender. Possession of the <see cref="Verified{T}"/> is the proof
    /// the sender was authenticated.
    /// </summary>
    public Verified<DidCommMessage>? Verified { get; }

    /// <summary>The encryption wrapping the message used.</summary>
    public DidCommEncryptionMode Mode { get; }

    /// <summary>
    /// The authenticated sender key identifier — the authcrypt <c>skid</c> or, for a nested signed
    /// message, the verified signer <c>kid</c>. <see langword="null"/> for anoncrypt without a nested
    /// signature, or when unpack failed.
    /// </summary>
    public string? SenderKeyId { get; }

    /// <summary>
    /// Whether the sender is cryptographically authenticated — <see langword="true"/> for authcrypt or
    /// for a verified nested signature, <see langword="false"/> for plain anoncrypt.
    /// </summary>
    public bool IsSenderAuthenticated { get; }

    /// <summary>Whether the encrypted message wrapped a signed message (sign-then-encrypt).</summary>
    public bool IsSignedInner { get; }

    /// <summary>
    /// Whether the decrypting recipient's DID appears in the plaintext <c>to</c> header — an advisory
    /// signal, never a unpack failure.
    /// </summary>
    /// <remarks>
    /// DIDComm v2.1 tensions two normative rules over this check. §Message Layer Addressing Consistency
    /// says "The to attribute in the plaintext message MUST contain the kid attribute of an encrypted
    /// message" and "When one of these checks fails, the result MUST be an error so clients know that the
    /// trust choices in the message packaging are inconsistent." §Message Headers says of the same
    /// situation — the recipient's own identifier being absent from <c>to</c> — "Implementations MUST NOT
    /// fail to accept a message when this is not the case, but SHOULD give a warning to their user as it
    /// could indicate malicious intent from the sender" (a recipient may legitimately be a blind-copy
    /// recipient not listed in <c>to</c>). The only reading honouring both is to accept the message (never
    /// fail decryption on this account) yet surface the inconsistency to the caller — which this property
    /// does. It is <see langword="true"/> when <c>to</c> is present and contains the recipient DID, and
    /// <see langword="false"/> when <c>to</c> is present without it (the "give a warning" case) or absent
    /// (§Message Headers: a recipient SHOULD then assume they are the only recipient). Meaningful only when
    /// <see cref="IsUnpacked"/> is <see langword="true"/>.
    /// </remarks>
    public bool IsRecipientAddressedInTo { get; }

    /// <summary>
    /// Whether the recovered plaintext carried a <c>from_prior</c> DID Rotation that itself verified — the
    /// sender switched from <see cref="PriorDid"/> to the new DID (the message <c>from</c>). The new DID
    /// and its DID document MUST be used for further communication (DIDComm v2.1 §DID Rotation). Meaningful
    /// only when <see cref="IsUnpacked"/> is <see langword="true"/>.
    /// </summary>
    public bool IsRotation { get; }

    /// <summary>
    /// The verified prior DID (the <c>from_prior</c> <c>iss</c>) when <see cref="IsRotation"/> is
    /// <see langword="true"/>, otherwise <see langword="null"/>. The new DID is the message <c>from</c>.
    /// </summary>
    public string? PriorDid { get; }

    /// <summary>
    /// The rotation's <c>from_prior</c> <c>iat</c> (issued-at, Unix epoch seconds) when <see cref="IsRotation"/>
    /// is <see langword="true"/> and the JWT carried one, otherwise <see langword="null"/>. DIDComm v2.1 §DID
    /// Rotation requires a recipient to ignore messages predating a rotation it has accepted; the library
    /// cannot enforce that ordering statelessly, so it surfaces the rotation instant for the application.
    /// </summary>
    public long? RotationIat { get; }

    /// <summary>The reason unpack failed, or <see cref="DidCommDecryptionError.None"/> when it succeeded.</summary>
    public DidCommDecryptionError Error { get; }


    //Mints a successful result. Internal so only the library's unpack path can produce one. A verified
    //from_prior rotation surfaces the prior DID; a message without one is a non-rotation result.
    internal static DidCommEncryptedUnpackResult Unpacked(
        DidCommMessage message,
        DidCommEncryptionMode mode,
        string? senderKeyId,
        bool isSenderAuthenticated,
        bool isSignedInner,
        bool isRecipientAddressedInTo,
        bool isRotation = false,
        string? priorDid = null,
        long? rotationIat = null)
    {
        //The authenticity proof exists only when the sender is authenticated (authcrypt or a verified nested
        //signature); plain anoncrypt recovers the plaintext but proves no sender, so it carries no Verified<T>.
        Verified<DidCommMessage>? verified = isSenderAuthenticated
            ? new Verified<DidCommMessage>(message, VerificationContextTag.Create(senderKeyId))
            : null;

        return new DidCommEncryptedUnpackResult(true, message, verified, mode, senderKeyId, isSenderAuthenticated, isSignedInner, isRecipientAddressedInTo, isRotation, priorDid, rotationIat, DidCommDecryptionError.None);
    }


    //Mints a failed result carrying the rejection reason and the (already known) mode.
    internal static DidCommEncryptedUnpackResult Failed(DidCommEncryptionMode mode, DidCommDecryptionError error)
    {
        return new DidCommEncryptedUnpackResult(false, message: null, verified: null, mode, senderKeyId: null, isSenderAuthenticated: false, isSignedInner: false, isRecipientAddressedInTo: false, isRotation: false, priorDid: null, rotationIat: null, error);
    }
}
