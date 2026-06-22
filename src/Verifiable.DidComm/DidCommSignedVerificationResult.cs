using Verifiable.Core;
using Verifiable.Cryptography;

namespace Verifiable.DidComm;

/// <summary>
/// The reason a DIDComm signed message failed verification, or <see cref="None"/> when it verified.
/// </summary>
/// <remarks>
/// The verifier is fail-closed: every value other than <see cref="None"/> denotes a rejected message
/// whose payload MUST NOT be trusted. The distinctions exist so a caller (and the conformance tests)
/// can tell an addressing-consistency violation from a cryptographic failure from a resolution
/// problem; none of them is more "valid" than another.
/// </remarks>
public enum DidCommSignatureVerificationError
{
    /// <summary>The message verified; its payload may be trusted.</summary>
    None = 0,

    /// <summary>
    /// The input is not a JWS JSON serialization (General or Flattened) — including a compact JWS,
    /// which a DIDComm signed message MUST NOT use (DIDComm v2.1 §DIDComm Signed Messages), and any
    /// other non-JWS input.
    /// </summary>
    MalformedEnvelope,

    /// <summary>
    /// The envelope carries more than one signature. A DIDComm signed message conveys the single
    /// sender signature; multi-signature envelopes are outside this profile and are rejected.
    /// </summary>
    MultipleSignatures,

    /// <summary>The signed-over payload is not a structurally valid DIDComm plaintext message.</summary>
    InvalidPlaintext,

    /// <summary>The signed plaintext lacks a <c>from</c> header, so the signer cannot be bound to it.</summary>
    MissingFrom,

    /// <summary>The signature lacks a <c>kid</c> in its unprotected header, so the signing key cannot be located.</summary>
    MissingKid,

    /// <summary>
    /// The integrity-protected <c>typ</c> is not <c>application/didcomm-signed+json</c>
    /// (DIDComm v2.1 §DIDComm Signed Messages).
    /// </summary>
    UnexpectedMediaType,

    /// <summary>
    /// The plaintext <c>from</c> does not match the signer's <c>kid</c> DID — the
    /// addressing-consistency MUST (DIDComm v2.1: "The from attribute in the plaintext message MUST
    /// match the signer's kid in a signed message.").
    /// </summary>
    FromKidMismatch,

    /// <summary>The signer DID could not be resolved to a DID document.</summary>
    SignerResolutionFailed,

    /// <summary>
    /// The <c>kid</c> is not authorized for the <c>authentication</c> verification relationship in the
    /// resolved DID document, so the message is rejected regardless of cryptographic validity
    /// (DIDComm v2.1 §Verification).
    /// </summary>
    KidNotAuthenticated,

    /// <summary>The cryptographic signature did not verify against the resolved key.</summary>
    SignatureInvalid,

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
/// The outcome of verifying a DIDComm signed message — the verified plaintext and signer when
/// <see cref="IsVerified"/> is <see langword="true"/>, or a <see cref="Error"/> reason otherwise.
/// </summary>
/// <remarks>
/// <para>
/// Mint-only: the constructor is <see langword="private"/> and the factories are
/// <see langword="internal"/>, so a result with <see cref="IsVerified"/> <see langword="true"/> can
/// only originate from this library's verification path — application code cannot fabricate a
/// "verified" result around an unverified message. This mirrors the JOSE layer's
/// <c>JwsVerificationResult</c> trust-carrier pattern.
/// </para>
/// <para>
/// The proof of verification is carried as a <see cref="Verified{T}"/> — the family-wide
/// proof-of-verification type minted only by a first-party verify library (this library is granted
/// <c>InternalsVisibleTo</c> by <c>Verifiable.Cryptography</c>). A signed message is always
/// authenticated, so <see cref="Verified"/> is present whenever <see cref="IsVerified"/> is
/// <see langword="true"/>, and <see cref="Message"/> is simply its <see cref="Verified{T}.Value"/>.
/// </para>
/// </remarks>
public sealed class DidCommSignedVerificationResult
{
    private DidCommSignedVerificationResult(
        bool isVerified,
        Verified<DidCommMessage>? verified,
        string? signerKid,
        bool isToHeaderPresent,
        bool isRotation,
        string? priorDid,
        long? rotationIat,
        DidCommSignatureVerificationError error)
    {
        IsVerified = isVerified;
        Verified = verified;
        SignerKid = signerKid;
        IsToHeaderPresent = isToHeaderPresent;
        IsRotation = isRotation;
        PriorDid = priorDid;
        RotationIat = rotationIat;
        Error = error;
    }


    /// <summary>Whether the signature verified and every addressing-consistency check passed.</summary>
    public bool IsVerified { get; }

    /// <summary>
    /// The proof that the message was verified — the authenticated plaintext wrapped in a
    /// <see cref="Verified{T}"/> — or <see langword="null"/> when verification failed. A trusted consumer
    /// API that accepts a <see cref="Verified{T}"/> therefore cannot be handed an unverified message.
    /// </summary>
    public Verified<DidCommMessage>? Verified { get; }

    /// <summary>The verified plaintext message (the <see cref="Verified"/> proof's value), or <see langword="null"/> when verification failed.</summary>
    public DidCommMessage? Message => Verified?.Value;

    /// <summary>The verified signer key identifier (the <c>kid</c>), or <see langword="null"/> when verification failed.</summary>
    public string? SignerKid { get; }

    /// <summary>
    /// Whether the verified message carried a <c>to</c> header. A signed message SHOULD carry one to
    /// guard against surreptitious forwarding (DIDComm v2.1 §DIDComm Signed Messages); its absence is
    /// not a verification failure but is surfaced so a caller can apply the SHOULD. Meaningful only
    /// when <see cref="IsVerified"/> is <see langword="true"/>.
    /// </summary>
    public bool IsToHeaderPresent { get; }

    /// <summary>
    /// Whether the verified message carried a <c>from_prior</c> DID Rotation that itself verified — the
    /// sender switched from <see cref="PriorDid"/> to the new DID (the message <c>from</c>). The new DID
    /// and its DID document MUST be used for further communication (DIDComm v2.1 §DID Rotation). Meaningful
    /// only when <see cref="IsVerified"/> is <see langword="true"/>.
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

    /// <summary>The reason verification failed, or <see cref="DidCommSignatureVerificationError.None"/> when it succeeded.</summary>
    public DidCommSignatureVerificationError Error { get; }


    //Mints a verified result, wrapping the authenticated message in a Verified<DidCommMessage> proof tagged with the
    //signer's verification context. Internal so only the library's verification path can produce one. A verified
    //from_prior rotation surfaces the prior DID; a message without one (or with one that was not present) is a
    //non-rotation result.
    internal static DidCommSignedVerificationResult Success(DidCommMessage message, string signerKid, bool isToHeaderPresent, bool isRotation = false, string? priorDid = null, long? rotationIat = null)
    {
        var verified = new Verified<DidCommMessage>(message, VerificationContextTag.Create(signerKid));

        return new DidCommSignedVerificationResult(true, verified, signerKid, isToHeaderPresent, isRotation, priorDid, rotationIat, DidCommSignatureVerificationError.None);
    }


    //Mints a failed result carrying the rejection reason.
    internal static DidCommSignedVerificationResult Failed(DidCommSignatureVerificationError error)
    {
        return new DidCommSignedVerificationResult(false, verified: null, signerKid: null, isToHeaderPresent: false, isRotation: false, priorDid: null, rotationIat: null, error);
    }
}
