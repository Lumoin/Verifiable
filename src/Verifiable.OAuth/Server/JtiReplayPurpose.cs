using System.Diagnostics;

namespace Verifiable.OAuth.Server;

/// <summary>
/// The kind of presented object a <c>jti</c> (or a one-time value handled the same way) identifies,
/// the domain <see cref="JtiReplayGuard.CorrelationKey(JtiReplayPurpose, string, string?, string)"/> keeps its replay records apart by.
/// </summary>
/// <remarks>
/// Each specification scopes the uniqueness of its identifier to its own kind of object: a request
/// object's <c>jti</c> is unique among request objects, a DPoP proof's among DPoP proofs
/// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.2">RFC 9449 §4.2</see>: "negligible
/// probability that the same value will be assigned to any other DPoP proof used in the same
/// context"), an assertion's among the assertions its issuer makes. The identifiers of two kinds can
/// coincide, for example when a client's <c>client_id</c> equals the issuer a DPoP proof is recorded
/// under, and neither object is then a replay of the other. The purpose is therefore part of every
/// replay record's key.
/// </remarks>
[DebuggerDisplay("JtiReplayPurpose={ToString(),nq}")]
public enum JtiReplayPurpose
{
    /// <summary>
    /// The <c>jti</c> of a JWT-Secured Authorization Request object
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9101#section-10.2">RFC 9101 §10.2</see>).
    /// </summary>
    RequestObject,

    /// <summary>
    /// The <c>jti</c> of a DPoP proof at the token endpoint or at a protected resource of the same
    /// authorization server, recorded per target URI
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-11.1">RFC 9449 §11.1</see>: "In the
    /// context of the target URI, servers can store the jti value of each DPoP proof").
    /// </summary>
    DpopProof,

    /// <summary>
    /// The <c>jti</c> of a JWT used as an authorization grant, including an Identity Assertion JWT
    /// Authorization Grant (<see href="https://www.rfc-editor.org/rfc/rfc7523#section-3">RFC 7523 §3</see> item 7).
    /// </summary>
    AuthorizationGrantAssertion,

    /// <summary>
    /// The <c>jti</c> of a JWT used for client authentication, <c>private_key_jwt</c>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc7523#section-3">RFC 7523 §3</see> item 7).
    /// </summary>
    ClientAssertion,

    /// <summary>The <c>nonce</c> of a Self-Issued OpenID Provider response, recorded once per audience.</summary>
    SelfIssuedResponseNonce
}
