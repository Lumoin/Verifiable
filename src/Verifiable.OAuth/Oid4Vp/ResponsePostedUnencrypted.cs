using System;
using System.Diagnostics;

namespace Verifiable.OAuth.Oid4Vp;

/// <summary>
/// Carries the plaintext <c>vp_token</c> received from the Wallet's
/// unencrypted <c>direct_post</c> POST per
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.2">OID4VP 1.0 §8.2</see>.
/// Sibling to <see cref="ResponsePosted"/> (which carries the encrypted
/// <c>direct_post.jwt</c> JWE); the two inputs let the PDA's
/// <see cref="VerifierJarServedState"/> dispatch on
/// <see cref="AuthorizationRequestObject.ResponseMode"/> at response time.
/// </summary>
/// <remarks>
/// HAIP 1.0 §5.1 mandates encrypted responses; this input is for non-HAIP
/// profiles or deployments that explicitly advertise <c>response_mode=direct_post</c>.
/// </remarks>
/// <param name="VpTokenJson">
/// The raw <c>vp_token</c> JSON string the Wallet POSTed in the
/// <c>vp_token</c> form field. Per OID4VP 1.0 §8.1 this is a JSON object
/// whose keys are DCQL credential query identifiers and whose values are
/// arrays of compact presentations.
/// </param>
/// <param name="ReceivedAt">The UTC instant the POST was received.</param>
[DebuggerDisplay("ResponsePostedUnencrypted ReceivedAt={ReceivedAt}")]
public sealed record ResponsePostedUnencrypted(
    string VpTokenJson,
    DateTimeOffset ReceivedAt): OAuthFlowInput;
