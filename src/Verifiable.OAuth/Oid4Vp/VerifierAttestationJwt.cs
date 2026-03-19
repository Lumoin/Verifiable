using System.Diagnostics;

namespace Verifiable.OAuth.Oid4Vp;

/// <summary>
/// A Verifier Attestation JWT extracted from the <c>jwt</c> JOSE header parameter of a
/// signed JAR, as defined in
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-12">OID4VP 1.0 §12</see>.
/// </summary>
/// <remarks>
/// <para>
/// The Verifier Attestation JWT is issued by a trust anchor known to the Wallet. It
/// proves that the Verifier is a legitimate client registered within a trust framework.
/// </para>
/// <para>
/// The Wallet must validate this JWT before accepting the JAR:
/// </para>
/// <list type="number">
///   <item><description>
///     Verify the JWT signature against the trust anchor's published key.
///   </description></item>
///   <item><description>
///     Check that the <c>sub</c> claim equals the <c>client_id</c> (minus the
///     <c>verifier_attestation:</c> prefix).
///   </description></item>
///   <item><description>
///     Check that the public key in the <c>cnf</c> claim matches the key used to sign
///     the JAR — this is the proof of possession binding the attestation to the request.
///   </description></item>
///   <item><description>
///     Verify expiry (<c>exp</c>) and, if present, that the <c>redirect_uris</c> claim
///     contains the JAR's <c>response_uri</c>.
///   </description></item>
/// </list>
/// <para>
/// Validation is performed by a <see cref="VerifierAttestationValidationDelegate"/>
/// supplied by the application. The library provides the parsed JWT string; the
/// application provides the trust anchor key and the validation logic.
/// </para>
/// </remarks>
[DebuggerDisplay("VerifierAttestationJwt CompactJwt={CompactJwt}")]
public sealed class VerifierAttestationJwt
{
    /// <summary>
    /// The compact JWT string extracted from the <c>jwt</c> JOSE header parameter.
    /// </summary>
    public string CompactJwt { get; }


    /// <summary>
    /// Creates a new <see cref="VerifierAttestationJwt"/> from the extracted header value.
    /// </summary>
    /// <param name="compactJwt">The compact JWT string from the <c>jwt</c> JOSE header.</param>
    public VerifierAttestationJwt(string compactJwt)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(compactJwt);
        CompactJwt = compactJwt;
    }
}
