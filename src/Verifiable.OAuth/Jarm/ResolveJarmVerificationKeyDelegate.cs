using Verifiable.Cryptography;

namespace Verifiable.OAuth.Jarm;

/// <summary>
/// Resolves the Authorization Server key a client verifies a JWT-secured authorization
/// response with, per
/// <see href="https://openid.net/specs/oauth-v2-jarm-final.html#section-2.4">JARM §2.4</see>.
/// </summary>
/// <remarks>
/// <para>
/// How the client obtains the AS's keys is out of JARM's scope; established mechanisms
/// such as OpenID Connect Discovery or RFC 8414 metadata (<c>jwks_uri</c>) SHOULD be
/// used. The application supplies that machinery here.
/// </para>
/// <para>
/// <see cref="JarmResponseValidation"/> only invokes this delegate after the <c>iss</c>
/// claim matched the expected issuer — the JARM §5.1 defence against specially crafted
/// JWTs steering the client to resolve hostile JWK set URLs.
/// </para>
/// <para>
/// The caller takes ownership of the returned key and disposes it after signature
/// verification.
/// </para>
/// </remarks>
/// <param name="issuer">The already-vetted issuer the response claims to come from.</param>
/// <param name="keyId">The <c>kid</c> from the response JWT's protected header, or <see langword="null"/> when absent.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>
/// The verification key, or <see langword="null"/> when no key matches — the response
/// then fails signature validation.
/// </returns>
public delegate ValueTask<PublicKeyMemory?> ResolveJarmVerificationKeyDelegate(
    string issuer,
    string? keyId,
    CancellationToken cancellationToken);
