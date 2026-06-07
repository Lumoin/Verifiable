using Verifiable.Cryptography;

namespace Verifiable.Core.Model.SelectiveDisclosure;

/// <summary>
/// Resolves an SD-CWT issuer's public key from its identifier (the embedded
/// SD-CWT <c>iss</c> claim, CWT claim 1). The application provides the
/// implementation based on its trust framework (for example a COSE key set
/// endpoint, OpenID Federation, or an X.509 trust list).
/// </summary>
/// <remarks>
/// <para>
/// Composed by <c>KbCwtVerification.VerifyAsync</c> to obtain the key the embedded
/// SD-CWT credential's issuer COSE_Sign1 signature is verified against.
/// </para>
/// </remarks>
/// <param name="issuerId">The <c>iss</c> claim from the embedded SD-CWT credential.</param>
/// <returns>The issuer's public key, or <see langword="null"/> if the issuer is not trusted.</returns>
public delegate PublicKeyMemory? ResolveSdCwtIssuerKeyDelegate(string issuerId);
