using System.Diagnostics;

namespace Verifiable.Fido2;

/// <summary>
/// A credential type and signature algorithm pair a relying party is willing to accept for a new
/// credential.
/// </summary>
/// <remarks>
/// <see href="https://www.w3.org/TR/webauthn-3/#dictionary-credential-params">W3C Web Authentication
/// Level 3, section 5.4: PublicKeyCredentialCreationOptions Dictionary, dictionary
/// <c>PublicKeyCredentialParameters</c></see>.
/// </remarks>
[DebuggerDisplay("PublicKeyCredentialParameters(Type={Type}, Alg={Alg})")]
public sealed record PublicKeyCredentialParameters
{
    /// <summary>
    /// The credential type, per <see cref="WellKnownPublicKeyCredentialTypes"/>.
    /// </summary>
    public required string Type { get; init; }

    /// <summary>
    /// The COSE algorithm identifier, per
    /// <see href="https://www.w3.org/TR/webauthn-3/#typedefdef-cosealgorithmidentifier">section
    /// 5.8.5: Cryptographic Algorithm Identifier (typedef <c>COSEAlgorithmIdentifier</c>)</see> — a
    /// <c>long</c> in the CR's own WebIDL, matching a C# <see cref="int"/>. See
    /// <see cref="Verifiable.JCose.WellKnownCoseAlgorithms"/> for the registered values.
    /// </summary>
    public required int Alg { get; init; }
}
