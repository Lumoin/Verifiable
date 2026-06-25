namespace Verifiable.OAuth.Oid4Vci;

/// <summary>
/// The outcome of resolving an OID4VCI JWS's §F.1 <c>jwk</c>/<c>x5c</c>/<c>kid</c> header key
/// reference (<see cref="Oid4VciHeaderKeyResolution"/>). Each caller maps these to its own
/// validation failure reason.
/// </summary>
internal enum HeaderKeyResolutionStatus
{
    /// <summary>The key was reconstructed; the outcome carries it.</summary>
    Resolved,

    /// <summary>The mutually-exclusive trio names more than one member or none, or the <c>jwk</c> is not a readable public key.</summary>
    InvalidKeyReference,

    /// <summary>The <c>jwk</c> header carries private or symmetric key material.</summary>
    JwkContainsPrivateKey,

    /// <summary>A <c>kid</c>/<c>x5c</c> reference could not be dereferenced — no resolver, missing trust material, or a chain that did not validate.</summary>
    KeyReferenceUnresolved
}
