namespace Verifiable.JCose;

/// <summary>Why a JWK states no public key the library reconstructs (RFC 7517 section 4, RFC 7518 section 6).</summary>
public enum JwkPublicKeyFailureKind
{
    /// <summary>A member the key's type requires is absent or carried as no string: <c>kty</c>, or <c>x</c>, <c>y</c>, <c>n</c> or <c>pub</c>.</summary>
    MemberAbsent,

    /// <summary>The <c>kty</c> names a key type the library reconstructs no key of.</summary>
    UnsupportedKeyType,

    /// <summary>The key's curve, algorithm or size is none the library reconstructs a key of its type for.</summary>
    UnsupportedCurveOrAlgorithm,

    /// <summary>
    /// The coordinates of an EC key name no point of its curve: <c>x</c> and <c>y</c> are not each the full width of the curve's
    /// coordinate (RFC 7518 sections 6.2.1.2 and 6.2.1.3), or the point they name does not lie on the curve (NIST SP 800-186
    /// appendix D.1.1.1).
    /// </summary>
    NotAPointOfTheCurve
}


/// <summary>
/// The refusal of a JWK by the library's own reconstruction of the public key it states, with a typed reason. It is an
/// <see cref="ArgumentException"/>, the JWK being the argument refused; a caller telling the reconstruction's refusal apart from
/// a fault of a delegate it supplied, the decoder or the allocator, catches this type, never <see cref="ArgumentException"/>.
/// </summary>
public sealed class JwkPublicKeyException : ArgumentException
{
    /// <summary>Gets the reason the JWK was refused.</summary>
    public JwkPublicKeyFailureKind FailureKind { get; }


    /// <summary>Initializes a refusal of a key whose type the library reconstructs no key of.</summary>
    public JwkPublicKeyException() : this(JwkPublicKeyFailureKind.UnsupportedKeyType, "The JWK states no public key the library reconstructs.")
    {
    }


    /// <summary>Initializes a refusal of a key whose type the library reconstructs no key of, with a description.</summary>
    /// <param name="message">The refusal description.</param>
    public JwkPublicKeyException(string message) : this(JwkPublicKeyFailureKind.UnsupportedKeyType, message)
    {
    }


    /// <summary>Initializes a refusal of a key whose type the library reconstructs no key of, with its cause.</summary>
    /// <param name="message">The refusal description.</param>
    /// <param name="innerException">The cause of the refusal.</param>
    public JwkPublicKeyException(string message, Exception innerException)
        : this(JwkPublicKeyFailureKind.UnsupportedKeyType, message, innerException)
    {
    }


    /// <summary>Initializes a refusal with its typed reason.</summary>
    /// <param name="failureKind">The reason the JWK was refused.</param>
    /// <param name="message">The refusal description.</param>
    public JwkPublicKeyException(JwkPublicKeyFailureKind failureKind, string message) : base(message)
    {
        FailureKind = failureKind;
    }


    /// <summary>Initializes a refusal with its typed reason and cause.</summary>
    /// <param name="failureKind">The reason the JWK was refused.</param>
    /// <param name="message">The refusal description.</param>
    /// <param name="innerException">The cause of the refusal.</param>
    public JwkPublicKeyException(JwkPublicKeyFailureKind failureKind, string message, Exception innerException)
        : base(message, innerException)
    {
        FailureKind = failureKind;
    }
}
