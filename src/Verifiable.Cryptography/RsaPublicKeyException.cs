using System.Security.Cryptography;

namespace Verifiable.Cryptography;

/// <summary>The reason an RSA public key could not be read or encoded.</summary>
public enum RsaPublicKeyFailureKind
{
    /// <summary>The input is not exactly one DER PKCS#1 RSA public key.</summary>
    MalformedEncoding,

    /// <summary>The modulus is not a positive integer.</summary>
    InvalidModulus,

    /// <summary>The public exponent is not an odd integer satisfying <c>3 &lt;= e &lt; n</c>.</summary>
    InvalidPublicExponent
}


/// <summary>An RSA public-key conversion refusal with a typed reason.</summary>
public sealed class RsaPublicKeyException: CryptographicException
{
    /// <summary>Gets the reason the public key was refused.</summary>
    public RsaPublicKeyFailureKind FailureKind { get; }


    /// <summary>Initializes a malformed-encoding refusal.</summary>
    public RsaPublicKeyException() : this(RsaPublicKeyFailureKind.MalformedEncoding, "The RSA public-key encoding is malformed.")
    {
    }


    /// <summary>Initializes a malformed-encoding refusal with a description.</summary>
    /// <param name="message">The refusal description.</param>
    public RsaPublicKeyException(string message) : this(RsaPublicKeyFailureKind.MalformedEncoding, message)
    {
    }


    /// <summary>Initializes a malformed-encoding refusal with its cause.</summary>
    /// <param name="message">The refusal description.</param>
    /// <param name="innerException">The cause of the refusal.</param>
    public RsaPublicKeyException(string message, Exception innerException)
        : this(RsaPublicKeyFailureKind.MalformedEncoding, message, innerException)
    {
    }


    /// <summary>Initializes a refusal with its typed reason.</summary>
    /// <param name="failureKind">The reason the public key was refused.</param>
    /// <param name="message">The refusal description.</param>
    public RsaPublicKeyException(RsaPublicKeyFailureKind failureKind, string message) : base(message)
    {
        FailureKind = failureKind;
    }


    /// <summary>Initializes a refusal with its typed reason and cause.</summary>
    /// <param name="failureKind">The reason the public key was refused.</param>
    /// <param name="message">The refusal description.</param>
    /// <param name="innerException">The cause of the refusal.</param>
    public RsaPublicKeyException(RsaPublicKeyFailureKind failureKind, string message, Exception innerException)
        : base(message, innerException)
    {
        FailureKind = failureKind;
    }
}
