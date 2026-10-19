namespace Verifiable.Core.Model.SelectiveDisclosure;

/// <summary>
/// The refusal of an SD-JWT's compact serialization by the reading that owns its wire shape (RFC 9901 sections 4 and 7.1): an
/// Issuer-signed JWT or Key Binding JWT that is no compact JWS, a disclosure that is no base64url text, no JSON array of two or
/// three elements, or carries a salt or a claim name that is no JSON string, two disclosures under one salt, a payload whose
/// digests break the section 7.1 rules, or a disclosure no digest references. It is a <see cref="FormatException"/>, so a caller
/// catching that keeps catching it; a caller telling the wire's refusal apart from a fault of a delegate it supplied - a decoder
/// beyond its refusal of text as no base64url, an encoder, a digest implementation - or from cancellation catches this type,
/// which the reading raises for its own refusals alone and never wraps another failure in.
/// </summary>
public sealed class SdJwtWireFormatException : FormatException
{
    /// <summary>Initializes a refusal of an SD-JWT's wire shape.</summary>
    public SdJwtWireFormatException() : base("The SD-JWT's compact serialization is not of the shape RFC 9901 defines.")
    {
    }


    /// <summary>Initializes a refusal of an SD-JWT's wire shape with its description.</summary>
    /// <param name="message">The refusal's description.</param>
    public SdJwtWireFormatException(string message) : base(message)
    {
    }


    /// <summary>Initializes a refusal of an SD-JWT's wire shape with its description and the refusal of the part it rests on.</summary>
    /// <param name="message">The refusal's description.</param>
    /// <param name="innerException">The refusal of the part: the decoder's refusal of text as no base64url, or the JSON reader's of a document.</param>
    public SdJwtWireFormatException(string message, Exception innerException) : base(message, innerException)
    {
    }
}
