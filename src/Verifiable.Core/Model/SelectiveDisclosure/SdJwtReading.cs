namespace Verifiable.Core.Model.SelectiveDisclosure;

/// <summary>
/// The part of an SD-JWT's compact serialization (RFC 9901 sections 4 and 7.1) its reading refuses, each a wire shape no
/// conformant Issuer or Holder produces.
/// </summary>
public enum SdJwtWireDefect
{
    /// <summary>The serialization carries no <c>~</c> after the Issuer-signed JWT (RFC 9901 section 4).</summary>
    SeparatorMissing,

    /// <summary>A component between the Issuer-signed JWT and the last <c>~</c> is empty: two separators follow each other.</summary>
    ComponentEmpty,

    /// <summary>A compact JWS stands among the disclosures: a Key Binding JWT that is repeated or not the final component.</summary>
    KeyBindingJwtNotFinal,

    /// <summary>The final component is neither empty, which the closing <c>~</c> of an SD-JWT leaves, nor one Key Binding JWT.</summary>
    TerminatorMissing,

    /// <summary>The Issuer-signed JWT is no compact JWS of three base64url segments (RFC 7515 section 7.1).</summary>
    IssuerJwtNotCompactJws,

    /// <summary>The Issuer-signed JWT's payload segment is no base64url text (RFC 7515 section 7.1).</summary>
    PayloadNotBase64UrlText,

    /// <summary>The Issuer-signed JWT's payload is not valid JSON (RFC 7519 section 7.2).</summary>
    PayloadNotJson,

    /// <summary>A disclosure is no base64url text (RFC 9901 section 4.2).</summary>
    DisclosureNotBase64UrlText,

    /// <summary>A disclosure's decoded text is not valid JSON (RFC 9901 section 4.2).</summary>
    DisclosureNotJson,

    /// <summary>A disclosure is no JSON array (RFC 9901 section 4.2).</summary>
    DisclosureNotAnArray,

    /// <summary>A disclosure array has another number of elements than two or three (RFC 9901 sections 4.2.1 and 4.2.2).</summary>
    DisclosureElementCount,

    /// <summary>A disclosure's salt is no JSON string (RFC 9901 section 4.2.1).</summary>
    SaltNotAString,

    /// <summary>A disclosure's claim name is no JSON string (RFC 9901 section 4.2.1).</summary>
    ClaimNameNotAString,

    /// <summary>Two disclosures carry the same salt (RFC 9901 section 9.3).</summary>
    SaltRepeated,

    /// <summary>A digest in an object's <c>_sd</c> array resolves to an array-element disclosure (RFC 9901 section 7.1 step 3.c.ii.1).</summary>
    ObjectDigestOfArrayElementDisclosure,

    /// <summary>A disclosure resolved into an object names <c>_sd</c> or <c>...</c> (RFC 9901 sections 4.2.1 and 7.1 step 3.c.ii.2).</summary>
    MechanismClaimName,

    /// <summary>A disclosure resolved into an object names a claim its level already carries (RFC 9901 section 7.1 step 3.c.ii.3).</summary>
    ClaimNameRepeated,

    /// <summary>A digest in an array resolves to an object-property disclosure (RFC 9901 section 7.1 step 3.c.iii.1).</summary>
    ArrayDigestOfPropertyDisclosure,

    /// <summary>A digest value is encountered more than once in the payload and the disclosures (RFC 9901 section 7.1 step 4).</summary>
    DigestRepeated,

    /// <summary>The payload's nesting of containers and recursive disclosures exceeds the depth the reading admits (RFC 9901 section 4.2.6).</summary>
    NestingTooDeep,

    /// <summary>A disclosure is referenced by no digest in the payload or in another disclosure (RFC 9901 section 7.1 step 5).</summary>
    DisclosureUnreferenced
}


/// <summary>What the reading of an SD-JWT's compact serialization answers: the token it reads, or the refusal of its wire shape.</summary>
public abstract record SdJwtReading;


/// <summary>The token an SD-JWT's compact serialization states, read; the receiver owns and disposes it.</summary>
/// <param name="Token">The token.</param>
public sealed record SdJwtRead(SdToken<string> Token) : SdJwtReading;


/// <summary>The refusal of an SD-JWT's compact serialization: the part refused and its description.</summary>
/// <param name="Defect">The part of the serialization refused.</param>
/// <param name="Description">The refusal's description, naming the rule the wire breaks.</param>
public sealed record SdJwtRefused(SdJwtWireDefect Defect, string Description) : SdJwtReading;


/// <summary>What the reading of one SD-JWT disclosure answers: the disclosure it reads, or the refusal of its wire shape.</summary>
public abstract record SdDisclosureReading;


/// <summary>The disclosure a base64url disclosure text states, read; the receiver owns and disposes it.</summary>
/// <param name="Disclosure">The disclosure.</param>
public sealed record SdDisclosureRead(SdDisclosure Disclosure) : SdDisclosureReading;


/// <summary>The refusal of a disclosure's wire shape: the part refused and its description.</summary>
/// <param name="Defect">The part of the disclosure refused.</param>
/// <param name="Description">The refusal's description, naming the rule the wire breaks.</param>
public sealed record SdDisclosureRefused(SdJwtWireDefect Defect, string Description) : SdDisclosureReading;
