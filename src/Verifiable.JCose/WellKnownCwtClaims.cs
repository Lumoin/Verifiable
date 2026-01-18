namespace Verifiable.JCose;

/// <summary>
/// CWT (CBOR Web Token) claim keys as defined in
/// <see href="https://www.iana.org/assignments/cwt/cwt.xhtml">IANA CWT Claims</see>.
/// </summary>
/// <remarks>
/// <para>
/// CWT uses integer keys for claims, unlike JWT which uses strings.
/// Standard claims are defined in RFC 8392.
/// </para>
/// <para>
/// See <see href="https://www.rfc-editor.org/rfc/rfc8392">RFC 8392 - CBOR Web Token (CWT)</see>.
/// </para>
/// </remarks>
public static class WellKnownCwtClaims
{
    /// <summary>
    /// Issuer (iss) claim.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Identifies the principal that issued the CWT.
    /// Value is tstr.
    /// </para>
    /// <para>
    /// See <see href="https://www.rfc-editor.org/rfc/rfc8392#section-3.1.1">RFC 8392 §3.1.1</see>.
    /// </para>
    /// </remarks>
    public const int Iss = 1;

    /// <summary>
    /// Subject (sub) claim.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Identifies the principal that is the subject of the CWT.
    /// Value is tstr.
    /// </para>
    /// <para>
    /// See <see href="https://www.rfc-editor.org/rfc/rfc8392#section-3.1.2">RFC 8392 §3.1.2</see>.
    /// </para>
    /// </remarks>
    public const int Sub = 2;

    /// <summary>
    /// Audience (aud) claim.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Identifies the recipients that the CWT is intended for.
    /// Value is tstr.
    /// </para>
    /// <para>
    /// See <see href="https://www.rfc-editor.org/rfc/rfc8392#section-3.1.3">RFC 8392 §3.1.3</see>.
    /// </para>
    /// </remarks>
    public const int Aud = 3;

    /// <summary>
    /// Expiration time (exp) claim.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Identifies the expiration time on or after which the CWT must not be accepted.
    /// Value is int or float (NumericDate).
    /// </para>
    /// <para>
    /// See <see href="https://www.rfc-editor.org/rfc/rfc8392#section-3.1.4">RFC 8392 §3.1.4</see>.
    /// </para>
    /// </remarks>
    public const int Exp = 4;

    /// <summary>
    /// Not before (nbf) claim.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Identifies the time before which the CWT must not be accepted.
    /// Value is int or float (NumericDate).
    /// </para>
    /// <para>
    /// See <see href="https://www.rfc-editor.org/rfc/rfc8392#section-3.1.5">RFC 8392 §3.1.5</see>.
    /// </para>
    /// </remarks>
    public const int Nbf = 5;

    /// <summary>
    /// Issued at (iat) claim.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Identifies the time at which the CWT was issued.
    /// Value is int or float (NumericDate).
    /// </para>
    /// <para>
    /// See <see href="https://www.rfc-editor.org/rfc/rfc8392#section-3.1.6">RFC 8392 §3.1.6</see>.
    /// </para>
    /// </remarks>
    public const int Iat = 6;

    /// <summary>
    /// CWT ID (cti) claim.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Provides a unique identifier for the CWT.
    /// Value is bstr. Equivalent to JWT "jti".
    /// </para>
    /// <para>
    /// See <see href="https://www.rfc-editor.org/rfc/rfc8392#section-3.1.7">RFC 8392 §3.1.7</see>.
    /// </para>
    /// </remarks>
    public const int Cti = 7;

    /// <summary>
    /// Confirmation (cnf) claim.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Contains confirmation methods such as proof-of-possession keys.
    /// Value is map. Used for key binding in SD-CWT.
    /// </para>
    /// <para>
    /// See <see href="https://www.rfc-editor.org/rfc/rfc8747">RFC 8747</see>.
    /// </para>
    /// </remarks>
    public const int Cnf = 8;

    /// <summary>
    /// Verifiable Credential Type (vct) claim.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Identifies the type of verifiable credential.
    /// Used in SD-JWT-VC and SD-CWT.
    /// </para>
    /// </remarks>
    public const int Vct = 11;

    /// <summary>
    /// Client nonce (cnonce) claim.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Nonce provided by the client. Used in key binding.
    /// </para>
    /// </remarks>
    public const int Cnonce = 39;


    /// <summary>
    /// Determines if the claim key is <see cref="Iss"/>.
    /// </summary>
    /// <param name="claimKey">The claim key.</param>
    /// <returns><see langword="true"/> if the claim is issuer; otherwise, <see langword="false"/>.</returns>
    public static bool IsIss(int claimKey) => claimKey == Iss;


    /// <summary>
    /// Determines if the claim key is <see cref="Sub"/>.
    /// </summary>
    /// <param name="claimKey">The claim key.</param>
    /// <returns><see langword="true"/> if the claim is subject; otherwise, <see langword="false"/>.</returns>
    public static bool IsSub(int claimKey) => claimKey == Sub;


    /// <summary>
    /// Determines if the claim key is <see cref="Aud"/>.
    /// </summary>
    /// <param name="claimKey">The claim key.</param>
    /// <returns><see langword="true"/> if the claim is audience; otherwise, <see langword="false"/>.</returns>
    public static bool IsAud(int claimKey) => claimKey == Aud;


    /// <summary>
    /// Determines if the claim key is <see cref="Exp"/>.
    /// </summary>
    /// <param name="claimKey">The claim key.</param>
    /// <returns><see langword="true"/> if the claim is expiration; otherwise, <see langword="false"/>.</returns>
    public static bool IsExp(int claimKey) => claimKey == Exp;


    /// <summary>
    /// Determines if the claim key is <see cref="Nbf"/>.
    /// </summary>
    /// <param name="claimKey">The claim key.</param>
    /// <returns><see langword="true"/> if the claim is not before; otherwise, <see langword="false"/>.</returns>
    public static bool IsNbf(int claimKey) => claimKey == Nbf;


    /// <summary>
    /// Determines if the claim key is <see cref="Iat"/>.
    /// </summary>
    /// <param name="claimKey">The claim key.</param>
    /// <returns><see langword="true"/> if the claim is issued at; otherwise, <see langword="false"/>.</returns>
    public static bool IsIat(int claimKey) => claimKey == Iat;


    /// <summary>
    /// Determines if the claim key is <see cref="Cti"/>.
    /// </summary>
    /// <param name="claimKey">The claim key.</param>
    /// <returns><see langword="true"/> if the claim is CWT ID; otherwise, <see langword="false"/>.</returns>
    public static bool IsCti(int claimKey) => claimKey == Cti;


    /// <summary>
    /// Determines if the claim key is <see cref="Cnf"/>.
    /// </summary>
    /// <param name="claimKey">The claim key.</param>
    /// <returns><see langword="true"/> if the claim is confirmation; otherwise, <see langword="false"/>.</returns>
    public static bool IsCnf(int claimKey) => claimKey == Cnf;


    /// <summary>
    /// Gets the claim name for a CWT claim key.
    /// </summary>
    /// <param name="claimKey">The CWT claim key.</param>
    /// <returns>The claim name, or null if unknown.</returns>
    public static string? GetClaimName(int claimKey) => claimKey switch
    {
        Iss => "iss",
        Sub => "sub",
        Aud => "aud",
        Exp => "exp",
        Nbf => "nbf",
        Iat => "iat",
        Cti => "cti",
        Cnf => "cnf",
        Vct => "vct",
        Cnonce => "cnonce",
        _ => null
    };


    /// <summary>
    /// Gets the CWT claim key for a JWT claim name.
    /// </summary>
    /// <param name="jwtClaimName">The JWT claim name.</param>
    /// <returns>The CWT claim key, or null if unknown.</returns>
    public static int? GetClaimKey(string jwtClaimName) => jwtClaimName switch
    {
        "iss" => Iss,
        "sub" => Sub,
        "aud" => Aud,
        "exp" => Exp,
        "nbf" => Nbf,
        "iat" => Iat,
        "jti" => Cti,
        "cnf" => Cnf,
        "vct" => Vct,
        "cnonce" => Cnonce,
        _ => null
    };
}