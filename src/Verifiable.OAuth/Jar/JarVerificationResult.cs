namespace Verifiable.OAuth.Jar;

/// <summary>
/// Discriminated-union result returned by <see cref="JarVerification.VerifyAsync"/>.
/// </summary>
/// <remarks>
/// JAR verification can fail at multiple layers — JWS signature, JOSE
/// header validity, JWT timing claims — and each failure category maps
/// to a distinct OAuth wire error code per
/// <see href="https://www.rfc-editor.org/rfc/rfc9101#section-5">RFC 9101 §5</see>.
/// A throwing API forces every caller to catch and translate; a
/// discriminated-union result makes the error mapping explicit at the
/// call site.
/// </remarks>
public abstract record JarVerificationResult;
