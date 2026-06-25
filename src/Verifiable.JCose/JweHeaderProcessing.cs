namespace Verifiable.JCose;

/// <summary>
/// JWE protected-header processing applied at every parse boundary: the duplicate-name and
/// rejected-by-design algorithm guards (<c>RSA1_5</c> per RFC 8725 §3.2, <c>zip</c> per RFC 8725 §3.6 /
/// RFC 7516 §4.1.3), and <c>crit</c> validation delegated to <see cref="JoseCriticalHeaderValidation"/>
/// (the shared RFC 7515 §4.1.11 / RFC 7516 §4.1.13 rule set used by both JWE and JWS).
/// </summary>
/// <remarks>
/// <para>
/// RFC 7516 §5.2 step 5 requires a consumer to verify that it understands and can process all fields it
/// is required to support, including those named by the <c>crit</c> Header Parameter. This library
/// understands no JWE header extensions beyond the registered parameters, so any <c>crit</c> entry naming
/// an unregistered extension is unsupported and the message MUST be rejected unless the caller declares
/// that extension understood; an entry naming a registered parameter violates the RFC 7515 §4.1.11
/// producer rule and MUST always be rejected.
/// </para>
/// <para>
/// The header is read through the library's own span reader (<see cref="JwkJsonReader"/>); there is no
/// JSON-serialization dependency in this project.
/// </para>
/// </remarks>
public static class JweHeaderProcessing
{
    /// <summary>
    /// Validates the protected-header <c>crit</c> parameter and the rejected-by-design algorithm guards
    /// over the decoded protected header JSON, understanding no <c>crit</c> extension.
    /// </summary>
    /// <remarks>
    /// Call after the <c>alg</c>/<c>enc</c> have been extracted but before any cryptographic work, so an
    /// unprocessable message is rejected before key agreement runs (RFC 7516 §5.2 step 5 precedes steps
    /// 6–16). Use <see cref="Validate(ReadOnlySpan{byte}, string, IReadOnlySet{string})"/> to declare a
    /// set of <c>crit</c> extensions the caller processes.
    /// </remarks>
    /// <param name="headerJson">The decoded UTF-8 protected header JSON bytes.</param>
    /// <param name="algorithm">The already-extracted <c>alg</c> value.</param>
    /// <exception cref="FormatException">
    /// Thrown when the header has duplicate parameter names; when <c>crit</c> is malformed, empty, lists a
    /// registered parameter, lists a parameter not present in the header, or names an extension this
    /// implementation does not understand; when <c>RSA1_5</c> is the key management algorithm; or when a
    /// <c>zip</c> parameter is present.
    /// </exception>
    public static void Validate(ReadOnlySpan<byte> headerJson, string algorithm) =>
        Validate(headerJson, algorithm, JoseCriticalHeaderValidation.NoUnderstoodExtensions);


    /// <summary>
    /// Validates the protected-header <c>crit</c> parameter and the rejected-by-design algorithm guards,
    /// accepting a set of <c>crit</c> extensions the caller understands.
    /// </summary>
    /// <param name="headerJson">The decoded UTF-8 protected header JSON bytes.</param>
    /// <param name="algorithm">The already-extracted <c>alg</c> value.</param>
    /// <param name="understoodCriticalExtensions">
    /// The set of <c>crit</c> extension names the caller declares it understands and processes.
    /// </param>
    /// <exception cref="FormatException">
    /// Thrown for the same reasons as <see cref="Validate(ReadOnlySpan{byte}, string)"/>, except that a
    /// critical entry present in <paramref name="understoodCriticalExtensions"/> is accepted.
    /// </exception>
    public static void Validate(
        ReadOnlySpan<byte> headerJson,
        string algorithm,
        IReadOnlySet<string> understoodCriticalExtensions)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(algorithm);
        ArgumentNullException.ThrowIfNull(understoodCriticalExtensions);

        if(JwkJsonReader.HasDuplicateTopLevelKeys(headerJson))
        {
            //RFC 7516 §4 ("The Header Parameter names within the JOSE Header MUST be unique") and §5.2
            //step 4. The library reads each parameter by first occurrence; without this gate a header
            //repeating "alg" would be processed with the first value while a last-value JSON parser
            //elsewhere would disagree — the validate-one/act-on-another divergence this check closes.
            throw new FormatException(
                "JWE protected header contains duplicate Header Parameter names, which MUST be "
                + "unique (RFC 7516 §4 / §5.2 step 4).");
        }

        RejectForbiddenAlgorithm(algorithm);

        if(JwkJsonReader.ContainsKey(headerJson, "zip"u8))
        {
            //RFC 8725 §3.6: compression before encryption reveals information about the plaintext (a
            //length oracle). This library rejects any JWE carrying "zip" rather than expanding it.
            throw new FormatException(
                "JWE tokens with a 'zip' compression parameter are rejected: compressing the "
                + "plaintext before encryption leaks plaintext length and enables compression "
                + "oracles (RFC 8725 §3.6).");
        }

        JoseCriticalHeaderValidation.Validate(headerJson, understoodCriticalExtensions);
    }


    /// <summary>
    /// Rejects key management algorithms this library refuses by design.
    /// </summary>
    /// <param name="algorithm">The <c>alg</c> value.</param>
    /// <exception cref="FormatException">Thrown when <paramref name="algorithm"/> is <c>RSA1_5</c>.</exception>
    public static void RejectForbiddenAlgorithm(string algorithm)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(algorithm);

        if(WellKnownJweAlgorithms.IsRsa15(algorithm))
        {
            //RFC 8725 §3.2: "Avoid all RSA-PKCS1 v1.5 encryption algorithms, preferring RSAES-OAEP."
            //RSAES-PKCS1-v1_5 (RSA1_5) is vulnerable to Bleichenbacher-style adaptive chosen-ciphertext
            //(million-message) attacks, so this library refuses it.
            throw new FormatException(
                "The 'RSA1_5' (RSAES-PKCS1-v1_5) key management algorithm is rejected: it is "
                + "vulnerable to Bleichenbacher adaptive chosen-ciphertext attacks and MUST be "
                + "avoided in favour of RSAES-OAEP (RFC 8725 §3.2).");
        }
    }
}
