namespace Verifiable.JCose;

/// <summary>
/// Shared JWE protected-header processing applied at every parse boundary: <c>crit</c>
/// validation per RFC 7515 §4.1.11 / RFC 7516 §4.1.13, and the rejected-by-design algorithm
/// guards (<c>RSA1_5</c> per RFC 8725 §3.2, <c>zip</c> per RFC 8725 §3.6 / RFC 7516 §4.1.3).
/// </summary>
/// <remarks>
/// <para>
/// RFC 7516 §5.2 step 5 requires a consumer to verify that it understands and can process all
/// fields it is required to support, including those named by the <c>crit</c> Header Parameter.
/// This library understands no JWE header extensions beyond the registered parameters, so any
/// <c>crit</c> entry naming an unregistered extension is unsupported and the message MUST be
/// rejected unless the caller declares that extension understood; an entry naming a registered
/// parameter violates the RFC 7515 §4.1.11 producer rule and MUST always be rejected.
/// </para>
/// <para>
/// The validators read the already-decoded protected header JSON through the library's own
/// span reader (<see cref="JwkJsonReader"/>); there is no JSON-serialization dependency in this
/// project, so <c>crit</c> is read with <see cref="JwkJsonReader.ExtractStringArrayProperty"/>
/// rather than a deserializer.
/// </para>
/// </remarks>
public static class JweHeaderProcessing
{
    //The header parameter names registered by RFC 7515 §4.1, RFC 7516 §4.1, and RFC 7518 §4.6.1
    //(epk/apu/apv) plus draft-madden-jose-ecdh-1pu-04 §2.2.1 (skid). These are the names a
    //producer MUST NOT list in "crit" (RFC 7515 §4.1.11) and that this implementation already
    //understands, so a "crit" entry naming any of them is rejected on both grounds.
    private static readonly HashSet<string> RegisteredHeaderParameterNames = new(StringComparer.Ordinal)
    {
        WellKnownJwkMemberNames.Alg,
        WellKnownJoseHeaderNames.Enc,
        "zip",
        WellKnownJoseHeaderNames.Epk,
        WellKnownJoseHeaderNames.Apu,
        WellKnownJoseHeaderNames.Apv,
        WellKnownJoseHeaderNames.Skid,
        WellKnownJoseHeaderNames.Typ,
        WellKnownJoseHeaderNames.Cty,
        WellKnownJoseHeaderNames.Jwk,
        WellKnownJwkMemberNames.Kid,
        "jku",
        WellKnownJwkMemberNames.X5u,
        WellKnownJwkMemberNames.X5c,
        WellKnownJwkMemberNames.X5t,
        WellKnownJwkMemberNames.X5tHashS256,
        "crit"
    };


    /// <summary>
    /// Validates the protected-header <c>crit</c> parameter and the rejected-by-design
    /// algorithm guards over the decoded protected header JSON.
    /// </summary>
    /// <remarks>
    /// Call after the <c>alg</c>/<c>enc</c> have been extracted but before any cryptographic
    /// work, so an unprocessable message is rejected before key agreement runs (RFC 7516 §5.2
    /// step 5 precedes steps 6–16). This overload understands no <c>crit</c> extension; any
    /// critical entry naming an unregistered parameter is rejected. Use
    /// <see cref="Validate(ReadOnlySpan{byte}, string, IReadOnlySet{string})"/> to declare a
    /// set of extensions the caller processes.
    /// </remarks>
    /// <param name="headerJson">The decoded UTF-8 protected header JSON bytes.</param>
    /// <param name="algorithm">The already-extracted <c>alg</c> value.</param>
    /// <exception cref="FormatException">
    /// Thrown when <c>crit</c> is malformed, empty, lists a registered parameter, lists a
    /// parameter not present in the header, or names an extension this implementation does not
    /// understand; when <c>RSA1_5</c> is the key management algorithm; or when a <c>zip</c>
    /// parameter is present.
    /// </exception>
    public static void Validate(ReadOnlySpan<byte> headerJson, string algorithm) =>
        Validate(headerJson, algorithm, understoodCriticalExtensions: EmptyExtensions);


    /// <summary>
    /// Validates the protected-header <c>crit</c> parameter and the rejected-by-design
    /// algorithm guards, accepting a set of <c>crit</c> extensions the caller understands.
    /// </summary>
    /// <remarks>
    /// A critical entry that names one of <paramref name="understoodCriticalExtensions"/> is
    /// accepted (RFC 7515 §4.1.11: "If any of the listed extension Header Parameters are not
    /// understood and supported by the recipient, then the JWS is invalid."). An entry naming a
    /// registered parameter is always rejected — a producer MUST NOT place registered names in
    /// <c>crit</c>, so the caller cannot whitelist them.
    /// </remarks>
    /// <param name="headerJson">The decoded UTF-8 protected header JSON bytes.</param>
    /// <param name="algorithm">The already-extracted <c>alg</c> value.</param>
    /// <param name="understoodCriticalExtensions">
    /// The set of <c>crit</c> extension names the caller declares it understands and processes.
    /// </param>
    /// <exception cref="FormatException">
    /// Thrown for the same reasons as <see cref="Validate(ReadOnlySpan{byte}, string)"/>, except
    /// that a critical entry present in <paramref name="understoodCriticalExtensions"/> is
    /// accepted.
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
            //RFC 7516 §4 ("The Header Parameter names within the JOSE Header MUST be unique") and
            //§5.2 step 4 ("verify that the resulting JOSE Header does not contain duplicate Header
            //Parameter names"). The library reads each parameter by first occurrence; without this
            //gate a header repeating "alg" would be processed with the first value while a
            //last-value JSON parser elsewhere would disagree — the validate-one/act-on-another
            //divergence this check closes.
            throw new FormatException(
                "JWE protected header contains duplicate Header Parameter names, which MUST be "
                + "unique (RFC 7516 §4 / §5.2 step 4).");
        }

        RejectForbiddenAlgorithm(algorithm);

        if(JwkJsonReader.ContainsKey(headerJson, "zip"u8))
        {
            //RFC 8725 §3.6: compression of data SHOULD NOT be done before encryption because
            //compressed data reveals information about the plaintext (a length oracle). This
            //library rejects any JWE carrying "zip" rather than expanding the plaintext.
            throw new FormatException(
                "JWE tokens with a 'zip' compression parameter are rejected: compressing the "
                + "plaintext before encryption leaks plaintext length and enables compression "
                + "oracles (RFC 8725 §3.6).");
        }

        ValidateCrit(headerJson, understoodCriticalExtensions);
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
            //RFC 8725 §3.2: "Avoid all RSA-PKCS1 v1.5 encryption algorithms, preferring
            //RSAES-OAEP." RSAES-PKCS1-v1_5 (RSA1_5) is vulnerable to Bleichenbacher-style
            //adaptive chosen-ciphertext (million-message) attacks, so this library refuses it.
            throw new FormatException(
                "The 'RSA1_5' (RSAES-PKCS1-v1_5) key management algorithm is rejected: it is "
                + "vulnerable to Bleichenbacher adaptive chosen-ciphertext attacks and MUST be "
                + "avoided in favour of RSAES-OAEP (RFC 8725 §3.2).");
        }
    }


    //RFC 7515 §4.1.11 / RFC 7516 §4.1.13: process "crit" by rejecting any message whose crit
    //lists a parameter the implementation does not understand, and any message whose crit
    //violates the producer rules (empty list, registered names, names absent from the header).
    private static void ValidateCrit(
        ReadOnlySpan<byte> headerJson,
        IReadOnlySet<string> understoodCriticalExtensions)
    {
        List<string>? critNames = JwkJsonReader.ExtractStringArrayProperty(headerJson, "crit"u8);
        if(critNames is null)
        {
            //Absent "crit", or a "crit" whose value is not a string-only JSON array. A present
            //"crit" that is not a string array is a malformed producer header per RFC 7515
            //§4.1.11; distinguish it from absence so a malformed value is rejected rather than
            //silently treated as "no crit".
            if(JwkJsonReader.ContainsKey(headerJson, "crit"u8))
            {
                throw new FormatException(
                    "The 'crit' header parameter must be a JSON array of strings (RFC 7515 §4.1.11).");
            }

            return;
        }

        if(critNames.Count == 0)
        {
            //RFC 7515 §4.1.11: "Producers MUST NOT use the empty list "[]" as the "crit" value."
            throw new FormatException(
                "The 'crit' header parameter MUST NOT be the empty list (RFC 7515 §4.1.11).");
        }

        for(int i = 0; i < critNames.Count; ++i)
        {
            string name = critNames[i];

            if(RegisteredHeaderParameterNames.Contains(name))
            {
                //RFC 7515 §4.1.11: producers MUST NOT include names defined by the JWS/JWE/JWA
                //specifications in "crit"; recipients MAY consider such a message invalid. This
                //library does, and a caller cannot whitelist a registered name.
                throw new FormatException(
                    $"The 'crit' header parameter lists the registered parameter '{name}', "
                    + "which producers MUST NOT include (RFC 7515 §4.1.11).");
            }

            if(!HeaderContainsName(headerJson, name))
            {
                //RFC 7515 §4.1.11: names in "crit" MUST occur as Header Parameter names within
                //the JOSE Header.
                throw new FormatException(
                    $"The 'crit' header parameter lists '{name}', which does not occur as a "
                    + "header parameter in the JOSE Header (RFC 7515 §4.1.11).");
            }

            if(!understoodCriticalExtensions.Contains(name))
            {
                //RFC 7516 §5.2 step 5: a critical extension the recipient does not understand
                //makes the message invalid. The caller declares the extensions it processes; an
                //undeclared critical name is rejected.
                throw new FormatException(
                    $"The 'crit' header parameter requires understanding extension '{name}', which "
                    + "this consumer does not declare understood, so the JWE is rejected (RFC 7516 "
                    + "§5.2 step 5, RFC 7515 §4.1.11).");
            }
        }
    }


    //Whether the header JSON carries a top-level member named exactly "name". The name arrives
    //as an already-decoded string from the "crit" array; encode it to UTF-8 once and scan for a
    //top-level key. A pooled scratch buffer is unnecessary here — crit names are short, bounded
    //identifiers and the scan is a key-presence check, not a hot path.
    private static bool HeaderContainsName(ReadOnlySpan<byte> headerJson, string name)
    {
        int byteCount = System.Text.Encoding.UTF8.GetByteCount(name);
        Span<byte> nameBytes = byteCount <= 128 ? stackalloc byte[byteCount] : new byte[byteCount];
        System.Text.Encoding.UTF8.GetBytes(name, nameBytes);

        return JwkJsonReader.ContainsKey(headerJson, nameBytes);
    }


    //The shared empty set for the no-understood-extension overload. A frozen empty set avoids
    //allocating a fresh HashSet on every parse-boundary call.
    private static readonly IReadOnlySet<string> EmptyExtensions =
        System.Collections.Frozen.FrozenSet<string>.Empty;
}
