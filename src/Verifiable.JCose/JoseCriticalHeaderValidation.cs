using System.Collections.Frozen;

namespace Verifiable.JCose;

/// <summary>
/// The shared <c>crit</c> (critical header) processing for JOSE protected headers, applied identically to
/// JWS (<see href="https://www.rfc-editor.org/rfc/rfc7515#section-4.1.11">RFC 7515 §4.1.11</see>) and JWE
/// (<see href="https://www.rfc-editor.org/rfc/rfc7516#section-4.1.13">RFC 7516 §4.1.13</see>). One
/// source of truth so the JWS verify path and the JWE parse path cannot drift apart.
/// </summary>
/// <remarks>
/// <para>
/// RFC 7515 §4.1.11: a producer MUST NOT use the empty list, MUST NOT list Header Parameter names
/// defined by the JWS/JWE/JWA specifications, and every name MUST occur as a Header Parameter in the
/// JOSE Header. RFC 7516 §5.2 step 5: a recipient MUST reject a message naming a critical extension it
/// does not understand. This validator enforces all of those; the caller declares which extensions it
/// understands (none, by default), so an unrecognized critical extension is rejected.
/// </para>
/// <para>
/// The header is read through the library's own span reader (<see cref="JwkJsonReader"/>); there is no
/// JSON-serialization dependency in this project.
/// </para>
/// </remarks>
public static class JoseCriticalHeaderValidation
{
    //The header parameter names registered by RFC 7515 §4.1, RFC 7516 §4.1, and RFC 7518 §4.6.1
    //(epk/apu/apv) plus draft-madden-jose-ecdh-1pu-04 §2.2.1 (skid). A producer MUST NOT list any of
    //these in "crit" (RFC 7515 §4.1.11), and this implementation already understands them, so a "crit"
    //entry naming any of them is rejected on both grounds — for JWS and JWE alike.
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

    /// <summary>The shared empty set for the no-understood-extension case (avoids per-call allocation).</summary>
    public static IReadOnlySet<string> NoUnderstoodExtensions { get; } = FrozenSet<string>.Empty;


    /// <summary>
    /// Validates <c>crit</c> over a decoded protected header, throwing on any violation. Understands no
    /// <c>crit</c> extension (any critical entry is rejected). Used by the JWE parse path.
    /// </summary>
    /// <param name="headerJson">The decoded UTF-8 protected header JSON bytes.</param>
    /// <exception cref="FormatException">Thrown when <c>crit</c> is malformed, empty, lists a registered parameter, lists a name not present in the header, or names an unsupported extension.</exception>
    public static void Validate(ReadOnlySpan<byte> headerJson) => Validate(headerJson, NoUnderstoodExtensions);


    /// <summary>
    /// Validates <c>crit</c> over a decoded protected header, throwing on any violation, accepting a set
    /// of <c>crit</c> extensions the caller understands.
    /// </summary>
    /// <param name="headerJson">The decoded UTF-8 protected header JSON bytes.</param>
    /// <param name="understoodCriticalExtensions">The <c>crit</c> extension names the caller processes.</param>
    /// <exception cref="FormatException">Thrown for the reasons in <see cref="Validate(ReadOnlySpan{byte})"/>, except that a critical entry the caller understands is accepted.</exception>
    public static void Validate(ReadOnlySpan<byte> headerJson, IReadOnlySet<string> understoodCriticalExtensions)
    {
        if(!TryValidate(headerJson, understoodCriticalExtensions, out string? failureReason))
        {
            throw new FormatException(failureReason);
        }
    }


    /// <summary>
    /// Whether <c>crit</c> is satisfied over a decoded protected header, understanding no extension. Never
    /// throws — the non-throwing form the JWS verify path uses to fail closed to <see langword="false"/>.
    /// </summary>
    /// <param name="headerJson">The decoded UTF-8 protected header JSON bytes.</param>
    public static bool IsSatisfied(ReadOnlySpan<byte> headerJson) => IsSatisfied(headerJson, NoUnderstoodExtensions);


    /// <summary>
    /// Whether <c>crit</c> is satisfied over a decoded protected header, accepting a set of extensions the
    /// caller understands. Never throws.
    /// </summary>
    /// <param name="headerJson">The decoded UTF-8 protected header JSON bytes.</param>
    /// <param name="understoodCriticalExtensions">The <c>crit</c> extension names the caller processes.</param>
    public static bool IsSatisfied(ReadOnlySpan<byte> headerJson, IReadOnlySet<string> understoodCriticalExtensions) =>
        TryValidate(headerJson, understoodCriticalExtensions, out _);


    /// <summary>
    /// Whether <c>crit</c> is present and lists <paramref name="extension"/> as a critical header parameter.
    /// RFC 7515 treats <c>crit</c> as optional in general (so <see cref="IsSatisfied(ReadOnlySpan{byte})"/> accepts
    /// an absent <c>crit</c>), but some parameters MUST be marked critical by their own specification — for example
    /// RFC 7797 §6 requires a producer of an unencoded-payload JWS (<c>b64:false</c>) to include <c>b64</c> in
    /// <c>crit</c>. A caller with such a requirement uses this to reject a header whose <c>crit</c> is absent or does
    /// not name the parameter; the remaining <c>crit</c> rules are validated separately by
    /// <see cref="IsSatisfied(ReadOnlySpan{byte}, IReadOnlySet{string})"/>.
    /// </summary>
    /// <param name="headerJson">The decoded UTF-8 protected header JSON bytes.</param>
    /// <param name="extension">The header parameter name that MUST appear in <c>crit</c>.</param>
    /// <returns><see langword="true"/> when <c>crit</c> is a string array that contains <paramref name="extension"/>.</returns>
    public static bool MarksCritical(ReadOnlySpan<byte> headerJson, string extension)
    {
        List<string>? critNames = JwkJsonReader.ExtractStringArrayProperty(headerJson, "crit"u8);

        return critNames is not null && critNames.Contains(extension);
    }


    //RFC 7515 §4.1.11 / RFC 7516 §4.1.13: the single crit rule set, expressed without throwing so both a
    //throwing (JWE) and a fail-closed bool (JWS) caller can share it. Returns false with a reason on any
    //violation: a present-but-non-array crit, the empty list, a registered name, a name absent from the
    //header, or an extension the caller has not declared understood.
    private static bool TryValidate(
        ReadOnlySpan<byte> headerJson,
        IReadOnlySet<string> understoodCriticalExtensions,
        out string? failureReason)
    {
        ArgumentNullException.ThrowIfNull(understoodCriticalExtensions);

        List<string>? critNames = JwkJsonReader.ExtractStringArrayProperty(headerJson, "crit"u8);
        if(critNames is null)
        {
            //Absent "crit" is fine; a present "crit" that is not a string array is a malformed producer
            //header per RFC 7515 §4.1.11 — distinguish it from absence so it is rejected rather than
            //silently treated as "no crit".
            if(JwkJsonReader.ContainsKey(headerJson, "crit"u8))
            {
                failureReason = "The 'crit' header parameter must be a JSON array of strings (RFC 7515 §4.1.11).";

                return false;
            }

            failureReason = null;

            return true;
        }

        if(critNames.Count == 0)
        {
            //RFC 7515 §4.1.11: "Producers MUST NOT use the empty list "[]" as the "crit" value."
            failureReason = "The 'crit' header parameter MUST NOT be the empty list (RFC 7515 §4.1.11).";

            return false;
        }

        for(int i = 0; i < critNames.Count; ++i)
        {
            string name = critNames[i];

            if(RegisteredHeaderParameterNames.Contains(name))
            {
                //RFC 7515 §4.1.11: producers MUST NOT include names defined by the JWS/JWE/JWA
                //specifications in "crit"; a caller cannot whitelist a registered name.
                failureReason =
                    $"The 'crit' header parameter lists the registered parameter '{name}', "
                    + "which producers MUST NOT include (RFC 7515 §4.1.11).";

                return false;
            }

            if(!HeaderContainsName(headerJson, name))
            {
                //RFC 7515 §4.1.11: names in "crit" MUST occur as Header Parameter names within the JOSE Header.
                failureReason =
                    $"The 'crit' header parameter lists '{name}', which does not occur as a "
                    + "header parameter in the JOSE Header (RFC 7515 §4.1.11).";

                return false;
            }

            if(!understoodCriticalExtensions.Contains(name))
            {
                //RFC 7515 §4.1.11 / RFC 7516 §5.2 step 5: a critical extension the recipient does not
                //understand makes the message invalid.
                failureReason =
                    $"The 'crit' header parameter requires understanding extension '{name}', which "
                    + "this consumer does not declare understood (RFC 7515 §4.1.11).";

                return false;
            }
        }

        failureReason = null;

        return true;
    }


    //Whether the header JSON carries a top-level member named exactly "name". The name arrives as an
    //already-decoded string from the "crit" array; encode it to UTF-8 once and scan for a top-level key.
    private static bool HeaderContainsName(ReadOnlySpan<byte> headerJson, string name)
    {
        int byteCount = System.Text.Encoding.UTF8.GetByteCount(name);
        Span<byte> nameBytes = byteCount <= 128 ? stackalloc byte[byteCount] : new byte[byteCount];
        System.Text.Encoding.UTF8.GetBytes(name, nameBytes);

        return JwkJsonReader.ContainsKey(headerJson, nameBytes);
    }
}
