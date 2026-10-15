using System.Text;
using Verifiable.Cryptography.Text;

namespace Verifiable.OAuth.ProtectedResource;

/// <summary>
/// The <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 Section 7.1</see>
/// <c>WWW-Authenticate: DPoP</c> challenge: builds the value a protected resource answers a request with when it
/// requires DPoP authentication, and reads the challenge out of the <c>WWW-Authenticate</c> field lines of a response.
/// Section 7.1: "The scheme name is DPoP."
/// </summary>
/// <remarks>
/// <para>
/// <see cref="BuildChallenge"/> writes the scheme, then each parameter it is given as a quoted-string, in the order
/// <c>realm</c>, <c>error</c>, <c>scope</c>, <c>algs</c>, <c>resource_metadata</c>, each at most once
/// (<see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.2">RFC 9110 Section 11.2</see>: "each parameter
/// name MUST only occur once per challenge"). It writes no <c>error_description</c>: a refusal's description can carry
/// presented text outside the RFC 6750 Section 3 character set, so the description travels in the response body, as
/// the <c>Bearer</c> refusals of the library carry it.
/// </para>
/// <para>
/// <see cref="TryParse"/> and <see cref="TryRead"/> read through the challenge-list reader of
/// <see cref="BearerTokenChallenge"/>, the one grammar the library reads either scheme with
/// (<see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.6.1">RFC 9110 Section 11.6.1</see>:
/// "WWW-Authenticate = #challenge"). Unknown parameters are ignored (Section 7.1: "Additional authentication parameters
/// MAY be used, and unknown parameters MUST be ignored by recipients."). Two <c>DPoP</c> challenges in one response
/// read as none, the library's own rule: RFC 9110 Section 11.5 lets a response carry "multiple challenges with the
/// same auth-scheme but with different realms", and neither states which of them a client is to act on. The names
/// of <c>algs</c> are the SP-separated tokens of its value with empty names passed over, so a malformed <c>algs</c>
/// never hides the <c>error</c> a client acts on.
/// </para>
/// </remarks>
public static class DpopChallenge
{
    /// <summary>The UTF-8 source literal of <see cref="AlgorithmsParameter"/>.</summary>
    public static ReadOnlySpan<byte> AlgorithmsParameterUtf8 => "algs"u8;

    /// <summary>
    /// The <c>algs</c> challenge parameter name. <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC
    /// 9449 Section 7.1</see>: "An algs parameter SHOULD be included to signal to the client the JWS algorithms that are
    /// acceptable for the DPoP proof JWT."
    /// </summary>
    public static string AlgorithmsParameter { get; } = Utf8Constants.ToInternedString(AlgorithmsParameterUtf8);


    /// <summary>
    /// Builds a <c>WWW-Authenticate</c> <c>DPoP</c> challenge value from the parameters given, written in the order
    /// <c>DPoP realm="...", error="...", scope="...", algs="...", resource_metadata="..."</c>, one SP after the scheme
    /// and <c>, </c> between parameters. A <see langword="null"/> or empty value, and an empty
    /// <paramref name="algorithms"/> list, are absent; with no parameter the value is the scheme alone, <c>DPoP</c>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.3">RFC 9110 Section 11.3</see>: "challenge =
    /// auth-scheme [ 1*SP ( token68 / #auth-param ) ]").
    /// </summary>
    /// <remarks>
    /// The character checks are those of <see cref="BearerTokenChallenge.BuildChallenge"/>, read from the one place
    /// they are written: the realm is representable in a quoted-string (RFC 9110 Section 11.5: "For historical
    /// reasons, a sender MUST only generate the quoted-string syntax."), the error is within %x20-21 / %x23-5B / %x5D-7E
    /// and the scope is a list of scope-tokens
    /// (<see href="https://www.rfc-editor.org/rfc/rfc6750#section-3">RFC 6750 Section 3</see>), each algorithm name is
    /// an RFC 9110 Section 5.6.2 token (<see cref="IsToken"/>), and the <c>resource_metadata</c> value is formatted by
    /// <see cref="ProtectedResourceChallenge.BuildChallenge"/>. The token bound on an <c>algs</c> name is the library's
    /// chosen bound: the clauses that exclude any other name are RFC 9449 Section 4.2 ("alg: An identifier for a JWS
    /// asymmetric digital signature algorithm from [IANA.JOSE.ALGS]") and Section 4.3, check 5 (the alg "indicates a
    /// registered asymmetric digital signature algorithm"), every registered name being made of tchar only; a
    /// quoted-string could carry a Collision-Resistant Name (RFC 7515 Section 4.1.1), which no DPoP proof may carry. A
    /// value outside its set is the caller's own argument and throws.
    /// </remarks>
    /// <param name="realm">The protection-space identifier (RFC 9449 Section 7.1, RFC 9110 Section 11.5).</param>
    /// <param name="error">The error code (RFC 9449 Section 7.1, RFC 6750 Section 3), for example <see cref="OAuthErrors.UseDpopNonce"/>.</param>
    /// <param name="scope">The space-delimited scopes the resource requires (RFC 9449 Section 7.1, RFC 6750 Section 3).</param>
    /// <param name="algorithms">The JWS <c>alg</c> values acceptable for the DPoP proof, written as the space-delimited <c>algs</c> value.</param>
    /// <param name="resourceMetadata">The <see href="https://www.rfc-editor.org/rfc/rfc9728#section-5.1">RFC 9728 Section 5.1</see> protected resource metadata URL.</param>
    /// <returns>The <c>WWW-Authenticate</c> value.</returns>
    /// <exception cref="ArgumentException">A value holds a character outside its set, or an algorithm name is empty or no token.</exception>
    public static string BuildChallenge(
        string? realm = null,
        string? error = null,
        string? scope = null,
        IReadOnlyList<string>? algorithms = null,
        Uri? resourceMetadata = null)
    {
        bool hasRealm = !string.IsNullOrEmpty(realm);
        bool hasError = !string.IsNullOrEmpty(error);
        bool hasScope = !string.IsNullOrEmpty(scope);
        IReadOnlyList<string> algorithmNames = algorithms ?? [];
        bool hasAlgorithms = algorithmNames.Count > 0;

        if(hasRealm && !BearerTokenChallenge.IsQuotedStringRepresentable(realm!))
        {
            throw new ArgumentException(
                "realm contains characters that cannot be represented in an RFC 9110 Section 5.6.4 quoted-string.", nameof(realm));
        }

        if(hasError && !BearerTokenChallenge.IsWithinNqsCharset(error!))
        {
            throw new ArgumentException(
                "error contains characters outside %x20-21 / %x23-5B / %x5D-7E (RFC 6750 Section 3).", nameof(error));
        }

        if(hasScope && !ScopeTokenSyntax.IsScopeList(scope!))
        {
            throw new ArgumentException(
                "scope must be single-space-delimited scope-tokens of %x21 / %x23-5B / %x5D-7E characters (RFC 6750 Section 3).", nameof(scope));
        }

        if(hasAlgorithms)
        {
            foreach(string? algorithm in algorithmNames)
            {
                if(!IsToken(algorithm))
                {
                    throw new ArgumentException(
                        "Each algorithm name must be a non-empty RFC 9110 Section 5.6.2 token.", nameof(algorithms));
                }
            }
        }

        string? resourceMetadataParameter = resourceMetadata is null ? null : FormatResourceMetadata(resourceMetadata);

        StringBuilder builder = new();
        _ = builder.Append(WellKnownAuthenticationSchemes.DPoP);
        bool isFirstParameter = true;

        if(hasRealm)
        {
            BearerTokenChallenge.AppendQuotedParameter(builder, BearerTokenChallenge.RealmParameter, realm!, ref isFirstParameter);
        }

        if(hasError)
        {
            BearerTokenChallenge.AppendQuotedParameter(builder, BearerTokenChallenge.ErrorParameter, error!, ref isFirstParameter);
        }

        if(hasScope)
        {
            BearerTokenChallenge.AppendQuotedParameter(builder, BearerTokenChallenge.ScopeParameter, scope!, ref isFirstParameter);
        }

        if(hasAlgorithms)
        {
            BearerTokenChallenge.AppendQuotedParameter(builder, AlgorithmsParameter, string.Join(' ', algorithmNames), ref isFirstParameter);
        }

        if(resourceMetadataParameter is not null)
        {
            _ = builder.Append(isFirstParameter ? " " : ", ");
            _ = builder.Append(resourceMetadataParameter);
        }

        return builder.ToString();
    }


    /// <summary>
    /// Reads the <c>DPoP</c> challenge of one <c>WWW-Authenticate</c> field value into its
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 Section 7.1</see> parameters, the value
    /// read as a challenge list as one field line of <see cref="TryRead"/>.
    /// </summary>
    /// <param name="challengeValue">The field value, for example <c>DPoP error="use_dpop_nonce", algs="ES256"</c>.</param>
    /// <param name="parameters">The parameters read; all absent when the reading fails.</param>
    /// <returns><see langword="false"/> when the value is outside the challenge grammar or holds no <c>DPoP</c> challenge or more than one.</returns>
    public static bool TryParse(string challengeValue, out DpopChallengeParameters parameters)
    {
        ArgumentNullException.ThrowIfNull(challengeValue);

        return BearerTokenChallenge.TryReadDpopChallenge([challengeValue], out parameters);
    }


    /// <summary>
    /// Reads the one <c>DPoP</c> challenge out of every <c>WWW-Authenticate</c> field line of a response, in received
    /// order, into its <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 Section 7.1</see>
    /// parameters: the reading a client of the scheme acts on, the library's DPoP nonce retry among them.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.6.1">RFC 9110 Section 11.6.1</see>: the field value
    /// "might contain more than one challenge, and each challenge can contain a comma-separated list of authentication
    /// parameters. Furthermore, the header field itself can occur multiple times."
    /// </summary>
    /// <param name="fieldLines">Every <c>WWW-Authenticate</c> field line of the response, in received order.</param>
    /// <param name="parameters">The parameters read; all absent when the reading fails.</param>
    /// <returns><see langword="false"/> when the lines are outside the challenge grammar or hold no <c>DPoP</c> challenge or more than one.</returns>
    public static bool TryRead(IReadOnlyList<string> fieldLines, out DpopChallengeParameters parameters)
    {
        ArgumentNullException.ThrowIfNull(fieldLines);

        return BearerTokenChallenge.TryReadDpopChallenge(fieldLines, out parameters);
    }


    /// <summary>
    /// The <c>resource_metadata</c> auth-param, formatted by <see cref="ProtectedResourceChallenge.BuildChallenge"/>
    /// and sliced after its scheme and SP, so the parameter joins this challenge's list without a second copy of the
    /// quoting rules, as <see cref="BearerTokenChallenge.BuildChallenge"/> joins it.
    /// </summary>
    /// <param name="resourceMetadata">The protected resource metadata URL.</param>
    /// <returns>The auth-param <c>resource_metadata="..."</c>.</returns>
    /// <exception cref="ArgumentException">The URL carries a control character a header field value cannot carry.</exception>
    private static string FormatResourceMetadata(Uri resourceMetadata)
    {
        string composed;
        try
        {
            composed = ProtectedResourceChallenge.BuildChallenge(WellKnownAuthenticationSchemes.DPoP, resourceMetadata);
        }
        catch(ArgumentException exception)
        {
            throw new ArgumentException(exception.Message, nameof(resourceMetadata), exception);
        }

        return composed[(WellKnownAuthenticationSchemes.DPoP.Length + 1)..];
    }


    /// <summary>
    /// Whether <paramref name="value"/> is a non-empty <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.6.2">RFC
    /// 9110 Section 5.6.2</see> token, "token = 1*tchar", each character checked by
    /// <see cref="BearerTokenChallenge.IsTokenChar"/>. The library holds every <c>algs</c> name to this grammar, its
    /// chosen bound, so the SP that delimits the list never falls inside a name. The clauses that exclude any other
    /// name are <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.2">RFC 9449 Section 4.2</see>, "alg: An
    /// identifier for a JWS asymmetric digital signature algorithm from [IANA.JOSE.ALGS]", and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">Section 4.3</see>, check 5, the alg "indicates a
    /// registered asymmetric digital signature algorithm": every registered name is made of tchar only. A quoted-string
    /// could carry a Collision-Resistant Name (<see href="https://www.rfc-editor.org/rfc/rfc7515#section-4.1.1">RFC 7515
    /// Section 4.1.1</see>), which no DPoP proof may carry. The library's protected resources hold the accepted
    /// algorithm list to it before the list reaches a challenge.
    /// </summary>
    /// <param name="value">The candidate algorithm name.</param>
    /// <returns><see langword="true"/> when the value is one or more tchar.</returns>
    internal static bool IsToken(string? value)
    {
        if(string.IsNullOrEmpty(value))
        {
            return false;
        }

        foreach(char c in value)
        {
            if(!BearerTokenChallenge.IsTokenChar(c))
            {
                return false;
            }
        }

        return true;
    }
}
