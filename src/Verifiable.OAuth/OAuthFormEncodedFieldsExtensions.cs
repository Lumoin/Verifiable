using System.Diagnostics.CodeAnalysis;

namespace Verifiable.OAuth;

/// <summary>
/// Typed accessor extensions for <see cref="OAuthFormEncodedFields"/>. Reads
/// well-known OAuth parameter values by name from the underlying dictionary.
/// </summary>
/// <remarks>
/// <para>
/// Each accessor returns <see langword="null"/> when the parameter is absent
/// from the field set. Accessors do not validate the value's format — that is
/// the responsibility of the caller acting on the value (matchers, request
/// builders, etc.). Parameter names are sourced from
/// <see cref="OAuthRequestParameters"/> so the typed surface and the wire
/// surface stay aligned.
/// </para>
/// <para>
/// Only parameters defined as constants in <see cref="OAuthRequestParameters"/>
/// have typed accessors here. Vendor-specific parameters
/// (<c>acr_values</c>, <c>prompt</c>, vendor-prefixed extensions) are read
/// via the underlying <see cref="OAuthFormEncodedFields.Fields"/> dictionary
/// directly. Adding a vendor-specific accessor in the future means adding
/// the constant to <see cref="OAuthRequestParameters"/> first; that keeps
/// the wire-name catalogue authoritative.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1034:Nested types should not be visible",
    Justification = "C# 14 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class OAuthFormEncodedFieldsExtensions
{
    extension(OAuthFormEncodedFields self)
    {
        /// <summary>
        /// Gets the <c>client_id</c> parameter value, or <see langword="null"/>
        /// when absent. See <see cref="OAuthRequestParameters.ClientId"/>.
        /// </summary>
        public string? ClientId =>
            self.Fields.TryGetValue(OAuthRequestParameters.ClientId, out string? value) ? value : null;


        /// <summary>
        /// Gets the <c>scope</c> parameter value, or <see langword="null"/>
        /// when absent. See <see cref="OAuthRequestParameters.Scope"/>.
        /// </summary>
        public string? Scope =>
            self.Fields.TryGetValue(OAuthRequestParameters.Scope, out string? value) ? value : null;


        /// <summary>
        /// Gets the <c>state</c> parameter value, or <see langword="null"/>
        /// when absent. See <see cref="OAuthRequestParameters.State"/>.
        /// </summary>
        public string? State =>
            self.Fields.TryGetValue(OAuthRequestParameters.State, out string? value) ? value : null;


        /// <summary>
        /// Gets the <c>redirect_uri</c> parameter value, or <see langword="null"/>
        /// when absent. See <see cref="OAuthRequestParameters.RedirectUri"/>.
        /// </summary>
        [SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
            Justification = "Wire-form OAuth parameter values are strings per RFC 6749 Appendix B; some redirect_uri values are URNs (e.g. urn:ietf:wg:oauth:2.0:oob). Parsing to Uri is the caller's concern.")]
        public string? RedirectUri =>
            self.Fields.TryGetValue(OAuthRequestParameters.RedirectUri, out string? value) ? value : null;


        /// <summary>
        /// Gets the <c>response_type</c> parameter value, or <see langword="null"/>
        /// when absent. See <see cref="OAuthRequestParameters.ResponseType"/>.
        /// </summary>
        public string? ResponseType =>
            self.Fields.TryGetValue(OAuthRequestParameters.ResponseType, out string? value) ? value : null;


        /// <summary>
        /// Gets the <c>response_mode</c> parameter value, or <see langword="null"/>
        /// when absent. See <see cref="OAuthRequestParameters.ResponseMode"/>.
        /// </summary>
        public string? ResponseMode =>
            self.Fields.TryGetValue(OAuthRequestParameters.ResponseMode, out string? value) ? value : null;


        /// <summary>
        /// Gets the <c>grant_type</c> parameter value, or <see langword="null"/>
        /// when absent. See <see cref="OAuthRequestParameters.GrantType"/>.
        /// </summary>
        public string? GrantType =>
            self.Fields.TryGetValue(OAuthRequestParameters.GrantType, out string? value) ? value : null;


        /// <summary>
        /// Gets the <c>code</c> parameter value, or <see langword="null"/>
        /// when absent. See <see cref="OAuthRequestParameters.Code"/>.
        /// </summary>
        public string? Code =>
            self.Fields.TryGetValue(OAuthRequestParameters.Code, out string? value) ? value : null;


        /// <summary>
        /// Gets the <c>code_verifier</c> parameter value, or <see langword="null"/>
        /// when absent. See <see cref="OAuthRequestParameters.CodeVerifier"/>.
        /// </summary>
        public string? CodeVerifier =>
            self.Fields.TryGetValue(OAuthRequestParameters.CodeVerifier, out string? value) ? value : null;


        /// <summary>
        /// Gets the <c>code_challenge</c> parameter value, or <see langword="null"/>
        /// when absent. See <see cref="OAuthRequestParameters.CodeChallenge"/>.
        /// </summary>
        public string? CodeChallenge =>
            self.Fields.TryGetValue(OAuthRequestParameters.CodeChallenge, out string? value) ? value : null;


        /// <summary>
        /// Gets the <c>code_challenge_method</c> parameter value, or <see langword="null"/>
        /// when absent. See <see cref="OAuthRequestParameters.CodeChallengeMethod"/>.
        /// </summary>
        public string? CodeChallengeMethod =>
            self.Fields.TryGetValue(OAuthRequestParameters.CodeChallengeMethod, out string? value) ? value : null;


        /// <summary>
        /// Gets the <c>refresh_token</c> parameter value, or <see langword="null"/>
        /// when absent. See <see cref="OAuthRequestParameters.RefreshToken"/>.
        /// </summary>
        public string? RefreshToken =>
            self.Fields.TryGetValue(OAuthRequestParameters.RefreshToken, out string? value) ? value : null;


        /// <summary>
        /// Gets the <c>iss</c> parameter value (RFC 9207 issuer identification
        /// on the authorization callback), or <see langword="null"/> when
        /// absent. See <see cref="OAuthRequestParameters.Iss"/>.
        /// </summary>
        public string? Iss =>
            self.Fields.TryGetValue(OAuthRequestParameters.Iss, out string? value) ? value : null;


        /// <summary>
        /// Gets the <c>token</c> parameter value (revocation /
        /// introspection input), or <see langword="null"/> when absent. See
        /// <see cref="OAuthRequestParameters.Token"/>.
        /// </summary>
        public string? Token =>
            self.Fields.TryGetValue(OAuthRequestParameters.Token, out string? value) ? value : null;


        /// <summary>
        /// Gets the <c>token_type_hint</c> parameter value, or
        /// <see langword="null"/> when absent. See
        /// <see cref="OAuthRequestParameters.TokenTypeHint"/>.
        /// </summary>
        public string? TokenTypeHint =>
            self.Fields.TryGetValue(OAuthRequestParameters.TokenTypeHint, out string? value) ? value : null;


        /// <summary>
        /// Gets the <c>request</c> parameter value (signed JAR per RFC 9101),
        /// or <see langword="null"/> when absent. See
        /// <see cref="OAuthRequestParameters.Request"/>.
        /// </summary>
        public string? Request =>
            self.Fields.TryGetValue(OAuthRequestParameters.Request, out string? value) ? value : null;


        /// <summary>
        /// Gets the <c>request_uri</c> parameter value (PAR-issued URI handle),
        /// or <see langword="null"/> when absent. See
        /// <see cref="OAuthRequestParameters.RequestUri"/>.
        /// </summary>
        [SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
            Justification = "Wire-form OAuth parameter values are strings per RFC 9126 §2.2; PAR request_uri values are commonly URNs (e.g. urn:ietf:params:oauth:request_uri:...). Parsing to Uri is the caller's concern.")]
        public string? RequestUri =>
            self.Fields.TryGetValue(OAuthRequestParameters.RequestUri, out string? value) ? value : null;
    }
}
