using System.Diagnostics;

namespace Verifiable.OAuth.Server;

/// <summary>
/// Single source of truth for the durations and clock-skew tolerance the
/// Authorization Server applies when issuing artifacts (PAR responses, JARs,
/// authorization codes, access tokens, ID tokens) and validating timing claims
/// on inbound material.
/// </summary>
/// <remarks>
/// <para>
/// Policy decisions about timing live here, not in endpoint code. Every site
/// that previously read a literal duration — for example
/// <c>now.AddSeconds(60)</c> — reads the corresponding property on
/// <see cref="AuthorizationServer.Timings"/> instead. The library does not
/// embed timing literals anywhere outside this type and its consumers.
/// </para>
/// <para>
/// Per-registration overrides remain available where applicable. Token
/// producers consult <see cref="ClientRecord"/> first via
/// <c>GetTokenLifetime</c> and fall back to the corresponding entry on this
/// policy when no override is set. This keeps the deployment-wide default in
/// one place while letting individual clients tighten or loosen lifetimes.
/// </para>
/// <para>
/// Defaults are aligned with the most demanding profile the library supports
/// — HAIP 1.0 / FAPI 2.0 — so that a deployment which simply uses
/// <see cref="Default"/> is conformant with those profiles' timing
/// requirements. Less demanding profiles can copy <see cref="Default"/> and
/// relax individual entries; more demanding deployments can shorten them.
/// </para>
/// <para>
/// All durations are <see cref="TimeSpan"/> values. The library converts to
/// JWT NumericDate (Unix seconds) at the wire boundary; in-process arithmetic
/// always uses <see cref="TimeSpan"/> against
/// <see cref="System.TimeProvider.GetUtcNow"/>.
/// </para>
/// </remarks>
[DebuggerDisplay("TimingPolicy ClockSkew={ClockSkewTolerance}")]
public sealed record TimingPolicy
{
    /// <summary>
    /// The lifetime of an OID4VP <c>request_uri</c> handle returned by PAR per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9126#section-2.2">RFC 9126 §2.2</see>.
    /// Default 60 seconds, matching the typical
    /// <see href="https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html">HAIP 1.0</see>
    /// deployment.
    /// </summary>
    /// <remarks>
    /// This is the lifetime of the external token, not of the JAR's <c>exp</c>
    /// claim. The two are distinct values per
    /// <see href="https://darutk.medium.com/implementers-note-about-jar-fff4cbd158fe">Kawasaki, Implementer's note about JAR</see>:
    /// the request URI may be valid for one window while the request object
    /// it dereferences to has its own expiry.
    /// </remarks>
    public TimeSpan Oid4VpRequestUriLifetime { get; init; } = TimeSpan.FromSeconds(60);

    /// <summary>
    /// The lifetime of the OID4VP JAR's <c>exp</c> claim relative to its
    /// <c>iat</c> claim. Default 60 seconds per
    /// <see href="https://openid.net/specs/fapi-2_0-security-profile.html">FAPI 2.0 Security Profile §5.2.2</see>
    /// Clause 13, which mandates an <c>exp</c> claim and constrains its window.
    /// </summary>
    public TimeSpan Oid4VpRequestObjectLifetime { get; init; } = TimeSpan.FromSeconds(60);

    /// <summary>
    /// The lifetime of an Authorization Code Pushed Authorization Request handle
    /// per <see href="https://www.rfc-editor.org/rfc/rfc9126#section-2.2">RFC 9126 §2.2</see>.
    /// Default 60 seconds.
    /// </summary>
    public TimeSpan AuthCodeParLifetime { get; init; } = TimeSpan.FromSeconds(60);

    /// <summary>
    /// The lifetime of an Authorization Code JAR's <c>exp</c> claim relative to its
    /// <c>iat</c> claim. Default 60 seconds per
    /// <see href="https://openid.net/specs/fapi-2_0-security-profile.html">FAPI 2.0 Security Profile §5.2.2</see>
    /// Clause 13, which mandates an <c>exp</c> claim and constrains its window.
    /// </summary>
    /// <remarks>
    /// Distinct from <see cref="AuthCodeParLifetime"/>: that value is the lifetime of
    /// the external <c>request_uri</c> handle the AS issues, this value is the lifetime
    /// of the signed Request Object the client pushes. RFC 9101 leaves the JAR
    /// lifetime profile-defined; FAPI 2.0 picks 60 seconds and the library aligns.
    /// </remarks>
    public TimeSpan AuthCodeRequestObjectLifetime { get; init; } = TimeSpan.FromSeconds(60);

    /// <summary>
    /// The lifetime of an OAuth 2.0 authorization code per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2">RFC 6749 §4.1.2</see>,
    /// which recommends a maximum of 10 minutes. Default 600 seconds.
    /// </summary>
    public TimeSpan AuthorizationCodeLifetime { get; init; } = TimeSpan.FromSeconds(600);

    /// <summary>
    /// The default lifetime of an RFC 9068 access token when the client
    /// registration does not specify a per-registration override via
    /// <see cref="ClientRecord.GetTokenLifetime"/>. Default 1 hour.
    /// </summary>
    public TimeSpan AccessTokenLifetime { get; init; } = TimeSpan.FromHours(1);

    /// <summary>
    /// The default lifetime of an OIDC 1.0 ID token when the client registration
    /// does not specify a per-registration override via
    /// <see cref="ClientRecord.GetTokenLifetime"/>. Default 1 hour.
    /// </summary>
    public TimeSpan IdTokenLifetime { get; init; } = TimeSpan.FromHours(1);

    /// <summary>
    /// The maximum wall-clock duration any single PDA-driven flow may remain
    /// open before the dispatcher's TTL check rejects further input. Default
    /// 5 minutes. Applied uniformly to client-side and server-side OID4VP
    /// flows and to wallet flows.
    /// </summary>
    /// <remarks>
    /// This is a ceiling on the entire flow lifetime, not on any individual
    /// step. Per-state expiry derives from the artifact lifetimes above
    /// (PAR window, JAR <c>exp</c>, code lifetime). The flow is rejected if
    /// it remains open past this ceiling regardless of artifact-level expiry.
    /// </remarks>
    public TimeSpan MaximumFlowLifetime { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// The clock-skew tolerance applied when validating <c>nbf</c>, <c>iat</c>,
    /// and <c>exp</c> claims on inbound JWTs. Default 60 seconds.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Both directions: a JAR observed before its <c>nbf</c> is accepted if
    /// the gap is within <see cref="ClockSkewTolerance"/>; a JAR observed
    /// after its <c>exp</c> is accepted if the gap is within
    /// <see cref="ClockSkewTolerance"/>. Validators that consume timing claims
    /// — wallet-side JAR validation, server-side request-object validation,
    /// token validation — read this value rather than embedding their own.
    /// </para>
    /// <para>
    /// 60 seconds matches
    /// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4.1.4">RFC 7519 §4.1.4</see>'s
    /// guidance to allow for "a small leeway" and is consistent with FAPI
    /// deployments that combine RFC 9068 access tokens with strict request-
    /// object lifetime checks.
    /// </para>
    /// </remarks>
    public TimeSpan ClockSkewTolerance { get; init; } = TimeSpan.FromSeconds(60);


    /// <summary>
    /// The library default policy. HAIP 1.0 / FAPI 2.0 aligned. Suitable as a
    /// starting point for any deployment; copy and modify individual entries
    /// when a specific profile demands different values.
    /// </summary>
    public static TimingPolicy Default { get; } = new();
}
