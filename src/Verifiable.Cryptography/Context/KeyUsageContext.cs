using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Cryptography.Context;

/// <summary>
/// Identifies the protocol-level role a key plays within an authorization server
/// or relying party — the context in which the key is used, distinct from its
/// cryptographic operation.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Why this dimension exists</strong>
/// </para>
/// <para>
/// <see cref="Purpose"/> describes the cryptographic operation a key performs
/// (signing, verification, encryption, key agreement). <see cref="KeyUsageContext"/>
/// describes the protocol role that operation fulfils (signing an access token,
/// signing an ID token, signing a JAR, signing an issued verifiable credential,
/// decrypting a direct_post response). A single cryptographic operation — signing —
/// applies in several distinct protocol contexts, each with its own lifecycle,
/// rotation policy, assurance requirements, and key-separation implications.
/// </para>
/// <para>
/// Key separation across protocol contexts is a cryptographic principle in its own
/// right: using one key for two protocol roles means compromise in one propagates
/// to the other. Having distinct keys per context is defense in depth, and in
/// regulated environments such as eIDAS2, credential-issuer keys carry binding and
/// assurance requirements that authorization-server keys do not.
/// </para>
/// <para>
/// Within token issuance, the access token, ID token, refresh token, and back-channel
/// logout token each carry distinct semantics. FAPI 2.0 deployments commonly use
/// different signing keys for ID tokens than for access tokens, and the OpenID Connect
/// RP Metadata Choices specification lets clients negotiate ID-token signing
/// algorithms separately from access tokens. Each token type therefore has its own
/// usage context rather than sharing a single token-issuance umbrella.
/// </para>
/// <para>
/// <strong>Extending with custom values</strong>
/// </para>
/// <para>
/// Call <see cref="Create"/> during application startup to add protocol contexts
/// the library does not define. Use code values above 1000 to avoid collisions
/// with future library additions.
/// </para>
/// <code>
/// public static class CustomKeyUsageContexts
/// {
///     public static KeyUsageContext BackupAttestation { get; } = KeyUsageContext.Create(1001);
/// }
/// </code>
/// <para>
/// <strong>Thread safety</strong>
/// </para>
/// <para>
/// <see cref="Create"/> is not thread-safe. Call it only during application
/// startup before concurrent access begins. Predefined values are immutable and
/// safe for concurrent read access.
/// </para>
/// </remarks>
/// <seealso cref="Purpose"/>
/// <seealso cref="CryptoAlgorithm"/>
/// <seealso cref="MaterialSemantics"/>
/// <seealso cref="Tag"/>
[DebuggerDisplay("{KeyUsageContextNames.GetName(this),nq}")]
public readonly struct KeyUsageContext: IEquatable<KeyUsageContext>
{
    /// <summary>
    /// Gets the numeric code for this usage context.
    /// </summary>
    public int Code { get; }


    private KeyUsageContext(int code)
    {
        Code = code;
    }


    /// <summary>
    /// No protocol role assigned. Typical for keys not yet bound to a protocol
    /// purpose, or for keys used outside the authorization-server surface.
    /// </summary>
    public static KeyUsageContext None { get; } = new(0);


    /// <summary>
    /// Signing of OAuth 2.0 JWT access tokens issued by the authorization server
    /// per <see href="https://www.rfc-editor.org/rfc/rfc9068">RFC 9068</see>.
    /// </summary>
    /// <remarks>
    /// Distinct from <see cref="IdTokenIssuance"/> so deployments can rotate or
    /// hardware-back ID-token keys independently from access-token keys, and so
    /// <see cref="SelectSigningKeyDelegate"/> implementations can branch on the
    /// usage when picking a key for a multi-algorithm registration.
    /// </remarks>
    public static KeyUsageContext AccessTokenIssuance { get; } = new(1);


    /// <summary>
    /// Signing of JWT-secured Authorization Requests (JAR, RFC 9101) for OAuth
    /// and OID4VP authorization flows.
    /// </summary>
    public static KeyUsageContext JarSigning { get; } = new(2);


    /// <summary>
    /// Signing of verifiable credentials issued over OID4VCI, including SD-JWT
    /// VCs and mdocs.
    /// </summary>
    public static KeyUsageContext CredentialIssuance { get; } = new(3);


    /// <summary>
    /// Decryption of OID4VP <c>direct_post.jwt</c> responses and other
    /// application-layer encrypted payloads received by the authorization server.
    /// </summary>
    public static KeyUsageContext ResponseDecryption { get; } = new(4);


    /// <summary>
    /// Signing of client assertions (RFC 7523) used for client authentication
    /// at the token endpoint.
    /// </summary>
    public static KeyUsageContext ClientAssertion { get; } = new(5);


    /// <summary>
    /// Signing of verifier attestations presented to wallets during OID4VP
    /// authorization flows.
    /// </summary>
    public static KeyUsageContext VerifierAttestation { get; } = new(6);


    /// <summary>
    /// Signing of wallet attestations presented to relying parties.
    /// </summary>
    public static KeyUsageContext WalletAttestation { get; } = new(7);


    /// <summary>
    /// Signing of DPoP (RFC 9449) proof-of-possession artefacts.
    /// </summary>
    public static KeyUsageContext DpopProof { get; } = new(8);


    /// <summary>
    /// Signing of OpenID Connect ID Tokens issued by the authorization server per
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#IDToken">OIDC Core §2</see>.
    /// </summary>
    /// <remarks>
    /// Distinct from <see cref="AccessTokenIssuance"/> because ID tokens carry
    /// different binding semantics — audience equals the OAuth Client ID rather
    /// than a resource server — and FAPI / RP Metadata Choices deployments may
    /// require different signing algorithms or rotation cadences.
    /// </remarks>
    public static KeyUsageContext IdTokenIssuance { get; } = new(9);


    private static readonly List<KeyUsageContext> contexts =
    [
        None,
        AccessTokenIssuance,
        JarSigning,
        CredentialIssuance,
        ResponseDecryption,
        ClientAssertion,
        VerifierAttestation,
        WalletAttestation,
        DpopProof,
        IdTokenIssuance
    ];


    /// <summary>
    /// Gets all registered usage context values.
    /// </summary>
    public static IReadOnlyList<KeyUsageContext> Contexts => contexts.AsReadOnly();


    /// <summary>
    /// Creates a new usage context value for protocol roles not defined by the library.
    /// </summary>
    /// <param name="code">The unique numeric code for this context.</param>
    /// <returns>The newly created usage context.</returns>
    /// <exception cref="ArgumentException">Thrown when the code already exists.</exception>
    /// <remarks>
    /// Use code values above 1000 to avoid collisions with future library additions.
    /// This method is not thread-safe. Call it only during application startup.
    /// </remarks>
    public static KeyUsageContext Create(int code)
    {
        for(int i = 0; i < contexts.Count; ++i)
        {
            if(contexts[i].Code == code)
            {
                throw new ArgumentException($"KeyUsageContext code {code} already exists.");
            }
        }

        var created = new KeyUsageContext(code);
        contexts.Add(created);
        return created;
    }


    /// <inheritdoc />
    public override string ToString() => KeyUsageContextNames.GetName(this);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(KeyUsageContext other) => Code == other.Code;


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) =>
        obj is KeyUsageContext other && Equals(other);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => Code;


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(in KeyUsageContext left, in KeyUsageContext right) =>
        left.Equals(right);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(in KeyUsageContext left, in KeyUsageContext right) =>
        !left.Equals(right);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(in object left, in KeyUsageContext right) =>
        Equals(left, right);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(in KeyUsageContext left, in object right) =>
        Equals(left, right);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(in object left, in KeyUsageContext right) =>
        !Equals(left, right);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(in KeyUsageContext left, in object right) =>
        !Equals(left, right);
}


/// <summary>
/// Provides human-readable names for <see cref="KeyUsageContext"/> values.
/// </summary>
public static class KeyUsageContextNames
{
    /// <summary>
    /// Gets the name for the specified usage context.
    /// </summary>
    public static string GetName(KeyUsageContext context) => GetName(context.Code);


    /// <summary>
    /// Gets the name for the specified usage context code.
    /// </summary>
    public static string GetName(int code) => code switch
    {
        var c when c == KeyUsageContext.None.Code => nameof(KeyUsageContext.None),
        var c when c == KeyUsageContext.AccessTokenIssuance.Code => nameof(KeyUsageContext.AccessTokenIssuance),
        var c when c == KeyUsageContext.JarSigning.Code => nameof(KeyUsageContext.JarSigning),
        var c when c == KeyUsageContext.CredentialIssuance.Code => nameof(KeyUsageContext.CredentialIssuance),
        var c when c == KeyUsageContext.ResponseDecryption.Code => nameof(KeyUsageContext.ResponseDecryption),
        var c when c == KeyUsageContext.ClientAssertion.Code => nameof(KeyUsageContext.ClientAssertion),
        var c when c == KeyUsageContext.VerifierAttestation.Code => nameof(KeyUsageContext.VerifierAttestation),
        var c when c == KeyUsageContext.WalletAttestation.Code => nameof(KeyUsageContext.WalletAttestation),
        var c when c == KeyUsageContext.DpopProof.Code => nameof(KeyUsageContext.DpopProof),
        var c when c == KeyUsageContext.IdTokenIssuance.Code => nameof(KeyUsageContext.IdTokenIssuance),
        _ => $"Custom ({code})"
    };
}
