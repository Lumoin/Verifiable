namespace Verifiable.OAuth.Oid4Vci;

/// <summary>
/// What a Credential Request asks for: a Credential Configuration by its
/// <c>credential_configuration_id</c>, or a Credential Dataset by a <c>credential_identifier</c>
/// the Token Response granted. Exactly one of <see cref="CredentialConfigurationId"/> and
/// <see cref="CredentialIdentifier"/> is set, so a request naming both or neither cannot be
/// expressed.
/// </summary>
/// <remarks>
/// <para>
/// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-8.2">OID4VCI 1.0 Section 8.2</see>
/// on <c>credential_identifier</c>: "When this parameter is used, the credential_configuration_id
/// MUST NOT be present." On <c>credential_configuration_id</c>: "When this parameter is used, the
/// credential_identifier MUST NOT be present."
/// </para>
/// <para>
/// A Wallet whose Token Response returned <c>credential_identifiers</c> requests by one of them
/// (<see cref="ForIdentifier"/>); otherwise it requests by the configuration
/// (<see cref="ForConfiguration"/>). <see cref="FromGrantedAuthorizations"/> chooses between the
/// two from the <see cref="GrantedCredentialAuthorization"/> values the library read off the Token
/// Response, so a Wallet does not read its own JSON to decide.
/// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-6.2">OID4VCI 1.0 Section 6.2</see>:
/// "The Wallet MUST use these identifiers together with an Access Token in subsequent Credential
/// Requests."
/// </para>
/// </remarks>
public sealed record CredentialRequestTarget
{
    /// <summary>
    /// Creates a target holding exactly one of the two values; the factories are the only callers.
    /// </summary>
    /// <param name="credentialConfigurationId">The configuration identifier, or <see langword="null"/>.</param>
    /// <param name="credentialIdentifier">The Credential identifier, or <see langword="null"/>.</param>
    private CredentialRequestTarget(string? credentialConfigurationId, string? credentialIdentifier)
    {
        CredentialConfigurationId = credentialConfigurationId;
        CredentialIdentifier = credentialIdentifier;
    }


    /// <summary>
    /// The <c>credential_configuration_id</c> the request names, or <see langword="null"/> when it
    /// names a <see cref="CredentialIdentifier"/>.
    /// </summary>
    public string? CredentialConfigurationId { get; }

    /// <summary>
    /// The <c>credential_identifier</c> the request names, or <see langword="null"/> when it names a
    /// <see cref="CredentialConfigurationId"/>.
    /// </summary>
    public string? CredentialIdentifier { get; }


    /// <summary>
    /// A target naming a Credential Configuration, for a Token Response that returned no
    /// <c>credential_identifiers</c>.
    /// </summary>
    /// <param name="credentialConfigurationId">A member name of the Credential Issuer's <c>credential_configurations_supported</c> object.</param>
    /// <returns>The target naming <paramref name="credentialConfigurationId"/> alone.</returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="credentialConfigurationId"/> is null, empty or white space.</exception>
    public static CredentialRequestTarget ForConfiguration(string credentialConfigurationId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(credentialConfigurationId);

        return new CredentialRequestTarget(credentialConfigurationId, credentialIdentifier: null);
    }


    /// <summary>
    /// A target naming a Credential Dataset by one of the <c>credential_identifiers</c> the Token
    /// Response returned.
    /// </summary>
    /// <param name="credentialIdentifier">One of the granted <c>credential_identifiers</c> values.</param>
    /// <returns>The target naming <paramref name="credentialIdentifier"/> alone.</returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="credentialIdentifier"/> is null, empty or white space.</exception>
    public static CredentialRequestTarget ForIdentifier(string credentialIdentifier)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(credentialIdentifier);

        return new CredentialRequestTarget(credentialConfigurationId: null, credentialIdentifier);
    }


    /// <summary>
    /// The target a Wallet requests under the <c>openid_credential</c> authorizations its Token
    /// Response granted: <see cref="ForIdentifier"/> with the first identifier of the first
    /// authorization naming <paramref name="credentialConfigurationId"/>;
    /// <see cref="ForConfiguration"/> when the response granted none; <see langword="null"/> when it
    /// granted authorizations for other configurations only, since then neither member may be
    /// named.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The list is <see cref="AuthCode.TokenResponse.GrantedCredentialAuthorizations"/>, or the
    /// token result's <see cref="AuthCode.AuthCodeFlowEndpointResult.GrantedCredentialAuthorizations"/>
    /// on the authorization-code path; the Pre-Authorized Code entry points of
    /// <see cref="Wallet.Oid4VciWalletClient"/> choose through this factory too. Several entries may
    /// name one configuration, and the first of them decides.
    /// </para>
    /// <para>
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-8.2">OID4VCI 1.0 Section 8.2</see>:
    /// "credential_identifier: REQUIRED when an Authorization Details of type openid_credential was
    /// returned from the Token Response. It MUST NOT be used otherwise. A string that identifies a
    /// Credential Dataset that is requested for issuance. When this parameter is used, the
    /// credential_configuration_id MUST NOT be present." And: "credential_configuration_id: REQUIRED
    /// if a credential_identifiers parameter was not returned from the Token Response as part of the
    /// authorization_details parameter. It MUST NOT be used otherwise."
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-6.2">OID4VCI 1.0 Section 6.2</see>:
    /// "The Wallet MUST use these identifiers together with an Access Token in subsequent Credential
    /// Requests."
    /// <see href="https://www.rfc-editor.org/rfc/rfc9396#section-2">RFC 9396 Section 2</see>:
    /// "An authorization_details array MAY contain multiple entries of the same type."
    /// </para>
    /// </remarks>
    /// <param name="credentialConfigurationId">The configuration the Wallet requests.</param>
    /// <param name="grantedAuthorizations">The granted authorizations, in the order the Token Response lists them.</param>
    /// <returns>The target, or <see langword="null"/> when the grant names other configurations only.</returns>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="credentialConfigurationId"/> is null, empty or white space, when an
    /// entry of <paramref name="grantedAuthorizations"/> is null, or when the entry naming the
    /// configuration lists no identifier or a first identifier that is null, empty or white space.
    /// </exception>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="grantedAuthorizations"/> is null.</exception>
    public static CredentialRequestTarget? FromGrantedAuthorizations(
        string credentialConfigurationId,
        IReadOnlyList<GrantedCredentialAuthorization> grantedAuthorizations)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(credentialConfigurationId);
        ArgumentNullException.ThrowIfNull(grantedAuthorizations);

        if(grantedAuthorizations.Count == 0)
        {
            return ForConfiguration(credentialConfigurationId);
        }

        foreach(GrantedCredentialAuthorization? granted in grantedAuthorizations)
        {
            if(granted is null)
            {
                throw new ArgumentException("A granted authorization is null.", nameof(grantedAuthorizations));
            }

            if(!string.Equals(granted.CredentialConfigurationId, credentialConfigurationId, StringComparison.Ordinal))
            {
                continue;
            }

            return granted.CredentialIdentifiers switch
            {
                [string firstIdentifier, ..] when !string.IsNullOrWhiteSpace(firstIdentifier) => ForIdentifier(firstIdentifier),
                _ => throw new ArgumentException(
                    "The granted authorization naming the configuration lists no usable identifier.", nameof(grantedAuthorizations))
            };
        }

        return null;
    }
}
