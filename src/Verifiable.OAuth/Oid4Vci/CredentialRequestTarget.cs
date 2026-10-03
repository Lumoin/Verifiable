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
/// (<see cref="ForConfiguration"/>).
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
}
