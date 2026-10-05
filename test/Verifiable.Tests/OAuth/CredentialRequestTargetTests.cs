using Verifiable.OAuth.Oid4Vci;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// The shape of <see cref="CredentialRequestTarget"/>, the one value through which a Wallet names
/// what a Credential Request asks for: a configuration or a granted identifier, never both and never
/// neither.
/// </summary>
[TestClass]
internal sealed class CredentialRequestTargetTests
{
    /// <summary>
    /// A target for a configuration carries the configuration identifier and no Credential identifier.
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-8.2">OID4VCI 1.0 Section 8.2</see>:
    /// "When this parameter is used, the credential_identifier MUST NOT be present."
    /// </summary>
    [TestMethod]
    public void ATargetForAConfigurationNamesTheConfigurationAlone()
    {
        CredentialRequestTarget target = CredentialRequestTarget.ForConfiguration("UniversityDegree_dc_sd_jwt");

        Assert.AreEqual("UniversityDegree_dc_sd_jwt", target.CredentialConfigurationId);
        Assert.IsNull(target.CredentialIdentifier);
    }


    /// <summary>
    /// A target for a granted identifier carries the Credential identifier and no configuration identifier.
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-8.2">OID4VCI 1.0 Section 8.2</see>:
    /// "When this parameter is used, the credential_configuration_id MUST NOT be present."
    /// </summary>
    [TestMethod]
    public void ATargetForAnIdentifierNamesTheIdentifierAlone()
    {
        CredentialRequestTarget target = CredentialRequestTarget.ForIdentifier("dataset-1");

        Assert.AreEqual("dataset-1", target.CredentialIdentifier);
        Assert.IsNull(target.CredentialConfigurationId);
    }


    /// <summary>
    /// A grant naming the requested configuration makes the target the first identifier it lists.
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-8.2">OID4VCI 1.0 Section 8.2</see>:
    /// "credential_identifier: REQUIRED when an Authorization Details of type openid_credential was
    /// returned from the Token Response. It MUST NOT be used otherwise."
    /// </summary>
    [TestMethod]
    public void AGrantForTheConfigurationTargetsItsFirstIdentifier()
    {
        CredentialRequestTarget? target = CredentialRequestTarget.FromGrantedAuthorizations(
            "UniversityDegree_dc_sd_jwt",
            [
                new GrantedCredentialAuthorization
                {
                    CredentialConfigurationId = "EmployeeBadge_dc_sd_jwt",
                    CredentialIdentifiers = ["badge-1"]
                },
                new GrantedCredentialAuthorization
                {
                    CredentialConfigurationId = "UniversityDegree_dc_sd_jwt",
                    CredentialIdentifiers = ["dataset-1", "dataset-2"]
                }
            ]);

        Assert.IsNotNull(target);
        Assert.AreEqual("dataset-1", target.CredentialIdentifier);
        Assert.IsNull(target.CredentialConfigurationId);
    }


    /// <summary>
    /// Two granted entries may name the same configuration; the target is the first identifier of
    /// the first of them.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9396#section-2">RFC 9396 Section 2</see>:
    /// "An authorization_details array MAY contain multiple entries of the same type."
    /// </summary>
    [TestMethod]
    public void TwoGrantsForTheConfigurationTargetTheFirstEntrysFirstIdentifier()
    {
        CredentialRequestTarget? target = CredentialRequestTarget.FromGrantedAuthorizations(
            "UniversityDegree_dc_sd_jwt",
            [
                new GrantedCredentialAuthorization
                {
                    CredentialConfigurationId = "UniversityDegree_dc_sd_jwt",
                    CredentialIdentifiers = ["dataset-1"]
                },
                new GrantedCredentialAuthorization
                {
                    CredentialConfigurationId = "UniversityDegree_dc_sd_jwt",
                    CredentialIdentifiers = ["dataset-2"]
                }
            ]);

        Assert.IsNotNull(target);
        Assert.AreEqual("dataset-1", target.CredentialIdentifier);
        Assert.IsNull(target.CredentialConfigurationId);
    }


    /// <summary>
    /// Without a granted <c>openid_credential</c> authorization the target is the configuration.
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-8.2">OID4VCI 1.0 Section 8.2</see>:
    /// "credential_configuration_id: REQUIRED if a credential_identifiers parameter was not returned
    /// from the Token Response as part of the authorization_details parameter. It MUST NOT be used
    /// otherwise."
    /// </summary>
    [TestMethod]
    public void NoGrantTargetsTheConfiguration()
    {
        CredentialRequestTarget? target = CredentialRequestTarget.FromGrantedAuthorizations(
            "UniversityDegree_dc_sd_jwt", []);

        Assert.IsNotNull(target);
        Assert.AreEqual("UniversityDegree_dc_sd_jwt", target.CredentialConfigurationId);
        Assert.IsNull(target.CredentialIdentifier);
    }


    /// <summary>
    /// A grant naming other configurations only leaves no member the request may name: an
    /// identifier was returned, so the configuration is not to be used, and none was returned for the
    /// requested configuration, so there is no target.
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-8.2">OID4VCI 1.0 Section 8.2</see>:
    /// "credential_configuration_id: REQUIRED if a credential_identifiers parameter was not returned
    /// from the Token Response as part of the authorization_details parameter. It MUST NOT be used
    /// otherwise."
    /// </summary>
    [TestMethod]
    public void AGrantForOtherConfigurationsOnlyHasNoTarget()
    {
        CredentialRequestTarget? target = CredentialRequestTarget.FromGrantedAuthorizations(
            "UniversityDegree_dc_sd_jwt",
            [
                new GrantedCredentialAuthorization
                {
                    CredentialConfigurationId = "EmployeeBadge_dc_sd_jwt",
                    CredentialIdentifiers = ["badge-1"]
                }
            ]);

        Assert.IsNull(target);
    }
}
