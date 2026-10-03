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
}
