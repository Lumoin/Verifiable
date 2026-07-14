using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Table-driven coverage for the string-valued well-known catalog family's predicates (the
/// WellKnownJwaValues shape: UTF-8 span plus interned string plus per-member Is* predicates),
/// added or converted across the WebAuthn/CTAP wire-string catalogs during the
/// style-conformance wave. Each catalog's own value set is checked so every predicate accepts
/// its own value and rejects every sibling value.
/// </summary>
[TestClass]
internal sealed class WellKnownCatalogStringPredicateTests
{
    /// <summary>Every Is* predicate on <see cref="WellKnownCtapVersions"/> matches only its own declared value.</summary>
    [TestMethod]
    public void WellKnownCtapVersionsPredicatesMatchOnlyTheirOwnValue()
    {
        string[] values =
        [
            WellKnownCtapVersions.Fido23,
            WellKnownCtapVersions.Fido21,
            WellKnownCtapVersions.Fido21Pre,
            WellKnownCtapVersions.Fido20,
            WellKnownCtapVersions.U2fV2,
        ];

        Func<string, bool>[] predicates =
        [
            WellKnownCtapVersions.IsFido23,
            WellKnownCtapVersions.IsFido21,
            WellKnownCtapVersions.IsFido21Pre,
            WellKnownCtapVersions.IsFido20,
            WellKnownCtapVersions.IsU2fV2,
        ];

        for(int i = 0; i < values.Length; i++)
        {
            Assert.IsTrue(predicates[i](values[i]), $"Predicate at index {i} must accept its own value.");

            int matchCount = 0;
            for(int j = 0; j < predicates.Length; j++)
            {
                matchCount += predicates[j](values[i]) ? 1 : 0;
            }

            Assert.AreEqual(1, matchCount, $"Value at index {i} must match exactly one predicate in its own catalog.");
        }
    }


    /// <summary>Every Is* predicate on <see cref="WellKnownCtapGetInfoOptionIds"/> matches only its own declared value.</summary>
    [TestMethod]
    public void WellKnownCtapGetInfoOptionIdsPredicatesMatchOnlyTheirOwnValue()
    {
        string[] values =
        [
            WellKnownCtapGetInfoOptionIds.Ep,
            WellKnownCtapGetInfoOptionIds.Plat,
            WellKnownCtapGetInfoOptionIds.Rk,
            WellKnownCtapGetInfoOptionIds.Uv,
            WellKnownCtapGetInfoOptionIds.AlwaysUv,
            WellKnownCtapGetInfoOptionIds.CredMgmt,
            WellKnownCtapGetInfoOptionIds.AuthnrCfg,
            WellKnownCtapGetInfoOptionIds.BioEnroll,
            WellKnownCtapGetInfoOptionIds.ClientPin,
            WellKnownCtapGetInfoOptionIds.LargeBlobs,
            WellKnownCtapGetInfoOptionIds.UvBioEnroll,
            WellKnownCtapGetInfoOptionIds.PinUvAuthToken,
            WellKnownCtapGetInfoOptionIds.SetMinPinLength,
            WellKnownCtapGetInfoOptionIds.MakeCredUvNotRqd,
        ];

        Func<string, bool>[] predicates =
        [
            WellKnownCtapGetInfoOptionIds.IsEp,
            WellKnownCtapGetInfoOptionIds.IsPlat,
            WellKnownCtapGetInfoOptionIds.IsRk,
            WellKnownCtapGetInfoOptionIds.IsUv,
            WellKnownCtapGetInfoOptionIds.IsAlwaysUv,
            WellKnownCtapGetInfoOptionIds.IsCredMgmt,
            WellKnownCtapGetInfoOptionIds.IsAuthnrCfg,
            WellKnownCtapGetInfoOptionIds.IsBioEnroll,
            WellKnownCtapGetInfoOptionIds.IsClientPin,
            WellKnownCtapGetInfoOptionIds.IsLargeBlobs,
            WellKnownCtapGetInfoOptionIds.IsUvBioEnroll,
            WellKnownCtapGetInfoOptionIds.IsPinUvAuthToken,
            WellKnownCtapGetInfoOptionIds.IsSetMinPinLength,
            WellKnownCtapGetInfoOptionIds.IsMakeCredUvNotRqd,
        ];

        for(int i = 0; i < values.Length; i++)
        {
            Assert.IsTrue(predicates[i](values[i]), $"Predicate at index {i} must accept its own value.");

            int matchCount = 0;
            for(int j = 0; j < predicates.Length; j++)
            {
                matchCount += predicates[j](values[i]) ? 1 : 0;
            }

            Assert.AreEqual(1, matchCount, $"Value at index {i} must match exactly one predicate in its own catalog.");
        }
    }


    /// <summary>Every Is* predicate on <see cref="WellKnownCtapRequestOptionIds"/> matches only its own declared value.</summary>
    [TestMethod]
    public void WellKnownCtapRequestOptionIdsPredicatesMatchOnlyTheirOwnValue()
    {
        string[] values =
        [
            WellKnownCtapRequestOptionIds.Rk,
            WellKnownCtapRequestOptionIds.Up,
            WellKnownCtapRequestOptionIds.Uv,
        ];

        Func<string, bool>[] predicates =
        [
            WellKnownCtapRequestOptionIds.IsRk,
            WellKnownCtapRequestOptionIds.IsUp,
            WellKnownCtapRequestOptionIds.IsUv,
        ];

        for(int i = 0; i < values.Length; i++)
        {
            Assert.IsTrue(predicates[i](values[i]), $"Predicate at index {i} must accept its own value.");

            int matchCount = 0;
            for(int j = 0; j < predicates.Length; j++)
            {
                matchCount += predicates[j](values[i]) ? 1 : 0;
            }

            Assert.AreEqual(1, matchCount, $"Value at index {i} must match exactly one predicate in its own catalog.");
        }
    }


    /// <summary>Every Is* predicate on <see cref="WellKnownClientDataTypes"/> matches only its own declared value.</summary>
    [TestMethod]
    public void WellKnownClientDataTypesPredicatesMatchOnlyTheirOwnValue()
    {
        string[] values =
        [
            WellKnownClientDataTypes.Create,
            WellKnownClientDataTypes.Get,
        ];

        Func<string, bool>[] predicates =
        [
            WellKnownClientDataTypes.IsCreate,
            WellKnownClientDataTypes.IsGet,
        ];

        for(int i = 0; i < values.Length; i++)
        {
            Assert.IsTrue(predicates[i](values[i]), $"Predicate at index {i} must accept its own value.");

            int matchCount = 0;
            for(int j = 0; j < predicates.Length; j++)
            {
                matchCount += predicates[j](values[i]) ? 1 : 0;
            }

            Assert.AreEqual(1, matchCount, $"Value at index {i} must match exactly one predicate in its own catalog.");
        }
    }


    /// <summary>Every Is* predicate on <see cref="WellKnownWebAuthnAttestationFormats"/> matches only its own declared value.</summary>
    [TestMethod]
    public void WellKnownWebAuthnAttestationFormatsPredicatesMatchOnlyTheirOwnValue()
    {
        string[] values =
        [
            WellKnownWebAuthnAttestationFormats.None,
            WellKnownWebAuthnAttestationFormats.Packed,
            WellKnownWebAuthnAttestationFormats.Tpm,
            WellKnownWebAuthnAttestationFormats.AndroidKey,
            WellKnownWebAuthnAttestationFormats.AndroidSafetyNet,
            WellKnownWebAuthnAttestationFormats.FidoU2f,
            WellKnownWebAuthnAttestationFormats.Apple,
        ];

        Func<string, bool>[] predicates =
        [
            WellKnownWebAuthnAttestationFormats.IsNone,
            WellKnownWebAuthnAttestationFormats.IsPacked,
            WellKnownWebAuthnAttestationFormats.IsTpm,
            WellKnownWebAuthnAttestationFormats.IsAndroidKey,
            WellKnownWebAuthnAttestationFormats.IsAndroidSafetyNet,
            WellKnownWebAuthnAttestationFormats.IsFidoU2f,
            WellKnownWebAuthnAttestationFormats.IsApple,
        ];

        for(int i = 0; i < values.Length; i++)
        {
            Assert.IsTrue(predicates[i](values[i]), $"Predicate at index {i} must accept its own value.");

            int matchCount = 0;
            for(int j = 0; j < predicates.Length; j++)
            {
                matchCount += predicates[j](values[i]) ? 1 : 0;
            }

            Assert.AreEqual(1, matchCount, $"Value at index {i} must match exactly one predicate in its own catalog.");
        }
    }


    /// <summary>Every Is* predicate on <see cref="WellKnownWebAuthnExtensionIdentifiers"/> matches only its own declared value.</summary>
    [TestMethod]
    public void WellKnownWebAuthnExtensionIdentifiersPredicatesMatchOnlyTheirOwnValue()
    {
        string[] values =
        [
            WellKnownWebAuthnExtensionIdentifiers.AppId,
            WellKnownWebAuthnExtensionIdentifiers.AppIdExclude,
            WellKnownWebAuthnExtensionIdentifiers.LargeBlob,
            WellKnownWebAuthnExtensionIdentifiers.LargeBlobKey,
            WellKnownWebAuthnExtensionIdentifiers.CredProtect,
            WellKnownWebAuthnExtensionIdentifiers.MinPinLength,
            WellKnownWebAuthnExtensionIdentifiers.HmacSecret,
            WellKnownWebAuthnExtensionIdentifiers.HmacSecretMc,
        ];

        Func<string, bool>[] predicates =
        [
            WellKnownWebAuthnExtensionIdentifiers.IsAppId,
            WellKnownWebAuthnExtensionIdentifiers.IsAppIdExclude,
            WellKnownWebAuthnExtensionIdentifiers.IsLargeBlob,
            WellKnownWebAuthnExtensionIdentifiers.IsLargeBlobKey,
            WellKnownWebAuthnExtensionIdentifiers.IsCredProtect,
            WellKnownWebAuthnExtensionIdentifiers.IsMinPinLength,
            WellKnownWebAuthnExtensionIdentifiers.IsHmacSecret,
            WellKnownWebAuthnExtensionIdentifiers.IsHmacSecretMc,
        ];

        for(int i = 0; i < values.Length; i++)
        {
            Assert.IsTrue(predicates[i](values[i]), $"Predicate at index {i} must accept its own value.");

            int matchCount = 0;
            for(int j = 0; j < predicates.Length; j++)
            {
                matchCount += predicates[j](values[i]) ? 1 : 0;
            }

            Assert.AreEqual(1, matchCount, $"Value at index {i} must match exactly one predicate in its own catalog.");
        }
    }


    /// <summary>Every Is* predicate on <see cref="WellKnownAttestationConveyancePreferences"/> matches only its own declared value.</summary>
    [TestMethod]
    public void WellKnownAttestationConveyancePreferencesPredicatesMatchOnlyTheirOwnValue()
    {
        string[] values =
        [
            WellKnownAttestationConveyancePreferences.None,
            WellKnownAttestationConveyancePreferences.Indirect,
            WellKnownAttestationConveyancePreferences.Direct,
            WellKnownAttestationConveyancePreferences.Enterprise,
        ];

        Func<string, bool>[] predicates =
        [
            WellKnownAttestationConveyancePreferences.IsNone,
            WellKnownAttestationConveyancePreferences.IsIndirect,
            WellKnownAttestationConveyancePreferences.IsDirect,
            WellKnownAttestationConveyancePreferences.IsEnterprise,
        ];

        for(int i = 0; i < values.Length; i++)
        {
            Assert.IsTrue(predicates[i](values[i]), $"Predicate at index {i} must accept its own value.");

            int matchCount = 0;
            for(int j = 0; j < predicates.Length; j++)
            {
                matchCount += predicates[j](values[i]) ? 1 : 0;
            }

            Assert.AreEqual(1, matchCount, $"Value at index {i} must match exactly one predicate in its own catalog.");
        }
    }


    /// <summary>Every Is* predicate on <see cref="WellKnownAuthenticatorAttachments"/> matches only its own declared value.</summary>
    [TestMethod]
    public void WellKnownAuthenticatorAttachmentsPredicatesMatchOnlyTheirOwnValue()
    {
        string[] values =
        [
            WellKnownAuthenticatorAttachments.Platform,
            WellKnownAuthenticatorAttachments.CrossPlatform,
        ];

        Func<string, bool>[] predicates =
        [
            WellKnownAuthenticatorAttachments.IsPlatform,
            WellKnownAuthenticatorAttachments.IsCrossPlatform,
        ];

        for(int i = 0; i < values.Length; i++)
        {
            Assert.IsTrue(predicates[i](values[i]), $"Predicate at index {i} must accept its own value.");

            int matchCount = 0;
            for(int j = 0; j < predicates.Length; j++)
            {
                matchCount += predicates[j](values[i]) ? 1 : 0;
            }

            Assert.AreEqual(1, matchCount, $"Value at index {i} must match exactly one predicate in its own catalog.");
        }
    }


    /// <summary>Every Is* predicate on <see cref="WellKnownPublicKeyCredentialHints"/> matches only its own declared value.</summary>
    [TestMethod]
    public void WellKnownPublicKeyCredentialHintsPredicatesMatchOnlyTheirOwnValue()
    {
        string[] values =
        [
            WellKnownPublicKeyCredentialHints.SecurityKey,
            WellKnownPublicKeyCredentialHints.ClientDevice,
            WellKnownPublicKeyCredentialHints.Hybrid,
        ];

        Func<string, bool>[] predicates =
        [
            WellKnownPublicKeyCredentialHints.IsSecurityKey,
            WellKnownPublicKeyCredentialHints.IsClientDevice,
            WellKnownPublicKeyCredentialHints.IsHybrid,
        ];

        for(int i = 0; i < values.Length; i++)
        {
            Assert.IsTrue(predicates[i](values[i]), $"Predicate at index {i} must accept its own value.");

            int matchCount = 0;
            for(int j = 0; j < predicates.Length; j++)
            {
                matchCount += predicates[j](values[i]) ? 1 : 0;
            }

            Assert.AreEqual(1, matchCount, $"Value at index {i} must match exactly one predicate in its own catalog.");
        }
    }


    /// <summary>Every Is* predicate on <see cref="WellKnownResidentKeyRequirements"/> matches only its own declared value.</summary>
    [TestMethod]
    public void WellKnownResidentKeyRequirementsPredicatesMatchOnlyTheirOwnValue()
    {
        string[] values =
        [
            WellKnownResidentKeyRequirements.Discouraged,
            WellKnownResidentKeyRequirements.Preferred,
            WellKnownResidentKeyRequirements.Required,
        ];

        Func<string, bool>[] predicates =
        [
            WellKnownResidentKeyRequirements.IsDiscouraged,
            WellKnownResidentKeyRequirements.IsPreferred,
            WellKnownResidentKeyRequirements.IsRequired,
        ];

        for(int i = 0; i < values.Length; i++)
        {
            Assert.IsTrue(predicates[i](values[i]), $"Predicate at index {i} must accept its own value.");

            int matchCount = 0;
            for(int j = 0; j < predicates.Length; j++)
            {
                matchCount += predicates[j](values[i]) ? 1 : 0;
            }

            Assert.AreEqual(1, matchCount, $"Value at index {i} must match exactly one predicate in its own catalog.");
        }
    }


    /// <summary>Every Is* predicate on <see cref="WellKnownUserVerificationRequirements"/> matches only its own declared value.</summary>
    [TestMethod]
    public void WellKnownUserVerificationRequirementsPredicatesMatchOnlyTheirOwnValue()
    {
        string[] values =
        [
            WellKnownUserVerificationRequirements.Required,
            WellKnownUserVerificationRequirements.Preferred,
            WellKnownUserVerificationRequirements.Discouraged,
        ];

        Func<string, bool>[] predicates =
        [
            WellKnownUserVerificationRequirements.IsRequired,
            WellKnownUserVerificationRequirements.IsPreferred,
            WellKnownUserVerificationRequirements.IsDiscouraged,
        ];

        for(int i = 0; i < values.Length; i++)
        {
            Assert.IsTrue(predicates[i](values[i]), $"Predicate at index {i} must accept its own value.");

            int matchCount = 0;
            for(int j = 0; j < predicates.Length; j++)
            {
                matchCount += predicates[j](values[i]) ? 1 : 0;
            }

            Assert.AreEqual(1, matchCount, $"Value at index {i} must match exactly one predicate in its own catalog.");
        }
    }


    /// <summary>Every Is* predicate on <see cref="WellKnownLargeBlobSupports"/> matches only its own declared value.</summary>
    [TestMethod]
    public void WellKnownLargeBlobSupportsPredicatesMatchOnlyTheirOwnValue()
    {
        string[] values =
        [
            WellKnownLargeBlobSupports.Required,
            WellKnownLargeBlobSupports.Preferred,
        ];

        Func<string, bool>[] predicates =
        [
            WellKnownLargeBlobSupports.IsRequired,
            WellKnownLargeBlobSupports.IsPreferred,
        ];

        for(int i = 0; i < values.Length; i++)
        {
            Assert.IsTrue(predicates[i](values[i]), $"Predicate at index {i} must accept its own value.");

            int matchCount = 0;
            for(int j = 0; j < predicates.Length; j++)
            {
                matchCount += predicates[j](values[i]) ? 1 : 0;
            }

            Assert.AreEqual(1, matchCount, $"Value at index {i} must match exactly one predicate in its own catalog.");
        }
    }


    /// <summary>Every Is* predicate on <see cref="WellKnownCredProtectPolicies"/> matches only its own declared value.</summary>
    [TestMethod]
    public void WellKnownCredProtectPoliciesPredicatesMatchOnlyTheirOwnValue()
    {
        string[] values =
        [
            WellKnownCredProtectPolicies.UserVerificationOptional,
            WellKnownCredProtectPolicies.UserVerificationOptionalWithCredentialIdList,
            WellKnownCredProtectPolicies.UserVerificationRequired,
        ];

        Func<string, bool>[] predicates =
        [
            WellKnownCredProtectPolicies.IsUserVerificationOptional,
            WellKnownCredProtectPolicies.IsUserVerificationOptionalWithCredentialIdList,
            WellKnownCredProtectPolicies.IsUserVerificationRequired,
        ];

        for(int i = 0; i < values.Length; i++)
        {
            Assert.IsTrue(predicates[i](values[i]), $"Predicate at index {i} must accept its own value.");

            int matchCount = 0;
            for(int j = 0; j < predicates.Length; j++)
            {
                matchCount += predicates[j](values[i]) ? 1 : 0;
            }

            Assert.AreEqual(1, matchCount, $"Value at index {i} must match exactly one predicate in its own catalog.");
        }
    }


    /// <summary>Every Is* predicate on <see cref="WellKnownAuthenticatorStatuses"/> matches only its own declared value.</summary>
    [TestMethod]
    public void WellKnownAuthenticatorStatusesPredicatesMatchOnlyTheirOwnValue()
    {
        string[] values =
        [
            WellKnownAuthenticatorStatuses.NotFidoCertified,
            WellKnownAuthenticatorStatuses.FidoCertified,
            WellKnownAuthenticatorStatuses.UserVerificationBypass,
            WellKnownAuthenticatorStatuses.AttestationKeyCompromise,
            WellKnownAuthenticatorStatuses.UserKeyRemoteCompromise,
            WellKnownAuthenticatorStatuses.UserKeyPhysicalCompromise,
            WellKnownAuthenticatorStatuses.UpdateAvailable,
            WellKnownAuthenticatorStatuses.Revoked,
            WellKnownAuthenticatorStatuses.SelfAssertionSubmitted,
            WellKnownAuthenticatorStatuses.FidoCertifiedL1,
            WellKnownAuthenticatorStatuses.FidoCertifiedL1Plus,
            WellKnownAuthenticatorStatuses.FidoCertifiedL2,
            WellKnownAuthenticatorStatuses.FidoCertifiedL2Plus,
            WellKnownAuthenticatorStatuses.FidoCertifiedL3,
            WellKnownAuthenticatorStatuses.FidoCertifiedL3Plus,
            WellKnownAuthenticatorStatuses.Fips140CertifiedL1,
            WellKnownAuthenticatorStatuses.Fips140CertifiedL2,
            WellKnownAuthenticatorStatuses.Fips140CertifiedL3,
            WellKnownAuthenticatorStatuses.Fips140CertifiedL4,
        ];

        Func<string, bool>[] predicates =
        [
            WellKnownAuthenticatorStatuses.IsNotFidoCertified,
            WellKnownAuthenticatorStatuses.IsFidoCertified,
            WellKnownAuthenticatorStatuses.IsUserVerificationBypass,
            WellKnownAuthenticatorStatuses.IsAttestationKeyCompromise,
            WellKnownAuthenticatorStatuses.IsUserKeyRemoteCompromise,
            WellKnownAuthenticatorStatuses.IsUserKeyPhysicalCompromise,
            WellKnownAuthenticatorStatuses.IsUpdateAvailable,
            WellKnownAuthenticatorStatuses.IsRevoked,
            WellKnownAuthenticatorStatuses.IsSelfAssertionSubmitted,
            WellKnownAuthenticatorStatuses.IsFidoCertifiedL1,
            WellKnownAuthenticatorStatuses.IsFidoCertifiedL1Plus,
            WellKnownAuthenticatorStatuses.IsFidoCertifiedL2,
            WellKnownAuthenticatorStatuses.IsFidoCertifiedL2Plus,
            WellKnownAuthenticatorStatuses.IsFidoCertifiedL3,
            WellKnownAuthenticatorStatuses.IsFidoCertifiedL3Plus,
            WellKnownAuthenticatorStatuses.IsFips140CertifiedL1,
            WellKnownAuthenticatorStatuses.IsFips140CertifiedL2,
            WellKnownAuthenticatorStatuses.IsFips140CertifiedL3,
            WellKnownAuthenticatorStatuses.IsFips140CertifiedL4,
        ];

        for(int i = 0; i < values.Length; i++)
        {
            Assert.IsTrue(predicates[i](values[i]), $"Predicate at index {i} must accept its own value.");

            int matchCount = 0;
            for(int j = 0; j < predicates.Length; j++)
            {
                matchCount += predicates[j](values[i]) ? 1 : 0;
            }

            Assert.AreEqual(1, matchCount, $"Value at index {i} must match exactly one predicate in its own catalog.");
        }
    }


    /// <summary>
    /// The sole Is* predicate on each single-member string catalog accepts its own value and
    /// rejects a value borrowed from an unrelated catalog of the same wire shape.
    /// </summary>
    [TestMethod]
    public void SingleMemberCatalogPredicatesAcceptOwnValueAndRejectAnUnrelatedValue()
    {
        Assert.IsTrue(WellKnownWebAuthnValues.IsRelatedOriginsWellKnownPath(WellKnownWebAuthnValues.RelatedOriginsWellKnownPath));
        Assert.IsFalse(WellKnownWebAuthnValues.IsRelatedOriginsWellKnownPath(WellKnownClientDataTypes.Create));
        Assert.IsTrue(WellKnownPublicKeyCredentialTypes.IsPublicKey(WellKnownPublicKeyCredentialTypes.PublicKey));
        Assert.IsFalse(WellKnownPublicKeyCredentialTypes.IsPublicKey(WellKnownClientDataTypes.Create));
    }
}
