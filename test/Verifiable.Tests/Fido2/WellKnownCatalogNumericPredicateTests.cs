using Verifiable.Apdu;
using Verifiable.Apdu.Ctap;
using Verifiable.Fido2.Ctap;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Table-driven coverage for the numeric-scalar well-known catalog family's predicates (the
/// WellKnownCoseAlgorithms shape: const plus per-member Is* predicates), added across the
/// CTAP2/ISO-7816-4 catalogs during the style-conformance wave. Each catalog's own value set
/// is checked so every predicate accepts its own value and rejects every sibling value.
/// </summary>
[TestClass]
internal sealed class WellKnownCatalogNumericPredicateTests
{
    /// <summary>
    /// Every Is* predicate on <see cref="WellKnownCommandParameters"/> accepts its own value; three of
    /// its four members coincide on the numeric value 0x00 by ISO/IEC 7816-4 accident (a plain class
    /// byte, a defined-zero P2, and the RFU sentinel all happen to be zero), so this asserts acceptance
    /// and a rejection against the one genuinely distinct sibling value (0x04) rather than exclusivity
    /// across the whole catalog.
    /// </summary>
    [TestMethod]
    public void WellKnownCommandParametersPredicatesAcceptOwnValueAndRejectADistinctSibling()
    {
        Assert.IsTrue(WellKnownCommandParameters.IsInterIndustryClassByte(WellKnownCommandParameters.InterIndustryClassByte));
        Assert.IsTrue(WellKnownCommandParameters.IsSelectByDfNameP1(WellKnownCommandParameters.SelectByDfNameP1));
        Assert.IsTrue(WellKnownCommandParameters.IsSelectFirstOrOnlyOccurrenceFciP2(WellKnownCommandParameters.SelectFirstOrOnlyOccurrenceFciP2));
        Assert.IsTrue(WellKnownCommandParameters.IsReservedForFutureUse(WellKnownCommandParameters.ReservedForFutureUse));

        Assert.IsFalse(WellKnownCommandParameters.IsInterIndustryClassByte(WellKnownCommandParameters.SelectByDfNameP1));
        Assert.IsFalse(WellKnownCommandParameters.IsSelectByDfNameP1(WellKnownCommandParameters.InterIndustryClassByte));
        Assert.IsFalse(WellKnownCommandParameters.IsSelectFirstOrOnlyOccurrenceFciP2(WellKnownCommandParameters.SelectByDfNameP1));
        Assert.IsFalse(WellKnownCommandParameters.IsReservedForFutureUse(WellKnownCommandParameters.SelectByDfNameP1));
    }


    /// <summary>
    /// Every Is* predicate on <see cref="WellKnownCtapCommandParameters"/> accepts its own value; the
    /// NFCCTAP class byte and the NFCCTAP_MSG "supports GETRESPONSE" P1 bit coincide on 0x80 by CTAP 2.3
    /// framing accident, so this asserts acceptance and a rejection against a genuinely distinct sibling
    /// value (0x11) rather than exclusivity across the whole catalog.
    /// </summary>
    [TestMethod]
    public void WellKnownCtapCommandParametersPredicatesAcceptOwnValueAndRejectADistinctSibling()
    {
        Assert.IsTrue(WellKnownCtapCommandParameters.IsClassByte(WellKnownCtapCommandParameters.ClassByte));
        Assert.IsTrue(WellKnownCtapCommandParameters.IsSupportsGetResponseP1Bit(WellKnownCtapCommandParameters.SupportsGetResponseP1Bit));
        Assert.IsTrue(WellKnownCtapCommandParameters.IsDeselectControlP1(WellKnownCtapCommandParameters.DeselectControlP1));
        Assert.IsTrue(WellKnownCtapCommandParameters.IsCancelP1(WellKnownCtapCommandParameters.CancelP1));

        Assert.IsFalse(WellKnownCtapCommandParameters.IsClassByte(WellKnownCtapCommandParameters.CancelP1));
        Assert.IsFalse(WellKnownCtapCommandParameters.IsSupportsGetResponseP1Bit(WellKnownCtapCommandParameters.CancelP1));
        Assert.IsFalse(WellKnownCtapCommandParameters.IsDeselectControlP1(WellKnownCtapCommandParameters.CancelP1));
        Assert.IsFalse(WellKnownCtapCommandParameters.IsCancelP1(WellKnownCtapCommandParameters.DeselectControlP1));
    }


    /// <summary>Every Is* predicate on <see cref="WellKnownCtapCommands"/> matches only its own declared value.</summary>
    [TestMethod]
    public void WellKnownCtapCommandsPredicatesMatchOnlyTheirOwnValue()
    {
        byte[] values =
        [
            WellKnownCtapCommands.MakeCredential,
            WellKnownCtapCommands.GetAssertion,
            WellKnownCtapCommands.GetInfo,
            WellKnownCtapCommands.ClientPin,
            WellKnownCtapCommands.Reset,
            WellKnownCtapCommands.GetNextAssertion,
            WellKnownCtapCommands.BioEnrollment,
            WellKnownCtapCommands.CredentialManagement,
            WellKnownCtapCommands.LargeBlobs,
            WellKnownCtapCommands.AuthenticatorConfig,
        ];

        Func<byte, bool>[] predicates =
        [
            WellKnownCtapCommands.IsMakeCredential,
            WellKnownCtapCommands.IsGetAssertion,
            WellKnownCtapCommands.IsGetInfo,
            WellKnownCtapCommands.IsClientPin,
            WellKnownCtapCommands.IsReset,
            WellKnownCtapCommands.IsGetNextAssertion,
            WellKnownCtapCommands.IsBioEnrollment,
            WellKnownCtapCommands.IsCredentialManagement,
            WellKnownCtapCommands.IsLargeBlobs,
            WellKnownCtapCommands.IsAuthenticatorConfig,
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


    /// <summary>Every Is* predicate on <see cref="WellKnownCtapStatusCodes"/> matches only its own declared value.</summary>
    [TestMethod]
    public void WellKnownCtapStatusCodesPredicatesMatchOnlyTheirOwnValue()
    {
        byte[] values =
        [
            WellKnownCtapStatusCodes.Ok,
            WellKnownCtapStatusCodes.InvalidCommand,
            WellKnownCtapStatusCodes.InvalidParameter,
            WellKnownCtapStatusCodes.InvalidLength,
            WellKnownCtapStatusCodes.InvalidSeq,
            WellKnownCtapStatusCodes.CborUnexpectedType,
            WellKnownCtapStatusCodes.InvalidCbor,
            WellKnownCtapStatusCodes.MissingParameter,
            WellKnownCtapStatusCodes.CredentialExcluded,
            WellKnownCtapStatusCodes.FpDatabaseFull,
            WellKnownCtapStatusCodes.LargeBlobStorageFull,
            WellKnownCtapStatusCodes.UnsupportedAlgorithm,
            WellKnownCtapStatusCodes.OperationDenied,
            WellKnownCtapStatusCodes.KeyStoreFull,
            WellKnownCtapStatusCodes.UnsupportedOption,
            WellKnownCtapStatusCodes.InvalidOption,
            WellKnownCtapStatusCodes.NoCredentials,
            WellKnownCtapStatusCodes.UserActionTimeout,
            WellKnownCtapStatusCodes.NotAllowed,
            WellKnownCtapStatusCodes.PinInvalid,
            WellKnownCtapStatusCodes.PinBlocked,
            WellKnownCtapStatusCodes.PinAuthInvalid,
            WellKnownCtapStatusCodes.PinAuthBlocked,
            WellKnownCtapStatusCodes.PinNotSet,
            WellKnownCtapStatusCodes.PuatRequired,
            WellKnownCtapStatusCodes.PinPolicyViolation,
            WellKnownCtapStatusCodes.UnauthorizedPermission,
            WellKnownCtapStatusCodes.UvBlocked,
            WellKnownCtapStatusCodes.IntegrityFailure,
            WellKnownCtapStatusCodes.UvInvalid,
            WellKnownCtapStatusCodes.InvalidSubcommand,
        ];

        Func<byte, bool>[] predicates =
        [
            WellKnownCtapStatusCodes.IsOk,
            WellKnownCtapStatusCodes.IsInvalidCommand,
            WellKnownCtapStatusCodes.IsInvalidParameter,
            WellKnownCtapStatusCodes.IsInvalidLength,
            WellKnownCtapStatusCodes.IsInvalidSeq,
            WellKnownCtapStatusCodes.IsCborUnexpectedType,
            WellKnownCtapStatusCodes.IsInvalidCbor,
            WellKnownCtapStatusCodes.IsMissingParameter,
            WellKnownCtapStatusCodes.IsCredentialExcluded,
            WellKnownCtapStatusCodes.IsFpDatabaseFull,
            WellKnownCtapStatusCodes.IsLargeBlobStorageFull,
            WellKnownCtapStatusCodes.IsUnsupportedAlgorithm,
            WellKnownCtapStatusCodes.IsOperationDenied,
            WellKnownCtapStatusCodes.IsKeyStoreFull,
            WellKnownCtapStatusCodes.IsUnsupportedOption,
            WellKnownCtapStatusCodes.IsInvalidOption,
            WellKnownCtapStatusCodes.IsNoCredentials,
            WellKnownCtapStatusCodes.IsUserActionTimeout,
            WellKnownCtapStatusCodes.IsNotAllowed,
            WellKnownCtapStatusCodes.IsPinInvalid,
            WellKnownCtapStatusCodes.IsPinBlocked,
            WellKnownCtapStatusCodes.IsPinAuthInvalid,
            WellKnownCtapStatusCodes.IsPinAuthBlocked,
            WellKnownCtapStatusCodes.IsPinNotSet,
            WellKnownCtapStatusCodes.IsPuatRequired,
            WellKnownCtapStatusCodes.IsPinPolicyViolation,
            WellKnownCtapStatusCodes.IsUnauthorizedPermission,
            WellKnownCtapStatusCodes.IsUvBlocked,
            WellKnownCtapStatusCodes.IsIntegrityFailure,
            WellKnownCtapStatusCodes.IsUvInvalid,
            WellKnownCtapStatusCodes.IsInvalidSubcommand,
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


    /// <summary>Every Is* predicate on <see cref="WellKnownCtapAuthenticatorConfigRequestKeys"/> matches only its own declared value.</summary>
    [TestMethod]
    public void WellKnownCtapAuthenticatorConfigRequestKeysPredicatesMatchOnlyTheirOwnValue()
    {
        int[] values =
        [
            WellKnownCtapAuthenticatorConfigRequestKeys.SubCommand,
            WellKnownCtapAuthenticatorConfigRequestKeys.SubCommandParams,
            WellKnownCtapAuthenticatorConfigRequestKeys.PinUvAuthProtocol,
            WellKnownCtapAuthenticatorConfigRequestKeys.PinUvAuthParam,
        ];

        Func<int, bool>[] predicates =
        [
            WellKnownCtapAuthenticatorConfigRequestKeys.IsSubCommand,
            WellKnownCtapAuthenticatorConfigRequestKeys.IsSubCommandParams,
            WellKnownCtapAuthenticatorConfigRequestKeys.IsPinUvAuthProtocol,
            WellKnownCtapAuthenticatorConfigRequestKeys.IsPinUvAuthParam,
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


    /// <summary>Every Is* predicate on <see cref="WellKnownCtapAuthenticatorConfigSubCommandParamsKeys"/> matches only its own declared value.</summary>
    [TestMethod]
    public void WellKnownCtapAuthenticatorConfigSubCommandParamsKeysPredicatesMatchOnlyTheirOwnValue()
    {
        int[] values =
        [
            WellKnownCtapAuthenticatorConfigSubCommandParamsKeys.NewMinPinLength,
            WellKnownCtapAuthenticatorConfigSubCommandParamsKeys.MinPinLengthRpIds,
            WellKnownCtapAuthenticatorConfigSubCommandParamsKeys.ForceChangePin,
            WellKnownCtapAuthenticatorConfigSubCommandParamsKeys.PinComplexityPolicy,
        ];

        Func<int, bool>[] predicates =
        [
            WellKnownCtapAuthenticatorConfigSubCommandParamsKeys.IsNewMinPinLength,
            WellKnownCtapAuthenticatorConfigSubCommandParamsKeys.IsMinPinLengthRpIds,
            WellKnownCtapAuthenticatorConfigSubCommandParamsKeys.IsForceChangePin,
            WellKnownCtapAuthenticatorConfigSubCommandParamsKeys.IsPinComplexityPolicy,
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


    /// <summary>Every Is* predicate on <see cref="WellKnownCtapAuthenticatorConfigSubCommands"/> matches only its own declared value.</summary>
    [TestMethod]
    public void WellKnownCtapAuthenticatorConfigSubCommandsPredicatesMatchOnlyTheirOwnValue()
    {
        int[] values =
        [
            WellKnownCtapAuthenticatorConfigSubCommands.EnableEnterpriseAttestation,
            WellKnownCtapAuthenticatorConfigSubCommands.ToggleAlwaysUv,
            WellKnownCtapAuthenticatorConfigSubCommands.SetMinPinLength,
            WellKnownCtapAuthenticatorConfigSubCommands.EnableLongTouchForReset,
            WellKnownCtapAuthenticatorConfigSubCommands.VendorPrototype,
        ];

        Func<int, bool>[] predicates =
        [
            WellKnownCtapAuthenticatorConfigSubCommands.IsEnableEnterpriseAttestation,
            WellKnownCtapAuthenticatorConfigSubCommands.IsToggleAlwaysUv,
            WellKnownCtapAuthenticatorConfigSubCommands.IsSetMinPinLength,
            WellKnownCtapAuthenticatorConfigSubCommands.IsEnableLongTouchForReset,
            WellKnownCtapAuthenticatorConfigSubCommands.IsVendorPrototype,
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


    /// <summary>Every Is* predicate on <see cref="WellKnownCtapBioEnrollmentModalities"/> matches only its own declared value.</summary>
    [TestMethod]
    public void WellKnownCtapBioEnrollmentModalitiesPredicatesMatchOnlyTheirOwnValue()
    {
        int[] values =
        [
            WellKnownCtapBioEnrollmentModalities.Fingerprint,
        ];

        Func<int, bool>[] predicates =
        [
            WellKnownCtapBioEnrollmentModalities.IsFingerprint,
        ];

        for(int i = 0; i < values.Length; i++)
        {
            Assert.IsTrue(predicates[i](values[i]), $"Predicate at index {i} must accept its own value.");

            int matchCount = 0;
            for(int j = 0; j < predicates.Length; j++)
            {
                matchCount += predicates[j](values[i]) ? 1 : 0;
            }

            Assert.AreEqual(1, matchCount, "The sole catalog value must match exactly its own predicate.");
        }
    }


    /// <summary>Every Is* predicate on <see cref="WellKnownCtapBioEnrollmentRequestKeys"/> matches only its own declared value.</summary>
    [TestMethod]
    public void WellKnownCtapBioEnrollmentRequestKeysPredicatesMatchOnlyTheirOwnValue()
    {
        int[] values =
        [
            WellKnownCtapBioEnrollmentRequestKeys.Modality,
            WellKnownCtapBioEnrollmentRequestKeys.SubCommand,
            WellKnownCtapBioEnrollmentRequestKeys.SubCommandParams,
            WellKnownCtapBioEnrollmentRequestKeys.PinUvAuthProtocol,
            WellKnownCtapBioEnrollmentRequestKeys.PinUvAuthParam,
            WellKnownCtapBioEnrollmentRequestKeys.GetModality,
        ];

        Func<int, bool>[] predicates =
        [
            WellKnownCtapBioEnrollmentRequestKeys.IsModality,
            WellKnownCtapBioEnrollmentRequestKeys.IsSubCommand,
            WellKnownCtapBioEnrollmentRequestKeys.IsSubCommandParams,
            WellKnownCtapBioEnrollmentRequestKeys.IsPinUvAuthProtocol,
            WellKnownCtapBioEnrollmentRequestKeys.IsPinUvAuthParam,
            WellKnownCtapBioEnrollmentRequestKeys.IsGetModality,
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


    /// <summary>Every Is* predicate on <see cref="WellKnownCtapBioEnrollmentResponseKeys"/> matches only its own declared value.</summary>
    [TestMethod]
    public void WellKnownCtapBioEnrollmentResponseKeysPredicatesMatchOnlyTheirOwnValue()
    {
        int[] values =
        [
            WellKnownCtapBioEnrollmentResponseKeys.Modality,
            WellKnownCtapBioEnrollmentResponseKeys.FingerprintKind,
            WellKnownCtapBioEnrollmentResponseKeys.MaxCaptureSamplesRequiredForEnroll,
            WellKnownCtapBioEnrollmentResponseKeys.TemplateId,
            WellKnownCtapBioEnrollmentResponseKeys.LastEnrollSampleStatus,
            WellKnownCtapBioEnrollmentResponseKeys.RemainingSamples,
            WellKnownCtapBioEnrollmentResponseKeys.TemplateInfos,
            WellKnownCtapBioEnrollmentResponseKeys.MaxTemplateFriendlyName,
        ];

        Func<int, bool>[] predicates =
        [
            WellKnownCtapBioEnrollmentResponseKeys.IsModality,
            WellKnownCtapBioEnrollmentResponseKeys.IsFingerprintKind,
            WellKnownCtapBioEnrollmentResponseKeys.IsMaxCaptureSamplesRequiredForEnroll,
            WellKnownCtapBioEnrollmentResponseKeys.IsTemplateId,
            WellKnownCtapBioEnrollmentResponseKeys.IsLastEnrollSampleStatus,
            WellKnownCtapBioEnrollmentResponseKeys.IsRemainingSamples,
            WellKnownCtapBioEnrollmentResponseKeys.IsTemplateInfos,
            WellKnownCtapBioEnrollmentResponseKeys.IsMaxTemplateFriendlyName,
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


    /// <summary>Every Is* predicate on <see cref="WellKnownCtapBioEnrollmentSubCommandParamsKeys"/> matches only its own declared value.</summary>
    [TestMethod]
    public void WellKnownCtapBioEnrollmentSubCommandParamsKeysPredicatesMatchOnlyTheirOwnValue()
    {
        int[] values =
        [
            WellKnownCtapBioEnrollmentSubCommandParamsKeys.TemplateId,
            WellKnownCtapBioEnrollmentSubCommandParamsKeys.TemplateFriendlyName,
            WellKnownCtapBioEnrollmentSubCommandParamsKeys.TimeoutMilliseconds,
        ];

        Func<int, bool>[] predicates =
        [
            WellKnownCtapBioEnrollmentSubCommandParamsKeys.IsTemplateId,
            WellKnownCtapBioEnrollmentSubCommandParamsKeys.IsTemplateFriendlyName,
            WellKnownCtapBioEnrollmentSubCommandParamsKeys.IsTimeoutMilliseconds,
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


    /// <summary>Every Is* predicate on <see cref="WellKnownCtapBioEnrollmentSubCommands"/> matches only its own declared value.</summary>
    [TestMethod]
    public void WellKnownCtapBioEnrollmentSubCommandsPredicatesMatchOnlyTheirOwnValue()
    {
        int[] values =
        [
            WellKnownCtapBioEnrollmentSubCommands.EnrollBegin,
            WellKnownCtapBioEnrollmentSubCommands.EnrollCaptureNextSample,
            WellKnownCtapBioEnrollmentSubCommands.CancelCurrentEnrollment,
            WellKnownCtapBioEnrollmentSubCommands.EnumerateEnrollments,
            WellKnownCtapBioEnrollmentSubCommands.SetFriendlyName,
            WellKnownCtapBioEnrollmentSubCommands.RemoveEnrollment,
            WellKnownCtapBioEnrollmentSubCommands.GetFingerprintSensorInfo,
        ];

        Func<int, bool>[] predicates =
        [
            WellKnownCtapBioEnrollmentSubCommands.IsEnrollBegin,
            WellKnownCtapBioEnrollmentSubCommands.IsEnrollCaptureNextSample,
            WellKnownCtapBioEnrollmentSubCommands.IsCancelCurrentEnrollment,
            WellKnownCtapBioEnrollmentSubCommands.IsEnumerateEnrollments,
            WellKnownCtapBioEnrollmentSubCommands.IsSetFriendlyName,
            WellKnownCtapBioEnrollmentSubCommands.IsRemoveEnrollment,
            WellKnownCtapBioEnrollmentSubCommands.IsGetFingerprintSensorInfo,
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


    /// <summary>Every Is* predicate on <see cref="WellKnownCtapClientPinRequestKeys"/> matches only its own declared value.</summary>
    [TestMethod]
    public void WellKnownCtapClientPinRequestKeysPredicatesMatchOnlyTheirOwnValue()
    {
        int[] values =
        [
            WellKnownCtapClientPinRequestKeys.PinUvAuthProtocol,
            WellKnownCtapClientPinRequestKeys.SubCommand,
            WellKnownCtapClientPinRequestKeys.KeyAgreement,
            WellKnownCtapClientPinRequestKeys.PinUvAuthParam,
            WellKnownCtapClientPinRequestKeys.NewPinEnc,
            WellKnownCtapClientPinRequestKeys.PinHashEnc,
            WellKnownCtapClientPinRequestKeys.Permissions,
            WellKnownCtapClientPinRequestKeys.RpId,
        ];

        Func<int, bool>[] predicates =
        [
            WellKnownCtapClientPinRequestKeys.IsPinUvAuthProtocol,
            WellKnownCtapClientPinRequestKeys.IsSubCommand,
            WellKnownCtapClientPinRequestKeys.IsKeyAgreement,
            WellKnownCtapClientPinRequestKeys.IsPinUvAuthParam,
            WellKnownCtapClientPinRequestKeys.IsNewPinEnc,
            WellKnownCtapClientPinRequestKeys.IsPinHashEnc,
            WellKnownCtapClientPinRequestKeys.IsPermissions,
            WellKnownCtapClientPinRequestKeys.IsRpId,
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


    /// <summary>Every Is* predicate on <see cref="WellKnownCtapClientPinResponseKeys"/> matches only its own declared value.</summary>
    [TestMethod]
    public void WellKnownCtapClientPinResponseKeysPredicatesMatchOnlyTheirOwnValue()
    {
        int[] values =
        [
            WellKnownCtapClientPinResponseKeys.KeyAgreement,
            WellKnownCtapClientPinResponseKeys.PinUvAuthToken,
            WellKnownCtapClientPinResponseKeys.PinRetries,
            WellKnownCtapClientPinResponseKeys.PowerCycleState,
            WellKnownCtapClientPinResponseKeys.UvRetries,
        ];

        Func<int, bool>[] predicates =
        [
            WellKnownCtapClientPinResponseKeys.IsKeyAgreement,
            WellKnownCtapClientPinResponseKeys.IsPinUvAuthToken,
            WellKnownCtapClientPinResponseKeys.IsPinRetries,
            WellKnownCtapClientPinResponseKeys.IsPowerCycleState,
            WellKnownCtapClientPinResponseKeys.IsUvRetries,
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


    /// <summary>Every Is* predicate on <see cref="WellKnownCtapClientPinSubCommands"/> matches only its own declared value.</summary>
    [TestMethod]
    public void WellKnownCtapClientPinSubCommandsPredicatesMatchOnlyTheirOwnValue()
    {
        int[] values =
        [
            WellKnownCtapClientPinSubCommands.GetPinRetries,
            WellKnownCtapClientPinSubCommands.GetKeyAgreement,
            WellKnownCtapClientPinSubCommands.SetPin,
            WellKnownCtapClientPinSubCommands.ChangePin,
            WellKnownCtapClientPinSubCommands.GetPinToken,
            WellKnownCtapClientPinSubCommands.GetPinUvAuthTokenUsingUvWithPermissions,
            WellKnownCtapClientPinSubCommands.GetUvRetries,
            WellKnownCtapClientPinSubCommands.GetPinUvAuthTokenUsingPinWithPermissions,
        ];

        Func<int, bool>[] predicates =
        [
            WellKnownCtapClientPinSubCommands.IsGetPinRetries,
            WellKnownCtapClientPinSubCommands.IsGetKeyAgreement,
            WellKnownCtapClientPinSubCommands.IsSetPin,
            WellKnownCtapClientPinSubCommands.IsChangePin,
            WellKnownCtapClientPinSubCommands.IsGetPinToken,
            WellKnownCtapClientPinSubCommands.IsGetPinUvAuthTokenUsingUvWithPermissions,
            WellKnownCtapClientPinSubCommands.IsGetUvRetries,
            WellKnownCtapClientPinSubCommands.IsGetPinUvAuthTokenUsingPinWithPermissions,
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


    /// <summary>Every Is* predicate on <see cref="WellKnownCtapCredentialManagementRequestKeys"/> matches only its own declared value.</summary>
    [TestMethod]
    public void WellKnownCtapCredentialManagementRequestKeysPredicatesMatchOnlyTheirOwnValue()
    {
        int[] values =
        [
            WellKnownCtapCredentialManagementRequestKeys.SubCommand,
            WellKnownCtapCredentialManagementRequestKeys.SubCommandParams,
            WellKnownCtapCredentialManagementRequestKeys.PinUvAuthProtocol,
            WellKnownCtapCredentialManagementRequestKeys.PinUvAuthParam,
        ];

        Func<int, bool>[] predicates =
        [
            WellKnownCtapCredentialManagementRequestKeys.IsSubCommand,
            WellKnownCtapCredentialManagementRequestKeys.IsSubCommandParams,
            WellKnownCtapCredentialManagementRequestKeys.IsPinUvAuthProtocol,
            WellKnownCtapCredentialManagementRequestKeys.IsPinUvAuthParam,
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


    /// <summary>Every Is* predicate on <see cref="WellKnownCtapCredentialManagementResponseKeys"/> matches only its own declared value.</summary>
    [TestMethod]
    public void WellKnownCtapCredentialManagementResponseKeysPredicatesMatchOnlyTheirOwnValue()
    {
        int[] values =
        [
            WellKnownCtapCredentialManagementResponseKeys.ExistingResidentCredentialsCount,
            WellKnownCtapCredentialManagementResponseKeys.MaxPossibleRemainingResidentCredentialsCount,
            WellKnownCtapCredentialManagementResponseKeys.Rp,
            WellKnownCtapCredentialManagementResponseKeys.RpIdHash,
            WellKnownCtapCredentialManagementResponseKeys.TotalRps,
            WellKnownCtapCredentialManagementResponseKeys.User,
            WellKnownCtapCredentialManagementResponseKeys.CredentialId,
            WellKnownCtapCredentialManagementResponseKeys.PublicKey,
            WellKnownCtapCredentialManagementResponseKeys.TotalCredentials,
            WellKnownCtapCredentialManagementResponseKeys.CredProtect,
            WellKnownCtapCredentialManagementResponseKeys.LargeBlobKey,
            WellKnownCtapCredentialManagementResponseKeys.ThirdPartyPayment,
        ];

        Func<int, bool>[] predicates =
        [
            WellKnownCtapCredentialManagementResponseKeys.IsExistingResidentCredentialsCount,
            WellKnownCtapCredentialManagementResponseKeys.IsMaxPossibleRemainingResidentCredentialsCount,
            WellKnownCtapCredentialManagementResponseKeys.IsRp,
            WellKnownCtapCredentialManagementResponseKeys.IsRpIdHash,
            WellKnownCtapCredentialManagementResponseKeys.IsTotalRps,
            WellKnownCtapCredentialManagementResponseKeys.IsUser,
            WellKnownCtapCredentialManagementResponseKeys.IsCredentialId,
            WellKnownCtapCredentialManagementResponseKeys.IsPublicKey,
            WellKnownCtapCredentialManagementResponseKeys.IsTotalCredentials,
            WellKnownCtapCredentialManagementResponseKeys.IsCredProtect,
            WellKnownCtapCredentialManagementResponseKeys.IsLargeBlobKey,
            WellKnownCtapCredentialManagementResponseKeys.IsThirdPartyPayment,
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


    /// <summary>Every Is* predicate on <see cref="WellKnownCtapCredentialManagementSubCommandParamsKeys"/> matches only its own declared value.</summary>
    [TestMethod]
    public void WellKnownCtapCredentialManagementSubCommandParamsKeysPredicatesMatchOnlyTheirOwnValue()
    {
        int[] values =
        [
            WellKnownCtapCredentialManagementSubCommandParamsKeys.RpIdHash,
            WellKnownCtapCredentialManagementSubCommandParamsKeys.CredentialId,
            WellKnownCtapCredentialManagementSubCommandParamsKeys.User,
        ];

        Func<int, bool>[] predicates =
        [
            WellKnownCtapCredentialManagementSubCommandParamsKeys.IsRpIdHash,
            WellKnownCtapCredentialManagementSubCommandParamsKeys.IsCredentialId,
            WellKnownCtapCredentialManagementSubCommandParamsKeys.IsUser,
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


    /// <summary>Every Is* predicate on <see cref="WellKnownCtapCredentialManagementSubCommands"/> matches only its own declared value.</summary>
    [TestMethod]
    public void WellKnownCtapCredentialManagementSubCommandsPredicatesMatchOnlyTheirOwnValue()
    {
        int[] values =
        [
            WellKnownCtapCredentialManagementSubCommands.GetCredsMetadata,
            WellKnownCtapCredentialManagementSubCommands.EnumerateRpsBegin,
            WellKnownCtapCredentialManagementSubCommands.EnumerateRpsGetNextRp,
            WellKnownCtapCredentialManagementSubCommands.EnumerateCredentialsBegin,
            WellKnownCtapCredentialManagementSubCommands.EnumerateCredentialsGetNextCredential,
            WellKnownCtapCredentialManagementSubCommands.DeleteCredential,
            WellKnownCtapCredentialManagementSubCommands.UpdateUserInformation,
        ];

        Func<int, bool>[] predicates =
        [
            WellKnownCtapCredentialManagementSubCommands.IsGetCredsMetadata,
            WellKnownCtapCredentialManagementSubCommands.IsEnumerateRpsBegin,
            WellKnownCtapCredentialManagementSubCommands.IsEnumerateRpsGetNextRp,
            WellKnownCtapCredentialManagementSubCommands.IsEnumerateCredentialsBegin,
            WellKnownCtapCredentialManagementSubCommands.IsEnumerateCredentialsGetNextCredential,
            WellKnownCtapCredentialManagementSubCommands.IsDeleteCredential,
            WellKnownCtapCredentialManagementSubCommands.IsUpdateUserInformation,
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


    /// <summary>Every Is* predicate on <see cref="WellKnownCtapFingerprintKinds"/> matches only its own declared value.</summary>
    [TestMethod]
    public void WellKnownCtapFingerprintKindsPredicatesMatchOnlyTheirOwnValue()
    {
        int[] values =
        [
            WellKnownCtapFingerprintKinds.Touch,
            WellKnownCtapFingerprintKinds.Swipe,
        ];

        Func<int, bool>[] predicates =
        [
            WellKnownCtapFingerprintKinds.IsTouch,
            WellKnownCtapFingerprintKinds.IsSwipe,
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


    /// <summary>Every Is* predicate on <see cref="WellKnownCtapGetAssertionRequestKeys"/> matches only its own declared value.</summary>
    [TestMethod]
    public void WellKnownCtapGetAssertionRequestKeysPredicatesMatchOnlyTheirOwnValue()
    {
        int[] values =
        [
            WellKnownCtapGetAssertionRequestKeys.RpId,
            WellKnownCtapGetAssertionRequestKeys.ClientDataHash,
            WellKnownCtapGetAssertionRequestKeys.AllowList,
            WellKnownCtapGetAssertionRequestKeys.Extensions,
            WellKnownCtapGetAssertionRequestKeys.Options,
            WellKnownCtapGetAssertionRequestKeys.PinUvAuthParam,
            WellKnownCtapGetAssertionRequestKeys.PinUvAuthProtocol,
        ];

        Func<int, bool>[] predicates =
        [
            WellKnownCtapGetAssertionRequestKeys.IsRpId,
            WellKnownCtapGetAssertionRequestKeys.IsClientDataHash,
            WellKnownCtapGetAssertionRequestKeys.IsAllowList,
            WellKnownCtapGetAssertionRequestKeys.IsExtensions,
            WellKnownCtapGetAssertionRequestKeys.IsOptions,
            WellKnownCtapGetAssertionRequestKeys.IsPinUvAuthParam,
            WellKnownCtapGetAssertionRequestKeys.IsPinUvAuthProtocol,
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


    /// <summary>Every Is* predicate on <see cref="WellKnownCtapGetAssertionResponseKeys"/> matches only its own declared value.</summary>
    [TestMethod]
    public void WellKnownCtapGetAssertionResponseKeysPredicatesMatchOnlyTheirOwnValue()
    {
        int[] values =
        [
            WellKnownCtapGetAssertionResponseKeys.Credential,
            WellKnownCtapGetAssertionResponseKeys.AuthData,
            WellKnownCtapGetAssertionResponseKeys.Signature,
            WellKnownCtapGetAssertionResponseKeys.User,
            WellKnownCtapGetAssertionResponseKeys.NumberOfCredentials,
            WellKnownCtapGetAssertionResponseKeys.UserSelected,
            WellKnownCtapGetAssertionResponseKeys.LargeBlobKey,
            WellKnownCtapGetAssertionResponseKeys.UnsignedExtensionOutputs,
        ];

        Func<int, bool>[] predicates =
        [
            WellKnownCtapGetAssertionResponseKeys.IsCredential,
            WellKnownCtapGetAssertionResponseKeys.IsAuthData,
            WellKnownCtapGetAssertionResponseKeys.IsSignature,
            WellKnownCtapGetAssertionResponseKeys.IsUser,
            WellKnownCtapGetAssertionResponseKeys.IsNumberOfCredentials,
            WellKnownCtapGetAssertionResponseKeys.IsUserSelected,
            WellKnownCtapGetAssertionResponseKeys.IsLargeBlobKey,
            WellKnownCtapGetAssertionResponseKeys.IsUnsignedExtensionOutputs,
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


    /// <summary>Every Is* predicate on <see cref="WellKnownCtapGetInfoMemberKeys"/> matches only its own declared value.</summary>
    [TestMethod]
    public void WellKnownCtapGetInfoMemberKeysPredicatesMatchOnlyTheirOwnValue()
    {
        int[] values =
        [
            WellKnownCtapGetInfoMemberKeys.Versions,
            WellKnownCtapGetInfoMemberKeys.Extensions,
            WellKnownCtapGetInfoMemberKeys.Aaguid,
            WellKnownCtapGetInfoMemberKeys.Options,
            WellKnownCtapGetInfoMemberKeys.PinUvAuthProtocols,
            WellKnownCtapGetInfoMemberKeys.MaxSerializedLargeBlobArray,
            WellKnownCtapGetInfoMemberKeys.ForcePinChange,
            WellKnownCtapGetInfoMemberKeys.MinPinLength,
            WellKnownCtapGetInfoMemberKeys.MaxRpIdsForSetMinPinLength,
            WellKnownCtapGetInfoMemberKeys.PreferredPlatformUvAttempts,
            WellKnownCtapGetInfoMemberKeys.UvModality,
            WellKnownCtapGetInfoMemberKeys.RemainingDiscoverableCredentials,
            WellKnownCtapGetInfoMemberKeys.AuthenticatorConfigCommands,
        ];

        Func<int, bool>[] predicates =
        [
            WellKnownCtapGetInfoMemberKeys.IsVersions,
            WellKnownCtapGetInfoMemberKeys.IsExtensions,
            WellKnownCtapGetInfoMemberKeys.IsAaguid,
            WellKnownCtapGetInfoMemberKeys.IsOptions,
            WellKnownCtapGetInfoMemberKeys.IsPinUvAuthProtocols,
            WellKnownCtapGetInfoMemberKeys.IsMaxSerializedLargeBlobArray,
            WellKnownCtapGetInfoMemberKeys.IsForcePinChange,
            WellKnownCtapGetInfoMemberKeys.IsMinPinLength,
            WellKnownCtapGetInfoMemberKeys.IsMaxRpIdsForSetMinPinLength,
            WellKnownCtapGetInfoMemberKeys.IsPreferredPlatformUvAttempts,
            WellKnownCtapGetInfoMemberKeys.IsUvModality,
            WellKnownCtapGetInfoMemberKeys.IsRemainingDiscoverableCredentials,
            WellKnownCtapGetInfoMemberKeys.IsAuthenticatorConfigCommands,
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


    /// <summary>Every Is* predicate on <see cref="WellKnownCtapHmacSecretExtensionKeys"/> matches only its own declared value.</summary>
    [TestMethod]
    public void WellKnownCtapHmacSecretExtensionKeysPredicatesMatchOnlyTheirOwnValue()
    {
        int[] values =
        [
            WellKnownCtapHmacSecretExtensionKeys.KeyAgreement,
            WellKnownCtapHmacSecretExtensionKeys.SaltEnc,
            WellKnownCtapHmacSecretExtensionKeys.SaltAuth,
            WellKnownCtapHmacSecretExtensionKeys.PinUvAuthProtocol,
        ];

        Func<int, bool>[] predicates =
        [
            WellKnownCtapHmacSecretExtensionKeys.IsKeyAgreement,
            WellKnownCtapHmacSecretExtensionKeys.IsSaltEnc,
            WellKnownCtapHmacSecretExtensionKeys.IsSaltAuth,
            WellKnownCtapHmacSecretExtensionKeys.IsPinUvAuthProtocol,
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


    /// <summary>Every Is* predicate on <see cref="WellKnownCtapLargeBlobsRequestKeys"/> matches only its own declared value.</summary>
    [TestMethod]
    public void WellKnownCtapLargeBlobsRequestKeysPredicatesMatchOnlyTheirOwnValue()
    {
        int[] values =
        [
            WellKnownCtapLargeBlobsRequestKeys.Get,
            WellKnownCtapLargeBlobsRequestKeys.Set,
            WellKnownCtapLargeBlobsRequestKeys.Offset,
            WellKnownCtapLargeBlobsRequestKeys.Length,
            WellKnownCtapLargeBlobsRequestKeys.PinUvAuthParam,
            WellKnownCtapLargeBlobsRequestKeys.PinUvAuthProtocol,
        ];

        Func<int, bool>[] predicates =
        [
            WellKnownCtapLargeBlobsRequestKeys.IsGet,
            WellKnownCtapLargeBlobsRequestKeys.IsSet,
            WellKnownCtapLargeBlobsRequestKeys.IsOffset,
            WellKnownCtapLargeBlobsRequestKeys.IsLength,
            WellKnownCtapLargeBlobsRequestKeys.IsPinUvAuthParam,
            WellKnownCtapLargeBlobsRequestKeys.IsPinUvAuthProtocol,
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


    /// <summary>Every Is* predicate on <see cref="WellKnownCtapLargeBlobsResponseKeys"/> matches only its own declared value.</summary>
    [TestMethod]
    public void WellKnownCtapLargeBlobsResponseKeysPredicatesMatchOnlyTheirOwnValue()
    {
        int[] values =
        [
            WellKnownCtapLargeBlobsResponseKeys.Config,
        ];

        Func<int, bool>[] predicates =
        [
            WellKnownCtapLargeBlobsResponseKeys.IsConfig,
        ];

        for(int i = 0; i < values.Length; i++)
        {
            Assert.IsTrue(predicates[i](values[i]), $"Predicate at index {i} must accept its own value.");

            int matchCount = 0;
            for(int j = 0; j < predicates.Length; j++)
            {
                matchCount += predicates[j](values[i]) ? 1 : 0;
            }

            Assert.AreEqual(1, matchCount, "The sole catalog value must match exactly its own predicate.");
        }
    }


    /// <summary>Every Is* predicate on <see cref="WellKnownCtapLastEnrollSampleStatuses"/> matches only its own declared value.</summary>
    [TestMethod]
    public void WellKnownCtapLastEnrollSampleStatusesPredicatesMatchOnlyTheirOwnValue()
    {
        int[] values =
        [
            WellKnownCtapLastEnrollSampleStatuses.Good,
            WellKnownCtapLastEnrollSampleStatuses.TooHigh,
            WellKnownCtapLastEnrollSampleStatuses.TooLow,
            WellKnownCtapLastEnrollSampleStatuses.TooLeft,
            WellKnownCtapLastEnrollSampleStatuses.TooRight,
            WellKnownCtapLastEnrollSampleStatuses.TooFast,
            WellKnownCtapLastEnrollSampleStatuses.TooSlow,
            WellKnownCtapLastEnrollSampleStatuses.PoorQuality,
            WellKnownCtapLastEnrollSampleStatuses.TooSkewed,
            WellKnownCtapLastEnrollSampleStatuses.TooShort,
            WellKnownCtapLastEnrollSampleStatuses.MergeFailure,
            WellKnownCtapLastEnrollSampleStatuses.Exists,
            WellKnownCtapLastEnrollSampleStatuses.NoUserActivity,
            WellKnownCtapLastEnrollSampleStatuses.NoUserPresenceTransition,
        ];

        Func<int, bool>[] predicates =
        [
            WellKnownCtapLastEnrollSampleStatuses.IsGood,
            WellKnownCtapLastEnrollSampleStatuses.IsTooHigh,
            WellKnownCtapLastEnrollSampleStatuses.IsTooLow,
            WellKnownCtapLastEnrollSampleStatuses.IsTooLeft,
            WellKnownCtapLastEnrollSampleStatuses.IsTooRight,
            WellKnownCtapLastEnrollSampleStatuses.IsTooFast,
            WellKnownCtapLastEnrollSampleStatuses.IsTooSlow,
            WellKnownCtapLastEnrollSampleStatuses.IsPoorQuality,
            WellKnownCtapLastEnrollSampleStatuses.IsTooSkewed,
            WellKnownCtapLastEnrollSampleStatuses.IsTooShort,
            WellKnownCtapLastEnrollSampleStatuses.IsMergeFailure,
            WellKnownCtapLastEnrollSampleStatuses.IsExists,
            WellKnownCtapLastEnrollSampleStatuses.IsNoUserActivity,
            WellKnownCtapLastEnrollSampleStatuses.IsNoUserPresenceTransition,
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


    /// <summary>Every Is* predicate on <see cref="WellKnownCtapMakeCredentialRequestKeys"/> matches only its own declared value.</summary>
    [TestMethod]
    public void WellKnownCtapMakeCredentialRequestKeysPredicatesMatchOnlyTheirOwnValue()
    {
        int[] values =
        [
            WellKnownCtapMakeCredentialRequestKeys.ClientDataHash,
            WellKnownCtapMakeCredentialRequestKeys.Rp,
            WellKnownCtapMakeCredentialRequestKeys.User,
            WellKnownCtapMakeCredentialRequestKeys.PubKeyCredParams,
            WellKnownCtapMakeCredentialRequestKeys.ExcludeList,
            WellKnownCtapMakeCredentialRequestKeys.Extensions,
            WellKnownCtapMakeCredentialRequestKeys.Options,
            WellKnownCtapMakeCredentialRequestKeys.PinUvAuthParam,
            WellKnownCtapMakeCredentialRequestKeys.PinUvAuthProtocol,
            WellKnownCtapMakeCredentialRequestKeys.EnterpriseAttestation,
            WellKnownCtapMakeCredentialRequestKeys.AttestationFormatsPreference,
        ];

        Func<int, bool>[] predicates =
        [
            WellKnownCtapMakeCredentialRequestKeys.IsClientDataHash,
            WellKnownCtapMakeCredentialRequestKeys.IsRp,
            WellKnownCtapMakeCredentialRequestKeys.IsUser,
            WellKnownCtapMakeCredentialRequestKeys.IsPubKeyCredParams,
            WellKnownCtapMakeCredentialRequestKeys.IsExcludeList,
            WellKnownCtapMakeCredentialRequestKeys.IsExtensions,
            WellKnownCtapMakeCredentialRequestKeys.IsOptions,
            WellKnownCtapMakeCredentialRequestKeys.IsPinUvAuthParam,
            WellKnownCtapMakeCredentialRequestKeys.IsPinUvAuthProtocol,
            WellKnownCtapMakeCredentialRequestKeys.IsEnterpriseAttestation,
            WellKnownCtapMakeCredentialRequestKeys.IsAttestationFormatsPreference,
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


    /// <summary>Every Is* predicate on <see cref="WellKnownCtapMakeCredentialResponseKeys"/> matches only its own declared value.</summary>
    [TestMethod]
    public void WellKnownCtapMakeCredentialResponseKeysPredicatesMatchOnlyTheirOwnValue()
    {
        int[] values =
        [
            WellKnownCtapMakeCredentialResponseKeys.Fmt,
            WellKnownCtapMakeCredentialResponseKeys.AuthData,
            WellKnownCtapMakeCredentialResponseKeys.AttStmt,
            WellKnownCtapMakeCredentialResponseKeys.EpAtt,
            WellKnownCtapMakeCredentialResponseKeys.LargeBlobKey,
            WellKnownCtapMakeCredentialResponseKeys.UnsignedExtensionOutputs,
        ];

        Func<int, bool>[] predicates =
        [
            WellKnownCtapMakeCredentialResponseKeys.IsFmt,
            WellKnownCtapMakeCredentialResponseKeys.IsAuthData,
            WellKnownCtapMakeCredentialResponseKeys.IsAttStmt,
            WellKnownCtapMakeCredentialResponseKeys.IsEpAtt,
            WellKnownCtapMakeCredentialResponseKeys.IsLargeBlobKey,
            WellKnownCtapMakeCredentialResponseKeys.IsUnsignedExtensionOutputs,
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


    /// <summary>Every Is* predicate on <see cref="WellKnownCtapPinUvAuthTokenPermissions"/> matches only its own declared value.</summary>
    [TestMethod]
    public void WellKnownCtapPinUvAuthTokenPermissionsPredicatesMatchOnlyTheirOwnValue()
    {
        int[] values =
        [
            WellKnownCtapPinUvAuthTokenPermissions.Mc,
            WellKnownCtapPinUvAuthTokenPermissions.Ga,
            WellKnownCtapPinUvAuthTokenPermissions.Cm,
            WellKnownCtapPinUvAuthTokenPermissions.Be,
            WellKnownCtapPinUvAuthTokenPermissions.Lbw,
            WellKnownCtapPinUvAuthTokenPermissions.Acfg,
            WellKnownCtapPinUvAuthTokenPermissions.Pcmr,
        ];

        Func<int, bool>[] predicates =
        [
            WellKnownCtapPinUvAuthTokenPermissions.IsMc,
            WellKnownCtapPinUvAuthTokenPermissions.IsGa,
            WellKnownCtapPinUvAuthTokenPermissions.IsCm,
            WellKnownCtapPinUvAuthTokenPermissions.IsBe,
            WellKnownCtapPinUvAuthTokenPermissions.IsLbw,
            WellKnownCtapPinUvAuthTokenPermissions.IsAcfg,
            WellKnownCtapPinUvAuthTokenPermissions.IsPcmr,
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
}
