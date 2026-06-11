using Verifiable.OAuth;
using Verifiable.OAuth.Oid4Vci;
using Verifiable.OAuth.Server;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// The generic RFC 9396 <c>type</c> → handler registry
/// (<see cref="AuthorizationDetailTypeRegistry"/>): the multi-type dispatch (§5/§7) the AS uses
/// in place of a hardcoded single-type check. The built-in <c>openid_credential</c> handler
/// reproduces the OID4VCI 1.0 §5.1.1 shape, an additional handler can be registered for a second
/// type, and an object whose <c>type</c> has no registered handler is the §5 unknown type.
/// </summary>
[TestClass]
internal sealed class AuthorizationDetailTypeRegistryTests
{
    /// <summary>A second authorization details type used to prove multi-type dispatch.</summary>
    private const string PaymentInitiationType = "payment_initiation";


    /// <summary>
    /// A fresh integration starts with exactly the built-in <c>openid_credential</c> handler
    /// registered — the type the AS metadata then advertises.
    /// </summary>
    [TestMethod]
    public void DefaultRegistryCarriesOnlyOpenIdCredential()
    {
        AuthorizationServerIntegration integration = new();

        Assert.IsTrue(integration.AuthorizationDetailTypes.IsRegistered(
            AuthorizationDetailsTypeValues.OpenIdCredential));
        Assert.HasCount(1, integration.AuthorizationDetailTypes.RegisteredTypes);
        Assert.AreEqual(
            AuthorizationDetailsTypeValues.OpenIdCredential,
            integration.AuthorizationDetailTypes.RegisteredTypes[0]);
    }


    /// <summary>
    /// RFC 9396 §5: an object whose <c>type</c> has no registered handler is refused as an
    /// unknown type, before any per-type shape check runs.
    /// </summary>
    [TestMethod]
    public void UnknownTypeIsRefused()
    {
        AuthorizationDetailTypeRegistry registry = new();
        registry.Register(OpenIdCredentialAuthorizationDetailHandler.Handler);

        AuthorizationDetail detail = new() { Type = PaymentInitiationType };

        string? error = registry.ValidateShape(detail, default);

        Assert.IsNotNull(error);
        Assert.Contains(PaymentInitiationType, error!);
    }


    /// <summary>
    /// The built-in <c>openid_credential</c> handler reproduces the §5.1.1 shape: a missing
    /// <c>credential_configuration_id</c> is refused, a present one is accepted.
    /// </summary>
    [TestMethod]
    public void OpenIdCredentialHandlerEnforcesConfigurationId()
    {
        AuthorizationDetailTypeRegistry registry = new();
        registry.Register(OpenIdCredentialAuthorizationDetailHandler.Handler);

        AuthorizationDetail missing = new()
        {
            Type = AuthorizationDetailsTypeValues.OpenIdCredential
        };
        Assert.IsNotNull(registry.ValidateShape(missing, default));

        AuthorizationDetail present = new()
        {
            Type = AuthorizationDetailsTypeValues.OpenIdCredential,
            ExtensionData = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["credential_configuration_id"] = "\"UniversityDegreeCredential\""
            }
        };
        Assert.IsNull(registry.ValidateShape(present, default));
    }


    /// <summary>
    /// §5.1.1 locations rule: when the validation context requires a location, an
    /// <c>openid_credential</c> object whose <c>locations</c> omits it is refused; one that
    /// carries it is accepted.
    /// </summary>
    [TestMethod]
    public void OpenIdCredentialHandlerEnforcesRequiredLocation()
    {
        AuthorizationDetailTypeRegistry registry = new();
        registry.Register(OpenIdCredentialAuthorizationDetailHandler.Handler);

        const string issuer = "https://credential-issuer.example.com";
        AuthorizationDetailValidationContext validation = new() { RequiredLocation = issuer };

        AuthorizationDetail withoutLocation = new()
        {
            Type = AuthorizationDetailsTypeValues.OpenIdCredential,
            ExtensionData = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["credential_configuration_id"] = "\"UniversityDegreeCredential\""
            }
        };
        Assert.IsNotNull(registry.ValidateShape(withoutLocation, validation));

        AuthorizationDetail withLocation = withoutLocation with { Locations = [issuer] };
        Assert.IsNull(registry.ValidateShape(withLocation, validation));
    }


    /// <summary>
    /// Multi-type dispatch (§5/§7): a second handler can be registered, after which an object of
    /// the second type is dispatched to it; that handler's own shape verdict governs.
    /// </summary>
    [TestMethod]
    public void SecondRegisteredTypeIsDispatchedToItsHandler()
    {
        AuthorizationDetailTypeRegistry registry = new();
        registry.Register(OpenIdCredentialAuthorizationDetailHandler.Handler);
        registry.Register(new AuthorizationDetailHandler
        {
            Type = PaymentInitiationType,
            ValidateShape = (detail, validation) =>
                detail.Actions is { Count: > 0 }
                    ? null
                    : "payment_initiation requires at least one action."
        });

        Assert.IsTrue(registry.IsRegistered(PaymentInitiationType));
        Assert.HasCount(2, registry.RegisteredTypes);

        AuthorizationDetail withoutActions = new() { Type = PaymentInitiationType };
        Assert.IsNotNull(registry.ValidateShape(withoutActions, default));

        AuthorizationDetail withActions = new()
        {
            Type = PaymentInitiationType,
            Actions = ["initiate"]
        };
        Assert.IsNull(registry.ValidateShape(withActions, default));
    }


    /// <summary>
    /// A duplicate registration for an already-registered <c>type</c> is rejected.
    /// </summary>
    [TestMethod]
    public void DuplicateRegistrationIsRejected()
    {
        AuthorizationDetailTypeRegistry registry = new();
        registry.Register(OpenIdCredentialAuthorizationDetailHandler.Handler);

        Assert.ThrowsExactly<ArgumentException>(() =>
            registry.Register(OpenIdCredentialAuthorizationDetailHandler.Handler));
    }


    /// <summary>
    /// RFC 9396 §5 strict validation, the "missing required fields" and accept cases: a strict
    /// handler built from a declared field set refuses an object lacking a required field, and
    /// accepts a well-formed one.
    /// </summary>
    [TestMethod]
    public void StrictHandlerEnforcesRequiredField()
    {
        AuthorizationDetailHandler strict = StrictPaymentInitiationHandler();

        AuthorizationDetail missing = new() { Type = PaymentInitiationType };
        Assert.IsNotNull(strict.ValidateShape(missing, default));

        AuthorizationDetail present = new()
        {
            Type = PaymentInitiationType,
            ExtensionData = Extension(("instructedAmount", "{\"amount\":\"1.00\"}"))
        };
        Assert.IsNull(strict.ValidateShape(present, default));
    }


    /// <summary>
    /// RFC 9396 §5: "is an object of known type but containing unknown fields." A strict handler
    /// refuses a type-specific member not naming a declared field.
    /// </summary>
    [TestMethod]
    public void StrictHandlerRefusesUnknownField()
    {
        AuthorizationDetailHandler strict = StrictPaymentInitiationHandler();

        AuthorizationDetail detail = new()
        {
            Type = PaymentInitiationType,
            ExtensionData = Extension(
                ("instructedAmount", "{\"amount\":\"1.00\"}"),
                ("unexpected", "\"x\""))
        };

        string? error = strict.ValidateShape(detail, default);

        Assert.IsNotNull(error);
        Assert.Contains("unexpected", error!);
    }


    /// <summary>
    /// RFC 9396 §5: "contains fields of the wrong type for the authorization details type." A
    /// strict handler refuses a declared field whose JSON value has the wrong shape — here a
    /// string where an object is declared.
    /// </summary>
    [TestMethod]
    public void StrictHandlerRefusesWrongFieldType()
    {
        AuthorizationDetailHandler strict = StrictPaymentInitiationHandler();

        AuthorizationDetail detail = new()
        {
            Type = PaymentInitiationType,
            ExtensionData = Extension(("instructedAmount", "\"not-an-object\""))
        };

        string? error = strict.ValidateShape(detail, default);

        Assert.IsNotNull(error);
        Assert.Contains("instructedAmount", error!);
    }


    /// <summary>
    /// RFC 9396 §5: "contains fields of the wrong type for the authorization details type." A
    /// wrong-typed §2.2 common field, recorded by the parser in
    /// <see cref="AuthorizationDetail.MalformedCommonFields"/>, is refused by a strict handler.
    /// </summary>
    [TestMethod]
    public void StrictHandlerRefusesWrongTypedCommonField()
    {
        AuthorizationDetailHandler strict = StrictPaymentInitiationHandler();

        AuthorizationDetail detail = new()
        {
            Type = PaymentInitiationType,
            ExtensionData = Extension(("instructedAmount", "{\"amount\":\"1.00\"}")),
            MalformedCommonFields = ["locations"]
        };

        string? error = strict.ValidateShape(detail, default);

        Assert.IsNotNull(error);
        Assert.Contains("locations", error!);
    }


    /// <summary>
    /// RFC 9396 §5: "contains fields with invalid values for the authorization details type." A
    /// strict handler's per-field value check rejects a well-shaped but invalid value — here a
    /// currency the API does not support.
    /// </summary>
    [TestMethod]
    public void StrictHandlerRefusesInvalidFieldValue()
    {
        AuthorizationDetailHandler strict = StrictPaymentInitiationHandler();

        AuthorizationDetail detail = new()
        {
            Type = PaymentInitiationType,
            ExtensionData = Extension(
                ("instructedAmount", "{\"amount\":\"1.00\"}"),
                ("currency", "\"XYZ\""))
        };

        string? error = strict.ValidateShape(detail, default);

        Assert.IsNotNull(error);
        Assert.Contains("currency", error!);

        AuthorizationDetail valid = new()
        {
            Type = PaymentInitiationType,
            ExtensionData = Extension(
                ("instructedAmount", "{\"amount\":\"1.00\"}"),
                ("currency", "\"EUR\""))
        };
        Assert.IsNull(strict.ValidateShape(valid, default));
    }


    /// <summary>
    /// The lenient <c>openid_credential</c> profile (OID4VCI 1.0 §5.1.1, never invalid due to
    /// unknown fields) keeps accepting an object that carries an unknown member and a wrong-typed
    /// common field — the strictness framework does not change it.
    /// </summary>
    [TestMethod]
    public void OpenIdCredentialStaysLenientForUnknownAndWrongTypedFields()
    {
        AuthorizationDetailTypeRegistry registry = new();
        registry.Register(OpenIdCredentialAuthorizationDetailHandler.Handler);

        AuthorizationDetail detail = new()
        {
            Type = AuthorizationDetailsTypeValues.OpenIdCredential,
            ExtensionData = Extension(
                ("credential_configuration_id", "\"UniversityDegreeCredential\""),
                ("vendor_extension", "{\"anything\":true}")),
            MalformedCommonFields = ["actions"]
        };

        Assert.IsNull(registry.ValidateShape(detail, default));
    }


    /// <summary>
    /// A strict handler built for a second type composes with the registry: an object of that
    /// type is dispatched to the strict validator, and the §5 unknown-field abort governs.
    /// </summary>
    [TestMethod]
    public void StrictHandlerComposesWithRegistryDispatch()
    {
        AuthorizationDetailTypeRegistry registry = new();
        registry.Register(OpenIdCredentialAuthorizationDetailHandler.Handler);
        registry.Register(StrictPaymentInitiationHandler());

        AuthorizationDetail withUnknownField = new()
        {
            Type = PaymentInitiationType,
            ExtensionData = Extension(
                ("instructedAmount", "{\"amount\":\"1.00\"}"),
                ("rogue", "1"))
        };
        Assert.IsNotNull(registry.ValidateShape(withUnknownField, default));

        AuthorizationDetail valid = new()
        {
            Type = PaymentInitiationType,
            ExtensionData = Extension(("instructedAmount", "{\"amount\":\"1.00\"}"))
        };
        Assert.IsNull(registry.ValidateShape(valid, default));
    }


    /// <summary>
    /// A strict <c>payment_initiation</c> handler with a required object field, an optional
    /// string-array field, and an optional string field whose value is checked against a closed
    /// currency set — the fixture exercising every §5 abort category.
    /// </summary>
    private static AuthorizationDetailHandler StrictPaymentInitiationHandler()
    {
        return new AuthorizationDetailHandler
        {
            Type = PaymentInitiationType,
            ValidateShape = AuthorizationDetailStrictFieldValidation.ForFields(
                new AuthorizationDetailFieldRule
                {
                    Name = "instructedAmount",
                    IsRequired = true,
                    Shape = AuthorizationDetailFieldShape.Object
                },
                new AuthorizationDetailFieldRule
                {
                    Name = "creditorAccount",
                    Shape = AuthorizationDetailFieldShape.StringArray
                },
                new AuthorizationDetailFieldRule
                {
                    Name = "currency",
                    Shape = AuthorizationDetailFieldShape.String,
                    ValidateValue = rawValue =>
                        string.Equals(JsonScalarText.AsString(rawValue), "EUR", StringComparison.Ordinal)
                            ? null
                            : "The field 'currency' must be 'EUR'."
                })
        };
    }


    private static Dictionary<string, string> Extension(params (string Key, string RawValue)[] members)
    {
        Dictionary<string, string> extension = new(StringComparer.Ordinal);
        foreach((string key, string rawValue) in members)
        {
            extension[key] = rawValue;
        }

        return extension;
    }
}
