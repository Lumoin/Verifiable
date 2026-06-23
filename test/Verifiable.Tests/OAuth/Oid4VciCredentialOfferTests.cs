using System.Text.Json;
using Verifiable.OAuth;
using Verifiable.OAuth.Oid4Vci;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// OID4VCI 1.0 §4.1 Credential Offer composition: the neutral <see cref="CredentialOffer"/>
/// model and the <see cref="CredentialOfferSerializer"/> that renders it to the §4.1.1 JSON
/// object and the §4.1.2/§4.1.3 deep links. Pure serialization — no dispatch pipeline; the
/// Issuer composes the offer out-of-band and delivers it by value or by reference.
/// </summary>
[TestClass]
internal sealed class Oid4VciCredentialOfferTests
{
    private static readonly Uri Issuer = new("https://credential-issuer.example.com");
    private const string ConfigurationId = "UniversityDegree_dc_sd_jwt";
    private const string PreAuthorizedCode = "oaKazRN8I0IbtZ0C7JuMn5";


    /// <summary>
    /// A Pre-Authorized Code offer with a fully-specified <c>tx_code</c> serializes to the
    /// §4.1.1 object: the issuer, the configuration ids array, and the grant block carrying the
    /// code and the Transaction Code rendering hints.
    /// </summary>
    [TestMethod]
    public void PreAuthorizedCodeOfferSerializesPerSpec()
    {
        CredentialOffer offer = new()
        {
            CredentialIssuer = Issuer,
            CredentialConfigurationIds = [ConfigurationId],
            PreAuthorizedCodeGrant = new PreAuthorizedCodeOfferGrant
            {
                PreAuthorizedCode = PreAuthorizedCode,
                TxCode = new TxCodeRequirement
                {
                    InputMode = TxCodeInputModes.Numeric,
                    Length = 4,
                    Description = "Please provide the one-time code that was sent via e-mail"
                }
            }
        };

        using JsonDocument doc = JsonDocument.Parse(CredentialOfferSerializer.ToJson(offer));
        JsonElement root = doc.RootElement;

        Assert.AreEqual("https://credential-issuer.example.com", root.GetProperty("credential_issuer").GetString());

        JsonElement ids = root.GetProperty("credential_configuration_ids");
        Assert.AreEqual(JsonValueKind.Array, ids.ValueKind);
        Assert.AreEqual(ConfigurationId, ids[0].GetString());

        JsonElement grant = root.GetProperty("grants")
            .GetProperty(WellKnownGrantTypes.PreAuthorizedCode);
        Assert.AreEqual(PreAuthorizedCode, grant.GetProperty("pre-authorized_code").GetString());

        JsonElement txCode = grant.GetProperty("tx_code");
        Assert.AreEqual("numeric", txCode.GetProperty("input_mode").GetString());
        Assert.AreEqual(4, txCode.GetProperty("length").GetInt32());
        Assert.AreEqual("Please provide the one-time code that was sent via e-mail",
            txCode.GetProperty("description").GetString());
    }


    /// <summary>
    /// §4.1.1: a <c>tx_code</c> object — even empty — signals a required Transaction Code, so an
    /// empty requirement still emits <c>"tx_code":{}</c>.
    /// </summary>
    [TestMethod]
    public void EmptyTxCodeIsEmittedAsAnEmptyObject()
    {
        CredentialOffer offer = new()
        {
            CredentialIssuer = Issuer,
            CredentialConfigurationIds = [ConfigurationId],
            PreAuthorizedCodeGrant = new PreAuthorizedCodeOfferGrant
            {
                PreAuthorizedCode = PreAuthorizedCode,
                TxCode = TxCodeRequirement.Empty
            }
        };

        using JsonDocument doc = JsonDocument.Parse(CredentialOfferSerializer.ToJson(offer));
        JsonElement txCode = doc.RootElement.GetProperty("grants")
            .GetProperty(WellKnownGrantTypes.PreAuthorizedCode)
            .GetProperty("tx_code");

        Assert.AreEqual(JsonValueKind.Object, txCode.ValueKind);
        Assert.IsEmpty(txCode.EnumerateObject(), "An empty tx_code requirement emits an empty object.");
    }


    /// <summary>
    /// When no Transaction Code is expected (<c>TxCode</c> is <see langword="null"/>), the
    /// <c>tx_code</c> member is absent entirely.
    /// </summary>
    [TestMethod]
    public void AbsentTxCodeOmitsTheMember()
    {
        CredentialOffer offer = new()
        {
            CredentialIssuer = Issuer,
            CredentialConfigurationIds = [ConfigurationId],
            PreAuthorizedCodeGrant = new PreAuthorizedCodeOfferGrant { PreAuthorizedCode = PreAuthorizedCode }
        };

        using JsonDocument doc = JsonDocument.Parse(CredentialOfferSerializer.ToJson(offer));
        JsonElement grant = doc.RootElement.GetProperty("grants")
            .GetProperty(WellKnownGrantTypes.PreAuthorizedCode);

        Assert.IsFalse(grant.TryGetProperty("tx_code", out _),
            "tx_code must be absent when no Transaction Code is expected.");
    }


    /// <summary>
    /// An Authorization Code offer serializes the <c>authorization_code</c> grant block with the
    /// opaque <c>issuer_state</c> the Wallet echoes in its Authorization Request.
    /// </summary>
    [TestMethod]
    public void AuthorizationCodeOfferSerializesIssuerState()
    {
        CredentialOffer offer = new()
        {
            CredentialIssuer = Issuer,
            CredentialConfigurationIds = [ConfigurationId],
            AuthorizationCodeGrant = new AuthorizationCodeOfferGrant { IssuerState = "eyJhbGciOiJSU0Et...FYUaBy" }
        };

        using JsonDocument doc = JsonDocument.Parse(CredentialOfferSerializer.ToJson(offer));
        JsonElement grant = doc.RootElement.GetProperty("grants")
            .GetProperty(WellKnownGrantTypes.AuthorizationCode);

        Assert.AreEqual("eyJhbGciOiJSU0Et...FYUaBy", grant.GetProperty("issuer_state").GetString());
    }


    /// <summary>
    /// §4.1.1: <c>grants</c> is OPTIONAL — an offer with no grants omits the member, leaving the
    /// Wallet to determine grant types from the issuer metadata.
    /// </summary>
    [TestMethod]
    public void OfferWithoutGrantsOmitsTheGrantsMember()
    {
        CredentialOffer offer = new()
        {
            CredentialIssuer = Issuer,
            CredentialConfigurationIds = [ConfigurationId]
        };

        using JsonDocument doc = JsonDocument.Parse(CredentialOfferSerializer.ToJson(offer));

        Assert.IsFalse(doc.RootElement.TryGetProperty("grants", out _),
            "grants must be absent when the offer advertises no grant types.");
    }


    /// <summary>
    /// §4.1.1 <c>tx_code.description</c>: "The length of the string MUST NOT exceed 300 characters."
    /// A description of exactly 300 characters is at the boundary and serializes; 301 is rejected.
    /// </summary>
    [TestMethod]
    public void TxCodeDescriptionAtThreeHundredCharactersIsAcceptedAndOverIsRejected()
    {
        CredentialOffer Offer(string description) => new()
        {
            CredentialIssuer = Issuer,
            CredentialConfigurationIds = [ConfigurationId],
            PreAuthorizedCodeGrant = new PreAuthorizedCodeOfferGrant
            {
                PreAuthorizedCode = PreAuthorizedCode,
                TxCode = new TxCodeRequirement { Description = description }
            }
        };

        string atLimit = new('x', 300);
        using JsonDocument doc = JsonDocument.Parse(CredentialOfferSerializer.ToJson(Offer(atLimit)));
        string serialized = doc.RootElement.GetProperty("grants")
            .GetProperty(WellKnownGrantTypes.PreAuthorizedCode)
            .GetProperty("tx_code").GetProperty("description").GetString()!;
        Assert.AreEqual(300, serialized.Length, "A 300-character description is at the limit and is accepted.");

        string overLimit = new('x', 301);
        Assert.ThrowsExactly<ArgumentException>(
            () => CredentialOfferSerializer.ToJson(Offer(overLimit)),
            "§4.1.1: tx_code.description MUST NOT exceed 300 characters.");
    }


    /// <summary>
    /// §4.1.1 <c>credential_configuration_ids</c> (REQUIRED): "a non-empty JSON array, where every
    /// entry is a string." An empty array is rejected; a distinct non-empty array serializes.
    /// </summary>
    [TestMethod]
    public void CredentialConfigurationIdsEmptyIsRejectedAndNonEmptyIsAccepted()
    {
        CredentialOffer empty = new()
        {
            CredentialIssuer = Issuer,
            CredentialConfigurationIds = []
        };

        Assert.ThrowsExactly<ArgumentException>(
            () => CredentialOfferSerializer.ToJson(empty),
            "§4.1.1: credential_configuration_ids is a non-empty array.");

        CredentialOffer distinct = new()
        {
            CredentialIssuer = Issuer,
            CredentialConfigurationIds = [ConfigurationId, "org.iso.18013.5.1.mDL"]
        };

        using JsonDocument doc = JsonDocument.Parse(CredentialOfferSerializer.ToJson(distinct));
        JsonElement ids = doc.RootElement.GetProperty("credential_configuration_ids");
        Assert.AreEqual(2, ids.GetArrayLength(), "Distinct non-empty configuration ids serialize.");
    }


    /// <summary>
    /// §4.1.1 <c>credential_configuration_ids</c>: each entry "uniquely identifies one of the keys
    /// in the credential_configurations_supported", so a list carrying a duplicate is rejected.
    /// </summary>
    [TestMethod]
    public void CredentialConfigurationIdsWithDuplicateEntriesIsRejected()
    {
        CredentialOffer duplicate = new()
        {
            CredentialIssuer = Issuer,
            CredentialConfigurationIds = [ConfigurationId, ConfigurationId]
        };

        Assert.ThrowsExactly<ArgumentException>(
            () => CredentialOfferSerializer.ToJson(duplicate),
            "§4.1.1: credential_configuration_ids entries are unique.");
    }


    /// <summary>
    /// §4.1.2: the by-value deep link carries the URL-encoded offer JSON under
    /// <c>credential_offer</c>, decoding back to exactly <see cref="CredentialOfferSerializer.ToJson"/>.
    /// </summary>
    [TestMethod]
    public void ByValueDeepLinkRoundTripsTheOfferJson()
    {
        CredentialOffer offer = new()
        {
            CredentialIssuer = Issuer,
            CredentialConfigurationIds = [ConfigurationId],
            PreAuthorizedCodeGrant = new PreAuthorizedCodeOfferGrant
            {
                PreAuthorizedCode = PreAuthorizedCode,
                TxCode = TxCodeRequirement.Empty
            }
        };

        string deepLink = CredentialOfferSerializer.ToByValueDeepLink(offer);

        string prefix = CredentialOfferSerializer.DefaultScheme
            + "?" + CredentialOfferParameterNames.CredentialOffer + "=";
        Assert.StartsWith(prefix, deepLink);

        string decoded = Uri.UnescapeDataString(deepLink[prefix.Length..]);
        Assert.AreEqual(CredentialOfferSerializer.ToJson(offer), decoded);
    }


    /// <summary>
    /// §4.1.3: the by-reference deep link carries the URL-encoded <c>https</c> offer URL under
    /// <c>credential_offer_uri</c>.
    /// </summary>
    [TestMethod]
    public void ByReferenceDeepLinkCarriesTheEncodedUri()
    {
        Uri offerUri = new("https://server.example.com/credential-offer/GkurKxf5T0Y-mnPFCHqWOMiZi4VS138cQO_V7PZHAdM");

        string deepLink = CredentialOfferSerializer.ToByReferenceDeepLink(offerUri);

        string prefix = CredentialOfferSerializer.DefaultScheme
            + "?" + CredentialOfferParameterNames.CredentialOfferUri + "=";
        Assert.StartsWith(prefix, deepLink);

        string decoded = Uri.UnescapeDataString(deepLink[prefix.Length..]);
        Assert.AreEqual(offerUri.OriginalString, decoded);
    }
}
