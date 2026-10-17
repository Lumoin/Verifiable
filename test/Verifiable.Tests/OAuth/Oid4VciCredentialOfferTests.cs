using System.Text.Json;
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
    private static Uri Issuer { get; } = new("https://credential-issuer.example.com");
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
        static CredentialOffer Offer(string description) => new()
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
        _ = Assert.ThrowsExactly<ArgumentException>(
            () => CredentialOfferSerializer.ToJson(Offer(overLimit)),
            "§4.1.1: tx_code.description MUST NOT exceed 300 characters.");
    }


    /// <summary>
    /// The length of a <c>tx_code.description</c> is counted in characters, each Unicode scalar value
    /// one: a description of 300 characters outside the Basic Multilingual Plane (600 UTF-16 code
    /// units) composes, and one of 301 such characters is refused with an
    /// <see cref="ArgumentException"/> naming <c>description</c>.
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-4.1.1">OID4VCI 1.0 Section 4.1.1</see>:
    /// "description: OPTIONAL. String containing guidance for the Holder of the Wallet on how to obtain
    /// the Transaction Code ... The length of the string MUST NOT exceed 300 characters."
    /// <see href="https://www.rfc-editor.org/rfc/rfc8259#section-1">RFC 8259 Section 1</see>: "A string
    /// is a sequence of zero or more Unicode characters [UNICODE]."
    /// </summary>
    /// <param name="characterCount">How many U+1F600 characters the description holds.</param>
    /// <param name="isComposed">Whether the offer composes.</param>
    [TestMethod]
    [DataRow(300, true)]
    [DataRow(301, false)]
    public void TxCodeDescriptionIsCountedInCharacters(int characterCount, bool isComposed)
    {
        string description = string.Concat(Enumerable.Repeat(char.ConvertFromUtf32(0x1F600), characterCount));
        CredentialOffer offer = new()
        {
            CredentialIssuer = Issuer,
            CredentialConfigurationIds = [ConfigurationId],
            PreAuthorizedCodeGrant = new PreAuthorizedCodeOfferGrant
            {
                PreAuthorizedCode = PreAuthorizedCode,
                TxCode = new TxCodeRequirement { Description = description }
            }
        };

        if(isComposed)
        {
            using JsonDocument document = JsonDocument.Parse(CredentialOfferSerializer.ToJson(offer));
            string composed = document.RootElement.GetProperty("grants")
                .GetProperty(WellKnownGrantTypes.PreAuthorizedCode)
                .GetProperty("tx_code").GetProperty("description").GetString()!;
            Assert.AreEqual(description, composed, "A description of 300 characters composes as given.");
        }
        else
        {
            ArgumentException error = Assert.ThrowsExactly<ArgumentException>(
                () => CredentialOfferSerializer.ToJson(offer),
                "A description of more than 300 characters is refused.");
            Assert.Contains("description", error.Message, StringComparison.Ordinal);
        }
    }


    /// <summary>
    /// The by-reference deep link is composed only for a <c>credential_offer_uri</c> that is an
    /// absolute URL using the <c>https</c> scheme: an <c>http</c> URL and a relative reference are
    /// refused with an <see cref="ArgumentException"/> naming <c>credential_offer_uri</c>, and an
    /// <c>https</c> URL composes the link carrying it URL-encoded.
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-4.1">OID4VCI 1.0 Section 4.1</see>:
    /// "credential_offer_uri: String that is a URL using the https scheme referencing a resource
    /// containing a JSON object with the Credential Offer parameters." The link is a value the
    /// End-User scans, so no exchange carries it; the composer is where the rule holds.
    /// </summary>
    /// <param name="credentialOfferUri">The <c>credential_offer_uri</c> handed to the composer.</param>
    /// <param name="isComposed">Whether the link composes.</param>
    [TestMethod]
    [DataRow("http://server.example.com/o", false)]
    [DataRow("o/1", false)]
    [DataRow("https://server.example.com/o", true)]
    public void ByReferenceDeepLinkRefusesAUriOtherThanHttps(string credentialOfferUri, bool isComposed)
    {
        Uri offerUri = new(credentialOfferUri, UriKind.RelativeOrAbsolute);

        if(isComposed)
        {
            Assert.AreEqual(
                "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fserver.example.com%2Fo",
                CredentialOfferSerializer.ToByReferenceDeepLink(offerUri));
        }
        else
        {
            ArgumentException error = Assert.ThrowsExactly<ArgumentException>(
                () => CredentialOfferSerializer.ToByReferenceDeepLink(offerUri),
                "A credential_offer_uri that is not an absolute https URL is refused.");
            Assert.Contains("credential_offer_uri", error.Message, StringComparison.Ordinal);
        }
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

        _ = Assert.ThrowsExactly<ArgumentException>(
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

        _ = Assert.ThrowsExactly<ArgumentException>(
            () => CredentialOfferSerializer.ToJson(duplicate),
            "§4.1.1: credential_configuration_ids entries are unique.");
    }


    /// <summary>
    /// §4.1.1 <c>credential_issuer</c> (REQUIRED): "The URL of the Credential Issuer". An offer whose
    /// <c>credential_issuer</c> is no URI reference at all (a scheme with no authority) is rejected
    /// with the parser's own <see cref="ArgumentException"/> naming the member.
    /// </summary>
    [TestMethod]
    public void CredentialIssuerThatIsNotAUrlIsRejected()
    {
        string offerJson =
            "{\"credential_issuer\":\"http://\",\"credential_configuration_ids\":[\"" + ConfigurationId + "\"]}";

        ArgumentException error = Assert.ThrowsExactly<ArgumentException>(
            () => CredentialOfferSerializer.FromJson(offerJson),
            "§4.1.1: credential_issuer is the URL of the Credential Issuer.");

        Assert.Contains("credential_issuer", error.Message, StringComparison.Ordinal);
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
