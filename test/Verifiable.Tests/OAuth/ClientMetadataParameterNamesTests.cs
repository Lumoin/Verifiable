using System.Buffers;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Cryptography;
using Verifiable.OAuth;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Introspection;
using Verifiable.OAuth.Jarm;
using Verifiable.OAuth.Oid4Vp;
using Verifiable.OAuth.Server.Pipeline;
using Verifiable.OAuth.Siop;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Pins <see cref="ClientMetadataParameterNames"/> — the one home for the RFC 7591 client
/// metadata member names — to the specification's wire spellings and proves the readers and
/// writers that spell a member do so through this table. The member list is defined across
/// <see href="https://www.rfc-editor.org/rfc/rfc7591#section-2">RFC 7591, Section 2</see>
/// ("The following client metadata fields are defined by this specification."),
/// <see href="https://www.rfc-editor.org/rfc/rfc7591#section-2.3">RFC 7591, Section 2.3</see>
/// (the <c>software_statement</c>) and
/// <see href="https://www.rfc-editor.org/rfc/rfc7591#section-3.2.1">RFC 7591, Section 3.2.1</see>
/// (the server-issued <c>client_id</c>, <c>client_secret</c>, <c>client_id_issued_at</c> and
/// <c>client_secret_expires_at</c> fields). Every expected spelling is typed from the RFC text,
/// never read off the table it verifies.
/// </summary>
[TestClass]
internal sealed class ClientMetadataParameterNamesTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider(TestClock.CanonicalEpoch);

    /// <summary>
    /// Each RFC 7591 member's interned string and its UTF-8 source span both equal the wire
    /// name the specification defines: <see href="https://www.rfc-editor.org/rfc/rfc7591#section-2">
    /// RFC 7591, Section 2</see> — "The following client metadata fields are defined by this
    /// specification." — with the identity fields from
    /// <see href="https://www.rfc-editor.org/rfc/rfc7591#section-3.2.1">RFC 7591, Section 3.2.1</see>
    /// and the software statement from
    /// <see href="https://www.rfc-editor.org/rfc/rfc7591#section-2.3">RFC 7591, Section 2.3</see>.
    /// A single member proves the interned string and the <c>Utf8</c> span never diverge.
    /// </summary>
    [TestMethod]
    [DataRow("redirect_uris")]
    [DataRow("token_endpoint_auth_method")]
    [DataRow("grant_types")]
    [DataRow("response_types")]
    [DataRow("client_name")]
    [DataRow("client_uri")]
    [DataRow("logo_uri")]
    [DataRow("scope")]
    [DataRow("contacts")]
    [DataRow("tos_uri")]
    [DataRow("policy_uri")]
    [DataRow("jwks_uri")]
    [DataRow("jwks")]
    [DataRow("software_id")]
    [DataRow("software_version")]
    [DataRow("software_statement")]
    [DataRow("client_id")]
    [DataRow("client_secret")]
    [DataRow("client_id_issued_at")]
    [DataRow("client_secret_expires_at")]
    public void MemberWireSpellingAndSpanAgreeWithRfc(string specWireName)
    {
        (string interned, string utf8Decoded, _) = ResolveMember(specWireName);

        Assert.AreEqual(specWireName, interned,
            $"RFC 7591 member '{specWireName}' MUST intern to its exact wire spelling in ClientMetadataParameterNames.");
        Assert.AreEqual(specWireName, utf8Decoded,
            $"The UTF-8 source span for '{specWireName}' MUST decode to the same wire spelling as the interned string.");
    }

    /// <summary>
    /// Each RFC 7591 member's <c>Is&lt;Member&gt;</c> predicate matches only the exact wire name
    /// ordinally: <see href="https://www.rfc-editor.org/rfc/rfc7591#section-2">RFC 7591, Section 2</see>
    /// defines the member names as JSON object names, and
    /// <see href="https://www.rfc-editor.org/rfc/rfc8259#section-4">RFC 8259, Section 4</see>
    /// ("The names within an object SHOULD be unique") treats a name as a case-sensitive string, so a
    /// case-folded or suffixed lookalike is a different name and MUST NOT match.
    /// </summary>
    [TestMethod]
    [DataRow("redirect_uris")]
    [DataRow("token_endpoint_auth_method")]
    [DataRow("grant_types")]
    [DataRow("response_types")]
    [DataRow("client_name")]
    [DataRow("client_uri")]
    [DataRow("logo_uri")]
    [DataRow("scope")]
    [DataRow("contacts")]
    [DataRow("tos_uri")]
    [DataRow("policy_uri")]
    [DataRow("jwks_uri")]
    [DataRow("jwks")]
    [DataRow("software_id")]
    [DataRow("software_version")]
    [DataRow("software_statement")]
    [DataRow("client_id")]
    [DataRow("client_secret")]
    [DataRow("client_id_issued_at")]
    [DataRow("client_secret_expires_at")]
    public void MemberPredicateIsExactAndOrdinal(string specWireName)
    {
        (_, _, Func<string, bool> predicate) = ResolveMember(specWireName);

        Assert.IsTrue(predicate(specWireName),
            $"Is-predicate for '{specWireName}' MUST match its exact wire spelling.");
        Assert.IsFalse(predicate(specWireName.ToUpperInvariant()),
            $"Is-predicate for '{specWireName}' MUST be ordinal (case-sensitive) and reject the upper-cased name.");
        Assert.IsFalse(predicate(specWireName + "_x"),
            $"Is-predicate for '{specWireName}' MUST be exact and reject a suffixed near-miss.");
    }

    /// <summary>
    /// <see cref="ClientIdMetadataDocumentReader.Parse"/> resolves a document whose members are
    /// written through <see cref="ClientMetadataParameterNames"/> and reads each value back,
    /// proving the reader and the table name the same members —
    /// <see href="https://www.rfc-editor.org/rfc/rfc7591#section-2">RFC 7591, Section 2</see>: "The
    /// following client metadata fields are defined by this specification." The document carries
    /// <c>client_id</c>, <c>jwks</c>, <c>jwks_uri</c>, <c>redirect_uris</c>,
    /// <c>token_endpoint_auth_method</c>, <c>client_name</c>, <c>software_statement</c> and
    /// <c>grant_types</c>, each property name emitted from the table's interned string.
    /// </summary>
    [TestMethod]
    public void ReaderResolvesDocumentWrittenThroughTheTable()
    {
        ReadOnlySpan<byte> document = WriteDocumentThroughTheTable();

        ClientIdMetadataDocumentReadResult result = ClientIdMetadataDocumentReader.Parse(document);

        Assert.IsFalse(result.HasDefects,
            $"A document whose members are written through the table MUST parse without defects; got {result.Defects}.");
        Assert.AreEqual("https://client.example.com/app", result.ClientId,
            "The reader MUST read client_id back through ClientMetadataParameterNames.ClientId.");
        Assert.IsNotNull(result.Metadata);
        Assert.AreEqual("Example Client", result.Metadata.ClientName,
            "The reader MUST read client_name back through ClientMetadataParameterNames.ClientName.");
        Assert.HasCount(1, result.Metadata.RedirectUris);
        Assert.AreEqual(new Uri("https://client.example.com/cb"), result.Metadata.RedirectUris[0],
            "The reader MUST read redirect_uris back through ClientMetadataParameterNames.RedirectUris.");
        Assert.HasCount(1, result.Metadata.GrantTypes);
        Assert.Contains(GrantType.AuthorizationCode, result.Metadata.GrantTypes,
            "The reader MUST read grant_types back through ClientMetadataParameterNames.GrantTypes.");
        Assert.AreEqual(ClientAuthenticationMethod.PrivateKeyJwt, result.Metadata.TokenEndpointAuthMethod!.Value,
            "The reader MUST read token_endpoint_auth_method back through ClientMetadataParameterNames.TokenEndpointAuthMethod.");
        Assert.IsNotNull(result.Metadata.Jwks);
        Assert.Contains("\"keys\"", result.Metadata.Jwks!, StringComparison.Ordinal,
            "The reader MUST read jwks back through ClientMetadataParameterNames.Jwks.");
        Assert.AreEqual(new Uri("https://client.example.com/jwks"), result.Metadata.JwksUri,
            "The reader MUST read jwks_uri back through ClientMetadataParameterNames.JwksUri.");
        Assert.AreEqual("eyJhbGciOiJSUzI1NiJ9.payload.sig", result.Metadata.SoftwareStatement,
            "The reader MUST read software_statement back through ClientMetadataParameterNames.SoftwareStatement.");
    }

    /// <summary>
    /// The registration endpoint emits <c>client_name</c> through the table: a registration whose
    /// <see cref="ClientMetadata.ClientName"/> is set is read back with the same value over the
    /// real wire, proving the response builder writes and the reader resolves the one
    /// <see href="https://www.rfc-editor.org/rfc/rfc7591#section-2">RFC 7591, Section 2</see>
    /// <c>client_name</c> member — "Human-readable string name of the client to be presented to
    /// the end-user".
    /// </summary>
    [TestMethod]
    public async Task RegistrationEndpointEmitsClientNameThroughTheTable()
    {
        await using TestHostShell host = new(TimeProvider);

        OAuthClient client = host.CreateOAuthClientWithoutRegistration();

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> signingKey =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        ClientMetadata metadata = new()
        {
            ClientName = "client-name-round-trip-probe",
            RedirectUris = [new Uri("https://client.example.com/callback")],
            TokenEndpointAuthMethod = ClientAuthenticationMethod.None,
            Scope = "openid"
        };

        RegisterClientOptions registerOptions = new()
        {
            RegistrationEndpoint = host.GlobalRegistrationEndpoint,
            AuthorizationServerIssuer = host.IssuerUri,
            Metadata = metadata,
            AuthenticationMethod = ClientAuthenticationMethod.None,
            SigningKeyMaterial = signingKey,
            Profile = PolicyProfile.Haip10
        };

        DynamicRegistrationResult registered = await client.DynamicRegistration
            .RegisterAsync(registerOptions, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual("client-name-round-trip-probe", registered.Response.Metadata.ClientName,
            "The registration endpoint MUST emit client_name through the table so the response echoes it unchanged.");
    }

    /// <summary>
    /// The per-profile client-metadata tables keep their own profile-specific member spellings and
    /// reference <see cref="ClientMetadataParameterNames"/> only for the shared RFC 7591 members:
    /// <see href="https://www.rfc-editor.org/rfc/rfc7591#section-2">RFC 7591, Section 2</see> defines
    /// the base members (the shared <c>client_id</c> and <c>jwks</c> the OpenID4VP table reuses),
    /// while each profile's own members carry the spellings of that profile's specification. This
    /// pin proves the tables did not collapse into one another.
    /// </summary>
    [TestMethod]
    public void PerProfileTablesCarryTheirOwnMembersAndShareOnlyTheBase()
    {
        Assert.AreEqual("authorization_signed_response_alg", JarmClientMetadataParameterNames.AuthorizationSignedResponseAlg,
            "The JARM table MUST keep its own authorization_signed_response_alg member.");
        Assert.AreEqual("authorization_encrypted_response_alg", JarmClientMetadataParameterNames.AuthorizationEncryptedResponseAlg,
            "The JARM table MUST keep its own authorization_encrypted_response_alg member.");
        Assert.AreEqual("authorization_encrypted_response_enc", JarmClientMetadataParameterNames.AuthorizationEncryptedResponseEnc,
            "The JARM table MUST keep its own authorization_encrypted_response_enc member.");

        Assert.AreEqual("subject_syntax_types_supported", SiopClientMetadataParameterNames.SubjectSyntaxTypesSupported,
            "The SIOP table MUST keep its own subject_syntax_types_supported member.");
        Assert.AreEqual("id_token_signed_response_alg", SiopClientMetadataParameterNames.IdTokenSignedResponseAlg,
            "The SIOP table MUST keep its own id_token_signed_response_alg member.");
        Assert.AreEqual("id_token_types_supported", SiopClientMetadataParameterNames.IdTokenTypesSupported,
            "The SIOP table MUST keep its own id_token_types_supported member.");
        Assert.AreEqual("request_object_signing_alg_values_supported", SiopClientMetadataParameterNames.RequestObjectSigningAlgValuesSupported,
            "The SIOP table MUST keep its own request_object_signing_alg_values_supported member.");

        Assert.AreEqual("vp_formats_supported", Oid4VpClientMetadataParameterNames.VpFormatsSupported,
            "The OpenID4VP table MUST keep its own vp_formats_supported member.");
        Assert.AreEqual("encrypted_response_enc_values_supported", Oid4VpClientMetadataParameterNames.EncryptedResponseEncValuesSupported,
            "The OpenID4VP table MUST keep its own encrypted_response_enc_values_supported member.");
        Assert.AreEqual("encrypted_response_alg_values_supported", Oid4VpClientMetadataParameterNames.EncryptedResponseAlgValuesSupported,
            "The OpenID4VP table MUST keep its own encrypted_response_alg_values_supported member.");

        Assert.AreEqual("introspection_signed_response_alg", IntrospectionClientMetadataParameterNames.IntrospectionSignedResponseAlg,
            "The introspection table MUST keep its own introspection_signed_response_alg member.");
        Assert.AreEqual("introspection_encrypted_response_alg", IntrospectionClientMetadataParameterNames.IntrospectionEncryptedResponseAlg,
            "The introspection table MUST keep its own introspection_encrypted_response_alg member.");
        Assert.AreEqual("introspection_encrypted_response_enc", IntrospectionClientMetadataParameterNames.IntrospectionEncryptedResponseEnc,
            "The introspection table MUST keep its own introspection_encrypted_response_enc member.");

        Assert.AreEqual(ClientMetadataParameterNames.ClientId, Oid4VpClientMetadataParameterNames.ClientId,
            "The OpenID4VP table's shared client_id member MUST spell the same wire name as the base RFC 7591 table.");
        Assert.AreEqual(ClientMetadataParameterNames.Jwks, Oid4VpClientMetadataParameterNames.Jwks,
            "The OpenID4VP table's shared jwks member MUST spell the same wire name as the base RFC 7591 table.");
    }

    /// <summary>
    /// Builds a Client ID Metadata Document whose every property name is the interned string from
    /// <see cref="ClientMetadataParameterNames"/>, so a mis-spelled table entry produces a document
    /// the reader cannot resolve. The JWKS carries a public EC key only, and every value is
    /// well-formed, so a conforming reader reports no defect.
    /// </summary>
    private static byte[] WriteDocumentThroughTheTable()
    {
        ArrayBufferWriter<byte> buffer = new();
        using(Utf8JsonWriter writer = new(buffer))
        {
            writer.WriteStartObject();
            writer.WriteString(ClientMetadataParameterNames.ClientId, "https://client.example.com/app");
            writer.WriteString(ClientMetadataParameterNames.ClientName, "Example Client");

            writer.WritePropertyName(ClientMetadataParameterNames.RedirectUris);
            writer.WriteStartArray();
            writer.WriteStringValue("https://client.example.com/cb");
            writer.WriteEndArray();

            writer.WritePropertyName(ClientMetadataParameterNames.GrantTypes);
            writer.WriteStartArray();
            writer.WriteStringValue("authorization_code");
            writer.WriteEndArray();

            writer.WriteString(ClientMetadataParameterNames.TokenEndpointAuthMethod, "private_key_jwt");

            writer.WritePropertyName(ClientMetadataParameterNames.Jwks);
            writer.WriteStartObject();
            writer.WritePropertyName("keys");
            writer.WriteStartArray();
            writer.WriteStartObject();
            writer.WriteString("kty", "EC");
            writer.WriteString("crv", "P-256");
            writer.WriteString("x", "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU");
            writer.WriteString("y", "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0");
            writer.WriteEndObject();
            writer.WriteEndArray();
            writer.WriteEndObject();

            writer.WriteString(ClientMetadataParameterNames.JwksUri, "https://client.example.com/jwks");
            writer.WriteString(ClientMetadataParameterNames.SoftwareStatement, "eyJhbGciOiJSUzI1NiJ9.payload.sig");
            writer.WriteEndObject();
        }

        return buffer.WrittenSpan.ToArray();
    }

    /// <summary>
    /// Routes an RFC 7591 wire name to the three forms <see cref="ClientMetadataParameterNames"/>
    /// exposes for that member — the interned string, the UTF-8 source span decoded to a string,
    /// and the <c>Is&lt;Member&gt;</c> predicate — so a test asserts the table's own values against
    /// a spelling typed from the RFC text. The switch label is a literal, not a value read off the
    /// table.
    /// </summary>
    private static (string Interned, string Utf8Decoded, Func<string, bool> Predicate) ResolveMember(string specWireName) =>
        specWireName switch
        {
            "redirect_uris" => (ClientMetadataParameterNames.RedirectUris,
                Encoding.UTF8.GetString(ClientMetadataParameterNames.RedirectUrisUtf8), ClientMetadataParameterNames.IsRedirectUris),
            "token_endpoint_auth_method" => (ClientMetadataParameterNames.TokenEndpointAuthMethod,
                Encoding.UTF8.GetString(ClientMetadataParameterNames.TokenEndpointAuthMethodUtf8), ClientMetadataParameterNames.IsTokenEndpointAuthMethod),
            "grant_types" => (ClientMetadataParameterNames.GrantTypes,
                Encoding.UTF8.GetString(ClientMetadataParameterNames.GrantTypesUtf8), ClientMetadataParameterNames.IsGrantTypes),
            "response_types" => (ClientMetadataParameterNames.ResponseTypes,
                Encoding.UTF8.GetString(ClientMetadataParameterNames.ResponseTypesUtf8), ClientMetadataParameterNames.IsResponseTypes),
            "client_name" => (ClientMetadataParameterNames.ClientName,
                Encoding.UTF8.GetString(ClientMetadataParameterNames.ClientNameUtf8), ClientMetadataParameterNames.IsClientName),
            "client_uri" => (ClientMetadataParameterNames.ClientUri,
                Encoding.UTF8.GetString(ClientMetadataParameterNames.ClientUriUtf8), ClientMetadataParameterNames.IsClientUri),
            "logo_uri" => (ClientMetadataParameterNames.LogoUri,
                Encoding.UTF8.GetString(ClientMetadataParameterNames.LogoUriUtf8), ClientMetadataParameterNames.IsLogoUri),
            "scope" => (ClientMetadataParameterNames.Scope,
                Encoding.UTF8.GetString(ClientMetadataParameterNames.ScopeUtf8), ClientMetadataParameterNames.IsScope),
            "contacts" => (ClientMetadataParameterNames.Contacts,
                Encoding.UTF8.GetString(ClientMetadataParameterNames.ContactsUtf8), ClientMetadataParameterNames.IsContacts),
            "tos_uri" => (ClientMetadataParameterNames.TosUri,
                Encoding.UTF8.GetString(ClientMetadataParameterNames.TosUriUtf8), ClientMetadataParameterNames.IsTosUri),
            "policy_uri" => (ClientMetadataParameterNames.PolicyUri,
                Encoding.UTF8.GetString(ClientMetadataParameterNames.PolicyUriUtf8), ClientMetadataParameterNames.IsPolicyUri),
            "jwks_uri" => (ClientMetadataParameterNames.JwksUri,
                Encoding.UTF8.GetString(ClientMetadataParameterNames.JwksUriUtf8), ClientMetadataParameterNames.IsJwksUri),
            "jwks" => (ClientMetadataParameterNames.Jwks,
                Encoding.UTF8.GetString(ClientMetadataParameterNames.JwksUtf8), ClientMetadataParameterNames.IsJwks),
            "software_id" => (ClientMetadataParameterNames.SoftwareId,
                Encoding.UTF8.GetString(ClientMetadataParameterNames.SoftwareIdUtf8), ClientMetadataParameterNames.IsSoftwareId),
            "software_version" => (ClientMetadataParameterNames.SoftwareVersion,
                Encoding.UTF8.GetString(ClientMetadataParameterNames.SoftwareVersionUtf8), ClientMetadataParameterNames.IsSoftwareVersion),
            "software_statement" => (ClientMetadataParameterNames.SoftwareStatement,
                Encoding.UTF8.GetString(ClientMetadataParameterNames.SoftwareStatementUtf8), ClientMetadataParameterNames.IsSoftwareStatement),
            "client_id" => (ClientMetadataParameterNames.ClientId,
                Encoding.UTF8.GetString(ClientMetadataParameterNames.ClientIdUtf8), ClientMetadataParameterNames.IsClientId),
            "client_secret" => (ClientMetadataParameterNames.ClientSecret,
                Encoding.UTF8.GetString(ClientMetadataParameterNames.ClientSecretUtf8), ClientMetadataParameterNames.IsClientSecret),
            "client_id_issued_at" => (ClientMetadataParameterNames.ClientIdIssuedAt,
                Encoding.UTF8.GetString(ClientMetadataParameterNames.ClientIdIssuedAtUtf8), ClientMetadataParameterNames.IsClientIdIssuedAt),
            "client_secret_expires_at" => (ClientMetadataParameterNames.ClientSecretExpiresAt,
                Encoding.UTF8.GetString(ClientMetadataParameterNames.ClientSecretExpiresAtUtf8), ClientMetadataParameterNames.IsClientSecretExpiresAt),
            _ => throw new ArgumentOutOfRangeException(nameof(specWireName), specWireName, "Unmapped RFC 7591 client metadata member name.")
        };
}
