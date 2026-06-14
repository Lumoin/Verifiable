using System.Text;
using Verifiable.JCose;
using Verifiable.Server;

namespace Verifiable.OAuth.Oid4Vci;

/// <summary>
/// Serializes an OID4VCI 1.0 §4.1.1 <see cref="CredentialOffer"/> to its wire forms — the
/// JSON object, the §4.1.2 by-value deep link (<c>credential_offer</c>), and the §4.1.3
/// by-reference deep link (<c>credential_offer_uri</c>) — and parses the inverse: the offer
/// JSON the Wallet receives by value or fetches by reference back into the model.
/// </summary>
/// <remarks>
/// Built on <see cref="JsonAppender"/> and <see cref="JwkJsonReader"/> to honour the
/// <c>Verifiable.OAuth</c> serialization firewall (no <c>System.Text.Json</c>). The Issuer
/// application composes the offer and chooses how to deliver it — a QR code or link carrying the
/// by-value deep link, or a URL it serves the JSON object from (via <see cref="ToJson"/>)
/// referenced by the by-reference deep link. §4.1.3: the offer is never signed and the
/// by-reference resource MUST be <c>application/json</c>. The Wallet recreates the offer with
/// <see cref="FromJson"/> (the offer JSON) or <see cref="ExtractFromDeepLink"/> (the §4.1.2
/// by-value deep link).
/// </remarks>
public static class CredentialOfferSerializer
{
    /// <summary>
    /// The custom URL scheme a native Wallet registers for Credential Offers (§4.1.2), including
    /// the <c>://</c> so it composes directly with the query string.
    /// </summary>
    public const string DefaultScheme = "openid-credential-offer://";

    /// <summary>
    /// §4.1.1 <c>tx_code.description</c>: "The length of the string MUST NOT exceed 300 characters."
    /// </summary>
    public const int MaxTxCodeDescriptionLength = 300;


    /// <summary>
    /// Serializes the offer to its §4.1.1 JSON object. <c>grants</c> is emitted only when at
    /// least one grant is present; a non-<see langword="null"/> <c>tx_code</c> is emitted even
    /// when empty (its presence signals a required Transaction Code).
    /// </summary>
    /// <param name="offer">The offer to serialize.</param>
    /// <returns>The JSON-encoded Credential Offer object.</returns>
    public static string ToJson(CredentialOffer offer)
    {
        ArgumentNullException.ThrowIfNull(offer);
        ValidateCredentialConfigurationIds(offer.CredentialConfigurationIds);
        ValidateTxCodeDescription(offer.PreAuthorizedCodeGrant?.TxCode?.Description);

        StringBuilder sb = JsonAppender.Rent();
        try
        {
            sb.Append('{');
            bool first = true;
            JsonAppender.AppendStringField(
                sb, CredentialIssuerMetadataParameterNames.CredentialIssuer,
                offer.CredentialIssuer.OriginalString, ref first);
            JsonAppender.AppendStringArrayField(
                sb, CredentialOfferParameterNames.CredentialConfigurationIds,
                offer.CredentialConfigurationIds, ref first);

            if(offer.PreAuthorizedCodeGrant is not null || offer.AuthorizationCodeGrant is not null)
            {
                JsonAppender.AppendRawField(
                    sb, CredentialOfferParameterNames.Grants, BuildGrantsJson(offer), ref first);
            }

            sb.Append('}');

            return sb.ToString();
        }
        finally
        {
            JsonAppender.Return(sb);
        }
    }


    /// <summary>
    /// Composes the §4.1.2 by-value deep link
    /// <c>&lt;scheme&gt;?credential_offer=&lt;url-encoded JSON&gt;</c>.
    /// </summary>
    /// <param name="offer">The offer to carry by value.</param>
    /// <param name="scheme">The invocation scheme; defaults to <see cref="DefaultScheme"/>.</param>
    /// <returns>The deep link a QR code or link can carry.</returns>
    public static string ToByValueDeepLink(CredentialOffer offer, string scheme = DefaultScheme)
    {
        ArgumentNullException.ThrowIfNull(offer);
        ArgumentException.ThrowIfNullOrEmpty(scheme);

        return $"{scheme}?{CredentialOfferParameterNames.CredentialOffer}="
            + Uri.EscapeDataString(ToJson(offer));
    }


    /// <summary>
    /// Composes the §4.1.3 by-reference deep link
    /// <c>&lt;scheme&gt;?credential_offer_uri=&lt;url-encoded URL&gt;</c>, where
    /// <paramref name="credentialOfferUri"/> is the <c>https</c> URL the Issuer serves the offer
    /// JSON from.
    /// </summary>
    /// <param name="credentialOfferUri">The URL the Wallet GETs to retrieve the offer object.</param>
    /// <param name="scheme">The invocation scheme; defaults to <see cref="DefaultScheme"/>.</param>
    /// <returns>The deep link a QR code or link can carry.</returns>
    public static string ToByReferenceDeepLink(Uri credentialOfferUri, string scheme = DefaultScheme)
    {
        ArgumentNullException.ThrowIfNull(credentialOfferUri);
        ArgumentException.ThrowIfNullOrEmpty(scheme);

        return $"{scheme}?{CredentialOfferParameterNames.CredentialOfferUri}="
            + Uri.EscapeDataString(credentialOfferUri.OriginalString);
    }


    /// <summary>
    /// Recreates the §4.1.1 <see cref="CredentialOffer"/> from its JSON object — the inverse of
    /// <see cref="ToJson"/>. Reads <c>credential_issuer</c>, <c>credential_configuration_ids</c>,
    /// and the <c>grants</c> block (the <c>urn:ietf:params:oauth:grant-type:pre-authorized_code</c>
    /// and <c>authorization_code</c> grants).
    /// </summary>
    /// <remarks>
    /// §4.1.1: "Additional Credential Offer parameters MAY be defined and used. The Wallet MUST
    /// ignore any unrecognized parameters." The reader looks up only the keys this specification
    /// defines, so an unrecognized top-level member, an unrecognized member inside a grant block,
    /// and any grant type other than the two defined here are all simply not read — they are
    /// ignored without error.
    /// </remarks>
    /// <param name="offerJson">The §4.1.1 Credential Offer JSON object.</param>
    /// <returns>The parsed Credential Offer.</returns>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="offerJson"/> carries no <c>credential_issuer</c> URL or no
    /// non-empty <c>credential_configuration_ids</c> array — both are REQUIRED by §4.1.1.
    /// </exception>
    public static CredentialOffer FromJson(string offerJson)
    {
        ArgumentException.ThrowIfNullOrEmpty(offerJson);

        ReadOnlySpan<byte> json = Encoding.UTF8.GetBytes(offerJson);

        //§4.1.1 credential_issuer (REQUIRED): "The URL of the Credential Issuer ... from which the
        //Wallet is requested to obtain one or more Credentials."
        string? credentialIssuer = JwkJsonReader.ExtractStringValue(
            json, CredentialIssuerMetadataParameterNames.CredentialIssuerUtf8);
        if(string.IsNullOrEmpty(credentialIssuer))
        {
            throw new ArgumentException(
                "§4.1.1 credential_issuer is REQUIRED; the offer JSON carries none.", nameof(offerJson));
        }

        //§4.1.1 credential_configuration_ids (REQUIRED): "A non-empty array of unique strings."
        List<string>? configurationIds = JwkJsonReader.ExtractStringArrayProperty(
            json, CredentialOfferParameterNames.CredentialConfigurationIdsUtf8);
        if(configurationIds is null || configurationIds.Count == 0)
        {
            throw new ArgumentException(
                "§4.1.1 credential_configuration_ids is a REQUIRED non-empty array; the offer JSON carries none.",
                nameof(offerJson));
        }

        //§4.1.1 grants (OPTIONAL): the grant-type → parameters map. Absent when the offer leaves the
        //Wallet to determine grant types from the issuer metadata.
        string? grantsJson = JwkJsonReader.ExtractObjectAsString(json, CredentialOfferParameterNames.GrantsUtf8);

        return new CredentialOffer
        {
            CredentialIssuer = new Uri(credentialIssuer, UriKind.RelativeOrAbsolute),
            CredentialConfigurationIds = configurationIds,
            PreAuthorizedCodeGrant = grantsJson is null ? null : ParsePreAuthorizedCodeGrant(grantsJson),
            AuthorizationCodeGrant = grantsJson is null ? null : ParseAuthorizationCodeGrant(grantsJson)
        };
    }


    /// <summary>
    /// Extracts a <see cref="CredentialOffer"/> from a §4.1.2 by-value deep link
    /// (<c>&lt;scheme&gt;?credential_offer=&lt;url-encoded JSON&gt;</c>) or from the raw
    /// URL-encoded <c>credential_offer</c> value, URL-decoding then parsing it with
    /// <see cref="FromJson"/>. The §4.1.3 by-reference form (<c>credential_offer_uri</c>) is
    /// surfaced by <see cref="TryGetCredentialOfferUri"/>, not here — a by-reference link carries
    /// no inline offer to parse.
    /// </summary>
    /// <remarks>
    /// §4.1: "The Credential Offer contains a single URI query parameter, either credential_offer
    /// or credential_offer_uri" — <c>credential_offer</c> "MUST NOT be present when the
    /// credential_offer_uri parameter is present." A link carrying both is malformed and rejected.
    /// </remarks>
    /// <param name="deepLinkOrValue">
    /// The full <c>&lt;scheme&gt;?credential_offer=...</c> deep link, or the raw URL-encoded offer
    /// JSON value.
    /// </param>
    /// <returns>The parsed Credential Offer.</returns>
    /// <exception cref="ArgumentException">
    /// Thrown when the link carries both <c>credential_offer</c> and <c>credential_offer_uri</c>
    /// (the §4.1 mutual-exclusion violation), or carries no <c>credential_offer</c> value to parse.
    /// </exception>
    public static CredentialOffer ExtractFromDeepLink(string deepLinkOrValue)
    {
        ArgumentException.ThrowIfNullOrEmpty(deepLinkOrValue);

        if(TryGetQueryParameters(deepLinkOrValue, out string? byValue, out string? byReference))
        {
            //§4.1: credential_offer "MUST NOT be present when the credential_offer_uri parameter is
            //present", and vice versa. A link carrying both is malformed.
            if(byValue is not null && byReference is not null)
            {
                throw new ArgumentException(
                    "§4.1 a Credential Offer link carries a single query parameter — either "
                    + "credential_offer or credential_offer_uri, never both.", nameof(deepLinkOrValue));
            }

            if(byReference is not null)
            {
                throw new ArgumentException(
                    "§4.1.3 this link carries a credential_offer_uri (by reference); fetch it with the "
                    + "wallet client's AcceptCredentialOfferAsync rather than parsing it inline.",
                    nameof(deepLinkOrValue));
            }

            if(byValue is null)
            {
                throw new ArgumentException(
                    "§4.1.2 the link carries no credential_offer value to parse.", nameof(deepLinkOrValue));
            }

            return FromJson(Uri.UnescapeDataString(byValue));
        }

        //No recognizable query: treat the argument as the raw (URL-encoded) credential_offer value.
        return FromJson(Uri.UnescapeDataString(deepLinkOrValue));
    }


    /// <summary>
    /// Reads the §4.1.3 <c>credential_offer_uri</c> out of a by-reference deep link
    /// (<c>&lt;scheme&gt;?credential_offer_uri=&lt;url-encoded https URL&gt;</c>), the URL the
    /// Wallet GETs to retrieve the offer object.
    /// </summary>
    /// <remarks>
    /// §4.1: a link carries a single query parameter; <c>credential_offer_uri</c> "MUST NOT be
    /// present when the credential_offer parameter is present." A link carrying both is malformed
    /// and rejected here too, so a caller probing for a by-reference URL still rejects the
    /// mutual-exclusion violation rather than silently preferring one form.
    /// </remarks>
    /// <param name="deepLink">The §4.1.3 by-reference deep link.</param>
    /// <param name="credentialOfferUri">The decoded <c>credential_offer_uri</c> when present.</param>
    /// <returns>
    /// <see langword="true"/> when the link carries a <c>credential_offer_uri</c>;
    /// <see langword="false"/> when it carries a by-value <c>credential_offer</c> instead (or
    /// neither).
    /// </returns>
    /// <exception cref="ArgumentException">
    /// Thrown when the link carries both <c>credential_offer</c> and <c>credential_offer_uri</c>.
    /// </exception>
    public static bool TryGetCredentialOfferUri(string deepLink, out Uri? credentialOfferUri)
    {
        ArgumentException.ThrowIfNullOrEmpty(deepLink);

        credentialOfferUri = null;
        if(!TryGetQueryParameters(deepLink, out string? byValue, out string? byReference))
        {
            return false;
        }

        if(byValue is not null && byReference is not null)
        {
            throw new ArgumentException(
                "§4.1 a Credential Offer link carries a single query parameter — either "
                + "credential_offer or credential_offer_uri, never both.", nameof(deepLink));
        }

        if(byReference is null)
        {
            return false;
        }

        credentialOfferUri = new Uri(Uri.UnescapeDataString(byReference), UriKind.RelativeOrAbsolute);

        return true;
    }


    //Parses the §4.1.1 urn:ietf:params:oauth:grant-type:pre-authorized_code grant block out of the
    //grants object, or null when the offer advertises no Pre-Authorized Code grant.
    private static PreAuthorizedCodeOfferGrant? ParsePreAuthorizedCodeGrant(string grantsJson)
    {
        ReadOnlySpan<byte> grants = Encoding.UTF8.GetBytes(grantsJson);
        string? grantJson = JwkJsonReader.ExtractObjectAsString(
            grants, OAuthRequestParameterValues.GrantTypePreAuthorizedCodeUtf8);
        if(grantJson is null)
        {
            return null;
        }

        ReadOnlySpan<byte> grant = Encoding.UTF8.GetBytes(grantJson);

        //pre-authorized_code (REQUIRED in this grant): the code the Wallet presents to the §6 token
        //endpoint. A grant block missing it is malformed.
        string? preAuthorizedCode = JwkJsonReader.ExtractStringValue(grant, OAuthRequestParameterNames.PreAuthorizedCodeUtf8);
        if(string.IsNullOrEmpty(preAuthorizedCode))
        {
            throw new ArgumentException(
                "§4.1.1 the pre-authorized_code grant is present but carries no REQUIRED "
                + "pre-authorized_code.", nameof(grantsJson));
        }

        //§4.1.1: tx_code is an "Object indicating that a Transaction Code is required if present,
        //even if empty." Its mere presence — independent of its hint members — signals the
        //requirement, so the model carries a non-null TxCode whenever the member is present.
        TxCodeRequirement? txCode = JwkJsonReader.ContainsKey(grant, OAuthRequestParameterNames.TxCodeUtf8)
            ? ParseTxCode(grant)
            : null;

        return new PreAuthorizedCodeOfferGrant
        {
            PreAuthorizedCode = preAuthorizedCode,
            TxCode = txCode,
            AuthorizationServer = JwkJsonReader.ExtractStringValue(grant, CredentialOfferParameterNames.AuthorizationServerUtf8)
        };
    }


    //Parses the §4.1.1 tx_code object's display hints. An all-unset object yields the empty
    //requirement — its presence alone already signalled the Transaction Code is required.
    private static TxCodeRequirement ParseTxCode(ReadOnlySpan<byte> grant)
    {
        string? txCodeJson = JwkJsonReader.ExtractObjectAsString(grant, OAuthRequestParameterNames.TxCodeUtf8);
        if(txCodeJson is null)
        {
            return TxCodeRequirement.Empty;
        }

        ReadOnlySpan<byte> txCode = Encoding.UTF8.GetBytes(txCodeJson);
        int? length = JwkJsonReader.TryExtractLongValue(txCode, CredentialOfferParameterNames.LengthUtf8, out long parsedLength)
            ? checked((int)parsedLength)
            : null;

        return new TxCodeRequirement
        {
            InputMode = JwkJsonReader.ExtractStringValue(txCode, CredentialOfferParameterNames.InputModeUtf8),
            Length = length,
            Description = JwkJsonReader.ExtractStringValue(txCode, CredentialOfferParameterNames.DescriptionUtf8)
        };
    }


    //Parses the §4.1.1 authorization_code grant block out of the grants object, or null when the
    //offer advertises no Authorization Code grant.
    private static AuthorizationCodeOfferGrant? ParseAuthorizationCodeGrant(string grantsJson)
    {
        ReadOnlySpan<byte> grants = Encoding.UTF8.GetBytes(grantsJson);
        string? grantJson = JwkJsonReader.ExtractObjectAsString(
            grants, OAuthRequestParameterValues.GrantTypeAuthorizationCodeUtf8);
        if(grantJson is null)
        {
            return null;
        }

        ReadOnlySpan<byte> grant = Encoding.UTF8.GetBytes(grantJson);

        return new AuthorizationCodeOfferGrant
        {
            IssuerState = JwkJsonReader.ExtractStringValue(grant, CredentialOfferParameterNames.IssuerStateUtf8),
            AuthorizationServer = JwkJsonReader.ExtractStringValue(grant, CredentialOfferParameterNames.AuthorizationServerUtf8)
        };
    }


    //Pulls the credential_offer / credential_offer_uri query values out of a deep link's query
    //string. Returns false when the argument carries no '?' query at all (the caller then treats it
    //as a raw credential_offer value). The values are returned still URL-encoded — the caller
    //decodes the one it uses.
    private static bool TryGetQueryParameters(string deepLink, out string? credentialOffer, out string? credentialOfferUri)
    {
        credentialOffer = null;
        credentialOfferUri = null;

        int queryStart = deepLink.IndexOf('?', StringComparison.Ordinal);
        if(queryStart < 0)
        {
            return false;
        }

        ReadOnlySpan<char> query = deepLink.AsSpan(queryStart + 1);
        foreach(Range pairRange in query.Split('&'))
        {
            ReadOnlySpan<char> pair = query[pairRange];
            int equals = pair.IndexOf('=');
            if(equals < 0)
            {
                continue;
            }

            ReadOnlySpan<char> name = pair[..equals];
            ReadOnlySpan<char> value = pair[(equals + 1)..];

            if(name.SequenceEqual(CredentialOfferParameterNames.CredentialOffer))
            {
                credentialOffer = value.ToString();
            }
            else if(name.SequenceEqual(CredentialOfferParameterNames.CredentialOfferUri))
            {
                credentialOfferUri = value.ToString();
            }
        }

        return true;
    }


    /// <summary>
    /// §4.1.1 <c>credential_configuration_ids</c> (REQUIRED): "a non-empty JSON array, where every
    /// entry is a string" identifying a Credential Configuration. Each entry uniquely identifies one
    /// of the keys in <c>credential_configurations_supported</c>, so the list carries no duplicates.
    /// </summary>
    private static void ValidateCredentialConfigurationIds(IReadOnlyList<string> configurationIds)
    {
        if(configurationIds.Count == 0)
        {
            throw new ArgumentException(
                "§4.1.1 credential_configuration_ids is a non-empty array; the offer lists none.",
                nameof(configurationIds));
        }

        HashSet<string> seen = new(StringComparer.Ordinal);
        foreach(string configurationId in configurationIds)
        {
            if(string.IsNullOrEmpty(configurationId))
            {
                throw new ArgumentException(
                    "§4.1.1 every credential_configuration_ids entry is a string; the offer carries an empty one.",
                    nameof(configurationIds));
            }

            if(!seen.Add(configurationId))
            {
                throw new ArgumentException(
                    $"§4.1.1 credential_configuration_ids entries are unique; '{configurationId}' is duplicated.",
                    nameof(configurationIds));
            }
        }
    }


    /// <summary>
    /// §4.1.1 <c>tx_code.description</c>: "The length of the string MUST NOT exceed 300 characters."
    /// </summary>
    private static void ValidateTxCodeDescription(string? description)
    {
        if(description is not null && description.Length > MaxTxCodeDescriptionLength)
        {
            throw new ArgumentException(
                $"§4.1.1 tx_code.description MUST NOT exceed {MaxTxCodeDescriptionLength} characters; "
                + $"the offer carries {description.Length}.",
                nameof(description));
        }
    }


    private static string BuildGrantsJson(CredentialOffer offer)
    {
        StringBuilder sb = JsonAppender.Rent();
        try
        {
            sb.Append('{');
            bool first = true;

            if(offer.PreAuthorizedCodeGrant is PreAuthorizedCodeOfferGrant preAuthorized)
            {
                JsonAppender.AppendRawField(
                    sb, OAuthRequestParameterValues.GrantTypePreAuthorizedCode,
                    BuildPreAuthorizedCodeGrantJson(preAuthorized), ref first);
            }

            if(offer.AuthorizationCodeGrant is AuthorizationCodeOfferGrant authorizationCode)
            {
                JsonAppender.AppendRawField(
                    sb, OAuthRequestParameterValues.GrantTypeAuthorizationCode,
                    BuildAuthorizationCodeGrantJson(authorizationCode), ref first);
            }

            sb.Append('}');

            return sb.ToString();
        }
        finally
        {
            JsonAppender.Return(sb);
        }
    }


    private static string BuildPreAuthorizedCodeGrantJson(PreAuthorizedCodeOfferGrant grant)
    {
        StringBuilder sb = JsonAppender.Rent();
        try
        {
            sb.Append('{');
            bool first = true;
            JsonAppender.AppendStringField(
                sb, OAuthRequestParameterNames.PreAuthorizedCode, grant.PreAuthorizedCode, ref first);

            //§4.1.1: the presence of tx_code — even an empty object — signals a required
            //Transaction Code, so it is emitted whenever TxCode is non-null.
            if(grant.TxCode is TxCodeRequirement txCode)
            {
                JsonAppender.AppendRawField(
                    sb, OAuthRequestParameterNames.TxCode, BuildTxCodeJson(txCode), ref first);
            }

            if(!string.IsNullOrEmpty(grant.AuthorizationServer))
            {
                JsonAppender.AppendStringField(
                    sb, CredentialOfferParameterNames.AuthorizationServer, grant.AuthorizationServer, ref first);
            }

            sb.Append('}');

            return sb.ToString();
        }
        finally
        {
            JsonAppender.Return(sb);
        }
    }


    private static string BuildTxCodeJson(TxCodeRequirement txCode)
    {
        StringBuilder sb = JsonAppender.Rent();
        try
        {
            sb.Append('{');
            bool first = true;

            if(!string.IsNullOrEmpty(txCode.InputMode))
            {
                JsonAppender.AppendStringField(
                    sb, CredentialOfferParameterNames.InputMode, txCode.InputMode, ref first);
            }

            if(txCode.Length is int length)
            {
                JsonAppender.AppendInt64Field(
                    sb, CredentialOfferParameterNames.Length, length, ref first);
            }

            if(!string.IsNullOrEmpty(txCode.Description))
            {
                JsonAppender.AppendStringField(
                    sb, CredentialOfferParameterNames.Description, txCode.Description, ref first);
            }

            sb.Append('}');

            return sb.ToString();
        }
        finally
        {
            JsonAppender.Return(sb);
        }
    }


    private static string BuildAuthorizationCodeGrantJson(AuthorizationCodeOfferGrant grant)
    {
        StringBuilder sb = JsonAppender.Rent();
        try
        {
            sb.Append('{');
            bool first = true;

            if(!string.IsNullOrEmpty(grant.IssuerState))
            {
                JsonAppender.AppendStringField(
                    sb, CredentialOfferParameterNames.IssuerState, grant.IssuerState, ref first);
            }

            if(!string.IsNullOrEmpty(grant.AuthorizationServer))
            {
                JsonAppender.AppendStringField(
                    sb, CredentialOfferParameterNames.AuthorizationServer, grant.AuthorizationServer, ref first);
            }

            sb.Append('}');

            return sb.ToString();
        }
        finally
        {
            JsonAppender.Return(sb);
        }
    }
}
