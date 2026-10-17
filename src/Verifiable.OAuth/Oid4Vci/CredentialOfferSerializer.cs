using System.Text;
using Verifiable.JCose;

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
            _ = sb.Append('{');
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

            _ = sb.Append('}');

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
    /// <remarks>
    /// Section 4.1: "credential_offer_uri: String that is a URL using the https scheme referencing a
    /// resource containing a JSON object with the Credential Offer parameters." The URI is the
    /// caller's own argument, so one that is not an absolute <c>https</c> URL is refused here rather
    /// than composed into a link no Wallet may follow.
    /// </remarks>
    /// <param name="credentialOfferUri">The URL the Wallet GETs to retrieve the offer object.</param>
    /// <param name="scheme">The invocation scheme; defaults to <see cref="DefaultScheme"/>.</param>
    /// <returns>The deep link a QR code or link can carry.</returns>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="credentialOfferUri"/> is not an absolute URL using the <c>https</c>
    /// scheme, or when <paramref name="scheme"/> is empty.
    /// </exception>
    public static string ToByReferenceDeepLink(Uri credentialOfferUri, string scheme = DefaultScheme)
    {
        ArgumentNullException.ThrowIfNull(credentialOfferUri);
        ArgumentException.ThrowIfNullOrEmpty(scheme);

        if(!credentialOfferUri.IsAbsoluteUri
            || !string.Equals(credentialOfferUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException(
                "Section 4.1 credential_offer_uri is a URL using the https scheme; the composer was given "
                + "a value that is not an absolute https URL.",
                nameof(credentialOfferUri));
        }

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
    /// Thrown when <paramref name="offerJson"/> violates a rule <see cref="TryParse"/> answers: no
    /// <c>credential_issuer</c> URL; a <c>credential_configuration_ids</c> that is absent, is no array of
    /// strings, is empty, or holds an empty or a repeated entry; a <c>grants</c> or a grant value that
    /// is no object; a pre-authorized grant without its code; a <c>tx_code</c> that is no object; a
    /// <c>tx_code.length</c> that is no Integer from 0 to 2147483647; or an <c>input_mode</c>,
    /// <c>description</c>, <c>authorization_server</c> or <c>issuer_state</c> that is no string.
    /// </exception>
    public static CredentialOffer FromJson(string offerJson)
    {
        ArgumentException.ThrowIfNullOrEmpty(offerJson);

        if(!TryParse(offerJson, out CredentialOffer? offer, out string? violatedRule))
        {
            throw new ArgumentException(violatedRule, nameof(offerJson));
        }

        return offer!;
    }


    /// <summary>
    /// Parses the §4.1.1 Credential Offer JSON object without raising — the inverse of
    /// <see cref="ToJson"/> answered as a value rather than an exception. <see cref="FromJson"/>
    /// raises the exact same rules as an <see cref="ArgumentException"/>; a caller reading the
    /// offer over the wire — where a malformed body is the remote party's mistake, not the
    /// caller's own — reports <paramref name="violatedRule"/> instead of catching one.
    /// </summary>
    /// <param name="offerJson">The §4.1.1 Credential Offer JSON object.</param>
    /// <param name="offer">The parsed offer on success; otherwise <see langword="null"/>.</param>
    /// <param name="violatedRule">
    /// The violated §4.1.1 rule, in the library's own words, on failure; otherwise
    /// <see langword="null"/>.
    /// </param>
    /// <returns><see langword="true"/> when <paramref name="offerJson"/> parses to a valid offer.</returns>
    internal static bool TryParse(string offerJson, out CredentialOffer? offer, out string? violatedRule)
    {
        offer = null;
        violatedRule = null;

        if(string.IsNullOrEmpty(offerJson))
        {
            violatedRule = "The Credential Offer JSON is empty.";

            return false;
        }

        ReadOnlySpan<byte> json = Encoding.UTF8.GetBytes(offerJson);

        //RFC 8259 §4 uniqueness posture applied to a Credential Offer: a repeated "credential_issuer"
        //would let this reader select the first occurrence — the issuer the Wallet is steered to trust —
        //while a duplicate second occurrence goes unnoticed, so the document is gated for well-formedness
        //before any member is read.
        if(!JwkJsonReader.IsWellFormedJsonDocument(json))
        {
            violatedRule = "The Credential Offer is not well-formed JSON, or contains a duplicate member name.";

            return false;
        }

        //§4.1.1 credential_issuer (REQUIRED): "The URL of the Credential Issuer ... from which the
        //Wallet is requested to obtain one or more Credentials."
        string? credentialIssuer = JwkJsonReader.ExtractStringValue(
            json, CredentialIssuerMetadataParameterNames.CredentialIssuerUtf8);
        if(string.IsNullOrEmpty(credentialIssuer))
        {
            violatedRule = "§4.1.1 credential_issuer is REQUIRED; the offer JSON carries none.";

            return false;
        }

        //§4.1.1 names the member "The URL of the Credential Issuer": a value that is no URI reference
        //at all (a scheme with no authority, for instance) is refused here as a rule, since the
        //Uri constructor would raise for it.
        if(!Uri.TryCreate(credentialIssuer, UriKind.RelativeOrAbsolute, out Uri? credentialIssuerUri))
        {
            violatedRule = "§4.1.1 credential_issuer is not a URL.";

            return false;
        }

        //§4.1.1 credential_configuration_ids (REQUIRED): "A non-empty array of unique strings."
        //The reader answers null for an absent member, a member that is no array and an array holding an entry that
        //is no string, so the member's presence tells which of the two rules the offer breaks.
        List<string>? configurationIds = JwkJsonReader.ExtractStringArrayProperty(
            json, CredentialOfferParameterNames.CredentialConfigurationIdsUtf8);
        if(configurationIds is null)
        {
            violatedRule = JwkJsonReader.ContainsKey(json, CredentialOfferParameterNames.CredentialConfigurationIdsUtf8)
                ? "Section 4.1.1 credential_configuration_ids is a non-empty array of unique strings; the offer carries a value that is no array of strings."
                : "Section 4.1.1 credential_configuration_ids is a REQUIRED non-empty array; the offer JSON carries none.";

            return false;
        }

        //The one rule the composer raises from: non-empty, every entry a non-empty string, none repeated.
        violatedRule = FindCredentialConfigurationIdsViolation(configurationIds);
        if(violatedRule is not null)
        {
            return false;
        }

        //Section 4.1.1 grants (OPTIONAL): "Object indicating to the Wallet the Grant Types the Credential
        //Issuer's Authorization Server is prepared to process for this Credential Offer." Absent when the
        //offer leaves the Wallet to determine grant types from the issuer metadata; a present member that
        //is no object breaks the rule and is never read as absent.
        if(!TryReadOptionalObject(json, CredentialOfferParameterNames.GrantsUtf8, out string? grantsJson))
        {
            violatedRule = "Section 4.1.1 grants is an Object indicating to the Wallet the Grant Types the Credential "
                + "Issuer's Authorization Server is prepared to process; the offer carries a grants member that is no object.";

            return false;
        }

        PreAuthorizedCodeOfferGrant? preAuthorizedCodeGrant = null;
        AuthorizationCodeOfferGrant? authorizationCodeGrant = null;
        if(grantsJson is not null)
        {
            preAuthorizedCodeGrant = ParsePreAuthorizedCodeGrant(grantsJson, out violatedRule);
            if(violatedRule is not null)
            {
                return false;
            }

            authorizationCodeGrant = ParseAuthorizationCodeGrant(grantsJson, out violatedRule);
            if(violatedRule is not null)
            {
                return false;
            }
        }

        offer = new CredentialOffer
        {
            CredentialIssuer = credentialIssuerUri,
            CredentialConfigurationIds = configurationIds,
            PreAuthorizedCodeGrant = preAuthorizedCodeGrant,
            AuthorizationCodeGrant = authorizationCodeGrant
        };

        return true;
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


    /// <summary>
    /// Parses the Section 4.1.1 <c>urn:ietf:params:oauth:grant-type:pre-authorized_code</c> grant
    /// block out of the grants object, or answers <see langword="null"/> when the offer advertises no
    /// Pre-Authorized Code grant. A grant value that is no object, a grant block without its REQUIRED
    /// <c>pre-authorized_code</c>, a <c>tx_code</c> that violates its rule, or an
    /// <c>authorization_server</c> that is no string is reported through
    /// <paramref name="violatedRule"/>, so <see cref="FromJson"/> (which raises the rule) and a parse of
    /// remote input (which answers it) share this one body. Section 4.1.1: "Every grant is represented
    /// by a name/value pair. The name is the Grant Type identifier; the value is an object that contains
    /// parameters" and "authorization_server: OPTIONAL string that the Wallet can use to identify the
    /// Authorization Server to use with this grant type"; a present member of another JSON type is
    /// refused, never read as absent.
    /// </summary>
    /// <param name="grantsJson">The Section 4.1.1 <c>grants</c> object.</param>
    /// <param name="violatedRule">The violated rule, or <see langword="null"/> when the block is valid or absent.</param>
    /// <returns>The parsed grant, or <see langword="null"/> when none is advertised or a rule is violated.</returns>
    private static PreAuthorizedCodeOfferGrant? ParsePreAuthorizedCodeGrant(string grantsJson, out string? violatedRule)
    {
        violatedRule = null;

        ReadOnlySpan<byte> grants = Encoding.UTF8.GetBytes(grantsJson);
        if(!TryReadOptionalObject(grants, WellKnownGrantTypes.PreAuthorizedCodeUtf8, out string? grantJson))
        {
            violatedRule = "Section 4.1.1 the value of each grants member is an object that contains the parameters "
                + "of its Grant Type; the offer carries the urn:ietf:params:oauth:grant-type:pre-authorized_code grant "
                + "as a value that is no object.";

            return null;
        }

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
            violatedRule = "§4.1.1 the pre-authorized_code grant is present but carries no REQUIRED "
                + "pre-authorized_code.";

            return null;
        }

        //§4.1.1: tx_code is an "Object indicating that a Transaction Code is required if present,
        //even if empty." Its mere presence — independent of its hint members — signals the
        //requirement, so the model carries a non-null TxCode whenever the member is present.
        TxCodeRequirement? txCode = null;
        if(JwkJsonReader.ContainsKey(grant, OAuthRequestParameterNames.TxCodeUtf8))
        {
            txCode = ParseTxCode(grant, out violatedRule);
            if(violatedRule is not null)
            {
                return null;
            }
        }

        if(!TryReadOptionalString(grant, CredentialOfferParameterNames.AuthorizationServerUtf8, out string? authorizationServer))
        {
            violatedRule = AuthorizationServerViolation;

            return null;
        }

        return new PreAuthorizedCodeOfferGrant
        {
            PreAuthorizedCode = preAuthorizedCode,
            TxCode = txCode,
            AuthorizationServer = authorizationServer
        };
    }


    /// <summary>
    /// Parses the Section 4.1.1 <c>tx_code</c> object's display hints. The caller has found the member
    /// present: "tx_code: OPTIONAL. Object indicating that a Transaction Code is required if present,
    /// even if empty." An object with every hint unset yields the empty requirement, since its presence
    /// alone signals that a Transaction Code is required. A <c>tx_code</c> that is no object, an
    /// <c>input_mode</c> ("OPTIONAL. String specifying the input character set.") or a
    /// <c>description</c> ("OPTIONAL. String containing guidance for the Holder of the Wallet on how to
    /// obtain the Transaction Code") that is no string, and a <c>length</c> that is no Integer a
    /// Transaction Code can have are each a violated rule, reported through
    /// <paramref name="violatedRule"/> so <see cref="TryParse"/> answers it as a value and
    /// <see cref="FromJson"/> raises it, never an arithmetic exception out of either and never a
    /// present member read as absent.
    /// </summary>
    /// <param name="grant">The Pre-Authorized Code grant block carrying the <c>tx_code</c> member.</param>
    /// <param name="violatedRule">The violated rule, or <see langword="null"/> when the object is valid.</param>
    /// <returns>The Transaction Code requirement with whichever hints the object carried, or <see langword="null"/> when a rule is violated.</returns>
    private static TxCodeRequirement? ParseTxCode(ReadOnlySpan<byte> grant, out string? violatedRule)
    {
        violatedRule = null;

        string? txCodeJson = JwkJsonReader.ExtractObjectAsString(grant, OAuthRequestParameterNames.TxCodeUtf8);
        if(txCodeJson is null)
        {
            violatedRule = "Section 4.1.1 tx_code is an Object indicating that a Transaction Code is required if "
                + "present, even if empty; the offer carries a tx_code member that is no object.";

            return null;
        }

        ReadOnlySpan<byte> txCode = Encoding.UTF8.GetBytes(txCodeJson);
        if(!TryReadTransactionCodeLength(txCode, out int? length))
        {
            violatedRule = "Section 4.1.1 tx_code.length is an Integer specifying the length of the "
                + "Transaction Code; the offer carries a length that is no Integer from 0 to 2147483647.";

            return null;
        }

        if(!TryReadOptionalString(txCode, CredentialOfferParameterNames.InputModeUtf8, out string? inputMode))
        {
            violatedRule = "Section 4.1.1 tx_code.input_mode is a String specifying the input character set; "
                + "the offer carries an input_mode member that is no string.";

            return null;
        }

        if(!TryReadOptionalString(txCode, CredentialOfferParameterNames.DescriptionUtf8, out string? description))
        {
            violatedRule = "Section 4.1.1 tx_code.description is a String containing guidance for the Holder of the "
                + "Wallet on how to obtain the Transaction Code; the offer carries a description member that is no string.";

            return null;
        }

        return new TxCodeRequirement
        {
            InputMode = inputMode,
            Length = length,
            Description = description
        };
    }


    /// <summary>
    /// Reads the Section 4.1.1 <c>tx_code.length</c> as a bounded number. The member is "OPTIONAL.
    /// Integer specifying the length of the Transaction Code", so an absent member is no hint, an
    /// Integer from zero to <see cref="int.MaxValue"/> is the hint, and any other present value (a
    /// negative or larger number, a fraction, an exponent, a string, a literal) violates the rule.
    /// The value narrows to <see cref="int"/> only after the bound holds, so no wire value reaches a
    /// conversion that can raise.
    /// </summary>
    /// <param name="txCode">The <c>tx_code</c> object.</param>
    /// <param name="length">The length hint, or <see langword="null"/> when the member is absent or violates the rule.</param>
    /// <returns><see langword="true"/> when the member is absent or holds such an Integer; <see langword="false"/> when it violates the rule.</returns>
    private static bool TryReadTransactionCodeLength(ReadOnlySpan<byte> txCode, out int? length)
    {
        length = null;
        if(!JwkJsonReader.ContainsKey(txCode, CredentialOfferParameterNames.LengthUtf8))
        {
            return true;
        }

        bool isInRange = JwkJsonReader.TryExtractLongValue(txCode, CredentialOfferParameterNames.LengthUtf8, out long parsedLength)
            && parsedLength is >= 0 and <= int.MaxValue;
        if(isInRange)
        {
            length = (int)parsedLength;
        }

        return isInRange;
    }


    /// <summary>
    /// Parses the Section 4.1.1 <c>authorization_code</c> grant block out of the grants object, or
    /// answers <see langword="null"/> when the offer advertises no Authorization Code grant. A grant
    /// value that is no object, and an <c>issuer_state</c> ("OPTIONAL. String value created by the
    /// Credential Issuer and opaque to the Wallet") or <c>authorization_server</c> ("OPTIONAL string")
    /// that is no string, is reported through <paramref name="violatedRule"/>: a present member of
    /// another JSON type is refused, never read as absent.
    /// </summary>
    /// <param name="grantsJson">The Section 4.1.1 <c>grants</c> object.</param>
    /// <param name="violatedRule">The violated rule, or <see langword="null"/> when the block is valid or absent.</param>
    /// <returns>The parsed grant, or <see langword="null"/> when none is advertised or a rule is violated.</returns>
    private static AuthorizationCodeOfferGrant? ParseAuthorizationCodeGrant(string grantsJson, out string? violatedRule)
    {
        violatedRule = null;

        ReadOnlySpan<byte> grants = Encoding.UTF8.GetBytes(grantsJson);
        if(!TryReadOptionalObject(grants, WellKnownGrantTypes.AuthorizationCodeUtf8, out string? grantJson))
        {
            violatedRule = "Section 4.1.1 the value of each grants member is an object that contains the parameters "
                + "of its Grant Type; the offer carries the authorization_code grant as a value that is no object.";

            return null;
        }

        if(grantJson is null)
        {
            return null;
        }

        ReadOnlySpan<byte> grant = Encoding.UTF8.GetBytes(grantJson);
        if(!TryReadOptionalString(grant, CredentialOfferParameterNames.IssuerStateUtf8, out string? issuerState))
        {
            violatedRule = "Section 4.1.1 issuer_state is a String value created by the Credential Issuer and opaque "
                + "to the Wallet; the offer carries an issuer_state member that is no string.";

            return null;
        }

        if(!TryReadOptionalString(grant, CredentialOfferParameterNames.AuthorizationServerUtf8, out string? authorizationServer))
        {
            violatedRule = AuthorizationServerViolation;

            return null;
        }

        return new AuthorizationCodeOfferGrant
        {
            IssuerState = issuerState,
            AuthorizationServer = authorizationServer
        };
    }


    /// <summary>
    /// The violated rule for an <c>authorization_server</c> of either grant that is no string, written
    /// once for both grant blocks. Section 4.1.1: "authorization_server: OPTIONAL string that the Wallet
    /// can use to identify the Authorization Server to use with this grant type".
    /// </summary>
    private static string AuthorizationServerViolation { get; } =
        "Section 4.1.1 authorization_server is a string that the Wallet can use to identify the Authorization "
        + "Server to use with this grant type; the offer carries an authorization_server member that is no string.";


    /// <summary>
    /// Reads an OPTIONAL member whose definition is an object. The document has passed
    /// <see cref="JwkJsonReader.IsWellFormedJsonDocument"/>, so a present object is always sliced whole;
    /// an absent member is no value, and a present member of any other JSON type (a string, a number, an
    /// array, a literal, <c>null</c>) breaks its definition and is never read as absent.
    /// </summary>
    /// <param name="json">The object carrying the member.</param>
    /// <param name="key">The member name.</param>
    /// <param name="objectJson">The member's object text, or <see langword="null"/> when the member is absent or is no object.</param>
    /// <returns><see langword="true"/> when the member is absent or is an object; <see langword="false"/> when it is present and is no object.</returns>
    private static bool TryReadOptionalObject(ReadOnlySpan<byte> json, ReadOnlySpan<byte> key, out string? objectJson)
    {
        objectJson = JwkJsonReader.ExtractObjectAsString(json, key);

        return objectJson is not null || !JwkJsonReader.ContainsKey(json, key);
    }


    /// <summary>
    /// Reads an OPTIONAL member whose definition is a string. The document has passed
    /// <see cref="JwkJsonReader.IsWellFormedJsonDocument"/>, so a present string is always read whole;
    /// an absent member is no value, and a present member of any other JSON type (a number, an object,
    /// an array, a literal, <c>null</c>) breaks its definition and is never read as absent.
    /// </summary>
    /// <param name="json">The object carrying the member.</param>
    /// <param name="key">The member name.</param>
    /// <param name="value">The member's string value, or <see langword="null"/> when the member is absent or is no string.</param>
    /// <returns><see langword="true"/> when the member is absent or is a string; <see langword="false"/> when it is present and is no string.</returns>
    private static bool TryReadOptionalString(ReadOnlySpan<byte> json, ReadOnlySpan<byte> key, out string? value)
    {
        value = JwkJsonReader.ExtractStringValue(json, key);

        return value is not null || !JwkJsonReader.ContainsKey(json, key);
    }


    /// <summary>
    /// Pulls the <c>credential_offer</c> / <c>credential_offer_uri</c> query values out of a deep
    /// link's query string. The values are returned still URL-encoded; the caller decodes the one it
    /// uses.
    /// </summary>
    /// <param name="deepLink">The deep link, or a raw <c>credential_offer</c> value.</param>
    /// <param name="credentialOffer">The still-encoded <c>credential_offer</c> value, or <see langword="null"/>.</param>
    /// <param name="credentialOfferUri">The still-encoded <c>credential_offer_uri</c> value, or <see langword="null"/>.</param>
    /// <returns>
    /// <see langword="false"/> when <paramref name="deepLink"/> carries no <c>?</c> query at all; the
    /// caller then treats it as a raw <c>credential_offer</c> value.
    /// </returns>
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
    /// Holds the caller's own offer to the Section 4.1.1 rule on <c>credential_configuration_ids</c>
    /// before it is composed, raising the rule <see cref="FindCredentialConfigurationIdsViolation"/>
    /// states.
    /// </summary>
    /// <param name="configurationIds">The offer's configuration identifiers.</param>
    /// <exception cref="ArgumentException">Thrown when the list violates the rule <see cref="FindCredentialConfigurationIdsViolation"/> states.</exception>
    private static void ValidateCredentialConfigurationIds(IReadOnlyList<string> configurationIds)
    {
        string? violatedRule = FindCredentialConfigurationIdsViolation(configurationIds);
        if(violatedRule is not null)
        {
            throw new ArgumentException(violatedRule, nameof(configurationIds));
        }
    }


    /// <summary>
    /// The Section 4.1.1 rule on <c>credential_configuration_ids</c>, written once for the composer
    /// and the reader: "credential_configuration_ids: REQUIRED. A non-empty array of unique strings
    /// that each identify one of the keys in the name/value pairs stored in the
    /// credential_configurations_supported Credential Issuer metadata." The list is non-empty, every
    /// entry is a non-empty string (an empty string identifies no key), and no entry repeats another
    /// under ordinal comparison. <see cref="ValidateCredentialConfigurationIds"/> raises the violated
    /// rule for the caller's own offer; <see cref="TryParse"/> answers it for an offer it reads.
    /// </summary>
    /// <param name="configurationIds">The configuration identifiers, in order.</param>
    /// <returns>The violated rule, or <see langword="null"/> when the list holds it.</returns>
    private static string? FindCredentialConfigurationIdsViolation(IReadOnlyList<string> configurationIds)
    {
        if(configurationIds.Count == 0)
        {
            return "Section 4.1.1 credential_configuration_ids is a non-empty array; the offer lists none.";
        }

        HashSet<string> seen = new(StringComparer.Ordinal);
        foreach(string configurationId in configurationIds)
        {
            if(string.IsNullOrEmpty(configurationId))
            {
                return "Section 4.1.1 every credential_configuration_ids entry is a non-empty string; the offer carries an empty one.";
            }

            if(!seen.Add(configurationId))
            {
                return "Section 4.1.1 credential_configuration_ids entries are unique; the offer repeats one.";
            }
        }

        return null;
    }


    /// <summary>
    /// Section 4.1.1 <c>tx_code.description</c>: "The length of the string MUST NOT exceed 300
    /// characters." The length is counted in characters as RFC 8259 Section 1 reads a string, "a
    /// sequence of zero or more Unicode characters": each Unicode scalar value counts once, so a
    /// character outside the Basic Multilingual Plane, two UTF-16 code units, counts as one.
    /// </summary>
    /// <param name="description">The description, or <see langword="null"/> when the offer carries none.</param>
    /// <exception cref="ArgumentException">Thrown when the description holds more than <see cref="MaxTxCodeDescriptionLength"/> characters.</exception>
    private static void ValidateTxCodeDescription(string? description)
    {
        if(description is null)
        {
            return;
        }

        int characterCount = CountUnicodeScalarValues(description);
        if(characterCount > MaxTxCodeDescriptionLength)
        {
            throw new ArgumentException(
                $"Section 4.1.1 tx_code.description MUST NOT exceed {MaxTxCodeDescriptionLength} characters; "
                + $"the offer carries {characterCount}.",
                nameof(description));
        }
    }


    /// <summary>
    /// Counts the Unicode scalar values of <paramref name="value"/>: a high surrogate followed by a
    /// low surrogate is one character, and every other UTF-16 code unit, an unpaired surrogate
    /// included, is one.
    /// </summary>
    /// <param name="value">The string to count.</param>
    /// <returns>The number of characters.</returns>
    private static int CountUnicodeScalarValues(string value)
    {
        int count = 0;
        for(int i = 0; i < value.Length; ++i)
        {
            if(char.IsHighSurrogate(value[i]) && i + 1 < value.Length && char.IsLowSurrogate(value[i + 1]))
            {
                ++i;
            }

            ++count;
        }

        return count;
    }


    private static string BuildGrantsJson(CredentialOffer offer)
    {
        StringBuilder sb = JsonAppender.Rent();
        try
        {
            _ = sb.Append('{');
            bool first = true;

            if(offer.PreAuthorizedCodeGrant is PreAuthorizedCodeOfferGrant preAuthorized)
            {
                JsonAppender.AppendRawField(
                    sb, WellKnownGrantTypes.PreAuthorizedCode,
                    BuildPreAuthorizedCodeGrantJson(preAuthorized), ref first);
            }

            if(offer.AuthorizationCodeGrant is AuthorizationCodeOfferGrant authorizationCode)
            {
                JsonAppender.AppendRawField(
                    sb, WellKnownGrantTypes.AuthorizationCode,
                    BuildAuthorizationCodeGrantJson(authorizationCode), ref first);
            }

            _ = sb.Append('}');

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
            _ = sb.Append('{');
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

            _ = sb.Append('}');

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
            _ = sb.Append('{');
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

            _ = sb.Append('}');

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
            _ = sb.Append('{');
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

            _ = sb.Append('}');

            return sb.ToString();
        }
        finally
        {
            JsonAppender.Return(sb);
        }
    }
}
