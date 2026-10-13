using Verifiable.JCose;

namespace Verifiable.OAuth.Oid4Vci;

/// <summary>
/// The span reader of a Token Response's RFC 9396 <c>authorization_details</c> member on UTF-8
/// bytes: it answers the granted <c>openid_credential</c> authorizations as
/// <see cref="GrantedCredentialAuthorization"/> values, in the order the response lists them, or
/// that the member is malformed. Both wallet paths read through it, the Pre-Authorized Code wallet
/// (<see cref="Wallet.Oid4VciWalletClient"/>) and the default Token Response parser of the
/// authorization-code client (<see cref="OAuthResponseParsers.ParseTokenResponse"/>), so one rule
/// decides what a grant is.
/// </summary>
/// <remarks>
/// <para>
/// The member is fixed-shape wire JSON: an <c>openid_credential</c> entry is read for its
/// <c>type</c>, <c>credential_configuration_id</c> and <c>credential_identifiers</c>, and every
/// other data field of the entry is ignored, as is every entry whose <c>type</c> is a string other
/// than <c>openid_credential</c>. The whole array is validated before a grant is answered: an empty
/// array, a member that is not an array, an entry that is not an object, an entry whose
/// <c>type</c> is absent or not a JSON string, or an <c>openid_credential</c> entry without its
/// configuration, with a <c>credential_configuration_id</c> that is empty or white space (which
/// names no Credential Configuration), without a non-empty <c>credential_identifiers</c>, or listing
/// an identifier that is empty or white space (which names no Credential Dataset), makes the member
/// malformed wherever it stands. An identifier listed twice in one entry is read as listed: the
/// entry is accepted with its identifiers in their order, repetitions included. The caller holds the
/// document to <see cref="JwkJsonReader.IsWellFormedJsonDocument"/> first.
/// </para>
/// <para>
/// Every member, the <c>authorization_details</c> member itself included, is found by the text its name
/// spells with its escapes decoded, and the member's value is read at the offset
/// <see cref="JwkJsonReader.IndexOfValue"/> answers, since an escaped spelling makes the raw name longer
/// than the text it spells.
/// <see href="https://www.rfc-editor.org/rfc/rfc8259#section-7">RFC 8259 Section 7</see>:
/// "Any character may be escaped."
/// <see href="https://www.rfc-editor.org/rfc/rfc8259#section-8.3">RFC 8259 Section 8.3</see>:
/// "Implementations that transform the textual representation into sequences of Unicode code units and
/// then perform the comparison numerically, code unit by code unit, are interoperable in the sense that
/// implementations will agree in all cases on equality or inequality of two strings."
/// </para>
/// <para>
/// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-6.2">OID4VCI 1.0 Section 6.2</see>:
/// "It is a non-empty array of objects, as defined in Section 7 of [RFC9396]." And:
/// "credential_identifiers: REQUIRED. A non-empty array of strings, each uniquely identifying a
/// Credential Dataset that can be issued using the Access Token returned in this response. Each of
/// these Credential Datasets corresponds to the Credential Configuration referenced in the
/// credential_configuration_id parameter. The Wallet MUST use these identifiers together with an
/// Access Token in subsequent Credential Requests." And: "The Wallet MUST ignore any unrecognized
/// parameters in the Token Response." And: "The Wallet MUST ignore any unrecognized data fields in
/// the authorization_details present in the Token Response."
/// </para>
/// <para>
/// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-5.1.1">OID4VCI 1.0 Section 5.1.1</see>:
/// "type: REQUIRED. String that determines the authorization details type. It MUST be set to
/// openid_credential for the purpose of this specification." And: "credential_configuration_id:
/// REQUIRED. String specifying a unique identifier of the Credential being described in the
/// credential_configurations_supported map in the Credential Issuer Metadata as defined in Section
/// 12.2.4."
/// </para>
/// <para>
/// <see href="https://www.rfc-editor.org/rfc/rfc9396#section-2">RFC 9396 Section 2</see>:
/// "type: An identifier for the authorization details type as a string. The value of the type
/// field determines the allowable contents of the object that contains it. The value is unique for
/// the described API in the context of the AS. This field is REQUIRED." And: "An
/// authorization_details array MAY contain multiple entries of the same type."
/// </para>
/// </remarks>
internal static class GrantedCredentialAuthorizationReader
{
    /// <summary>
    /// Reads the <c>openid_credential</c> authorizations a Token Response's
    /// <c>authorization_details</c> member grants.
    /// </summary>
    /// <param name="tokenJson">The Token Response body, a document <see cref="JwkJsonReader.IsWellFormedJsonDocument"/> accepted.</param>
    /// <param name="grantedAuthorizations">
    /// The granted authorizations in the order the response lists them; empty when the member is
    /// absent, holds no <c>openid_credential</c> entry, or is malformed.
    /// </param>
    /// <returns><see langword="true"/> when the member is absent or well-formed; <see langword="false"/> when it is malformed.</returns>
    internal static bool TryRead(
        ReadOnlySpan<byte> tokenJson, out IReadOnlyList<GrantedCredentialAuthorization> grantedAuthorizations)
    {
        grantedAuthorizations = [];

        //The member is found by the text its name spells, an escaped spelling included, and read at the
        //offset of its value the reader answers, since an escape makes the raw name longer than the text
        //it spells.
        int position = JwkJsonReader.IndexOfValue(tokenJson, OAuthRequestParameterNames.AuthorizationDetailsUtf8);
        if(position < 0)
        {
            return true;
        }

        if(position >= tokenJson.Length || tokenJson[position] != (byte)'[')
        {
            return false;
        }

        bool hasEntry = false;
        List<GrantedCredentialAuthorization>? granted = null;
        position++;
        while(true)
        {
            while(position < tokenJson.Length && IsArraySeparator(tokenJson[position]))
            {
                position++;
            }

            if(position >= tokenJson.Length)
            {
                return false;
            }

            if(tokenJson[position] == (byte)']')
            {
                grantedAuthorizations = (IReadOnlyList<GrantedCredentialAuthorization>?)granted ?? [];

                //Section 6.2: the member is a non-empty array, so an array that closes without an
                //entry is malformed rather than an absence of details.
                return hasEntry;
            }

            int objectEnd = tokenJson[position] == (byte)'{' ? FindObjectEnd(tokenJson, position) : -1;
            if(objectEnd < 0)
            {
                return false;
            }

            ReadOnlySpan<byte> detail = tokenJson[position..objectEnd];
            position = objectEnd;
            hasEntry = true;

            //RFC 9396 Section 2: every entry carries type as a string. The reader answers null for a
            //type that is absent or not a JSON string (a number, null, an object or an array), which
            //makes the member malformed wherever the entry stands; a string of another type is an
            //entry for another API and is skipped.
            string? type = JwkJsonReader.ExtractStringValue(detail, AuthorizationDetailsParameterNames.TypeUtf8);
            if(type is null)
            {
                return false;
            }

            if(!string.Equals(type, AuthorizationDetailsTypeValues.OpenIdCredential, StringComparison.Ordinal))
            {
                continue;
            }

            string? configurationId = JwkJsonReader.ExtractStringValue(
                detail, Oid4VciCredentialParameterNames.CredentialConfigurationIdUtf8);
            List<string>? identifiers = JwkJsonReader.ExtractStringArrayProperty(
                detail, Oid4VciCredentialParameterNames.CredentialIdentifiersUtf8);
            if(string.IsNullOrWhiteSpace(configurationId)
                || identifiers is not { Count: > 0 }
                || identifiers.Exists(string.IsNullOrWhiteSpace))
            {
                return false;
            }

            granted ??= [];
            granted.Add(new GrantedCredentialAuthorization
            {
                CredentialConfigurationId = configurationId,
                CredentialIdentifiers = identifiers
            });
        }
    }


    /// <summary>Whether <paramref name="value"/> is JSON whitespace or the comma between array elements.</summary>
    /// <param name="value">The byte read between array elements.</param>
    /// <returns><see langword="true"/> for a space, tab, carriage return, line feed or comma.</returns>
    private static bool IsArraySeparator(byte value) =>
        value is (byte)' ' or (byte)'\t' or (byte)'\r' or (byte)'\n' or (byte)',';


    /// <summary>
    /// Finds the end of the JSON object starting at <paramref name="start"/>: the index after its
    /// closing brace, counting nested objects and arrays and skipping string contents, escapes
    /// included, so a brace inside a string does not end the object.
    /// </summary>
    /// <param name="json">The JSON text.</param>
    /// <param name="start">The index of the object's opening brace.</param>
    /// <returns>The index after the closing brace, or -1 when the object does not close.</returns>
    private static int FindObjectEnd(ReadOnlySpan<byte> json, int start)
    {
        int depth = 0;
        for(int position = start; position < json.Length; position++)
        {
            byte current = json[position];
            if(current == (byte)'"')
            {
                position++;
                while(position < json.Length && json[position] != (byte)'"')
                {
                    if(json[position] == (byte)'\\')
                    {
                        position++;
                    }

                    position++;
                }

                continue;
            }

            depth += current switch
            {
                (byte)'{' or (byte)'[' => 1,
                (byte)'}' or (byte)']' => -1,
                _ => 0
            };

            if(depth == 0)
            {
                return position + 1;
            }
        }

        return -1;
    }
}
