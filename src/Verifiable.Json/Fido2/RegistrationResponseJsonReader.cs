using System;
using System.Buffers;
using System.Buffers.Text;
using System.Collections.Generic;
using System.Text.Json;
using Verifiable.Fido2;

namespace Verifiable.Json;

/// <summary>
/// Reader for the W3C WebAuthn Level 3 JSON serialization of a registration <c>PublicKeyCredential</c>
/// — the <c>RegistrationResponseJSON</c> document a browser's <c>PublicKeyCredential.toJSON()</c>
/// produces and a relying party server receives as the request body closing a registration ceremony.
/// </summary>
/// <remarks>
/// <para>
/// <see href="https://www.w3.org/TR/webauthn-3/#dictdef-registrationresponsejson">W3C Web
/// Authentication Level 3, section 5.1's <c>toJSON()</c> serialization — dictionary <c>RegistrationResponseJSON</c></see>:
/// required members <c>id</c> (<c>DOMString</c>), <c>rawId</c> (<c>Base64URLString</c>), <c>response</c>
/// (<see href="https://www.w3.org/TR/webauthn-3/#dictdef-authenticatorattestationresponsejson">dictionary
/// <c>AuthenticatorAttestationResponseJSON</c></see>), <c>clientExtensionResults</c>
/// (<see href="https://www.w3.org/TR/webauthn-3/#dictdef-authenticationextensionsclientoutputsjson">
/// dictionary <c>AuthenticationExtensionsClientOutputsJSON</c></see>), and <c>type</c>
/// (<c>DOMString</c>, required to be <see cref="WellKnownPublicKeyCredentialTypes.PublicKey"/> per
/// <see href="https://www.w3.org/TR/webauthn-3/#dom-publickeycredential-type-slot">section 5.1's
/// <c>[[type]]</c> internal slot</see>); optional member <c>authenticatorAttachment</c> (<c>DOMString</c>).
/// Of <c>AuthenticatorAttestationResponseJSON</c>'s members, only the required <c>clientDataJSON</c>
/// and <c>attestationObject</c> (both <c>Base64URLString</c>) are modeled — the section's own comments
/// note that <c>authenticatorData</c>, <c>transports</c>, <c>publicKey</c>, and <c>publicKeyAlgorithm</c>
/// (all but <c>publicKey</c> likewise required) are mirrors of information already recoverable by
/// decoding <c>attestationObject</c> itself
/// (<see cref="Verifiable.Cbor.Fido2.AttestationObjectCborReader.Parse"/>), so a genuine client
/// response carrying any of them is tolerated rather than rejected, and none is modeled.
/// </para>
/// <para>
/// <strong>Base64url.</strong> Every <c>Base64URLString</c> member is decoded per
/// <see href="https://www.w3.org/TR/webauthn-3/#base64url-encoding">section 3's Base64url Encoding
/// dependency</see>: RFC 4648 section 5's URL- and filename-safe alphabet, "with all trailing '='
/// characters omitted". <see cref="System.Buffers.Text.Base64Url"/> itself tolerates padding on
/// decode, so a padded value is rejected explicitly by this reader rather than silently accepted.
/// </para>
/// <para>
/// <strong>id/rawId consistency.</strong> <see href="https://www.w3.org/TR/webauthn-3/#dom-publickeycredential-identifier-slot">
/// section 5.1's <c>id</c> attribute</see> "returns the base64url encoding of the data contained in
/// the [[identifier]] internal slot", and <c>rawId</c> is that same slot's raw bytes, base64url
/// encoded by <c>toJSON()</c> — the two members are therefore always textually identical on a
/// genuine wire document. A mismatch is rejected as malformed rather than silently preferring one
/// member over the other.
/// </para>
/// <para>
/// <strong>Tolerant, not strict.</strong> Unlike <see cref="PublicKeyCredentialCreationOptionsJsonReader"/>
/// (which parses a document this library's own writer produces, a closed world), this reader parses a
/// document a browser produces — an uncontrolled vocabulary this library does not author. An
/// unrecognised member at any level is therefore skipped rather than rejected, mirroring
/// <see cref="ClientDataJsonReader"/>'s posture toward the same kind of externally-authored input.
/// </para>
/// </remarks>
public static class RegistrationResponseJsonReader
{
    /// <summary>The <c>id</c> member name.</summary>
    private const string IdMember = "id";

    /// <summary>The <c>rawId</c> member name.</summary>
    private const string RawIdMember = "rawId";

    /// <summary>The <c>response</c> member name.</summary>
    private const string ResponseMember = "response";

    /// <summary>The <c>response.clientDataJSON</c> member name.</summary>
    private const string ClientDataJsonMember = "clientDataJSON";

    /// <summary>The <c>response.attestationObject</c> member name.</summary>
    private const string AttestationObjectMember = "attestationObject";

    /// <summary>The <c>authenticatorAttachment</c> member name.</summary>
    private const string AuthenticatorAttachmentMember = "authenticatorAttachment";

    /// <summary>The <c>clientExtensionResults</c> member name.</summary>
    private const string ClientExtensionResultsMember = "clientExtensionResults";

    /// <summary>The <c>type</c> member name.</summary>
    private const string TypeMember = "type";


    /// <summary>
    /// Bounds JSON nesting depth. The deepest legal path this reader models is two levels
    /// (<c>response.clientDataJSON</c>); an extension output under <c>clientExtensionResults</c> may
    /// nest further, but its content is skipped rather than parsed, so 8 stays generous while still
    /// capping recursion depth at parse time.
    /// </summary>
    private static JsonReaderOptions ReaderOptions { get; } = new() { MaxDepth = 8 };


    /// <summary>
    /// Parses a <c>RegistrationResponseJSON</c> document into a
    /// <see cref="WebAuthnRegistrationResponseEnvelope"/>.
    /// </summary>
    /// <param name="document">The raw document bytes, exactly as received over the wire.</param>
    /// <param name="pool">The memory pool the envelope's carriers rent from.</param>
    /// <returns>The decoded envelope. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="Fido2FormatException">
    /// <paramref name="document"/> is not valid JSON, its top level is not an object, a required
    /// member is missing or has the wrong JSON type, a top-level member name repeats, <c>type</c> is
    /// not <see cref="WellKnownPublicKeyCredentialTypes.PublicKey"/>, <c>id</c> and <c>rawId</c>
    /// disagree, a <c>Base64URLString</c> member is padded or is not valid base64url, or nesting
    /// exceeds the depth bound.
    /// </exception>
    public static WebAuthnRegistrationResponseEnvelope Read(ReadOnlyMemory<byte> document, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        try
        {
            return ReadObject(document.Span, pool);
        }
        catch(Exception exception) when(exception is JsonException or FormatException or OverflowException or ArgumentOutOfRangeException)
        {
            throw new Fido2FormatException("The RegistrationResponseJSON document is not well-formed.", exception);
        }
    }


    /// <summary>
    /// Parses <paramref name="document"/> — already established to be well-formed
    /// <c>RegistrationResponseJSON</c> — into a <see cref="WebAuthnRegistrationResponseEnvelope"/>,
    /// decoding each <c>Base64URLString</c> member straight into the pooled carrier
    /// <see cref="Fido2RegistrationVerifier"/> consumes.
    /// </summary>
    private static WebAuthnRegistrationResponseEnvelope ReadObject(ReadOnlySpan<byte> document, MemoryPool<byte> pool)
    {
        Utf8JsonReader reader = new(document, ReaderOptions);
        if(!reader.Read() || reader.TokenType != JsonTokenType.StartObject)
        {
            throw new Fido2FormatException("The RegistrationResponseJSON top level MUST be a JSON object.");
        }

        HashSet<string> seenMembers = new(StringComparer.Ordinal);
        string? id = null;
        string? rawId = null;
        string? clientDataJson = null;
        string? attestationObject = null;
        bool responseSeen = false;
        string? authenticatorAttachment = null;
        bool clientExtensionResultsSeen = false;
        string? type = null;

        while(reader.Read() && reader.TokenType != JsonTokenType.EndObject)
        {
            string memberName = reader.GetString()!;
            if(!seenMembers.Add(memberName))
            {
                throw new Fido2FormatException($"The RegistrationResponseJSON member '{memberName}' is repeated.");
            }

            if(!reader.Read())
            {
                throw new Fido2FormatException($"The RegistrationResponseJSON member '{memberName}' is truncated.");
            }

            _ = memberName switch
            {
                IdMember => AssignId(ref reader, memberName, ref id),
                RawIdMember => AssignRawId(ref reader, memberName, ref rawId),
                ResponseMember => AssignResponse(ref reader, ref clientDataJson, ref attestationObject, ref responseSeen),
                AuthenticatorAttachmentMember => AssignAuthenticatorAttachment(ref reader, memberName, ref authenticatorAttachment),
                ClientExtensionResultsMember => AssignClientExtensionResults(ref reader, memberName, ref clientExtensionResultsSeen),
                TypeMember => AssignType(ref reader, memberName, ref type),
                _ => SkipValue(ref reader)
            };
        }

        if(reader.TokenType != JsonTokenType.EndObject)
        {
            throw new Fido2FormatException("The RegistrationResponseJSON object is not terminated.");
        }

        if(reader.Read())
        {
            throw new Fido2FormatException("The RegistrationResponseJSON document carries content trailing its closing brace.");
        }

        if(id is null)
        {
            throw new Fido2FormatException("The RegistrationResponseJSON member 'id' is required.");
        }

        if(rawId is null)
        {
            throw new Fido2FormatException("The RegistrationResponseJSON member 'rawId' is required.");
        }

        if(!responseSeen)
        {
            throw new Fido2FormatException("The RegistrationResponseJSON member 'response' is required.");
        }

        if(!clientExtensionResultsSeen)
        {
            throw new Fido2FormatException("The RegistrationResponseJSON member 'clientExtensionResults' is required.");
        }

        if(type is null)
        {
            throw new Fido2FormatException("The RegistrationResponseJSON member 'type' is required.");
        }

        if(!WellKnownPublicKeyCredentialTypes.IsPublicKey(type))
        {
            throw new Fido2FormatException($"The RegistrationResponseJSON member 'type' MUST be '{WellKnownPublicKeyCredentialTypes.PublicKey}'; got '{type}'.");
        }

        if(!string.Equals(id, rawId, StringComparison.Ordinal))
        {
            throw new Fido2FormatException("The RegistrationResponseJSON members 'id' and 'rawId' MUST encode the same credential identifier.");
        }

        CredentialId? credentialId = null;
        PooledMemory? clientDataJsonMemory = null;
        PooledMemory? attestationObjectMemory = null;
        try
        {
            credentialId = DecodeBase64Url(rawId, RawIdMember, pool, CredentialId.Create);
            clientDataJsonMemory = DecodeBase64Url(clientDataJson!, ClientDataJsonMember, pool, static (decoded, memoryPool) => PooledMemory.FromBytes(decoded, memoryPool, BufferTags.Json));
            attestationObjectMemory = DecodeBase64Url(attestationObject!, AttestationObjectMember, pool, static (decoded, memoryPool) => PooledMemory.FromBytes(decoded, memoryPool, Fido2BufferTags.AttestationObjectPayload));

            return new WebAuthnRegistrationResponseEnvelope(credentialId, clientDataJsonMemory, attestationObjectMemory, authenticatorAttachment);
        }
        catch
        {
            credentialId?.Dispose();
            clientDataJsonMemory?.Dispose();
            attestationObjectMemory?.Dispose();
            throw;
        }

        //Assigns the decoded 'id' value to id.
        static bool AssignId(ref Utf8JsonReader reader, string memberName, ref string? id)
        {
            id = ReadRequiredString(ref reader, memberName);

            return true;
        }

        //Assigns the decoded 'rawId' value to rawId.
        static bool AssignRawId(ref Utf8JsonReader reader, string memberName, ref string? rawId)
        {
            rawId = ReadRequiredString(ref reader, memberName);

            return true;
        }

        //Assigns the decoded 'response' object's members to clientDataJson and attestationObject and
        //marks the member seen.
        static bool AssignResponse(ref Utf8JsonReader reader, ref string? clientDataJson, ref string? attestationObject, ref bool responseSeen)
        {
            (clientDataJson, attestationObject) = ReadAttestationResponse(ref reader);
            responseSeen = true;

            return true;
        }

        //Assigns the decoded 'authenticatorAttachment' value to authenticatorAttachment.
        static bool AssignAuthenticatorAttachment(ref Utf8JsonReader reader, string memberName, ref string? authenticatorAttachment)
        {
            authenticatorAttachment = ReadRequiredString(ref reader, memberName);

            return true;
        }

        //Requires and skips the 'clientExtensionResults' object and marks the member seen.
        static bool AssignClientExtensionResults(ref Utf8JsonReader reader, string memberName, ref bool clientExtensionResultsSeen)
        {
            RequireObjectAndSkipMembers(ref reader, memberName);
            clientExtensionResultsSeen = true;

            return true;
        }

        //Assigns the decoded 'type' value to type.
        static bool AssignType(ref Utf8JsonReader reader, string memberName, ref string? type)
        {
            type = ReadRequiredString(ref reader, memberName);

            return true;
        }

        //Skips an unrecognised member's value.
        static bool SkipValue(ref Utf8JsonReader reader)
        {
            reader.Skip();

            return true;
        }
    }


    /// <summary>
    /// Reads the <c>response</c> member's <c>AuthenticatorAttestationResponseJSON</c> object,
    /// returning its two modeled members' raw base64url text (see the type-level remarks for why
    /// <c>transports</c>/<c>publicKey</c>/<c>publicKeyAlgorithm</c> are tolerated but not modeled).
    /// </summary>
    private static (string ClientDataJson, string AttestationObject) ReadAttestationResponse(ref Utf8JsonReader reader)
    {
        if(reader.TokenType != JsonTokenType.StartObject)
        {
            throw new Fido2FormatException("The RegistrationResponseJSON member 'response' MUST be a JSON object.");
        }

        HashSet<string> seenMembers = new(StringComparer.Ordinal);
        string? clientDataJson = null;
        string? attestationObject = null;

        while(reader.Read() && reader.TokenType != JsonTokenType.EndObject)
        {
            string memberName = reader.GetString()!;
            if(!seenMembers.Add(memberName))
            {
                throw new Fido2FormatException($"The 'response' member '{memberName}' is repeated.");
            }

            if(!reader.Read())
            {
                throw new Fido2FormatException($"The 'response' member '{memberName}' is truncated.");
            }

            _ = memberName switch
            {
                ClientDataJsonMember => AssignClientDataJson(ref reader, memberName, ref clientDataJson),
                AttestationObjectMember => AssignAttestationObject(ref reader, memberName, ref attestationObject),
                _ => SkipValue(ref reader)
            };
        }

        if(reader.TokenType != JsonTokenType.EndObject)
        {
            throw new Fido2FormatException("The 'response' object is not terminated.");
        }

        if(clientDataJson is null)
        {
            throw new Fido2FormatException("The 'response' member 'clientDataJSON' is required.");
        }

        if(attestationObject is null)
        {
            throw new Fido2FormatException("The 'response' member 'attestationObject' is required.");
        }

        return (clientDataJson, attestationObject);

        //Assigns the decoded 'clientDataJSON' value to clientDataJson.
        static bool AssignClientDataJson(ref Utf8JsonReader reader, string memberName, ref string? clientDataJson)
        {
            clientDataJson = ReadRequiredString(ref reader, memberName);

            return true;
        }

        //Assigns the decoded 'attestationObject' value to attestationObject.
        static bool AssignAttestationObject(ref Utf8JsonReader reader, string memberName, ref string? attestationObject)
        {
            attestationObject = ReadRequiredString(ref reader, memberName);

            return true;
        }

        //Skips an unrecognised member's value.
        static bool SkipValue(ref Utf8JsonReader reader)
        {
            reader.Skip();

            return true;
        }
    }


    /// <summary>
    /// Requires <paramref name="memberName"/>'s value to be a JSON object and discards its contents
    /// unread — <c>AuthenticationExtensionsClientOutputsJSON</c> currently defines no members (see the
    /// type-level remarks) and this wave's ceremony orchestration consumes none of its IANA-registered
    /// extension-specific entries.
    /// </summary>
    private static void RequireObjectAndSkipMembers(ref Utf8JsonReader reader, string memberName)
    {
        if(reader.TokenType != JsonTokenType.StartObject)
        {
            throw new Fido2FormatException($"The RegistrationResponseJSON member '{memberName}' MUST be a JSON object.");
        }

        while(reader.Read() && reader.TokenType != JsonTokenType.EndObject)
        {
            reader.Skip();
        }

        if(reader.TokenType != JsonTokenType.EndObject)
        {
            throw new Fido2FormatException($"The RegistrationResponseJSON member '{memberName}' object is not terminated.");
        }
    }


    /// <summary>Reads the current token as a required JSON string, rejecting any other token type.</summary>
    private static string ReadRequiredString(ref Utf8JsonReader reader, string memberName)
    {
        if(reader.TokenType != JsonTokenType.String)
        {
            throw new Fido2FormatException($"The member '{memberName}' MUST be a string.");
        }

        return reader.GetString()!;
    }


    /// <summary>
    /// Builds a <typeparamref name="TResult"/> carrier from a member's decoded bytes.
    /// </summary>
    /// <param name="decoded">The member's decoded bytes, valid only for the call's duration.</param>
    /// <param name="pool">The memory pool the resulting carrier rents from.</param>
    private delegate TResult DecodedBase64UrlFactory<TResult>(ReadOnlySpan<byte> decoded, MemoryPool<byte> pool);


    /// <summary>
    /// Decodes a <c>Base64URLString</c> member — rejecting padding explicitly since
    /// <see cref="Base64Url.TryDecodeFromChars(ReadOnlySpan{char}, Span{byte}, out int)"/> tolerates
    /// it on decode where the wire format (see the type-level remarks) does not permit it — through an
    /// <see cref="ArrayPool{T}"/>-rented scratch buffer, handing the decoded span to
    /// <paramref name="factory"/> so it lands directly in the caller's pool-backed wire carrier rather
    /// than a standalone heap array.
    /// </summary>
    private static TResult DecodeBase64Url<TResult>(string encoded, string memberName, MemoryPool<byte> pool, DecodedBase64UrlFactory<TResult> factory)
    {
        if(encoded.Contains('=', StringComparison.Ordinal))
        {
            throw new Fido2FormatException($"The member '{memberName}' MUST be base64url without padding.");
        }

        byte[] rented = ArrayPool<byte>.Shared.Rent(Base64Url.GetMaxDecodedLength(encoded.Length));
        try
        {
            if(!Base64Url.TryDecodeFromChars(encoded, rented, out int bytesWritten))
            {
                throw new Fido2FormatException($"The member '{memberName}' is not valid base64url.");
            }

            return factory(rented.AsSpan(0, bytesWritten), pool);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rented, clearArray: true);
        }
    }
}
