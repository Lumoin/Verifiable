namespace Verifiable.Fido2;

/// <summary>
/// Buffer-content discriminators and pre-built <see cref="Tag"/> instances for the FIDO2/WebAuthn
/// byte artifacts this layer owns.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="Verifiable.Foundation.BufferTags"/> carries only the format-neutral encodings (JSON,
/// CBOR) and leaves domain-specific buffer roles to the format owner, reached through the
/// <see cref="BufferKind.Create(int)"/> seam (codes at or above 1000) — mirrors
/// <see cref="Verifiable.JCose.JoseBufferTags"/> exactly.
/// </para>
/// </remarks>
/// <seealso cref="Tag"/>
/// <seealso cref="BufferKind"/>
/// <seealso cref="Verifiable.Foundation.BufferTags"/>
public static class Fido2BufferTags
{
    /// <summary>
    /// Buffer kind for the <c>largeBlob</c> extension's decoded <c>blob</c> payload bytes — a
    /// <see cref="System.Text.Json"/>-allocated array wrapped rather than copied, per
    /// <see cref="TaggedMemory{T}"/>'s own convention.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-large-blob-extension">W3C Web
    /// Authentication Level 3, section 10.1.5: Large blob storage extension (largeBlob)</see>.
    /// </remarks>
    public static BufferKind LargeBlobKind { get; } = BufferKind.Create(1010);

    /// <summary>
    /// Tag for the <c>largeBlob</c> extension's decoded <c>blob</c> payload bytes, carrying
    /// <see cref="LargeBlobKind"/>.
    /// </summary>
    public static Tag LargeBlob { get; } = Tag.Create(LargeBlobKind);

    /// <summary>
    /// Buffer kind for a CTAP2-canonical CBOR-encoded <c>authenticatorGetInfo</c> response payload —
    /// the bytes an <see cref="Ctap.EncodeCtapGetInfoResponseDelegate"/> implementation produces,
    /// before the CTAP2 status byte prefixes it into a full response envelope.
    /// </summary>
    public static BufferKind CtapGetInfoResponseKind { get; } = BufferKind.Create(1011);

    /// <summary>
    /// Tag for a CTAP2-canonical CBOR-encoded <c>authenticatorGetInfo</c> response payload, carrying
    /// <see cref="CtapGetInfoResponseKind"/>.
    /// </summary>
    public static Tag CtapGetInfoResponsePayload { get; } = Tag.Create(CtapGetInfoResponseKind);

    /// <summary>
    /// Buffer kind for a complete CTAP2 response envelope (a status byte followed by CBOR-encoded
    /// response data) that <see cref="Ctap.Ctap2TransceiveDelegate"/> exchanges, transport-agnostic —
    /// the authenticator-API-layer counterpart of <c>Verifiable.Apdu.Ctap.CtapBufferKinds.CtapEnvelope</c>.
    /// </summary>
    public static BufferKind CtapResponseEnvelopeKind { get; } = BufferKind.Create(1012);

    /// <summary>
    /// Tag for a complete CTAP2 response envelope, carrying <see cref="CtapResponseEnvelopeKind"/>.
    /// </summary>
    public static Tag CtapResponseEnvelope { get; } = Tag.Create(CtapResponseEnvelopeKind);

    /// <summary>
    /// Buffer kind for a CTAP2-canonical CBOR-encoded <c>authenticatorMakeCredential</c> request
    /// parameter map — the bytes a <see cref="Ctap.EncodeCtapMakeCredentialRequestDelegate"/>
    /// implementation produces, before the command byte prefixes it into a full request envelope.
    /// </summary>
    public static BufferKind CtapMakeCredentialRequestKind { get; } = BufferKind.Create(1013);

    /// <summary>
    /// Tag for a CTAP2-canonical CBOR-encoded <c>authenticatorMakeCredential</c> request parameter map,
    /// carrying <see cref="CtapMakeCredentialRequestKind"/>.
    /// </summary>
    public static Tag CtapMakeCredentialRequestPayload { get; } = Tag.Create(CtapMakeCredentialRequestKind);

    /// <summary>
    /// Buffer kind for a CTAP2-canonical CBOR-encoded <c>authenticatorMakeCredential</c> response
    /// payload — the bytes a <see cref="Ctap.EncodeCtapMakeCredentialResponseDelegate"/> implementation
    /// produces, before the CTAP2 status byte prefixes it into a full response envelope.
    /// </summary>
    public static BufferKind CtapMakeCredentialResponseKind { get; } = BufferKind.Create(1014);

    /// <summary>
    /// Tag for a CTAP2-canonical CBOR-encoded <c>authenticatorMakeCredential</c> response payload,
    /// carrying <see cref="CtapMakeCredentialResponseKind"/>.
    /// </summary>
    public static Tag CtapMakeCredentialResponsePayload { get; } = Tag.Create(CtapMakeCredentialResponseKind);

    /// <summary>
    /// Buffer kind for a <see cref="AuthenticatorDataWriter.Write"/>-produced <c>authData</c> wire
    /// payload — a freshly allocated array wrapped rather than copied.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data">W3C Web Authentication
    /// Level 3, section 6.1: Authenticator Data.</see>
    /// </remarks>
    public static BufferKind AuthenticatorDataKind { get; } = BufferKind.Create(1015);

    /// <summary>
    /// Tag for an <c>authData</c> wire payload, carrying <see cref="AuthenticatorDataKind"/>.
    /// </summary>
    public static Tag AuthenticatorDataPayload { get; } = Tag.Create(AuthenticatorDataKind);

    /// <summary>
    /// Buffer kind for a CTAP2-canonical CBOR-encoded <c>credentialPublicKey</c> COSE_Key payload — the
    /// bytes a <c>Verifiable.Cbor.Fido2.CredentialPublicKeyCborWriter</c> implementation produces.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-attested-credential-data">W3C Web
    /// Authentication Level 3, section 6.5.1: Attested Credential Data.</see>
    /// </remarks>
    public static BufferKind CredentialPublicKeyKind { get; } = BufferKind.Create(1016);

    /// <summary>
    /// Tag for a CTAP2-canonical CBOR-encoded <c>credentialPublicKey</c> payload, carrying
    /// <see cref="CredentialPublicKeyKind"/>.
    /// </summary>
    public static Tag CredentialPublicKeyPayload { get; } = Tag.Create(CredentialPublicKeyKind);

    /// <summary>
    /// Buffer kind for a CTAP2-canonical CBOR-encoded <c>attestationObject</c> payload — the bytes a
    /// <c>Verifiable.Cbor.Fido2.AttestationObjectCborWriter</c> implementation produces.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-generating-an-attestation-object">W3C Web
    /// Authentication Level 3, section 6.5.4: Generating an Attestation Object.</see>
    /// </remarks>
    public static BufferKind AttestationObjectKind { get; } = BufferKind.Create(1017);

    /// <summary>
    /// Tag for a CTAP2-canonical CBOR-encoded <c>attestationObject</c> payload, carrying
    /// <see cref="AttestationObjectKind"/>.
    /// </summary>
    public static Tag AttestationObjectPayload { get; } = Tag.Create(AttestationObjectKind);

    /// <summary>
    /// Buffer kind for a CTAP2-canonical CBOR-encoded <c>authenticatorGetAssertion</c> request
    /// parameter map — the bytes a <see cref="Ctap.EncodeCtapGetAssertionRequestDelegate"/>
    /// implementation produces, before the command byte prefixes it into a full request envelope.
    /// </summary>
    public static BufferKind CtapGetAssertionRequestKind { get; } = BufferKind.Create(1018);

    /// <summary>
    /// Tag for a CTAP2-canonical CBOR-encoded <c>authenticatorGetAssertion</c> request parameter map,
    /// carrying <see cref="CtapGetAssertionRequestKind"/>.
    /// </summary>
    public static Tag CtapGetAssertionRequestPayload { get; } = Tag.Create(CtapGetAssertionRequestKind);

    /// <summary>
    /// Buffer kind for a CTAP2-canonical CBOR-encoded <c>authenticatorGetAssertion</c> response
    /// payload — the bytes a <see cref="Ctap.EncodeCtapGetAssertionResponseDelegate"/> implementation
    /// produces, before the CTAP2 status byte prefixes it into a full response envelope.
    /// </summary>
    public static BufferKind CtapGetAssertionResponseKind { get; } = BufferKind.Create(1019);

    /// <summary>
    /// Tag for a CTAP2-canonical CBOR-encoded <c>authenticatorGetAssertion</c> response payload,
    /// carrying <see cref="CtapGetAssertionResponseKind"/>.
    /// </summary>
    public static Tag CtapGetAssertionResponsePayload { get; } = Tag.Create(CtapGetAssertionResponseKind);

    /// <summary>
    /// Buffer kind for a CTAP2-canonical CBOR-encoded self-attestation <c>packed</c> attestation
    /// statement (<c>attStmt</c>) payload — the bytes a
    /// <c>Verifiable.Cbor.Fido2.PackedAttestationStatementCborWriter</c> implementation produces.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation">W3C Web Authentication
    /// Level 3, section 8.2: Packed Attestation Statement Format.</see>
    /// </remarks>
    public static BufferKind PackedAttestationStatementKind { get; } = BufferKind.Create(1020);

    /// <summary>
    /// Tag for a CTAP2-canonical CBOR-encoded self-attestation <c>packed</c> attestation statement
    /// payload, carrying <see cref="PackedAttestationStatementKind"/>.
    /// </summary>
    public static Tag PackedAttestationStatementPayload { get; } = Tag.Create(PackedAttestationStatementKind);

    /// <summary>
    /// Buffer kind for a CTAP2-canonical CBOR-encoded <c>authenticatorClientPIN</c> request parameter
    /// map — the bytes a <see cref="Ctap.EncodeCtapClientPinRequestDelegate"/> implementation
    /// produces, before the command byte prefixes it into a full request envelope.
    /// </summary>
    public static BufferKind CtapClientPinRequestKind { get; } = BufferKind.Create(1021);

    /// <summary>
    /// Tag for a CTAP2-canonical CBOR-encoded <c>authenticatorClientPIN</c> request parameter map,
    /// carrying <see cref="CtapClientPinRequestKind"/>.
    /// </summary>
    public static Tag CtapClientPinRequestPayload { get; } = Tag.Create(CtapClientPinRequestKind);

    /// <summary>
    /// Buffer kind for a CTAP2-canonical CBOR-encoded <c>authenticatorClientPIN</c> response
    /// payload — the bytes a <see cref="Ctap.EncodeCtapClientPinResponseDelegate"/> implementation
    /// produces, before the CTAP2 status byte prefixes it into a full response envelope.
    /// </summary>
    public static BufferKind CtapClientPinResponseKind { get; } = BufferKind.Create(1022);

    /// <summary>
    /// Tag for a CTAP2-canonical CBOR-encoded <c>authenticatorClientPIN</c> response payload, carrying
    /// <see cref="CtapClientPinResponseKind"/>.
    /// </summary>
    public static Tag CtapClientPinResponsePayload { get; } = Tag.Create(CtapClientPinResponseKind);

    /// <summary>
    /// Buffer kind for a CTAP2-canonical CBOR-encoded <c>authenticatorConfig</c> request parameter
    /// map — the bytes a <see cref="Ctap.EncodeCtapAuthenticatorConfigRequestDelegate"/> implementation
    /// produces, before the command byte prefixes it into a full request envelope.
    /// </summary>
    public static BufferKind CtapAuthenticatorConfigRequestKind { get; } = BufferKind.Create(1023);

    /// <summary>
    /// Tag for a CTAP2-canonical CBOR-encoded <c>authenticatorConfig</c> request parameter map,
    /// carrying <see cref="CtapAuthenticatorConfigRequestKind"/>.
    /// </summary>
    public static Tag CtapAuthenticatorConfigRequestPayload { get; } = Tag.Create(CtapAuthenticatorConfigRequestKind);

    /// <summary>
    /// Buffer kind for a CTAP2-canonical CBOR-encoded <c>authenticatorConfig</c> <c>subCommandParams</c>
    /// map — the bytes <c>Verifiable.Cbor.Ctap.CtapAuthenticatorConfigRequestCborWriter.WriteSubCommandParams</c>
    /// produces, both the segment embedded in the request parameter map and the segment covered
    /// byte-for-byte by the <c>authenticatorConfig</c> verify message's own <c>subCommandParams</c> span.
    /// </summary>
    public static BufferKind CtapAuthenticatorConfigSubCommandParamsKind { get; } = BufferKind.Create(1024);

    /// <summary>
    /// Tag for a CTAP2-canonical CBOR-encoded <c>authenticatorConfig</c> <c>subCommandParams</c> map,
    /// carrying <see cref="CtapAuthenticatorConfigSubCommandParamsKind"/>.
    /// </summary>
    public static Tag CtapAuthenticatorConfigSubCommandParamsPayload { get; } = Tag.Create(CtapAuthenticatorConfigSubCommandParamsKind);

    /// <summary>
    /// Buffer kind for a CTAP2-canonical CBOR-encoded <c>authenticatorCredentialManagement</c> request
    /// parameter map — the bytes a <see cref="Ctap.EncodeCtapCredentialManagementRequestDelegate"/>
    /// implementation produces, before the command byte prefixes it into a full request envelope.
    /// </summary>
    public static BufferKind CtapCredentialManagementRequestKind { get; } = BufferKind.Create(1025);

    /// <summary>
    /// Tag for a CTAP2-canonical CBOR-encoded <c>authenticatorCredentialManagement</c> request parameter
    /// map, carrying <see cref="CtapCredentialManagementRequestKind"/>.
    /// </summary>
    public static Tag CtapCredentialManagementRequestPayload { get; } = Tag.Create(CtapCredentialManagementRequestKind);

    /// <summary>
    /// Buffer kind for a CTAP2-canonical CBOR-encoded <c>authenticatorCredentialManagement</c>
    /// <c>subCommandParams</c> map — the bytes
    /// <c>Verifiable.Cbor.Ctap.CtapCredentialManagementRequestCborWriter.WriteSubCommandParams</c>
    /// produces, both the segment embedded in the request parameter map and the segment covered
    /// byte-for-byte by the credMgmt verify message's own <c>subCommandParams</c> span.
    /// </summary>
    public static BufferKind CtapCredentialManagementSubCommandParamsKind { get; } = BufferKind.Create(1026);

    /// <summary>
    /// Tag for a CTAP2-canonical CBOR-encoded <c>authenticatorCredentialManagement</c>
    /// <c>subCommandParams</c> map, carrying <see cref="CtapCredentialManagementSubCommandParamsKind"/>.
    /// </summary>
    public static Tag CtapCredentialManagementSubCommandParamsPayload { get; } = Tag.Create(CtapCredentialManagementSubCommandParamsKind);

    /// <summary>
    /// Buffer kind for a CTAP2-canonical CBOR-encoded <c>authenticatorCredentialManagement</c> response
    /// payload — the bytes a <see cref="Ctap.EncodeCtapCredentialManagementResponseDelegate"/>
    /// implementation produces, before the CTAP2 status byte prefixes it into a full response envelope.
    /// </summary>
    public static BufferKind CtapCredentialManagementResponseKind { get; } = BufferKind.Create(1027);

    /// <summary>
    /// Tag for a CTAP2-canonical CBOR-encoded <c>authenticatorCredentialManagement</c> response payload,
    /// carrying <see cref="CtapCredentialManagementResponseKind"/>.
    /// </summary>
    public static Tag CtapCredentialManagementResponsePayload { get; } = Tag.Create(CtapCredentialManagementResponseKind);

    /// <summary>
    /// Buffer kind for a CTAP2-canonical CBOR-encoded <c>authenticatorMakeCredential</c> authData
    /// <c>extensions</c> output map — the bytes
    /// <c>Verifiable.Cbor.Ctap.CtapMakeCredentialExtensionOutputsCborWriter.Write</c> produces, appended
    /// verbatim by <see cref="AuthenticatorDataWriter.Write"/> when its <c>extensions</c> parameter is
    /// non-empty.
    /// </summary>
    public static BufferKind CtapMakeCredentialExtensionOutputsKind { get; } = BufferKind.Create(1028);

    /// <summary>
    /// Tag for a CTAP2-canonical CBOR-encoded <c>authenticatorMakeCredential</c> authData
    /// <c>extensions</c> output map, carrying <see cref="CtapMakeCredentialExtensionOutputsKind"/>.
    /// </summary>
    public static Tag CtapMakeCredentialExtensionOutputsPayload { get; } = Tag.Create(CtapMakeCredentialExtensionOutputsKind);

    /// <summary>
    /// Buffer kind for a CTAP2-canonical CBOR-encoded <c>authenticatorBioEnrollment</c> request
    /// parameter map — the bytes a <see cref="Ctap.EncodeCtapBioEnrollmentRequestDelegate"/>
    /// implementation produces, before the command byte prefixes it into a full request envelope.
    /// </summary>
    public static BufferKind CtapBioEnrollmentRequestKind { get; } = BufferKind.Create(1029);

    /// <summary>
    /// Tag for a CTAP2-canonical CBOR-encoded <c>authenticatorBioEnrollment</c> request parameter map,
    /// carrying <see cref="CtapBioEnrollmentRequestKind"/>.
    /// </summary>
    public static Tag CtapBioEnrollmentRequestPayload { get; } = Tag.Create(CtapBioEnrollmentRequestKind);

    /// <summary>
    /// Buffer kind for a CTAP2-canonical CBOR-encoded <c>authenticatorBioEnrollment</c>
    /// <c>subCommandParams</c> map — the bytes
    /// <c>Verifiable.Cbor.Ctap.CtapBioEnrollmentRequestCborWriter.WriteSubCommandParams</c> produces,
    /// both the segment embedded in the request parameter map and the segment covered byte-for-byte by
    /// bioEnroll's own verify message's <c>subCommandParams</c> span.
    /// </summary>
    public static BufferKind CtapBioEnrollmentSubCommandParamsKind { get; } = BufferKind.Create(1030);

    /// <summary>
    /// Tag for a CTAP2-canonical CBOR-encoded <c>authenticatorBioEnrollment</c> <c>subCommandParams</c>
    /// map, carrying <see cref="CtapBioEnrollmentSubCommandParamsKind"/>.
    /// </summary>
    public static Tag CtapBioEnrollmentSubCommandParamsPayload { get; } = Tag.Create(CtapBioEnrollmentSubCommandParamsKind);

    /// <summary>
    /// Buffer kind for a CTAP2-canonical CBOR-encoded <c>authenticatorBioEnrollment</c> response
    /// payload — the bytes a <see cref="Ctap.EncodeCtapBioEnrollmentResponseDelegate"/> implementation
    /// produces, before the CTAP2 status byte prefixes it into a full response envelope.
    /// </summary>
    public static BufferKind CtapBioEnrollmentResponseKind { get; } = BufferKind.Create(1031);

    /// <summary>
    /// Tag for a CTAP2-canonical CBOR-encoded <c>authenticatorBioEnrollment</c> response payload,
    /// carrying <see cref="CtapBioEnrollmentResponseKind"/>.
    /// </summary>
    public static Tag CtapBioEnrollmentResponsePayload { get; } = Tag.Create(CtapBioEnrollmentResponseKind);

    /// <summary>
    /// Buffer kind for a CTAP2-canonical CBOR-encoded <c>authenticatorLargeBlobs</c> request parameter
    /// map — the bytes a <see cref="Ctap.EncodeCtapLargeBlobsRequestDelegate"/> implementation produces,
    /// before the command byte prefixes it into a full request envelope.
    /// </summary>
    public static BufferKind CtapLargeBlobsRequestKind { get; } = BufferKind.Create(1032);

    /// <summary>
    /// Tag for a CTAP2-canonical CBOR-encoded <c>authenticatorLargeBlobs</c> request parameter map,
    /// carrying <see cref="CtapLargeBlobsRequestKind"/>.
    /// </summary>
    public static Tag CtapLargeBlobsRequestPayload { get; } = Tag.Create(CtapLargeBlobsRequestKind);

    /// <summary>
    /// Buffer kind for a CTAP2-canonical CBOR-encoded <c>authenticatorLargeBlobs</c> <c>get</c> response
    /// payload — the bytes a <see cref="Ctap.EncodeCtapLargeBlobsResponseDelegate"/> implementation
    /// produces, before the CTAP2 status byte prefixes it into a full response envelope. A <c>set</c>
    /// outcome carries no response body, so no buffer of this kind is ever produced for one.
    /// </summary>
    public static BufferKind CtapLargeBlobsResponseKind { get; } = BufferKind.Create(1033);

    /// <summary>
    /// Tag for a CTAP2-canonical CBOR-encoded <c>authenticatorLargeBlobs</c> <c>get</c> response payload,
    /// carrying <see cref="CtapLargeBlobsResponseKind"/>.
    /// </summary>
    public static Tag CtapLargeBlobsResponsePayload { get; } = Tag.Create(CtapLargeBlobsResponseKind);

    /// <summary>
    /// Buffer kind for the persistent, authenticator-opaque serialized large-blob array bytes stored on
    /// <see cref="Ctap.Authenticator.Automata.CtapAuthenticatorState.SerializedLargeBlobArray"/> — the
    /// CBOR-encoded large-blob array concatenated with its trailing 16-byte truncated SHA-256 hash (CTAP
    /// 2.3 §6.10, line 7539). Distinct from <see cref="LargeBlobKind"/> (<c>1010</c>), which tags the
    /// UNRELATED §10.1.5 WebAuthn client extension's decoded blob payload — trap 11: the two domains must
    /// never share a tag.
    /// </summary>
    public static BufferKind CtapSerializedLargeBlobArrayKind { get; } = BufferKind.Create(1034);

    /// <summary>
    /// Tag for the persistent serialized large-blob array bytes, carrying
    /// <see cref="CtapSerializedLargeBlobArrayKind"/>.
    /// </summary>
    public static Tag CtapSerializedLargeBlobArrayPayload { get; } = Tag.Create(CtapSerializedLargeBlobArrayKind);

    /// <summary>
    /// Buffer kind for a CTAP2-canonical CBOR-encoded <c>authenticatorGetAssertion</c> authData
    /// <c>extensions</c> output map — the bytes
    /// <c>Verifiable.Cbor.Ctap.CtapGetAssertionExtensionOutputsCborWriter.Write</c> produces, appended
    /// verbatim by <see cref="AuthenticatorDataWriter.Write"/> when its <c>extensions</c> parameter is
    /// non-empty. Distinct from <see cref="CtapMakeCredentialExtensionOutputsKind"/>: the two commands'
    /// extensions-output maps are unrelated wire values that happen to share a writer shape.
    /// </summary>
    public static BufferKind CtapGetAssertionExtensionOutputsKind { get; } = BufferKind.Create(1035);

    /// <summary>
    /// Tag for a CTAP2-canonical CBOR-encoded <c>authenticatorGetAssertion</c> authData <c>extensions</c>
    /// output map, carrying <see cref="CtapGetAssertionExtensionOutputsKind"/>.
    /// </summary>
    public static Tag CtapGetAssertionExtensionOutputsPayload { get; } = Tag.Create(CtapGetAssertionExtensionOutputsKind);

    /// <summary>
    /// Buffer kind for a CTAP2-canonical CBOR-encoded <c>fido-u2f</c> attestation statement
    /// (<c>attStmt</c>) payload — the bytes a
    /// <c>Verifiable.Cbor.Fido2.FidoU2fAttestationStatementCborWriter</c> implementation produces.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-fido-u2f-attestation">W3C Web Authentication
    /// Level 3, section 8.6: FIDO U2F Attestation Statement Format.</see>
    /// </remarks>
    public static BufferKind FidoU2fAttestationStatementKind { get; } = BufferKind.Create(1036);

    /// <summary>
    /// Tag for a CTAP2-canonical CBOR-encoded <c>fido-u2f</c> attestation statement payload, carrying
    /// <see cref="FidoU2fAttestationStatementKind"/>.
    /// </summary>
    public static Tag FidoU2fAttestationStatementPayload { get; } = Tag.Create(FidoU2fAttestationStatementKind);

    /// <summary>
    /// Buffer kind for a CTAP2-canonical CBOR-encoded <c>android-key</c> attestation statement
    /// (<c>attStmt</c>) payload — the bytes an
    /// <c>Verifiable.Cbor.Fido2.AndroidKeyAttestationStatementCborWriter</c> implementation produces.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-android-key-attestation">W3C Web Authentication
    /// Level 3, section 8.4: Android Key Attestation Statement Format.</see>
    /// </remarks>
    public static BufferKind AndroidKeyAttestationStatementKind { get; } = BufferKind.Create(1037);

    /// <summary>
    /// Tag for a CTAP2-canonical CBOR-encoded <c>android-key</c> attestation statement payload, carrying
    /// <see cref="AndroidKeyAttestationStatementKind"/>.
    /// </summary>
    public static Tag AndroidKeyAttestationStatementPayload { get; } = Tag.Create(AndroidKeyAttestationStatementKind);
}
