using System;
using Verifiable.Core.Model.Common;

namespace Verifiable.Core.Resolvers;

/// <summary>
/// Well-known DIF DID Registration string values: the <c>didState.state</c> values, the
/// <c>didDocumentOperation</c> values, the <c>options</c> property names, and the
/// <c>signingRequest</c>/<c>signingResponse</c>/<c>decryptionRequest</c>/<c>decryptionResponse</c>
/// member names. Centralizing the wire names keeps the lifecycle model, a future HTTP/JSON binding,
/// and tests consistent.
/// </summary>
/// <remarks>
/// See <see href="https://identity.foundation/did-registration/">DIF DID Registration</see>.
/// </remarks>
public static class WellKnownDidRegistrationValues
{
    /// <summary>The <c>didState.state</c> value <c>finished</c> (the operation completed).</summary>
    public static string StateFinished { get; } = "finished";

    /// <summary>The <c>didState.state</c> value <c>failed</c> (the operation failed).</summary>
    public static string StateFailed { get; } = "failed";

    /// <summary>The <c>didState.state</c> value <c>action</c> (the client must act, e.g. sign).</summary>
    public static string StateAction { get; } = "action";

    /// <summary>The <c>didState.state</c> value <c>wait</c> (the registrar is processing asynchronously).</summary>
    public static string StateWait { get; } = "wait";

    /// <summary>The <c>didDocumentOperation</c> value <c>setDidDocument</c> (replace the document); the <c>update</c> default.</summary>
    public static string SetDidDocument { get; } = "setDidDocument";

    /// <summary>The <c>didDocumentOperation</c> value <c>addToDidDocument</c> (merge in the supplied properties).</summary>
    public static string AddToDidDocument { get; } = "addToDidDocument";

    /// <summary>The <c>didDocumentOperation</c> value <c>removeFromDidDocument</c> (remove the supplied properties).</summary>
    public static string RemoveFromDidDocument { get; } = "removeFromDidDocument";

    /// <summary>The <c>didDocumentOperation</c> extension value <c>deactivate</c>.</summary>
    public static string DeactivateOperation { get; } = "deactivate";

    /// <summary>The <c>options.clientSecretMode</c> boolean enabling client-managed secret mode.</summary>
    public static string ClientSecretModeOption { get; } = "clientSecretMode";

    /// <summary>The <c>options.storeSecrets</c> boolean enabling registrar-internal secret storage.</summary>
    public static string StoreSecretsOption { get; } = "storeSecrets";

    /// <summary>The <c>options.returnSecrets</c> boolean enabling return of generated secrets to the client.</summary>
    public static string ReturnSecretsOption { get; } = "returnSecrets";

    //did:web method-specific create options. Per the DIF spec method-specific input parameters are conveyed
    //through the options object; these are the keys the did:web builder reads when joined into the Create flow
    //(via DidRegistrationBuilders), each mapping to a WebDidBuilder.BuildAsync named parameter. The
    //universal-registrar reference driver derives the host from its configured baseUrl rather than a per-request
    //option, so these names are library-chosen and may be finalized when an HTTP binding lands.

    /// <summary>The <c>options.domain</c> value carrying the <c>did:web</c> host (e.g. <c>example.com</c>); required for a <c>did:web</c> create.</summary>
    public static string WebDomainOption { get; } = "domain";

    /// <summary>
    /// The <c>options.representation</c> value selecting the document representation
    /// (<see cref="RepresentationJsonLd"/>/<see cref="RepresentationJsonWithContext"/>/<see cref="RepresentationJsonWithoutContext"/>,
    /// mapped to <see cref="DidRepresentationType"/> by <see cref="ToDidRepresentationType"/>). Absent, the
    /// builder's JSON-LD default applies.
    /// </summary>
    public static string WebRepresentationOption { get; } = "representation";

    /// <summary>The <c>options.didCoreVersion</c> value: the DID Core context URI the <c>@context</c> array starts with (e.g. <see cref="Context.DidCore10"/>). Absent when the representation omits <c>@context</c>.</summary>
    public static string WebDidCoreVersionOption { get; } = "didCoreVersion";

    /// <summary>The <c>options.additionalContexts</c> value: a sequence of extra <c>@context</c> entries appended after the DID Core context.</summary>
    public static string WebAdditionalContextsOption { get; } = "additionalContexts";

    /// <summary>The <see cref="WebRepresentationOption"/> token for a full JSON-LD representation (<c>@context</c> required).</summary>
    public static string RepresentationJsonLd { get; } = "jsonLd";

    /// <summary>The <see cref="WebRepresentationOption"/> token for a JSON representation that still includes <c>@context</c>.</summary>
    public static string RepresentationJsonWithContext { get; } = "jsonWithContext";

    /// <summary>The <see cref="WebRepresentationOption"/> token for a plain JSON representation without <c>@context</c>.</summary>
    public static string RepresentationJsonWithoutContext { get; } = "jsonWithoutContext";

    /// <summary>The <c>secret.verificationMethod</c> member: the verification-method templates.</summary>
    public static string SecretVerificationMethod { get; } = "verificationMethod";

    /// <summary>The <c>secret.signingResponse</c> member carrying the client signatures.</summary>
    public static string SecretSigningResponse { get; } = "signingResponse";

    /// <summary>The <c>secret.decryptionResponse</c> member carrying the client decryptions.</summary>
    public static string SecretDecryptionResponse { get; } = "decryptionResponse";

    /// <summary>The <c>signingRequest</c>/<c>decryptionRequest</c> informational <c>payload</c> member (the unencoded form).</summary>
    public static string Payload { get; } = "payload";

    /// <summary>The <c>signingRequest</c> required <c>serializedPayload</c> member (base64-encoded bytes to sign).</summary>
    public static string SerializedPayload { get; } = "serializedPayload";

    /// <summary>The <c>signingResponse</c> required <c>signature</c> member (base64-encoded signature).</summary>
    public static string Signature { get; } = "signature";

    /// <summary>The <c>decryptionRequest</c> required <c>encryptedPayload</c> member (base64-encoded ciphertext).</summary>
    public static string EncryptedPayload { get; } = "encryptedPayload";

    /// <summary>The <c>decryptionResponse</c> required <c>decryptedPayload</c> member (base64-encoded plaintext).</summary>
    public static string DecryptedPayload { get; } = "decryptedPayload";

    /// <summary>The <c>kid</c> member (the key identifier) shared by signing and decryption requests/responses.</summary>
    public static string Kid { get; } = "kid";

    /// <summary>The signing <c>alg</c> member (the signature algorithm).</summary>
    public static string Alg { get; } = "alg";

    /// <summary>The decryption <c>enc</c> member (the encryption algorithm).</summary>
    public static string Enc { get; } = "enc";

    /// <summary>The <c>purpose</c> member (the verification relationship, e.g. <c>authentication</c>).</summary>
    public static string Purpose { get; } = "purpose";

    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="value"/> is one of the four standard
    /// <c>didState.state</c> values.
    /// </summary>
    /// <param name="value">The candidate state value.</param>
    public static bool IsKnownState(string? value)
    {
        return value == StateFinished
            || value == StateFailed
            || value == StateAction
            || value == StateWait;
    }

    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="value"/> is one of the standard
    /// <c>didDocumentOperation</c> values (<c>setDidDocument</c>, <c>addToDidDocument</c>,
    /// <c>removeFromDidDocument</c>, or the <c>deactivate</c> extension). Method-specific operations
    /// are not recognized here.
    /// </summary>
    /// <param name="value">The candidate operation value.</param>
    public static bool IsKnownDidDocumentOperation(string? value)
    {
        return value == SetDidDocument
            || value == AddToDidDocument
            || value == RemoveFromDidDocument
            || value == DeactivateOperation;
    }

    /// <summary>
    /// Maps a <see cref="WebRepresentationOption"/> token to a <see cref="DidRepresentationType"/>, or
    /// <see langword="null"/> when <paramref name="value"/> is <see langword="null"/> or not a recognized token.
    /// A neutral primitive: it never throws on an unknown token; the caller decides how to treat one.
    /// </summary>
    /// <param name="value">The candidate representation token.</param>
    public static DidRepresentationType? ToDidRepresentationType(string? value) => value switch
    {
        not null when value == RepresentationJsonLd => DidRepresentationType.JsonLd,
        not null when value == RepresentationJsonWithContext => DidRepresentationType.JsonWithContext,
        not null when value == RepresentationJsonWithoutContext => DidRepresentationType.JsonWithoutContext,
        _ => null
    };
}
