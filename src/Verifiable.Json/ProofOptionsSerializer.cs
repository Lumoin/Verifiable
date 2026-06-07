using System;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization.Metadata;
using Verifiable.Core.Model.DataIntegrity;

namespace Verifiable.Json;

/// <summary>
/// Provides the default JSON implementation of <see cref="ProofOptionsSerializeDelegate"/>.
/// </summary>
/// <remarks>
/// <para>
/// The proof options document is a spec-mandated intermediate artifact that gets
/// canonicalized and hashed during both signing and verification. It contains the
/// proof metadata fields (<c>type</c>, <c>cryptosuite</c>, <c>created</c>,
/// <c>verificationMethod</c>, <c>proofPurpose</c>) plus an optional <c>@context</c>
/// inherited from the secured document for RDFC canonicalization.
/// </para>
/// <para>
/// See <see href="https://www.w3.org/TR/vc-data-integrity/#add-proof">
/// W3C Data Integrity §4.2 Add Proof</see>.
/// </para>
/// <para>
/// See also <see href="https://github.com/w3c/vc-data-integrity/issues/323">
/// Issue #323: Context availability for verification</see> and
/// <see href="https://www.w3.org/TR/vc-data-integrity/#validating-contexts">
/// §2.4.1 Validating Contexts</see> for context validation requirements.
/// </para>
/// </remarks>
public static class ProofOptionsSerializer
{
    /// <summary>
    /// Creates a <see cref="ProofOptionsSerializeDelegate"/> bound to the specified
    /// JSON serializer options.
    /// </summary>
    /// <param name="options">The JSON serializer options with registered converters.</param>
    /// <returns>A delegate that serializes <see cref="ProofOptionsDocument"/> instances to JSON.</returns>
    /// <example>
    /// <code>
    /// var serializeProofOptions = ProofOptionsSerializer.Create(jsonOptions);
    ///
    /// var signedCredential = await credential.SignAsync(
    ///     privateKey,
    ///     verificationMethodId,
    ///     cryptosuite,
    ///     proofCreated,
    ///     canonicalize,
    ///     contextResolver,
    ///     encodeProofValue,
    ///     serializeCredential,
    ///     deserializeCredential,
    ///     serializeProofOptions,
    ///     encoder,
    ///     memoryPool,
    ///     cancellationToken);
    /// </code>
    /// </example>
    public static ProofOptionsSerializeDelegate Create(JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        return (proofOptions) => Serialize(proofOptions, options);
    }


    /// <summary>
    /// Serializes a <see cref="ProofOptionsDocument"/> to a JSON string.
    /// </summary>
    /// <remarks>
    /// <para>
    /// When the options carry <see cref="ProofOptionsDocument.ReceivedProofJson"/> — a
    /// proof parsed from a wire document — the options are reconstructed from THOSE
    /// bytes by removing <c>proofValue</c> (Data Integrity 1.0 §4.2 Verify Proof), so
    /// the canonicalized form is built from the signer's own member shapes: a
    /// multi-domain set, a scalar-versus-array choice, a timestamp format, or an
    /// extension member all survive exactly as signed.
    /// </para>
    /// <para>
    /// Otherwise (signing, or verifying a proof built in memory) the typed members are
    /// written, mirroring the wire converter member-for-member minus <c>proofValue</c>:
    /// EVERY member the wire proof will carry — including <c>id</c>,
    /// <c>previousProof</c>, <c>challenge</c>, and <c>domain</c> — is part of the
    /// canonicalized options and therefore covered by the signature.
    /// </para>
    /// </remarks>
    /// <param name="proofOptions">The proof options document to serialize.</param>
    /// <param name="options">The JSON serializer options with registered converters.</param>
    /// <returns>The serialized proof options JSON string.</returns>
    public static string Serialize(ProofOptionsDocument proofOptions, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(proofOptions);
        ArgumentNullException.ThrowIfNull(options);

        if(proofOptions.ReceivedProofJson is not null)
        {
            return SerializeFromReceived(proofOptions, options);
        }

        var obj = new JsonObject();

        if(proofOptions.Id is not null)
        {
            obj["id"] = proofOptions.Id;
        }

        obj["type"] = proofOptions.Type;
        obj["cryptosuite"] = proofOptions.Cryptosuite.CryptosuiteName;
        obj["created"] = proofOptions.Created;

        if(proofOptions.Expires is not null)
        {
            obj["expires"] = proofOptions.Expires;
        }

        obj["verificationMethod"] = proofOptions.VerificationMethod;
        obj["proofPurpose"] = proofOptions.ProofPurpose;

        if(proofOptions.Domain is { Count: > 0 } domain)
        {
            //Mirror the wire converter's shape choice: a one-element set is the scalar
            //form, a multi-domain set is the array (Data Integrity 1.0 §2.1).
            if(domain.Count == 1)
            {
                obj["domain"] = domain[0];
            }
            else
            {
                var array = new JsonArray();
                for(int i = 0; i < domain.Count; ++i)
                {
                    array.Add((JsonNode?)JsonValue.Create(domain[i]));
                }

                obj["domain"] = array;
            }
        }

        if(proofOptions.Challenge is not null)
        {
            obj["challenge"] = proofOptions.Challenge;
        }

        if(proofOptions.Nonce is not null)
        {
            obj["nonce"] = proofOptions.Nonce;
        }

        if(proofOptions.PreviousProof is not null)
        {
            obj["previousProof"] = proofOptions.PreviousProof;
        }

        AppendContext(obj, proofOptions.Context, options);

        return obj.ToJsonString(options);
    }


    /// <summary>
    /// The §4.2 reconstruction from the received wire proof: a copy of the proof with
    /// <c>proofValue</c> removed, plus the secured document's <c>@context</c> when the
    /// cryptosuite requires JSON-LD processing.
    /// </summary>
    private static string SerializeFromReceived(ProofOptionsDocument proofOptions, JsonSerializerOptions options)
    {
        JsonNode? parsed = JsonNode.Parse(proofOptions.ReceivedProofJson!);
        if(parsed is not JsonObject obj)
        {
            throw new JsonException("The received proof JSON must be a JSON object.");
        }

        obj.Remove("proofValue");
        AppendContext(obj, proofOptions.Context, options);

        return obj.ToJsonString(options);
    }


    private static void AppendContext(JsonObject obj, object? context, JsonSerializerOptions options)
    {
        if(context is null)
        {
            return;
        }

        //Serialize the context through the registered converters (e.g., JsonLdContextConverter),
        //then parse as a JsonNode to embed in the proof options document.
        //options.GetTypeInfo retrieves the JsonTypeInfo registered for this concrete type,
        //routing through the configured IJsonTypeInfoResolver (e.g. VerifiableJsonContext)
        //without requiring reflection-based serialization.
        JsonTypeInfo contextTypeInfo = options.GetTypeInfo(context.GetType());
        string contextJson = JsonSerializer.Serialize(context, contextTypeInfo);
        obj["@context"] = JsonNode.Parse(contextJson);
    }
}