using System.Text.Json;
using System.Text.Json.Nodes;
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
    /// <param name="proofOptions">The proof options document to serialize.</param>
    /// <param name="options">The JSON serializer options with registered converters.</param>
    /// <returns>The serialized proof options JSON string.</returns>
    public static string Serialize(ProofOptionsDocument proofOptions, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(proofOptions);
        ArgumentNullException.ThrowIfNull(options);

        var obj = new JsonObject
        {
            ["type"] = proofOptions.Type,
            ["cryptosuite"] = proofOptions.Cryptosuite.CryptosuiteName,
            ["created"] = proofOptions.Created,
            ["verificationMethod"] = proofOptions.VerificationMethod,
            ["proofPurpose"] = proofOptions.ProofPurpose
        };

        if(proofOptions.Context is not null)
        {
            //Serialize the context through the registered converters (e.g., JsonLdContextConverter),
            //then parse as a JsonNode to embed in the proof options document.
            string contextJson = JsonSerializer.Serialize(proofOptions.Context, proofOptions.Context.GetType(), options);
            obj["@context"] = JsonNode.Parse(contextJson);
        }

        return obj.ToJsonString(options);
    }
}