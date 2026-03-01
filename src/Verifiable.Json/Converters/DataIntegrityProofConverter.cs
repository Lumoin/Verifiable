using System.Text.Json;
using System.Text.Json.Serialization;
using Verifiable.Core.Model.DataIntegrity;
using Verifiable.Core.Model.Did;

namespace Verifiable.Json.Converters;

/// <summary>
/// Converts <see cref="DataIntegrityProof"/> to and from JSON with proper handling
/// of the <c>verificationMethod</c> property based on <c>proofPurpose</c>,
/// the <c>cryptosuite</c> property to <see cref="CryptosuiteInfo"/> instances,
/// and verification method subclass dispatch for embedded methods.
/// </summary>
/// <remarks>
/// <para>
/// This converter shares the same <see cref="VerificationMethodTypeSelector"/> as
/// <see cref="VerificationMethodConverter"/>, ensuring that embedded verification
/// methods in proofs are deserialized to the same subclass types as those in
/// DID documents. This is critical for round-tripping: a proof's embedded
/// verification method with additional properties (e.g., <c>blockchainAccountId</c>)
/// must preserve those properties through serialization and deserialization.
/// </para>
/// <para>
/// See <see href="https://www.w3.org/TR/vc-data-integrity/#proofs">VC Data Integrity §4 Proofs</see>.
/// </para>
/// </remarks>
public class DataIntegrityProofConverter: JsonConverter<DataIntegrityProof>
{
    private CryptosuiteInfoFactoryDelegate CryptosuiteFactory { get; }
    private VerificationMethodTypeSelector VmTypeSelector { get; }


    /// <summary>
    /// Creates a converter using the default cryptosuite factory and verification method type selector.
    /// </summary>
    public DataIntegrityProofConverter()
        : this(VerificationMethodTypeSelectors.Default, CryptosuiteInfoFactory.Default)
    {
    }


    /// <summary>
    /// Creates a converter using a custom cryptosuite factory and default VM type selector.
    /// </summary>
    /// <param name="cryptosuiteFactory">The factory for resolving cryptosuite names to instances.</param>
    public DataIntegrityProofConverter(CryptosuiteInfoFactoryDelegate cryptosuiteFactory)
        : this(VerificationMethodTypeSelectors.Default, cryptosuiteFactory)
    {
    }


    /// <summary>
    /// Creates a converter with full control over both dispatch mechanisms.
    /// </summary>
    /// <param name="vmTypeSelector">
    /// The delegate that maps verification method <c>type</c> strings to .NET types.
    /// Should be the same instance used by <see cref="VerificationMethodConverter"/>
    /// to ensure consistent type dispatch across DID documents and proofs.
    /// </param>
    /// <param name="cryptosuiteFactory">The factory for resolving cryptosuite names to instances.</param>
    public DataIntegrityProofConverter(
        VerificationMethodTypeSelector vmTypeSelector,
        CryptosuiteInfoFactoryDelegate cryptosuiteFactory)
    {
        ArgumentNullException.ThrowIfNull(vmTypeSelector);
        ArgumentNullException.ThrowIfNull(cryptosuiteFactory);
        VmTypeSelector = vmTypeSelector;
        CryptosuiteFactory = cryptosuiteFactory;
    }


    /// <inheritdoc />
    public override DataIntegrityProof Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if(reader.TokenType != JsonTokenType.StartObject)
        {
            throw new JsonException($"Expected StartObject for DataIntegrityProof, but got {reader.TokenType}.");
        }

        using var document = JsonDocument.ParseValue(ref reader);
        var root = document.RootElement;

        var proof = new DataIntegrityProof();

        //Extract proofPurpose first since it determines the VerificationMethodReference subclass.
        string? proofPurpose = null;
        if(root.TryGetProperty("proofPurpose", out var proofPurposeElement))
        {
            proofPurpose = proofPurposeElement.GetString();
            proof.ProofPurpose = proofPurpose;
        }

        if(root.TryGetProperty("id", out var idElement))
        {
            proof.Id = idElement.GetString();
        }

        if(root.TryGetProperty("type", out var typeElement))
        {
            proof.Type = typeElement.GetString() ?? DataIntegrityProof.DataIntegrityProofType;
        }

        if(root.TryGetProperty("cryptosuite", out var cryptosuiteElement))
        {
            var cryptosuiteName = cryptosuiteElement.GetString();
            if(cryptosuiteName is not null)
            {
                proof.Cryptosuite = CryptosuiteFactory(cryptosuiteName);
            }
        }

        if(root.TryGetProperty("created", out var createdElement))
        {
            proof.Created = createdElement.GetString();
        }

        if(root.TryGetProperty("expires", out var expiresElement))
        {
            proof.Expires = expiresElement.GetString();
        }

        if(root.TryGetProperty("verificationMethod", out var verificationMethodElement))
        {
            proof.VerificationMethod = CreateVerificationMethodReference(
                verificationMethodElement,
                proofPurpose,
                options);
        }

        if(root.TryGetProperty("proofValue", out var proofValueElement))
        {
            proof.ProofValue = proofValueElement.GetString();
        }

        if(root.TryGetProperty("domain", out var domainElement))
        {
            proof.Domain = domainElement.GetString();
        }

        if(root.TryGetProperty("challenge", out var challengeElement))
        {
            proof.Challenge = challengeElement.GetString();
        }

        if(root.TryGetProperty("nonce", out var nonceElement))
        {
            proof.Nonce = nonceElement.GetString();
        }

        if(root.TryGetProperty("previousProof", out var previousProofElement))
        {
            proof.PreviousProof = previousProofElement.GetString();
        }

        return proof;
    }


    /// <inheritdoc />
    public override void Write(Utf8JsonWriter writer, DataIntegrityProof value, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(writer);
        ArgumentNullException.ThrowIfNull(value);
        writer.WriteStartObject();

        if(value.Id is not null)
        {
            writer.WriteString("id", value.Id);
        }

        writer.WriteString("type", value.Type);

        if(value.Cryptosuite is not null)
        {
            writer.WriteString("cryptosuite", value.Cryptosuite.CryptosuiteName);
        }

        if(value.Created is not null)
        {
            writer.WriteString("created", value.Created);
        }

        if(value.Expires is not null)
        {
            writer.WriteString("expires", value.Expires);
        }

        if(value.VerificationMethod is not null)
        {
            writer.WritePropertyName("verificationMethod");
            if(value.VerificationMethod.IsEmbeddedVerification)
            {
                JsonSerializer.Serialize(writer, value.VerificationMethod.EmbeddedVerification, options);
            }
            else
            {
                writer.WriteStringValue(value.VerificationMethod.VerificationReferenceId);
            }
        }

        if(value.ProofPurpose is not null)
        {
            writer.WriteString("proofPurpose", value.ProofPurpose);
        }

        if(value.ProofValue is not null)
        {
            writer.WriteString("proofValue", value.ProofValue);
        }

        if(value.Domain is not null)
        {
            writer.WriteString("domain", value.Domain);
        }

        if(value.Challenge is not null)
        {
            writer.WriteString("challenge", value.Challenge);
        }

        if(value.Nonce is not null)
        {
            writer.WriteString("nonce", value.Nonce);
        }

        if(value.PreviousProof is not null)
        {
            writer.WriteString("previousProof", value.PreviousProof);
        }

        writer.WriteEndObject();
    }


    /// <summary>
    /// Creates the appropriate <see cref="VerificationMethodReference"/> subclass based on proof purpose.
    /// For embedded verification methods, uses the shared <see cref="VerificationMethodTypeSelector"/>
    /// to ensure consistent subclass dispatch with DID document deserialization.
    /// </summary>
    private VerificationMethodReference? CreateVerificationMethodReference(
        JsonElement element,
        string? proofPurpose,
        JsonSerializerOptions options)
    {
        if(element.ValueKind == JsonValueKind.Null)
        {
            return null;
        }

        string? referenceId = null;
        VerificationMethod? embedded = null;

        if(element.ValueKind == JsonValueKind.String)
        {
            referenceId = element.GetString();
        }
        else if(element.ValueKind == JsonValueKind.Object)
        {
            //Use the shared VM type selector for embedded verification methods.
            //This ensures the same subclass is instantiated whether the verification
            //method appears in a DID document or in a Data Integrity proof.
            if(element.TryGetProperty("type", out var typeElement))
            {
                var vmTypeString = typeElement.GetString();
                if(vmTypeString is not null)
                {
                    Type targetType = VmTypeSelector(vmTypeString);
                    embedded = (VerificationMethod?)element.Deserialize(targetType, options);
                }
            }

            //Fallback if no type property found.
            embedded ??= element.Deserialize<VerificationMethod>(options);
        }
        else
        {
            throw new JsonException($"Expected string or object for verificationMethod, but got {element.ValueKind}.");
        }

        return proofPurpose switch
        {
            AuthenticationMethod.Purpose => referenceId is not null
                ? new AuthenticationMethod(referenceId)
                : new AuthenticationMethod(embedded!),

            AssertionMethod.Purpose => referenceId is not null
                ? new AssertionMethod(referenceId)
                : new AssertionMethod(embedded!),

            KeyAgreementMethod.Purpose => referenceId is not null
                ? new KeyAgreementMethod(referenceId)
                : new KeyAgreementMethod(embedded!),

            CapabilityInvocationMethod.Purpose => referenceId is not null
                ? new CapabilityInvocationMethod(referenceId)
                : new CapabilityInvocationMethod(embedded!),

            CapabilityDelegationMethod.Purpose => referenceId is not null
                ? new CapabilityDelegationMethod(referenceId)
                : new CapabilityDelegationMethod(embedded!),

            null => throw new JsonException("Missing proofPurpose property. Cannot determine verification method type."),

            _ => throw new JsonException($"Unknown proofPurpose: '{proofPurpose}'. Expected one of: {AuthenticationMethod.Purpose}, {AssertionMethod.Purpose}, {KeyAgreementMethod.Purpose}, {CapabilityInvocationMethod.Purpose}, {CapabilityDelegationMethod.Purpose}.")
        };
    }
}