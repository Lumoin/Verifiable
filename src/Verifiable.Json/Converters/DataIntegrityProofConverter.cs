using System;
using System.Text.Json;
using System.Text.Json.Serialization;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Model.Proofs;

namespace Verifiable.Json.Converters;

/// <summary>
/// Converts <see cref="DataIntegrityProof"/> to and from JSON with proper handling
/// of the <c>verificationMethod</c> property based on <c>proofPurpose</c> and
/// the <c>cryptosuite</c> property to <see cref="CryptosuiteInfo"/> instances.
/// </summary>
/// <remarks>
/// <para>
/// In Data Integrity proofs, the verification purpose is expressed via the <c>proofPurpose</c>
/// property rather than the property name (as in DID documents). This converter reads
/// <c>proofPurpose</c> first to determine which <see cref="VerificationMethodReference"/>
/// subclass to instantiate for the <c>verificationMethod</c> property.
/// </para>
/// <para>
/// The <c>cryptosuite</c> property is deserialized to a <see cref="CryptosuiteInfo"/> instance
/// using a factory delegate. Known cryptosuites are resolved to their singleton instances,
/// while unknown cryptosuites are wrapped in <see cref="UnknownCryptosuiteInfo"/>.
/// </para>
/// <para>
/// <strong>Extensibility:</strong>
/// </para>
/// <para>
/// To support custom cryptosuites, provide a factory delegate that chains to
/// <see cref="CryptosuiteInfo.FromName"/> for built-in types:
/// </para>
/// <code>
/// var converter = new DataIntegrityProofConverter(name =>
///     name == CryptosuiteInfo.MyCustomSuite.CryptosuiteName
///         ? CryptosuiteInfo.MyCustomSuite
///         : CryptosuiteInfo.FromName(name));
///
/// options.Converters.Add(converter);
/// </code>
/// <para>
/// See <see href="https://www.w3.org/TR/vc-data-integrity/#proofs">VC Data Integrity §4 Proofs</see>.
/// </para>
/// </remarks>
public class DataIntegrityProofConverter: JsonConverter<DataIntegrityProof>
{
    private CryptosuiteInfoFactoryDelegate CryptosuiteFactory { get; }


    /// <summary>
    /// Creates a converter using the default cryptosuite factory.
    /// </summary>
    public DataIntegrityProofConverter() : this(CryptosuiteInfoFactory.Default)
    {
    }


    /// <summary>
    /// Creates a converter using a custom cryptosuite factory.
    /// </summary>
    /// <param name="cryptosuiteFactory">The factory for resolving cryptosuite names to instances.</param>
    public DataIntegrityProofConverter(CryptosuiteInfoFactoryDelegate cryptosuiteFactory)
    {
        CryptosuiteFactory = cryptosuiteFactory ?? throw new ArgumentNullException(nameof(cryptosuiteFactory));
    }


    /// <inheritdoc/>
    public override DataIntegrityProof Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if(reader.TokenType != JsonTokenType.StartObject)
        {
            throw new JsonException($"Expected StartObject for DataIntegrityProof, but got {reader.TokenType}.");
        }

        //Parse the entire object to access proofPurpose before verificationMethod.
        using var document = JsonDocument.ParseValue(ref reader);
        var root = document.RootElement;

        var proof = new DataIntegrityProof();

        //Extract proofPurpose first since we need it to determine VerificationMethod type.
        string? proofPurpose = null;
        if(root.TryGetProperty("proofPurpose", out var proofPurposeElement))
        {
            proofPurpose = proofPurposeElement.GetString();
            proof.ProofPurpose = proofPurpose;
        }

        //Process id.
        if(root.TryGetProperty("id", out var idElement))
        {
            proof.Id = idElement.GetString();
        }

        //Process type.
        if(root.TryGetProperty("type", out var typeElement))
        {
            proof.Type = typeElement.GetString() ?? DataIntegrityProof.DataIntegrityProofType;
        }

        //Process cryptosuite to CryptosuiteInfo using the factory.
        if(root.TryGetProperty("cryptosuite", out var cryptosuiteElement))
        {
            var cryptosuiteName = cryptosuiteElement.GetString();
            if(cryptosuiteName is not null)
            {
                proof.Cryptosuite = CryptosuiteFactory(cryptosuiteName);
            }
        }

        //Process created as XMLSCHEMA11-2 dateTimeStamp string.
        if(root.TryGetProperty("created", out var createdElement))
        {
            proof.Created = createdElement.GetString();
        }

        //Process expires as XMLSCHEMA11-2 dateTimeStamp string.
        if(root.TryGetProperty("expires", out var expiresElement))
        {
            proof.Expires = expiresElement.GetString();
        }

        //Process verificationMethod using proofPurpose to determine the concrete type.
        if(root.TryGetProperty("verificationMethod", out var verificationMethodElement))
        {
            proof.VerificationMethod = CreateVerificationMethodReference(
                verificationMethodElement,
                proofPurpose,
                options);
        }

        //Process proofValue.
        if(root.TryGetProperty("proofValue", out var proofValueElement))
        {
            proof.ProofValue = proofValueElement.GetString();
        }

        //Process domain.
        if(root.TryGetProperty("domain", out var domainElement))
        {
            proof.Domain = domainElement.GetString();
        }

        //Process challenge.
        if(root.TryGetProperty("challenge", out var challengeElement))
        {
            proof.Challenge = challengeElement.GetString();
        }

        //Process nonce.
        if(root.TryGetProperty("nonce", out var nonceElement))
        {
            proof.Nonce = nonceElement.GetString();
        }

        //Process previousProof.
        if(root.TryGetProperty("previousProof", out var previousProofElement))
        {
            proof.PreviousProof = previousProofElement.GetString();
        }

        return proof;
    }


    /// <inheritdoc/>
    public override void Write(Utf8JsonWriter writer, DataIntegrityProof value, JsonSerializerOptions options)
    {
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
    /// </summary>
    /// <param name="element">The JSON element containing the verification method value.</param>
    /// <param name="proofPurpose">The proof purpose determining which subclass to create.</param>
    /// <param name="options">The serializer options for deserializing embedded methods.</param>
    /// <returns>The appropriate verification method reference subclass, or null.</returns>
    /// <exception cref="JsonException">Thrown when proofPurpose is missing or unknown.</exception>
    private static VerificationMethodReference? CreateVerificationMethodReference(
        JsonElement element,
        string? proofPurpose,
        JsonSerializerOptions options)
    {
        if(element.ValueKind == JsonValueKind.Null)
        {
            return null;
        }

        //Determine if this is a string reference or embedded object.
        string? referenceId = null;
        VerificationMethod? embedded = null;

        if(element.ValueKind == JsonValueKind.String)
        {
            referenceId = element.GetString();
        }
        else if(element.ValueKind == JsonValueKind.Object)
        {
            var embeddedJson = element.GetRawText();
            embedded = JsonSerializer.Deserialize<VerificationMethod>(embeddedJson, options);
        }
        else
        {
            throw new JsonException($"Expected string or object for verificationMethod, but got {element.ValueKind}.");
        }

        //Create the appropriate subclass based on proofPurpose.
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