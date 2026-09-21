using System.Text.Json;
using System.Text.Json.Serialization;
using Verifiable.Core.Model.Common;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.Model.DataIntegrity;
using static Verifiable.Json.Converters.CredentialConverterShared;

namespace Verifiable.Json.Converters;

/// <summary>
/// Converts <see cref="VerifiableCredential"/> and its embedded-secured subtype
/// <see cref="DataIntegritySecuredCredential"/> to and from JSON, flattening the
/// open-world <see cref="VerifiableCredential.AdditionalData"/> bucket at the object root
/// and round-tripping the in-graph Data Integrity proof chain.
/// </summary>
/// <remarks>
/// <para>
/// A hand-written converter is required for two reasons the source generator cannot serve:
/// </para>
/// <list type="bullet">
/// <item><description>
/// <strong>Open-world fidelity.</strong> Any member the typed model does not name (an
/// extension claim, a term defined only by an additional context) must survive a
/// round-trip. Such members are flattened at the credential root, not nested under an
/// <c>additionalData</c> object, matching <see cref="ServiceConverter"/> and
/// <see cref="CredentialSubjectConverter"/>.
/// </description></item>
/// <item><description>
/// <strong>Securing-state discrimination.</strong> The unsecured
/// <see cref="VerifiableCredential"/> carries no <c>proof</c> member; the embedded-secured
/// <see cref="DataIntegritySecuredCredential"/> adds an in-graph proof chain. When a
/// <c>proof</c> member is present, the converter materializes the secured subtype even if
/// the requested type is the open <see cref="VerifiableCredential"/>, so the proof is never
/// silently dropped.
/// </description></item>
/// </list>
/// <para>
/// Per-member values delegate to the converters already registered on the options
/// (<see cref="JsonLdContextConverter"/>, <see cref="IssuerConverter"/>,
/// <see cref="CredentialSubjectConverter"/>, <see cref="DataIntegrityProofConverter"/>) via
/// <see cref="JsonSerializerOptions.GetTypeInfo"/>, so the wire shape is identical to the
/// source-generated path the converter replaces.
/// </para>
/// </remarks>
public class VerifiableCredentialConverter: JsonConverter<VerifiableCredential>
{
    /// <inheritdoc/>
    public override bool CanConvert(Type typeToConvert)
    {
        return typeToConvert == typeof(VerifiableCredential)
            || typeToConvert == typeof(DataIntegritySecuredCredential);
    }


    /// <inheritdoc/>
    public override VerifiableCredential Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        if(reader.TokenType != JsonTokenType.StartObject)
        {
            JsonThrowHelper.ThrowJsonException("Expected StartObject when reading a VerifiableCredential.");
        }

        using var document = JsonDocument.ParseValue(ref reader);
        var root = document.RootElement;

        var hasProof = root.TryGetProperty(WellKnownCredentialMemberNames.Proof, out var proofElement)
            && proofElement.ValueKind != JsonValueKind.Null;

        //A proof member (or an explicitly requested secured type) means the embedded-secured
        //subtype; otherwise the unsecured credential. Upcasting on a present proof keeps the
        //proof from being silently dropped when a caller deserializes the open base type.
        var credential = hasProof || typeToConvert == typeof(DataIntegritySecuredCredential)
            ? new DataIntegritySecuredCredential()
            : new VerifiableCredential();

        Dictionary<string, object>? additionalData = null;

        foreach(var property in root.EnumerateObject())
        {
            switch(property.Name)
            {
                case string name when name == WellKnownCredentialMemberNames.Context:
                {
                    credential.Context = Deserialize<Context>(property.Value, options);
                    break;
                }
                case string name when name == WellKnownCredentialMemberNames.Id:
                {
                    credential.Id = property.Value.GetString();
                    break;
                }
                case string name when name == WellKnownCredentialMemberNames.Type:
                {
                    credential.Type = ReadStringList(property.Value);
                    break;
                }
                case string name when name == WellKnownCredentialMemberNames.Name:
                {
                    credential.Name = property.Value.GetString();
                    break;
                }
                case string name when name == WellKnownCredentialMemberNames.Description:
                {
                    credential.Description = property.Value.GetString();
                    break;
                }
                case string name when name == WellKnownCredentialMemberNames.Issuer:
                {
                    credential.Issuer = Deserialize<Issuer>(property.Value, options);
                    break;
                }
                case string name when name == WellKnownCredentialMemberNames.CredentialSubject:
                {
                    credential.CredentialSubject = Deserialize<List<CredentialSubject>>(property.Value, options);
                    break;
                }
                case string name when name == WellKnownCredentialMemberNames.ValidFrom:
                {
                    credential.ValidFrom = property.Value.GetString();
                    break;
                }
                case string name when name == WellKnownCredentialMemberNames.ValidUntil:
                {
                    credential.ValidUntil = property.Value.GetString();
                    break;
                }
                case string name when name == WellKnownCredentialMemberNames.CredentialStatus:
                {
                    credential.CredentialStatus = Deserialize<List<CredentialStatus>>(property.Value, options);
                    break;
                }
                case string name when name == WellKnownCredentialMemberNames.CredentialSchema:
                {
                    credential.CredentialSchema = Deserialize<List<CredentialSchema>>(property.Value, options);
                    break;
                }
                case string name when name == WellKnownCredentialMemberNames.RelatedResource:
                {
                    credential.RelatedResource = Deserialize<List<RelatedResource>>(property.Value, options);
                    break;
                }
                case string name when name == WellKnownCredentialMemberNames.RefreshService:
                {
                    credential.RefreshService = Deserialize<List<RefreshService>>(property.Value, options);
                    break;
                }
                case string name when name == WellKnownCredentialMemberNames.TermsOfUse:
                {
                    credential.TermsOfUse = Deserialize<List<TermsOfUse>>(property.Value, options);
                    break;
                }
                case string name when name == WellKnownCredentialMemberNames.Evidence:
                {
                    credential.Evidence = Deserialize<List<Evidence>>(property.Value, options);
                    break;
                }
                case string name when name == WellKnownCredentialMemberNames.Proof:
                {
                    if(hasProof)
                    {
                        ((DataIntegritySecuredCredential)credential).Proof = ReadProofs(property.Value, options);
                    }

                    break;
                }
                default:
                {
                    AdditionalDataJson.AddFromElement(ref additionalData, property.Name, property.Value);
                    break;
                }
            }
        }

        credential.AdditionalData = additionalData;

        return credential;
    }


    /// <inheritdoc/>
    public override void Write(Utf8JsonWriter writer, VerifiableCredential value, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(writer);
        ArgumentNullException.ThrowIfNull(value);
        ArgumentNullException.ThrowIfNull(options);

        writer.WriteStartObject();

        if(value.Context is not null)
        {
            writer.WritePropertyName(WellKnownCredentialMemberNames.Context);
            WriteMember(writer, typeof(Context), value.Context, options);
        }

        if(value.Id is not null)
        {
            writer.WriteString(WellKnownCredentialMemberNames.Id, value.Id);
        }

        if(value.Type is not null)
        {
            WriteStringList(writer, WellKnownCredentialMemberNames.Type, value.Type);
        }

        if(value.Name is not null)
        {
            writer.WriteString(WellKnownCredentialMemberNames.Name, value.Name);
        }

        if(value.Description is not null)
        {
            writer.WriteString(WellKnownCredentialMemberNames.Description, value.Description);
        }

        if(value.Issuer is not null)
        {
            writer.WritePropertyName(WellKnownCredentialMemberNames.Issuer);
            WriteMember(writer, typeof(Issuer), value.Issuer, options);
        }

        if(value.CredentialSubject is not null)
        {
            writer.WritePropertyName(WellKnownCredentialMemberNames.CredentialSubject);
            WriteMember(writer, typeof(List<CredentialSubject>), value.CredentialSubject, options);
        }

        if(value.ValidFrom is not null)
        {
            writer.WriteString(WellKnownCredentialMemberNames.ValidFrom, value.ValidFrom);
        }

        if(value.ValidUntil is not null)
        {
            writer.WriteString(WellKnownCredentialMemberNames.ValidUntil, value.ValidUntil);
        }

        if(value.CredentialStatus is not null)
        {
            writer.WritePropertyName(WellKnownCredentialMemberNames.CredentialStatus);
            WriteMember(writer, typeof(List<CredentialStatus>), value.CredentialStatus, options);
        }

        if(value.CredentialSchema is not null)
        {
            writer.WritePropertyName(WellKnownCredentialMemberNames.CredentialSchema);
            WriteMember(writer, typeof(List<CredentialSchema>), value.CredentialSchema, options);
        }

        if(value.RelatedResource is not null)
        {
            writer.WritePropertyName(WellKnownCredentialMemberNames.RelatedResource);
            WriteMember(writer, typeof(List<RelatedResource>), value.RelatedResource, options);
        }

        if(value.RefreshService is not null)
        {
            writer.WritePropertyName(WellKnownCredentialMemberNames.RefreshService);
            WriteMember(writer, typeof(List<RefreshService>), value.RefreshService, options);
        }

        if(value.TermsOfUse is not null)
        {
            writer.WritePropertyName(WellKnownCredentialMemberNames.TermsOfUse);
            WriteMember(writer, typeof(List<TermsOfUse>), value.TermsOfUse, options);
        }

        if(value.Evidence is not null)
        {
            writer.WritePropertyName(WellKnownCredentialMemberNames.Evidence);
            WriteMember(writer, typeof(List<Evidence>), value.Evidence, options);
        }

        if(value is DataIntegritySecuredCredential secured && secured.Proof is not null)
        {
            writer.WritePropertyName(WellKnownCredentialMemberNames.Proof);
            WriteMember(writer, typeof(List<DataIntegrityProof>), secured.Proof, options);
        }

        AdditionalDataJson.WriteEntries(writer, value.AdditionalData);

        writer.WriteEndObject();
    }
}
