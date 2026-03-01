using System.Text.Json;
using System.Text.Json.Serialization;
using Verifiable.Core.Model.Did.Methods;
using Verifiable.Json;
using Verifiable.Json.Converters;
using Verifiable.Json.Converters.Dcql;

namespace Verifiable.Tests.TestInfrastructure;

internal static class JsonSerializerOptionsExtensions
{
    public static DidMethodFactoryDelegate DefaultDidIdFactory { get; } = did =>
    {
        return did switch
        {
            var d when d.StartsWith(EbsiDidMethod.Prefix, StringComparison.Ordinal) => new EbsiDidMethod(did),
            var d when d.StartsWith(KeyDidMethod.Prefix, StringComparison.Ordinal) => new KeyDidMethod(did),
            var d when d.StartsWith(WebDidMethod.Prefix, StringComparison.Ordinal) => new WebDidMethod(did),
            _ => new GenericDidMethod(did)
        };
    };


    public static JsonSerializerOptions ApplyVerifiableDefaults(this JsonSerializerOptions options)
    {
        options.DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull;
        options.PropertyNamingPolicy = new DefaultNamingNamingPolicy(Array.AsReadOnly([JsonNamingPolicy.CamelCase]));
        options.PropertyNameCaseInsensitive = true;

        //Source-generated serialization metadata for AOT compatibility.
        options.TypeInfoResolver = VerifiableJsonContext.Default;

        //DID document converters.
        options.Converters.Add(new DictionaryStringObjectJsonConverter());
        options.Converters.Add(new SingleOrArrayControllerConverter());
        options.Converters.Add(new VerificationMethodReferenceConverterFactory());
        options.Converters.Add(new VerificationMethodConverter());
        options.Converters.Add(new ServiceConverter());
        options.Converters.Add(new JsonLdContextConverter());
        options.Converters.Add(new DataIntegrityProofConverter());
        options.Converters.Add(new DidIdConverter(DefaultDidIdFactory));

        //Verifiable Credential converters.
        options.Converters.Add(new IssuerConverter());
        options.Converters.Add(new CredentialSubjectConverter());

        //DCQL converters.
        options.Converters.Add(new DcqlQueryConverter());
        options.Converters.Add(new CredentialQueryConverter());
        options.Converters.Add(new CredentialQueryMetaConverter());
        options.Converters.Add(new ClaimsQueryConverter());
        options.Converters.Add(new TrustedAuthoritiesQueryConverter());
        options.Converters.Add(new CredentialSetQueryConverter());

        return options;
    }
}