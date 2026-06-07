using System.Text.Json;
using System.Text.Json.Serialization;
using Verifiable.Core.Model.Did.Methods;
using Verifiable.Cryptography;
using Verifiable.Json;
using Verifiable.Json.Converters;
using Verifiable.Json.Converters.Dcql;
using Verifiable.Json.StatusList;

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


    public static JsonSerializerOptions ApplyVerifiableDefaults(this JsonSerializerOptions options, bool requireDcqlMeta = true)
    {
        options.DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull;
        options.PropertyNamingPolicy = new DefaultNamingNamingPolicy(Array.AsReadOnly([JsonNamingPolicy.CamelCase]));
        options.PropertyNameCaseInsensitive = true;

        //Source-generated serialization metadata for AOT compatibility.
        options.TypeInfoResolver = VerifiableJsonContext.Default;

        //DID document converters.
        options.Converters.Add(new DictionaryStringObjectJsonConverter(VerifiableJsonContext.Default));
        options.Converters.Add(new SingleOrArrayControllerConverter());
        options.Converters.Add(new VerificationMethodReferenceConverterFactory());
        options.Converters.Add(new VerificationMethodConverter());
        options.Converters.Add(new ServiceConverter());
        options.Converters.Add(new JsonLdContextConverter());
        options.Converters.Add(new DataIntegrityProofConverter());
        options.Converters.Add(new DidUrlConverter());
        options.Converters.Add(new DidIdConverter(DefaultDidIdFactory));

        //Verifiable Credential converters.
        options.Converters.Add(new IssuerConverter());
        options.Converters.Add(new CredentialSubjectConverter());
        options.Converters.Add(new VerifiableCredentialConverter());
        options.Converters.Add(new VerifiablePresentationConverter());
        options.Converters.Add(new EnvelopedVerifiablePresentationConverter());

        //DCQL converters. CredentialQueryConverter enforces the OID4VP §6.1 'meta'
        //requirement by default; converter-fidelity tests pass requireDcqlMeta:false.
        options.Converters.Add(new DcqlQueryConverter());
        options.Converters.Add(new CredentialQueryConverter(requireDcqlMeta));
        options.Converters.Add(new CredentialQueryMetaConverter());
        options.Converters.Add(new ClaimsQueryConverter());
        options.Converters.Add(new TrustedAuthoritiesQueryConverter());
        options.Converters.Add(new CredentialSetQueryConverter());

        //OID4VP client_metadata (Verifier metadata) converters — snake_case wire names
        //and correct shape (bare vp_formats_supported map, jwks as a JSON object).
        options.Converters.Add(new VpFormatsSupportedConverter());
        options.Converters.Add(new VerifierClientMetadataConverter());

        //Status list converters.
        options.Converters.Add(new StatusListJsonConverter(SensitiveMemoryPool<byte>.Shared));
        options.Converters.Add(new StatusListReferenceJsonConverter());
        options.Converters.Add(new StatusClaimJsonConverter());
        options.Converters.Add(new StatusListAggregationJsonConverter());

        return options;
    }
}