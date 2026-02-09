using System;
using System.Text.Json;
using System.Text.Json.Serialization;
using Verifiable.Core.Model.Did.Methods;
using Verifiable.Jose;
using Verifiable.Json.Converters;

namespace Verifiable.Tests.TestInfrastructure
{
    internal static class JsonSerializerOptionsExtensions
    {
        public static DidMethodFactoryDelegate DefaultDidIdFactory = did =>
        {
            return did switch
            {
                var d when did.StartsWith(EbsiDidMethod.Prefix, StringComparison.Ordinal) => new EbsiDidMethod(did),
                var d when did.StartsWith(KeyDidMethod.Prefix, StringComparison.Ordinal) => new KeyDidMethod(did),
                var d when did.StartsWith(WebDidMethod.Prefix, StringComparison.Ordinal) => new WebDidMethod(did),
                _ => new GenericDidMethod(did)
            };
        };


        public static IDictionary<string, Type> DefaultServiceTypeMap = new Dictionary<string, Type>
        {
        };


        public static JsonSerializerOptions ApplyVerifiableDefaults(this JsonSerializerOptions options)
        {
            options.DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull;
            options.PropertyNamingPolicy = new DefaultNamingNamingPolicy(Array.AsReadOnly([JsonNamingPolicy.CamelCase]));
            options.PropertyNameCaseInsensitive = true;

            options.Converters.Add(new DictionaryStringObjectJsonConverter());
            options.Converters.Add(new ControllerConverter());
            options.Converters.Add(new VerificationMethodReferenceConverterFactory());
            options.Converters.Add(new VerificationMethodConverter());
            options.Converters.Add(new ServiceConverterFactory());
            options.Converters.Add(new JsonLdContextConverter());
            options.Converters.Add(new IssuerConverter());
            options.Converters.Add(new CredentialSubjectConverter());
            options.Converters.Add(new DataIntegrityProofConverter());
            options.Converters.Add(new DidIdConverter(DefaultDidIdFactory));

            return options;
        }
    }
}