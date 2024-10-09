using System.Text.Json;
using System.Text.Json.Serialization;
using Verifiable.Core;
using Verifiable.Core.Did;
using Verifiable.Core.Did.Methods;
using Verifiable.Jwt;

namespace Verifiable.Tests
{
    public static class JsonSerializerOptionsExtensions
    {        
        public static DidMethodFactoryDelegate DefaultDidIdFactory = did =>
        {
            return did switch
            {
                var d when did.StartsWith(EbsiDidMethod.Prefix) => new EbsiDidMethod(did),
                var d when did.StartsWith(KeyDidMethod.Prefix) => new KeyDidMethod(did),
                var d when did.StartsWith(WebDidMethod.Prefix) => new WebDidMethod(did),                
                _ => new GenericDidMethod(did)
            };
        };

              
        public static IDictionary<string, Type> DefaultServiceTypeMap = new Dictionary<string, Type>
        {            
        };
        

        public static JsonSerializerOptions ApplyVerifiableDefaults(this JsonSerializerOptions options)
        {            
            options.DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull;
            options.PropertyNamingPolicy = new DefaultNamingNamingPolicy(Array.AsReadOnly(new JsonNamingPolicy[] { JsonNamingPolicy.CamelCase }));
            options.PropertyNameCaseInsensitive = true;

            options.Converters.Add(new DictionaryStringObjectJsonConverter());
            options.Converters.Add(new ControllerConverter());
            options.Converters.Add(new VerificationRelationshipConverterFactory());
            options.Converters.Add(new VerificationMethodConverter());
            options.Converters.Add(new ServiceConverterFactory());
            options.Converters.Add(new JsonLdContextConverter());
            options.Converters.Add(new DidIdConverter(DefaultDidIdFactory));
           
            return options;
        }
    }
}
