using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace DotDecentralized.Core.Did
{
    /// <summary>
    /// Abc.
    /// TODO: Customize this if more extensive type mapping and converter selection is needed.
    /// </summary>
    public class ServiceConverterFactory: JsonConverterFactory
    {
        /// <summary>
        /// TODO: What are the standardized services in https://www.w3.org/TR/did-spec-registries/ and could be here? The rest ought to be moved out.
        /// When refactoring TODO, retain this observation: Service needs to be always handled unless the library user explicitly removes it.
        /// </summary>
        public static ImmutableDictionary<string, Type> DefaultTypeMap => new Dictionary<string, Type>(StringComparer.OrdinalIgnoreCase) { { nameof(Service), typeof(Service) } }.ToImmutableDictionary();

        private ImmutableDictionary<string, Type> TypeMap { get; }


        public ServiceConverterFactory(): this(DefaultTypeMap) { }

        public ServiceConverterFactory(ImmutableDictionary<string, Type> typeMap)
        {
            TypeMap = typeMap;
        }


        /// <inheritdoc/>
        public override bool CanConvert(Type typeToConvert)
        {
            //TODO: This requires there is Service derived on the TypeMap! So this may not be needed then? Either add here or have a fallback as a service
            //with AdditonalData always if TypeMap fails and no Service is otherwise found?
            return TypeMap.Values.Any(mappedServiceType => mappedServiceType.IsAssignableFrom(typeToConvert));
        }



        /// <inheritdoc/>
        [return: NotNull]
        public override JsonConverter CreateConverter(Type typeToConvert, JsonSerializerOptions options)
        {
            //This will throw rather than throw if creating instance fails.
            //If type could be Nullable<T>, then .CreateInstance could also return null.
            return (JsonConverter)Activator.CreateInstance(
                typeof(ServiceConverter<>)
                    .MakeGenericType(new Type[] { typeToConvert }),
                    BindingFlags.Instance | BindingFlags.Public,
                    binder: null,
                    args: new object[] { TypeMap },
                    culture: null)!;
        }
    }


    /// <summary>
    /// Converts a <see cref="Service"/> derived object to and from JSON.
    /// </summary>
    /// <typeparam name="T">A service type to convert.</typeparam>
    public class ServiceConverter<T>: JsonConverter<T> where T: Service
    {
        /// <summary>
        /// A runtime map of <see cref="Service"/> and sub-types.
        /// </summary>
        private ImmutableDictionary<string, Type> TypeMap { get; }


        /// <summary>
        /// Works around https://github.com/dotnet/docs/issues/19268 for the problem if options were passed to (de)serialization here.
        /// Better options: derive a version for passed-in options that collect other parameters and conveters
        /// so that recursion would not occur or provide possibility for users to pass in collection either for
        /// all or per type. This could by default, if nothing else is passed in, use a version of options the
        /// framework passes with this converter removed or this particular here as a quick'n'dirty.
        ///
        /// This is basically needed to dynamically detect types and if the user wants to have a strong
        /// type for it.
        /// </summary>
        private JsonSerializerOptions DefaultOptionsForAll { get; } = new JsonSerializerOptions()
        {
            //It's assumed this is wanted in this quick'n'dity.
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,

            //This is needed to roundtrip between JSON and .NET types.
            PropertyNameCaseInsensitive = true,

            //This is needed when data is read without strong types
            //to Service.Extension data and then serialized back.
            //Otherwise there is a difference in output compared
            //to the original.
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        };


        /// <summary>
        /// A default constructor for <see cref="Service"/> and sub-type conversions.
        /// </summary>
        /// <param name="typeMap">A runtime map of of <see cref="Service"/> and sub-types.</param>
        public ServiceConverter(ImmutableDictionary<string, Type> typeMap)
        {
            TypeMap = typeMap ?? throw new ArgumentNullException(nameof(typeMap));
        }


        /// <inheritdoc/>
        [return: NotNull]
        public override T Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            if(reader.TokenType != JsonTokenType.StartObject)
            {
                ThrowHelper.ThrowJsonException();
            }

            //Parsing the document forwards moves the index. The element start position
            //is stored to a temporary variable here so it can be given directly to JsonSerializer.
            var elementStartPosition = reader;
            using(var jsonDocument = JsonDocument.ParseValue(ref reader))
            {
                //TODO: This discriminator can be lifted and this converter generalized further.
                //While the Factory can instantiate the generalized version with a specific
                //discriminator and type map.
                const string ServiceTypeDiscriminator = "type";
                var serviceElement = jsonDocument.RootElement;
                var serviceType = serviceElement.GetProperty(ServiceTypeDiscriminator).GetString();

                if(!string.IsNullOrEmpty(serviceType))
                {
                    if(TypeMap.TryGetValue(serviceType, out var targetType))
                    {
                        return (T)JsonSerializer.Deserialize(ref elementStartPosition, targetType, DefaultOptionsForAll)!;
                    }

                    //No type for this, so next attempt is just as plain service according to the specification,
                    //nothing extra and no strong typing.
                    return (T)JsonSerializer.Deserialize<Service>(ref elementStartPosition, DefaultOptionsForAll)!;
                }

                throw new JsonException($"No handler for service \"{serviceType}\" found.");
            }
        }


        /// <inheritdoc/>
        public override void Write(Utf8JsonWriter writer, T value, JsonSerializerOptions options)
        {
            JsonSerializer.Serialize(writer, value, value.GetType(), DefaultOptionsForAll);
        }
    }
}
