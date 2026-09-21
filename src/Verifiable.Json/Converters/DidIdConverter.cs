using System.Text.Json;
using System.Text.Json.Serialization;
using Verifiable.Core.Did.Methods;

namespace Verifiable.Json.Converters
{
    /// <summary>
    /// Builds the concrete <see cref="GenericDidMethod"/> for a DID identifier string, dispatching on the DID
    /// method segment. Supplied to <see cref="DidIdConverter"/> so JSON deserialization can produce the
    /// method-specific type without the converter itself knowing every registered method.
    /// </summary>
    /// <param name="did">The DID identifier string read from JSON.</param>
    /// <returns>The DID method instance the identifier resolves to.</returns>
    public delegate GenericDidMethod DidMethodFactoryDelegate(string did);


    /// <summary>
    /// Converts a DID identifier between its JSON string representation and a <see cref="GenericDidMethod"/>
    /// instance, delegating construction of the concrete method type to a <see cref="DidMethodFactoryDelegate"/>.
    /// </summary>
    public class DidIdConverter: JsonConverter<GenericDidMethod>
    {
        private DidMethodFactoryDelegate DidFactory { get; }


        /// <summary>
        /// Determines whether the specified instance is or inherits from <see cref="GenericDidMethod"/> and so
        /// can be converted to it. The specific type instantiated is decided by the <see cref="DidMethodFactoryDelegate"/>
        /// supplied as parameter to the constructor.
        /// </summary>
        /// <remarks><see langword="true"/> if type derives from <see cref="GenericDidMethod"/>; <see langword="false"/> otherwise.</remarks>
        public override bool CanConvert(Type typeToConvert) => typeof(GenericDidMethod).IsAssignableFrom(typeToConvert);


        /// <summary>
        /// Creates the converter with the factory that builds the concrete DID method type for a read identifier.
        /// </summary>
        /// <param name="didFactory">Builds the concrete <see cref="GenericDidMethod"/> for a decoded DID string.</param>
        public DidIdConverter(DidMethodFactoryDelegate didFactory)
        {
            DidFactory = didFactory;
        }


        /// <summary>
        /// Reads a DID identifier string from JSON and builds its concrete <see cref="GenericDidMethod"/> via
        /// <see cref="DidFactory"/>.
        /// </summary>
        /// <param name="reader">The UTF-8 JSON reader positioned at the DID identifier string.</param>
        /// <param name="typeToConvert">The requested target type.</param>
        /// <param name="options">The active serializer options.</param>
        /// <returns>The DID method instance the identifier resolves to.</returns>
        public override GenericDidMethod Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            string? did = reader.GetString();
            if(did == null)
            {
                JsonThrowHelper.ThrowJsonException("Did identifier must be a valid identifier string.");
            }

            return DidFactory(did);
        }


        /// <summary>
        /// Writes a <see cref="GenericDidMethod"/> as its DID identifier string.
        /// </summary>
        /// <param name="writer">The UTF-8 JSON writer.</param>
        /// <param name="value">The DID method instance to serialize.</param>
        /// <param name="options">The active serializer options.</param>
        public override void Write(Utf8JsonWriter writer, GenericDidMethod value, JsonSerializerOptions options)
        {
            ArgumentNullException.ThrowIfNull(writer);
            ArgumentNullException.ThrowIfNull(value);

            writer.WriteStringValue((string)value);
        }
    }
}
