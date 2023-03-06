using System;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Verifiable.Core.Did
{
    public delegate GenericDidId DidIdFactoryDelegate(string did);


    public class DidIdConverter: JsonConverter<GenericDidId>
    {
        private DidIdFactoryDelegate DidFactory { get; }


        /// <summary>
        /// Determines whether the specified instance is or inherits from <see cref="GenericDidId"/> and so
        /// can be converted to it. The specifi type instantiated is decided by the <see cref="DidIdFactoryDelegate"/>
        /// supplied as parameter to the constructor.
        /// </summary>
        /// <remarks><see langword="true"/> if type derives from <see cref="GenericDidId"/>; <see langword="false"/> otherwise.</remarks>
        public override bool CanConvert(Type objectType) => typeof(GenericDidId).IsAssignableFrom(objectType);


        public DidIdConverter(DidIdFactoryDelegate didFactory)
        {
            DidFactory = didFactory;
        }

        
        public override GenericDidId Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            string? did = reader.GetString();
            if(did == null)
            {                
                ThrowHelper.ThrowJsonException("Did identifier must be a valid identifier string.");
            }

            return DidFactory(did);
        }


        public override void Write(Utf8JsonWriter writer, GenericDidId value, JsonSerializerOptions options)
        {
            writer.WriteStringValue((string)value);
        }
    }
}
