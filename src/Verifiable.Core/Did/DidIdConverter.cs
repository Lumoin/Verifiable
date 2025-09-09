﻿using System;
using System.Text.Json;
using System.Text.Json.Serialization;
using Verifiable.Core.Did.Methods;

namespace Verifiable.Core.Did
{
    public delegate GenericDidMethod DidMethodFactoryDelegate(string did);


    public class DidIdConverter: JsonConverter<GenericDidMethod>
    {
        private DidMethodFactoryDelegate DidFactory { get; }


        /// <summary>
        /// Determines whether the specified instance is or inherits from <see cref="GenericDidId"/> and so
        /// can be converted to it. The specific type instantiated is decided by the <see cref="DidMethodFactoryDelegate"/>
        /// supplied as parameter to the constructor.
        /// </summary>
        /// <remarks><see langword="true"/> if type derives from <see cref="GenericDidId"/>; <see langword="false"/> otherwise.</remarks>
        public override bool CanConvert(Type objectType) => typeof(GenericDidMethod).IsAssignableFrom(objectType);


        public DidIdConverter(DidMethodFactoryDelegate didFactory)
        {
            DidFactory = didFactory;
        }

        
        public override GenericDidMethod Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            string? did = reader.GetString();
            if(did == null)
            {                
                ThrowHelper.ThrowJsonException("Did identifier must be a valid identifier string.");
            }

            return DidFactory(did);
        }


        public override void Write(Utf8JsonWriter writer, GenericDidMethod value, JsonSerializerOptions options)
        {
            writer.WriteStringValue((string)value);
        }
    }
}
