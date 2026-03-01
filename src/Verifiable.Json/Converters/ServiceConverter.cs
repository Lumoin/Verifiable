using System.Text.Json;
using System.Text.Json.Serialization;
using Verifiable.Core.Model.Did;

namespace Verifiable.Json.Converters;

/// <summary>
/// Converts <see cref="Service"/> and its subclasses to and from JSON using a
/// <see cref="ServiceTypeSelector"/> delegate for type dispatch.
/// </summary>
/// <remarks>
/// <para>
/// This converter reads the <c>type</c> property from each service entry and uses
/// the <see cref="ServiceTypeSelector"/> to determine which .NET type to instantiate.
/// </para>
/// <para>
/// When the selector returns <c>typeof(Service)</c> (the default for unknown types),
/// the converter manually parses the JSON object into a <see cref="Service"/> instance,
/// placing unrecognized properties into <see cref="Service.AdditionalData"/>. This avoids
/// re-entrant serialization and keeps the converter AOT-compatible.
/// </para>
/// <para>
/// When the selector returns a derived type, the converter uses
/// <see cref="JsonSerializerOptions.GetTypeInfo"/> for AOT-friendly deserialization.
/// Since <see cref="CanConvert"/> only matches the base <see cref="Service"/> type,
/// STJ handles derived types directly without re-entering this converter.
/// </para>
/// <para>
/// <strong>Extensibility:</strong>
/// </para>
/// <code>
/// var defaultSelector = ServiceTypeSelectors.Default;
/// ServiceTypeSelector mySelector = serviceType => serviceType switch
/// {
///     "IdentityResolverService" => typeof(UntpIdentityResolverService),
///     "DIDCommMessaging" => typeof(DIDCommService),
///     _ => defaultSelector(serviceType)
/// };
///
/// options.Converters.Add(new ServiceConverter(mySelector));
/// </code>
/// </remarks>
public class ServiceConverter: JsonConverter<Service>
{
    private ServiceTypeSelector TypeSelector { get; }


    /// <summary>
    /// Creates a converter using the default type selector.
    /// </summary>
    public ServiceConverter() : this(ServiceTypeSelectors.Default)
    {
    }


    /// <summary>
    /// Creates a converter using a custom type selector.
    /// </summary>
    /// <param name="typeSelector">
    /// The delegate that maps service <c>type</c> strings to .NET types.
    /// </param>
    public ServiceConverter(ServiceTypeSelector typeSelector)
    {
        ArgumentNullException.ThrowIfNull(typeSelector);
        TypeSelector = typeSelector;
    }


    /// <inheritdoc />
    public override bool CanConvert(Type typeToConvert)
    {
        return typeToConvert == typeof(Service);
    }


    /// <inheritdoc />
    public override Service Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        if(reader.TokenType != JsonTokenType.StartObject)
        {
            JsonThrowHelper.ThrowJsonException();
        }

        using(var document = JsonDocument.ParseValue(ref reader))
        {
            var element = document.RootElement;

            if(!element.TryGetProperty("type", out var typeElement))
            {
                JsonThrowHelper.ThrowJsonException("Service entry is missing the required 'type' property.");
            }

            var serviceType = typeElement.GetString();
            if(string.IsNullOrEmpty(serviceType))
            {
                JsonThrowHelper.ThrowJsonException("Service 'type' property must not be null or empty.");
            }

            Type targetType = TypeSelector(serviceType);

            //Base type: manual parse to avoid re-entering this converter.
            if(targetType == typeof(Service))
            {
                return ReadBaseService(element, serviceType);
            }

            //Derived type: AOT-friendly deserialization. Since CanConvert only
            //matches typeof(Service), STJ won't re-enter this converter.
            var typeInfo = options.GetTypeInfo(targetType);
            return (Service)JsonSerializer.Deserialize(element, typeInfo)!;
        }
    }


    /// <inheritdoc />
    public override void Write(Utf8JsonWriter writer, Service value, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(writer);
        ArgumentNullException.ThrowIfNull(value);
        ArgumentNullException.ThrowIfNull(options);

        //Derived type: AOT-friendly serialization. Since CanConvert only matches
        //typeof(Service), STJ won't re-enter this converter for derived types.
        if(value.GetType() != typeof(Service))
        {
            var typeInfo = options.GetTypeInfo(value.GetType());
            JsonSerializer.Serialize(writer, value, typeInfo);
            return;
        }

        //Base type: manual write to avoid re-entering this converter.
        WriteBaseService(writer, value);
    }


    /// <summary>
    /// Manually parses a <see cref="Service"/> from a JSON object, placing unrecognized
    /// properties into <see cref="Service.AdditionalData"/>. Uses
    /// <see cref="JsonElementConversion.Convert"/> for value materialization.
    /// </summary>
    private static Service ReadBaseService(JsonElement element, string serviceType)
    {
        var service = new Service { Type = serviceType };
        Dictionary<string, object>? additionalData = null;

        foreach(var property in element.EnumerateObject())
        {
            if(property.NameEquals("id"u8))
            {
                var idString = property.Value.GetString();
                if(idString is not null)
                {
                    service.Id = new Uri(idString, UriKind.RelativeOrAbsolute);
                }
            }
            else if(property.NameEquals("type"u8))
            {
                //Already handled above. Could also be an array.
                if(property.Value.ValueKind == JsonValueKind.Array)
                {
                    var types = new List<string>();
                    foreach(var item in property.Value.EnumerateArray())
                    {
                        var t = item.GetString();
                        if(t is not null)
                        {
                            types.Add(t);
                        }
                    }

                    service.Types = types;
                    service.Type = types.Count > 0 ? types[0] : serviceType;
                }
            }
            else if(property.NameEquals("serviceEndpoint"u8))
            {
                switch(property.Value.ValueKind)
                {
                    case JsonValueKind.String:
                    {
                        service.ServiceEndpoint = property.Value.GetString();
                        break;
                    }
                    case JsonValueKind.Object:
                    {
                        service.ServiceEndpointMap =
                            (IDictionary<string, object>?)JsonElementConversion.Convert(property.Value);
                        break;
                    }
                    case JsonValueKind.Array:
                    {
                        var endpoints = new List<object>();
                        foreach(var item in property.Value.EnumerateArray())
                        {
                            var converted = JsonElementConversion.Convert(item);
                            if(converted is not null)
                            {
                                endpoints.Add(converted);
                            }
                        }

                        service.ServiceEndpoints = endpoints;
                        break;
                    }
                }
            }
            else
            {
                //Unknown property — store in AdditionalData.
                additionalData ??= new Dictionary<string, object>(StringComparer.Ordinal);
                var value = JsonElementConversion.Convert(property.Value);
                if(value is not null)
                {
                    additionalData[property.Name] = value;
                }
            }
        }

        if(additionalData is not null)
        {
            service.AdditionalData = additionalData;
        }

        return service;
    }


    /// <summary>
    /// Manually writes a base <see cref="Service"/> to JSON, including any properties
    /// stored in <see cref="Service.AdditionalData"/>.
    /// </summary>
    private static void WriteBaseService(Utf8JsonWriter writer, Service service)
    {
        writer.WriteStartObject();

        if(service.Id is not null)
        {
            writer.WriteString("id"u8, service.Id.OriginalString);
        }

        if(service.Types is { Count: > 1 })
        {
            writer.WriteStartArray("type"u8);
            foreach(var t in service.Types)
            {
                writer.WriteStringValue(t);
            }

            writer.WriteEndArray();
        }
        else if(service.Type is not null)
        {
            writer.WriteString("type"u8, service.Type);
        }

        if(service.ServiceEndpoint is not null)
        {
            writer.WriteString("serviceEndpoint"u8, service.ServiceEndpoint);
        }
        else if(service.ServiceEndpointMap is not null)
        {
            writer.WritePropertyName("serviceEndpoint"u8);
            ManualJsonWriter.WriteValue(writer, service.ServiceEndpointMap);
        }
        else if(service.ServiceEndpoints is not null)
        {
            writer.WriteStartArray("serviceEndpoint"u8);
            foreach(var endpoint in service.ServiceEndpoints)
            {
                ManualJsonWriter.WriteValue(writer, endpoint);
            }

            writer.WriteEndArray();
        }

        if(service.AdditionalData is not null)
        {
            foreach(var kvp in service.AdditionalData)
            {
                writer.WritePropertyName(kvp.Key);
                ManualJsonWriter.WriteValue(writer, kvp.Value);
            }
        }

        writer.WriteEndObject();
    }
}