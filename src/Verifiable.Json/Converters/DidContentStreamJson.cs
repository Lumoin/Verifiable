using System;
using System.Text.Json;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.Model.DataIntegrity;
using Verifiable.Core.Model.Did;
using Verifiable.Foundation;

namespace Verifiable.Json.Converters;

/// <summary>
/// Writes a dereferenced <see cref="DidDereferencingResult.ContentStream"/> resource as a JSON value. The
/// content stream is an open <see cref="object"/> because dereferencing yields different resource shapes, so
/// the writer dispatches on the runtime type. Shared by <see cref="DidDereferencingResultConverter"/> (which
/// wraps it in the dereferencing-result envelope) and the bare content-stream serializer used by the HTTP(S)
/// binding's plain-media-type dereferencing case.
/// </summary>
internal static class DidContentStreamJson
{
    /// <summary>
    /// Writes <paramref name="contentStream"/> as a JSON value, dispatching on its runtime type.
    /// </summary>
    public static void Write(Utf8JsonWriter writer, object? contentStream, JsonSerializerOptions options)
    {
        switch(contentStream)
        {
            case null:
            {
                writer.WriteNullValue();

                break;
            }
            case DidDocument document:
            {
                JsonSerializer.Serialize(writer, document, options.GetTypeInfo(typeof(DidDocument)));

                break;
            }
            case DataIntegritySecuredPresentation securedPresentation:
            {
                JsonSerializer.Serialize(writer, securedPresentation, options.GetTypeInfo(typeof(DataIntegritySecuredPresentation)));

                break;
            }
            case VerifiablePresentation presentation:
            {
                JsonSerializer.Serialize(writer, presentation, options.GetTypeInfo(typeof(VerifiablePresentation)));

                break;
            }
            case VerificationMethod verificationMethod:
            {
                JsonSerializer.Serialize(writer, verificationMethod, options.GetTypeInfo(typeof(VerificationMethod)));

                break;
            }
            case Service service:
            {
                JsonSerializer.Serialize(writer, service, options.GetTypeInfo(typeof(Service)));

                break;
            }
            case string serviceEndpoint:
            {
                writer.WriteStringValue(serviceEndpoint);

                break;
            }
            case TaggedMemory<byte> taggedBytes:
            {
                WriteBytes(writer, taggedBytes.Span);

                break;
            }
            case ReadOnlyMemory<byte> bytes:
            {
                WriteBytes(writer, bytes.Span);

                break;
            }
            default:
            {
                JsonThrowHelper.ThrowJsonException(
                    $"A dereferenced content stream of type '{contentStream.GetType()}' is not a supported resource shape.");

                break;
            }
        }
    }


    //A dereferenced byte resource is written raw when it is itself JSON (for example a fetched JSON
    //document), otherwise as a base64 JSON string so an opaque binary resource survives the envelope.
    private static void WriteBytes(Utf8JsonWriter writer, ReadOnlySpan<byte> utf8)
    {
        if(TryWriteRawJson(writer, utf8))
        {
            return;
        }

        writer.WriteBase64StringValue(utf8);
    }


    private static bool TryWriteRawJson(Utf8JsonWriter writer, ReadOnlySpan<byte> utf8)
    {
        JsonDocument? parsed = null;
        try
        {
            var jsonReader = new Utf8JsonReader(utf8);
            if(!JsonDocument.TryParseValue(ref jsonReader, out parsed))
            {
                return false;
            }

            //A valid JSON document must consume the whole span; trailing bytes mean it is not a single
            //JSON value, so treat the resource as opaque binary instead.
            if(jsonReader.Read())
            {
                return false;
            }

            parsed.RootElement.WriteTo(writer);

            return true;
        }
        catch(JsonException)
        {
            return false;
        }
        finally
        {
            parsed?.Dispose();
        }
    }
}
