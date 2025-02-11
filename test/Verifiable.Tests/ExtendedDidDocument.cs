using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Serialization;
using Verifiable.Core.Did;

namespace Verifiable.Core
{
    /// <summary>
    /// https://www.w3.org/TR/did-core/#service-endpoints
    /// </summary>
    [DebuggerDisplay("Service(Id = {Id})")]
    public class ExtendedService: Service
    {
        [JsonExtensionData]
        public IDictionary<string, JsonElement>? AdditionalData { get; set; }
    }

    /// <summary>
    /// The core library provide a type for W3C defined DID type. It may
    /// be possible in production extra data needs to serialized or
    /// deserialized. This data can be unknown or the system not updated
    /// to the latest expected data. Serializing or deserializing unknown
    /// data is a potential security or information disclosure risk so
    /// is not provided in the model by default.
    /// </summary>
    public class TestExtendedDidDocument: DidDocument
    {
        public new ExtendedService[]? Service { get; set; }

        [JsonExtensionData]
        public IDictionary<string, object>? AdditionalData { get; set; }
    }
}
