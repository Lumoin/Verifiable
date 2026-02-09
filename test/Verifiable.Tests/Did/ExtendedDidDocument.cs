using System.Diagnostics;
using System.Text.Json.Serialization;
using Verifiable.Core.Model.Did;

namespace Verifiable.Tests.Did
{
    /// <summary>
    /// https://www.w3.org/TR/did-core/#service-endpoints
    /// </summary>
    [DebuggerDisplay("Service(Id = {Id})")]
    internal class ExtendedService: Service
    {        
    }

    /// <summary>
    /// The core library provide a type for W3C defined DID type. It may
    /// be possible in production extra data needs to serialized or
    /// deserialized. This data can be unknown or the system not updated
    /// to the latest expected data. Serializing or deserializing unknown
    /// data is a potential security or information disclosure risk so
    /// is not provided in the model by default.
    /// </summary>
    internal class TestExtendedDidDocument: DidDocument
    {
        public new ExtendedService[]? Service { get; set; }

        [JsonExtensionData]
        public IDictionary<string, object>? AdditionalData { get; set; }
    }
}
