using System.Collections.Generic;

namespace Verifiable.Core.Did
{    
    /// <summary>
    /// https://www.w3.org/TR/did-spec-registries/#context
    /// </summary>
    public class Context
    {
        public List<object>? Contexes { get; set; }

        public IDictionary<string, object>? AdditionalData { get; set; }
    }
}
