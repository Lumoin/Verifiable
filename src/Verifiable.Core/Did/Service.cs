using System;
using System.Diagnostics;

namespace Verifiable.Core.Did
{
    /// <summary>
    /// https://www.w3.org/TR/did-core/#services
    /// </summary>
    [DebuggerDisplay("Service(Id = {Id})")]
    public class Service
    {
        public Uri? Id { get; set; }
        
        public string? Type { get; set; }
        
        public string? ServiceEndpoint { get; set; }        
    }
}
