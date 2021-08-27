using System.Diagnostics;

namespace Verifiable.Core.Did
{
    /// <summary>
    /// https://w3c.github.io/did-core/#verification-methods
    /// </summary>
    [DebuggerDisplay("VerificationMethod(Id = {Id})")]
    public class VerificationMethod
    {
        //TODO: Could be FractionOrUri: Uri, or C# 10/F# discriminated union (like VerificationRelationship would be).
        public string? Id { get; set; }

        public string? Type { get; set; }

        public string? Controller { get; set; }

        public KeyFormat? KeyFormat { get; set; }
    }
}
