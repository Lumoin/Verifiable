using System.Collections.Generic;
using System.Text.RegularExpressions;
using Verifiable.Assessment;


namespace Verifiable.Core.Did
{
    /// <summary>
    /// Contains validation rules common for all DID documents.
    /// </summary>
    public static class DidDocumentValidationRules
    {
        public static IList<Claim> ValidatePrefix(DidDocument document)
        {
            Regex regex = DidRegex.DidIdentifier();
            bool isSuccess = regex.IsMatch(document.Id?.Id ?? string.Empty);
            return new List<Claim>
            {
                new(ClaimId.KeyDidIdFormat, isSuccess ? ClaimOutcome.Success : ClaimOutcome.Failure)
            };
        }
    }

    public static partial class DidRegex
    {
        /// <summary>
        /// Validates that the identifier in the DID document conforms to the did: method specification.
        /// </summary>
        /// <remarks>
        /// The caret, <c>^</c>, is not in the specification but added here for pattern matching purposes.
        /// <para>
        [GeneratedRegex("^did:([a-z0-9]+):((?:[a-zA-Z0-9]|\\.|-|_|%[0-9a-fA-F]{2})+)(\\/[^?#]*)?(\\?[^#]*)?(#.*)?$")]
        public static partial Regex DidIdentifier();
    }    
}
