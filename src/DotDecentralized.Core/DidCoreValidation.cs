using DotDecentralized.Core.Did;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Diagnostics.CodeAnalysis;

namespace DotDecentralized.Core
{
    /// <summary>
    /// DID Core validation rules as specificied in https://www.w3.org/TR/did-core/.
    /// </summary>
    public static class DidCoreValidation
    {
        //TODO: Write a top level validation function, something like TryValidateConformingDidDocument()
        //https://www.w3.org/TR/did-core/#conformance.

        /// <summary>
        /// Checks the first item is <see cref="DidCoreConstants.JsonLdContextFirstUri"/>.
        /// </summary>
        /// <typeparam name="T">An object derived from <see cref="Context"/>.</typeparam>
        /// <param name="obj">The context to check.</param>
        /// <param name="results">The validation results if there were any. An empty collection otherwise.</param>
        /// <returns>True if validation succeeds. False otherwise.</returns>
        /// <remarks>See more at <a href="https://www.w3.org/TR/did-core/#json-ld"/>.</remarks>
        public static bool TryValidJsonLdUriAsFirst<T>([NotNull] T obj, out ICollection<ValidationResult> results) where T: Context
        {
            if(obj is null)
            {
                throw new ArgumentNullException(nameof(obj));
            }

            var firstContext = obj.Contexes?[0] as string;
            bool success = firstContext?.Equals(DidCoreConstants.JsonLdContextFirstUri, StringComparison.InvariantCultureIgnoreCase) == true;
            results = new List<ValidationResult>();
            if(!success)
            {
                results.Add(new ValidationResult($"Context does not specify \"{DidCoreConstants.JsonLdContextFirstUri}\" as its first URI. This is mandated by DID Core specification."));
            }

            return success;
        }
    }
}
