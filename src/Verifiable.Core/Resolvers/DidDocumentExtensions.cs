using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Core.Model.Did;

namespace Verifiable.Core.Resolvers;

/// <summary>
/// Extension methods for navigating service entries in a <see cref="DidDocument"/>.
/// </summary>
/// <remarks>
/// <para>
/// These methods implement the service endpoint construction algorithm defined in
/// W3C DID Core 1.1 §7.2, used when dereferencing a DID URL with a
/// <c>?service=</c> query parameter such as:
/// </para>
/// <code>
/// did:web:trust.verifable.app:did:123?service=ProductPassport
/// did:web:trust.verifable.app:did:123?service=ProductPassport&amp;relativeRef=/items/456
/// </code>
/// <para>
/// The caller receives the constructed endpoint URL and decides how to use it.
/// </para>
/// <para>
/// See <see href="https://www.w3.org/TR/did-core/#services">DID Core 1.1 §5.4 Services</see>
/// and <see href="https://www.w3.org/TR/did-core/#did-url-dereferencing">§7.2 DID URL Dereferencing</see>.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "The analyzer is not up to date with the latest syntax.")]
public static class DidDocumentExtensions
{
    extension(DidDocument document)
    {
        /// <summary>
        /// Finds a service entry by its ID fragment or by its type.
        /// </summary>
        /// <param name="serviceIdOrType">
        /// The service identifier to match. Matched first against the fragment of the service
        /// <c>id</c> (e.g., <c>"ProductPassport"</c> matches <c>"did:web:example.com#ProductPassport"</c>),
        /// then against the service <c>type</c> value.
        /// </param>
        /// <returns>The matching <see cref="Service"/>, or <see langword="null"/> if not found.</returns>
        /// <exception cref="ArgumentException">
        /// Thrown when <paramref name="serviceIdOrType"/> is null or whitespace.
        /// </exception>
        public Service? FindService(string serviceIdOrType)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(serviceIdOrType);

            if(document.Service is null || document.Service.Length == 0)
            {
                return null;
            }

            //Normalize the candidate to compare against id fragments without the leading '#'.
            string fragment = serviceIdOrType.StartsWith('#')
                ? serviceIdOrType[1..]
                : serviceIdOrType;

            for(int i = 0; i < document.Service.Length; i++)
            {
                var service = document.Service[i];

                //Match by id fragment — the most specific match.
                if(service.Id is not null)
                {
                    string? idString = service.Id.ToString();
                    if(idString is not null)
                    {
                        int hashIndex = idString.IndexOf('#', StringComparison.Ordinal);
                        if(hashIndex >= 0)
                        {
                            string idFragment = idString[(hashIndex + 1)..];
                            if(string.Equals(idFragment, fragment, StringComparison.Ordinal))
                            {
                                return service;
                            }
                        }
                        else if(string.Equals(idString, serviceIdOrType, StringComparison.Ordinal))
                        {
                            return service;
                        }
                    }
                }

                //Fall back to matching by type.
                if(string.Equals(service.Type, serviceIdOrType, StringComparison.Ordinal))
                {
                    return service;
                }

                if(service.Types is not null)
                {
                    for(int j = 0; j < service.Types.Count; j++)
                    {
                        if(string.Equals(service.Types[j], serviceIdOrType, StringComparison.Ordinal))
                        {
                            return service;
                        }
                    }
                }
            }

            return null;
        }

        /// <summary>
        /// Constructs the final endpoint URL for a service entry per DID Core 1.1 §7.2,
        /// optionally appending a relative reference path.
        /// </summary>
        /// <param name="serviceIdOrType">
        /// The service identifier or type to locate. See <see cref="FindService"/> for matching rules.
        /// </param>
        /// <param name="relativeRef">
        /// An optional relative reference appended to the service endpoint URL, corresponding
        /// to the <c>relativeRef</c> query parameter in the DID URL. For example,
        /// <c>"/items/456"</c> appended to <c>"https://example.com/passport"</c> gives
        /// <c>"https://example.com/passport/items/456"</c>.
        /// </param>
        /// <returns>
        /// The constructed endpoint URL string, or <see langword="null"/> if the service was
        /// not found or has no string endpoint.
        /// </returns>
        /// <exception cref="ArgumentException">
        /// Thrown when <paramref name="serviceIdOrType"/> is null or whitespace.
        /// </exception>
        /// <remarks>
        /// <para>
        /// This method handles only string service endpoints (<see cref="Service.ServiceEndpoint"/>).
        /// Map and multi-valued endpoints are caller-specific and returned without appending
        /// the relative reference.
        /// </para>
        /// <para>
        /// See <see href="https://www.w3.org/TR/did-core/#did-url-dereferencing">DID Core 1.1 §7.2</see>.
        /// </para>
        /// </remarks>
        [SuppressMessage("Design", "CA1055:URI-like return values should not be strings", Justification = "Service endpoints in DID documents are strings per the DID Core specification. System.Uri does not handle DID-specific URL patterns correctly.")]
        public string? BuildServiceEndpointUrl(string serviceIdOrType, string? relativeRef = null)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(serviceIdOrType);

            var service = document.FindService(serviceIdOrType);
            if(service?.ServiceEndpoint is null)
            {
                return null;
            }

            if(string.IsNullOrEmpty(relativeRef))
            {
                return service.ServiceEndpoint;
            }

            //Append relative reference per DID Core 1.1 §7.2: avoid double slash.
            string baseUrl = service.ServiceEndpoint.TrimEnd('/');
            string relative = relativeRef.StartsWith('/') ? relativeRef : $"/{relativeRef}";

            return $"{baseUrl}{relative}";
        }

        /// <summary>
        /// Returns all service entries whose type matches the given value.
        /// </summary>
        /// <param name="serviceType">The service type string to match.</param>
        /// <returns>
        /// A read-only list of matching services, or an empty list if none match.
        /// </returns>
        /// <exception cref="ArgumentException">
        /// Thrown when <paramref name="serviceType"/> is null or whitespace.
        /// </exception>
        public IReadOnlyList<Service> FindServicesByType(string serviceType)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(serviceType);

            if(document.Service is null || document.Service.Length == 0)
            {
                return [];
            }

            var results = new List<Service>();
            for(int i = 0; i < document.Service.Length; i++)
            {
                var service = document.Service[i];

                if(string.Equals(service.Type, serviceType, StringComparison.Ordinal))
                {
                    results.Add(service);
                    continue;
                }

                if(service.Types is not null)
                {
                    for(int j = 0; j < service.Types.Count; j++)
                    {
                        if(string.Equals(service.Types[j], serviceType, StringComparison.Ordinal))
                        {
                            results.Add(service);
                            break;
                        }
                    }
                }
            }

            return results;
        }
    }
}
