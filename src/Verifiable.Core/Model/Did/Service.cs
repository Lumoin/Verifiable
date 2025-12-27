using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Core.Model.Did
{
    /// <summary>
    /// Represents a service endpoint in a controlled identifier document as defined in
    /// the W3C Controlled Identifiers v1.0 specification.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Services express ways of communicating with the controller or associated entities
    /// in relation to the controlled identifier. A service can be any type the controller
    /// wants to advertise for discovery, authentication, authorization, or interaction.
    /// </para>
    /// <para>
    /// Due to privacy concerns, revealing public information through services (such as
    /// social media accounts, personal websites, and email addresses) is discouraged.
    /// See <see href="https://www.w3.org/TR/cid-1.0/#keep-personal-data-private">
    /// CID 1.0 §6.1 Keep Personal Data Private</see>.
    /// </para>
    /// <para>
    /// See <see href="https://www.w3.org/TR/cid-1.0/#services">CID 1.0 §2.1.4 Services</see>.
    /// </para>
    /// </remarks>
    [DebuggerDisplay("Service(Id = {Id}, Type = {Type})")]
    public class Service: IEquatable<Service>
    {
        /// <summary>
        /// An optional unique identifier for this service.
        /// </summary>
        /// <remarks>
        /// <para>
        /// If present, the value must be a URL. A conforming document must not include
        /// multiple service entries with the same <c>id</c>.
        /// </para>
        /// <para>
        /// See <see href="https://www.w3.org/TR/cid-1.0/#services">CID 1.0 §2.1.4 Services</see>.
        /// </para>
        /// </remarks>
        public Uri? Id { get; set; }

        /// <summary>
        /// The type of service being offered.
        /// </summary>
        /// <remarks>
        /// <para>
        /// The value must be a string or a set of strings. To maximize interoperability,
        /// the service type and its associated properties should be registered in the
        /// Verifiable Credential Extensions registry.
        /// </para>
        /// <para>
        /// When multiple types are needed, use <see cref="Types"/> instead. If both are set,
        /// <see cref="Types"/> takes precedence during serialization.
        /// </para>
        /// <para>
        /// See <see href="https://www.w3.org/TR/cid-1.0/#services">CID 1.0 §2.1.4 Services</see>.
        /// </para>
        /// </remarks>
        public string? Type { get; set; }

        /// <summary>
        /// Multiple types for this service when more than one type applies.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Use this property when the service has multiple types. For a single type,
        /// <see cref="Type"/> can be used instead.
        /// </para>
        /// </remarks>
        public List<string>? Types { get; set; }

        /// <summary>
        /// The endpoint URL for this service when a simple string endpoint is sufficient.
        /// </summary>
        /// <remarks>
        /// <para>
        /// The value must be a valid URL conforming to the URL Standard. For more complex
        /// endpoint configurations, use <see cref="ServiceEndpointMap"/> or
        /// <see cref="ServiceEndpoints"/> instead.
        /// </para>
        /// <para>
        /// See <see href="https://www.w3.org/TR/cid-1.0/#services">CID 1.0 §2.1.4 Services</see>.
        /// </para>
        /// </remarks>
        public string? ServiceEndpoint { get; set; }

        /// <summary>
        /// A structured service endpoint when the endpoint requires additional properties.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Use this property when the service endpoint needs to express structured data
        /// beyond a simple URL. The map contents are service-type specific.
        /// </para>
        /// <para>
        /// For example, an encrypted messaging service might express how to initiate
        /// the encrypted link before messaging begins.
        /// </para>
        /// </remarks>
        public IDictionary<string, object>? ServiceEndpointMap { get; set; }

        /// <summary>
        /// Multiple service endpoints when the service is available at several locations.
        /// </summary>
        /// <remarks>
        /// <para>
        /// The value is a set composed of one or more strings (URLs) and/or maps.
        /// Use this property when the service has multiple endpoints.
        /// </para>
        /// </remarks>
        public List<object>? ServiceEndpoints { get; set; }

        /// <summary>
        /// Additional properties as defined by the specific service type.
        /// </summary>
        public IDictionary<string, object>? AdditionalData { get; set; }


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public bool Equals(Service? other)
        {
            if(other is null)
            {
                return false;
            }

            if(ReferenceEquals(this, other))
            {
                return true;
            }

            return Equals(Id, other.Id)
                && string.Equals(Type, other.Type, StringComparison.Ordinal)
                && string.Equals(ServiceEndpoint, other.ServiceEndpoint, StringComparison.Ordinal);
        }


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public override bool Equals([NotNullWhen(true)] object? obj) => obj is Service service && Equals(service);


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public override int GetHashCode()
        {
            var hash = new HashCode();
            hash.Add(Id);
            hash.Add(Type);
            hash.Add(ServiceEndpoint);

            return hash.ToHashCode();
        }


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static bool operator ==(Service? left, Service? right)
        {
            if(left is null)
            {
                return right is null;
            }

            return left.Equals(right);
        }


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static bool operator !=(Service? left, Service? right) => !(left == right);
    }
}