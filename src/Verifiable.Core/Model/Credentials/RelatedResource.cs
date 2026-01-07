using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Core.Model.Credentials;

/// <summary>
/// Represents a related resource with integrity protection as defined in the W3C
/// Verifiable Credentials Data Model v2.0 specification.
/// </summary>
/// <remarks>
/// <para>
/// Related resources enable credentials to reference external content while ensuring
/// that content has not been modified since the credential was issued. This is useful
/// for including images, documents, or other data that should not change after issuance.
/// </para>
/// <para>
/// Integrity protection is provided through cryptographic digests. Verifiers can
/// retrieve the resource and verify that its digest matches the one in the credential.
/// </para>
/// <para>
/// See <see href="https://www.w3.org/TR/vc-data-model-2.0/#integrity-of-related-resources">
/// VC Data Model 2.0 §5.3 Integrity of Related Resources</see>.
/// </para>
/// </remarks>
[DebuggerDisplay("RelatedResource(Id = {Id}, MediaType = {MediaType})")]
public class RelatedResource: IEquatable<RelatedResource>
{
    /// <summary>
    /// The URL of the related resource.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The URL where the resource can be retrieved. Verifiers dereference this URL
    /// to obtain the resource content for integrity verification.
    /// </para>
    /// </remarks>
    public required string Id { get; set; }

    /// <summary>
    /// A cryptographic digest of the resource content using Subresource Integrity format.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The value is a Subresource Integrity (SRI) string containing the digest algorithm
    /// and base64-encoded hash value (e.g., <c>sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC</c>).
    /// </para>
    /// <para>
    /// Either <see cref="DigestSRI"/> or <see cref="DigestMultibase"/> should be present
    /// to enable integrity verification.
    /// </para>
    /// </remarks>
    public string? DigestSRI { get; set; }

    /// <summary>
    /// A cryptographic digest of the resource content using multibase-encoded multihash format.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The value is a multibase-encoded multihash string that includes both the hash
    /// algorithm identifier and the digest value in a self-describing format.
    /// </para>
    /// <para>
    /// Either <see cref="DigestSRI"/> or <see cref="DigestMultibase"/> should be present
    /// to enable integrity verification.
    /// </para>
    /// </remarks>
    public string? DigestMultibase { get; set; }

    /// <summary>
    /// The media type of the related resource.
    /// </summary>
    /// <remarks>
    /// <para>
    /// An IANA media type (e.g., <c>image/png</c>, <c>application/pdf</c>) indicating
    /// the format of the resource. This helps verifiers and applications handle the
    /// resource appropriately.
    /// </para>
    /// </remarks>
    public string? MediaType { get; set; }

    /// <summary>
    /// Additional properties for the related resource.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Allows additional metadata about the resource as defined by the credential's
    /// JSON-LD context.
    /// </para>
    /// </remarks>
    public IDictionary<string, object>? AdditionalData { get; set; }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(RelatedResource? other)
    {
        if(other is null)
        {
            return false;
        }

        if(ReferenceEquals(this, other))
        {
            return true;
        }

        return string.Equals(Id, other.Id, StringComparison.Ordinal)
            && string.Equals(DigestSRI, other.DigestSRI, StringComparison.Ordinal)
            && string.Equals(DigestMultibase, other.DigestMultibase, StringComparison.Ordinal)
            && string.Equals(MediaType, other.MediaType, StringComparison.Ordinal);
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) =>
        obj is RelatedResource other && Equals(other);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.Add(Id, StringComparer.Ordinal);
        hash.Add(DigestSRI, StringComparer.Ordinal);
        hash.Add(DigestMultibase, StringComparer.Ordinal);
        hash.Add(MediaType, StringComparer.Ordinal);
        return hash.ToHashCode();
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(RelatedResource? left, RelatedResource? right)
    {
        if(left is null)
        {
            return right is null;
        }

        return left.Equals(right);
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(RelatedResource? left, RelatedResource? right) =>
        !(left == right);
}