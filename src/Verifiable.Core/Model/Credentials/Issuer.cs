using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Core.Model.Credentials;

/// <summary>
/// Represents the issuer of a Verifiable Credential as defined in the W3C Verifiable
/// Credentials Data Model v2.0 specification.
/// </summary>
/// <remarks>
/// <para>
/// The issuer is the entity that creates and signs the credential, asserting the claims
/// within. Issuers are responsible for the accuracy and validity of the claims they make.
/// </para>
/// <para>
/// In the VC Data Model, the issuer can be expressed in two forms:
/// </para>
/// <list type="bullet">
/// <item><description>
/// <strong>Simple form:</strong> A URI string identifying the issuer.
/// </description></item>
/// <item><description>
/// <strong>Object form:</strong> An object containing an <c>id</c> property and
/// optional metadata such as <see cref="Name"/> and <see cref="Description"/>.
/// </description></item>
/// </list>
/// <para>
/// This class represents both forms. Serialization converters handle the polymorphic
/// nature transparently, outputting a simple string when only <see cref="Id"/> is set.
/// </para>
/// <para>
/// See <see href="https://www.w3.org/TR/vc-data-model-2.0/#issuer">VC Data Model 2.0 §4.7 Issuer</see>.
/// </para>
/// </remarks>
[DebuggerDisplay("Issuer(Id = {Id}, Name = {Name})")]
public class Issuer: IEquatable<Issuer>
{
    /// <summary>
    /// The unique identifier of the issuer.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This must be a URL. Typically a DID (e.g., <c>did:example:issuer</c>) or HTTPS URL
    /// that can be dereferenced to obtain the issuer's controlled identifier document
    /// containing verification methods for signature verification.
    /// </para>
    /// <para>
    /// See <see href="https://www.w3.org/TR/vc-data-model-2.0/#issuer">VC Data Model 2.0 §4.7 Issuer</see>.
    /// </para>
    /// </remarks>
    public required string Id { get; set; }

    /// <summary>
    /// An optional human-readable name for the issuer.
    /// </summary>
    /// <remarks>
    /// <para>
    /// See <see href="https://www.w3.org/TR/vc-data-model-2.0/#names-and-descriptions">
    /// VC Data Model 2.0 §4.6 Names and Descriptions</see>.
    /// </para>
    /// </remarks>
    public string? Name { get; set; }

    /// <summary>
    /// An optional human-readable description of the issuer.
    /// </summary>
    /// <remarks>
    /// <para>
    /// See <see href="https://www.w3.org/TR/vc-data-model-2.0/#names-and-descriptions">
    /// VC Data Model 2.0 §4.6 Names and Descriptions</see>.
    /// </para>
    /// </remarks>
    public string? Description { get; set; }

    /// <summary>
    /// An optional URL to an image representing the issuer.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Can be used for display purposes in credential wallets and verifier interfaces.
    /// </para>
    /// </remarks>
    public string? Image { get; set; }

    /// <summary>
    /// Additional properties about the issuer as defined by the JSON-LD context.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Allows arbitrary issuer metadata beyond the standard properties.
    /// </para>
    /// </remarks>
    public IDictionary<string, object>? AdditionalData { get; set; }


    /// <summary>
    /// Creates an <see cref="Issuer"/> from a URI string.
    /// </summary>
    /// <param name="id">The issuer URI.</param>
    /// <returns>An issuer instance with only the ID set.</returns>
    public static Issuer FromUri(string id) => new() { Id = id };


    /// <summary>
    /// Implicitly converts a string URI to an <see cref="Issuer"/>.
    /// </summary>
    /// <param name="id">The issuer URI.</param>
    public static implicit operator Issuer(string id) => FromUri(id);


    /// <summary>
    /// Implicitly converts an <see cref="Issuer"/> to its URI string.
    /// </summary>
    /// <param name="issuer">The issuer to convert.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="issuer"/> is null.</exception>
    public static implicit operator string(Issuer issuer)
    {
        ArgumentNullException.ThrowIfNull(issuer);

        return issuer.Id;
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(Issuer? other)
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
            && string.Equals(Name, other.Name, StringComparison.Ordinal)
            && string.Equals(Description, other.Description, StringComparison.Ordinal)
            && string.Equals(Image, other.Image, StringComparison.Ordinal);
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) => obj is Issuer other && Equals(other);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.Add(Id, StringComparer.Ordinal);
        hash.Add(Name, StringComparer.Ordinal);
        hash.Add(Description, StringComparer.Ordinal);
        hash.Add(Image, StringComparer.Ordinal);

        return hash.ToHashCode();
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(Issuer? left, Issuer? right)
    {
        if(left is null)
        {
            return right is null;
        }

        return left.Equals(right);
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(Issuer? left, Issuer? right) => !(left == right);
}