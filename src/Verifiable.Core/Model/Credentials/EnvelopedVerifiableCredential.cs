using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Core.Model.Common;

namespace Verifiable.Core.Model.Credentials;

/// <summary>
/// Wraps an enveloping-secured Verifiable Credential for inclusion in a
/// <see cref="VerifiablePresentation"/>, per W3C VC Data Model 2.0.
/// </summary>
/// <remarks>
/// <para>
/// An enveloping-secured credential (JOSE, COSE, SD-JWT, SD-CWT) is an opaque secured
/// string, not a JSON-LD credential object. To carry it inside a presentation's
/// <c>verifiableCredential</c> array, VC-DM 2.0 defines this type: its <see cref="Id"/>
/// is a <c>data:</c> URL (RFC 2397) whose media type identifies the securing format and
/// whose body is the secured credential, and its <see cref="Type"/> is
/// <c>"EnvelopedVerifiableCredential"</c>.
/// </para>
/// <para>
/// See <see href="https://www.w3.org/TR/vc-data-model-2.0/#enveloped-verifiable-credentials">
/// VC-DM 2.0 §4.13 Verifiable Presentations, "Enveloped Verifiable Credentials"</see>.
/// </para>
/// </remarks>
[DebuggerDisplay("EnvelopedVerifiableCredential(Id = {Id})")]
public sealed class EnvelopedVerifiableCredential: IEquatable<EnvelopedVerifiableCredential>
{
    /// <summary>
    /// The JSON-LD context. Per VC-DM 2.0 the object's <c>@context</c> MUST be present
    /// and include a context that defines the <c>id</c>, <c>type</c>, and
    /// <c>EnvelopedVerifiableCredential</c> terms, such as
    /// <see cref="Common.Context.Credentials20"/>. When this object rides inside a
    /// presentation's <c>verifiableCredential</c> array the member is still emitted —
    /// the requirement is on the object itself.
    /// </summary>
    public Context? Context { get; set; }

    /// <summary>
    /// The <c>data:</c> URL (RFC 2397) carrying the enveloping-secured credential,
    /// for example <c>data:application/vc+jwt,&lt;compact-jws&gt;</c>.
    /// </summary>
    public string? Id { get; set; }

    /// <summary>
    /// The credential type, which must include <c>"EnvelopedVerifiableCredential"</c>.
    /// </summary>
    public List<string>? Type { get; set; }


    /// <summary>
    /// Equality is identity-based on <see cref="Id"/> (the <c>data:</c> URL, which embeds the
    /// enveloped bytes and so is unique per secured payload) and <see cref="Context"/>. RFC 2397
    /// embeds a <c>data:</c> URL's content directly in the URL body rather than by reference, so
    /// <see cref="Id"/> alone already carries the entire enveloping-secured credential: two
    /// instances with the same <see cref="Id"/> cannot differ in the bytes they envelope. This
    /// covers the enveloped payload; <see cref="Type"/> is not additionally consulted because
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#enveloped-verifiable-credentials">
    /// VC-DM 2.0 §4.13 Verifiable Presentations, "Enveloped Verifiable Credentials"</see> fixes it
    /// to the single value <c>"EnvelopedVerifiableCredential"</c> ("The type value of the object
    /// MUST be <c>EnvelopedVerifiableCredential</c>.") for every conformant instance of this type,
    /// so a conformant document carries no content in <see cref="Type"/> that <see cref="Id"/> does
    /// not already determine.
    /// </summary>
    /// <param name="other">The instance to compare against.</param>
    /// <returns><see langword="true"/> if the instances are equal; otherwise <see langword="false"/>.</returns>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(EnvelopedVerifiableCredential? other)
    {
        if(other is null)
        {
            return false;
        }

        if(ReferenceEquals(this, other))
        {
            return true;
        }

        return Equals(Context, other.Context) && string.Equals(Id, other.Id, StringComparison.Ordinal);
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) =>
        obj is EnvelopedVerifiableCredential other && Equals(other);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.Add(Context);
        hash.Add(Id, StringComparer.Ordinal);

        return hash.ToHashCode();
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(EnvelopedVerifiableCredential? left, EnvelopedVerifiableCredential? right)
    {
        if(left is null)
        {
            return right is null;
        }

        return left.Equals(right);
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(EnvelopedVerifiableCredential? left, EnvelopedVerifiableCredential? right) => !(left == right);
}
