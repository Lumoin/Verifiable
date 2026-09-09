using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Core.Model.Common;

namespace Verifiable.Core.Model.Credentials;

/// <summary>
/// Expresses an enveloping-secured Verifiable Presentation, per W3C VC Data Model 2.0.
/// </summary>
/// <remarks>
/// <para>
/// An enveloping-secured presentation (JOSE, COSE) is an opaque secured string, not a
/// JSON-LD presentation object. VC-DM 2.0 defines this type to express it: the
/// <see cref="Context"/> MUST be present and include a context (such as the base
/// context) defining the <c>id</c>, <c>type</c>, and
/// <c>EnvelopedVerifiablePresentation</c> terms; the <see cref="Id"/> MUST be a
/// <c>data:</c> URL (RFC 2397) expressing the secured presentation, for example
/// <c>data:application/vp+jwt,&lt;compact-jws&gt;</c>; and the <see cref="Type"/> MUST
/// be <c>"EnvelopedVerifiablePresentation"</c>.
/// </para>
/// <para>
/// See <see href="https://www.w3.org/TR/vc-data-model-2.0/#enveloped-verifiable-presentations">
/// VC-DM 2.0 §4.13 Verifiable Presentations, "Enveloped Verifiable Presentations"</see>.
/// </para>
/// </remarks>
[DebuggerDisplay("EnvelopedVerifiablePresentation(Id = {Id})")]
public sealed class EnvelopedVerifiablePresentation: IEquatable<EnvelopedVerifiablePresentation>
{
    /// <summary>
    /// The JSON-LD context. MUST be present and include a context that defines the
    /// <c>id</c>, <c>type</c>, and <c>EnvelopedVerifiablePresentation</c> terms,
    /// such as <see cref="Common.Context.Credentials20"/>.
    /// </summary>
    public Context? Context { get; set; }

    /// <summary>
    /// The <c>data:</c> URL (RFC 2397) carrying the enveloping-secured presentation,
    /// for example <c>data:application/vp+jwt,&lt;compact-jws&gt;</c>.
    /// </summary>
    public string? Id { get; set; }

    /// <summary>
    /// The type, which must be <c>"EnvelopedVerifiablePresentation"</c>.
    /// </summary>
    public List<string>? Type { get; set; }


    /// <summary>
    /// Equality is identity-based on <see cref="Id"/> (the <c>data:</c> URL, which embeds the
    /// enveloped bytes and so is unique per secured payload) and <see cref="Context"/>. RFC 2397
    /// embeds a <c>data:</c> URL's content directly in the URL body rather than by reference, so
    /// <see cref="Id"/> alone already carries the entire enveloping-secured presentation: two
    /// instances with the same <see cref="Id"/> cannot differ in the bytes they envelope. This
    /// covers the enveloped payload; <see cref="Type"/> is not additionally consulted because
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#enveloped-verifiable-presentations">
    /// VC-DM 2.0 §4.13 Verifiable Presentations, "Enveloped Verifiable Presentations"</see> fixes it
    /// to the single value <c>"EnvelopedVerifiablePresentation"</c> for every conformant instance of
    /// this type, so a conformant document carries no content in <see cref="Type"/> that
    /// <see cref="Id"/> does not already determine.
    /// </summary>
    /// <param name="other">The instance to compare against.</param>
    /// <returns><see langword="true"/> if the instances are equal; otherwise <see langword="false"/>.</returns>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(EnvelopedVerifiablePresentation? other)
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
        obj is EnvelopedVerifiablePresentation other && Equals(other);


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
    public static bool operator ==(EnvelopedVerifiablePresentation? left, EnvelopedVerifiablePresentation? right)
    {
        if(left is null)
        {
            return right is null;
        }

        return left.Equals(right);
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(EnvelopedVerifiablePresentation? left, EnvelopedVerifiablePresentation? right) => !(left == right);
}
