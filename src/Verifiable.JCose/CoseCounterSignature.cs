using System.Diagnostics;
using System.Linq;
using Verifiable.Cryptography;

namespace Verifiable.JCose;

/// <summary>
/// Closed-sum discriminator for a version 2 countersignature per
/// <see href="https://www.rfc-editor.org/rfc/rfc9338#section-3">RFC 9338 §3</see> — the full
/// <see cref="CounterSignatureV2"/> or a <see cref="CounterSignatureV2Sequence"/> of several (both
/// COSE header label <see cref="CoseHeaderParameters.CounterSignatureVersion2"/>, 11 — RFC 9338 §2
/// Table 1 types the label's value as <c>COSE_Countersignature / [+ COSE_Countersignature]</c>), or
/// the abbreviated <see cref="CounterSignature0V2"/> (COSE header label
/// <see cref="CoseHeaderParameters.Countersignature0Version2"/>, 12) form.
/// </summary>
/// <remarks>
/// <see href="https://www.rfc-editor.org/rfc/rfc9338#section-3.1">RFC 9338 §3.1</see>: "The
/// structures cannot be converted between each other; as the signature computation includes
/// a parameter identifying which structure is being used, the converted structure will fail
/// signature validation." The two sibling shapes are therefore modeled as distinct types
/// rather than one type with an optional-headers flag, so the shape a caller holds already
/// states which of the two it is.
/// </remarks>
public abstract class CoseCounterSignature: IDisposable
{
    /// <summary>Restricts direct subtyping to the sibling classes declared in this file.</summary>
    private protected CoseCounterSignature()
    {
    }


    /// <summary>Disposes whatever carrier the case holds.</summary>
    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }


    /// <summary>
    /// Disposes whatever carrier the case holds when <paramref name="disposing"/> is <see langword="true"/>.
    /// </summary>
    /// <param name="disposing">Whether managed state is being released.</param>
    /// <remarks>
    /// The hierarchy is closed by the constructor above and no case holds an unmanaged resource, so this exists
    /// to give each case one place to release its carrier rather than to support a finalizer.
    /// </remarks>
    protected abstract void Dispose(bool disposing);
}


/// <summary>
/// The full version 2 countersignature (COSE header label 11) — structurally a
/// <c>COSE_Signature</c> per
/// <see href="https://www.rfc-editor.org/rfc/rfc9338#section-3.1">RFC 9338 §3.1</see>:
/// "The COSE_Countersignature structure allows for the same set of capabilities as a
/// COSE_Signature. [...] COSE_Countersignature = COSE_Signature" — a straight type alias, so
/// this wraps the existing <see cref="CoseSignatureComponent"/> shape rather than
/// re-declaring its protected/unprotected/signature fields.
/// </summary>
/// <remarks>
/// <para>
/// Full countersignatures can themselves carry protected and unprotected attributes and can
/// be chained (countersigning a countersignature) — RFC 9338 §3.1: "This also means that the
/// countersignature can itself be countersigned."
/// </para>
/// <para>
/// <strong>Ownership:</strong> owns <see cref="Component"/>; disposing this instance disposes
/// it and, transitively, its own protected-header and signature carriers.
/// </para>
/// </remarks>
[DebuggerDisplay("CounterSignatureV2: {Component}")]
public sealed class CounterSignatureV2: CoseCounterSignature, IEquatable<CounterSignatureV2>
{
    private bool disposed;


    /// <summary>
    /// Initializes a new instance of the <see cref="CounterSignatureV2"/> class. Ownership of
    /// <paramref name="component"/> transfers to this instance.
    /// </summary>
    /// <param name="component">
    /// The COSE_Signature-shaped countersignature content (protected header, unprotected
    /// header, signature value).
    /// </param>
    public CounterSignatureV2(CoseSignatureComponent component)
    {
        ArgumentNullException.ThrowIfNull(component);

        Component = component;
    }


    /// <summary>
    /// Gets the COSE_Signature-shaped countersignature content. Owned by this instance;
    /// disposed via <see cref="Dispose"/>.
    /// </summary>
    public CoseSignatureComponent Component { get; }

    /// <summary>
    /// Gets this countersignature's OWN raw, undecoded protected-header wire bytes
    /// (<see cref="CoseSignatureComponent.ProtectedHeader"/> — a convenience passthrough, since a full
    /// countersignature carries its own <c>COSE_Signature</c>-shaped protected header, distinct from the
    /// target it countersigns). Owned by <see cref="Component"/>; disposed via <see cref="Dispose"/>.
    /// </summary>
    public EncodedCoseProtectedHeader ProtectedHeader => Component.ProtectedHeader;


    /// <summary>Disposes <see cref="Component"/>.</summary>
    /// <param name="disposing">Whether managed state is being released.</param>
    protected override void Dispose(bool disposing)
    {
        if(disposed)
        {
            return;
        }

        if(disposing)
        {
            Component.Dispose();
        }

        disposed = true;
    }


    /// <inheritdoc/>
    public bool Equals(CounterSignatureV2? other) => other is not null && (ReferenceEquals(this, other) || Component.Equals(other.Component));


    /// <inheritdoc/>
    public override bool Equals(object? obj) => Equals(obj as CounterSignatureV2);


    /// <inheritdoc/>
    public override int GetHashCode() => Component.GetHashCode();


    /// <summary>Equality operator.</summary>
    public static bool operator ==(CounterSignatureV2? left, CounterSignatureV2? right) => left is null ? right is null : left.Equals(right);


    /// <summary>Inequality operator.</summary>
    public static bool operator !=(CounterSignatureV2? left, CounterSignatureV2? right) => !(left == right);
}


/// <summary>
/// The abbreviated version 2 countersignature (COSE header label 12) — per
/// <see href="https://www.rfc-editor.org/rfc/rfc9338#section-3.2">RFC 9338 §3.2</see>:
/// "COSE_Countersignature0 = bstr" — no protected or unprotected attributes of its own; "the
/// parameters for computing or verifying the abbreviated countersignature are provided by the
/// same context used to describe the encryption, signature, or MAC processing."
/// </summary>
/// <remarks>
/// <strong>Ownership:</strong> owns <see cref="Value"/>; disposing this instance disposes it.
/// </remarks>
[DebuggerDisplay("CounterSignature0V2: {Value}")]
public sealed class CounterSignature0V2: CoseCounterSignature, IEquatable<CounterSignature0V2>
{
    private bool disposed;


    /// <summary>
    /// Initializes a new instance of the <see cref="CounterSignature0V2"/> class. Ownership of
    /// <paramref name="value"/> transfers to this instance.
    /// </summary>
    /// <param name="value">The signature value bytes.</param>
    public CounterSignature0V2(Signature value)
    {
        ArgumentNullException.ThrowIfNull(value);

        Value = value;
    }


    /// <summary>
    /// Gets the signature value. Owned by this instance; disposed via <see cref="Dispose"/>.
    /// </summary>
    public Signature Value { get; }


    /// <summary>Disposes <see cref="Value"/>.</summary>
    /// <param name="disposing">Whether managed state is being released.</param>
    protected override void Dispose(bool disposing)
    {
        if(disposed)
        {
            return;
        }

        if(disposing)
        {
            Value.Dispose();
        }

        disposed = true;
    }


    /// <inheritdoc/>
    public bool Equals(CounterSignature0V2? other) => other is not null && (ReferenceEquals(this, other) || Value.Equals(other.Value));


    /// <inheritdoc/>
    public override bool Equals(object? obj) => Equals(obj as CounterSignature0V2);


    /// <inheritdoc/>
    public override int GetHashCode() => Value.GetHashCode();


    /// <summary>Equality operator.</summary>
    public static bool operator ==(CounterSignature0V2? left, CounterSignature0V2? right) => left is null ? right is null : left.Equals(right);


    /// <summary>Inequality operator.</summary>
    public static bool operator !=(CounterSignature0V2? left, CounterSignature0V2? right) => !(left == right);
}


/// <summary>
/// One or more full version 2 countersignatures (COSE header label 11) carried together —
/// the <c>[+ COSE_Countersignature]</c> array arm of
/// <see href="https://www.rfc-editor.org/rfc/rfc9338#section-2">RFC 9338 §2 Table 1</see>'s
/// value type union for that label: "<c>COSE_Countersignature / [+ COSE_Countersignature]</c>".
/// A message with several independent countersigners uses this shape; a lone countersigner
/// uses the sibling single-value <see cref="CounterSignatureV2"/> shape instead — both decode
/// from the SAME header label, so a caller distinguishes them structurally, not by label.
/// </summary>
/// <remarks>
/// <strong>Ownership:</strong> owns every element of <see cref="Countersignatures"/>; disposing
/// this instance disposes each.
/// </remarks>
[DebuggerDisplay("CounterSignatureV2Sequence: {Countersignatures.Count} elements")]
public sealed class CounterSignatureV2Sequence: CoseCounterSignature, IEquatable<CounterSignatureV2Sequence>
{
    private bool disposed;


    /// <summary>
    /// Initializes a new instance of the <see cref="CounterSignatureV2Sequence"/> class. Ownership of
    /// every element of <paramref name="countersignatures"/> transfers to this instance.
    /// </summary>
    /// <param name="countersignatures">The countersignatures carried together, in wire order.</param>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="countersignatures"/> is empty — RFC 9338 §2 Table 1's
    /// <c>[+ COSE_Countersignature]</c> CDDL requires at least one element.
    /// </exception>
    public CounterSignatureV2Sequence(IReadOnlyList<CounterSignatureV2> countersignatures)
    {
        ArgumentNullException.ThrowIfNull(countersignatures);
        if(countersignatures.Count == 0)
        {
            throw new ArgumentException(
                "A CounterSignatureV2Sequence requires at least one element (RFC 9338 §2 Table 1, [+ COSE_Countersignature]).",
                nameof(countersignatures));
        }

        Countersignatures = countersignatures;
    }


    /// <summary>
    /// Gets the countersignatures carried together, in wire order. Owned by this instance;
    /// disposed via <see cref="Dispose"/>.
    /// </summary>
    public IReadOnlyList<CounterSignatureV2> Countersignatures { get; }


    /// <summary>Disposes every element of <see cref="Countersignatures"/>.</summary>
    /// <param name="disposing">Whether managed state is being released.</param>
    protected override void Dispose(bool disposing)
    {
        if(disposed)
        {
            return;
        }

        if(disposing)
        {
            foreach(CounterSignatureV2 countersignature in Countersignatures)
            {
                countersignature.Dispose();
            }
        }

        disposed = true;
    }


    /// <inheritdoc/>
    public bool Equals(CounterSignatureV2Sequence? other)
    {
        if(other is null)
        {
            return false;
        }

        if(ReferenceEquals(this, other))
        {
            return true;
        }

        return Countersignatures.SequenceEqual(other.Countersignatures);
    }


    /// <inheritdoc/>
    public override bool Equals(object? obj) => Equals(obj as CounterSignatureV2Sequence);


    /// <inheritdoc/>
    public override int GetHashCode()
    {
        var hash = new HashCode();

        foreach(CounterSignatureV2 countersignature in Countersignatures)
        {
            hash.Add(countersignature);
        }

        return hash.ToHashCode();
    }


    /// <summary>Equality operator.</summary>
    public static bool operator ==(CounterSignatureV2Sequence? left, CounterSignatureV2Sequence? right) => left is null ? right is null : left.Equals(right);


    /// <summary>Inequality operator.</summary>
    public static bool operator !=(CounterSignatureV2Sequence? left, CounterSignatureV2Sequence? right) => !(left == right);
}
