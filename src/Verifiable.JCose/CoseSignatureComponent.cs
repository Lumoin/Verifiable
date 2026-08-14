using System.Diagnostics;
using Verifiable.Cryptography;

namespace Verifiable.JCose;

/// <summary>
/// Represents one signer's <c>COSE_Signature</c> entry within a <c>COSE_Sign</c>
/// multi-signer message, per
/// <see href="https://www.rfc-editor.org/rfc/rfc9052#section-4.1">RFC 9052 §4.1</see>.
/// </summary>
/// <remarks>
/// <para>
/// COSE_Signature structure per RFC 9052:
/// </para>
/// <code>
/// COSE_Signature = [
///     protected : bstr,        ; Serialized signer-layer protected header
///     unprotected : header_map ; Signer-layer unprotected header
///     signature : bstr         ; Signature bytes
/// ]
/// </code>
/// <para>
/// <strong>Ownership:</strong> this component owns its <see cref="ProtectedHeader"/> (an
/// <see cref="EncodedCoseProtectedHeader"/> pool-rented carrier) and its
/// <see cref="Signature"/> (a <see cref="Verifiable.Cryptography.Signature"/> pool-rented
/// carrier). Disposing the component disposes both.
/// </para>
/// <para>
/// Mirrors <see cref="CoseSign1Message"/>'s raw-protected-header discipline: the signer's
/// protected header is carried as its exact wire bytes, never a re-encoded dictionary —
/// RFC 9052 §4.4's <c>sign_protected</c> Sig_structure field must be built from these exact
/// bytes for the signature to verify.
/// </para>
/// </remarks>
[DebuggerDisplay("CoseSignatureComponent: Signature={Signature.AsReadOnlySpan().Length} bytes")]
public sealed class CoseSignatureComponent: IEquatable<CoseSignatureComponent>, IDisposable
{
    private bool disposed;


    /// <summary>
    /// Initializes a new instance of the <see cref="CoseSignatureComponent"/> class.
    /// Ownership of <paramref name="protectedHeader"/> and <paramref name="signature"/>
    /// transfers to the component; disposing the component disposes both.
    /// </summary>
    /// <param name="protectedHeader">The signer's own serialized protected header carrier.</param>
    /// <param name="unprotectedHeader">The signer's own unprotected header map.</param>
    /// <param name="signature">The signature carrier.</param>
    public CoseSignatureComponent(
        EncodedCoseProtectedHeader protectedHeader,
        IReadOnlyDictionary<int, object>? unprotectedHeader,
        Signature signature)
    {
        ArgumentNullException.ThrowIfNull(protectedHeader);
        ArgumentNullException.ThrowIfNull(signature);

        ProtectedHeader = protectedHeader;
        UnprotectedHeader = unprotectedHeader;
        Signature = signature;
    }


    /// <summary>
    /// Gets the signer's own serialized protected header carrier. Owned by this component;
    /// disposed via <see cref="Dispose"/>.
    /// </summary>
    /// <remarks>
    /// Serialized as a CBOR map then wrapped as a bstr in the COSE_Signature array. RFC 9052
    /// §4.4's <c>sign_protected</c> Sig_structure field is built from these exact bytes, never
    /// a re-encoding.
    /// </remarks>
    public EncodedCoseProtectedHeader ProtectedHeader { get; }

    /// <summary>
    /// Gets the signer's own unprotected header as an integer-keyed dictionary.
    /// </summary>
    public IReadOnlyDictionary<int, object>? UnprotectedHeader { get; }

    /// <summary>
    /// Gets the signature carrier. Owned by this component; disposed via <see cref="Dispose"/>.
    /// </summary>
    public Signature Signature { get; }


    /// <inheritdoc/>
    public void Dispose()
    {
        if(disposed)
        {
            return;
        }

        ProtectedHeader.Dispose();
        Signature.Dispose();
        disposed = true;
    }


    /// <inheritdoc/>
    public bool Equals(CoseSignatureComponent? other)
    {
        if(other is null)
        {
            return false;
        }

        if(ReferenceEquals(this, other))
        {
            return true;
        }

        return ProtectedHeader.AsReadOnlySpan().SequenceEqual(other.ProtectedHeader.AsReadOnlySpan())
            && Signature.AsReadOnlySpan().SequenceEqual(other.Signature.AsReadOnlySpan());
    }


    /// <inheritdoc/>
    public override bool Equals(object? obj) => Equals(obj as CoseSignatureComponent);


    /// <inheritdoc/>
    public override int GetHashCode()
    {
        var hash = new HashCode();

        foreach(byte b in ProtectedHeader.AsReadOnlySpan())
        {
            hash.Add(b);
        }

        ReadOnlySpan<byte> signatureSpan = Signature.AsReadOnlySpan();
        foreach(byte b in signatureSpan.Slice(0, Math.Min(16, signatureSpan.Length)))
        {
            hash.Add(b);
        }

        return hash.ToHashCode();
    }


    /// <summary>Equality operator.</summary>
    public static bool operator ==(CoseSignatureComponent? left, CoseSignatureComponent? right) => left is null ? right is null : left.Equals(right);


    /// <summary>Inequality operator.</summary>
    public static bool operator !=(CoseSignatureComponent? left, CoseSignatureComponent? right) => !(left == right);
}
