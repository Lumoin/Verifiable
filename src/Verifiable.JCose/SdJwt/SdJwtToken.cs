using System.ComponentModel;
using System.Diagnostics;

namespace Verifiable.Jose.SdJwt;

/// <summary>
/// Represents a parsed SD-JWT, consisting of an Issuer-signed JWT and zero or more disclosures.
/// </summary>
/// <remarks>
/// <para>
/// The SD-JWT format is: <c>&lt;Issuer-signed JWT&gt;~&lt;D.1&gt;~&lt;D.2&gt;~...~&lt;D.N&gt;~</c>
/// </para>
/// <para>
/// Note the trailing tilde character, which distinguishes an SD-JWT from an SD-JWT+KB.
/// </para>
/// <para>
/// See <see href="https://www.rfc-editor.org/rfc/rfc9901.html#section-4">RFC 9901 Section 4</see>.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class SdJwtToken: IEquatable<SdJwtToken>
{
    /// <summary>
    /// Gets the Issuer-signed JWT (the first component before the first tilde).
    /// </summary>
    public string IssuerSignedJwt { get; }

    /// <summary>
    /// Gets the list of disclosures included in this SD-JWT.
    /// </summary>
    public IReadOnlyList<Disclosure> Disclosures { get; }

    /// <summary>
    /// Gets the Key Binding JWT if present, otherwise null.
    /// </summary>
    /// <remarks>
    /// When present, this transforms the SD-JWT into an SD-JWT+KB.
    /// </remarks>
    public string? KeyBindingJwt { get; }

    /// <summary>
    /// Gets a value indicating whether this is an SD-JWT+KB (has Key Binding).
    /// </summary>
    public bool HasKeyBinding => KeyBindingJwt is not null;


    /// <summary>
    /// Initializes a new instance of the <see cref="SdJwtToken"/> class.
    /// </summary>
    /// <param name="issuerSignedJwt">The Issuer-signed JWT.</param>
    /// <param name="disclosures">The list of disclosures.</param>
    /// <param name="keyBindingJwt">The optional Key Binding JWT.</param>
    public SdJwtToken(string issuerSignedJwt, IReadOnlyList<Disclosure> disclosures, string? keyBindingJwt = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(issuerSignedJwt, nameof(issuerSignedJwt));
        ArgumentNullException.ThrowIfNull(disclosures, nameof(disclosures));

        IssuerSignedJwt = issuerSignedJwt;
        Disclosures = disclosures;
        KeyBindingJwt = keyBindingJwt;
    }


    private string DebuggerDisplay =>
        HasKeyBinding
            ? $"SD-JWT+KB: {Disclosures.Count} disclosures"
            : $"SD-JWT: {Disclosures.Count} disclosures";


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(SdJwtToken? other)
    {
        if(other is null)
        {
            return false;
        }

        if(ReferenceEquals(this, other))
        {
            return true;
        }

        if(!string.Equals(IssuerSignedJwt, other.IssuerSignedJwt, StringComparison.Ordinal))
        {
            return false;
        }

        if(!string.Equals(KeyBindingJwt, other.KeyBindingJwt, StringComparison.Ordinal))
        {
            return false;
        }

        if(Disclosures.Count != other.Disclosures.Count)
        {
            return false;
        }

        for(int i = 0; i < Disclosures.Count; i++)
        {
            if(!Disclosures[i].Equals(other.Disclosures[i]))
            {
                return false;
            }
        }

        return true;
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals(object? obj) => obj is SdJwtToken other && Equals(other);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.Add(IssuerSignedJwt, StringComparer.Ordinal);
        hash.Add(KeyBindingJwt, StringComparer.Ordinal);

        foreach(Disclosure disclosure in Disclosures)
        {
            hash.Add(disclosure);
        }

        return hash.ToHashCode();
    }


    /// <summary>
    /// Returns a string representation of this SD-JWT token.
    /// </summary>
    public override string ToString() => this.Serialize();


    /// <summary>
    /// Equality operator.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(SdJwtToken? left, SdJwtToken? right) =>
        left is null ? right is null : left.Equals(right);


    /// <summary>
    /// Inequality operator.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(SdJwtToken? left, SdJwtToken? right) => !(left == right);
}