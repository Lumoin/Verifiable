using System.ComponentModel;
using System.Diagnostics;

namespace Verifiable.JCose.Sd;

/// <summary>
/// A selective disclosure token containing an issuer-signed payload and disclosures.
/// </summary>
/// <typeparam name="TEnvelope">
/// The envelope type: <see cref="string"/> for SD-JWT, <see cref="ReadOnlyMemory{T}"/>
/// of <see cref="byte"/> for SD-CWT.
/// </typeparam>
/// <remarks>
/// <para>
/// <strong>Token Structure:</strong>
/// </para>
/// <code>
/// ┌─────────────────────────────────────────────────────────────────────────┐
/// │                           SdToken Structure                             │
/// ├─────────────────────────────────────────────────────────────────────────┤
/// │                                                                         │
/// │  ┌──────────────────┐   ┌─────────────┐   ┌─────────────────────────┐  │
/// │  │  IssuerSigned    │ + │ Disclosures │ + │ KeyBinding (optional)   │  │
/// │  │  (JWT or CWT)    │   │ [D1,D2,...] │   │ (KB-JWT or KB-CWT)      │  │
/// │  └──────────────────┘   └─────────────┘   └─────────────────────────┘  │
/// │                                                                         │
/// └─────────────────────────────────────────────────────────────────────────┘
/// </code>
/// <para>
/// <strong>Wire Format (SD-JWT):</strong>
/// </para>
/// <code>
/// Without key binding: &lt;issuer-jwt&gt;~&lt;disclosure1&gt;~&lt;disclosure2&gt;~...~
/// With key binding:    &lt;issuer-jwt&gt;~&lt;disclosure1&gt;~&lt;disclosure2&gt;~...~&lt;kb-jwt&gt;
/// </code>
/// <para>
/// <strong>Selective Disclosure Flow:</strong>
/// </para>
/// <code>
///                        ┌─────────┐
///                        │ Issuer  │
///                        └────┬────┘
///                             │ Issues SD token with all disclosures
///                             ▼
///                        ┌─────────┐
///                        │ Holder  │
///                        └────┬────┘
///                             │ Selects subset of disclosures
///                             │ Optionally adds key binding
///                             ▼
///                        ┌─────────┐
///                        │Verifier │
///                        └─────────┘
/// </code>
/// <para>
/// <strong>Usage:</strong>
/// </para>
/// <list type="bullet">
/// <item><description>SD-JWT: <c>SdToken&lt;string&gt;</c> where <see cref="IssuerSigned"/> is the compact JWT serialization.</description></item>
/// <item><description>SD-CWT: <c>SdToken&lt;ReadOnlyMemory&lt;byte&gt;&gt;</c> where <see cref="IssuerSigned"/> is the COSE_Sign1 bytes.</description></item>
/// </list>
/// <para>
/// <strong>Thread Safety:</strong> This class is immutable and thread-safe.
/// </para>
/// </remarks>
/// <example>
/// <code>
/// //Create an SD-JWT token.
/// var disclosures = new[] { givenNameDisclosure, familyNameDisclosure };
/// var token = new SdToken&lt;string&gt;(issuerJwt, disclosures);
///
/// //Create an SD-CWT token.
/// var cwtToken = new SdToken&lt;ReadOnlyMemory&lt;byte&gt;&gt;(coseSign1Bytes, disclosures);
///
/// //Select disclosures for presentation.
/// var presentation = token.SelectDisclosures(d => d.ClaimName == "given_name");
///
/// //Add key binding.
/// var bound = token.WithKeyBinding(keyBindingJwt);
/// </code>
/// </example>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public class SdToken<TEnvelope>: IEquatable<SdToken<TEnvelope>> where TEnvelope : notnull
{
    /// <summary>
    /// The issuer-signed payload (JWT string or CWT bytes).
    /// </summary>
    /// <remarks>
    /// For SD-JWT, this is the compact serialization of the JWT (header.payload.signature).
    /// For SD-CWT, this is the CBOR-encoded COSE_Sign1 bytes.
    /// </remarks>
    public TEnvelope IssuerSigned { get; }

    /// <summary>
    /// The disclosures included in this token.
    /// </summary>
    /// <remarks>
    /// For issuance, this contains all disclosures.
    /// For presentation, this contains only the selected disclosures.
    /// </remarks>
    public IReadOnlyList<SdDisclosure> Disclosures { get; }

    /// <summary>
    /// The key binding proof, or <c>null</c> if not present.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Key binding proves possession of a private key corresponding to a public key
    /// embedded in the issuer-signed payload (in the <c>cnf</c> claim).
    /// </para>
    /// <para>
    /// For SD-JWT, this is a KB-JWT (typ: kb+jwt).
    /// For SD-CWT, this is a KB-CWT.
    /// </para>
    /// </remarks>
    public TEnvelope? KeyBinding { get; }

    /// <summary>
    /// Whether this token has key binding.
    /// </summary>
    public bool HasKeyBinding => KeyBinding is not null;


    /// <summary>
    /// Creates a new selective disclosure token.
    /// </summary>
    /// <param name="issuerSigned">The issuer-signed payload.</param>
    /// <param name="disclosures">The disclosures.</param>
    /// <param name="keyBinding">Optional key binding proof.</param>
    public SdToken(TEnvelope issuerSigned, IReadOnlyList<SdDisclosure> disclosures, TEnvelope? keyBinding = default)
    {
        ArgumentNullException.ThrowIfNull(issuerSigned);
        ArgumentNullException.ThrowIfNull(disclosures);

        IssuerSigned = issuerSigned;
        Disclosures = disclosures;
        KeyBinding = keyBinding;
    }


    /// <summary>
    /// Creates a new token with a subset of disclosures.
    /// </summary>
    /// <param name="selector">Function to select which disclosures to include.</param>
    /// <returns>A new token with only the selected disclosures.</returns>
    /// <remarks>
    /// The issuer-signed payload is preserved. Key binding is removed since
    /// it would need to be recomputed for the new disclosure set.
    /// </remarks>
    public SdToken<TEnvelope> SelectDisclosures(Func<SdDisclosure, bool> selector)
    {
        ArgumentNullException.ThrowIfNull(selector);

        var selected = Disclosures.Where(selector).ToList();
        return new SdToken<TEnvelope>(IssuerSigned, selected);
    }


    /// <summary>
    /// Creates a new token with the specified disclosures.
    /// </summary>
    /// <param name="disclosures">The disclosures to include.</param>
    /// <returns>A new token with the specified disclosures.</returns>
    /// <exception cref="ArgumentException">
    /// Thrown when a disclosure is not present in this token.
    /// </exception>
    public SdToken<TEnvelope> SelectDisclosures(IEnumerable<SdDisclosure> disclosures)
    {
        ArgumentNullException.ThrowIfNull(disclosures);

        var selected = disclosures.ToList();

        foreach(SdDisclosure disclosure in selected)
        {
            if(!Disclosures.Contains(disclosure))
            {
                throw new ArgumentException(
                    $"Disclosure not present in token: {disclosure}",
                    nameof(disclosures));
            }
        }

        return new SdToken<TEnvelope>(IssuerSigned, selected);
    }


    /// <summary>
    /// Creates a new token with key binding attached.
    /// </summary>
    /// <param name="keyBinding">The key binding proof.</param>
    /// <returns>A new token with key binding.</returns>
    public SdToken<TEnvelope> WithKeyBinding(TEnvelope keyBinding)
    {
        ArgumentNullException.ThrowIfNull(keyBinding);

        return new SdToken<TEnvelope>(IssuerSigned, Disclosures, keyBinding);
    }


    /// <summary>
    /// Creates a new token without key binding.
    /// </summary>
    /// <returns>A new token without key binding.</returns>
    public SdToken<TEnvelope> WithoutKeyBinding()
    {
        return new SdToken<TEnvelope>(IssuerSigned, Disclosures);
    }


    private string DebuggerDisplay =>
        HasKeyBinding
            ? $"SdToken+KB: {Disclosures.Count} disclosures"
            : $"SdToken: {Disclosures.Count} disclosures";


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(SdToken<TEnvelope>? other)
    {
        if(other is null)
        {
            return false;
        }

        if(ReferenceEquals(this, other))
        {
            return true;
        }

        if(!EqualityComparer<TEnvelope>.Default.Equals(IssuerSigned, other.IssuerSigned))
        {
            return false;
        }

        if(!EqualityComparer<TEnvelope?>.Default.Equals(KeyBinding, other.KeyBinding))
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


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals(object? obj) => obj is SdToken<TEnvelope> other && Equals(other);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.Add(IssuerSigned);
        hash.Add(KeyBinding);

        foreach(SdDisclosure disclosure in Disclosures)
        {
            hash.Add(disclosure);
        }

        return hash.ToHashCode();
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(SdToken<TEnvelope>? left, SdToken<TEnvelope>? right) =>
        left is null ? right is null : left.Equals(right);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(SdToken<TEnvelope>? left, SdToken<TEnvelope>? right) => !(left == right);
}