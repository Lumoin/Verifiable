using System.ComponentModel;

namespace Verifiable.JCose;

/// <summary>
/// The shared abstract base for the four JOSE-shaped dictionary types in this
/// library: <see cref="JwtHeader"/>, <see cref="JwtPayload"/>,
/// <see cref="UnverifiedJwtHeader"/>, and <see cref="UnverifiedJwtPayload"/>.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Design rationale.</strong>
/// The four leaves form a 2&#215;2 grid along two orthogonal axes:
/// </para>
/// <list type="bullet">
/// <item><description>
/// <em>Role</em> — <c>Header</c> versus <c>Payload</c>. The two roles carry
/// different content (algorithm metadata versus claims) and appear at
/// different positions in JWS and JWE compact forms. Distinct types prevent
/// accidental argument swapping at API boundaries: a function signed
/// <c>(JwtHeader header, JwtPayload payload)</c> cannot be miscalled with the
/// arguments reversed.
/// </description></item>
/// <item><description>
/// <em>Trust state</em> — <c>Verified</c> versus <c>Unverified</c>. The two
/// states differ in whether the enclosing JWS signature has been verified.
/// Distinct types prevent unverified material from flowing into code paths
/// that require verified material: a function signed
/// <c>(JwtHeader header)</c> rejects an <see cref="UnverifiedJwtHeader"/> at
/// compile time.
/// </description></item>
/// </list>
/// <para>
/// <strong>Why a shared base.</strong>
/// Before this base existed the four leaves duplicated identical scaffolding
/// — base constructors, hash code, the <see cref="object"/>-typed
/// <see cref="Equals(object)"/> override, equality operators. This base
/// absorbs the duplicable parts while preserving the type identities that
/// give the four leaves their compile-time guarantees.
/// </para>
/// <para>
/// <strong>Why trust state and role are <em>not</em> subtype axes.</strong>
/// A naive design might inherit <see cref="UnverifiedJwtHeader"/> from
/// <see cref="JwtHeader"/> ("an unverified header is a kind of header"). That
/// would defeat the trust-marker discipline: a function accepting
/// <see cref="JwtHeader"/> would accept <see cref="UnverifiedJwtHeader"/> via
/// subtype polymorphism, and the compile-time guarantee against trusting
/// unverified material would vanish. The same argument applies to header
/// versus payload. The four leaves are therefore <em>siblings</em> under this
/// base, not a subtype hierarchy.
/// </para>
/// <para>
/// <strong>Cross-type equality is asymmetric.</strong>
/// Two leaves of different concrete types must <em>not</em> compare equal,
/// even when their dictionary contents are identical. A
/// <see cref="JwtHeader"/> and an <see cref="UnverifiedJwtHeader"/> with the
/// same key-value pairs represent fundamentally different trust states; a
/// <see cref="JwtHeader"/> and a <see cref="JwtPayload"/> with the same
/// content represent fundamentally different roles. Each leaf overrides
/// <see cref="object.Equals(object)"/> to short-circuit on runtime type
/// identity; this base lifts <see cref="GetHashCode"/> (a hash collision
/// across types is harmless) but leaves typed equality to the leaves.
/// </para>
/// </remarks>
public abstract class JoseDictionary: Dictionary<string, object>
{
    /// <summary>
    /// Creates an empty JOSE dictionary.
    /// </summary>
    protected JoseDictionary(): base() { }

    /// <summary>
    /// Creates a JOSE dictionary with the specified initial capacity.
    /// </summary>
    /// <param name="capacity">The initial number of entries the dictionary can contain.</param>
    protected JoseDictionary(int capacity): base(capacity) { }

    /// <summary>
    /// Creates a JOSE dictionary populated from any key-value enumerable,
    /// including <see cref="Dictionary{TKey,TValue}"/>,
    /// <see cref="IReadOnlyDictionary{TKey,TValue}"/>, and
    /// <see cref="IDictionary{TKey,TValue}"/>.
    /// </summary>
    /// <param name="entries">The key-value pairs to copy.</param>
    protected JoseDictionary(IEnumerable<KeyValuePair<string, object>> entries): base(entries) { }


    /// <summary>
    /// Returns the dictionary-content hash code shared across all
    /// <see cref="JoseDictionary"/> leaves. Hash collisions across leaf types
    /// are acceptable because hash equality is necessary but not sufficient
    /// for value equality; each leaf's typed
    /// <see cref="object.Equals(object)"/> short-circuits on runtime type
    /// identity.
    /// </summary>
    /// <returns>A hash code derived from the dictionary's entries.</returns>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => DictionaryEquality.GetDictionaryHashCode(this);
}
