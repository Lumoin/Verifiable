using System;
using System.Diagnostics;
using Verifiable.Cryptography.Context;

namespace Verifiable.Cryptography;

/// <summary>
/// A value of type <typeparamref name="T"/> whose authenticity has been established by a
/// verification operation. Possession of a <see cref="Verified{T}"/> is itself proof that
/// verification succeeded.
/// </summary>
/// <remarks>
/// <para>
/// This separates the <em>trust</em> axis from the <em>data</em> axis. The wire form (for example a
/// verifiable credential or a decrypted message) is the untrusted, freely-constructible value — used
/// both for building/issuing and as deserialized-but-unverified input. Wrapping it in
/// <see cref="Verified{T}"/> marks the authenticated state. A trusted consumer API that accepts a
/// <see cref="Verified{T}"/> therefore cannot be called with unverified data: the distinction is
/// enforced by the compiler, not by convention.
/// </para>
/// <para>
/// <strong>The constructor is <see langword="private"/>.</strong> Not even code in this assembly can call
/// <c>new Verified&lt;T&gt;(...)</c>. The only ways to obtain an instance are the two static mints below,
/// each granted to first-party verification libraries via <c>InternalsVisibleTo</c>:
/// <see cref="CreateAsserted"/>, which always succeeds, and <see cref="TryCreateBound"/>, which refuses
/// (returns <see langword="null"/>) unless its <see cref="BoundProvenance"/> witnesses the exact value being
/// minted (<see cref="BoundProvenance.Witnesses(object)"/>). A verify path therefore cannot fabricate a
/// binding for one value out of a <see cref="BoundProvenance"/> established for another. The honest scope of
/// this guarantee is that neither mint, nor any <see cref="BoundProvenance"/> producer, is reachable BY
/// COMPILED REFERENCE outside the first-party assemblies granted that access — not "un-fakeable from any
/// assembly" in some absolute sense, but structurally confined to a known, reviewed boundary. Two caveats
/// bound even that, and neither is a regression nor closable by a capability design: the grants are
/// simple-name only (this assembly is not strong-named), so an assembly that CLAIMS a granted name is inside
/// the boundary; and <c>BindingFlags.NonPublic</c> reflection bypasses accessibility. Both require hostile
/// code already loaded in-process — the boundary defends against accidental and by-reference misuse, not
/// against an attacker running inside the same process.
/// </para>
/// <para>
/// <strong>Bound is reference-payload-only.</strong> <see cref="BoundProvenance.Witnesses(object)"/> is an
/// instance-identity (<c>ReferenceEquals</c>) check, so <see cref="TryCreateBound"/> can only ever succeed for a
/// reference-typed <typeparamref name="T"/> — a value-type <typeparamref name="T"/> boxes fresh at every
/// boundary crossing, so no witness could ever match, and <see cref="TryCreateBound"/> refuses it explicitly
/// (rather than relying on that incidental boxing behavior to fail closed on its own). This is documented, not
/// silent: every <see cref="BoundProvenance"/>-targeted payload in this family is a reference type (a message,
/// a credential, a signature-facts record), never a value type or an interned <see cref="string"/> — a
/// <see cref="string"/> is a label, not a payload, so it is never the subject a gate witnesses.
/// </para>
/// <para>
/// <strong>Instance identity, not content identity.</strong> The witness ties a
/// <see cref="BoundProvenance"/> to a specific object instance, not to that instance's content at mint time — a
/// shared mutable payload mutated after minting still satisfies the witness. This library treats
/// <see cref="Verified{T}"/> as an immutable POST-VERIFICATION SNAPSHOT boundary by convention: a mint site
/// hands the minted value to nothing that could still mutate it. Closing this structurally (a per-payload
/// content-commitment witness) is a distinct design axis, left as a follow-up rather than folded into this
/// witness check.
/// </para>
/// <para>
/// <strong>Attribution honesty is a convention, not a compiler check (no
/// analyzer).</strong> A mint site produces <see cref="CreateAsserted"/> only where nothing in scope
/// resolves the claimed identity against anything else — a genuine bring-your-own-key path.
/// Wherever a resolvable identity commitment exists (a certificate digest, a resolved DID
/// verification method, a controller-resolved verification method, a key-agreement sender), the
/// site earns <see cref="TryCreateBound"/> instead. <see cref="IsIdentityBound"/> lets a consumer
/// tell the two apart; a compile-time authorization seam that requires <see cref="BoundProvenance"/>
/// — never <see cref="AssertedProvenance"/> — closes the gap where an asserted label could otherwise
/// normalize into a de-facto authenticated principal. The structural guards — this type's private
/// constructor plus its two internal, witness-checked mints, and <see cref="BoundProvenance"/>'s own
/// private constructor plus internal gates — already make a FORGED <see cref="IsIdentityBound"/> or
/// a raw <c>new Verified&lt;T&gt;(...)</c> unrepresentable; no analyzer project exists or is needed
/// for that half. What no type can catch is the one residual left: a future mint site settling for
/// <see cref="CreateAsserted"/> where a <see cref="BoundProvenance"/> gate was in fact reachable and
/// would have succeeded. That residual is this paragraph's convention — a code-review concern, not a
/// compile-time one.
/// </para>
/// <para>
/// <strong><see langword="default"/>(<see cref="Verified{T}"/>) is INERT, never a usable proof.</strong>
/// A private constructor does not stop the language from handing out this struct's own all-zero
/// default — <see langword="default"/>(<see cref="Verified{T}"/>), an uninitialized field, a skipped
/// array element, a default parameter — none of which run the constructor, so none of them are
/// "minted" in the sense this type's whole design is built around. <see cref="IsVerified"/> is
/// <see langword="false"/> for exactly this case (and only this case: the constructor always sets it
/// <see langword="true"/>), and <see cref="Value"/> THROWS <see cref="InvalidOperationException"/>
/// rather than silently handing back a fabricated <typeparamref name="T"/> default — closing the gap
/// where such a default instance previously behaved indistinguishably from a genuinely verified one to
/// any caller that read <see cref="Value"/> without checking. A caller holding a
/// <see cref="Verified{T}"/><c>?</c> (the family's own convention — see <c>JAdESValidationResult.Verified</c>,
/// <c>DidCommSignedVerificationResult.Verified</c>) and checking it for <see langword="null"/> before use
/// never reaches this guard at all; it exists for the struct's own bare default.
/// </para>
/// <para>
/// <see cref="Context"/> carries the verification context as a <see cref="Tag"/>, derived from
/// <see cref="Provenance"/> at mint time — the same "context present at the decision point, provenance
/// visible" mechanism used across the cryptography layer (<c>Purpose.Verification</c> plus the identity's
/// <see cref="KeyId"/> when one is known). It is never read from a caller-supplied <see cref="Tag"/>: the
/// only way to influence it is through the provenance a mint actually carries.
/// </para>
/// </remarks>
/// <typeparam name="T">The type of the verified value.</typeparam>
[DebuggerDisplay("{DebuggerDisplayText,nq}")]
public readonly record struct Verified<T> where T : notnull
{
    private T? MintedValue { get; }

    private bool WasVerified { get; }


    /// <summary>
    /// The verified value. Guarded: reading this on an instance <see cref="IsVerified"/> reports
    /// <see langword="false"/> for — most notably <see langword="default"/>(<see cref="Verified{T}"/>) —
    /// throws rather than silently returning a fabricated <typeparamref name="T"/> default. See the type
    /// remarks on default-instance semantics.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// This instance was never minted by an internal verification path (<see cref="IsVerified"/> is
    /// <see langword="false"/>).
    /// </exception>
    public T Value => WasVerified
        ? MintedValue!
        : throw new InvalidOperationException(
            "This Verified<T> carries no proof of verification -- it is the type's own default value " +
            "(default(Verified<T>), an uninitialized field, or a skipped array element), never minted by " +
            "an internal verification path. Check IsVerified before reading Value, or -- the common case " +
            "across this family -- hold a Verified<T>? and check that for null instead of relying on this " +
            "struct's own default.");

    /// <summary>
    /// The verification context, derived from <see cref="Provenance"/> at mint time and carried as a
    /// <see cref="Tag"/>.
    /// </summary>
    public Tag Context { get; }

    /// <summary>
    /// The verification provenance this instance was minted with — <see langword="null"/> only for the
    /// type's own default value (see the type remarks); otherwise an <see cref="AssertedProvenance"/> or a
    /// <see cref="BoundProvenance"/>.
    /// </summary>
    public VerificationProvenance? Provenance { get; }

    /// <summary>
    /// <see langword="true"/> when <see cref="Provenance"/> is a <see cref="BoundProvenance"/> — an identity
    /// a typed gate actually checked against this value, not merely asserted.
    /// </summary>
    public bool IsIdentityBound => Provenance is BoundProvenance;

    /// <summary>
    /// <see langword="true"/> when this instance was minted by an internal verification path and
    /// <see cref="Value"/> is safe to read; <see langword="false"/> for the type's own default value —
    /// see the type remarks.
    /// </summary>
    public bool IsVerified => WasVerified;


    private Verified(T value, VerificationProvenance provenance)
    {
        ArgumentNullException.ThrowIfNull(value);
        ArgumentNullException.ThrowIfNull(provenance);
        MintedValue = value;
        Provenance = provenance;
        Context = BuildContext(provenance);
        WasVerified = true;
    }


    /// <summary>
    /// Mints a verified value whose identity a typed gate checked against <paramref name="value"/> itself.
    /// Intentionally <see langword="internal"/> so that only a first-party verification library granted
    /// <c>InternalsVisibleTo</c> by this assembly can reach it.
    /// </summary>
    /// <param name="value">The value whose authenticity was established.</param>
    /// <param name="provenance">The binding to mint with.</param>
    /// <returns>
    /// The minted instance, or <see langword="null"/> when <paramref name="provenance"/> was established for a
    /// different value (<see cref="BoundProvenance.Witnesses(object)"/> fails), or when <typeparamref name="T"/>
    /// is a value type — a <see cref="BoundProvenance"/> witness is instance identity, which a value type can
    /// never satisfy — refused explicitly rather than left to fail incidentally on every call's fresh boxing.
    /// </returns>
    internal static Verified<T>? TryCreateBound(T value, BoundProvenance provenance)
    {
        ArgumentNullException.ThrowIfNull(value);
        ArgumentNullException.ThrowIfNull(provenance);

        if(typeof(T).IsValueType)
        {
            return null;
        }

        if(!provenance.Witnesses(value))
        {
            return null;
        }

        return new Verified<T>(value, provenance);
    }

    /// <summary>
    /// Mints a verified value with an asserted, unbound label. Intentionally <see langword="internal"/> so
    /// that only a first-party verification library granted <c>InternalsVisibleTo</c> by this assembly can
    /// reach it.
    /// </summary>
    /// <param name="value">The value whose authenticity was established.</param>
    /// <param name="provenance">The asserted provenance to mint with.</param>
    internal static Verified<T> CreateAsserted(T value, AssertedProvenance provenance)
    {
        return new Verified<T>(value, provenance);
    }


    private static Tag BuildContext(VerificationProvenance provenance)
    {
        Tag tag = Tag.Create(Purpose.Verification);
        if(provenance.Identity is KeyId identity)
        {
            tag = tag.With(identity);
        }

        return tag;
    }


    private string DebuggerDisplayText => WasVerified ? $"Verified: {MintedValue}" : "Verified: <default, unverified>";
}
