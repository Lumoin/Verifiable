using System;
using System.Diagnostics;

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
/// The constructor is intentionally <see langword="internal"/>. It lives in the cryptography layer so
/// the whole family of libraries can share one proof type, yet only the first-party verification paths
/// can mint one: this assembly grants <c>InternalsVisibleTo</c> to those libraries (the credential and
/// presentation verify operations in <c>Verifiable.Core</c>, and any sibling verify library similarly
/// granted), so their verify paths construct a <see cref="Verified{T}"/> while consumers in other
/// assemblies — the OAuth layer, applications — receive one from a verify call and cannot fabricate
/// one. This makes the type a genuine proof-of-verification rather than a forgeable marker. The
/// guarantee is therefore "minted only by an explicit, auditable set of first-party verify libraries",
/// not "minted by anyone".
/// </para>
/// <para>
/// <see cref="Context"/> carries the verification context as a <see cref="Tag"/> — the same
/// "context present at the decision point, provenance visible" mechanism used across the
/// cryptography layer (the signing/verification algorithm, <c>Purpose.Verification</c>, and the
/// resolved verification method or key identifier). It is <see cref="Tag.Empty"/> when a verify
/// path has no additional context to record.
/// </para>
/// </remarks>
/// <typeparam name="T">The type of the verified value.</typeparam>
[DebuggerDisplay("Verified: {Value}")]
public readonly record struct Verified<T> where T : notnull
{
    /// <summary>
    /// The verified value.
    /// </summary>
    public T Value { get; }

    /// <summary>
    /// The verification context and provenance (algorithm, purpose, verification method), carried
    /// as a <see cref="Tag"/>.
    /// </summary>
    public Tag Context { get; }


    /// <summary>
    /// Mints a verified value. Intentionally <see langword="internal"/> so that only a first-party
    /// verification library granted <c>InternalsVisibleTo</c> by this assembly can construct a
    /// <see cref="Verified{T}"/>.
    /// </summary>
    /// <param name="value">The value whose authenticity was established.</param>
    /// <param name="context">The verification context/provenance.</param>
    internal Verified(T value, Tag context)
    {
        ArgumentNullException.ThrowIfNull(value);
        ArgumentNullException.ThrowIfNull(context);
        Value = value;
        Context = context;
    }
}
