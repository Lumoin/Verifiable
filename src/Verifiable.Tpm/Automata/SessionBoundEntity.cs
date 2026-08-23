using System;
using System.Buffers;
using System.Diagnostics;
using System.Security.Cryptography;
using Verifiable.Tpm.Spec;

namespace Verifiable.Tpm.Automata;

/// <summary>
/// A session's recorded bound-entity value: the bind entity's Name with the entity's authorization
/// value (trailing zeros stripped) XORed into the tail, computed once at
/// <c>TPM2_StartAuthSession()</c> and held for the session's whole life — the simulator's model of
/// the reference implementation's <c>SESSION.u1.boundEntity</c> member (TPM 2.0 Library Part 4,
/// <c>SessionComputeBoundEntity()</c>; Part 1, clause 17.6.10: "the authorization value is combined
/// with the Name and stored in the SESSION boundEntity member").
/// </summary>
/// <remarks>
/// <para>
/// Folding the authValue into the recorded value — rather than recording the Name alone — is what
/// makes the bind-omission decision (Part 1, clause 17.6.10 equations 21/22) sensitive to the bound
/// entity's CURRENT authorization value: rotating the entity's authValue changes the recomputed value,
/// the comparison fails, and the binding ends, exactly as clause 17.6.10 requires ("If the
/// administrator for a persistent object changes the authorization, sessions bound to the old
/// authorization should no longer be valid") and exactly what defeats the clause's NV Index
/// "squatting" attack (an attacker who recreates an identically-Named Index under an authValue they
/// know must not inherit an old session's binding). A Name-only record is blind to both.
/// </para>
/// <para>
/// The fold follows Part 4 revision 1.83's <c>SessionComputeBoundEntity()</c> exactly: the Name is
/// zero-padded to the maximum Name size, the stripped authValue is XORed right-aligned into the FULL
/// padded buffer (overlapping the Name's own octets when the two do not both fit), and the recorded
/// size is always that maximum. Revision 1.83 applies the fold to reserved handles too (the older
/// "the bound value of a reserved handle is the handle itself" early return is commented out in the
/// reference), so a session bound to a hierarchy also unbinds when that hierarchy's authValue rotates.
/// The maximum here is <see cref="BindValueSize"/> = 66 octets: a 2-octet Name-algorithm prefix plus
/// the SHA-512 digest width, the widest Name this model can produce — the reference's
/// <c>sizeof(TPMU_NAME)</c> for the same algorithm set.
/// </para>
/// <para>
/// The Name that enters the fold is the same bind-form Name <c>TryResolveBindEntity</c> has always
/// recorded (a permanent handle's or NV Index's 4-octet handle value, an object's real computed
/// Name), so the value is internally consistent between bind time and every use-site recomputation;
/// the use sites that accept both an NV Index's handle form and its computed form recompute the fold
/// over each accepted form. The value is a secret: the Name is public, so revealing the folded value
/// reveals the authValue's octets by XOR — hence the pinned, zero-on-dispose
/// <see cref="SensitiveMemory"/> carrier.
/// </para>
/// </remarks>
[DebuggerDisplay("SessionBoundEntity(IsBound={IsBound})")]
public sealed class SessionBoundEntity: SensitiveMemory
{
    /// <summary>
    /// The recorded bind value's fixed size: a 2-octet Name-algorithm prefix plus the SHA-512 digest
    /// width, the widest Name this model produces (the reference's <c>sizeof(TPMU_NAME)</c> for the
    /// same algorithm set). Part 4's <c>SessionComputeBoundEntity()</c> always sets the bind value to
    /// this maximum, whatever the entity's own Name length.
    /// </summary>
    private const int BindValueSize = 66;

    /// <summary>
    /// The shared not-bound value, recorded for a session started with <c>bind == TPM_RH_NULL</c> and
    /// for every POLICY/TRIAL session (which never applies the bind-omission optimization — Part 3,
    /// clause 11.1.1's own "the session is not bound"). Backed by <see cref="EmptyMemoryOwner"/>, so
    /// it is safe to alias across every unbound session and immune to disposal.
    /// </summary>
    public static SessionBoundEntity Unbound { get; } = new(EmptyMemoryOwner.Instance);

    /// <summary>
    /// Initializes the carrier over <paramref name="storage"/>, whose ownership transfers to this
    /// instance.
    /// </summary>
    /// <param name="storage">The memory owner holding the folded bind value.</param>
    private SessionBoundEntity(IMemoryOwner<byte> storage): base(storage, TpmTags.BoundEntity)
    {
    }

    /// <summary>
    /// Gets whether this value records a real bind entity — the model of Part 4's
    /// <c>SESSION_ATTRIBUTES.isBound</c>, which gates <c>IsSessionBindEntity()</c> before any
    /// comparison runs.
    /// </summary>
    public bool IsBound => MemoryOwner is not EmptyMemoryOwner;

    /// <summary>
    /// Computes the bind value for an entity — Part 4's <c>SessionComputeBoundEntity()</c>: the Name
    /// zero-padded to <see cref="BindValueSize"/>, the stripped authValue XORed right-aligned into
    /// the full padded buffer.
    /// </summary>
    /// <param name="entityName">The bind entity's Name in this model's recorded bind form; never empty (an unbound session records <see cref="Unbound"/> instead).</param>
    /// <param name="strippedAuthValue">The entity's authorization value with trailing zeros already removed (Part 1, clause 17.6.4.3; the reference strips unconditionally in <c>EntityGetAuthValue()</c>).</param>
    /// <param name="pool">The memory pool the folded value's pinned storage is rented from.</param>
    /// <returns>The computed bound-entity value; the caller owns it.</returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="entityName"/> is empty or either input exceeds <see cref="BindValueSize"/> octets.</exception>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="pool"/> is <see langword="null"/>.</exception>
    public static SessionBoundEntity Compute(ReadOnlySpan<byte> entityName, ReadOnlySpan<byte> strippedAuthValue, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        if(entityName.IsEmpty || entityName.Length > BindValueSize)
        {
            throw new ArgumentException($"An entity Name must be 1..{BindValueSize} octets.", nameof(entityName));
        }

        if(strippedAuthValue.Length > BindValueSize)
        {
            throw new ArgumentException($"A stripped authValue cannot exceed {BindValueSize} octets.", nameof(strippedAuthValue));
        }

        IMemoryOwner<byte> storage = pool.Rent(BindValueSize, AllocationKind.Pinned);
        Fold(entityName, strippedAuthValue, storage.Memory.Span[..BindValueSize]);

        return new SessionBoundEntity(storage);
    }

    /// <summary>
    /// Decides whether this session is bound to the entity authorized now — Part 4's
    /// <c>IsSessionBindEntity()</c>: recompute the candidate entity's bind value from its Name and its
    /// CURRENT authorization value, and compare against the value recorded at
    /// <c>TPM2_StartAuthSession()</c>. A rotation of the entity's authValue since the bind, or a
    /// different entity squatting on the same Name, changes the recomputation and ends the match.
    /// </summary>
    /// <param name="entityName">The candidate entity's Name in this model's recorded bind form.</param>
    /// <param name="strippedCurrentAuthValue">The candidate entity's LIVE authorization value, trailing zeros removed — never the value captured at bind time.</param>
    /// <returns><see langword="true"/> when the recomputed bind value equals the recorded one; always <see langword="false"/> for <see cref="Unbound"/>.</returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="entityName"/> is empty or either input exceeds <see cref="BindValueSize"/> octets.</exception>
    public bool Matches(ReadOnlySpan<byte> entityName, ReadOnlySpan<byte> strippedCurrentAuthValue)
    {
        if(!IsBound)
        {
            return false;
        }

        if(entityName.IsEmpty || entityName.Length > BindValueSize)
        {
            throw new ArgumentException($"An entity Name must be 1..{BindValueSize} octets.", nameof(entityName));
        }

        if(strippedCurrentAuthValue.Length > BindValueSize)
        {
            throw new ArgumentException($"A stripped authValue cannot exceed {BindValueSize} octets.", nameof(strippedCurrentAuthValue));
        }

        Span<byte> candidate = stackalloc byte[BindValueSize];
        Fold(entityName, strippedCurrentAuthValue, candidate);

        //Both values are structurally BindValueSize octets, so this is Part 4's MemoryEqual2B size-and-
        //content check; the comparison is fixed-time because the folded value is authValue-derived.
        bool isMatch = CryptographicOperations.FixedTimeEquals(candidate, AsReadOnlySpan());
        CryptographicOperations.ZeroMemory(candidate);

        return isMatch;
    }

    /// <summary>
    /// The fold itself: copy the Name, zero the tail, XOR the authValue right-aligned into the full
    /// buffer (Part 4 revision 1.83's loop, overlap included).
    /// </summary>
    /// <param name="entityName">The entity's Name.</param>
    /// <param name="strippedAuthValue">The entity's stripped authorization value.</param>
    /// <param name="bind">The <see cref="BindValueSize"/>-octet destination.</param>
    private static void Fold(ReadOnlySpan<byte> entityName, ReadOnlySpan<byte> strippedAuthValue, Span<byte> bind)
    {
        entityName.CopyTo(bind);
        bind[entityName.Length..].Clear();

        int authStart = BindValueSize - strippedAuthValue.Length;
        for(int i = 0; i < strippedAuthValue.Length; i++)
        {
            bind[authStart + i] ^= strippedAuthValue[i];
        }
    }
}
