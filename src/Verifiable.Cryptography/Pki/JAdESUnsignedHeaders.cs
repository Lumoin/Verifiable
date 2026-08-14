using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The <c>etsiU</c> unprotected header parameter (clause 5.3.1) — the single JSON-array unprotected-header
/// container that holds every unsigned (post-signature) JAdES component, in strict append-only incorporation
/// order, per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
/// ETSI TS 119 182-1 V1.2.1, clause 5.3.1</see>. The JAdES-side counterpart of
/// <see cref="CBAdESUnsignedHeaders"/>; see the remarks below for the one structural fact CB-AdES's own CBOR
/// substrate does not need to represent.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Array, not map (JA-5.3.1-01/-06).</strong> "The <c>etsiU</c> unprotected header parameter shall be
/// a JSON array whose elements contain JSON values that are not signed by the JAdES signature." NOTE 1
/// explains why: certain electronic time-stamp message imprints are computed by digesting a concatenation of
/// unsigned components in wire order, so an ordered, append-only sequence is load-bearing, not incidental —
/// exactly the same fact <see cref="CBAdESUnsignedHeaders"/>'s own remarks record for <c>uHeaders</c>, and
/// exactly why <see cref="ElementsBefore"/> exists here too.
/// </para>
/// <para>
/// <strong>Content scope (JA-5.3.1-02).</strong> "The <c>etsiU</c> header parameter shall contain JSON values
/// that qualify the JAdES signature itself, or the signer, or the JWS Payload."
/// </para>
/// <para>
/// <strong>Append-only (JA-5.3.1-03), enforced by API shape, not a runtime flag.</strong> "New JSON values
/// shall always be added at the end of the <c>etsiU</c> array." <see cref="Append"/> is the only way to grow
/// an instance: it returns a NEW <see cref="JAdESUnsignedHeaders"/> with the supplied element placed after
/// every element this instance already holds. There is no insert-at, reorder, or remove operation of any kind.
/// </para>
/// <para>
/// <strong>Whole-array duality (JA-5.3.1-04/-09/-10/-11) — the one structural fact JAdES needs
/// that CB-AdES's CBOR substrate does not.</strong> "The array shall not contain JSON values in clear in some
/// positions, and base64url encoded unsigned JSON values in others. Either all of them shall be incorporated
/// in clear or shall be incorporated base64url encoded." <see cref="Mode"/> carries this container-level fact
/// once, and every constructor/<see cref="Append"/> call validates every element whose own carrier
/// self-reports a mode (<see cref="JAdESUnsignedHeaderElement.DeclaredMode"/>) against it. This is a
/// <strong>fail-closed unrepresentable</strong> design, not a collected-violation one: this library states the
/// choice directly ("mixed = fail-closed violation"), and it mirrors
/// <see cref="CBAdESUnsignedHeaders"/>'s own precedent of enforcing its invariants (non-emptiness) by
/// constructor throw rather than by producing a value that represents the violation for later reporting. The
/// two mode-agnostic arms (<c>cSig</c>, unknown — <see cref="JAdESUnsignedHeaderElement.DeclaredMode"/> is
/// <see langword="null"/>) are exempt from this check, since neither is decoded here regardless of
/// which mode the container declares.
/// </para>
/// <para>
/// <strong>JA-5.3.1-14, enforced here (not at the element level).</strong> "If the <c>etsiU</c> header
/// parameter contains JSON values in clear, instances of <c>tstContainer</c> type shall have the
/// <c>canonAlg</c> member, except for the <c>sigTst</c> JSON object." Every <c>tstContainer</c> arm this library
/// models except <c>sigTst</c> is subject to this rule — <c>arcTst</c>, <c>sigRTst</c>, <c>rfsTst</c>
/// (<c>sigTst</c> is the stated exception, enforced
/// unconditionally at its own element constructor per JA-5.3.4-05). A clear-mode
/// <see cref="JAdESUnsignedHeaderElementArchiveTimestamp"/>/<see cref="JAdESUnsignedHeaderElementSignatureAndReferencesTimestamp"/>/
/// <see cref="JAdESUnsignedHeaderElementReferencesTimestamp"/> placed into a
/// <see cref="JAdESEtsiUIncorporationMode.ClearJson"/> container whose decoded
/// <see cref="AdESTimestampContainer.CanonAlg"/> is <see langword="null"/> is rejected here, at the point this
/// element-level fact and the container-level mode both become known together.
/// </para>
/// <para>
/// <strong>Non-empty (JA-5.3.1-07), enforced at construction.</strong> "The <c>etsiU</c> header parameter
/// shall be a non-empty array." An instance cannot exist with zero elements.
/// </para>
/// <para>
/// <strong>Sole-member default (JA-5.3.1-12), a SHOULD, not a SHALL.</strong> "The <c>etsiU</c> header
/// parameter should be the only header parameter incorporated to the JWS Unprotected Header." Tolerating a
/// non-conformant signature with additional unprotected-header siblings is a validator policy choice for a
/// later stage; this type cannot see sibling unprotected-header members.
/// </para>
/// <para>
/// <strong>Ownership.</strong> This instance owns every element reachable through its indexer — every concrete
/// <see cref="JAdESUnsignedHeaderElement"/> arm implements <see cref="IDisposable"/>.
/// <see cref="Dispose"/> disposes them all.
/// </para>
/// </remarks>
[DebuggerDisplay("JAdESUnsignedHeaders({Count} elements, {Mode})")]
public sealed class JAdESUnsignedHeaders: IReadOnlyList<JAdESUnsignedHeaderElement>, IDisposable
{
    /// <summary>
    /// The ordered backing storage of this instance's elements, in incorporation (wire) order. Never empty
    /// (enforced at construction, JA-5.3.1-07) and never mutated in place — <see cref="Append"/> always returns
    /// a new, independently-backed instance.
    /// </summary>
    private JAdESUnsignedHeaderElement[] Elements { get; }


    /// <summary>
    /// Initializes a new <see cref="JAdESUnsignedHeaders"/> from its full ordered element sequence. Takes a
    /// snapshot: subsequent mutation of <paramref name="elements"/> has no effect on this instance.
    /// </summary>
    /// <param name="mode">
    /// The whole-array incorporation mode (JA-5.3.1-04/-09) every mode-reporting element must be consistent
    /// with — see the type remarks.
    /// </param>
    /// <param name="elements">
    /// The unsigned header elements, in incorporation (wire) order (JA-5.3.1-01/-03). Must contain at least one
    /// element (JA-5.3.1-07).
    /// </param>
    /// <exception cref="ArgumentNullException"><paramref name="elements"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="elements"/> is empty; contains an element whose <see cref="JAdESUnsignedHeaderElement.DeclaredMode"/>
    /// conflicts with <paramref name="mode"/> (JA-5.3.1-10/-11); or contains a clear-mode <c>arcTst</c> element
    /// whose decoded time-stamp container is missing <c>canonAlg</c> while <paramref name="mode"/> is
    /// <see cref="JAdESEtsiUIncorporationMode.ClearJson"/> (JA-5.3.1-14).
    /// </exception>
    public JAdESUnsignedHeaders(JAdESEtsiUIncorporationMode mode, IReadOnlyList<JAdESUnsignedHeaderElement> elements)
    {
        ArgumentNullException.ThrowIfNull(elements);

        if(elements.Count == 0)
        {
            throw new ArgumentException(
                "The 'etsiU' header parameter shall be a non-empty array (ETSI TS 119 182-1 V1.2.1, clause 5.3.1, JA-5.3.1-07).",
                nameof(elements));
        }

        var snapshot = new JAdESUnsignedHeaderElement[elements.Count];
        for(int i = 0; i < elements.Count; ++i)
        {
            ValidateElement(mode, elements[i], nameof(elements));
            snapshot[i] = elements[i];
        }

        Mode = mode;
        Elements = snapshot;
    }


    /// <summary>
    /// Initializes a new <see cref="JAdESUnsignedHeaders"/> directly from an already-owned, already-validated
    /// backing array and mode. Used internally by <see cref="Append"/>, which always produces a non-empty
    /// array, so the public constructor's guards would be redundant here.
    /// </summary>
    private JAdESUnsignedHeaders(JAdESEtsiUIncorporationMode mode, JAdESUnsignedHeaderElement[] elements)
    {
        Mode = mode;
        Elements = elements;
    }


    /// <summary>
    /// Gets the whole-array incorporation mode (JA-5.3.1-04/-09/-10/-11): every element in this
    /// container is either uniformly base64url-opaque or uniformly clear-JSON, per this value.
    /// </summary>
    public JAdESEtsiUIncorporationMode Mode { get; }

    /// <summary>Gets the number of elements currently incorporated into this instance.</summary>
    public int Count => Elements.Length;

    /// <summary>Gets the element at the given zero-based position, in incorporation (wire) order.</summary>
    /// <param name="index">The zero-based position.</param>
    public JAdESUnsignedHeaderElement this[int index] => Elements[index];


    /// <summary>
    /// Returns a NEW <see cref="JAdESUnsignedHeaders"/> with <paramref name="element"/> incorporated after
    /// every element this instance already holds (JA-5.3.1-03: "New JSON values shall always be added at the
    /// end"). This instance is left unchanged; there is no insert-at, reorder, or remove operation on this
    /// type.
    /// </summary>
    /// <param name="element">The element to append.</param>
    /// <returns>A new instance with <paramref name="element"/> as its last element.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="element"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="element"/>'s <see cref="JAdESUnsignedHeaderElement.DeclaredMode"/> conflicts with
    /// <see cref="Mode"/> (JA-5.3.1-10/-11); or it is a clear-mode <c>arcTst</c> element whose decoded
    /// time-stamp container is missing <c>canonAlg</c> while <see cref="Mode"/> is
    /// <see cref="JAdESEtsiUIncorporationMode.ClearJson"/> (JA-5.3.1-14).
    /// </exception>
    public JAdESUnsignedHeaders Append(JAdESUnsignedHeaderElement element)
    {
        ValidateElement(Mode, element, nameof(element));

        var next = new JAdESUnsignedHeaderElement[Elements.Length + 1];
        for(int i = 0; i < Elements.Length; ++i)
        {
            next[i] = Elements[i];
        }

        next[Elements.Length] = element;

        return new JAdESUnsignedHeaders(Mode, next);
    }


    /// <summary>
    /// Returns the elements strictly before the given position, in incorporation order — the prefix an
    /// <c>arcTst</c> element at that position covers under clause 5.3.6.2.3 step 7a / 5.3.6.2.4 step 7c's
    /// validation-time message-imprint variant ("take the elements in <c>etsiU</c> JSON array... that precede
    /// (appear BEFORE) the <c>arcTst</c> JSON object that contains the electronic time-stamp that is being
    /// validated"). Passing <see cref="Count"/> returns every element — the generation-time variant's
    /// full-sequence view.
    /// </summary>
    /// <param name="index">
    /// The exclusive upper bound: elements at positions <c>0</c> through <c>index - 1</c> are returned. Must be
    /// within <c>[0, Count]</c>.
    /// </param>
    /// <returns>A new, independent snapshot list of the elements before <paramref name="index"/>.</returns>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="index"/> is negative or greater than <see cref="Count"/>.
    /// </exception>
    public IReadOnlyList<JAdESUnsignedHeaderElement> ElementsBefore(int index)
    {
        if(index < 0 || index > Elements.Length)
        {
            throw new ArgumentOutOfRangeException(
                nameof(index),
                index,
                "The prefix boundary must be within [0, Count] (ETSI TS 119 182-1 V1.2.1, clause 5.3.6.2.3 step 7a / 5.3.6.2.4 step 7c).");
        }

        var prefix = new JAdESUnsignedHeaderElement[index];
        for(int i = 0; i < index; ++i)
        {
            prefix[i] = Elements[i];
        }

        return prefix;
    }


    /// <summary>Returns an enumerator over the elements, in incorporation order.</summary>
    public IEnumerator<JAdESUnsignedHeaderElement> GetEnumerator()
    {
        return ((IEnumerable<JAdESUnsignedHeaderElement>)Elements).GetEnumerator();
    }


    /// <summary>Returns a non-generic enumerator over the elements, in incorporation order.</summary>
    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();


    /// <summary>Disposes every element reachable through this instance.</summary>
    public void Dispose()
    {
        for(int i = 0; i < Elements.Length; ++i)
        {
            if(Elements[i] is IDisposable disposable)
            {
                disposable.Dispose();
            }
        }
    }


    /// <summary>
    /// Validates one element against a declared incorporation mode — the shared core behind the constructor
    /// and <see cref="Append"/>. See the type remarks for JA-5.3.1-10/-11 and JA-5.3.1-14.
    /// </summary>
    private static void ValidateElement(JAdESEtsiUIncorporationMode mode, JAdESUnsignedHeaderElement element, string paramName)
    {
        ArgumentNullException.ThrowIfNull(element, paramName);

        JAdESEtsiUIncorporationMode? declaredMode = element.DeclaredMode;
        if(declaredMode.HasValue && declaredMode.Value != mode)
        {
            throw new ArgumentException(
                "The 'etsiU' array shall not contain JSON values in clear in some positions and base64url " +
                "encoded unsigned JSON values in others; either all of them shall be incorporated in clear or " +
                "shall be incorporated base64url encoded (ETSI TS 119 182-1 V1.2.1, clause 5.3.1, " +
                "JA-5.3.1-10/-11).",
                paramName);
        }

        if(mode == JAdESEtsiUIncorporationMode.ClearJson && IsClearModeTstContainerMissingCanonAlg(element))
        {
            throw new ArgumentException(
                "If the 'etsiU' header parameter contains JSON values in clear, instances of tstContainer " +
                "type shall have the canonAlg member, except for the sigTst JSON object (ETSI TS 119 182-1 " +
                "V1.2.1, clause 5.3.1, JA-5.3.1-14).",
                paramName);
        }
    }


    /// <summary>
    /// Determines whether <paramref name="element"/> is a clear-mode <c>tstContainer</c> instance subject to
    /// JA-5.3.1-14 (<c>arcTst</c>, <c>sigRTst</c>, <c>rfsTst</c> — every <c>tstContainer</c> arm except the
    /// unconditionally-exempt <c>sigTst</c>) whose decoded
    /// time-stamp container is missing <c>canonAlg</c>. <see langword="false"/> for every other arm, and for an
    /// opaque-mode carriage of these three (nothing decoded, nothing to check).
    /// </summary>
    private static bool IsClearModeTstContainerMissingCanonAlg(JAdESUnsignedHeaderElement element) => element switch
    {
        JAdESUnsignedHeaderElementArchiveTimestamp { Carriage: JAdESClearUnsignedValue<AdESTimestampContainer> clear } => clear.Value.CanonAlg is null,
        JAdESUnsignedHeaderElementSignatureAndReferencesTimestamp { Carriage: JAdESClearUnsignedValue<AdESTimestampContainer> clear } => clear.Value.CanonAlg is null,
        JAdESUnsignedHeaderElementReferencesTimestamp { Carriage: JAdESClearUnsignedValue<AdESTimestampContainer> clear } => clear.Value.CanonAlg is null,
        _ => false
    };
}
