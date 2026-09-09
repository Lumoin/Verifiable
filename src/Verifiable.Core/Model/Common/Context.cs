using System;
using System.Collections.Generic;

namespace Verifiable.Core.Model.Common
{
    /// <summary>
    /// The wire shape a <see cref="Context"/> was parsed from, or should be written as.
    /// </summary>
    /// <remarks>
    /// JSON-LD 1.1 itself treats a scalar <c>@context</c> value and an array as equivalent —
    /// <see href="https://www.w3.org/TR/json-ld11/#dfn-embedded-context">JSON-LD 1.1 §1.4
    /// Terminology, "embedded context"</see>: "Its value may be a map for a context definition,
    /// as an IRI, or as an array combining either of the above." This is JSON-LD's own permission,
    /// not one VC Data Model 2.0 or DID Core separately grant — VCDM 2.0 §4.3 in fact requires the
    /// ordered-SET (array) form for a built document; see <see cref="Context.FromIris"/>. Carrying
    /// which form a PARSED document used lets a re-serialized document keep its original bytes,
    /// which matters to JCS-based Data Integrity proofs where the canonicalized bytes are exactly
    /// what is signed.
    /// </remarks>
    public enum ContextForm
    {
        /// <summary>The wire value is a single string or a single inline object, not an array.</summary>
        Scalar,

        /// <summary>The wire value is a JSON array, regardless of how many entries it holds.</summary>
        Array
    }


    /// <summary>
    /// Represents a JSON-LD context that defines the terms and vocabulary used in
    /// Controlled Identifier Documents, Verifiable Credentials, and related structures.
    /// </summary>
    /// <remarks>
    /// <para>
    /// JSON-LD contexts map terms to IRIs, enabling unambiguous interpretation of
    /// property names and values across different systems. The <c>@context</c> property
    /// is required in all JSON-LD documents and determines how the document should
    /// be processed.
    /// </para>
    /// <para>
    /// This class provides well-known context URIs as static properties for use when
    /// constructing documents. The first context in a Verifiable Credential must be
    /// <see cref="Credentials20"/>; a DID document carries <see cref="DidCore10"/> (the published DID Core 1.0
    /// Recommendation, the interoperable default), <see cref="DidCore11"/> (the DID Core 1.1 Candidate
    /// Recommendation), or — for the verification-method and relationship vocabulary both DID Core versions now
    /// layer on — <see cref="Cid10"/> (Controlled Identifiers 1.0).
    /// </para>
    /// <para>
    /// See <see href="https://www.w3.org/TR/json-ld11/#the-context">JSON-LD 1.1 §3.1 The Context</see>.
    /// </para>
    /// </remarks>
    public sealed class Context: IEquatable<Context>
    {
        /// <summary>
        /// Controlled Identifiers v1.0 context URI.
        /// Used for DID documents following the CID 1.0 specification.
        /// </summary>
        /// <remarks>
        /// See <see href="https://www.w3.org/TR/cid-1.0/#json-ld-context">CID 1.0 §4.2 JSON-LD context</see>.
        /// </remarks>
        public static string Cid10 { get; } = "https://www.w3.org/ns/cid/v1";

        /// <summary>
        /// Verifiable Credentials Data Model v2.0 context URI.
        /// Must be the first context in any VC 2.0 credential or presentation.
        /// </summary>
        /// <remarks>
        /// See <see href="https://www.w3.org/TR/vc-data-model-2.0/#contexts">VC Data Model 2.0 §4.3 Contexts</see>.
        /// </remarks>
        public static string Credentials20 { get; } = "https://www.w3.org/ns/credentials/v2";

        /// <summary>
        /// The example-vocabulary context URI VC Data Model 2.0 publishes for prototyping — terms such as
        /// <c>alumniOf</c> or <c>degree</c> used by the specification's own illustrative credentials, before
        /// a developer publishes a stable, use-case-specific context of their own.
        /// </summary>
        /// <remarks>
        /// See <see href="https://www.w3.org/TR/vc-data-model-2.0/#getting-started">VC Data Model 2.0 §4.1
        /// Getting Started, "Example 1: A template for creating prototype verifiable credentials"</see>: "the
        /// <c>https://www.w3.org/ns/credentials/examples/v2</c> URL above would then be replaced with the URL
        /// of a use-case-specific context" once a developer stabilizes their own vocabulary.
        /// </remarks>
        public static string CredentialsExamples20 { get; } = "https://www.w3.org/ns/credentials/examples/v2";

        /// <summary>
        /// The context a conforming document that does not define every term it uses MUST append as the last
        /// <c>@context</c> entry, so undefined terms have a defined (permissive) vocabulary rather than being
        /// rejected or silently dropped by JSON-LD processing.
        /// </summary>
        /// <remarks>
        /// See <see href="https://www.w3.org/TR/vc-data-model-2.0/#extensibility">VC Data Model 2.0 §5.2
        /// Extensibility</see>: "If a conforming document does not use JSON-LD Contexts that define all terms
        /// used, it MUST include the <c>https://www.w3.org/ns/credentials/undefined-terms/v2</c> as the last
        /// value in the <c>@context</c> property."
        /// </remarks>
        public static string UndefinedTerms20 { get; } = "https://www.w3.org/ns/credentials/undefined-terms/v2";

        /// <summary>
        /// Data Integrity v1.0 context URI.
        /// Required when using Data Integrity proofs to secure documents.
        /// </summary>
        /// <remarks>
        /// See <see href="https://www.w3.org/TR/vc-data-integrity/#contexts-and-vocabularies">
        /// Data Integrity 1.0 §2.4 Contexts and Vocabularies</see>.
        /// </remarks>
        public static string DataIntegrity20 { get; } = "https://w3id.org/security/data-integrity/v2";

        /// <summary>
        /// The DID Core 1.0 JSON-LD context URI (<c>https://www.w3.org/ns/did/v1</c>), the value a DID Core 1.0
        /// JSON-LD DID document carries as the first <c>@context</c> entry.
        /// </summary>
        /// <remarks>
        /// <para>
        /// This is the context from the W3C Recommendation, DID Core 1.0. It remains the interoperable default:
        /// 1.0 is the published Recommendation, whereas <see cref="DidCore11"/> is a later Candidate Recommendation
        /// that is not yet a Recommendation. New documents target 1.0 unless 1.1 is explicitly requested.
        /// </para>
        /// <para>
        /// See <see href="https://www.w3.org/TR/did-1.0/#json-ld">DID Core 1.0 §6.3 JSON-LD</see>.
        /// </para>
        /// </remarks>
        public static string DidCore10 { get; } = "https://www.w3.org/ns/did/v1";

        /// <summary>
        /// The DID Core 1.1 JSON-LD context URI (<c>https://www.w3.org/ns/did/v1.1</c>), the value DID Core 1.1
        /// mandates as the (first) <c>@context</c> entry of a JSON-LD DID document.
        /// </summary>
        /// <remarks>
        /// <para>
        /// DID Core 1.1 refactors the data model to layer on top of
        /// <see href="https://www.w3.org/TR/cid-1.0/">Controlled Identifiers (CID) 1.0</see> — the shared
        /// verification-method and verification-relationship terms (<see cref="Cid10"/>) are defined there, and
        /// resolution was moved out into the DID Resolution specification — so 1.1 is primarily a structural and
        /// editorial revision of 1.0 rather than a data-model break. DID Core 1.1 (§6.2.3 JSON-LD Processors)
        /// requires the serialized <c>@context</c> value to be the string <c>https://www.w3.org/ns/did/v1.1</c>, or
        /// an array with that URL as its first element.
        /// </para>
        /// <para>
        /// At the time of writing 1.1 is a W3C Candidate Recommendation (not yet a Recommendation); the W3C status
        /// advises implementing 1.0 for production interoperability, so <see cref="DidCore10"/> stays the library
        /// default and this 1.1 context is opt-in.
        /// </para>
        /// <para>
        /// See <see href="https://www.w3.org/TR/did-1.1/#json-ld-processors">DID Core 1.1 §6.2.3 JSON-LD Processors</see>.
        /// </para>
        /// </remarks>
        public static string DidCore11 { get; } = "https://www.w3.org/ns/did/v1.1";

        /// <summary>
        /// Multikey v1 context URI.
        /// Used when verification methods use the Multikey format.
        /// </summary>
        /// <remarks>
        /// See <see href="https://www.w3.org/TR/cid-1.0/#Multikey">CID 1.0 §2.2.2 Multikey</see>.
        /// </remarks>
        public static string Multikey10 { get; } = "https://w3id.org/security/multikey/v1";


        /// <summary>
        /// The ordered <c>@context</c> entries: each is either an IRI or an inline context definition.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Order is significant — earlier entries take precedence when terms conflict, and the first entry
        /// carries the normative meaning checked by <see cref="Validation.ContextValidationRules.ValidateFirstEntry"/>
        /// (VC Data Model 2.0 §4.3 for credentials/presentations; DID Core for DID documents). This list is never
        /// <see langword="null"/>; an absent <c>@context</c> is the absence of a <see cref="Context"/> instance,
        /// not an instance with zero entries.
        /// </para>
        /// </remarks>
        public IReadOnlyList<ContextEntry> Entries { get; }

        /// <summary>
        /// The wire shape (<see cref="ContextForm.Scalar"/> or <see cref="ContextForm.Array"/>) this context was
        /// parsed from, or should be written as.
        /// </summary>
        /// <remarks>
        /// This is a serialization detail, not part of the context's meaning — JSON-LD treats a scalar value and
        /// a single-element array as equivalent, so <see cref="Form"/> is deliberately excluded from
        /// <see cref="Equals(Context?)"/> and <see cref="GetHashCode"/>.
        /// </remarks>
        public ContextForm Form { get; }


        /// <summary>
        /// Constructs a context from its ordered entries and wire form. The entries are copied, so a
        /// caller's later mutation of the array or list it passed cannot reach this instance —
        /// <see cref="Context"/> is otherwise immutable end to end. <see cref="ContextForm.Scalar"/>
        /// is refused unless <paramref name="entries"/> holds exactly one entry, since a scalar wire
        /// value is a single string or object, never a list — the same loud refusal
        /// <see cref="ContextEntry()"/> gives a degenerate, neither-IRI-nor-definition entry, rather
        /// than silently accepting a shape the wire form cannot represent.
        /// </summary>
        /// <param name="entries">The ordered <c>@context</c> entries.</param>
        /// <param name="form">The wire shape to round-trip as.</param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="entries"/> is <see langword="null"/>.</exception>
        /// <exception cref="ArgumentException">
        /// Thrown when <paramref name="form"/> is <see cref="ContextForm.Scalar"/> and
        /// <paramref name="entries"/> does not hold exactly one entry.
        /// </exception>
        public Context(IReadOnlyList<ContextEntry> entries, ContextForm form)
        {
            ArgumentNullException.ThrowIfNull(entries);

            ContextEntry[] copiedEntries = [.. entries];
            if(form == ContextForm.Scalar && copiedEntries.Length != 1)
            {
                throw new ArgumentException("A scalar-form context must carry exactly one entry; the wire value is a single string or object, not a list.", nameof(entries));
            }

            Entries = copiedEntries;
            Form = form;
        }


        /// <summary>
        /// Builds a context from one or more IRIs, always in <see cref="ContextForm.Array"/> — VC Data
        /// Model 2.0 §4.3 Contexts requires the <c>@context</c> value to be an
        /// <see href="https://infra.spec.whatwg.org/#ordered-set">ordered set</see>, i.e. a JSON array,
        /// even when it holds a single entry; a bare scalar is a shape this library's own VCALM gate
        /// (<c>VcalmJsonParsing</c>) refuses as malformed for exactly that reason. The
        /// <see cref="ContextForm.Scalar"/> form therefore arises only through the
        /// <see cref="Context(IReadOnlyList{ContextEntry}, ContextForm)"/> constructor, when
        /// round-tripping something that was actually parsed as a scalar.
        /// </summary>
        /// <param name="iris">The context IRIs, in wire order.</param>
        /// <returns>The constructed context.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="iris"/> is <see langword="null"/>.</exception>
        public static Context FromIris(params string[] iris)
        {
            ArgumentNullException.ThrowIfNull(iris);

            var entries = new ContextEntry[iris.Length];
            for(int i = 0; i < iris.Length; ++i)
            {
                entries[i] = ContextEntry.FromIri(iris[i]);
            }

            return new Context(entries, ContextForm.Array);
        }


        /// <summary>
        /// Compares contexts by their ordered entries alone: <see cref="Form"/> is excluded, since JSON-LD
        /// treats a scalar value and an equivalent single-element array as the same context.
        /// </summary>
        /// <param name="other">The context to compare against.</param>
        /// <returns><see langword="true"/> when both contexts carry the same entries in the same order.</returns>
        public bool Equals(Context? other)
        {
            if(other is null)
            {
                return false;
            }

            if(ReferenceEquals(this, other))
            {
                return true;
            }

            if(Entries.Count != other.Entries.Count)
            {
                return false;
            }

            for(int i = 0; i < Entries.Count; ++i)
            {
                if(!Entries[i].Equals(other.Entries[i]))
                {
                    return false;
                }
            }

            return true;
        }


        /// <inheritdoc/>
        public override bool Equals(object? obj)
        {
            return obj is Context other && Equals(other);
        }


        /// <summary>
        /// A hash consistent with <see cref="Equals(Context?)"/>: computed over <see cref="Entries"/> only, so
        /// two contexts with the same entries but a different <see cref="Form"/> hash identically.
        /// </summary>
        /// <returns>The hash code.</returns>
        public override int GetHashCode()
        {
            var hash = new HashCode();
            for(int i = 0; i < Entries.Count; ++i)
            {
                hash.Add(Entries[i]);
            }

            return hash.ToHashCode();
        }


        /// <inheritdoc/>
        public static bool operator ==(Context? left, Context? right)
        {
            if(left is null)
            {
                return right is null;
            }

            return left.Equals(right);
        }


        /// <inheritdoc/>
        public static bool operator !=(Context? left, Context? right)
        {
            return !(left == right);
        }
    }
}
