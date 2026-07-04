using System.Collections.Generic;

namespace Verifiable.Core.Model.Common
{
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
    public sealed class Context
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
        /// See <see href="https://www.w3.org/TR/did-1.0/#json-ld">DID Core 1.0 §6.3.2 JSON-LD</see>.
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
        /// The ordered list of context values.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Context values can be strings (URIs) or objects (inline context definitions).
        /// The order is significant: earlier contexts take precedence when terms conflict.
        /// </para>
        /// <para>
        /// For Verifiable Credentials, the first value must be <see cref="Credentials20"/>.
        /// For DID documents, the first value should be <see cref="Cid10"/> or <see cref="DidCore10"/>.
        /// </para>
        /// </remarks>
        public List<object>? Contexts { get; set; }

        /// <summary>
        /// Additional inline context definitions.
        /// </summary>
        /// <remarks>
        /// Allows defining custom terms inline rather than referencing external context documents.
        /// </remarks>
        public IDictionary<string, object>? AdditionalData { get; set; }
    }
}
