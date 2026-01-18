using System.Collections.Generic;
using Verifiable.Core.Model.Common;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.Model.DataIntegrity;

namespace Verifiable.Core.Credentials
{
    /// <summary>
    /// Represents a Verifiable Presentation as defined in the W3C Verifiable Credentials
    /// Data Model v2.0 specification.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A Verifiable Presentation is a tamper-evident presentation of data from one or more
    /// Verifiable Credentials issued by one or more issuers. It allows a holder to present
    /// credentials to a verifier while proving control over the credentials being presented.
    /// </para>
    /// <para>
    /// Presentations are typically used in interactive protocols where the verifier issues
    /// a challenge that the holder must include in the presentation proof, preventing replay
    /// attacks and proving liveness.
    /// </para>
    /// <para>
    /// Certain types of presentations might contain data synthesized from, but not containing,
    /// the original Verifiable Credentials (for example, zero-knowledge proofs).
    /// </para>
    /// <para>
    /// See <see href="https://www.w3.org/TR/vc-data-model-2.0/#presentations">
    /// VC Data Model 2.0 §3.3 Presentations</see>.
    /// </para>
    /// </remarks>
    public class VerifiablePresentation
    {
        /// <summary>
        /// The JSON-LD context that defines the terms used in this presentation.
        /// </summary>
        /// <remarks>
        /// <para>
        /// The first context must be <see cref="Context.Credentials20"/>.
        /// </para>
        /// <para>
        /// See <see href="https://www.w3.org/TR/vc-data-model-2.0/#contexts">VC Data Model 2.0 §4.3 Contexts</see>.
        /// </para>
        /// </remarks>
        public Context? Context { get; set; }

        /// <summary>
        /// An optional unique identifier for the presentation.
        /// </summary>
        /// <remarks>
        /// <para>
        /// When present, this should be a URL. It enables referencing specific presentation
        /// instances, though presentations are typically short-lived.
        /// </para>
        /// <para>
        /// See <see href="https://www.w3.org/TR/vc-data-model-2.0/#identifiers">VC Data Model 2.0 §4.4 Identifiers</see>.
        /// </para>
        /// </remarks>
        public string? Id { get; set; }

        /// <summary>
        /// The types of this presentation.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Must include <c>"VerifiablePresentation"</c>. Additional types can specify
        /// the kind of presentation or protocol being used.
        /// </para>
        /// <para>
        /// See <see href="https://www.w3.org/TR/vc-data-model-2.0/#types">VC Data Model 2.0 §4.5 Types</see>.
        /// </para>
        /// </remarks>
        public List<string>? Type { get; set; }

        /// <summary>
        /// The entity presenting the credentials.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Typically the identifier (such as a DID) of the holder who controls the
        /// presented credentials. The holder may or may not be a subject of the
        /// credentials being presented.
        /// </para>
        /// <para>
        /// See <see href="https://www.w3.org/TR/vc-data-model-2.0/#verifiable-presentations">
        /// VC Data Model 2.0 §4.13 Verifiable Presentations</see>.
        /// </para>
        /// </remarks>
        public string? Holder { get; set; }

        /// <summary>
        /// The Verifiable Credentials being presented.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Can contain complete credential objects or external references to credentials.
        /// The credentials may use various securing mechanisms.
        /// </para>
        /// <para>
        /// See <see href="https://www.w3.org/TR/vc-data-model-2.0/#verifiable-presentations">
        /// VC Data Model 2.0 §4.13 Verifiable Presentations</see>.
        /// </para>
        /// </remarks>
        public List<VerifiableCredential>? VerifiableCredential { get; set; }

        /// <summary>
        /// One or more cryptographic proofs authenticating the presentation.
        /// </summary>
        /// <remarks>
        /// <para>
        /// The presentation proof typically uses the <c>authentication</c> verification
        /// relationship from the holder's controlled identifier document. It should include
        /// any challenge issued by the verifier to prevent replay attacks.
        /// </para>
        /// <para>
        /// See <see href="https://www.w3.org/TR/vc-data-model-2.0/#securing-mechanisms">
        /// VC Data Model 2.0 §4.12 Securing Mechanisms</see>.
        /// </para>
        /// </remarks>
        public List<DataIntegrityProof>? Proof { get; set; }

        /// <summary>
        /// Terms of use that apply to this presentation.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Holders can specify terms of use when presenting credentials, expressing
        /// conditions or restrictions on how the presentation may be used.
        /// </para>
        /// <para>
        /// See <see href="https://www.w3.org/TR/vc-data-model-2.0/#terms-of-use">
        /// VC Data Model 2.0 §5.5 Terms of Use</see>.
        /// </para>
        /// </remarks>
        public List<TermsOfUse>? TermsOfUse { get; set; }

        /// <summary>
        /// Additional properties as defined by the JSON-LD context.
        /// </summary>
        public IDictionary<string, object>? AdditionalData { get; set; }
    }
}