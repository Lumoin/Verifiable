using System;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Core.Model.Common;
using Verifiable.Core.Model.DataIntegrity;
using Verifiable.Foundation;

namespace Verifiable.Core.Model.Credentials
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
    /// This type is the UNSECURED presentation — the input to a securing mechanism.
    /// An embedded Data Integrity proof produces a
    /// <see cref="DataIntegrity.DataIntegritySecuredPresentation"/> (this type plus a
    /// <c>proof</c> member); an enveloping mechanism (JOSE, COSE) carries this object as
    /// a payload referenced from an <see cref="EnvelopedVerifiablePresentation"/>.
    /// </para>
    /// <para>
    /// See <see href="https://www.w3.org/TR/vc-data-model-2.0/#presentations">
    /// VC Data Model 2.0 §3.3 Presentations</see>.
    /// </para>
    /// </remarks>
    public class VerifiablePresentation: IEquatable<VerifiablePresentation>
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
        /// Enveloping-secured credentials presented alongside (or instead of) the
        /// JSON-LD credentials in <see cref="VerifiableCredential"/>.
        /// </summary>
        /// <remarks>
        /// <para>
        /// An enveloping-secured credential (JOSE, COSE, SD-JWT, SD-CWT) is carried as an
        /// <see cref="Credentials.EnvelopedVerifiableCredential"/> whose <c>id</c> is a
        /// <c>data:</c> URL. On the wire both this list and <see cref="VerifiableCredential"/>
        /// are emitted into the single <c>verifiableCredential</c> array; the serializer
        /// discriminates each element on read by its <c>type</c> and <c>data:</c> <c>id</c>.
        /// </para>
        /// <para>
        /// See <see href="https://www.w3.org/TR/vc-data-model-2.0/#presentations">VC-DM 2.0 §3.3 Presentations</see>.
        /// </para>
        /// </remarks>
        public List<EnvelopedVerifiableCredential>? EnvelopedVerifiableCredential { get; set; }

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


        /// <summary>
        /// Equality compares this presentation's own members: <see cref="Context"/>,
        /// <see cref="Id"/>, <see cref="Holder"/>, the <see cref="Type"/> sequence, the
        /// <see cref="VerifiableCredential"/> and <see cref="EnvelopedVerifiableCredential"/>
        /// sequences, <see cref="TermsOfUse"/>, and <see cref="AdditionalData"/>, compared only
        /// when <paramref name="other"/> has this exact runtime type, mirroring
        /// <see cref="VerifiableCredential.Equals(VerifiableCredential?)"/>. Sequence members
        /// compare element-wise in order via <see cref="StructuralEquality.SequenceEqual"/>, so
        /// each <see cref="VerifiableCredential"/> element is compared through that type's own
        /// (<see cref="VerifiableCredential.Context"/>, <see cref="VerifiableCredential.Id"/>,
        /// <see cref="VerifiableCredential.Issuer"/>, <see cref="VerifiableCredential.ValidFrom"/>,
        /// <see cref="VerifiableCredential.ValidUntil"/>) equality: two presentations whose
        /// credentials differ only in subject claims, status, or an embedded proof still compare
        /// equal at that element, a scope this method does not widen. <see cref="AdditionalData"/>
        /// is an open JSON-LD bucket and compares structurally via
        /// <see cref="StructuralEquality.JsonEqual"/>. This method is <see langword="virtual"/>:
        /// a derived type such as <see cref="DataIntegrity.DataIntegritySecuredPresentation"/>,
        /// which adds a proof chain, overrides it to fold its own members in, so the override is
        /// still reached when the instance is compared through this base static type, this
        /// class's <c>IEquatable&lt;VerifiablePresentation&gt;</c> implementation, or the
        /// inherited <c>operator ==</c>: a presentation carrying that proof is never equal to
        /// one lacking it or signed differently, regardless of which static type the caller holds
        /// the instances as.
        /// </summary>
        /// <param name="other">The presentation to compare against.</param>
        /// <returns><see langword="true"/> if the presentations are equal; otherwise <see langword="false"/>.</returns>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public virtual bool Equals(VerifiablePresentation? other)
        {
            if(other is null)
            {
                return false;
            }

            if(ReferenceEquals(this, other))
            {
                return true;
            }

            if(GetType() != other.GetType())
            {
                return false;
            }

            return Equals(Context, other.Context)
                && string.Equals(Id, other.Id, StringComparison.Ordinal)
                && string.Equals(Holder, other.Holder, StringComparison.Ordinal)
                && StructuralEquality.SequenceEqual(Type, other.Type)
                && StructuralEquality.SequenceEqual(VerifiableCredential, other.VerifiableCredential)
                && StructuralEquality.SequenceEqual(EnvelopedVerifiableCredential, other.EnvelopedVerifiableCredential)
                && StructuralEquality.SequenceEqual(TermsOfUse, other.TermsOfUse)
                && StructuralEquality.JsonEqual(AdditionalData, other.AdditionalData);
        }


        /// <inheritdoc/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public override bool Equals([NotNullWhen(true)] object? obj) =>
            obj is VerifiablePresentation other && Equals(other);


        /// <inheritdoc/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public override int GetHashCode()
        {
            var hash = new HashCode();
            hash.Add(Context);
            hash.Add(Id, StringComparer.Ordinal);
            hash.Add(Holder, StringComparer.Ordinal);
            hash.Add(StructuralEquality.SequenceHashCode(Type));
            hash.Add(StructuralEquality.SequenceHashCode(VerifiableCredential));
            hash.Add(StructuralEquality.SequenceHashCode(EnvelopedVerifiableCredential));
            hash.Add(StructuralEquality.SequenceHashCode(TermsOfUse));
            hash.Add(StructuralEquality.JsonHashCode(AdditionalData));

            return hash.ToHashCode();
        }


        /// <inheritdoc/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static bool operator ==(VerifiablePresentation? left, VerifiablePresentation? right)
        {
            if(left is null)
            {
                return right is null;
            }

            return left.Equals(right);
        }


        /// <inheritdoc/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static bool operator !=(VerifiablePresentation? left, VerifiablePresentation? right) => !(left == right);
    }
}
