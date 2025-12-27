using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using Verifiable.Core.Model.Common;
using Verifiable.Core.Model.Did.Methods;

namespace Verifiable.Core.Model.Did
{
    /// <summary>
    /// Represents a DID document as defined in W3C DID Core and Controlled Identifiers specifications.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A DID document contains information associated with a DID, including mechanisms
    /// that the DID subject can use to authenticate itself and prove its association
    /// with the DID. A DID document might also contain additional attributes or claims
    /// describing the subject.
    /// </para>
    /// <para>
    /// The DID document is the result of DID resolution and contains:
    /// </para>
    /// <list type="bullet">
    /// <item><description>The DID subject identifier</description></item>
    /// <item><description>Verification methods (cryptographic public keys)</description></item>
    /// <item><description>Verification relationships (how keys can be used)</description></item>
    /// <item><description>Service endpoints for interacting with the subject</description></item>
    /// </list>
    /// <para>
    /// See <see href="https://www.w3.org/TR/did-1.0/#did-documents">DID Core §4 DID Documents</see>
    /// and <see href="https://www.w3.org/TR/cid-1.0/">Controlled Identifiers (CID) 1.0</see>.
    /// </para>
    /// </remarks>
    [DebuggerDisplay("{Id}")]
    public class DidDocument: IEquatable<DidDocument>
    {
        /// <summary>
        /// The JSON-LD context for the DID document.
        /// </summary>
        /// <remarks>
        /// <para>
        /// The <c>@context</c> property defines the vocabulary used in the DID document.
        /// At minimum, this should include the DID Core context. Additional contexts
        /// may be added for verification method types, service types, or other extensions.
        /// </para>
        /// <para>
        /// See <see href="https://www.w3.org/TR/did-1.0/#production-0">DID Core §4.1 @context</see>.
        /// </para>
        /// </remarks>
        public Context? Context { get; set; }


        /// <summary>
        /// The DID subject that this document describes.
        /// </summary>
        /// <remarks>
        /// <para>
        /// The <c>id</c> property is the DID for the subject of the DID document.
        /// This is the only required property in a DID document. The type is
        /// <see cref="GenericDidMethod"/> to allow lenient parsing of any DID method;
        /// the serialization converter may produce a more specific type if the
        /// DID method is recognized.
        /// </para>
        /// <para>
        /// See <see href="https://www.w3.org/TR/did-1.0/#did-subject">DID Core §4.2 DID Subject</see>.
        /// </para>
        /// </remarks>
        public GenericDidMethod? Id { get; set; }


        /// <summary>
        /// Alternative identifiers for the DID subject.
        /// </summary>
        /// <remarks>
        /// <para>
        /// The <c>alsoKnownAs</c> property contains URIs that the DID subject is also
        /// known by. These can be other DIDs or any conformant URI per RFC 3986.
        /// </para>
        /// <para>
        /// See <see href="https://www.w3.org/TR/cid-1.0/#also-known-as">CID 1.0 §2.1.3 Also Known As</see>.
        /// </para>
        /// </remarks>
        public string[]? AlsoKnownAs { get; set; }


        /// <summary>
        /// The entities authorized to make changes to this DID document.
        /// </summary>
        /// <remarks>
        /// <para>
        /// The <c>controller</c> property identifies one or more entities that are
        /// authorized to make changes to the DID document. Each controller is identified
        /// by a DID.
        /// </para>
        /// <para>
        /// See <see href="https://www.w3.org/TR/cid-1.0/#controller">CID 1.0 §2.1.2 Controller</see>.
        /// </para>
        /// </remarks>
        public Controller[]? Controller { get; set; }


        /// <summary>
        /// The verification methods associated with this DID document.
        /// </summary>
        /// <remarks>
        /// <para>
        /// The <c>verificationMethod</c> property contains cryptographic public keys
        /// or other verification methods that can be referenced by verification
        /// relationships. These methods are not directly usable until they are
        /// referenced by a verification relationship.
        /// </para>
        /// <para>
        /// See <see href="https://www.w3.org/TR/cid-1.0/#verification-methods">CID 1.0 §2.2 Verification Methods</see>.
        /// </para>
        /// </remarks>
        public VerificationMethod[]? VerificationMethod { get; set; }


        /// <summary>
        /// Verification methods used for authentication.
        /// </summary>
        /// <remarks>
        /// <para>
        /// The <c>authentication</c> verification relationship is used to specify how
        /// the DID subject is expected to be authenticated, for purposes such as
        /// logging into a website or engaging in challenge-response protocols.
        /// </para>
        /// <para>
        /// See <see cref="AuthenticationMethod"/> and
        /// <see href="https://www.w3.org/TR/cid-1.0/#authentication">CID 1.0 §2.3.1 Authentication</see>.
        /// </para>
        /// </remarks>
        public AuthenticationMethod[]? Authentication { get; set; }


        /// <summary>
        /// Verification methods used for making assertions.
        /// </summary>
        /// <remarks>
        /// <para>
        /// The <c>assertionMethod</c> verification relationship is used to specify how
        /// the DID subject is expected to express claims, such as for issuing
        /// Verifiable Credentials.
        /// </para>
        /// <para>
        /// See <see cref="AssertionMethod"/> and
        /// <see href="https://www.w3.org/TR/cid-1.0/#assertion">CID 1.0 §2.3.2 Assertion</see>.
        /// </para>
        /// </remarks>
        public AssertionMethod[]? AssertionMethod { get; set; }


        /// <summary>
        /// Verification methods used for key agreement.
        /// </summary>
        /// <remarks>
        /// <para>
        /// The <c>keyAgreement</c> verification relationship is used to specify how
        /// an entity can generate encryption material to transmit confidential
        /// information to the DID subject.
        /// </para>
        /// <para>
        /// See <see cref="KeyAgreementMethod"/> and
        /// <see href="https://www.w3.org/TR/cid-1.0/#key-agreement">CID 1.0 §2.3.3 Key Agreement</see>.
        /// </para>
        /// </remarks>
        public KeyAgreementMethod[]? KeyAgreement { get; set; }


        /// <summary>
        /// Verification methods used for capability invocation.
        /// </summary>
        /// <remarks>
        /// <para>
        /// The <c>capabilityInvocation</c> verification relationship is used to specify
        /// verification methods that might be used by the DID subject to invoke
        /// cryptographic capabilities, such as authorization to update the DID document.
        /// </para>
        /// <para>
        /// See <see cref="CapabilityInvocationMethod"/> and
        /// <see href="https://www.w3.org/TR/cid-1.0/#capability-invocation">CID 1.0 §2.3.4 Capability Invocation</see>.
        /// </para>
        /// </remarks>
        public CapabilityInvocationMethod[]? CapabilityInvocation { get; set; }


        /// <summary>
        /// Verification methods used for capability delegation.
        /// </summary>
        /// <remarks>
        /// <para>
        /// The <c>capabilityDelegation</c> verification relationship is used to specify
        /// mechanisms that might be used by the DID subject to delegate cryptographic
        /// capabilities to another party.
        /// </para>
        /// <para>
        /// See <see cref="CapabilityDelegationMethod"/> and
        /// <see href="https://www.w3.org/TR/cid-1.0/#capability-delegation">CID 1.0 §2.3.5 Capability Delegation</see>.
        /// </para>
        /// </remarks>
        public CapabilityDelegationMethod[]? CapabilityDelegation { get; set; }


        /// <summary>
        /// Service endpoints associated with the DID subject.
        /// </summary>
        /// <remarks>
        /// <para>
        /// The <c>service</c> property contains service endpoints that can be used
        /// to interact with the DID subject or associated entities. Services can
        /// represent messaging endpoints, credential repositories, or any other
        /// type of service.
        /// </para>
        /// <para>
        /// See <see href="https://www.w3.org/TR/cid-1.0/#services">CID 1.0 §2.1.4 Services</see>.
        /// </para>
        /// </remarks>
        public Service[]? Service { get; set; }


        /// <inheritdoc/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public override bool Equals([NotNullWhen(true)] object? obj)
        {
            if(obj is null)
            {
                return false;
            }

            if(ReferenceEquals(this, obj))
            {
                return true;
            }

            if(GetType() != obj.GetType())
            {
                return false;
            }

            return Equals((DidDocument)obj);
        }


        /// <inheritdoc/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public bool Equals(DidDocument? other)
        {
            if(other is null)
            {
                return false;
            }

            return Equals(Id, other.Id)
                && Equals(Context, other.Context)
                && (AlsoKnownAs?.SequenceEqual(other.AlsoKnownAs!) ?? other.AlsoKnownAs is null)
                && (Controller?.SequenceEqual(other.Controller!) ?? other.Controller is null)
                && (VerificationMethod?.SequenceEqual(other.VerificationMethod!) ?? other.VerificationMethod is null)
                && (Authentication?.SequenceEqual(other.Authentication!) ?? other.Authentication is null)
                && (AssertionMethod?.SequenceEqual(other.AssertionMethod!) ?? other.AssertionMethod is null)
                && (KeyAgreement?.SequenceEqual(other.KeyAgreement!) ?? other.KeyAgreement is null)
                && (CapabilityInvocation?.SequenceEqual(other.CapabilityInvocation!) ?? other.CapabilityInvocation is null)
                && (CapabilityDelegation?.SequenceEqual(other.CapabilityDelegation!) ?? other.CapabilityDelegation is null)
                && (Service?.SequenceEqual(other.Service!) ?? other.Service is null);
        }


        /// <inheritdoc/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public override int GetHashCode()
        {
            var hash = new HashCode();
            hash.Add(Context);
            hash.Add(Id);

            if(AlsoKnownAs is not null)
            {
                for(int i = 0; i < AlsoKnownAs.Length; ++i)
                {
                    hash.Add(AlsoKnownAs[i]);
                }
            }

            if(Controller is not null)
            {
                for(int i = 0; i < Controller.Length; ++i)
                {
                    hash.Add(Controller[i]);
                }
            }

            if(VerificationMethod is not null)
            {
                for(int i = 0; i < VerificationMethod.Length; ++i)
                {
                    hash.Add(VerificationMethod[i]);
                }
            }

            if(Authentication is not null)
            {
                for(int i = 0; i < Authentication.Length; ++i)
                {
                    hash.Add(Authentication[i]);
                }
            }

            if(AssertionMethod is not null)
            {
                for(int i = 0; i < AssertionMethod.Length; ++i)
                {
                    hash.Add(AssertionMethod[i]);
                }
            }

            if(KeyAgreement is not null)
            {
                for(int i = 0; i < KeyAgreement.Length; ++i)
                {
                    hash.Add(KeyAgreement[i]);
                }
            }

            if(CapabilityInvocation is not null)
            {
                for(int i = 0; i < CapabilityInvocation.Length; ++i)
                {
                    hash.Add(CapabilityInvocation[i]);
                }
            }

            if(CapabilityDelegation is not null)
            {
                for(int i = 0; i < CapabilityDelegation.Length; ++i)
                {
                    hash.Add(CapabilityDelegation[i]);
                }
            }

            if(Service is not null)
            {
                for(int i = 0; i < Service.Length; ++i)
                {
                    hash.Add(Service[i]);
                }
            }

            return hash.ToHashCode();
        }


        /// <inheritdoc/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static bool operator ==(DidDocument? left, DidDocument? right)
        {
            if(left is null)
            {
                return right is null;
            }

            return left.Equals(right);
        }


        /// <inheritdoc/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static bool operator !=(DidDocument? left, DidDocument? right)
        {
            return !(left == right);
        }
    }
}