using System;
using System.Diagnostics;
using System.Linq;

namespace Verifiable.Core.Did
{
    //TODO: Probably the explanations from https://www.w3.org/TR/did-core/#architecture-overview
    //should be added directly to DidDocument.

    //These at https://www.w3.org/TR/did-core/#did-parameters could be extension methods
    //and something like HasService(), GetService() so the core type remains open to extension
    //and simple. These are extensible, although official DID registries are recommended.

    //ICollection -> the order does not matter
    //IList -> the order matters
    //Consider using IReadOnly versions?

    //Check optionality at https://www.w3.org/TR/did-core/#core-properties-for-a-did-document
    //and decide if type checking should be used (now added ad-hoc) or optionality types
    //or both. Type system checks would allow missing types during runtime, which may
    //preferrable, but maybe it should be clear by way of using appropriate runtime
    //types if they are not flagged by correctness-checking functions or exceptions?

    /// <summary>
    /// https://w3c.github.io/did-core/
    /// </summary>
    [DebuggerDisplay("DidDocument(Id = {Id})")]
    public class DidDocument: IEquatable<DidDocument>
    {
        /// <summary>
        /// https://w3c.github.io/did-core/#json-ld
        /// </summary>
        public Context? Context { get; set; }

        /// <summary>
        /// https://w3c.github.io/did-core/#did-subject
        /// </summary>
        public Uri? Id { get; set; }

        //TODO: Make this a real class.
        /// <summary>
        /// https://w3c.github.io/did-core/#also-known-as.
        /// </summary>
        public string[]? AlsoKnownAs { get; set; }
        
        /// <summary>
        /// https://w3c.github.io/did-core/#did-controller
        /// </summary>
        public Controller[]? Controller { get; set; }

        /// <summary>
        /// https://w3c.github.io/did-core/#verification-methods
        /// </summary>
        public VerificationMethod[]? VerificationMethod { get; set; }

        /// <summary>
        /// https://w3c.github.io/did-core/#authentication
        /// </summary>
        public AuthenticationMethod[]? Authentication { get; set; }

        /// <summary>
        /// https://w3c.github.io/did-core/#assertionmethod
        /// </summary>
        public AssertionMethod[]? AssertionMethod { get; set; }

        /// <summary>
        /// https://w3c.github.io/did-core/#keyagreement
        /// </summary>
        public KeyAgreementMethod[]? KeyAgreement { get; set; }

        /// <summary>
        /// https://w3c.github.io/did-core/#capabilitydelegation
        /// </summary>
        public CapabilityDelegationMethod[]? CapabilityDelegation { get; set; }

        /// <summary>
        /// https://w3c.github.io/did-core/#capabilityinvocation
        /// </summary>
        public CapabilityInvocationMethod[]? CapabilityInvocation { get; set; }

        /// <summary>
        /// https://w3c.github.io/did-core/#service-endpoints
        /// </summary>
        public Service[]? Service { get; set; }

        //TODO: The following as JSON Extension data + plus inherited from the converter?

        /// <summary>
        /// https://www.w3.org/TR/did-spec-registries/#created
        /// </summary>
        /*[JsonPropertyName("created")]
        public DateTimeOffset? Created { get; set; }

        /// <summary>
        /// https://www.w3.org/TR/did-spec-registries/#updated
        /// </summary>
        [JsonPropertyName("updated")]
        public DateTimeOffset? Updated { get; set; }*/

        //TODO: The following is technical equality, also logical one should be considered.
        //See at https://w3c.github.io/did-core/#also-known-as.

        /// <inheritdoc/>
        public override bool Equals(object? obj)
        {
            if (obj is null)
            {
                return false;
            }

            if (ReferenceEquals(this, obj))
            {
                return true;
            }

            if (GetType() != obj.GetType())
            {
                return false;
            }

            return Equals((DidDocument)obj);
        }


        /// <inheritdoc/>
        public bool Equals(DidDocument? other)
        {
            if (other is null)
            {
                return false;
            }

            return Context == other.Context
                && Id == other?.Id
                && (AlsoKnownAs?.SequenceEqual(other!.AlsoKnownAs!)).GetValueOrDefault()
                && (Controller?.SequenceEqual(other!.Controller!)).GetValueOrDefault()
                && (VerificationMethod?.SequenceEqual(other!.VerificationMethod!)).GetValueOrDefault()
                && (Authentication?.SequenceEqual(other!.Authentication!)).GetValueOrDefault()
                && (AssertionMethod?.SequenceEqual(other!.AssertionMethod!)).GetValueOrDefault()
                && (KeyAgreement?.SequenceEqual(other!.KeyAgreement!)).GetValueOrDefault()
                && (CapabilityDelegation?.SequenceEqual(other!.CapabilityDelegation!)).GetValueOrDefault()
                && (Service?.SequenceEqual(other!.Service!)).GetValueOrDefault();
        }


        /// <inheritdoc/>
        public override int GetHashCode()
        {
            var hash = new HashCode();
            hash.Add(Context);
            hash.Add(Id);

            for (int i = 0; i < AlsoKnownAs?.Length; ++i)
            {
                hash.Add(AlsoKnownAs[i]);
            }

            for (int i = 0; i < Controller?.Length; ++i)
            {
                hash.Add(Controller[i]);
            }

            for (int i = 0; i < VerificationMethod?.Length; ++i)
            {
                hash.Add(VerificationMethod[i]);
            }

            for (int i = 0; i < Authentication?.Length; ++i)
            {
                hash.Add(Authentication[i]);
            }

            for (int i = 0; i < AssertionMethod?.Length; ++i)
            {
                hash.Add(AssertionMethod[i]);
            }

            for (int i = 0; i < KeyAgreement?.Length; ++i)
            {
                hash.Add(KeyAgreement[i]);
            }

            for (int i = 0; i < KeyAgreement?.Length; ++i)
            {
                hash.Add(KeyAgreement[i]);
            }

            for (int i = 0; i < CapabilityDelegation?.Length; ++i)
            {
                hash.Add(CapabilityDelegation[i]);
            }

            for (int i = 0; i < Service?.Length; ++i)
            {
                hash.Add(Service[i]);
            }

            return hash.ToHashCode();
        }
    }
}
