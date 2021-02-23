using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;


namespace DotDecentralized.Core.Did
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
    public class DidDocument : IEquatable<DidDocument>
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

        //TODO: Make this a Controller class, maybe with implicit and explicit conversion to and from string. Same for some key formats?
        /// <summary>
        /// https://w3c.github.io/did-core/#control
        /// </summary>
        public string[]? Controller { get; set; }

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


    /// <summary>
    /// https://www.w3.org/TR/did-core/#services
    /// </summary>
    [DebuggerDisplay("Service(Id = {Id})")]
    public class Service
    {
        public Uri? Id { get; set; }

        //This should be an array, see new document. Do in converter like for Context. Maybe introduce type for this purpose?
        //https://docs.microsoft.com/en-us/dotnet/api/system.collections.generic.sortedlist-2 etc.?
        //Maybe with explicit conversions to/from a type? See https://docs.microsoft.com/en-us/dotnet/csharp/language-reference/operators/user-defined-conversion-operators.
        public string? Type { get; set; }

        //This can a string, a map or a set. See at https://www.w3.org/TR/did-core/#service-properties. In ION there is "serviceEndpoint": { "origins": [ "https://www.vcsatoshi.com/" ] }.
        //Look at https://github.com/dotnet/runtime/issues/53195, https://github.com/steveharter/designs/blob/6437453395619af937bf84a60c13d1bc43d7ca05/accepted/2020/serializer/WriteableDomAndDynamic.md#api-walkthrough
        //and https://github.com/dotnet/designs/pull/163 for a writeable DOM and complex object logic with STJ (and Newtonsoft).
        public string? ServiceEndpoint { get; set; }

        //Here is an example of a more complicated service endpoint. -> Take in as a test.
        //https://www.w3.org/TR/did-spec-registries/#example-24-example-of-service-and-serviceendpoint-properties

        //The following comment should probably include, in addition to "standard notes" that
        //one preferably should extend the data instead of putting it into a bucket like that.
        //But that the bucket exists in case one wants to "eat up" all data.
        //Is ServiceDtos examples the best way to see this? I.e. the AdditionalData is not visible
        //UNLESS on inherits. It needs to clear it's so that one needs to inherit if additional data
        //is expected? Also, shouldn't in those examples the ServiceEndpoint be extended?

        /// <summary>
        /// Each service extension MAY include additional properties and MAY further restrict the properties associated with the extension.
        /// </summary>
        //public IDictionary<string, object>? AdditionalData { get; set; }
    }


    /// <summary>
    /// https://w3c.github.io/did-core/#key-types-and-formats
    /// </summary>
    public static class DidCoreKeyTypes
    {
        public const string RsaVerificationKey2018 = "rsaVerificationKey2018";
        public const string Ed25519VerificationKey2018 = "ed25519VerificationKey2018";
        public const string SchnorrSecp256k1VerificationKey2019 = "schnorrSecp256k1VerificationKey2019";
        public const string X25519KeyAgreementKey2019 = "x25519KeyAgreementKey2019";
    }


    /// <summary>
    /// Constants for various cryptographic algorithms used in
    /// decentralized identifiers and verifiable credentials.
    /// </summary>
    public static class CryptographyAlgorithmConstants
    {
        /// <summary>
        /// ECDH constants.
        /// </summary>
        public static class Ecdh
        {
            /// <summary>
            /// By definition, see at <see href="https://tools.ietf.org/html/rfc8037#section-2"/>.
            /// </summary>
            public const string KeyType = "OKP";

            /// <summary>
            /// By definition, see at <see href="https://tools.ietf.org/html/rfc8032#section-5.1.5"/>.
            /// </summary>
            public const int KeySizeInBytes = 32;

            public static class EdDsa
            {
                public const string Algorithm = "EdDSA";

                /// <summary>
                /// EdDSA key curves.
                /// </summary>
                public static class Curves
                {
                    //TODO: Add links to definitions as linked in https://tools.ietf.org/html/rfc8037#page-7.
                    public const string Ed25519 = "Ed25519";
                    public const string Ed448 = "Ed448";
                }
            }


            // https://www.rfc-editor.org/rfc/rfc8037.html#section-3.2
            public static class EcdhEs
            {
                //https://datatracker.ietf.org/doc/html/rfc7748#section-6.1
                public static class Curves
                {
                    public const string X25519 = "X25519";
                    public const string X448 = "X448";
                }
            }
        }
    }


    //TODO: These not as nameof-attributes since in the specification they start with
    //small letter while capital letter is a .NET convention.
    /// <summary>
    /// https://www.w3.org/TR/did-spec-registries/#verification-method-types
    /// </summary>
    public static class DidRegisteredKeyTypes
    {
        /// <summary>
        /// https://www.w3.org/TR/did-spec-registries/#jwsverificationkey2020
        /// </summary>
        public const string JwsVerificationKey2020 = "jwsVerificationKey2020";

        /// <summary>
        /// https://www.w3.org/TR/did-spec-registries/#ecdsasecp256k1verificationkey2019
        /// </summary>
        public const string EcdsaSecp256k1VerificationKey2019 = "ecdsaSecp256k1VerificationKey2019";

        /// <summary>
        /// https://www.w3.org/TR/did-spec-registries/#ed25519verificationkey2018
        /// </summary>
        public const string Ed25519VerificationKey2018 = "ed25519VerificationKey2018";

        /// <summary>
        /// https://www.w3.org/TR/did-spec-registries/#gpgverificationkey2020
        /// </summary>
        public const string GpgVerificationKey2020 = "gpgVerificationKey2020";

        /// <summary>
        /// https://www.w3.org/TR/did-spec-registries/#rsaverificationkey2018
        /// </summary>
        public const string RsaVerificationKey2018 = "rsaVerificationKey2018";

        /// <summary>
        /// https://www.w3.org/TR/did-spec-registries/#x25519keyagreementkey2019
        /// </summary>
        public const string X25519KeyAgreementKey2019 = "x25519KeyAgreementKey2019";

        /// <summary>
        /// https://www.w3.org/TR/did-spec-registries/#ecdsasecp256k1recoverymethod2020
        /// </summary>
        public const string EcdsaSecp256k1RecoveryMethod2020 = "ecdsaSecp256k1RecoveryMethod2020";
    }


    /// <summary>
    /// This class holds some general constants as specified by DID Core specification.
    /// </summary>
    public static class DidCoreConstants
    {
        /// <summary>
        /// The DID documents must have a @context part in which the first URI is this.
        /// </summary>
        public const string JsonLdContextFirstUri = "https://www.w3.org/ns/did/v1";
    }

    /// <summary>
    /// https://www.w3.org/TR/did-core/#key-types-and-formats
    /// </summary>
    public abstract class KeyFormat { }


    [DebuggerDisplay("PublicKeyHex({Key})")]
    public class PublicKeyHex : KeyFormat
    {
        public string Key { get; set; }

        public PublicKeyHex(string key)
        {
            Key = key ?? throw new ArgumentNullException(nameof(key));
        }
    }


    [DebuggerDisplay("PublicKeyBase58({Key})")]
    public class PublicKeyBase58 : KeyFormat
    {
        public string Key { get; set; }

        public PublicKeyBase58(string key)
        {
            Key = key ?? throw new ArgumentNullException(nameof(key));
        }
    }


    [DebuggerDisplay("PublicKeyPem({Key})")]
    public class PublicKeyPem : KeyFormat
    {
        public string Key { get; set; }

        public PublicKeyPem(string key)
        {
            Key = key ?? throw new ArgumentNullException(nameof(key));
        }
    }


    /// <summary>
    /// https://www.w3.org/TR/did-core/#dfn-publickeyjwk, https://tools.ietf.org/html/rfc7517
    /// </summary>
    /// <remarks>Note that must not contain private key information, such as 'd' field,
    /// by DID Core specification.</remarks>
    [DebuggerDisplay("PublicKeyJwk(Crv = {Crv}, Kid = {Kid}, Kty = {Kty}, X = {X}, Y = {Y}, E = {E}, N = {N})")]
    public class PublicKeyJwk : KeyFormat
    {
        public string? Crv { get; set; }

        public string? Kid { get; set; }

        public string? Kty { get; set; }

        public string? X { get; set; }

        public string? Y { get; set; }

        //'E' and 'N' are for the RSA keys as per RFC 7517.
        public string? E { get; set; }

        public string? N { get; set; }
    }


    /// <summary>
    /// https://w3c.github.io/did-core/#verification-methods
    /// </summary>
    [DebuggerDisplay("VerificationMethod(Id = {Id})")]
    public class VerificationMethod
    {
        //TODO: Could be FractionOrUri: Uri, or C# 10/F# discriminated union (like VerificationRelationship would be).
        public string? Id { get; set; }

        public string? Type { get; set; }

        public string? Controller { get; set; }

        public KeyFormat? KeyFormat { get; set; }
    }


    /// <summary>
    /// https://w3c.github.io/did-core/#verification-methods
    /// The reference Id field is string because it can be a fragment like "#key-1".
    /// </summary>
    [DebuggerDisplay("VerificationRelationship(Id = {Id}, IsEmbeddedVerification = {IsEmbeddedVerification})")]
    public abstract class VerificationRelationship
    {
        public string? VerificationReferenceId { get; }
        public VerificationMethod? EmbeddedVerification { get; }

        protected VerificationRelationship(string verificationReferenceId) => VerificationReferenceId = verificationReferenceId;
        protected VerificationRelationship(VerificationMethod embeddedVerification) => EmbeddedVerification = embeddedVerification;

        public string? Id => EmbeddedVerification == null ? VerificationReferenceId : EmbeddedVerification.Id?.ToString();

        public bool IsEmbeddedVerification { get { return EmbeddedVerification != null; } }
    }


    /// <summary>
    /// https://w3c.github.io/did-core/#verification-methods
    /// </summary>
    [DebuggerDisplay("AuthenticationMethod(Id = {Id}, IsEmbeddedVerification = {IsEmbeddedVerification})")]
    public class AuthenticationMethod : VerificationRelationship
    {
        public AuthenticationMethod(string verificationReferenceId) : base(verificationReferenceId) { }
        public AuthenticationMethod(VerificationMethod embeddedVerification) : base(embeddedVerification) { }
    }

    /// <summary>
    /// https://w3c.github.io/did-core/#verification-methods
    /// </summary>
    [DebuggerDisplay("AssertionMethod(Id = {Id}, IsEmbeddedVerification = {IsEmbeddedVerification})")]
    public class AssertionMethod : VerificationRelationship
    {
        public AssertionMethod(string verificationReferenceId) : base(verificationReferenceId) { }
        public AssertionMethod(VerificationMethod embeddedVerification) : base(embeddedVerification) { }
    }


    /// <summary>
    /// https://w3c.github.io/did-core/#verification-methods
    /// </summary>
    [DebuggerDisplay("KeyAgreementMethod(Id = {Id}, IsEmbeddedVerification = {IsEmbeddedVerification})")]
    public class KeyAgreementMethod : VerificationRelationship
    {
        public KeyAgreementMethod(string verificationReferenceId) : base(verificationReferenceId) { }
        public KeyAgreementMethod(VerificationMethod embeddedVerification) : base(embeddedVerification) { }
    }

    /// <summary>
    /// https://www.w3.org/TR/did-core/#verification-methods
    /// </summary>
    [DebuggerDisplay("CapabilityDelegationMethod(Id = {Id}, IsEmbeddedVerification = {IsEmbeddedVerification})")]
    public class CapabilityDelegationMethod : VerificationRelationship
    {
        public CapabilityDelegationMethod(string verificationReferenceId) : base(verificationReferenceId) { }
        public CapabilityDelegationMethod(VerificationMethod embeddedVerification) : base(embeddedVerification) { }
    }

    /// <summary>
    /// https://w3c.github.io/did-core/#verification-methods
    /// </summary>
    [DebuggerDisplay("CapabilityInvocationMethod(Id = {Id}, IsEmbeddedVerification = {IsEmbeddedVerification})")]
    public class CapabilityInvocationMethod : VerificationRelationship
    {
        public CapabilityInvocationMethod(string verificationReferenceId) : base(verificationReferenceId) { }
        public CapabilityInvocationMethod(VerificationMethod embeddedVerification) : base(embeddedVerification) { }
    }


    //TODO: Should the additional data be typed or a generic? In .NET5 it could be
    //Dynamic, modelled as in https://docs.microsoft.com/en-us/dotnet/standard/serialization/system-text-json-converters-how-to?pivots=dotnet-5-0#deserialize-inferred-types-to-object-properties.
    //The issue here already now is about reading arbitrary amounts of data from a network
    //or another source beyond trust boundary.
    //Look at https://github.com/dotnet/runtime/issues/29690, https://github.com/steveharter/designs/blob/6437453395619af937bf84a60c13d1bc43d7ca05/accepted/2020/serializer/WriteableDomAndDynamic.md#api-walkthrough
    //and https://github.com/dotnet/designs/pull/163 for a writeable DOM and complex object logic with STJ (and Newtonsoft).
    /// <summary>
    /// https://www.w3.org/TR/did-spec-registries/#context
    /// </summary>
    public class Context
    {
        public List<object>? Contexes { get; set; }

        public IDictionary<string, object>? AdditionalData { get; set; }
    }
}
