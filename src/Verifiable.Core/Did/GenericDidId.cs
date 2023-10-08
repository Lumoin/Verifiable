using System;
using System.Diagnostics;


namespace Verifiable.Core.Did
{
    public static class WellKnownDidMethodPrefixes
    {
        /// <summary>
        /// 
        /// </summary>
        public static readonly string KeyDidPrefix = "did:key:";

        /// <summary>
        /// If <paramref name="didPrefix"/> is <see cref="KeyDidPrefix"/> or not.
        /// </summary>
        /// <param name="didPrefix">The did method prefix.</param>.
        /// <returns><see langword="true" /> if  <paramref name="didPrefix"/> is <see cref="KeyDidPrefix"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsKeyDidPrefix(string didPrefix) => Equals(KeyDidPrefix, didPrefix);

        /// <summary>
        /// Returns the equivalent static instance, or the original instance if none match.
        /// This conversion is optional but allows for performance optimizations when comparing method values elsewhere.
        /// </summary>
        /// <param name="didPrefix">The property to canocalize.</param>
        /// <returns>The equivalent static instance of <paramref name="didPrefix"/>, or the original instance if none match.</returns>
        public static string GetCanonicalizedValue(string didPrefix) => didPrefix switch
        {
            string _ when IsKeyDidPrefix(didPrefix) => KeyDidPrefix,
            string _ => didPrefix
        };


        /// <summary>
        /// Returns a value that indicates if the DID method prefixes are the same.
        /// </summary>
        /// <param name="didPrefixA">The first DID method prefix to compare.</param>
        /// <param name="didPrefixB">The second DID method prefix to compare.</param>
        /// <returns>
        /// <see langword="true" /> if the <paramref name="didPrefixA"/> and <paramref name="didPrefixB"/> are the same; otherwise, <see langword="false" />.
        /// </returns>
        public static bool Equals(string didPrefixA, string didPrefixB)
        {
            return object.ReferenceEquals(didPrefixA, didPrefixB) || StringComparer.InvariantCulture.Equals(didPrefixA, didPrefixB);
        }
    }


    /// <summary>
    /// This is used when the DID identifier is either not recognized or it is treated as a generic DID identifier.
    /// The identifier URN still need to conform with what is expected from a DID identifier and a URN.
    /// </summary>
    /// <remarks>The DID method specific identifiers should inherit from this. They may provide more granular constructors
    /// with DID method specific parameters and functionality.</remarks>
    [DebuggerDisplay("{Id}")]
    public record GenericDidId
    {
        /// <summary>
        /// The prefix of this particular DID method.
        /// </summary>
        public static string Prefix => string.Empty;

        /// <summary>
        /// The full DID identifier string.
        /// </summary>
        public string Id { get; private set; }


        /// <summary>
        /// Creates a new instance of <see cref="GenericDidId"/>. 
        /// </summary>
        /// <param name="id">The full DID identifier string.</param>
        public GenericDidId(string id)
        {
            Id = id;
        }


        /// <summary>
        /// Implicit conversion from <see cref="GenericDidId"/> or derived DID methods to <see langword="string"/>.
        /// </summary>
        /// <param name="didId"></param>
        public static implicit operator string(GenericDidId didId) => didId.Id;


        /// <summary>
        /// Explicit conversion from <see langword="string"/> to <see cref="GenericDidId"/> or derived DID methods.
        /// </summary>
        /// <param name="didId"></param>
        public static explicit operator GenericDidId(string didId) => new(didId);


        /// <inheritdoc/>
        public override string ToString() => Id;
    }


    public record KeyDidId: GenericDidId
    {
        /// <summary>
        /// The prefix of this particular DID method.
        /// </summary>
        public static new string Prefix => "did:key:";


        public KeyDidId(string didString) : base(didString)
        {
            if(!didString.StartsWith(Prefix))
            {
                throw new ArgumentException("The DID string must start with 'did:key:'", nameof(didString));
            }
        }


        /// <summary>
        /// Implicit conversion from <see cref="KeyDidId"/> or derived DID methods to <see langword="string"/>.
        /// </summary>
        /// <param name="didId"></param>
        public static implicit operator string(KeyDidId didId) => didId.Id;


        /// <summary>
        /// Explicit conversion from <see langword="string"/> to <see cref="KeyDidId"/> or derived DID methods.
        /// </summary>
        /// <param name="didId"></param>
        public static explicit operator KeyDidId(string didId) => new(didId);
    }


    public record WebDidId: GenericDidId
    {
        public WebDidId(string didString) : base(didString)
        {
            if(!didString.StartsWith("did:web:"))
            {
                throw new ArgumentException("The DID string must start with 'did:web:'", nameof(didString));
            }
        }


        /// <summary>
        /// Implicit conversion from <see cref="WebDidId"/> or derived DID methods to <see langword="string"/>.
        /// </summary>
        /// <param name="didId"></param>
        public static implicit operator string(WebDidId didId) => didId.Id;


        /// <summary>
        /// Explicit conversion from <see langword="string"/> to <see cref="WebDidId"/> or derived DID methods.
        /// </summary>
        /// <param name="didId"></param>
        public static explicit operator WebDidId(string didId) => new(didId);
    }


    public record EbsiDidId: GenericDidId
    {
        /// <summary>
        /// The prefix of this particular DID method.
        /// </summary>
        public static new string Prefix => "did:ebsi:";


        public EbsiDidId(string didString) : base(didString)
        {
            if(!didString.StartsWith("did:ebsi:"))
            {
                throw new ArgumentException("The DID string must start with 'did:ebsi:'", nameof(didString));
            }
        }


        /// <summary>
        /// Implicit conversion from <see cref="EbsiDidId"/> or derived DID methods to <see langword="string"/>.
        /// </summary>
        /// <param name="didId"></param>
        public static implicit operator string(EbsiDidId didId) => didId.Id;


        /// <summary>
        /// Explicit conversion from <see langword="string"/> to <see cref="EbsiDidId"/> or derived DID methods.
        /// </summary>
        /// <param name="didId"></param>
        public static explicit operator EbsiDidId(string didId) => new(didId);
    }


    /// <summary>
    /// The DID Keri method identifier.
    /// </summary>
    /// <remarks>Authoritative definition at <see href="https://weboftrust.github.io/ietf-did-keri/draft-pfeairheller-did-keri.html#section-3.1">
    /// The 3. did:keri Format: 3.1 Method Name</see>.</remarks>
    public record KeriDidId: GenericDidId
    {
        public KeriDidId(string didString) : base(didString)
        {
            if(!didString.StartsWith("did:keri:"))
            {
                throw new ArgumentException("The DID string must start with 'did:keri:'", nameof(didString));
            }
        }


        /// <summary>
        /// Implicit conversion from <see cref="KeriDidId"/> or derived DID methods to <see langword="string"/>.
        /// </summary>
        /// <param name="didId"></param>
        public static implicit operator string(KeriDidId didId) => didId.Id;


        /// <summary>
        /// Explicit conversion from <see langword="string"/> to <see cref="KeriDidId"/> or derived DID methods.
        /// </summary>
        /// <param name="didId"></param>
        public static explicit operator KeriDidId(string didId) => new(didId);
    }


    /// <summary>
    /// The DID AtProto Placeholder method identifier.
    /// </summary>
    /// <remarks>Authoritative definition at <see href="https://atproto.com/specs/did-plc">DID Placeholder (did:plc)</see>.</remarks>
    public record PlaceholderDidId: GenericDidId
    {
        public PlaceholderDidId(string didString) : base(didString)
        {
            if(!didString.StartsWith("did:plc:"))
            {
                throw new ArgumentException("The DID string must start with 'did:plc:'", nameof(didString));
            }
        }


        /// <summary>
        /// Implicit conversion from <see cref="PlaceholderDidId"/> or derived DID methods to <see langword="string"/>.
        /// </summary>
        /// <param name="didId"></param>
        public static implicit operator string(PlaceholderDidId didId) => didId.Id;


        /// <summary>
        /// Explicit conversion from <see langword="string"/> to <see cref="PlaceholderDidId"/> or derived DID methods.
        /// </summary>
        /// <param name="didId"></param>
        public static explicit operator PlaceholderDidId(string didId) => new(didId);
    }
}
