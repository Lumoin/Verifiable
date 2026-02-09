using System;

namespace Verifiable.Core.Model.Did.Methods
{
    /// <summary>
    /// The DID Keri method identifier.
    /// </summary>
    /// <remarks>Authoritative definition at <see href="https://weboftrust.github.io/ietf-did-keri/draft-pfeairheller-did-keri.html#section-3.1">
    /// The 3. did:keri Format: 3.1 Method Name</see>.</remarks>
    public record KeriDidMethod: GenericDidMethod
    {
        public KeriDidMethod(string didString): base(didString)
        {
            ArgumentNullException.ThrowIfNull(didString);
            if(!didString.StartsWith("did:keri:", StringComparison.InvariantCulture))
            {
                throw new ArgumentException("The DID string must start with 'did:keri:'", nameof(didString));
            }
        }


        /// <summary>
        /// Implicit conversion from <see cref="KeriDidMethod"/> or derived DID methods to <see langword="string"/>.
        /// </summary>
        /// <param name="didId"></param>
        public static implicit operator string(KeriDidMethod didId)
        {
            ArgumentNullException.ThrowIfNull(didId);

            return didId.Id;
        }


        /// <summary>
        /// Explicit conversion from <see langword="string"/> to <see cref="KeriDidMethod"/> or derived DID methods.
        /// </summary>
        /// <param name="didId"></param>
        public static explicit operator KeriDidMethod(string didId)
        {
            ArgumentNullException.ThrowIfNull(didId);

            return new KeriDidMethod(didId);
        }

       
        /// <inheritdoc/>
        public override string ToString() => Id;        
    }
}
