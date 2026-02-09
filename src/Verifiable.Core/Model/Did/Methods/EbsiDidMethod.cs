using System;

namespace Verifiable.Core.Model.Did.Methods
{
    public record EbsiDidMethod: GenericDidMethod
    {
        /// <summary>
        /// The prefix of this particular DID method, including suffix <c>':'</c>.
        /// </summary>
        /// <remarks>This is <see cref="WellKnownDidMethodPrefixes.Ebsi"/> with colon.</remarks>
        public static new string Prefix => "did:ebsi:";


        public EbsiDidMethod(string didString): base(didString)
        {
            ArgumentNullException.ThrowIfNull(didString);
            if(!didString.StartsWith(Prefix, StringComparison.InvariantCulture))
            {
                throw new ArgumentException($"The DID string must start with '{Prefix}'.", nameof(didString));
            }
        }


        /// <summary>
        /// Implicit conversion from <see cref="EbsiDidMethod"/> or derived DID methods to <see langword="string"/>.
        /// </summary>
        /// <param name="didId"></param>
        public static implicit operator string(EbsiDidMethod didId)
        {
            ArgumentNullException.ThrowIfNull(didId);

            return didId.Id;
        }


        /// <summary>
        /// Explicit conversion from <see langword="string"/> to <see cref="EbsiDidMethod"/> or derived DID methods.
        /// </summary>
        /// <param name="didId"></param>
        public static explicit operator EbsiDidMethod(string didId)
        {
            ArgumentNullException.ThrowIfNull(didId);

            return new(didId);
        }


        /// <inheritdoc/>
        public override string ToString() => Id;
    }
}
