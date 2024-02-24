using System;

namespace Verifiable.Core.Did.Methods
{
    public record EbsiDidMethod: GenericDidMethod
    {
        /// <summary>
        /// The prefix of this particular DID method.
        /// </summary>
        public static new string Prefix => "did:ebsi:";


        public EbsiDidMethod(string didString) : base(didString)
        {
            if(!didString.StartsWith("did:ebsi:"))
            {
                throw new ArgumentException("The DID string must start with 'did:ebsi:'", nameof(didString));
            }
        }


        /// <summary>
        /// Implicit conversion from <see cref="EbsiDidMethod"/> or derived DID methods to <see langword="string"/>.
        /// </summary>
        /// <param name="didId"></param>
        public static implicit operator string(EbsiDidMethod didId) => didId.Id;


        /// <summary>
        /// Explicit conversion from <see langword="string"/> to <see cref="EbsiDidMethod"/> or derived DID methods.
        /// </summary>
        /// <param name="didId"></param>
        public static explicit operator EbsiDidMethod(string didId) => new(didId);
    }
}
