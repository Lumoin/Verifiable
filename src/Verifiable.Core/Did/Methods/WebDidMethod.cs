using System;

namespace Verifiable.Core.Did.Methods
{
    public record WebDidMethod: GenericDidMethod
    {
        public WebDidMethod(string didString) : base(didString)
        {
            if(!didString.StartsWith("did:web:"))
            {
                throw new ArgumentException("The DID string must start with 'did:web:'", nameof(didString));
            }
        }


        /// <summary>
        /// Implicit conversion from <see cref="WebDidMethod"/> or derived DID methods to <see langword="string"/>.
        /// </summary>
        /// <param name="didId"></param>
        public static implicit operator string(WebDidMethod didId) => didId.Id;


        /// <summary>
        /// Explicit conversion from <see langword="string"/> to <see cref="WebDidMethod"/> or derived DID methods.
        /// </summary>
        /// <param name="didId"></param>
        public static explicit operator WebDidMethod(string didId) => new(didId);
    }
}
