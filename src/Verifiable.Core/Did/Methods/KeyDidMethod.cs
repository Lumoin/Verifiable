using System;

namespace Verifiable.Core.Did.Methods
{
    public record KeyDidMethod: GenericDidMethod
    {
        /// <summary>
        /// The prefix of <c>did:key</c> method, including suffix <c>':'</c>.
        /// </summary>
        /// <remarks>This is <see cref="WellKnownDidMethodPrefixes.KeyDidMethodPrefix"/> with colon.</remarks>
        public static new string Prefix { get; } = $"{WellKnownDidMethodPrefixes.KeyDidMethodPrefix}:";


        public KeyDidMethod(string didString): base(didString)
        {            
            if(!didString.StartsWith(Prefix))
            {
                throw new ArgumentException($"The DID string must start with '{Prefix}'.", nameof(didString));
            }
        }


        /// <summary>
        /// Implicit conversion from <see cref="KeyDidMethod"/> or derived DID methods to <see langword="string"/>.
        /// </summary>
        /// <param name="didId"></param>
        public static implicit operator string(KeyDidMethod didId) => didId.Id;


        /// <summary>
        /// Explicit conversion from <see langword="string"/> to <see cref="KeyDidMethod"/> or derived DID methods.
        /// </summary>
        /// <param name="didId"></param>
        public static explicit operator KeyDidMethod(string didId) => new(didId);
    }
}
