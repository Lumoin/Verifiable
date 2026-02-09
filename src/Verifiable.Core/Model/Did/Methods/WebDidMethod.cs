using System;

namespace Verifiable.Core.Model.Did.Methods
{
    public record WebDidMethod: GenericDidMethod
    {
        /// <summary>
        /// The prefix of <c>did:web</c> method, including suffix <c>':'</c>.
        /// </summary>
        /// <remarks>This is <see cref="WellKnownDidMethodPrefixes.WebDidMethodPrefix"/> with colon.</remarks>
        public static new string Prefix { get; } = $"{WellKnownDidMethodPrefixes.WebDidMethodPrefix}:";


        public WebDidMethod(string didString): base(didString)
        {
        ArgumentNullException.ThrowIfNull(didString);
        if(!didString.StartsWith(WellKnownDidMethodPrefixes.WebDidMethodPrefix, StringComparison.InvariantCulture))
            {
                throw new ArgumentException($"The DID string must start with '{Prefix}'.", nameof(didString));
            }
        }


        /// <summary>
        /// Implicit conversion from <see cref="WebDidMethod"/> or derived DID methods to <see langword="string"/>.
        /// </summary>
        /// <param name="didId"></param>
    public static implicit operator string(WebDidMethod didId)
    {
        ArgumentNullException.ThrowIfNull(didId);

        return didId.Id;
    }


        /// <summary>
        /// Explicit conversion from <see langword="string"/> to <see cref="WebDidMethod"/> or derived DID methods.
        /// </summary>
        /// <param name="didId"></param>
    public static explicit operator WebDidMethod(string didId)
    {
        ArgumentNullException.ThrowIfNull(didId);

        return new(didId);
    }


        /// <inheritdoc/>
        public override string ToString() => Id;
    }
}
