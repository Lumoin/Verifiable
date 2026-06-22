using System;

namespace Verifiable.Core.Did.Methods.Peer
{
    /// <summary>
    /// Represents a <c>did:peer</c> DID method implementation as defined by the
    /// <see href="https://identity.foundation/peer-did-method-spec/">Peer DID Method specification</see>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The <c>did:peer</c> method generates DID identifiers that encode their own DID document
    /// material in the identifier itself, requiring no external verifiable data registry. The
    /// numalgo character immediately after the prefix selects the generation algorithm:
    /// </para>
    /// <list type="bullet">
    /// <item><description><c>0</c>: a single inception key, functionally equivalent to <c>did:key</c>.</description></item>
    /// <item><description><c>1</c>: a genesis-document SHA-256 hash (not supported by this resolver).</description></item>
    /// <item><description><c>2</c>: multiple keys and services encoded as period-separated elements.</description></item>
    /// </list>
    /// <para>
    /// Peer DIDs are intended for pairwise, peer-to-peer relationships such as DIDComm messaging
    /// where the parties exchange DID documents directly rather than anchoring them to a public
    /// ledger.
    /// </para>
    /// </remarks>
    public record PeerDidMethod: GenericDidMethod
    {
        /// <summary>
        /// The prefix of the <c>did:peer</c> method, including the trailing <c>':'</c>.
        /// </summary>
        /// <remarks>This is <see cref="WellKnownDidMethodPrefixes.PeerDidMethodPrefix"/> with colon.</remarks>
        public static new string Prefix { get; } = $"{WellKnownDidMethodPrefixes.PeerDidMethodPrefix}:";


        /// <summary>
        /// Initializes a new instance of the <see cref="PeerDidMethod"/> class using the specified DID string.
        /// </summary>
        /// <param name="didString">The DID string to associate with this instance. The string must start with <see cref="Prefix"/>.</param>
        /// <exception cref="ArgumentNullException">Thrown if <paramref name="didString"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">Thrown if <paramref name="didString"/> does not start with <see cref="Prefix"/>.</exception>
        public PeerDidMethod(string didString): base(didString)
        {
            ArgumentNullException.ThrowIfNull(didString);
            if(!didString.StartsWith(Prefix, StringComparison.InvariantCulture))
            {
                throw new ArgumentException($"The DID string must start with '{Prefix}'.", nameof(didString));
            }
        }


        /// <summary>
        /// Implicit conversion from <see cref="PeerDidMethod"/> or derived DID methods to <see langword="string"/>.
        /// </summary>
        /// <param name="didId"></param>
        public static implicit operator string(PeerDidMethod didId)
        {
            ArgumentNullException.ThrowIfNull(didId);

            return didId.Id;
        }


        /// <summary>
        /// Explicit conversion from <see langword="string"/> to <see cref="PeerDidMethod"/> or derived DID methods.
        /// </summary>
        /// <param name="didId"></param>
        public static explicit operator PeerDidMethod(string didId)
        {
            ArgumentNullException.ThrowIfNull(didId);

            return new(didId);
        }


        /// <inheritdoc/>
        public override string ToString() => Id;
    }
}
