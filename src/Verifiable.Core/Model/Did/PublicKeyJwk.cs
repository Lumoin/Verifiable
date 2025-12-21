using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;

namespace Verifiable.Core.Model.Did
{
    /// <summary>
    /// This JSON Web Key (JWK) type is used for following purposes
    /// <list type="table">
    /// <listheader>
    ///    <term>Method</term>
    ///    <description>Link for further information</description>
    /// </listheader>
    /// <item>
    ///    <term>General DID</term>
    ///    <description><see href="https://www.w3.org/TR/did-core/#dfn-publickeyjwk">DID</see></description>
    /// </item>
    /// <item>
    ///    <term>Specific DID</term>
    ///    <description><see href="https://w3c-ccg.github.io/did-method-key/">did:key method</see></description>
    /// </item>
    /// <item>
    ///    <term>Specific signature suites</term>
    ///    <description><see href="https://w3c.github.io/vc-jws-2020/">JSON Web Signature 2020</see></description>
    /// </item>
    /// <item>
    ///    <term>JWK (RFC 7517) specification</term>
    ///    <description><see href="https://tools.ietf.org/html/rfc7517">JWK (RFC 7517) specification</see></description>
    /// </item>
    /// </list>
    /// </summary>
    /// <remarks>Note that for DID specifications private key information, such as 'd' field,
    /// MUST not be present. The DID usage of JWK is compatible with
    /// <see href="https://tools.ietf.org/html/rfc7517">JWK (RFC 7517) specification</see>.</remarks>
    [DebuggerDisplay("PublicKeyJwk()")]
    public class PublicKeyJwk: KeyFormat
    {
        public Dictionary<string, object> Header { get; set; } = [];

        public Dictionary<string, object>? Payload { get; set; }


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public override bool Equals(KeyFormat? other)
        {
            if(other is not PublicKeyJwk jwk)
            {
                return false;
            }

            if(ReferenceEquals(this, jwk))
            {
                return true;
            }

            return DictionariesEqual(Header, jwk.Header)
                && DictionariesEqual(Payload, jwk.Payload);
        }

        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public override int GetHashCode()
        {
            var hash = new HashCode();

            //Add Header dictionary contents to hash.
            if(Header != null)
            {
                foreach(var kvp in Header.OrderBy(x => x.Key))
                {
                    hash.Add(kvp.Key);
                    hash.Add(kvp.Value);
                }
            }

            //Add Payload dictionary contents to hash.
            if(Payload != null)
            {
                foreach(var kvp in Payload.OrderBy(x => x.Key))
                {
                    hash.Add(kvp.Key);
                    hash.Add(kvp.Value);
                }
            }

            return hash.ToHashCode();
        }

        /// <summary>
        /// Compares two dictionaries for value equality.
        /// </summary>
        /// <param name="dict1">The first dictionary to compare.</param>
        /// <param name="dict2">The second dictionary to compare.</param>
        /// <returns>True if the dictionaries have the same key-value pairs; otherwise, false.</returns>
        private static bool DictionariesEqual(Dictionary<string, object>? dict1, Dictionary<string, object>? dict2)
        {
            if(dict1 is null && dict2 is null)
            {
                return true;
            }

            if(dict1 is null || dict2 is null)
            {
                return false;
            }

            if(dict1.Count != dict2.Count)
            {
                return false;
            }

            foreach(var kvp in dict1)
            {
                if(!dict2.TryGetValue(kvp.Key, out var value) || !Equals(kvp.Value, value))
                {
                    return false;
                }
            }

            return true;
        }
    }
}
