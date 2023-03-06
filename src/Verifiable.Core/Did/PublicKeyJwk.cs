using System.Collections.Generic;
using System.Diagnostics;

namespace Verifiable.Core.Did
{
    //https://bitbucket.org/openid/ekyc-ida/src/master/schema/verified_claims_request.json
    
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
        public Dictionary<string, object> Header { get; set; } = new Dictionary<string, object>();

        public Dictionary<string, object>? Payload { get; set; }        
    }
}
