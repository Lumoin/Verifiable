using Verifiable.Core.Did;

namespace Verifiable.Core.Builders
{
    /// <summary>
    /// ...
    /// </summary>
    public class EbsiDidBuilder: Builder<DidDocument, object, EbsiDidBuilder>
    {
        //According to https://ec.europa.eu/digital-building-blocks/wikis/display/EBSIDOC/EBSI+DID+Method
        //the following fields are required Legal Entities EBSI DID Document is compliant with the W3C DID Document specification but defines the following fields as required.
        //verificationMethod verificationMethod[].publicKeyJwk assertionMethod
    }
}
