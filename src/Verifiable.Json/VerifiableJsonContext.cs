using System.Collections.Generic;
using System.Text.Json.Serialization;
using Verifiable.Core.Model.Common;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.Model.DataIntegrity;
using Verifiable.Core.Model.Dcql;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Resolvers;
using Verifiable.Core.StatusList;
using Verifiable.DidComm;
using Verifiable.JCose;
using Verifiable.OAuth.Oid4Vp;

namespace Verifiable.Json;

/// <summary>
/// Source-generated serialization metadata for roundtrip tests. Lists root
/// document types and types that custom converters resolve via
/// <c>options.GetTypeInfo</c>. All converters read primitive arrays
/// (string, int, bool) manually, so no <c>List&lt;string&gt;</c> entry is needed.
/// </summary>
//DID and VC root document types.
[JsonSerializable(typeof(DidDocument))]
[JsonSerializable(typeof(DidDocumentMetadata))]
//DID Resolution / DID URL Dereferencing result envelopes (W3C DID Resolution HTTP(S) binding) and
//their metadata / error sub-objects. Service is registered so the dereferencing-result converter can
//serialize a fragment-dereferenced service resource via GetTypeInfo.
[JsonSerializable(typeof(DidResolutionResult))]
[JsonSerializable(typeof(DidDereferencingResult))]
[JsonSerializable(typeof(DidResolutionMetadata))]
[JsonSerializable(typeof(DidDereferencingMetadata))]
[JsonSerializable(typeof(DidProblemDetails))]
[JsonSerializable(typeof(Service))]
[JsonSerializable(typeof(VerifiableCredential))]
[JsonSerializable(typeof(DataIntegritySecuredCredential))]
[JsonSerializable(typeof(VerifiablePresentation))]
[JsonSerializable(typeof(DataIntegritySecuredPresentation))]
[JsonSerializable(typeof(EnvelopedVerifiablePresentation))]
//DCQL root type. Element types have custom converters and are resolved
//per-element via GetTypeInfo.
[JsonSerializable(typeof(DcqlQuery))]
[JsonSerializable(typeof(CredentialQuery))]
[JsonSerializable(typeof(CredentialSetQuery))]
[JsonSerializable(typeof(ClaimsQuery))]
[JsonSerializable(typeof(TrustedAuthoritiesQuery))]
[JsonSerializable(typeof(CredentialQueryMeta))]
//VerificationMethod resolved via GetTypeInfo in VerificationMethodConverter
//and for embedded verification in VerificationMethodReferenceConverter and
//DataIntegrityProofConverter. VerificationMethodReference subclasses are
//fully handled by manual converters and do not go through source-gen.
[JsonSerializable(typeof(VerificationMethod))]
//JOSE header and JWK serialization.
[JsonSerializable(typeof(JwtHeader))]
[JsonSerializable(typeof(JwtPayload))]
[JsonSerializable(typeof(JwksDocument))]
[JsonSerializable(typeof(JsonWebKey))]
[JsonSerializable(typeof(Dictionary<string, string>))]
[JsonSerializable(typeof(Dictionary<string, object?>))]
[JsonSerializable(typeof(Dictionary<string, object>))]
//Primitive types that appear as values in Dictionary<string, object> payloads.
//Required for polymorphic serialization of JWT claims (e.g., iat as long).
[JsonSerializable(typeof(long))]
[JsonSerializable(typeof(int))]
[JsonSerializable(typeof(bool))]
[JsonSerializable(typeof(double))]
//Primitive arrays used in manual converters (e.g. StatusListAggregationJsonConverter).
[JsonSerializable(typeof(string[]))]
//JSON-LD context serialization for proof options documents.
[JsonSerializable(typeof(Context))]
//Status list types resolved via GetTypeInfo in status list converters.
[JsonSerializable(typeof(Core.StatusList.StatusList))]
[JsonSerializable(typeof(StatusListReference))]
[JsonSerializable(typeof(StatusClaim))]
[JsonSerializable(typeof(StatusListAggregation))]
//OID4VP protocol types.
[JsonSerializable(typeof(VpToken))]
[JsonSerializable(typeof(VpFormatsSupported))]
[JsonSerializable(typeof(VerifierClientMetadata))]
[JsonSerializable(typeof(AuthorizationRequestObject))]
[JsonSerializable(typeof(WalletMetadata))]
[JsonSerializable(typeof(DirectPostBody))]
[JsonSerializable(typeof(DirectPostJwtBody))]
[JsonSerializable(typeof(DirectPostResult))]
//DIDComm plaintext message types. The root DidCommMessage is resolved via GetTypeInfo by the
//pack/unpack delegates; the DidCommMessageConverter handles all three manually, with Attachment
//and AttachmentData read/written inline rather than through source-gen.
[JsonSerializable(typeof(DidCommMessage))]
[JsonSerializable(typeof(Attachment))]
[JsonSerializable(typeof(AttachmentData))]
public partial class VerifiableJsonContext: JsonSerializerContext
{
}
