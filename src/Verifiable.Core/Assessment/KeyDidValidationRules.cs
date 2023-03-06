using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Verifiable.Core;
using Verifiable.Core.Did;


namespace Verifiable.Assessment
{
    /// <summary>
    /// Contains validation rules specific for <c>did:key</c> DID documents.
    /// </summary>
    public static class KeyDidValidationRules
    {
        /// <summary>
        /// A collection of all the assessment rules that are applied to <c>did:key</c> DID documents.
        /// </summary>        
        public static IList<ClaimDelegate<DidDocument>> AllRules { get; } = new List<ClaimDelegate<DidDocument>>
        {
            new(ValidateIdEncodingAsync, new List<ClaimId>{ ClaimId.KeyDidIdEncoding }),
            new(ValidateKeyFormatAsync, new List<ClaimId>{ ClaimId.KeyDidKeyFormat }),
            new(ValidateIdFormatAsync, new List<ClaimId>{ ClaimId.KeyDidIdFormat }),
            new(ValidateSingleVerificationMethodAsync, new List<ClaimId>{ ClaimId.KeyDidSingleVerificationMethod }),
            new(ValidateIdPrefixMatchAsync, new List<ClaimId>{ ClaimId.KeyDidIdPrefixMatch }),
            new(ValidateFragmentIdentifierRepetitionAsync, new List<ClaimId>{ ClaimId.KeyDidFragmentIdentifierRepetition }),            
        };


        /// <summary>
        /// Validates the encoding of the ID in the provided <c>did:key</c> DID document.
        /// </summary>
        /// <param name="document">The <c>did:key</c> DID document to validate.</param>
        /// <returns>Claims indicating the validation outcome.</returns>
        public static ValueTask<IList<Claim>> ValidateIdEncodingAsync(DidDocument document)
        {
            IList<Claim> claims = new List<Claim>();
            if(document.Id != null)
            {
                var idFormat = document.Id.Id.AsSpan();
                var didNameAndVerb = idFormat[0..8];
                var keyDidType = idFormat[8..];
                if(didNameAndVerb.SequenceEqual(KeyDidId.Prefix))
                {
                    if(
                        keyDidType.StartsWith(Base58BtcEncodedMulticodecHeaders.P256PublicKey)
                        || keyDidType.StartsWith(Base58BtcEncodedMulticodecHeaders.P384PublicKey)
                        || keyDidType.StartsWith(Base58BtcEncodedMulticodecHeaders.P521PublicKey)
                        || keyDidType.StartsWith(Base58BtcEncodedMulticodecHeaders.Secp256k1PublicKey)
                        || keyDidType.StartsWith(Base58BtcEncodedMulticodecHeaders.RsaPublicKey2048)
                        || keyDidType.StartsWith(Base58BtcEncodedMulticodecHeaders.RsaPublicKey4096)
                        || keyDidType.StartsWith(Base58BtcEncodedMulticodecHeaders.Ed25519PublicKey)
                        || keyDidType.StartsWith(Base58BtcEncodedMulticodecHeaders.X25519PublicKey)
                        )
                    {
                        claims.Add(new Claim(ClaimId.KeyDidIdEncoding, ClaimOutcome.Success, ClaimContext.None));                        
                    }
                    else
                    {
                        claims.Add(new Claim(ClaimId.KeyDidIdEncoding, ClaimOutcome.Failure, ClaimContext.None));                        
                    }                    
                }
            }
            else
            {
                claims.Add(new Claim(ClaimId.KeyDidIdEncoding, ClaimOutcome.Failure, ClaimContext.None));
            }
            
            return ValueTask.FromResult(claims);
        }


        /// <summary>
        /// Validates the format of the ID in the provided <c>did:key</c> DID document.
        /// </summary>
        /// <param name="document">The <c>did:key</c> DID document to validate.</param>
        /// <returns>Claims indicating the validation outcome.</returns>
        public static ValueTask<IList<Claim>> ValidateIdFormatAsync(DidDocument document)
        {
            IList<Claim> claims = new List<Claim>(1);
            ClaimOutcome isFormatValid = ClaimOutcome.Failure;
            if(document.Id != null)
            {
                Regex regex = KeyDidRegex.DidKeyIdentifier();
                isFormatValid = regex.IsMatch(document.Id.Id) == true ? ClaimOutcome.Success : ClaimOutcome.Failure;
            }

            claims.Add(new(ClaimId.KeyDidIdFormat, isFormatValid, ClaimContext.None));

            return ValueTask.FromResult(claims);
        }


        /// <summary>
        /// Validates the verification method in the provided <c>did:key</c> DID document, ensuring that it contains a single method that matches the document's ID.
        /// </summary>
        /// <param name="document">The <c>did:key</c> DID document to validate.</param>
        /// <returns>Claims indicating the validation outcome.</returns>
        public static ValueTask<IList<Claim>> ValidateSingleVerificationMethodAsync(DidDocument document)
        {
            IList<Claim> claims = new List<Claim>(1);
            bool isSuccess = document.VerificationMethod?.Length == 1;
            claims.Add(new Claim(ClaimId.KeyDidSingleVerificationMethod, isSuccess ? ClaimOutcome.Success : ClaimOutcome.Failure, ClaimContext.None));

            return ValueTask.FromResult(claims);
        }


        /// <summary>
        /// Validates the prefix of the verification method identifier in the provided <c>did:key</c> DID document, ensuring that it matches the document's ID.
        /// </summary>
        /// <param name="document">The <c>did:key</c> DID document to validate.</param>
        /// <returns>A list of claims indicating the validation outcome.</returns>
        public static ValueTask<IList<Claim>> ValidateIdPrefixMatchAsync(DidDocument document)
        {
            IList<Claim> claims = new List<Claim>(1);
            bool isSuccess = document.VerificationMethod?[0].Id?.StartsWith(document?.Id?.Id ?? string.Empty) ?? false;
            claims.Add(new Claim(ClaimId.KeyDidIdPrefixMatch, isSuccess ? ClaimOutcome.Success : ClaimOutcome.Failure, ClaimContext.None));

            return ValueTask.FromResult(claims);
        }


        /// <summary>
        /// Validates the fragment identifier of the verification method in the provided <c>did:key</c> DID document, ensuring that it repeats the document's ID.
        /// </summary>
        /// <param name="document">The <c>did:key</c> DID document to validate.</param>
        /// <returns>A list of claims indicating the validation outcome.</returns>
        public static ValueTask<IList<Claim>> ValidateFragmentIdentifierRepetitionAsync(DidDocument document)
        {
            IList<Claim> claims = new List<Claim>(1);
            string? verificationMethodId = document.VerificationMethod?[0].Id;
            string? documentId = document.Id?.Id;

            bool isSuccess = false;
            if(verificationMethodId != null && documentId != null)
            {
                ReadOnlySpan<char> vmIdSpan = verificationMethodId.AsSpan();
                ReadOnlySpan<char> docIdSpan = documentId.AsSpan();

                int hashIndex = vmIdSpan.LastIndexOf('#');
                if(hashIndex != -1)
                {
                    ReadOnlySpan<char> fragmentSpan = vmIdSpan.Slice(hashIndex + 1);
                    
                    //Remove the "did:key:" prefix from docIdSpan...
                    ReadOnlySpan<char> docIdSpanWithoutPrefix = docIdSpan.Slice("did:key:".Length);
                    isSuccess = fragmentSpan.SequenceEqual(docIdSpanWithoutPrefix);
                }
            }

            claims.Add(new Claim(ClaimId.KeyDidFragmentIdentifierRepetition, isSuccess ? ClaimOutcome.Success : ClaimOutcome.Failure, ClaimContext.None));

            return ValueTask.FromResult(claims);
        }



        /// <summary>
        /// Validates the format of the key in the provided <c>did:key</c> DID document.
        /// </summary>
        /// <param name="document">The <c>did:key</c> DID document to validate.</param>
        /// <returns>Claims indicating the validation outcome.</returns>
        public static ValueTask<IList<Claim>> ValidateKeyFormatAsync(DidDocument document)
        {
            IList<Claim> resultClaims = new List<Claim>();
            if(document.VerificationMethod?[0]?.KeyFormat is PublicKeyJwk keyFormat)
            {
                var headers = keyFormat.Header;
                resultClaims = JwtKeyTypeHeaderValidationUtilities.ValidateHeader(headers);
            }
            else if(document.VerificationMethod?[0]?.KeyFormat is PublicKeyMultibase multiKeyFormat)
            {
                //TODO: This here will be refactored.
                resultClaims.Add(new Claim(ClaimId.KeyDidKeyFormat, ClaimOutcome.Success, ClaimContext.None));
            }

            return ValueTask.FromResult(resultClaims);
        }
    }


    public static partial class KeyDidRegex
    {
        /// <summary>
        /// Validates that the verification method in the DID document conforms to the did:key method specification.
        /// </summary>
        /// <remarks>
        /// The caret, <c>^</c>, is not in the specification but added here for pattern matching purposes.
        /// <para>
        [GeneratedRegex("^did:key:z[a-km-zA-HJ-NP-Z1-9]+$")]
        public static partial Regex DidKeyIdentifier();


        /// <summary>
        /// Validates that the identifier in the DID document conforms to the did:key method specification.
        /// </summary>
        /// <remarks>
        /// The caret, <c>^</c>, is not in the specification but added here for pattern matching purposes.
        /// <para>        
        [GeneratedRegex("^did:key:z[a-km-zA-HJ-NP-Z1-9]+\\#[a-km-zA-HJ-NP-Z1-9]+$")]
        public static partial Regex DidKeyIdentifierWithFragment();
    }
}
