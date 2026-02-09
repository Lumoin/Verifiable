using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Model.Did.Methods;
using Verifiable.Cryptography;


namespace Verifiable.Core.Assessment
{
    /// <summary>
    /// Contains validation rules specific for <c>did:key</c> DID documents.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The <see cref="KeyDidValidationRules"/> class provides a comprehensive set of validation
    /// rules that verify the structure and content of <c>did:key</c> DID documents according to
    /// the specification.
    /// </para>
    /// <para>
    /// <strong>Available Rules:</strong>
    /// </para>
    /// <list type="bullet">
    /// <item><description>
    /// <see cref="ValidateIdEncodingAsync"/>: Validates that the DID uses a recognized multicodec
    /// encoding for the key type.
    /// </description></item>
    /// <item><description>
    /// <see cref="ValidateIdFormatAsync"/>: Validates that the DID ID matches the expected format
    /// pattern.
    /// </description></item>
    /// <item><description>
    /// <see cref="ValidateSingleVerificationMethodAsync"/>: Validates that exactly one verification
    /// method is present.
    /// </description></item>
    /// <item><description>
    /// <see cref="ValidateIdPrefixMatchAsync"/>: Validates that the verification method ID starts
    /// with the document ID.
    /// </description></item>
    /// <item><description>
    /// <see cref="ValidateFragmentIdentifierRepetitionAsync"/>: Validates that the fragment
    /// identifier repeats the key portion of the DID.
    /// </description></item>
    /// <item><description>
    /// <see cref="ValidateKeyFormatAsync"/>: Validates the key format (JWK or Multibase).
    /// </description></item>
    /// </list>
    /// <para>
    /// <strong>Cancellation Support:</strong>
    /// </para>
    /// <para>
    /// All validation methods accept a <see cref="CancellationToken"/> and will respect
    /// cancellation requests. For the simple synchronous validations in this class, the
    /// cancellation token is checked at the start of each method.
    /// </para>
    /// </remarks>
    public static class KeyDidValidationRules
    {
        /// <summary>
        /// A collection of all the assessment rules that are applied to <c>did:key</c> DID documents.
        /// </summary>
        /// <remarks>
        /// <para>
        /// This collection can be passed directly to a <see cref="ClaimIssuer{TInput}"/> to create
        /// a complete validation pipeline for <c>did:key</c> documents.
        /// </para>
        /// </remarks>
        public static List<ClaimDelegate<DidDocument>> AllRules { get; } =
        [
            new(ValidateIdEncodingAsync, [ClaimId.KeyDidIdEncoding]),
            new(ValidateKeyFormatAsync, [ClaimId.KeyDidKeyFormat]),
            new(ValidateIdFormatAsync, [ClaimId.KeyDidIdFormat]),
            new(ValidateSingleVerificationMethodAsync, [ClaimId.KeyDidSingleVerificationMethod]),
            new(ValidateIdPrefixMatchAsync, [ClaimId.KeyDidIdPrefixMatch]),
            new(ValidateFragmentIdentifierRepetitionAsync, [ClaimId.KeyDidFragmentIdentifierRepetition]),
        ];


        /// <summary>
        /// Validates the encoding of the ID in the provided <c>did:key</c> DID document.
        /// </summary>
        /// <param name="document">The <c>did:key</c> DID document to validate.</param>
        /// <param name="cancellationToken">Token to monitor for cancellation requests.</param>
        /// <returns>Claims indicating the validation outcome.</returns>
        /// <remarks>
        /// <para>
        /// This validation checks that the DID uses one of the recognized Base58-BTC encoded
        /// multicodec headers for supported key types:
        /// </para>
        /// <list type="bullet">
        /// <item><description>P-256 (secp256r1)</description></item>
        /// <item><description>P-384 (secp384r1)</description></item>
        /// <item><description>P-521 (secp521r1)</description></item>
        /// <item><description>secp256k1</description></item>
        /// <item><description>RSA 2048</description></item>
        /// <item><description>RSA 4096</description></item>
        /// <item><description>Ed25519</description></item>
        /// <item><description>X25519</description></item>
        /// </list>
        /// </remarks>
        public static ValueTask<List<Claim>> ValidateIdEncodingAsync(
            DidDocument document,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(document);
            cancellationToken.ThrowIfCancellationRequested();

            List<Claim> claims = new List<Claim>();
            if(document.Id != null)
            {
                var idFormat = document.Id.Id.AsSpan();
                var didNameAndVerb = idFormat[0..8];
                var keyDidType = idFormat[8..];
                if(didNameAndVerb.SequenceEqual(KeyDidMethod.Prefix))
                {
                    if(
                        keyDidType.StartsWith(Base58BtcEncodedMulticodecHeaders.P256PublicKey)
                        || keyDidType.StartsWith(Base58BtcEncodedMulticodecHeaders.P384PublicKey)
                        || keyDidType.StartsWith(Base58BtcEncodedMulticodecHeaders.P521PublicKey)
                        || keyDidType.StartsWith(Base58BtcEncodedMulticodecHeaders.Secp256k1PublicKey)
                        || keyDidType.StartsWith(Base58BtcEncodedMulticodecHeaders.RsaPublicKey2048)
                        || keyDidType.StartsWith(Base58BtcEncodedMulticodecHeaders.RsaPublicKey4096)
                        || keyDidType.StartsWith(Base58BtcEncodedMulticodecHeaders.Ed25519PublicKey)
                        || keyDidType.StartsWith(Base58BtcEncodedMulticodecHeaders.X25519PublicKey))
                    {
                        claims.Add(new Claim(ClaimId.KeyDidIdEncoding, ClaimOutcome.Success));
                    }
                    else
                    {
                        claims.Add(new Claim(ClaimId.KeyDidIdEncoding, ClaimOutcome.Failure));
                    }
                }
            }
            else
            {
                claims.Add(new Claim(ClaimId.KeyDidIdEncoding, ClaimOutcome.Failure));
            }

            return ValueTask.FromResult(claims);
        }


        /// <summary>
        /// Validates the format of the ID in the provided <c>did:key</c> DID document.
        /// </summary>
        /// <param name="document">The <c>did:key</c> DID document to validate.</param>
        /// <param name="cancellationToken">Token to monitor for cancellation requests.</param>
        /// <returns>Claims indicating the validation outcome.</returns>
        /// <remarks>
        /// <para>
        /// This validation checks that the DID ID matches the expected format pattern:
        /// <c>did:key:z[a-km-zA-HJ-NP-Z1-9]+</c>
        /// </para>
        /// <para>
        /// The pattern uses the Base58-BTC alphabet which excludes characters that are easily
        /// confused (0, O, I, l).
        /// </para>
        /// </remarks>
        public static ValueTask<List<Claim>> ValidateIdFormatAsync(
            DidDocument document,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(document);
            cancellationToken.ThrowIfCancellationRequested();

            List<Claim> claims = new List<Claim>(1);
            ClaimOutcome isFormatValid = ClaimOutcome.Failure;
            if(document.Id != null)
            {
                Regex regex = KeyDidRegex.DidKeyIdentifier();
                isFormatValid = regex.IsMatch(document.Id.Id) == true ? ClaimOutcome.Success : ClaimOutcome.Failure;
            }

            claims.Add(new(ClaimId.KeyDidIdFormat, isFormatValid));

            return ValueTask.FromResult(claims);
        }


        /// <summary>
        /// Validates the verification method in the provided <c>did:key</c> DID document,
        /// ensuring that it contains a single method.
        /// </summary>
        /// <param name="document">The <c>did:key</c> DID document to validate.</param>
        /// <param name="cancellationToken">Token to monitor for cancellation requests.</param>
        /// <returns>Claims indicating the validation outcome.</returns>
        /// <remarks>
        /// <para>
        /// According to the <c>did:key</c> specification, a <c>did:key</c> document should contain
        /// exactly one verification method that is derived from the key in the DID.
        /// </para>
        /// </remarks>
        public static ValueTask<List<Claim>> ValidateSingleVerificationMethodAsync(
            DidDocument document,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(document);
            cancellationToken.ThrowIfCancellationRequested();

            List<Claim> claims = new List<Claim>(1);
            bool isSuccess = document.VerificationMethod?.Length == 1;
            claims.Add(new Claim(ClaimId.KeyDidSingleVerificationMethod, isSuccess ? ClaimOutcome.Success : ClaimOutcome.Failure));

            return ValueTask.FromResult(claims);
        }


        /// <summary>
        /// Validates the prefix of the verification method identifier in the provided <c>did:key</c>
        /// DID document, ensuring that it matches the document's ID.
        /// </summary>
        /// <param name="document">The <c>did:key</c> DID document to validate.</param>
        /// <param name="cancellationToken">Token to monitor for cancellation requests.</param>
        /// <returns>A list of claims indicating the validation outcome.</returns>
        /// <remarks>
        /// <para>
        /// The verification method ID should start with the document's DID ID, followed by a
        /// fragment identifier. For example, if the document ID is <c>did:key:z6Mk...</c>, the
        /// verification method ID should be <c>did:key:z6Mk...#z6Mk...</c>.
        /// </para>
        /// </remarks>
        public static ValueTask<List<Claim>> ValidateIdPrefixMatchAsync(
            DidDocument document,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(document);
            cancellationToken.ThrowIfCancellationRequested();

            List<Claim> claims = new List<Claim>(1);
            bool isSuccess = document.VerificationMethod?[0].Id?.StartsWith(document?.Id?.Id ?? string.Empty,StringComparison.InvariantCulture) ?? false;
            claims.Add(new Claim(ClaimId.KeyDidIdPrefixMatch, isSuccess ? ClaimOutcome.Success : ClaimOutcome.Failure));

            return ValueTask.FromResult(claims);
        }


        /// <summary>
        /// Validates the fragment identifier of the verification method in the provided <c>did:key</c>
        /// DID document, ensuring that it repeats the key portion of the DID.
        /// </summary>
        /// <param name="document">The <c>did:key</c> DID document to validate.</param>
        /// <param name="cancellationToken">Token to monitor for cancellation requests.</param>
        /// <returns>A list of claims indicating the validation outcome.</returns>
        /// <remarks>
        /// <para>
        /// According to the <c>did:key</c> specification, the fragment identifier should repeat
        /// the multibase-encoded public key portion of the DID. For example, if the DID is
        /// <c>did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK</c>, the verification
        /// method ID should be <c>did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK</c>.
        /// </para>
        /// </remarks>
        public static ValueTask<List<Claim>> ValidateFragmentIdentifierRepetitionAsync(
            DidDocument document,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(document);
            cancellationToken.ThrowIfCancellationRequested();

            List<Claim> claims = [];
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

                    //Remove the "did:key:" prefix from docIdSpan.
                    ReadOnlySpan<char> docIdSpanWithoutPrefix = docIdSpan.Slice(KeyDidMethod.Prefix.Length);
                    isSuccess = fragmentSpan.SequenceEqual(docIdSpanWithoutPrefix);
                }
            }

            claims.Add(new Claim(ClaimId.KeyDidFragmentIdentifierRepetition, isSuccess ? ClaimOutcome.Success : ClaimOutcome.Failure));

            return ValueTask.FromResult(claims);
        }


        /// <summary>
        /// Validates the format of the key in the provided <c>did:key</c> DID document.
        /// </summary>
        /// <param name="document">The <c>did:key</c> DID document to validate.</param>
        /// <param name="cancellationToken">Token to monitor for cancellation requests.</param>
        /// <returns>Claims indicating the validation outcome.</returns>
        /// <remarks>
        /// <para>
        /// This validation checks the key format of the verification method. Supported formats are:
        /// </para>
        /// <list type="bullet">
        /// <item><description>
        /// <see cref="PublicKeyJwk"/>: JSON Web Key format. The key parameters are validated
        /// according to the key type (EC, RSA, OKP).
        /// </description></item>
        /// <item><description>
        /// <see cref="PublicKeyMultibase"/>: Multibase-encoded key format.
        /// </description></item>
        /// </list>
        /// </remarks>
        public static ValueTask<List<Claim>> ValidateKeyFormatAsync(
            DidDocument document,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(document);
            cancellationToken.ThrowIfCancellationRequested();

            List<Claim> resultClaims = [];
            if(document.VerificationMethod?[0]?.KeyFormat is PublicKeyJwk keyFormat)
            {
                var headers = keyFormat.Header;
                resultClaims = JwtKeyTypeHeaderValidationUtilities.ValidateHeader(headers);
            }
            else if(document.VerificationMethod?[0]?.KeyFormat is PublicKeyMultibase multiKeyFormat)
            {
                //TODO: This will be refactored to validate the multibase format.
                resultClaims.Add(new Claim(ClaimId.KeyDidKeyFormat, ClaimOutcome.Success));
            }

            return ValueTask.FromResult(resultClaims);
        }
    }


    /// <summary>
    /// Provides compiled regular expressions for validating <c>did:key</c> identifiers.
    /// </summary>
    public static partial class KeyDidRegex
    {
        /// <summary>
        /// Validates that the DID identifier conforms to the <c>did:key</c> method specification.
        /// </summary>
        /// <remarks>
        /// <para>
        /// The pattern matches: <c>did:key:z[Base58-BTC characters]+</c>
        /// </para>
        /// <para>
        /// The caret (<c>^</c>) and dollar (<c>$</c>) anchors ensure the entire string matches.
        /// </para>
        /// </remarks>
        /// <returns>A compiled regex for validating <c>did:key</c> identifiers.</returns>
        [GeneratedRegex("^did:key:z[a-km-zA-HJ-NP-Z1-9]+$")]
        public static partial Regex DidKeyIdentifier();


        /// <summary>
        /// Validates that the identifier with fragment conforms to the <c>did:key</c> method
        /// specification.
        /// </summary>
        /// <remarks>
        /// <para>
        /// The pattern matches: <c>did:key:z[Base58-BTC characters]+#[Base58-BTC characters]+</c>
        /// </para>
        /// </remarks>
        /// <returns>A compiled regex for validating <c>did:key</c> identifiers with fragments.</returns>
        [GeneratedRegex("^did:key:z[a-km-zA-HJ-NP-Z1-9]+\\#[a-km-zA-HJ-NP-Z1-9]+$")]
        public static partial Regex DidKeyIdentifierWithFragment();
    }
}