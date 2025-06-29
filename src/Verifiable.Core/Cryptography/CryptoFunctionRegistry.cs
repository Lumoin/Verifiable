using System;
using System.Buffers;
using System.Collections.Frozen;
using System.Threading.Tasks;

namespace Verifiable.Core.Cryptography
{

    //TODO: Write a much better explanation summary that this is registry for routing data between functions.

    public delegate ValueTask<IMemoryOwner<byte>> SigningDelegate(ReadOnlySpan<byte> privateKeyBytes, ReadOnlySpan<byte> dataToSign, MemoryPool<byte> signaturePool, FrozenDictionary<string, object>? context = null);
    public delegate ValueTask<bool> VerificationDelegate(ReadOnlySpan<byte> dataToVerify, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKeyMaterial, FrozenDictionary<string, object>? context = null);
    public delegate T PatternMatcher<T, TDiscriminator1, TDiscriminator2>(TDiscriminator1 algorithm, TDiscriminator2 purpose, string? qualifier = null) where T: Delegate;


    public static class CryptoFunctionRegistry<TDiscriminator1, TDiscriminator2>
    {
        private static PatternMatcher<VerificationDelegate, TDiscriminator1, TDiscriminator2>? VerificationMatcher { get; set; }

        private static PatternMatcher<SigningDelegate, TDiscriminator1, TDiscriminator2>? SigningMatcher { get; set; }


        /// <summary>
        /// Initializes the CryptoFunctionRegistry with signing and verification pattern matchers.
        /// </summary>
        public static void Initialize(PatternMatcher<SigningDelegate, TDiscriminator1, TDiscriminator2> signingMatcher, PatternMatcher<VerificationDelegate, TDiscriminator1, TDiscriminator2> verificationMatcher)
        {
            SigningMatcher = signingMatcher;
            VerificationMatcher = verificationMatcher;
        }


        /// <summary>
        /// Initializes the CryptoFunctionRegistry with signing and verification pattern matchers that
        /// can handle key material transformations.
        /// </summary>
        /// <remarks>
        /// This is a specialized version of Initialize that's used for delegates that need to transform
        /// key material formats (e.g. compressed to raw) before performing cryptographic operations.
        /// </remarks>
        public static void InitializeWithTransformers(PatternMatcher<SigningDelegate, TDiscriminator1, TDiscriminator2> signingMatcher, PatternMatcher<VerificationDelegate, TDiscriminator1, TDiscriminator2> verificationMatcher)
        {
            // This uses the same underlying mechanism as Initialize, but the provided matchers
            // should return delegates that have transformation logic built into them
            SigningMatcher = signingMatcher;
            VerificationMatcher = verificationMatcher;
        }


        public static SigningDelegate ResolveSigning(TDiscriminator1 algorithm, TDiscriminator2 purpose, string? qualifier = null)
        {
            if(SigningMatcher == null)
            {
                throw new InvalidOperationException("Signing matcher has not been initialized.");
            }

            return SigningMatcher(algorithm, purpose, qualifier);
        }


        public static VerificationDelegate ResolveVerification(TDiscriminator1 algorithm, TDiscriminator2 purpose, string? qualifier = null)
        {
            if(VerificationMatcher == null)
            {
                throw new InvalidOperationException("The library has not been initialized with a pattern matcher.");
            }

            return VerificationMatcher(algorithm, purpose, qualifier);
        }
    }
}
