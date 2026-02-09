using System.Buffers;
using System.Runtime.InteropServices;

namespace Verifiable.Tests
{
    internal static partial class Sodium
    {
        public unsafe static IMemoryOwner<byte> ConvertEd25519PublicKeyToCurve25519PublicKey(ReadOnlySpan<byte> ed25519PublicKey, MemoryPool<byte> sensitiveMemoryPool)
        {
            var curve25519PrimaryKey = sensitiveMemoryPool.Rent(32);
            fixed(byte* fixedEd25519PublicKey = &MemoryMarshal.GetReference(ed25519PublicKey))
            {
                fixed(byte* fixedcurve25519PrimaryKey = &MemoryMarshal.GetReference(curve25519PrimaryKey.Memory.Span))
                {
                    //TODO: If ret != 0, then error.
                    var ret = crypto_sign_ed25519_pk_to_curve25519(fixedcurve25519PrimaryKey, fixedEd25519PublicKey);

                    return curve25519PrimaryKey;
                }
            }
        }


        public static byte[] ConvertEd25519PrivateKeyToCurve25519PrivateKey(byte[] ed25519PrivateKey)
        {
            var curve25519_sk = new byte[32];

            //TODO: If ret != 0, then error.
            var ret = crypto_sign_ed25519_sk_to_curve25519(curve25519_sk, ed25519PrivateKey);
            
            return curve25519_sk;
        }


        [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
        [DllImport("libsodium", CallingConvention = CallingConvention.Cdecl)]
        private unsafe static extern int crypto_sign_ed25519_pk_to_curve25519(byte* curve25519Pk, in byte* ed25519Pk);


        [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
        [LibraryImport("libsodium")]
        private static partial int crypto_sign_ed25519_sk_to_curve25519(byte[] x25519_sk, in byte[] ed25519_skpk);
    }
}
