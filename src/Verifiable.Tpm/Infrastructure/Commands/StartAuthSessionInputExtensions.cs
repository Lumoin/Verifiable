using System;
using System.Security.Cryptography;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Handles;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Factory methods for creating <see cref="StartAuthSessionInput"/> configurations.
/// </summary>
/// <remarks>
/// <para>
/// This extension class provides convenient factory methods for common session configurations.
/// Session types include:
/// </para>
/// <list type="bullet">
///   <item><description><strong>Unbound, unsalted:</strong> Simplest session with no cryptographic binding.</description></item>
///   <item><description><strong>Bound:</strong> Session cryptographically bound to an entity's authValue.</description></item>
///   <item><description><strong>Salted:</strong> Session uses encrypted salt for additional entropy.</description></item>
///   <item><description><strong>Bound and salted:</strong> Maximum security with both binding and salt.</description></item>
/// </list>
/// <para>
/// See TPM 2.0 Part 1, Section 19.6 for session binding and salting details.
/// </para>
/// </remarks>
public static class StartAuthSessionInputExtensions
{
    extension(StartAuthSessionInput)
    {
        /// <summary>
        /// Creates an unbound, unsalted HMAC session.
        /// </summary>
        /// <param name="authHash">The hash algorithm for the session.</param>
        /// <returns>A StartAuthSessionInput configured for an unbound, unsalted HMAC session.</returns>
        /// <remarks>
        /// <para>
        /// This is the simplest HMAC session configuration. The session provides integrity
        /// protection via cpHash/rpHash verification but has no cryptographic binding to
        /// any entity and no additional entropy from a salt.
        /// </para>
        /// <para>
        /// Use cases include:
        /// </para>
        /// <list type="bullet">
        ///   <item><description>Auditing command execution.</description></item>
        ///   <item><description>Response integrity verification for commands that don't require authorization.</description></item>
        ///   <item><description>Testing and development scenarios.</description></item>
        /// </list>
        /// </remarks>
        public static StartAuthSessionInput CreateUnboundUnsaltedHmacSession(TpmAlgIdConstants authHash)
        {
            byte[] nonce = new byte[GetDigestSize(authHash)];
            RandomNumberGenerator.Fill(nonce);

            return new StartAuthSessionInput
            {
                TpmKey = (uint)TpmRh.TPM_RH_NULL,
                Bind = (uint)TpmRh.TPM_RH_NULL,
                NonceCaller = nonce,
                EncryptedSalt = ReadOnlyMemory<byte>.Empty,
                SessionType = TpmSeConstants.TPM_SE_HMAC,
                AuthHash = authHash
            };
        }

        /// <summary>
        /// Creates an unbound, unsalted policy session.
        /// </summary>
        /// <param name="authHash">The hash algorithm for the session.</param>
        /// <returns>A StartAuthSessionInput configured for an unbound, unsalted policy session.</returns>
        /// <remarks>
        /// <para>
        /// Policy sessions are used for policy-based authorization. Commands update the
        /// session's policyDigest, and the final digest must match the object's authPolicy.
        /// </para>
        /// </remarks>
        public static StartAuthSessionInput CreateUnboundUnsaltedPolicySession(TpmAlgIdConstants authHash)
        {
            byte[] nonce = new byte[GetDigestSize(authHash)];
            RandomNumberGenerator.Fill(nonce);

            return new StartAuthSessionInput
            {
                TpmKey = (uint)TpmRh.TPM_RH_NULL,
                Bind = (uint)TpmRh.TPM_RH_NULL,
                NonceCaller = nonce,
                EncryptedSalt = ReadOnlyMemory<byte>.Empty,
                SessionType = TpmSeConstants.TPM_SE_POLICY,
                AuthHash = authHash
            };
        }

        /// <summary>
        /// Creates a trial policy session.
        /// </summary>
        /// <param name="authHash">The hash algorithm for the session.</param>
        /// <returns>A StartAuthSessionInput configured for a trial policy session.</returns>
        /// <remarks>
        /// <para>
        /// Trial sessions are used to compute policy digests without actually authorizing
        /// any commands. The resulting policyDigest can then be used when creating objects
        /// with policy-based authorization.
        /// </para>
        /// </remarks>
        public static StartAuthSessionInput CreateTrialPolicySession(TpmAlgIdConstants authHash)
        {
            byte[] nonce = new byte[GetDigestSize(authHash)];
            RandomNumberGenerator.Fill(nonce);

            return new StartAuthSessionInput
            {
                TpmKey = (uint)TpmRh.TPM_RH_NULL,
                Bind = (uint)TpmRh.TPM_RH_NULL,
                NonceCaller = nonce,
                EncryptedSalt = ReadOnlyMemory<byte>.Empty,
                SessionType = TpmSeConstants.TPM_SE_TRIAL,
                AuthHash = authHash
            };
        }

        private static int GetDigestSize(TpmAlgIdConstants authHash) => authHash switch
        {
            TpmAlgIdConstants.TPM_ALG_SHA1 => 20,
            TpmAlgIdConstants.TPM_ALG_SHA256 => 32,
            TpmAlgIdConstants.TPM_ALG_SHA384 => 48,
            TpmAlgIdConstants.TPM_ALG_SHA512 => 64,
            TpmAlgIdConstants.TPM_ALG_SM3_256 => 32,
            _ => 32 //Default to SHA-256 size.
        };
    }
}