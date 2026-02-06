using System;
using System.Collections.Generic;
using Verifiable.JCose;
using Verifiable.Jose;

namespace Verifiable.Core.Assessment
{
    public static class DefaultJwtValidationClaims
    {
        /// <summary>
        /// Validates that the JWT algorithm is not 'none'.
        /// </summary>
        /// <remarks>
        /// This validation rule is based on the security best practices outlined in JWT RFC 7519.
        /// The 'none' algorithm is a security vulnerability when misused since it indicates that no digital signature
        /// or Message Authentication Code (MAC) is required. Without a signature or MAC, the integrity of the token
        /// cannot be verified. This rule ensures that the algorithm specified in the JWT header is not 'none'.
        /// </remarks>
        /// <param name="jwtHeaders">JWT headers as a dictionary of key-value pairs.</param>
        /// <returns>A ValidationResult object indicating the result of the validation check.</returns>
        public static IList<Claim> ValidateAlgIsNotNone(Dictionary<string, object> jwtHeaders)
        {
            ArgumentNullException.ThrowIfNull(jwtHeaders);
            var checks = new List<Claim>();
            if(!jwtHeaders.TryGetValue("alg", out object? value))
            {
                checks.Add(new Claim(ClaimId.AlgExists, ClaimOutcome.Failure));
                return checks;
            }

            string algValue = value as string ?? string.Empty;
            if(WellKnownJwaValues.IsNone(algValue))
            {
                checks.Add(new Claim(ClaimId.AlgIsNone, ClaimOutcome.Failure));
                return checks;
            }

            checks.Add(new Claim(ClaimId.AlgIsValid, ClaimOutcome.Success));
            return checks;
        }
    }


    public static class JwtKeyTypeHeaderValidationUtilities
    {
        private static readonly List<(Func<string, bool> IsAlg, Func<string, bool> IsCrv)> AlgCrvPairs = new()
        {
            (WellKnownJwaValues.IsEs256, WellKnownCurveValues.IsP256),
            (WellKnownJwaValues.IsEs384, WellKnownCurveValues.IsP384),
            (WellKnownJwaValues.IsEs512, WellKnownCurveValues.IsP521),
            (WellKnownJwaValues.IsEs256k1, WellKnownCurveValues.IsSecp256k1)
        };


        /// <summary>
        /// Validates the JWT header key parameters.
        /// </summary>
        /// <param name="jwtHeaders">JWT headers as a dictionary of key-value pairs.</param>
        /// <returns>A ClaimCheckPoint object indicating the result of the validation check.</returns>
        public static List<Claim> ValidateHeader(Dictionary<string, object> jwtHeaders)
        {
            ArgumentNullException.ThrowIfNull(jwtHeaders);
            List<Claim> claims = [];
            if(!jwtHeaders.TryGetValue(JwkProperties.Kty, out object? ktyValue) || ktyValue is not string kty || string.IsNullOrEmpty(kty))
            {
                claims.Add(new Claim(ClaimId.KtyMissingOrEmpty, ClaimOutcome.Failure));
                return claims;
            }

            switch(kty)
            {
                case string k when WellKnownKeyTypeValues.IsEc(k):
                    claims.AddRange(ValidateEc(jwtHeaders, AlgCrvPairs, true, true));
                    claims.Add(new Claim(ClaimId.EcKeyType, ClaimOutcome.Success));
                    break;
                case string k when WellKnownKeyTypeValues.IsRsa(k):
                    claims.AddRange(ValidateRsa(jwtHeaders));
                    claims.Add(new Claim(ClaimId.RsaKeyType, ClaimOutcome.Success));
                    break;
                case string k when WellKnownKeyTypeValues.IsOct(k):
                    //TODO:Additional validation logic for 'oct' can go here...
                    claims.Add(new Claim(ClaimId.OctKeyType, ClaimOutcome.Success)); //TODO: Placeholder...
                    break;
                case string k when WellKnownKeyTypeValues.IsOkp(k):
                    List<(Func<string, bool> IsAlg, Func<string, bool> IsCrv)> algCrvPairsForOkp = new()
                    {
                        (WellKnownJwaValues.IsEdDsa, WellKnownCurveValues.IsEd25519),
                        (str => true, WellKnownCurveValues.IsX25519)
                    };
                    claims.AddRange(ValidateOkp(jwtHeaders, algCrvPairsForOkp));
                    claims.Add(new Claim(ClaimId.OkpKeyType, ClaimOutcome.Success));
                    break;
                default:
                    claims.Add(new Claim(ClaimId.UnsupportedKeyType, ClaimOutcome.Failure));
                    break;
            }

            return claims;
        }


        public static List<Claim> ValidateEc(
            Dictionary<string, object> jwtHeaders,
            List<(Func<string, bool> IsAlg, Func<string, bool> IsCrv)> algCrvPairs,
            bool isEcAlgRequired = false,
            bool isYCoordinateMandatory = true)
        {
            ArgumentNullException.ThrowIfNull(jwtHeaders);
            ArgumentNullException.ThrowIfNull(algCrvPairs);
            List<Claim> claims = new();

            // Check for mandatory 'crv' field (Curve)
            if(jwtHeaders.TryGetValue(JwkProperties.Crv, out object? crvValue) && crvValue is string crv && !string.IsNullOrEmpty(crv))
            {
                claims.Add(new Claim(ClaimId.EcMissingCurve, ClaimOutcome.Success));
            }
            else
            {
                claims.Add(new Claim(ClaimId.EcMissingCurve, ClaimOutcome.Failure));
            }

            // Check for mandatory 'x' field (X Coordinate)
            if(jwtHeaders.TryGetValue(JwkProperties.X, out object? xValue) && xValue is string x && !string.IsNullOrEmpty(x))
            {
                claims.Add(new Claim(ClaimId.EcMissingXCoordinate, ClaimOutcome.Success));
            }
            else
            {
                claims.Add(new Claim(ClaimId.EcMissingXCoordinate, ClaimOutcome.Failure));
            }

            // Check for mandatory 'y' field (Y Coordinate), if required
            if(isYCoordinateMandatory)
            {
                if(jwtHeaders.TryGetValue(JwkProperties.Y, out object? yValue) && yValue is string y && !string.IsNullOrEmpty(y))
                {
                    claims.Add(new Claim(ClaimId.EcMissingYCoordinate, ClaimOutcome.Success));
                }
                else
                {
                    claims.Add(new Claim(ClaimId.EcMissingYCoordinate, ClaimOutcome.Failure));
                }
            }

            // Validate 'alg' (Algorithm) and 'crv' (Curve)
            if(crvValue is string crvStr)
            {
                if(jwtHeaders.TryGetValue(JwkProperties.Alg, out object? algValue))
                {
                    if(algValue is string alg && !string.IsNullOrEmpty(alg))
                    {
                        ClaimOutcome isValid = ClaimOutcome.Failure;
                        foreach((Func<string, bool> IsAlg, Func<string, bool> IsCrv) in algCrvPairs)
                        {
                            if(IsAlg(alg) && IsCrv(crvStr))
                            {
                                isValid = ClaimOutcome.Success;
                                break;
                            }
                        }

                        claims.Add(new Claim(ClaimId.EcValidAlgAndCrvCombination, isValid));
                    }
                    else if(isEcAlgRequired)
                    {
                        claims.Add(new Claim(ClaimId.EcValidAlgAndCrvCombination, ClaimOutcome.Failure));
                    }
                }
                else if(!isEcAlgRequired)
                {
                    claims.Add(new Claim(ClaimId.EcAlgOptionalAndNotPresentOrEmpty, ClaimOutcome.Success));
                }
                else
                {
                    claims.Add(new Claim(ClaimId.EcValidAlgAndCrvCombination, ClaimOutcome.Failure));
                }
            }

            return claims;
        }


        public static List<Claim> ValidateRsa(Dictionary<string, object> jwtHeaders)
        {
            ArgumentNullException.ThrowIfNull(jwtHeaders);
            List<Claim> claims = [];
            if(!jwtHeaders.TryGetValue("e", out object? eValue) || eValue is not string eStr || string.IsNullOrEmpty(eStr))
            {
                claims.Add(new Claim(ClaimId.RsaMissingExponent, ClaimOutcome.Failure));
                return claims;
            }

            if(!jwtHeaders.TryGetValue("n", out object? nValue) || nValue is not string nStr || string.IsNullOrEmpty(nStr))
            {
                claims.Add(new Claim(ClaimId.RsaMissingModulus, ClaimOutcome.Failure));
                return claims;
            }

            //TODO: Constants for RSA key lengths...
            // Expected lengths for DER-encoded, Base64Url-encoded RSA keys
            //const int Rsa2048DerEncodedBase64UrlEncodedLength = 360;
            //const int Rsa4096DerEncodedBase64UrlEncodedLength = 702;
            const int Rsa2048RawModulusBase64UrlEncodedLength = 342; //256 bytes * 4/3 ≈ 342 chars.
            const int Rsa4096RawModulusBase64UrlEncodedLength = 683; //512 bytes * 4/3 ≈ 683 chars.

            if(nStr.Length == Rsa2048RawModulusBase64UrlEncodedLength || nStr.Length == Rsa4096RawModulusBase64UrlEncodedLength)
            {
                claims.Add(new Claim(ClaimId.RsaKeyValid, ClaimOutcome.Success));
                return claims;
            }

            claims.Add(new Claim(ClaimId.RsaKeyInvalid, ClaimOutcome.Failure));
            return claims;
        }


        public static List<Claim> ValidateOkp(Dictionary<string, object> jwtHeaders, List<(Func<string, bool> IsAlg, Func<string, bool> IsCrv)> algCrvPairs, bool isOkpAlgRequired = false)
        {
            ArgumentNullException.ThrowIfNull(jwtHeaders);
            ArgumentNullException.ThrowIfNull(algCrvPairs);
            List<Claim> claims = [];
            if(!jwtHeaders.TryGetValue(JwkProperties.Crv, out object? crvValue) || crvValue is not string crvStr || string.IsNullOrEmpty(crvStr))
            {
                claims.Add(new Claim(ClaimId.OkpMissingCurve, ClaimOutcome.Failure));
                return claims;
            }

            ClaimOutcome isValid = ClaimOutcome.Failure;
            if(jwtHeaders.TryGetValue(JwkProperties.Alg, out object? algValue) && algValue is string algStr)
            {
                if(WellKnownCurveValues.IsX25519(crvStr) && !string.IsNullOrEmpty(algStr))
                {
                    claims.Add(new Claim(ClaimId.OkpAlgShouldNotBePresentForX25519, ClaimOutcome.Failure));
                    return claims;
                }

                foreach((Func<string, bool> IsAlg, Func<string, bool> IsCrv) in algCrvPairs)
                {
                    if(IsAlg(algStr) && IsCrv(crvStr))
                    {
                        isValid = ClaimOutcome.Success;
                        break;
                    }
                }

                claims.Add(new Claim(ClaimId.OkpValidAlgAndCrvCombination, isValid));
            }
            else
            {
                claims.Add(new Claim(ClaimId.OkpAlgOptionalOrNotPresent, ClaimOutcome.Success));
            }

            return claims;
        }
    }
}
