using Verifiable.Jwt;

namespace Verifiable.Tests.Jwt
{
    [TestClass]
    public sealed class JwtUtilitiesTests
    {
        /* ReadOnlySpan<byte> RsaExponent65537 = new byte[] { 0x01, 0x00, 0x01 };
           var e = Base64Url.Encode(RsaExponent65537);
           Assert.AreEqual("AQAB", e);
        */

        //As per definition the exponent used by did:key RSA keys is 65537.
        //https://w3c-ccg.github.io/did-method-key/#x2048-bit-modulus-public-exponent-65537
        //This seem to be the default parameter, though better to be explicit and secure about this.
        //ReadOnlySpan<byte> RsaExponent65537 = new byte[] { 0x01, 0x00, 0x01 };
        //This translates to "AQAB" in Base64.
        //var publicExponent_e = Base64UrlEncoder.Encode(RsaExponent65537.ToArray());
        //E = "AQAB",

        //Exponent is fixed and not transmitted in key information so this too can be fixed. Write a better document about this.
        /*
            RSA public modulus n.
            RSA public exponent e.
            RSA secret exponent d = e^-1 \bmod (p-1)(q-1).
            RSA secret prime p.
            RSA secret prime q with p < q.
            Multiplicative inverse u = p^-1 \bmod q.
        */

        private static string RsaExponent65537 => "AQAB";

        [TestMethod]
        public void RfcRsaTestVector()
        {
            //This is the RSA test case from https://datatracker.ietf.org/doc/html/rfc7638#section-3.1.
            var e = RsaExponent65537;
            var kty = "RSA";
            var n = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw";
            var thumbPrintBytes = JoseUtilities.ComputeRsaThumbprint(e, kty, n);
            
            var thumbprint = Base64Url.Encode(thumbPrintBytes);
            Assert.AreEqual("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs", thumbprint);
        }

        //The following are the cases from https://w3c-ccg.github.io/lds-jws2020/#example-2-example-in-did-document.
        //Because the implementation is the same, it reassures the tests and code are correct
        //according to the W3C specification and RFC, which the W3C specification is based on.

        [TestMethod]
        public void Ed25519LdsJws2020OkpCryptoSuiteExample()
        {
            //This is the RSA test case from https://datatracker.ietf.org/doc/html/rfc7638#section-3.1.
            var kty = "OKP";
            var crv = "Ed25519";
            var x = "VCpo2LMLhn6iWku8MKvSLg2ZAoC-nlOyPVQaO3FxVeQ";
            var thumbPrintBytes = JoseUtilities.ComputeEcdhThumbprint(crv, kty, x);

            var thumbprint = Base64Url.Encode(thumbPrintBytes);
            Assert.AreEqual("_Qq0UL2Fq651Q0Fjd6TvnYE-faHiOpRlPVQcY_-tA4A", thumbprint);
        }


        [TestMethod]
        public void Secp256k1EcLdsJws2020CryptoSuiteExample()
        {
            var kty = "EC";
            var crv = "secp256k1";
            var x = "Z4Y3NNOxv0J6tCgqOBFnHnaZhJF6LdulT7z8A-2D5_8";
            var y = "i5a2NtJoUKXkLm6q8nOEu9WOkso1Ag6FTUT6k_LMnGk";
            var thumbPrintBytes = JoseUtilities.ComputeECThumbprint(crv, kty, x, y);

            var thumbprint = Base64Url.Encode(thumbPrintBytes);
            Assert.AreEqual("4SZ-StXrp5Yd4_4rxHVTCYTHyt4zyPfN1fIuYsm6k3A", thumbprint);
        }


        [TestMethod]
        public void RsaLdsJws2020CryptoSuiteExample()
        {
            //This is the RSA test case from https://datatracker.ietf.org/doc/html/rfc7638#section-3.1.
            var e = RsaExponent65537;
            var kty = "RSA";
            var n = "omwsC1AqEk6whvxyOltCFWheSQvv1MExu5RLCMT4jVk9khJKv8JeMXWe3bWHatjPskdf2dlaGkW5QjtOnUKL742mvr4tCldKS3ULIaT1hJInMHHxj2gcubO6eEegACQ4QSu9LO0H-LM_L3DsRABB7Qja8HecpyuspW1Tu_DbqxcSnwendamwL52V17eKhlO4uXwv2HFlxufFHM0KmCJujIKyAxjD_m3q__IiHUVHD1tDIEvLPhG9Azsn3j95d-saIgZzPLhQFiKluGvsjrSkYU5pXVWIsV-B2jtLeeLC14XcYxWDUJ0qVopxkBvdlERcNtgF4dvW4X00EHj4vCljFw";
            var thumbPrintBytes = JoseUtilities.ComputeRsaThumbprint(e, kty, n);

            var thumbprint = Base64Url.Encode(thumbPrintBytes);
            Assert.AreEqual("n4cQ-I_WkHMcwXBJa7IHkYu8CMfdNcZKnKsOrnHLpFs", thumbprint);
        }


        [TestMethod]
        public void NistP256LdsJws2020CryptoSuiteExample()
        {
            var kty = "EC";
            var crv = "P-256";
            var x = "38M1FDts7Oea7urmseiugGW7tWc3mLpJh6rKe7xINZ8";
            var y = "nDQW6XZ7b_u2Sy9slofYLlG03sOEoug3I0aAPQ0exs4";
            var thumbPrintBytes = JoseUtilities.ComputeECThumbprint(crv, kty, x, y);

            var thumbprint = Base64Url.Encode(thumbPrintBytes);
            Assert.AreEqual("_TKzHv2jFIyvdTGF1Dsgwngfdg3SH6TpDv0Ta1aOEkw", thumbprint);
        }


        [TestMethod]
        public void NistP384LdsJws2020CryptoSuiteExample()
        {
            var kty = "EC";
            var crv = "P-384";
            var x = "GnLl6mDti7a2VUIZP5w6pcRX8q5nvEIgB3Q_5RI2p9F_QVsaAlDN7IG68Jn0dS_F";
            var y = "jq4QoAHKiIzezDp88s_cxSPXtuXYFliuCGndgU4Qp8l91xzD1spCmFIzQgVjqvcP";
            var thumbPrintBytes = JoseUtilities.ComputeECThumbprint(crv, kty, x, y);

            var thumbprint = Base64Url.Encode(thumbPrintBytes);
            Assert.AreEqual("8wgRfY3sWmzoeAL-78-oALNvNj67ZlQxd1ss_NX1hZY", thumbprint);
        }


        [TestMethod]
        public void NistP521LdsJws2020CryptoSuiteExample()
        {
            var kty = "EC";
            var crv = "P-521";
            var x = "AVlZG23LyXYwlbjbGPMxZbHmJpDSu-IvpuKigEN2pzgWtSo--Rwd-n78nrWnZzeDc187Ln3qHlw5LRGrX4qgLQ-y";
            var y = "ANIbFeRdPHf1WYMCUjcPz-ZhecZFybOqLIJjVOlLETH7uPlyG0gEoMWnIZXhQVypPy_HtUiUzdnSEPAylYhHBTX2";
            var thumbPrintBytes = JoseUtilities.ComputeECThumbprint(crv, kty, x, y);

            var thumbprint = Base64Url.Encode(thumbPrintBytes);
            Assert.AreEqual("NjQ6Y_ZMj6IUK_XkgCDwtKHlNTUTVjEYOWZtxhp1n-E", thumbprint);
        }
    }
}
