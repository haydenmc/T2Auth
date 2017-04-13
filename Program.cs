using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace T2Auth
{
    class Program
    {
        private static string AuthServerPublicModulusStr = "a2303d7c7d3ff28daa2dfd4f7fddcbb939aa461a3a298f22f4cbc8f87c6e584479861b1a638ea2daf87a18420f65b486cbe70453ce4f5f38a55b30026457eab3ef2716aa409d25cb8b809a9ef06e3bcdc5b37f0d975cca972601d6a6d4be10e8e5994708e878ab846caa58466eea79ccd1b49f9f06e4d6b335ba2b47b6dc81a04167a2c2fa2b9f847c1375cb6fef1a3c7ced04f750a9605fab584d2d2a4bbed6d41d4c2eeb5e223ac3bc6d8ac025f4b25bb1058998f768025baea18272a3bddab58f94a9cb4a14452eaf7a50812e012fc42feb5d986183da134f168b447e4da6e00c351bc679b098b78bfdf3e17efcd65ec3d2098a14426957db5e30fa01292961f3caf3aadb12aff45782dd9f8737953491c90ad4df8b76ef2559b4ef3bae957f964cf4c9ded3d2171c9d190ba5a6a079a3d75f2c583217db626bd4074a2559794b475a9c2384096aa2b4816d2e61c144d1de14164b77428a5329da3a4a8174b6a84d8733495ac6bc7efa981f23b4f401a6216e18771856721c74ff136c1cbe7449de0dff26c04f940d3ce31ef369e3b09932ffe7ffb347554bd2171dc5c79337a6d0dad0f8aa5f45bf054d0d0e5b73eaa83e6fdcaf4cbf2422697aa570823c682d76087b6815b0212c80e3ed550420a45f70533214619efc468548af45b6e73fec0acbae55b08c978c0c3de09c79a50626502c49b541b7bf002508cc5a8095";
        private static string AuthServerPublicExponentStr = "3";
        static void Main(string[] args)
        {
            VerifyAuth("Apex-	2505515	3	c0322c18b40aa07679442bda3fadc9c0645fed4e62960e1dbffb29d1ed29b1f19957a3943396df37951ee67d4d3fec0533997b0acfe5a8e8a8fdbf964d618cef	641d03a429e2aedb0f84703c71d55b425f903a55d4f41382cf2c3f524e1e7240e9238e55b30611f47d5b41d287ae403318f4ad4a34e780afaca7802f7c57dba81cb12292085dd1fff66f9674fe8ed4174df57415662d9b5bbbdb306cff30759d63ad9718decd4bc1c733dc95ae8cff38e1370e80e3029938ab9545e2d9bf252c1beebb2e4d182a0807fb18e5d2b4dedbdf37a3b282f366dacfeaae47d108af5dd5f634c2b076aaa5144368c71b315b2f8bcda0e64e4a69a9a49e0f8c01e10ad5fcbdc58b6f179f55422c52915bf4f779813dd637d3e09c5842071344c4401ca218f466381951c686e27532e52bff46a0f0142ae49660a22c7bdce96ff0ed15edd0fefbb7d4b06c6cc84a8ad19ddc0d8106dcb91575ff58bd5ce09ac39602265b244e76ea78260a83b4a0a9b56a50d543f57d8a6cee17615a8c05c9d7b4e0d9fcdde2c3472c791fc84334b4a65f4a50a09c14987de64aded9c51cf2f8c00d9b961d86fc1fd3a8e2e8abcc4b92545894daaeeccf2219f91e4226f51d611bc286f615a0b755ab48c2bc962f62f12ce6acaac39416819d0bf4629bdcc42e24df5024a3ded8e104a33c99ccd6e4b6bacfa655d424b864d9ecebaa5c730b760a2389ca580597179024d61d4c7ef4b653e8375dba866417659eb54c09627f32ed670447d667c108b13ca4a2ab997f7ef6a2fa6b803b256a47cf1e646feef58bcf06a49e");
        }

        static void VerifyAuth(string clientCert)
        {
            var certFields = clientCert.Split('\t'); // Split cert into fields
            if (certFields.Length < 5)
            {
                throw new Exception("Invalid certificate: Incorrect number of fields.");
            }
            var userName = certFields[0];
            var guid = certFields[1];
            var e = certFields[2];
            var n = certFields[3];
            var sig = certFields[4];

            Console.WriteLine($"User: {userName}\nGUID: {guid}\nExponent: {e}\nModulus: {n}\nSignature: {sig}");

            // Calculate SHA1 sum
            var hashAlgorithm = SHA1.Create();
            var sha1Str = userName + "\t" + guid + "\t" + e + "\t" + n;
            var calculatedSum = hashAlgorithm.ComputeHash(Encoding.UTF8.GetBytes(sha1Str));
            var calculatedSumStr = string.Join("", calculatedSum.Select(b => b.ToString("x2")).ToArray());

            Console.WriteLine($"Calculated SHA1Sum: {calculatedSumStr}");

            // Decrypt SHA1 sum
            var rsa = RSA.Create();
            var rsaParams = new RSAParameters(); // Export params
            rsaParams.Exponent = new byte[] { (byte)e[0] }; // Set public key props
            rsaParams.Modulus = HexStringToByteArray(n);
            Console.WriteLine($"Exponent bytes: {rsaParams.Exponent.Length}\nModulus bytes: {rsaParams.Modulus.Length}");
            rsa.ImportParameters(rsaParams); // Import params
            var decryptedSig = rsa.Decrypt(HexStringToByteArray(sig), RSAEncryptionPadding.OaepSHA1); // Decrypt the signature segment
            var decryptedSigStr = Encoding.UTF8.GetString(decryptedSig);

            Console.WriteLine($"Decrypted SHA1Sum: {decryptedSigStr}");
        }

        public static byte[] HexStringToByteArray(string hex) {
            return Enumerable
                .Range(0, hex.Length / 2)
                .Select(x => Convert.ToByte(hex.Substring(x * 2, 2), 16))
                .ToArray();
        }
    }
}
