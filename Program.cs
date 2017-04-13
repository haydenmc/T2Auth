using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace T2Auth
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Hello World!");
        }

        static void VerityAuth(string clientCert)
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

            // Get SHA1 sum
            var hashAlgorithm = SHA1.Create();
            var sha1Str = userName + "\t" + guid + "\t" + e + "\t" + n;
            var certSum = hashAlgorithm.ComputeHash(Encoding.UTF8.GetBytes(sha1Str));

            var rsaParams = new RSAParameters();
            rsaParams.Exponent = HexStringToByteArray(e);
            rsaParams.Modulus = HexStringToByteArray(n);

            var rsa = RSA.Create();
            rsa.Decrypt(Encoding.ASCII.GetBytes(sig), RSAEncryptionPadding.OaepSHA1)
        }

        public static byte[] HexStringToByteArray(string hex) {
            return Enumerable.Range(0, hex.Length)
                            .Where(x => x % 2 == 0)
                            .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                            .ToArray();
        }
    }
}
