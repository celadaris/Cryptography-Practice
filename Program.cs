using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto;
using System.IO;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;

namespace cryptoPractice
{
    class Program
    {
        static void Main(string[] args)
        {
            //Declare Variables
            string SourceData;
            byte[] tmpSource;

            //Enter any text
            Console.WriteLine("Enter any text: ");
            SourceData = Console.ReadLine();

            //Create byte array from source data
            tmpSource = ASCIIEncoding.ASCII.GetBytes(SourceData);
            Console.WriteLine();
            Console.WriteLine();
            Console.WriteLine("Key pairs are generating wait a moment...");
            Console.WriteLine();

            //rSAKeyPairGenerator generates the RSA key pair based on the random number and strength of the key required
            RsaKeyPairGenerator rSAKeyPair = new RsaKeyPairGenerator();
            SecureRandom secureRandom = new SecureRandom();
            secureRandom.SetSeed(secureRandom.GenerateSeed(1000));
            rSAKeyPair.Init(new KeyGenerationParameters(secureRandom, 2048));
            AsymmetricCipherKeyPair keyPair = rSAKeyPair.GenerateKeyPair();

            //Extract private/public key from the pair
            RsaKeyParameters privateKey = keyPair.Private as RsaKeyParameters;
            RsaKeyParameters publicKey = keyPair.Public as RsaKeyParameters;

            //print public key in pem format
            TextWriter textWriter = new StringWriter();
            PemWriter pemWriter = new PemWriter(textWriter);
            pemWriter.WriteObject(publicKey);
            pemWriter.Writer.Flush();
            string printPublicKey = textWriter.ToString();
            Console.WriteLine("Public key is: " + printPublicKey);
            Console.WriteLine();

            //Encryption process
            IAsymmetricBlockCipher encryptCipher = new OaepEncoding(new RsaEngine());
            encryptCipher.Init(true, publicKey);
            byte[] cipherText = encryptCipher.ProcessBlock(tmpSource, 0, tmpSource.Length);
            string result = Encoding.UTF8.GetString(cipherText);
            Console.WriteLine("Encrypted Text: ");
            Console.WriteLine(result);
            Console.WriteLine();
            Console.WriteLine();

            Console.WriteLine("Do you want to decrypt the text???? Press 'y' for yes and any other key for 'no'");
            char input = Console.ReadKey().KeyChar;

            if (input == 'y' || input == 'Y')
            {
                Decrypt(cipherText, privateKey);
            }
            Console.ReadLine();
        }

        static void Decrypt(byte[] ct, RsaKeyParameters pvtKey)
        {
            IAsymmetricBlockCipher decryptCipher = new OaepEncoding(new RsaEngine());
            decryptCipher.Init(false, pvtKey);
            byte[] deciphered = decryptCipher.ProcessBlock(ct, 0, ct.Length);
            string decipheredText = Encoding.UTF8.GetString(deciphered);
            Console.WriteLine();
            Console.WriteLine();

            Console.WriteLine("Decrypted Text: " + decipheredText);
            Console.WriteLine();
            Console.WriteLine();
        }
    }
}
