using System.Text;
using System.Security.Cryptography;

string message = "meter=001;reading=01234";

byte[] plaintext = Encoding.UTF8.GetBytes(message);

Console.WriteLine("Message length in bytes: " + plaintext.Length);
Console.WriteLine("Message bytes: " + Convert.ToHexString(plaintext));

byte[] key = RandomNumberGenerator.GetBytes(16);

Console.WriteLine("Key length in bits: " + (key.Length * 8));

byte[] nonce = RandomNumberGenerator.GetBytes(12);

Console.WriteLine("Nonce: " + Convert.ToHexString(nonce));