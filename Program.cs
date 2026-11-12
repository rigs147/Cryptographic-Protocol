using System.Text;

string message = "meter=001;reading=01234";

byte[] plaintext = Encoding.UTF8.GetBytes(message);

Console.WriteLine("Message length in bytes: " + plaintext.Length);
Console.WriteLine("Message bytes: " + Convert.ToHexString(plaintext));