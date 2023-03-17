using System.Security.Cryptography;
using System.Text;

namespace API.Helpers
{
    public class AesCrypto
    {
        public static string Encrypt(string data, string passphrase, byte[] salt = null)
        {
            salt = salt ?? GenerateRandomBytes(8);
            string saltString = Convert.ToBase64String(salt);

            byte[] salted = new byte[48];
            byte[] dx = new byte[0];
            int count = 0;

            while (count < 48)
            {
                byte[] buffer = new byte[dx.Length + Encoding.UTF8.GetBytes(passphrase).Length + salt.Length];
                Buffer.BlockCopy(dx, 0, buffer, 0, dx.Length);
                Buffer.BlockCopy(Encoding.UTF8.GetBytes(passphrase), 0, buffer, dx.Length, Encoding.UTF8.GetBytes(passphrase).Length);
                Buffer.BlockCopy(salt, 0, buffer, dx.Length + Encoding.UTF8.GetBytes(passphrase).Length, salt.Length);

                using (MD5 md5 = MD5.Create())
                    dx = md5.ComputeHash(buffer);

                Buffer.BlockCopy(dx, 0, salted, count, dx.Length);

                count += dx.Length;
            }

            byte[] key = new byte[32];
            byte[] iv = new byte[16];

            Buffer.BlockCopy(salted, 0, key, 0, key.Length);
            Buffer.BlockCopy(salted, key.Length, iv, 0, iv.Length);

            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                using (MemoryStream memoryStream = new MemoryStream())
                {
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        byte[] dataBytes = Encoding.UTF8.GetBytes(data);
                        cryptoStream.Write(dataBytes, 0, dataBytes.Length);
                        cryptoStream.FlushFinalBlock();
                        cryptoStream.Close();
                    }
                    byte[] encrypted = memoryStream.ToArray();
                    return Convert.ToBase64String(Encoding.UTF8.GetBytes("Salted__")
                        .Concat(salt)
                        .Concat(encrypted)
                        .ToArray());
                }
            }
        }

        private static byte[] GenerateRandomBytes(int length)
        {
            byte[] bytes = new byte[length];
            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(bytes);
            }
            return bytes;
        }
    }
}
