using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Forms;

namespace BIL4106_HW
{
    public class Utilities
    {
        public static void SaveKeys(string keyFileName)
        {
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(2048))
            {
                try
                {
                    // Can be verified via:
                    // openssl rsa -in private.key -pubout > public2.pem
                    using (StreamWriter writer = File.CreateText(keyFileName + "_public.pem"))
                    {
                        writer.Write(RSAKeys.ExportPublicKey(rsa));
                    }
                    using (StreamWriter writer = File.CreateText(keyFileName + "_private.key"))
                    {
                        writer.Write(RSAKeys.ExportPrivateKey(rsa));
                    }
                }
                catch (Exception e)
                {
                    MessageBox.Show("Error while writing keys to files." + Environment.NewLine + e.Message);
                }
                finally
                {
                    rsa.PersistKeyInCsp = false;
                }
            }
        }

        public static void SignAndEncrypt(RSACryptoServiceProvider privateKey, RSACryptoServiceProvider publicKey,
            FileStream stream, string encryptedFileName, string AESKeyFileName)
        {
            byte[] sign = null;
            try
            {
                sign = privateKey.SignData(stream, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
            }
            catch (Exception e)
            {
                MessageBox.Show("Error while signing the file." + Environment.NewLine + e.Message);
                return;
            }
            finally
            {
                stream.Seek(0, SeekOrigin.Begin);
            }

            //============//

            byte[] encryptedRSA = null;
            try
            {
                using (FileStream fs = new FileStream(encryptedFileName, FileMode.Create, FileAccess.Write))
                {
                    using (RijndaelManaged AES = new RijndaelManaged())
                    {
                        AES.GenerateIV();
                        AES.GenerateKey();
                        encryptedRSA = publicKey.Encrypt(AES.Key, false);

                        fs.Write(AES.IV, 0, AES.BlockSize / 8);
                        using (var cs = new CryptoStream(fs, AES.CreateEncryptor(), CryptoStreamMode.Write))
                        {
                            cs.Write(sign, 0, sign.Length);
                            stream.CopyTo(cs);
                            cs.Close();
                        }
                    }
                }
            }
            catch (Exception e)
            {
                MessageBox.Show("Error while encrypting the file or writing to file." + Environment.NewLine + e.Message);
                return;
            }
            finally
            {
                stream.Seek(0, SeekOrigin.Begin);
            }

            try
            {
                using (StreamWriter writer = File.CreateText(AESKeyFileName))
                {
                    writer.Write(BitConverter.ToString(encryptedRSA).Replace("-", "").ToLowerInvariant());
                }
            }
            catch (Exception e)
            {
                MessageBox.Show("Error while writing crypted AES key." + Environment.NewLine + e.Message);
                return;
            }
        }

        public static void DecryptAndVerify(RSACryptoServiceProvider privateKey, RSACryptoServiceProvider publicKey,
            FileStream stream, string AESKeyFileName, string decryptedFileName)
        {
            string aesKey = null;
            try
            {
                using (var streamReader = new StreamReader(AESKeyFileName, Encoding.UTF8))
                {
                    aesKey = streamReader.ReadLine();
                }
            }
            catch (Exception e)
            {
                MessageBox.Show("Error while reading AES Key file." + Environment.NewLine + e.Message);
                return;
            }

            byte[] data = null;
            try
            {
                data = StringToByteArray(aesKey);
            }
            catch (Exception e)
            {
                MessageBox.Show("Corrupt AES Key file." + Environment.NewLine + e.Message);
                return;
            }

            byte[] AESKey = null;
            try
            {
                AESKey = privateKey.Decrypt(data, false);
            }
            catch (Exception e)
            {
                MessageBox.Show("Decrypting the AES Key file did not succeed." + Environment.NewLine + e.Message);
                return;
            }

            byte[] sign = null;
            try
            {
                using (RijndaelManaged AES = new RijndaelManaged())
                {
                    AES.Key = AESKey;
                    var iv = ReadFully(stream, AES.BlockSize / 8);
                    AES.IV = iv;

                    using (var cs = new NotClosingCryptoStream(stream, AES.CreateDecryptor(), CryptoStreamMode.Read))
                    {
                        sign = ReadFully(cs, 256);
                        using (FileStream fs = new FileStream(decryptedFileName, FileMode.Create, FileAccess.Write))
                        {
                            cs.CopyTo(fs);
                        }
                    }
                }
            }
            catch (Exception e)
            {
                MessageBox.Show("Error while decrypting the file or writing to file." + Environment.NewLine + e.Message);
                return;
            }
            finally
            {
                stream.Seek(0, SeekOrigin.Begin);
            }

            //============//

            try
            {
                using (FileStream decrypted = new FileStream(decryptedFileName, FileMode.Open, FileAccess.Read, FileShare.None))
                {
                    if (publicKey.VerifyData(decrypted, sign, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1))
                    {
                        MessageBox.Show("File sign is verified");
                    }
                    else
                    {
                        MessageBox.Show("File is tempered");
                    }
                }
            }
            catch (Exception e)
            {
                MessageBox.Show("Error while verifying the signature." + Environment.NewLine + e.Message);
                return;
            }
        }

        /// <summary>
        /// Heavily modified from https://stackoverflow.com/a/27578879
        /// </summary>
        /// <param name="privateKey"></param>
        /// <param name="stream"></param>
        /// <param name="signFileName"></param>
        public static void Sign(RSACryptoServiceProvider privateKey, FileStream stream, string signFileName)
        {
            byte[] sign = null;
            try
            {
                sign = privateKey.SignData(stream, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
            }
            catch (Exception e)
            {
                MessageBox.Show("Error while signing the file." + Environment.NewLine + e.Message);
                return;
            }
            finally
            {
                stream.Seek(0, SeekOrigin.Begin);
            }

            try
            {
                using (StreamWriter writer = File.CreateText(signFileName))
                {
                    writer.Write(BitConverter.ToString(sign).Replace("-", "").ToLowerInvariant());
                }
            }
            catch (Exception e)
            {
                MessageBox.Show("Error while writing the signature file." + Environment.NewLine + e.Message);
                return;
            }
        }

        /// <summary>
        /// Heavily modified from https://stackoverflow.com/a/27578879
        /// </summary>
        /// <param name="publicKey"></param>
        /// <param name="stream"></param>
        /// <param name="signFileName"></param>
        public static void Verify(RSACryptoServiceProvider publicKey, FileStream stream, string signFileName)
        {
            string sign = null;
            try
            {
                using (var streamReader = new StreamReader(signFileName, Encoding.UTF8))
                {
                    sign = streamReader.ReadLine();
                }
            }
            catch (Exception e)
            {
                MessageBox.Show("Error while reading the signature file." + Environment.NewLine + e.Message);
                return;
            }

            byte[] data = null;
            try
            {
                data = StringToByteArray(sign);
            }
            catch (Exception e)
            {
                MessageBox.Show("Corrupt signature file." + Environment.NewLine + e.Message);
                return;
            }

            try
            {
                if (publicKey.VerifyData(stream, data, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1))
                {
                    MessageBox.Show("File sign is verified");
                }
                else
                {
                    MessageBox.Show("File is tempered");
                }
            }
            catch (Exception e)
            {
                MessageBox.Show("Error while verifying the signature." + Environment.NewLine + e.Message);
                return;
            }
            finally
            {
                stream.Seek(0, SeekOrigin.Begin);
            }
        }

        /// <summary>
        /// Taken from https://stackoverflow.com/a/30821908
        /// </summary>
        /// <param name="publicKey"></param>
        /// <param name="stream"></param>
        /// <param name="encryptedFileName"></param>
        /// <param name="AESKeyFileName"></param>
        public static void EncryptAES(RSACryptoServiceProvider publicKey, FileStream stream,
            string encryptedFileName, string AESKeyFileName)
        {
            byte[] encryptedRSA = null;
            try
            {
                using (FileStream fs = new FileStream(encryptedFileName, FileMode.Create, FileAccess.Write))
                {
                    using (RijndaelManaged AES = new RijndaelManaged())
                    {
                        AES.GenerateIV();
                        AES.GenerateKey();
                        encryptedRSA = publicKey.Encrypt(AES.Key, false);

                        fs.Write(AES.IV, 0, AES.BlockSize / 8);
                        using (var cs = new CryptoStream(fs, AES.CreateEncryptor(), CryptoStreamMode.Write))
                        {
                            stream.CopyTo(cs);
                            cs.Close();
                        }
                    }
                }
            }
            catch (Exception e)
            {
                MessageBox.Show("Error while encrypting the file or writing to file." + Environment.NewLine + e.Message);
                return;
            }
            finally
            {
                stream.Seek(0, SeekOrigin.Begin);
            }

            try
            {
                using (StreamWriter writer = File.CreateText(AESKeyFileName))
                {
                    writer.Write(BitConverter.ToString(encryptedRSA).Replace("-", "").ToLowerInvariant());
                }
            }
            catch (Exception e)
            {
                MessageBox.Show("Error while writing crypted AES key." + Environment.NewLine + e.Message);
                return;
            }
        }

        /// <summary>
        /// Taken from https://stackoverflow.com/a/30821908
        /// </summary>
        /// <param name="privateKey"></param>
        /// <param name="stream"></param>
        /// <param name="AESKeyFileName"></param>
        /// <param name="decryptedFileName"></param>
        public static void DecryptAES(RSACryptoServiceProvider privateKey, FileStream stream,
            string AESKeyFileName, string decryptedFileName)
        {
            string aesKey = null;
            try
            {
                using (var streamReader = new StreamReader(AESKeyFileName, Encoding.UTF8))
                {
                    aesKey = streamReader.ReadLine();
                }
            }
            catch (Exception e)
            {
                MessageBox.Show("Error while reading AES Key file." + Environment.NewLine + e.Message);
                return;
            }

            byte[] data = null;
            try
            {
                data = StringToByteArray(aesKey);
            }
            catch (Exception e)
            {
                MessageBox.Show("Corrupt AES Key file." + Environment.NewLine + e.Message);
                return;
            }

            byte[] AESKey = null;
            try
            {
                AESKey = privateKey.Decrypt(data, false);
            }
            catch (Exception e)
            {
                MessageBox.Show("Decrypting the AES Key file did not succeed." + Environment.NewLine + e.Message);
                return;
            }

            try
            {
                using (RijndaelManaged AES = new RijndaelManaged())
                {
                    AES.Key = AESKey;
                    var iv = ReadFully(stream, AES.BlockSize / 8);
                    AES.IV = iv;

                    using (var cs = new NotClosingCryptoStream(stream, AES.CreateDecryptor(), CryptoStreamMode.Read))
                    {
                        using (FileStream fs = new FileStream(decryptedFileName, FileMode.Create, FileAccess.Write))
                        {
                            cs.CopyTo(fs);
                        }
                    }
                }
            }
            catch (Exception e)
            {
                MessageBox.Show("Error while decrypting the file or writing to file." + Environment.NewLine + e.Message);
                return;
            }
            finally
            {
                stream.Seek(0, SeekOrigin.Begin);
            }
        }

        /// <summary>
        /// Taken from https://stackoverflow.com/a/30821908
        /// </summary>
        /// <param name="stream">stream</param>
        /// <param name="length">lenght to read</param>
        /// <returns></returns>
        public static byte[] ReadFully(Stream stream, int length)
        {
            int offset = 0;
            byte[] buffer = new byte[length];
            while (offset < length)
            {
                offset += stream.Read(buffer, offset, length - offset);
            }
            return buffer;
        }

        /// <summary>
        /// Slightly modified from https://stackoverflow.com/a/41270318
        /// Read more about Generics here: https://stackoverflow.com/a/6529618
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="stream"></param>
        /// <returns></returns>
        public static string CalculateHash<T>(FileStream stream) where T : HashAlgorithm, new()
        {
            using (T crypt = new T())
            {
                byte[] hash = crypt.ComputeHash(stream);
                stream.Seek(0, SeekOrigin.Begin);
                return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
            }
        }

        /// <summary>
        /// Taken from https://stackoverflow.com/a/311179
        /// </summary>
        /// <param name="hex"></param>
        /// <returns></returns>
        public static byte[] StringToByteArray(string hex)
        {
            int NumberChars = hex.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }
    }
    /// <summary>
    /// Taken from https://stackoverflow.com/a/28057998
    /// </summary>
    class NotClosingCryptoStream : CryptoStream
    {
        public NotClosingCryptoStream(Stream stream, ICryptoTransform transform, CryptoStreamMode mode)
            : base(stream, transform, mode)
        {
        }

        protected override void Dispose(bool disposing)
        {
            if (!HasFlushedFinalBlock)
                FlushFinalBlock();

            base.Dispose(false);
        }
    }
}