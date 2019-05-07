using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using ErikTheCoder.Logging;
using ErikTheCoder.ServiceContract;
using Newtonsoft.Json;


namespace ErikTheCoder.Encryptor
{
    public static class Program
    {
        public static async Task Main(string[] Arguments)
        {
            try
            {
                await Run(Arguments);
                SafeConsole.WriteLine(null);
            }
            catch (Exception exception)
            {
                SafeConsole.WriteLine(exception.GetSummary(true, true), ConsoleColor.Red);
            }
        }


        private static async Task Run(IReadOnlyList<string> Arguments)
        {
            EncryptedFileHeader encryptedFileHeader = ParseCommandLine(Arguments);
            switch (encryptedFileHeader.Operation)
            {
                case Operation.Encrypt:
                    await Encrypt(encryptedFileHeader);
                    break;
                case Operation.Decrypt:
                    await Decrypt(encryptedFileHeader.Filename);
                    break;
                default:
                    throw new ArgumentException($"{encryptedFileHeader.Operation} operation not supported.");
            }
        }


        // TODO: Add progress bar.
        private static async Task Encrypt(EncryptedFileHeader EncryptedFileHeader)
        {
            const string encryptedFileExtension = ".encrypted";
            bool inputPathIsFile = File.Exists(EncryptedFileHeader.Filename);
            if (!inputPathIsFile && !Directory.Exists(EncryptedFileHeader.Filename)) throw new Exception($"{EncryptedFileHeader.Filename} input path does not exist.");
            // TODO: Support encrypting entire directories using System.IO.Compression.ZipFile class.
            if (!inputPathIsFile) throw new NotSupportedException("Encrypting directories is not supported.");
            // Get password from user.
            // TODO: Hide password.
            // TODO: Confirm password.
            SafeConsole.Write("Enter password: ");
            string password = SafeConsole.ReadLine();
            string outputFilename = Path.ChangeExtension(EncryptedFileHeader.Filename, encryptedFileExtension);
            using (FileStream inputFileStream = File.Open(EncryptedFileHeader.Filename, FileMode.Open, FileAccess.Read, FileShare.Read))
            using (FileStream outputFileStream = File.Open(outputFilename, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                // Generate key from password and random salt.
                using (RNGCryptoServiceProvider random = new RNGCryptoServiceProvider()) { random.GetBytes(EncryptedFileHeader.Salt); }
                using (DeriveBytes keyDerivation = KeyDerivation.Create(EncryptedFileHeader.KeyDerivationAlgorithm, password, EncryptedFileHeader.Salt, EncryptedFileHeader.KeyDerivationIterations))
                using (SymmetricAlgorithm cipher = Cipher.Create(EncryptedFileHeader.CipherAlgorithm))
                {
                    byte[] key = keyDerivation.GetBytes(EncryptedFileHeader.KeyLength);
                    // Create cipher and generate initialization vector.
                    // Generate a new initialization vector for each encryption to prevent identical plaintexts from producing identical ciphertexts when encrypted using the same key.
                    cipher.GenerateIV();
                    EncryptedFileHeader.InitializationVector = new byte[cipher.IV.Length];
                    cipher.IV.CopyTo(EncryptedFileHeader.InitializationVector, 0);
                    // Write integer length of encrypted file header followed by the header bytes.
                    byte[] encryptedFileHeaderBytes = Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(EncryptedFileHeader));
                    await outputFileStream.WriteAsync(BitConverter.GetBytes(encryptedFileHeaderBytes.Length));
                    await outputFileStream.WriteAsync(encryptedFileHeaderBytes);
                    // Create encrypting output stream.
                    byte[] buffer = new byte[cipher.BlockSize];
                    using (ICryptoTransform encryptor = cipher.CreateEncryptor(key, EncryptedFileHeader.InitializationVector))
                    using (CryptoStream cryptoStream = new CryptoStream(outputFileStream, encryptor, CryptoStreamMode.Write))
                    {
                        // Repeatedly read a block from input stream and write it to the encrypted output stream.
                        int bytesRead;
                        while ((bytesRead = await inputFileStream.ReadAsync(buffer, 0, buffer.Length)) > 0) await cryptoStream.WriteAsync(buffer, 0, bytesRead);
                    }
                }
            }
            SafeConsole.WriteLine($"Wrote encrypted file to {outputFilename}.");
        }


        private static async Task Decrypt(string InputPath)
        {
            //using (FileStream inputFileStream = File.Open(InputPath, FileMode.Open, FileAccess.Read, FileShare.Read))
            //{
            //    // Read integer length of encrypted file header followed by header bytes.
            //    byte[] headerLengthBytes = new byte[sizeof(int)];
            //    await inputFileStream.ReadAsync(headerLengthBytes, 0, headerLengthBytes.Length);
            //    int headerLength = BitConverter.ToInt32(headerLengthBytes);
            //    byte[] headerBytes = new byte[headerLength];
            //    await inputFileStream.ReadAsync(headerBytes, 0, headerBytes.Length);
            //    EncryptedFileHeader encryptedFileHeader = JsonConvert.DeserializeObject<EncryptedFileHeader>(Encoding.UTF8.GetString(headerBytes));
            //    // Create decrypting input stream and plaintext output stream.
            //    SymmetricAlgorithm cipher = Cipher.Create(encryptedFileHeader.CipherAlgorithm);
            //    using (ICryptoTransform decryptor = cipher.CreateDecryptor())

            //        string outputFilename = Path.Combine(Path.GetDirectoryName(InputPath), encryptedFileHeader.Filename);
            //    using (FileStream outputFileStream = File.Open(outputFilename, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            //    {

            //    }
            //}
        }


        private static EncryptedFileHeader ParseCommandLine(IReadOnlyList<string> Arguments)
        {
            if (Arguments.Count % 2 != 0) throw new ArgumentException("Invalid number of arguments.  Arguments must be passed in a pair: -argumentName argumentValue or /argumentName argumentValue.");
            EncryptedFileHeader encryptedFileHeader = new EncryptedFileHeader();
            for (int index = 0; index < Arguments.Count; index++)
            {
                string argumentName = Arguments[index];
                index++;
                string argumentValue = Arguments[index];
                switch (argumentName?.ToLower())
                {
                    case "-i":
                    case "/i":
                    case "-input":
                    case "/input":
                        encryptedFileHeader.Filename = argumentValue;
                        break;
                    case "-o":
                    case "/o":
                    case "-operation":
                    case "/operation":
                        encryptedFileHeader.Operation = Enum.Parse<Operation>(argumentValue, true);
                        break;
                    case "-c":
                    case "/c":
                    case "-cipher":
                    case "/cipher":
                        encryptedFileHeader.CipherAlgorithm = argumentValue;
                        break;
                    case "-kd":
                    case "/kd":
                    case "-keyderivation":
                    case "/keyderivation":
                        encryptedFileHeader.KeyDerivationAlgorithm = argumentValue;
                        break;
                    case "-kdi":
                    case "/kdi":
                    case "-kditerations":
                    case "/kditerations":
                        if (int.TryParse(argumentValue, out int keyDerivationIterations)) encryptedFileHeader.KeyDerivationIterations = keyDerivationIterations;
                        break;
                    case "-kl":
                    case "/kl":
                    case "-keylength":
                    case "/keylength":
                        if (int.TryParse(argumentValue, out int keyLength)) encryptedFileHeader.KeyLength = keyLength;
                        break;
                    case "-sl":
                    case "/sl":
                    case "-saltlength":
                    case "/saltlength":
                        if (int.TryParse(argumentValue, out int saltLength)) encryptedFileHeader.Salt = new byte[saltLength];
                        break;
                }
            }
            // Validate arguments.
            if (string.IsNullOrEmpty(encryptedFileHeader.Filename)) throw new ArgumentException("Specify an input path via -i argument.");
            if (encryptedFileHeader.Operation == Operation.Unknown) throw new ArgumentException("Specify an operation via -o argument.");
            if (encryptedFileHeader.CipherAlgorithm is null) throw new ArgumentException("Specify a cipher via -c argument.");
            if (encryptedFileHeader.KeyDerivationAlgorithm is null) throw new ArgumentException("Specify a key derivation algorithm via -kd argument.");
            if (encryptedFileHeader.KeyDerivationIterations <= 0) throw new ArgumentException("Specify key derivation iterations via -kdi argument");
            if (encryptedFileHeader.KeyLength == 0) throw new ArgumentException("Specify a key length in bytes via -kl argument.");
            if (encryptedFileHeader.Salt.Length <= 0) throw new ArgumentException("Specify a salt length via -sl argument.");
            return encryptedFileHeader;
        }
    }
}
