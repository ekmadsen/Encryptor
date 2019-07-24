using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using ErikTheCoder.Logging;
using ErikTheCoder.Utilities;
using Newtonsoft.Json;


namespace ErikTheCoder.Encryptor
{
    public static class Program
    {
        private const string _elapsedSecondsFormat = "0.000";
        private static Stopwatch _stopwatch;


        public static async Task Main(string[] Arguments)
        {
            try
            {
                await RunAsync(Arguments);
                ThreadsafeConsole.WriteLine(null);
            }
            catch (Exception exception)
            {
                ThreadsafeConsole.WriteLine(exception.GetSummary(true, true), ConsoleColor.Red);
            }
        }


        private static async Task RunAsync(IReadOnlyList<string> Arguments)
        {
            _stopwatch = Stopwatch.StartNew();
            EncryptedFileHeader encryptedFileHeader = ParseCommandLine(Arguments);
            ThreadsafeConsole.WriteLine();
            switch (encryptedFileHeader.Operation)
            {
                case Operation.Encrypt:
                    await EncryptAsync(encryptedFileHeader);
                    break;
                case Operation.Decrypt:
                    await DecryptAsync(encryptedFileHeader.Filename);
                    break;
                default:
                    throw new ArgumentException($"{encryptedFileHeader.Operation} operation not supported.");
            }
        }


        // TODO: Add progress bar.
        private static async Task EncryptAsync(EncryptedFileHeader EncryptedFileHeader)
        {
            const string encryptedFileExtension = ".encrypted";
            bool inputPathIsFile = File.Exists(EncryptedFileHeader.Filename);
            if (!inputPathIsFile && !Directory.Exists(EncryptedFileHeader.Filename)) throw new Exception($"{EncryptedFileHeader.Filename} input path does not exist.");
            ThreadsafeConsole.WriteLine(inputPathIsFile ? "InputPath is a file." : "InputPath is a directory.");
            // TODO: Support encrypting entire directories using System.IO.Compression.ZipFile class.
            if (!inputPathIsFile) throw new NotSupportedException("Encrypting directories is not supported.");
            // Get password from user.
            // TODO: Hide password.
            // TODO: Confirm password.
            ThreadsafeConsole.WriteLine();
            ThreadsafeConsole.Write("Enter password: ", ConsoleColor.Yellow);
            string password = ThreadsafeConsole.ReadLine();
            ThreadsafeConsole.WriteLine();
            string outputFilename = Path.ChangeExtension(EncryptedFileHeader.Filename, encryptedFileExtension);
            ThreadsafeConsole.WriteLine($"Output filename is {outputFilename}.");
            TimeSpan encryptionStart = _stopwatch.Elapsed;
            using (FileStream inputFileStream = File.Open(EncryptedFileHeader.Filename, FileMode.Open, FileAccess.Read, FileShare.Read))
            using (FileStream outputFileStream = File.Open(outputFilename, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                // Generate key from password and random salt.
                using (RNGCryptoServiceProvider random = new RNGCryptoServiceProvider()) { random.GetBytes(EncryptedFileHeader.Salt); }
                using (DeriveBytes keyDerivation = KeyDerivation.Create(EncryptedFileHeader.KeyDerivationAlgorithm, password, EncryptedFileHeader.Salt, EncryptedFileHeader.KeyDerivationIterations))
                using (SymmetricAlgorithm cipher = Cipher.Create(EncryptedFileHeader.CipherAlgorithm))
                {
                    byte[] key = keyDerivation.GetBytes(EncryptedFileHeader.KeyLength);
                    ThreadsafeConsole.WriteLine($"Encryption key (derived from password and a random salt) is {Convert.ToBase64String(key)}.");
                    // Create cipher and generate initialization vector.
                    // Generate a new initialization vector for each encryption to prevent identical plaintexts from producing identical ciphertexts when encrypted using the same key.
                    cipher.GenerateIV();
                    EncryptedFileHeader.InitializationVector = new byte[cipher.IV.Length];
                    cipher.IV.CopyTo(EncryptedFileHeader.InitializationVector, 0);
                    ThreadsafeConsole.WriteLine($"Cipher initialization vector is {Convert.ToBase64String(EncryptedFileHeader.InitializationVector)}.");
                    // Write integer length of encrypted file header followed by the the header bytes.
                    byte[] fileHeaderBytes = Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(EncryptedFileHeader));
                    await outputFileStream.WriteAsync(BitConverter.GetBytes(fileHeaderBytes.Length));
                    await outputFileStream.WriteAsync(fileHeaderBytes);
                    // Create encrypting output stream.
                    byte[] buffer = new byte[cipher.BlockSize];
                    using (ICryptoTransform encryptor = cipher.CreateEncryptor(key, EncryptedFileHeader.InitializationVector))
                    using (CryptoStream cryptoStream = new CryptoStream(outputFileStream, encryptor, CryptoStreamMode.Write))
                    {
                        // To limit memory usage, repeatedly read a small block from input stream and write it to the encrypted output stream.
                        int bytesRead;
                        while ((bytesRead = await inputFileStream.ReadAsync(buffer, 0, buffer.Length)) > 0) await cryptoStream.WriteAsync(buffer, 0, bytesRead);
                    }
                }
            }
            TimeSpan encryptionDuration = _stopwatch.Elapsed - encryptionStart;
            ThreadsafeConsole.WriteLine($"Wrote encrypted file to {outputFilename}.");
            ThreadsafeConsole.WriteLine($"Encryption took {encryptionDuration.TotalSeconds.ToString(_elapsedSecondsFormat)} seconds.");
        }


        private static async Task DecryptAsync(string InputPath)
        {
            // Get password from user.
            // TODO: Hide password.
            // TODO: Confirm password.
            ThreadsafeConsole.Write("Enter password: ", ConsoleColor.Yellow);
            string password = ThreadsafeConsole.ReadLine();
            ThreadsafeConsole.WriteLine();
            string outputFilename;
            TimeSpan encryptionStart = _stopwatch.Elapsed;
            using (FileStream inputFileStream = File.Open(InputPath, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                // Read integer length of encrypted file header followed by header bytes.
                byte[] headerLengthBytes = new byte[sizeof(int)];
                await inputFileStream.ReadAsync(headerLengthBytes, 0, headerLengthBytes.Length);
                int headerLength = BitConverter.ToInt32(headerLengthBytes);
                byte[] headerBytes = new byte[headerLength];
                await inputFileStream.ReadAsync(headerBytes, 0, headerBytes.Length);
                EncryptedFileHeader encryptedFileHeader = JsonConvert.DeserializeObject<EncryptedFileHeader>(Encoding.UTF8.GetString(headerBytes));
                outputFilename = Path.Combine(Path.GetDirectoryName(InputPath), encryptedFileHeader.Filename);
                ThreadsafeConsole.WriteLine($"Output filename is {outputFilename}.");
                // Generate key from password (provided by user) and salt (stored in encrypted file).
                using (DeriveBytes keyDerivation = KeyDerivation.Create(encryptedFileHeader.KeyDerivationAlgorithm, password, encryptedFileHeader.Salt, encryptedFileHeader.KeyDerivationIterations))
                {
                    byte[] key = keyDerivation.GetBytes(encryptedFileHeader.KeyLength);
                    ThreadsafeConsole.WriteLine($"Encryption key (derived from password and salt) is {Convert.ToBase64String(key)}.");
                    ThreadsafeConsole.WriteLine($"Cipher initialization vector is {Convert.ToBase64String(encryptedFileHeader.InitializationVector)}.");
                    // Create cipher from key (see above) plus algorithm name and initialization vector (stored in unencrypted header at beginning of encrypted file).
                    // Create decrypting input stream.
                    using (SymmetricAlgorithm cipher = Cipher.Create(encryptedFileHeader.CipherAlgorithm))
                    using (ICryptoTransform decryptor = cipher.CreateDecryptor(key, encryptedFileHeader.InitializationVector))
                    using (CryptoStream cryptoStream = new CryptoStream(inputFileStream, decryptor, CryptoStreamMode.Read))
                    using (FileStream outputFileStream = File.Open(outputFilename, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                    {
                        // To limit memory usage, repeatedly read a small block from input stream and write it to the decrypted output stream.
                        byte[] buffer = new byte[cipher.BlockSize];
                        int bytesRead;
                        while ((bytesRead = await cryptoStream.ReadAsync(buffer, 0, buffer.Length)) > 0) await outputFileStream.WriteAsync(buffer, 0, bytesRead);
                    }
                }
            }
            TimeSpan encryptionDuration = _stopwatch.Elapsed - encryptionStart;
            ThreadsafeConsole.WriteLine($"Wrote decrypted file to {outputFilename}.");
            ThreadsafeConsole.WriteLine($"Decryption took {encryptionDuration.TotalSeconds.ToString(_elapsedSecondsFormat)} seconds.");
        }


        // Encryption arguments = -i "C:\Users\Erik\Temp\Test.pdf" -o encrypt -c aescng -kd rfc2898 -kdi 1000 -kl 32 -sl 16
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
                    default:
                        throw new ArgumentException($"{argumentName} not supported.");
                }
            }
            // Validate arguments.
            if (string.IsNullOrEmpty(encryptedFileHeader.Filename)) throw new ArgumentException("Specify an input path via -i argument.");
            // ReSharper disable once ConvertIfStatementToSwitchStatement
            if (encryptedFileHeader.Operation == Operation.Unknown) throw new ArgumentException("Specify an operation via -o argument.");
            if (encryptedFileHeader.Operation == Operation.Encrypt)
            {
                if (encryptedFileHeader.CipherAlgorithm is null) throw new ArgumentException("Specify a cipher via -c argument.");
                if (encryptedFileHeader.KeyDerivationAlgorithm is null) throw new ArgumentException("Specify a key derivation algorithm via -kd argument.");
                if (encryptedFileHeader.KeyDerivationIterations <= 0) throw new ArgumentException("Specify key derivation iterations via -kdi argument");
                if (encryptedFileHeader.KeyLength <= 0) throw new ArgumentException("Specify a key length in bytes via -kl argument.");
                if (encryptedFileHeader.Salt.Length <= 0) throw new ArgumentException("Specify a salt length via -sl argument.");
            }
            return encryptedFileHeader;
        }
    }
}
