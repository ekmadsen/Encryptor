using JetBrains.Annotations;

namespace ErikTheCoder.Encryptor
{
    public class EncryptedFileHeader
    {
        public string Filename {get; set; }
        public Operation Operation { get; set; } = Operation.Unknown;
        public string KeyDerivationAlgorithm { get; set; }
        public int KeyDerivationIterations { get; set; }
        public int KeyLength { get; set; }
        public byte[] Salt { get; set; }
        public string CipherAlgorithm { get; set; }
        public byte[] InitializationVector { get; set; }


        public EncryptedFileHeader()
        {
            Salt = new byte[0];
            InitializationVector = new byte[0];
        }
    }
}
