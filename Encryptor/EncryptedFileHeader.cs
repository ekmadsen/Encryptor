using JetBrains.Annotations;

namespace ErikTheCoder.Encryptor
{
    public class EncryptedFileHeader
    {
        public string Filename {[UsedImplicitly] get; set; }
        public string KeyDerivationAlgorithm { [UsedImplicitly] get; set; }
        public int KeyLength { [UsedImplicitly] get; set; }
        public byte[] Salt { [UsedImplicitly] get; set; }
        public string CipherAlgorithm { [UsedImplicitly] get; set; }
        public byte[] InitializationVector { [UsedImplicitly] get; set; }
    }
}
