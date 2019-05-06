using System;
using System.Security.Cryptography;


namespace ErikTheCoder.Encryptor
{
    public static class KeyDerivation
    {
        private const string _pdb = "pdb";
        private const string _rfc2898 = "rfc2898";



        public static DeriveBytes Create(string Name, string Password, byte[] Salt, int Iterations)
        {
            switch (Name?.ToLower())
            {
                case _pdb:
                    return new PasswordDeriveBytes(Password, Salt) {IterationCount = Iterations};
                case _rfc2898:
                    return new Rfc2898DeriveBytes(Password, Salt, Iterations);
                default:
                    throw new ArgumentException($"{Name} key derivation not supported.");
            }
        }


        public static string GetName(DeriveBytes KeyDerivation)
        {
            string fullTypeName = KeyDerivation.GetType().FullName;
            switch (fullTypeName)
            {
                case "System.Security.Cryptography.PasswordDeriveBytes":
                    return _pdb;
                case "System.Security.Cryptography.Rfc2898DeriveBytes":
                    return _rfc2898;
                default:
                    throw new ArgumentException($"{fullTypeName} class not supported.");
            }
        }
    }
}
