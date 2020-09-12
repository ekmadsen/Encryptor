using System;
using System.Security.Cryptography;


namespace ErikTheCoder.Encryptor
{
    public static class KeyDerivation
    {
        public static DeriveBytes Create(string Name, string Password, byte[] Salt, int Iterations)
        {
            return Name?.ToLower() switch
            {
                "pdb" => new PasswordDeriveBytes(Password, Salt) {IterationCount = Iterations},
                "rfc2898" => new Rfc2898DeriveBytes(Password, Salt, Iterations),
                _ => throw new ArgumentException($"{Name} key derivation not supported.")
            };
        }
    }
}
