using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

// Independent Windows BCrypt calls matching the client imports, synthetic keys only.
internal static class NativeCngFixtures
{
    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)] private static extern int BCryptOpenAlgorithmProvider(out IntPtr handle, string algorithm, string implementation, int flags);
    [DllImport("bcrypt.dll")] private static extern int BCryptCloseAlgorithmProvider(IntPtr handle, int flags);
    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)] private static extern int BCryptImportKeyPair(IntPtr algorithm, IntPtr importKey, string format, out IntPtr key, byte[] blob, int length, int flags);
    [DllImport("bcrypt.dll")] private static extern int BCryptDestroyKey(IntPtr key);
    [DllImport("bcrypt.dll")] private static extern int BCryptSecretAgreement(IntPtr privateKey, IntPtr publicKey, out IntPtr secret, int flags);
    [DllImport("bcrypt.dll")] private static extern int BCryptDestroySecret(IntPtr secret);
    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)] private static extern int BCryptDeriveKey(IntPtr secret, string kdf, IntPtr parameters, byte[] output, int length, out int written, int flags);
    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)] private static extern int BCryptSetProperty(IntPtr handle, string property, byte[] input, int length, int flags);
    [DllImport("bcrypt.dll")] private static extern int BCryptGenerateSymmetricKey(IntPtr algorithm, out IntPtr key, IntPtr keyObject, int objectLength, byte[] secret, int secretLength, int flags);
    [DllImport("bcrypt.dll")] private static extern int BCryptEncrypt(IntPtr key, byte[] input, int inputLength, IntPtr padding, byte[] iv, int ivLength, byte[] output, int outputLength, out int written, int flags);
    [DllImport("bcrypt.dll")] private static extern int BCryptDecrypt(IntPtr key, byte[] input, int inputLength, IntPtr padding, byte[] iv, int ivLength, byte[] output, int outputLength, out int written, int flags);

    private static void Check(int status)
    {
        if (status != 0) throw new CryptographicException("Synthetic BCrypt fixture failed, status " + status.ToString("X8"));
    }

    internal static byte[] Derive(ECDiffieHellman client, byte[] serverBlob)
    {
        IntPtr algorithm = IntPtr.Zero, privateKey = IntPtr.Zero, publicKey = IntPtr.Zero, secret = IntPtr.Zero;
        ECParameters material = client.ExportParameters(true);
        byte[] privateBlob = [0x45, 0x43, 0x4b, 0x32, 32, 0, 0, 0, .. material.Q.X!, .. material.Q.Y!, .. material.D!];
        byte[] derived = new byte[16];
        bool success = false;
        try
        {
            Check(BCryptOpenAlgorithmProvider(out algorithm, "ECDH_P256", null, 0));
            Check(BCryptImportKeyPair(algorithm, IntPtr.Zero, "ECCPRIVATEBLOB", out privateKey, privateBlob, privateBlob.Length, 0));
            Check(BCryptImportKeyPair(algorithm, IntPtr.Zero, "ECCPUBLICBLOB", out publicKey, serverBlob, serverBlob.Length, 0));
            Check(BCryptSecretAgreement(privateKey, publicKey, out secret, 0));
            // Exact native call shape: HASH, NULL parameter list, 16 output bytes.
            Check(BCryptDeriveKey(secret, "HASH", IntPtr.Zero, derived, derived.Length, out int written, 0));
            if (written != 16) throw new CryptographicException("Unexpected native KDF result length");
            success = true;
            return derived;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(privateBlob);
            CryptographicOperations.ZeroMemory(material.D!);
            if (!success) CryptographicOperations.ZeroMemory(derived);
            try { if (secret != IntPtr.Zero) Check(BCryptDestroySecret(secret)); }
            finally
            {
                try { if (publicKey != IntPtr.Zero) Check(BCryptDestroyKey(publicKey)); }
                finally
                {
                    try { if (privateKey != IntPtr.Zero) Check(BCryptDestroyKey(privateKey)); }
                    finally { if (algorithm != IntPtr.Zero) Check(BCryptCloseAlgorithmProvider(algorithm, 0)); }
                }
            }
        }
    }

    internal static byte[] Encrypt(byte[] plaintext, byte[] key, byte[] iv) => Transform(true, plaintext, key, iv);
    internal static byte[] Decrypt(byte[] ciphertext, byte[] key, byte[] iv) => Transform(false, ciphertext, key, iv);

    private static byte[] Transform(bool encrypt, byte[] input, byte[] keyBytes, byte[] ivBytes)
    {
        IntPtr algorithm = IntPtr.Zero, key = IntPtr.Zero;
        byte[] iv = (byte[])ivBytes.Clone();
        try
        {
            Check(BCryptOpenAlgorithmProvider(out algorithm, "AES", null, 0));
            byte[] mode = Encoding.Unicode.GetBytes("ChainingModeCBC\0");
            Check(BCryptSetProperty(algorithm, "ChainingMode", mode, mode.Length, 0));
            // Modern CNG owns the key-object allocation when this pair is NULL/0.
            Check(BCryptGenerateSymmetricKey(algorithm, out key, IntPtr.Zero, 0, keyBytes, keyBytes.Length, 0));
            int size;
            Check(encrypt ? BCryptEncrypt(key, input, input.Length, IntPtr.Zero, iv, iv.Length, null, 0, out size, 1)
                : BCryptDecrypt(key, input, input.Length, IntPtr.Zero, iv, iv.Length, null, 0, out size, 1));
            byte[] output = new byte[size];
            ivBytes.CopyTo(iv, 0);
            try
            {
                int written;
                Check(encrypt ? BCryptEncrypt(key, input, input.Length, IntPtr.Zero, iv, iv.Length, output, output.Length, out written, 1)
                    : BCryptDecrypt(key, input, input.Length, IntPtr.Zero, iv, iv.Length, output, output.Length, out written, 1));
                return output.AsSpan(0, written).ToArray();
            }
            finally { CryptographicOperations.ZeroMemory(output); }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(iv);
            try { if (key != IntPtr.Zero) Check(BCryptDestroyKey(key)); }
            finally { if (algorithm != IntPtr.Zero) Check(BCryptCloseAlgorithmProvider(algorithm, 0)); }
        }
    }
}
