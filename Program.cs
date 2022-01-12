using System;
using System.Security.Cryptography;
using Microsoft.Data.Sqlite;
using static HashPass;
using static Key;

char c = '\0';
User? loggedIn = null;
do
{
    using (var connection = new SqliteConnection("Data Source=a.db"))
    using (var command = connection.CreateCommand())
    {
        int res = -1;
        string? username, password, secret;

        Console.WriteLine("Menu:");
        Console.WriteLine("1: Register,");
        Console.WriteLine("2: Login,");
        Console.WriteLine("3: Update account,");
        Console.WriteLine("4: Logout,");
        Console.WriteLine("5: Get Account Info,");
        Console.WriteLine("6: Exit");
        Console.WriteLine("Enter your selection: ");
        string? s = Console.ReadLine();
        s ??= "6";
        c = s[0];

        switch (c)
        {
            case '1':
                if(loggedIn != null){
                    Console.WriteLine("Logged in");
                    break;
                }
                Console.WriteLine("Enter username");
                username = Console.ReadLine();
                Console.WriteLine("Enter password");
                password = Console.ReadLine();
                Console.WriteLine("Enter some secret");
                secret = Console.ReadLine();
                if (username == null || secret == null || password == null)
                {
                    Console.WriteLine("error: Null input");
                    break;
                }
                var u = new User(username, secret, password);
                connection.Open();
                command.CommandText = @"
				insert into users (
						user_guid,
						user_name,
						cleartext,
						ciphertext,
						iv,
						passhash)
				values (
						$user_guid,
						$user_name,
						$cleartext,
						$ciphertext,
						$iv,
						$passhash
						)";

                command.Parameters.AddWithValue("$user_guid", u.UserGuid);
                command.Parameters.AddWithValue("$user_name", u.UserName);
                command.Parameters.AddWithValue("$cleartext", u.ClearText);
                command.Parameters.AddWithValue("$ciphertext", u.CipherText);
                command.Parameters.AddWithValue("$iv", u.IV);
                command.Parameters.AddWithValue("$passhash", u.PassHash);
                res = command.ExecuteNonQuery();
                if (res > 0)
                    Console.WriteLine("Record inserted successfully");
                else
                    Console.WriteLine("Some Error Occurred");
                connection.Close();
                break;

            case '2':
                if (loggedIn != null)
                {
                    Console.WriteLine("already logged in!");
                    break;
                }
                Console.WriteLine("Enter username");
                username = Console.ReadLine();
                Console.WriteLine("Enter password");
                password = Console.ReadLine();
                if (username == null || password == null)
                {
                    Console.WriteLine("error: Null input");
                    break;
                }
                command.CommandText = @"
                SELECT user_guid, cleartext, ciphertext, iv, passhash FROM users WHERE user_name=$user_name
                ";
                command.Parameters.AddWithValue("$user_name", username);
                connection.Open();
                using (SqliteDataReader reader = command.ExecuteReader())
                {
                    if (!reader.HasRows)
                    {
                        Console.WriteLine("Has no rows");
                        break;
                    }
                    if (reader.FieldCount != 5)
                    {
                        Console.WriteLine("Incorrect schema");
                    }
                    reader.Read();
                    var passhash = reader.GetString(4);
                    var salt = getSalt(passhash);
                    if (hashPass(Convert.FromHexString(salt), password) != passhash)
                    {
                        Console.WriteLine("bad password");
                        break;
                    }
                    loggedIn = new User
                    {
                        UserName = username,
                        IV = reader.GetString(3),
                        PassHash = passhash,
                        ClearText = reader.GetString(1),
                        CipherText = reader.GetString(2),
                        UserGuid = Guid.Parse(reader.GetString(0))
                    };
                }
                Console.WriteLine("Logged in as");
                Console.WriteLine(loggedIn);
                break;

            case '3':
                if(loggedIn == null){
                    Console.WriteLine("Not logged in");
                    break;
                }
                Console.WriteLine("Enter a new secret");
                secret = Console.ReadLine();
                if(secret == null){
                    Console.WriteLine("secret cannot be empty");
                    break;
                }
                loggedIn = new User(loggedIn, secret);
                connection.Open();
                command.CommandText = @"
                UPDATE users
                SET cleartext = $cleartext, ciphertext = $ciphertext
                WHERE user_guid = $user_guid
                ";
                command.Parameters.AddWithValue("$cleartext", loggedIn.ClearText);
                command.Parameters.AddWithValue("$ciphertext", loggedIn.CipherText);
                command.Parameters.AddWithValue("$user_guid", loggedIn.UserGuid);
                res = command.ExecuteNonQuery();
                if(res > 0){
                    Console.WriteLine("Success. New value:");
                    Console.WriteLine(loggedIn);
                }else{
                    Console.WriteLine("Some error occurred");
                }
                break;

            case '4':
                loggedIn = null;
                break;
            case '5':
                if(loggedIn == null){
                    Console.WriteLine("Not logged in");
                    break;
                }
                Console.WriteLine("Your account is ");
                Console.WriteLine(loggedIn);
                Console.WriteLine("Your secret is ");
                Console.WriteLine(loggedIn.Secret);
                break;
            default:
                c = '6'; break;
        }
    }
} while (c != '6');
public static class Key
{
    public static byte[] key = {
    (byte) 33,
    (byte) 40,
    (byte) 212,
    (byte) 209,
    (byte) 219,
    (byte) 205,
    (byte) 88,
    (byte) 100,
    (byte) 20,
    (byte) 23,
    (byte) 131,
    (byte) 149,
    (byte) 104,
    (byte) 200,
    (byte) 215,
    (byte) 17,
    (byte) 36,
    (byte) 102,
    (byte) 106,
    (byte) 19,
    (byte) 165,
    (byte) 234,
    (byte) 163,
    (byte) 139,
    (byte) 133,
    (byte) 63,
    (byte) 139,
    (byte) 249,
    (byte) 224,
    (byte) 41,
    (byte) 186,
    (byte) 209,
};
}
public class User
{
    public User(){}
    public User(User user, string secret):this(user) {
        ClearText = secret;
        AesEncrypt(secret);
    }
    public User(User user)
    {
        UserGuid = user.UserGuid;
        UserName = user.UserName;
        ClearText = user.ClearText;
        CipherText = user.CipherText;
        IV = user.IV;
        PassHash = user.PassHash;
    }
    public User(string username, string secret, string password)
    {
        Console.WriteLine("Creating user");
        UserName = username;
        ClearText = secret;
        using (var aes = Aes.Create())
        {
            aes.Key = key;
            IV = Convert.ToHexString(aes.IV);
            var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
            using (MemoryStream msEncrypt = new MemoryStream())
            {
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                    {
                        swEncrypt.Write(secret);
                    }
                    CipherText = Convert.ToHexString(msEncrypt.ToArray());
                }
            }
        }

        byte[] salt;
        new RNGCryptoServiceProvider().GetBytes(salt = new byte[16]);
        PassHash = hashPass(salt, password);
    }
    public Guid UserGuid { get; set; } = Guid.NewGuid();
    public string UserName { get; set; } = "";
    public string ClearText { get; set; } = "";
    public string CipherText { get; set; } = "";
    public string Secret { get => Decrypt(); }
    private string Decrypt(){
        {
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key;
                aesAlg.IV = Convert.FromHexString(IV);

                // Create a decryptor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new MemoryStream(Convert.FromHexString(CipherText)))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {

                            // Read the decrypted bytes from the decrypting stream
                            // and place them in a string.
                            return srDecrypt.ReadToEnd();
                        }
                    }
                }
            }
        }
    }
    public string IV { get; set; } = "";
    public string PassHash { get; set; } = "";
    private void AesEncrypt(string secret){
        using (var aes = Aes.Create())
        {
            aes.Key = key;
            aes.IV = Convert.FromHexString(IV);
            var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
            using (MemoryStream msEncrypt = new MemoryStream())
            {
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                    {
                        swEncrypt.Write(secret);
                    }
                    CipherText = Convert.ToHexString(msEncrypt.ToArray());
                }
            }
        }
    }
    public override string ToString()
    {
        return $"UserGuid: {UserGuid},\n" +
         $"UserName: {UserName},\n" +
         $"ClearText: {ClearText},\n" +
         $"CipherText: {CipherText},\n" +
         $"IV: {IV},\n" +
         $"PassHash: {PassHash}";
    }
}
public static class HashPass
{
    public static string getSalt(string hexString)
    {
        var hexStringAsArray = Convert.FromHexString(hexString);
        var salt = new byte[16];
        Array.Copy(hexStringAsArray, 0, salt, 0, 16);
        return Convert.ToHexString(salt);
    }
    public static string hashPass(byte[] salt, string password)
    {
        var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 100000);
        var hash = pbkdf2.GetBytes(20);
        var hashBytes = new byte[36];
        Array.Copy(salt, 0, hashBytes, 0, 16);
        Array.Copy(hash, 0, hashBytes, 16, 20);
        return Convert.ToHexString(hashBytes);
    }
}
