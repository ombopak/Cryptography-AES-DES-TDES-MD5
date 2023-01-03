using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

namespace Cryptography
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        int keySize = 128;
        public MainWindow()
        {
            InitializeComponent();
        }

        private void btnAESEncrypt_Click(object sender, RoutedEventArgs e)
        {
            // Get the plaintext and key from the text boxes
            string plaintext = plainTextAES.Text;
            string key = keyTextAES.Text;

            // Convert the plaintext and key to bytes
            byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
            byte[] keyBytes = Encoding.UTF8.GetBytes(key);

            // Padding the key to 16 bytes if it is shorter 
            if (keyBytes.Length < 16)
            {
                Array.Resize(ref keyBytes, 16);
            }
            if (keyBytes.Length > 16)
            {
                Array.Resize(ref keyBytes, 16);
            }

            // Use the AES algorithm to encrypt the plaintext
            Aes aes = Aes.Create();
            aes.KeySize = keySize;
            aes.Key = keyBytes;
            aes.IV = keyBytes;
            ICryptoTransform transform = aes.CreateEncryptor();
            byte[] ciphertextBytes = transform.TransformFinalBlock(plaintextBytes, 0, plaintextBytes.Length);


            // Convert the ciphertext to a base64-encoded string
           string ciphertext = Convert.ToBase64String(ciphertextBytes);

            string asd = BitConverter.ToString(ciphertextBytes).Replace("-", "").ToLower();
           


            // Display the ciphertext in the CiphertextTextBox
            cipherTextAES.Text = ciphertext;

        }

        private void btnAESDecrypt_Click(object sender, RoutedEventArgs e)
        {
            // Get the ciphertext and key from the text boxes
            string ciphertext = cipherTextAES.Text;
            string key = keyTextAES.Text;

            // Convert the ciphertext and key to bytes
            byte[] ciphertextBytes = Convert.FromBase64String(ciphertext);
            byte[] keyBytes = Encoding.UTF8.GetBytes(key);

            // Padding the key to 16 bytes if it is shorter
            if (keyBytes.Length < 16)
            {
                Array.Resize(ref keyBytes, 16);
            }
            if (keyBytes.Length > 16)
            {
                Array.Resize(ref keyBytes, 16);
            }

            // Use the AES algorithm to decrypt the ciphertext
            Aes aes = Aes.Create();
            aes.Key = keyBytes;
            aes.IV = keyBytes;
            ICryptoTransform transform = aes.CreateDecryptor();
            byte[] plaintextBytes = transform.TransformFinalBlock(ciphertextBytes, 0, ciphertextBytes.Length);

            // Convert the plaintext to a string
            string plaintext = Encoding.UTF8.GetString(plaintextBytes);

            // Display the plaintext in the PlaintextTextBox
            decryptChiperTextAES.Text = plaintext;
        }

        private void btnDESEncrypt_Click(object sender, RoutedEventArgs e)
        {
            // Get the plaintext and key from the text boxes
            string plaintext = plainTextDES.Text;
            string key = keyTextDES.Text;

            // Convert the plaintext and key to bytes
            byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
            byte[] keyBytes = Encoding.UTF8.GetBytes(key);

            // Padding the key to 8 bytes if it is shorter ||
            if (keyBytes.Length < 8)
            {
                Array.Resize(ref keyBytes, 8);
            }
            if (keyBytes.Length > 8)
            {
                Array.Resize(ref keyBytes, 8);
            }

            Debug.WriteLine(plaintextBytes + "THIS IS IT");


            // Use the DES algorithm to encrypt the plaintext
            DES des = DES.Create();
            des.Key = keyBytes;
            des.IV = keyBytes;
            ICryptoTransform transform = des.CreateEncryptor();
            byte[] ciphertextBytes = transform.TransformFinalBlock(plaintextBytes, 0, plaintextBytes.Length);

            

            string asd = BitConverter.ToString(ciphertextBytes).Replace("-", "").ToLower();
            Debug.WriteLine(asd);

            // Convert the ciphertext to a base64-encoded string
            string ciphertext = Convert.ToBase64String(ciphertextBytes);

            // Display the ciphertext in the CiphertextTextBox
            cipherTextDES.Text = ciphertext;
        }

        private void btnDESDecrypt_Click(object sender, RoutedEventArgs e)
        {
            // Get the ciphertext and key from the text boxes
            string ciphertext = cipherTextDES.Text;
            string key = keyTextDES.Text;

            // Convert the ciphertext and key to bytes
            byte[] ciphertextBytes = Convert.FromBase64String(ciphertext);
            byte[] keyBytes = Encoding.UTF8.GetBytes(key);

            //USING PADDING
            if (keyBytes.Length < 8)
            {
                Array.Resize(ref keyBytes, 8);
            }
            if (keyBytes.Length > 8)
            {
                Array.Resize(ref keyBytes, 8);
            }

            // Use the DES algorithm to decrypt the ciphertext
            DES des = DES.Create();
            des.Key = keyBytes;
            des.IV = keyBytes;
            ICryptoTransform transform = des.CreateDecryptor();
            byte[] plaintextBytes = transform.TransformFinalBlock(ciphertextBytes, 0, ciphertextBytes.Length);

            // Convert the plaintext to a string
            string plaintext = Encoding.UTF8.GetString(plaintextBytes);

            // Display the plaintext in the PlaintextTextBox
            decryptChiperTextDES.Text = plaintext;
        }

        private void btnTDESEncrypt_Click(object sender, RoutedEventArgs e)
        {
            // Get the plaintext and key from the text boxes
            string plaintext = plainTextTDES.Text;
            string key = keyTextTDES.Text;

            // Convert the plaintext and key to bytes
            byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
            byte[] keyBytes = Encoding.UTF8.GetBytes(key);

            //USING PADDING
            if (keyBytes.Length < 24)
            {
                Array.Resize(ref keyBytes, 24);
            }
            if (keyBytes.Length > 24)
            {
                Array.Resize(ref keyBytes, 24);
            }

            // Use the TripleDES algorithm to encrypt the plaintext
            TripleDES tdes = TripleDES.Create();
            tdes.Key = keyBytes;

            //USING PADDING
            if (keyBytes.Length > 8)
            {
                Array.Resize(ref keyBytes, 8);
            }

            tdes.IV = keyBytes;
            ICryptoTransform transform = tdes.CreateEncryptor();
            byte[] ciphertextBytes = transform.TransformFinalBlock(plaintextBytes, 0, plaintextBytes.Length);

            // Convert the ciphertext to a base64-encoded string
            string ciphertext = Convert.ToBase64String(ciphertextBytes);

            // Display the ciphertext in the CiphertextTextBox
            txtTDESEncrypt.Text = ciphertext;
        }

        private void btnTDESDecrypt_Click(object sender, RoutedEventArgs e)
        {
            // Get the ciphertext and key from the text boxes
            string ciphertext = txtTDESEncrypt.Text;
            string key = keyTextTDES.Text;

            // Convert the ciphertext and key to bytes
            byte[] ciphertextBytes = Convert.FromBase64String(ciphertext);
            byte[] keyBytes = Encoding.UTF8.GetBytes(key);

            //USING PADDING
            if (keyBytes.Length < 24)
            {
                Array.Resize(ref keyBytes, 24);
            }
            if (keyBytes.Length > 24)
            {
                Array.Resize(ref keyBytes, 24);
            }

            // Use the TripleDES algorithm to decrypt the ciphertext
            TripleDES tdes = TripleDES.Create();

            tdes.Key = keyBytes;

            //USING PADDING
            if (keyBytes.Length > 8)
            {
                Array.Resize(ref keyBytes, 8);
            }

            tdes.IV = keyBytes;
            ICryptoTransform transform = tdes.CreateDecryptor();
            byte[] plaintextBytes = transform.TransformFinalBlock(ciphertextBytes, 0, ciphertextBytes.Length);

            // Convert the plaintext to a string
            string plaintext = Encoding.UTF8.GetString(plaintextBytes);

            // Display the plaintext in the PlaintextTextBox
            txtTDESDecrypt.Text = plaintext;
        }

       

        private void BtnMd5Hash_Click(object sender, RoutedEventArgs e)
        {
            // Get the input string from the text box
            string input = plainTextMD5.Text;
                //.Trim().Replace(" ","");
            string salt = "12093jksdfjsdkjf";

            // Using Salt
            string inputsalt = input + salt;

            // Convert the input string to a byte array
            byte[] inputBytes = Encoding.UTF8.GetBytes(input);

            // Compute the hash of the input
            MD5 md5 = MD5.Create();
            byte[] hashBytes = md5.ComputeHash(inputBytes);

            // Compute the hash of the input
            //SHA1 sha1 = SHA1.Create();
            //byte[] hashBytes = sha1.ComputeHash(inputBytes);

            // Compute the hash of the input
            //SHA256 sha256 = SHA256.Create();
            //byte[] hashBytes = sha256.ComputeHash(inputBytes);

            // Convert the hash to a base64-encoded string
            //string hash = Convert.ToBase64String(hashBytes);
            string hash = BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
            // Display the hash in the HashTextBox
            hashMD5Text.Text = hash;
        }
    }
}
