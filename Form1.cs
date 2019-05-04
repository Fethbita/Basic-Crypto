using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Forms;

namespace BIL4106_HW
{
    public partial class Form1 : Form
    {
        private string filename;
        private FileStream stream = null;
        private RSACryptoServiceProvider publicKey = null;
        private RSACryptoServiceProvider privateKey = null;

        public Form1()
        {
            InitializeComponent();
            toggleControls();
        }

        private void hash_btn_Click(object sender, EventArgs e)
        {
            disableControls();
            backgroundWorker1.RunWorkerAsync();
        }
        private void doit_btn_Click(object sender, EventArgs e)
        {
            if (sign_radio.Checked)
            {
                string signFileName = null;
                saveFileDialog1.Title = "Save signature";
                saveFileDialog1.DefaultExt = "sign";
                if (saveFileDialog1.ShowDialog() == DialogResult.OK && saveFileDialog1.FileName != "")
                {
                    signFileName = saveFileDialog1.FileName;

                    disableControls();
                    backgroundWorker2.RunWorkerAsync(signFileName);
                }
                resetSaveFileDialog();
            }
            else if (encrypt_radio.Checked)
            {
                string encryptedFileName = null;
                saveFileDialog1.Title = "Encrpted file to save";
                saveFileDialog1.DefaultExt = "aes";
                if (saveFileDialog1.ShowDialog() == DialogResult.OK && saveFileDialog1.FileName != "")
                {
                    encryptedFileName = saveFileDialog1.FileName;

                    disableControls();
                    backgroundWorker3.RunWorkerAsync(encryptedFileName);
                }
                resetSaveFileDialog();
            }
            else if (signencrypt_radio.Checked)
            {
                // Why sign and encrypt but not encrypt and sign
                // https://crypto.stackexchange.com/a/5466
                string encryptedFileName = null;
                saveFileDialog1.Title = "Encrpted & Signed file to save";
                saveFileDialog1.DefaultExt = "signed-aes";
                if (saveFileDialog1.ShowDialog() == DialogResult.OK && saveFileDialog1.FileName != "")
                {
                    encryptedFileName = saveFileDialog1.FileName;

                    disableControls();
                    backgroundWorker4.RunWorkerAsync(encryptedFileName);
                }
                resetSaveFileDialog();
            }
        }
        private void doitreverse_btn_Click(object sender, EventArgs e)
        {
            if (verify_radio.Checked)
            {
                string signFileName = null;
                openFileDialog1.Title = "Open signature file";
                if (openFileDialog1.ShowDialog() == DialogResult.OK)
                {
                    signFileName = openFileDialog1.FileName;

                    disableControls();
                    backgroundWorker5.RunWorkerAsync(signFileName);
                }
                resetOpenFileDialog();
            }
            else if (decrypt_radio.Checked)
            {
                string decryptedFileName = null;
                saveFileDialog1.Title = "Decrypted File to save";
                if (saveFileDialog1.ShowDialog() == DialogResult.OK && saveFileDialog1.FileName != "")
                {
                    decryptedFileName = saveFileDialog1.FileName;

                    disableControls();
                    backgroundWorker6.RunWorkerAsync(decryptedFileName);
                }
                resetSaveFileDialog();
            }
            else if (decryptverify_radio.Checked)
            {
                // Why sign and encrypt but not encrypt and sign
                // https://crypto.stackexchange.com/a/5466
                string decryptedFileName = null;
                saveFileDialog1.Title = "Decrypted File to save";
                if (saveFileDialog1.ShowDialog() == DialogResult.OK && saveFileDialog1.FileName != "")
                {
                    decryptedFileName = saveFileDialog1.FileName;

                    disableControls();
                    backgroundWorker7.RunWorkerAsync(decryptedFileName);
                }
                resetSaveFileDialog();
            }
        }
        private void createToolStripMenuItem_Click(object sender, EventArgs e)
        {
            saveFileDialog1.Title = "Save public-private key pairs";
            saveFileDialog1.FileName = "keys";
            if (saveFileDialog1.ShowDialog() == DialogResult.OK && saveFileDialog1.FileName != "")
            {
                Utilities.SaveKeys(saveFileDialog1.FileName);
            }
            resetSaveFileDialog();
        }
        private void openFileToolStripMenuItem_Click(object sender, EventArgs e)
        {
            openFileDialog1.Title = "Open File";
            if (openFileDialog1.ShowDialog() == DialogResult.OK)
            {
                if (stream != null)
                {
                    stream.Dispose();
                    stream = null;
                }
                stream = new FileStream(openFileDialog1.FileName, FileMode.Open, FileAccess.Read, FileShare.None);
                filename = openFileDialog1.FileName;
                label2.Text = filename;
            }
            resetOpenFileDialog();
            toggleControls();
        }
        private void openPublicKeyToolStripMenuItem_Click(object sender, EventArgs e)
        {
            if (publicKey != null)
            {
                publicKey.Dispose();
                publicKey = null;
            }

            openFileDialog1.Title = "Open Public Key";
            if (openFileDialog1.ShowDialog() == DialogResult.OK)
            {
                try
                {
                    string publicKeyFile;
                    using (var streamReader = new StreamReader(openFileDialog1.FileName, Encoding.UTF8))
                    {
                        publicKeyFile = streamReader.ReadToEnd();
                    }
                    publicKey = RSAKeys.ImportPublicKey(publicKeyFile);
                }
                catch (Exception ex)
                {
                    publicKey = null;
                    resetOpenFileDialog();
                    MessageBox.Show("Error while importing Public Key" + Environment.NewLine + ex.Message);
                    return;
                }
                label4.Text = openFileDialog1.FileName;
            }
            resetOpenFileDialog();
            toggleControls();
        }
        private void openPrivateKeyToolStripMenuItem_Click(object sender, EventArgs e)
        {
            if (privateKey != null)
            {
                privateKey.Dispose();
                privateKey = null;
            }

            openFileDialog1.Title = "Open Private Key";
            if (openFileDialog1.ShowDialog() == DialogResult.OK)
            {
                try
                {
                    string privateKeyFile;
                    using (var streamReader = new StreamReader(openFileDialog1.FileName, Encoding.UTF8))
                    {
                        privateKeyFile = streamReader.ReadToEnd();
                    }
                    privateKey = RSAKeys.ImportPrivateKey(privateKeyFile);
                }
                catch (Exception ex)
                {
                    privateKey = null;
                    resetOpenFileDialog();
                    MessageBox.Show("Error while importing Private Key" + Environment.NewLine + ex.Message);
                    return;
                }
                label6.Text = openFileDialog1.FileName;
            }
            resetOpenFileDialog();
            toggleControls();
        }
        private void helpToolStripMenuItem_Click(object sender, EventArgs e)
        {
            MessageBox.Show("To sign use sender's private key" + Environment.NewLine +
                "To encrypt use receiver's public key" + Environment.NewLine +
                "To sign and encrypt use sender's private & receiver's public key" + Environment.NewLine + Environment.NewLine +
                "To verify signature use sender's public key" + Environment.NewLine +
                "To decrypt use receiver's private key" + Environment.NewLine +
                "To decrypt and verify use sender's public & receiver's private key" + Environment.NewLine, "Help");
        }
        private void toggleControls()
        {
            closefile_btn.Enabled = false;
            closepublic_btn.Enabled = false;
            closeprivate_btn.Enabled = false;

            groupBox1.Enabled = false;
            sign_radio.Enabled = false;
            encrypt_radio.Enabled = false;
            signencrypt_radio.Enabled = false;
            doit_btn.Enabled = false;

            verify_radio.Enabled = false;
            decrypt_radio.Enabled = false;
            decryptverify_radio.Enabled = false;
            doitreverse_btn.Enabled = false;

            if (!string.IsNullOrEmpty(filename))
            {
                closefile_btn.Enabled = true;
                groupBox1.Enabled = true;
                if (publicKey != null)
                {
                    closepublic_btn.Enabled = true;

                    encrypt_radio.Enabled = true;
                    encrypt_radio.Checked = true;
                    doit_btn.Enabled = true;

                    verify_radio.Enabled = true;
                    verify_radio.Checked = true;
                    doitreverse_btn.Enabled = true;
                }
                if (privateKey != null)
                {
                    closeprivate_btn.Enabled = true;

                    sign_radio.Enabled = true;
                    sign_radio.Checked = true;
                    doit_btn.Enabled = true;

                    decrypt_radio.Enabled = true;
                    decrypt_radio.Checked = true;
                    doitreverse_btn.Enabled = true;
                }
                if (publicKey != null && privateKey != null)
                {
                    signencrypt_radio.Enabled = true;
                    decryptverify_radio.Enabled = true;
                }
            }
            else
            {
                if (publicKey != null)
                {
                    closepublic_btn.Enabled = true;
                }
                if (privateKey != null)
                {
                    closeprivate_btn.Enabled = true;
                }
            }
        }
        private void closefile_btn_Click(object sender, EventArgs e)
        {
            if (stream != null)
            {
                filename = "";
                label2.Text = filename;
                stream.Dispose();
                stream = null;
            }
            toggleControls();
        }
        private void closepublic_btn_Click(object sender, EventArgs e)
        {
            if (publicKey != null)
            {
                label4.Text = "";
                publicKey.Dispose();
                publicKey = null;
            }
            toggleControls();
        }
        private void closeprivate_btn_Click(object sender, EventArgs e)
        {
            if (privateKey != null)
            {
                label6.Text = "";
                privateKey.Dispose();
                privateKey = null;
            }
            toggleControls();
        }
        private void Form1_FormClosed(object sender, FormClosedEventArgs e)
        {
            if (stream != null)
            {
                stream.Dispose();
                stream = null;
            }
            if (publicKey != null)
            {
                publicKey.Dispose();
                publicKey = null;
            }
            if (privateKey != null)
            {
                privateKey.Dispose();
                privateKey = null;
            }
        }
        private void resetSaveFileDialog()
        {
            saveFileDialog1.Reset();
            saveFileDialog1.AddExtension = true;
            saveFileDialog1.InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
        }
        private void resetOpenFileDialog()
        {
            openFileDialog1.Reset();
            openFileDialog1.InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Desktop); ;
        }
        private void disableControls()
        {
            menuStrip1.Enabled = false;

            closefile_btn.Enabled = false;
            closepublic_btn.Enabled = false;
            closeprivate_btn.Enabled = false;

            groupBox1.Enabled = false;
            sign_radio.Enabled = false;
            encrypt_radio.Enabled = false;
            signencrypt_radio.Enabled = false;
            doit_btn.Enabled = false;

            verify_radio.Enabled = false;
            decrypt_radio.Enabled = false;
            decryptverify_radio.Enabled = false;
            doitreverse_btn.Enabled = false;
        }
    }
}