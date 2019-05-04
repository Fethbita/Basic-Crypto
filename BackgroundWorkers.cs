using System;
using System.Security.Cryptography;
using System.Windows.Forms;

namespace BIL4106_HW
{
    public partial class Form1 : Form
    {
        private void backgroundWorker_RunWorkerCompleted(object sender, System.ComponentModel.RunWorkerCompletedEventArgs e)
        {
            menuStrip1.Enabled = true;
            toggleControls();
        }
        private void backgroundWorker1_DoWork(object sender, System.ComponentModel.DoWorkEventArgs e)
        {
            for (int i = 0; i < checkedListBox1.Items.Count; i++)
            {
                if (checkedListBox1.GetItemChecked(i))
                {
                    if (i == 0)
                    {
                        this.Invoke((Func<DialogResult>)(() => MessageBox.Show(Utilities.CalculateHash<MD5Cng>(stream), "MD5")));
                    }
                    if (i == 1)
                    {
                        this.Invoke((Func<DialogResult>)(() => MessageBox.Show(Utilities.CalculateHash<RIPEMD160Managed>(stream), "RIPEMD")));
                    }
                    if (i == 2)
                    {
                        this.Invoke((Func<DialogResult>)(() => MessageBox.Show(Utilities.CalculateHash<SHA1Cng>(stream), "SHA-1")));
                    }
                    if (i == 3)
                    {
                        this.Invoke((Func<DialogResult>)(() => MessageBox.Show(Utilities.CalculateHash<SHA256Cng>(stream), "SHA256")));
                    }
                    if (i == 4)
                    {
                        this.Invoke((Func<DialogResult>)(() => MessageBox.Show(Utilities.CalculateHash<SHA384Cng>(stream), "SHA384")));
                    }
                    if (i == 5)
                    {
                        this.Invoke((Func<DialogResult>)(() => MessageBox.Show(Utilities.CalculateHash<SHA512Cng>(stream), "SHA512")));
                    }
                }
            }
        }
        private void backgroundWorker2_DoWork(object sender, System.ComponentModel.DoWorkEventArgs e)
        {
            string signFileName = e.Argument as string;

            Utilities.Sign(privateKey, stream, signFileName);
        }
        private void backgroundWorker3_DoWork(object sender, System.ComponentModel.DoWorkEventArgs e)
        {
            string encryptedFileName = e.Argument as string;

            Utilities.EncryptAES(publicKey, stream, encryptedFileName);
        }
        private void backgroundWorker4_DoWork(object sender, System.ComponentModel.DoWorkEventArgs e)
        {
            string encryptedFileName = e.Argument as string;

            Utilities.SignAndEncrypt(privateKey, publicKey, stream, encryptedFileName);
        }
        private void backgroundWorker5_DoWork(object sender, System.ComponentModel.DoWorkEventArgs e)
        {
            string signFileName = e.Argument as string;

            Utilities.Verify(publicKey, stream, signFileName);
        }
        private void backgroundWorker6_DoWork(object sender, System.ComponentModel.DoWorkEventArgs e)
        {
            string decryptedFileName = e.Argument as string;

            Utilities.DecryptAES(privateKey, stream, decryptedFileName);

        }
        private void backgroundWorker7_DoWork(object sender, System.ComponentModel.DoWorkEventArgs e)
        {
            string decryptedFileName = e.Argument as string;

            Utilities.DecryptAndVerify(privateKey, publicKey, stream, decryptedFileName);
        }
    }
}
