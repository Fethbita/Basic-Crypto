using System;

namespace BIL4106_HW
{
    partial class Form1
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            this.components = new System.ComponentModel.Container();
            this.hash_btn = new System.Windows.Forms.Button();
            this.checkedListBox1 = new System.Windows.Forms.CheckedListBox();
            this.openFileDialog1 = new System.Windows.Forms.OpenFileDialog();
            this.menuStrip1 = new System.Windows.Forms.MenuStrip();
            this.fileToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.openToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.openPublicKeyToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.openPrivateKeyToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.createToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.helpToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.label1 = new System.Windows.Forms.Label();
            this.label2 = new System.Windows.Forms.Label();
            this.saveFileDialog1 = new System.Windows.Forms.SaveFileDialog();
            this.signencrypt_radio = new System.Windows.Forms.RadioButton();
            this.encrypt_radio = new System.Windows.Forms.RadioButton();
            this.sign_radio = new System.Windows.Forms.RadioButton();
            this.doit_btn = new System.Windows.Forms.Button();
            this.label4 = new System.Windows.Forms.Label();
            this.label3 = new System.Windows.Forms.Label();
            this.label6 = new System.Windows.Forms.Label();
            this.label5 = new System.Windows.Forms.Label();
            this.closefile_btn = new System.Windows.Forms.Button();
            this.doitreverse_btn = new System.Windows.Forms.Button();
            this.decryptverify_radio = new System.Windows.Forms.RadioButton();
            this.decrypt_radio = new System.Windows.Forms.RadioButton();
            this.verify_radio = new System.Windows.Forms.RadioButton();
            this.closepublic_btn = new System.Windows.Forms.Button();
            this.closeprivate_btn = new System.Windows.Forms.Button();
            this.toolTip1 = new System.Windows.Forms.ToolTip(this.components);
            this.backgroundWorker1 = new System.ComponentModel.BackgroundWorker();
            this.backgroundWorker2 = new System.ComponentModel.BackgroundWorker();
            this.backgroundWorker3 = new System.ComponentModel.BackgroundWorker();
            this.backgroundWorker4 = new System.ComponentModel.BackgroundWorker();
            this.backgroundWorker5 = new System.ComponentModel.BackgroundWorker();
            this.backgroundWorker6 = new System.ComponentModel.BackgroundWorker();
            this.backgroundWorker7 = new System.ComponentModel.BackgroundWorker();
            this.groupBox1 = new System.Windows.Forms.GroupBox();
            this.groupBox2 = new System.Windows.Forms.GroupBox();
            this.groupBox3 = new System.Windows.Forms.GroupBox();
            this.menuStrip1.SuspendLayout();
            this.groupBox1.SuspendLayout();
            this.groupBox2.SuspendLayout();
            this.groupBox3.SuspendLayout();
            this.SuspendLayout();
            // 
            // hash_btn
            // 
            this.hash_btn.Location = new System.Drawing.Point(129, 13);
            this.hash_btn.Name = "hash_btn";
            this.hash_btn.Size = new System.Drawing.Size(95, 96);
            this.hash_btn.TabIndex = 0;
            this.hash_btn.Text = "Hash";
            this.hash_btn.UseVisualStyleBackColor = true;
            this.hash_btn.Click += new System.EventHandler(this.hash_btn_Click);
            // 
            // checkedListBox1
            // 
            this.checkedListBox1.FormattingEnabled = true;
            this.checkedListBox1.Items.AddRange(new object[] {
            "MD5",
            "RIPEMD",
            "SHA-1",
            "SHA256",
            "SHA384",
            "SHA512"});
            this.checkedListBox1.Location = new System.Drawing.Point(4, 14);
            this.checkedListBox1.Name = "checkedListBox1";
            this.checkedListBox1.Size = new System.Drawing.Size(94, 94);
            this.checkedListBox1.TabIndex = 1;
            // 
            // openFileDialog1
            // 
            this.openFileDialog1.InitialDirectory = "D:\\Private\\Desktop";
            // 
            // menuStrip1
            // 
            this.menuStrip1.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.fileToolStripMenuItem,
            this.createToolStripMenuItem,
            this.helpToolStripMenuItem});
            this.menuStrip1.Location = new System.Drawing.Point(0, 0);
            this.menuStrip1.Name = "menuStrip1";
            this.menuStrip1.Size = new System.Drawing.Size(250, 24);
            this.menuStrip1.TabIndex = 2;
            this.menuStrip1.Text = "menuStrip1";
            // 
            // fileToolStripMenuItem
            // 
            this.fileToolStripMenuItem.DropDownItems.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.openToolStripMenuItem,
            this.openPublicKeyToolStripMenuItem,
            this.openPrivateKeyToolStripMenuItem});
            this.fileToolStripMenuItem.Name = "fileToolStripMenuItem";
            this.fileToolStripMenuItem.Size = new System.Drawing.Size(37, 20);
            this.fileToolStripMenuItem.Text = "&File";
            // 
            // openToolStripMenuItem
            // 
            this.openToolStripMenuItem.Name = "openToolStripMenuItem";
            this.openToolStripMenuItem.ShortcutKeyDisplayString = "";
            this.openToolStripMenuItem.ShortcutKeys = ((System.Windows.Forms.Keys)((System.Windows.Forms.Keys.Control | System.Windows.Forms.Keys.O)));
            this.openToolStripMenuItem.Size = new System.Drawing.Size(205, 22);
            this.openToolStripMenuItem.Text = "&Open File";
            this.openToolStripMenuItem.Click += new System.EventHandler(this.openFileToolStripMenuItem_Click);
            // 
            // openPublicKeyToolStripMenuItem
            // 
            this.openPublicKeyToolStripMenuItem.Name = "openPublicKeyToolStripMenuItem";
            this.openPublicKeyToolStripMenuItem.ShortcutKeys = ((System.Windows.Forms.Keys)((System.Windows.Forms.Keys.Control | System.Windows.Forms.Keys.P)));
            this.openPublicKeyToolStripMenuItem.Size = new System.Drawing.Size(205, 22);
            this.openPublicKeyToolStripMenuItem.Text = "Open &Public Key";
            this.openPublicKeyToolStripMenuItem.Click += new System.EventHandler(this.openPublicKeyToolStripMenuItem_Click);
            // 
            // openPrivateKeyToolStripMenuItem
            // 
            this.openPrivateKeyToolStripMenuItem.Name = "openPrivateKeyToolStripMenuItem";
            this.openPrivateKeyToolStripMenuItem.ShortcutKeys = ((System.Windows.Forms.Keys)((System.Windows.Forms.Keys.Control | System.Windows.Forms.Keys.R)));
            this.openPrivateKeyToolStripMenuItem.Size = new System.Drawing.Size(205, 22);
            this.openPrivateKeyToolStripMenuItem.Text = "Open P&rivate Key";
            this.openPrivateKeyToolStripMenuItem.Click += new System.EventHandler(this.openPrivateKeyToolStripMenuItem_Click);
            // 
            // createToolStripMenuItem
            // 
            this.createToolStripMenuItem.Name = "createToolStripMenuItem";
            this.createToolStripMenuItem.ShortcutKeys = ((System.Windows.Forms.Keys)((System.Windows.Forms.Keys.Control | System.Windows.Forms.Keys.C)));
            this.createToolStripMenuItem.Size = new System.Drawing.Size(80, 20);
            this.createToolStripMenuItem.Text = "&Create Keys";
            this.createToolStripMenuItem.Click += new System.EventHandler(this.createToolStripMenuItem_Click);
            // 
            // helpToolStripMenuItem
            // 
            this.helpToolStripMenuItem.Name = "helpToolStripMenuItem";
            this.helpToolStripMenuItem.ShortcutKeys = ((System.Windows.Forms.Keys)((System.Windows.Forms.Keys.Control | System.Windows.Forms.Keys.F1)));
            this.helpToolStripMenuItem.Size = new System.Drawing.Size(44, 20);
            this.helpToolStripMenuItem.Text = "&Help";
            this.helpToolStripMenuItem.Click += new System.EventHandler(this.helpToolStripMenuItem_Click);
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.Location = new System.Drawing.Point(12, 24);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(58, 13);
            this.label1.TabIndex = 3;
            this.label1.Text = "Filename =";
            // 
            // label2
            // 
            this.label2.AutoSize = true;
            this.label2.Location = new System.Drawing.Point(67, 24);
            this.label2.Name = "label2";
            this.label2.Size = new System.Drawing.Size(0, 13);
            this.label2.TabIndex = 4;
            // 
            // saveFileDialog1
            // 
            this.saveFileDialog1.InitialDirectory = "D:\\Private\\Desktop";
            // 
            // signencrypt_radio
            // 
            this.signencrypt_radio.AutoSize = true;
            this.signencrypt_radio.Location = new System.Drawing.Point(5, 61);
            this.signencrypt_radio.Name = "signencrypt_radio";
            this.signencrypt_radio.Size = new System.Drawing.Size(94, 17);
            this.signencrypt_radio.TabIndex = 3;
            this.signencrypt_radio.Text = "Sign && Encrypt";
            this.toolTip1.SetToolTip(this.signencrypt_radio, "Use sender\'s private & receiver\'s public key");
            this.signencrypt_radio.UseVisualStyleBackColor = true;
            // 
            // encrypt_radio
            // 
            this.encrypt_radio.AutoSize = true;
            this.encrypt_radio.Location = new System.Drawing.Point(5, 38);
            this.encrypt_radio.Name = "encrypt_radio";
            this.encrypt_radio.Size = new System.Drawing.Size(61, 17);
            this.encrypt_radio.TabIndex = 2;
            this.encrypt_radio.Text = "Encrypt";
            this.toolTip1.SetToolTip(this.encrypt_radio, "Use receiver\'s public key");
            this.encrypt_radio.UseVisualStyleBackColor = true;
            // 
            // sign_radio
            // 
            this.sign_radio.AutoSize = true;
            this.sign_radio.Checked = true;
            this.sign_radio.Location = new System.Drawing.Point(5, 15);
            this.sign_radio.Name = "sign_radio";
            this.sign_radio.Size = new System.Drawing.Size(95, 17);
            this.sign_radio.TabIndex = 1;
            this.sign_radio.TabStop = true;
            this.sign_radio.Text = "Sign (SHA512)";
            this.toolTip1.SetToolTip(this.sign_radio, "Use sender\'s private key");
            this.sign_radio.UseVisualStyleBackColor = true;
            // 
            // doit_btn
            // 
            this.doit_btn.Location = new System.Drawing.Point(129, 13);
            this.doit_btn.Name = "doit_btn";
            this.doit_btn.Size = new System.Drawing.Size(95, 96);
            this.doit_btn.TabIndex = 0;
            this.doit_btn.Text = "Go";
            this.doit_btn.UseVisualStyleBackColor = true;
            this.doit_btn.Click += new System.EventHandler(this.doit_btn_Click);
            // 
            // label4
            // 
            this.label4.AutoSize = true;
            this.label4.Location = new System.Drawing.Point(75, 201);
            this.label4.Name = "label4";
            this.label4.Size = new System.Drawing.Size(0, 13);
            this.label4.TabIndex = 9;
            // 
            // label3
            // 
            this.label3.AutoSize = true;
            this.label3.Location = new System.Drawing.Point(12, 201);
            this.label3.Name = "label3";
            this.label3.Size = new System.Drawing.Size(66, 13);
            this.label3.TabIndex = 8;
            this.label3.Text = "Public Key =";
            // 
            // label6
            // 
            this.label6.AutoSize = true;
            this.label6.Location = new System.Drawing.Point(79, 223);
            this.label6.Name = "label6";
            this.label6.Size = new System.Drawing.Size(0, 13);
            this.label6.TabIndex = 11;
            // 
            // label5
            // 
            this.label5.AutoSize = true;
            this.label5.Location = new System.Drawing.Point(12, 223);
            this.label5.Name = "label5";
            this.label5.Size = new System.Drawing.Size(70, 13);
            this.label5.TabIndex = 10;
            this.label5.Text = "Private Key =";
            // 
            // closefile_btn
            // 
            this.closefile_btn.Location = new System.Drawing.Point(11, 162);
            this.closefile_btn.Name = "closefile_btn";
            this.closefile_btn.Size = new System.Drawing.Size(77, 34);
            this.closefile_btn.TabIndex = 12;
            this.closefile_btn.Text = "Close File";
            this.closefile_btn.UseVisualStyleBackColor = true;
            this.closefile_btn.Click += new System.EventHandler(this.closefile_btn_Click);
            // 
            // doitreverse_btn
            // 
            this.doitreverse_btn.Location = new System.Drawing.Point(129, 13);
            this.doitreverse_btn.Name = "doitreverse_btn";
            this.doitreverse_btn.Size = new System.Drawing.Size(95, 96);
            this.doitreverse_btn.TabIndex = 14;
            this.doitreverse_btn.Text = "Go";
            this.doitreverse_btn.UseVisualStyleBackColor = true;
            this.doitreverse_btn.Click += new System.EventHandler(this.doitreverse_btn_Click);
            // 
            // decryptverify_radio
            // 
            this.decryptverify_radio.AutoSize = true;
            this.decryptverify_radio.Location = new System.Drawing.Point(5, 61);
            this.decryptverify_radio.Name = "decryptverify_radio";
            this.decryptverify_radio.Size = new System.Drawing.Size(100, 17);
            this.decryptverify_radio.TabIndex = 3;
            this.decryptverify_radio.Text = "Decrypt && Verify";
            this.toolTip1.SetToolTip(this.decryptverify_radio, "Use sender\'s public & receiver\'s private key");
            this.decryptverify_radio.UseVisualStyleBackColor = true;
            // 
            // decrypt_radio
            // 
            this.decrypt_radio.AutoSize = true;
            this.decrypt_radio.Location = new System.Drawing.Point(5, 38);
            this.decrypt_radio.Name = "decrypt_radio";
            this.decrypt_radio.Size = new System.Drawing.Size(62, 17);
            this.decrypt_radio.TabIndex = 2;
            this.decrypt_radio.Text = "Decrypt";
            this.toolTip1.SetToolTip(this.decrypt_radio, "Use receiver\'s private key");
            this.decrypt_radio.UseVisualStyleBackColor = true;
            // 
            // verify_radio
            // 
            this.verify_radio.AutoSize = true;
            this.verify_radio.Checked = true;
            this.verify_radio.Location = new System.Drawing.Point(5, 15);
            this.verify_radio.Name = "verify_radio";
            this.verify_radio.Size = new System.Drawing.Size(124, 17);
            this.verify_radio.TabIndex = 1;
            this.verify_radio.TabStop = true;
            this.verify_radio.Text = "Verify Sign (SHA512)";
            this.toolTip1.SetToolTip(this.verify_radio, "Use sender\'s public key");
            this.verify_radio.UseVisualStyleBackColor = true;
            // 
            // closepublic_btn
            // 
            this.closepublic_btn.Location = new System.Drawing.Point(87, 162);
            this.closepublic_btn.Name = "closepublic_btn";
            this.closepublic_btn.Size = new System.Drawing.Size(77, 34);
            this.closepublic_btn.TabIndex = 16;
            this.closepublic_btn.Text = "Close Public Key";
            this.closepublic_btn.UseVisualStyleBackColor = true;
            this.closepublic_btn.Click += new System.EventHandler(this.closepublic_btn_Click);
            // 
            // closeprivate_btn
            // 
            this.closeprivate_btn.Location = new System.Drawing.Point(163, 162);
            this.closeprivate_btn.Name = "closeprivate_btn";
            this.closeprivate_btn.Size = new System.Drawing.Size(77, 34);
            this.closeprivate_btn.TabIndex = 17;
            this.closeprivate_btn.Text = "Close Private Key";
            this.closeprivate_btn.UseVisualStyleBackColor = true;
            this.closeprivate_btn.Click += new System.EventHandler(this.closeprivate_btn_Click);
            // 
            // backgroundWorker1
            // 
            this.backgroundWorker1.DoWork += new System.ComponentModel.DoWorkEventHandler(this.backgroundWorker1_DoWork);
            this.backgroundWorker1.RunWorkerCompleted += new System.ComponentModel.RunWorkerCompletedEventHandler(this.backgroundWorker_RunWorkerCompleted);
            // 
            // backgroundWorker2
            // 
            this.backgroundWorker2.DoWork += new System.ComponentModel.DoWorkEventHandler(this.backgroundWorker2_DoWork);
            this.backgroundWorker2.RunWorkerCompleted += new System.ComponentModel.RunWorkerCompletedEventHandler(this.backgroundWorker_RunWorkerCompleted);
            // 
            // backgroundWorker3
            // 
            this.backgroundWorker3.DoWork += new System.ComponentModel.DoWorkEventHandler(this.backgroundWorker3_DoWork);
            this.backgroundWorker3.RunWorkerCompleted += new System.ComponentModel.RunWorkerCompletedEventHandler(this.backgroundWorker_RunWorkerCompleted);
            // 
            // backgroundWorker4
            // 
            this.backgroundWorker4.DoWork += new System.ComponentModel.DoWorkEventHandler(this.backgroundWorker4_DoWork);
            this.backgroundWorker4.RunWorkerCompleted += new System.ComponentModel.RunWorkerCompletedEventHandler(this.backgroundWorker_RunWorkerCompleted);
            // 
            // backgroundWorker5
            // 
            this.backgroundWorker5.DoWork += new System.ComponentModel.DoWorkEventHandler(this.backgroundWorker5_DoWork);
            this.backgroundWorker5.RunWorkerCompleted += new System.ComponentModel.RunWorkerCompletedEventHandler(this.backgroundWorker_RunWorkerCompleted);
            // 
            // backgroundWorker6
            // 
            this.backgroundWorker6.DoWork += new System.ComponentModel.DoWorkEventHandler(this.backgroundWorker6_DoWork);
            this.backgroundWorker6.RunWorkerCompleted += new System.ComponentModel.RunWorkerCompletedEventHandler(this.backgroundWorker_RunWorkerCompleted);
            // 
            // backgroundWorker7
            // 
            this.backgroundWorker7.DoWork += new System.ComponentModel.DoWorkEventHandler(this.backgroundWorker7_DoWork);
            this.backgroundWorker7.RunWorkerCompleted += new System.ComponentModel.RunWorkerCompletedEventHandler(this.backgroundWorker_RunWorkerCompleted);
            // 
            // groupBox1
            // 
            this.groupBox1.Controls.Add(this.checkedListBox1);
            this.groupBox1.Controls.Add(this.hash_btn);
            this.groupBox1.Location = new System.Drawing.Point(12, 41);
            this.groupBox1.Name = "groupBox1";
            this.groupBox1.Size = new System.Drawing.Size(227, 115);
            this.groupBox1.TabIndex = 18;
            this.groupBox1.TabStop = false;
            this.groupBox1.Text = "Hash";
            // 
            // groupBox2
            // 
            this.groupBox2.Controls.Add(this.signencrypt_radio);
            this.groupBox2.Controls.Add(this.sign_radio);
            this.groupBox2.Controls.Add(this.encrypt_radio);
            this.groupBox2.Controls.Add(this.doit_btn);
            this.groupBox2.Location = new System.Drawing.Point(12, 239);
            this.groupBox2.Name = "groupBox2";
            this.groupBox2.Size = new System.Drawing.Size(227, 115);
            this.groupBox2.TabIndex = 19;
            this.groupBox2.TabStop = false;
            this.groupBox2.Text = "Send";
            // 
            // groupBox3
            // 
            this.groupBox3.Controls.Add(this.decryptverify_radio);
            this.groupBox3.Controls.Add(this.verify_radio);
            this.groupBox3.Controls.Add(this.doitreverse_btn);
            this.groupBox3.Controls.Add(this.decrypt_radio);
            this.groupBox3.Location = new System.Drawing.Point(12, 360);
            this.groupBox3.Name = "groupBox3";
            this.groupBox3.Size = new System.Drawing.Size(227, 115);
            this.groupBox3.TabIndex = 20;
            this.groupBox3.TabStop = false;
            this.groupBox3.Text = "Receive";
            // 
            // Form1
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(250, 486);
            this.Controls.Add(this.groupBox3);
            this.Controls.Add(this.groupBox2);
            this.Controls.Add(this.groupBox1);
            this.Controls.Add(this.closeprivate_btn);
            this.Controls.Add(this.closepublic_btn);
            this.Controls.Add(this.closefile_btn);
            this.Controls.Add(this.label1);
            this.Controls.Add(this.label2);
            this.Controls.Add(this.label3);
            this.Controls.Add(this.label4);
            this.Controls.Add(this.label5);
            this.Controls.Add(this.label6);
            this.Controls.Add(this.menuStrip1);
            this.MainMenuStrip = this.menuStrip1;
            this.MinimumSize = new System.Drawing.Size(266, 525);
            this.Name = "Form1";
            this.Text = "HW1";
            this.FormClosed += new System.Windows.Forms.FormClosedEventHandler(this.Form1_FormClosed);
            this.menuStrip1.ResumeLayout(false);
            this.menuStrip1.PerformLayout();
            this.groupBox1.ResumeLayout(false);
            this.groupBox2.ResumeLayout(false);
            this.groupBox2.PerformLayout();
            this.groupBox3.ResumeLayout(false);
            this.groupBox3.PerformLayout();
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.Button hash_btn;
        private System.Windows.Forms.CheckedListBox checkedListBox1;
        private System.Windows.Forms.OpenFileDialog openFileDialog1;
        private System.Windows.Forms.MenuStrip menuStrip1;
        private System.Windows.Forms.ToolStripMenuItem fileToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem openToolStripMenuItem;
        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.Label label2;
        private System.Windows.Forms.SaveFileDialog saveFileDialog1;
        private System.Windows.Forms.RadioButton signencrypt_radio;
        private System.Windows.Forms.RadioButton encrypt_radio;
        private System.Windows.Forms.RadioButton sign_radio;
        private System.Windows.Forms.Button doit_btn;
        private System.Windows.Forms.ToolStripMenuItem openPublicKeyToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem openPrivateKeyToolStripMenuItem;
        private System.Windows.Forms.Label label4;
        private System.Windows.Forms.Label label3;
        private System.Windows.Forms.Label label6;
        private System.Windows.Forms.Label label5;
        private System.Windows.Forms.Button closefile_btn;
        private System.Windows.Forms.Button doitreverse_btn;
        private System.Windows.Forms.RadioButton decryptverify_radio;
        private System.Windows.Forms.RadioButton decrypt_radio;
        private System.Windows.Forms.RadioButton verify_radio;
        private System.Windows.Forms.Button closepublic_btn;
        private System.Windows.Forms.Button closeprivate_btn;
        private System.Windows.Forms.ToolTip toolTip1;
        private System.Windows.Forms.ToolStripMenuItem createToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem helpToolStripMenuItem;
        private System.ComponentModel.BackgroundWorker backgroundWorker1;
        private System.ComponentModel.BackgroundWorker backgroundWorker2;
        private System.ComponentModel.BackgroundWorker backgroundWorker3;
        private System.ComponentModel.BackgroundWorker backgroundWorker4;
        private System.ComponentModel.BackgroundWorker backgroundWorker5;
        private System.ComponentModel.BackgroundWorker backgroundWorker6;
        private System.ComponentModel.BackgroundWorker backgroundWorker7;
        private System.Windows.Forms.GroupBox groupBox1;
        private System.Windows.Forms.GroupBox groupBox2;
        private System.Windows.Forms.GroupBox groupBox3;
    }
}

