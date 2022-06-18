using Microsoft.Win32;
using System.Collections.Generic;
using System.Windows;
using SniffDoge_gui.lib;

namespace SniffDoge_gui
{
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        private void scan_btn_Click(object sender, RoutedEventArgs e)
        {
            Results_tb.Text = "";
            string results = "";
            OpenFileDialog openFileDialog = new OpenFileDialog();
            openFileDialog.Filter = "Jar File (*.jar)|*.jar";
            openFileDialog.Title = "Select File To Scan";

            bool? result = openFileDialog.ShowDialog();
            if (result == true)
            {
                if (!openFileDialog.FileName.EndsWith(".jar"))
                {
                    Results_tb.Text = "Selected file is not a valid jar.";
                    return;
                }
                List<string> res = Binary.Scan(openFileDialog.FileName);
                foreach (string s in res)
                {
                    results += "YARA Match found: " + s + "\n";
                }
                if (results.Length == 0) Results_tb.Text = "No YARA matches found.";
                else Results_tb.Text = results;
            }
        }

        private void Close_btn_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }

        private void Min_btn_Click(object sender, RoutedEventArgs e)
        {
            SystemCommands.MinimizeWindow(this);
        }

        private void Type_Scan(object sender, RoutedEventArgs e)
        {
            Results_tb.Text = "";
            string results = "";
            OpenFileDialog openFileDialog = new OpenFileDialog();
            openFileDialog.Filter = "Jar File (*.jar)|*.jar";
            openFileDialog.Title = "Select File To Scan";

            bool? result = openFileDialog.ShowDialog();
            if (result == true)
            {
                if (!openFileDialog.FileName.EndsWith(".jar"))
                {
                    Results_tb.Text = "Selected file is not a valid jar.";
                    return;
                }
                int custom_payload = 0;
                int neo = 0;
                int ben = 0;
                List<string> res = Type.Scan(openFileDialog.FileName);
                foreach (string r in res)
                {
                    results += "YARA Match found: " + r + "\n";
                    switch (r)
                    {
                        case { } when r.StartsWith("$type_custompayload"):
                            custom_payload++;
                            break;
                        case { } when r.StartsWith("$type_neorat"):
                            neo++;
                            break;
                        case { } when r.StartsWith("$type_ben"):
                            ben++;
                            break;
                    }
                }
                results += "Most Likely type is: " + Calc.Highest(custom_payload, neo, ben);
                if (results.Length == 0) Results_tb.Text = "No YARA matches found.\n";
                else Results_tb.Text = results;
            }
        }

        private void Add_Rules(object sender, RoutedEventArgs e)
        {
            Results_tb.Text = "";
            OpenFileDialog openFileDialog = new OpenFileDialog();
            openFileDialog.Filter = "Yara Rule (*.yara)|*.yara|All files (*.*)|*.*";
            openFileDialog.Title = "Select File To Scan";

            bool? result = openFileDialog.ShowDialog();
            if (result == true)
            {
                Import.Rule(openFileDialog.FileName);
                Results_tb.Text = "Rule file added.";
            }
        }

        private void Custom_Rules(object sender, RoutedEventArgs e)
        {
            Results_tb.Text = "";
            string results = "";
            OpenFileDialog openFileDialog = new OpenFileDialog();
            openFileDialog.Filter = "Jar File (*.jar)|*.jar";
            openFileDialog.Title = "Select File To Scan";

            bool? result = openFileDialog.ShowDialog();
            if (result == true)
            {
                if (!openFileDialog.FileName.EndsWith(".jar"))
                {
                    Results_tb.Text = "Selected file is not a valid jar.";
                    return;
                }
                List<string> res = Custom.Scan(openFileDialog.FileName);
                foreach (string s in res)
                {
                    results += "YARA Match found: " + s + "\n";
                }
                if (results.Length == 0) Results_tb.Text = "No YARA matches found.";
                else Results_tb.Text = results;
            }
        }
    }
}