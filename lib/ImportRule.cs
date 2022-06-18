using System;
using System.IO;

namespace SniffDoge_gui.lib
{
    public class Import
    {
        public static void Rule(string path)
        {
            string apd = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "SniffDoge\\Rules\\Custom\\");
            try
            {
                File.Copy(path, apd + Path.GetFileName(path));
            }
            catch (IOException iox)
            {
                throw iox;
            }
        }
    }
}