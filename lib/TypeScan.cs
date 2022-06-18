using libyaraNET;
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;

namespace SniffDoge_gui.lib
{
    class Type
    {
        public static List<string> Scan(string path)
        {
            List<string> res = new List<string>();
            List<ScanResult> results = new List<ScanResult>();
            string apd = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "SniffDoge");
            ClearDecomp();
            ZipFile.ExtractToDirectory(path, Path.Combine(apd, "Decompression"));
            var files = Directory.GetFiles(Path.Combine(apd, "Decompression"));
            string[] allfiles = Directory.GetFiles(Path.Combine(apd, "Decompression"), "*.class", SearchOption.AllDirectories);
            foreach (var f in allfiles)
            {
                if (f.EndsWith(".class"))
                {
                    using (var ctx = new YaraContext())
                    {
                        Rules? rules = null;
                        try
                        {
                            using (var compiler = new Compiler())
                            {
                                compiler.AddRuleFile(Path.Combine(apd, "Rules\\Types.yara"));
                                rules = compiler.GetRules();
                            }
                            var scanner = new Scanner();
                            results = scanner.ScanFile(f, rules);
                        }
                        finally
                        {
                            if (rules != null) rules.Dispose();
                        }
                    }
                }
                foreach (var r in results)
                {
                    foreach (var s in r.Matches)
                    {
                        res.Add(s.Key + " in class file " + Path.GetFileName(f));
                    }
                }
            }
            return res;
        }

        private static void ClearDecomp()
        {
            string[] decomp = Directory.GetFiles(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "SniffDoge\\Decompression"), "*.*", SearchOption.AllDirectories);
            foreach (var f in decomp)
            {
                try
                {
                    File.Delete(f);
                }
                catch (IOException iox)
                {
                    throw iox;
                }
            }
            string[] dirs = Directory.GetDirectories(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "SniffDoge\\Decompression"));
            foreach (var d in dirs)
            {
                try
                {
                    Directory.Delete(d, true);
                }
                catch (IOException iox)
                {
                    throw iox;
                }
            }
        }
    }
}
