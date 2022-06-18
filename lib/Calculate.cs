namespace SniffDoge_gui.lib
{
    public class Calc
    {
        public static string Highest(int c, int n, int b)
        {
            if (c > n && c > b)
            {
                return "CustomPayload";
            }
            else if (n > b)
            {
                return "NeoRat";
            }
            else if (b > n)
            {
                return "Ben Type";
            }
            else if (c == 0 && b == 0 && n == 0)
            {
                return "BreadCat";
            }
            else
            {
                return "Unknown";
            }
        }
    }
}