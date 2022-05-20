using System;

namespace Test
{
    internal class Program
    {
        private static void Main(string[] args)
        {
            while (true)
            {
                Console.Clear();
                Console.WriteLine("========================================================================================================================");
                Console.WriteLine();
                Console.WriteLine("                                 Honoo.BouncyCastle.Helpers        Runtime version " + Environment.Version);
                Console.WriteLine();
                Console.WriteLine("========================================================================================================================");
                Console.WriteLine();
                Console.WriteLine("  1. Hash/HMAC/CMAC/MAC                    Q. Hash Speed");
                Console.WriteLine("  2. Symmetric Encryption                  W. Encryption Speed");
                Console.WriteLine("  3. Asymmetric Encryption");
                Console.WriteLine("  4. Signature");
                Console.WriteLine("  5. Certificate");
                Console.WriteLine("  6. ");
                Console.WriteLine("  7. ");
                Console.WriteLine("  8. ");
                Console.WriteLine("  9. ");
                Console.WriteLine();
                Console.WriteLine();
                Console.WriteLine("  Z. Temporaries");
                Console.WriteLine();
                Console.WriteLine();
                Console.Write("Choice a project:");
                while (true)
                {
                    var kc = Console.ReadKey(true).KeyChar;
                    switch (kc)
                    {
                        case '1':
                            Console.Clear();
                            Hash.Test();
                            goto end;

                        case '2':
                            Console.Clear();
                            Symmetric.Test();
                            goto end;

                        case '3':
                            Console.Clear();
                            Asymmetric.Test();
                            goto end;

                        case '4':
                            Console.Clear();
                            Signature.Test();
                            goto end;

                        case '5':
                            Console.Clear();
                            Certificate.Test();
                            goto end;

                        case 'Z':
                        case 'z':
                            Console.Clear();
                            Temporaries.Test();
                            goto end;
                    }
                }

            end:
                Console.WriteLine();
                Console.Write("Press any key to Main Menu...");
                Console.Write("\r\n\r\n\r\n\r\n\r\n\r\n\r\n");
                Console.ReadKey(true);
            }
        }
    }
}