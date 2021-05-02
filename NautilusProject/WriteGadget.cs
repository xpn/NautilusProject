using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NautilusProject
{
    public class WriteGadget
    {
        public static void WriteMemory(IntPtr addr, IntPtr value)
        {
            var mngdRefCustomeMarshaller = typeof(System.String).Assembly.GetType("System.StubHelpers.MngdRefCustomMarshaler");
            var CreateMarshaler = mngdRefCustomeMarshaller.GetMethod("CreateMarshaler", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);

            CreateMarshaler.Invoke(null, new object[] { addr, value });
        }
    }
}