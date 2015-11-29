using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SQLite;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace _sln {
    class Program {
        String fromPath;
        String toPath;
        static void Main(string[] args) {
            new Program("", "");
        }
        Program(String fromPath, String toPath) {
            if (fromPath == "") {
                fromPath = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData) + @"\Google\Chrome\User Data\Default\Cookies"; ;
            }
            if (toPath == "") {
                toPath = Path.Combine(Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location), "cookie");
            }
            run(fromPath, toPath);
        }
        static void run(String fromPath, String toPath) {
            if (!System.IO.File.Exists(fromPath)) throw new System.IO.FileNotFoundException("Cant find cookie store", fromPath); // race condition, but i'll risk it
            File.Copy(fromPath, toPath, true);
            var connectionString = "Data Source=" + toPath + ";pooling=false";
            var list = new List<Dictionary<String, String>>();
            using (var conn = new SQLiteConnection(connectionString)) {
                using (var cmd = conn.CreateCommand()) {
                    cmd.CommandText = "SELECT host_key,name,encrypted_value,value FROM cookies WHERE value = ''";
                    conn.Open();
                    using (SQLiteDataReader reader = cmd.ExecuteReader()) {
                        while (reader.Read()) {
                            String hostKey = (String)reader["host_key"];
                            String name = (String)reader["name"];
                            Byte[] encryptedValue = (Byte[])reader["encrypted_value"];
                            String value = (String)reader["value"];
                            if (encryptedValue.Length == 0) {
                                continue;
                            }
                            var decodedData = System.Security.Cryptography.ProtectedData.Unprotect(encryptedValue, null, System.Security.Cryptography.DataProtectionScope.CurrentUser);
                            var plainText = Encoding.ASCII.GetString(decodedData);
                            list.Add(new Dictionary<string, string>() {
                                { "hostKey", hostKey },
                                { "name", name },
                                { "value",plainText}
                            });
                        }
                    }
                }
                using (SQLiteTransaction trans = conn.BeginTransaction()) {
                    foreach (var i in list) {
                        using (SQLiteCommand cmd = conn.CreateCommand()) {
                            cmd.CommandText = "update cookies set value = @value where host_key = @hostKey and name = @name ";
                            cmd.Parameters.Add(new SQLiteParameter("@value", i["value"]));
                            cmd.Parameters.Add(new SQLiteParameter("@hostKey", i["hostKey"]));
                            cmd.Parameters.Add(new SQLiteParameter("@name", i["name"]));
                            cmd.ExecuteNonQuery();
                        }
                    }
                    trans.Commit();
                }
                conn.Close();
            }
        }
    }
}
