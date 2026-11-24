using System.Data.SqlClient;
using System.Runtime.Serialization.Formatters.Binary;
using System.Web;
public class Service {
  public object Get(string id) {
    var cmd = new SqlCommand("SELECT * FROM Users WHERE Id = " + id);   // CS-001
    var bf = new BinaryFormatter();                                     // CS-003
    var obj = bf.Deserialize(stream);
    var settings = new Newtonsoft.Json.JsonSerializerSettings {
      TypeNameHandling = Newtonsoft.Json.TypeNameHandling.All };        // CS-004
    System.Diagnostics.Process.Start("cmd.exe", "/c " + Request.Query["c"]); // CS-005
    var h = System.Security.Cryptography.MD5.Create();                  // CS-006
    builder.AllowAnyOrigin().AllowCredentials();                        // CS-010
    return obj;
  }
}
