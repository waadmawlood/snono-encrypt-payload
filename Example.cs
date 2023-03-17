using API.Helpers;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using RestSharp;
using System.ComponentModel.DataAnnotations;

namespace API.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class ResellerController : BaseController
    {
        string keyEncrypt = "abcdefghijuklmno0123456789012345";

        [HttpPost("login")]
        public Task login(LoginDto loginDto)
        {
            var data = new
            {
                username = loginDto.Username,
                password = loginDto.Password,
            };
            var json = JsonConvert.SerializeObject(data, Formatting.Indented);
            string encryptedString = AesCrypto.Encrypt(json, keyEncrypt);

            var body = JsonConvert.SerializeObject(new
            {
                payload = encryptedString
            });

            var client = new RestClient();
            var request = new RestRequest("https://demo4.sasradius.com/admin/api/index.php/api/login", Method.Post);
            request.AddHeader("Accept", "application/json");
            request.AddHeader("Content-Type", "application/json");
            request.AddParameter("application/json", body, ParameterType.RequestBody);

            RestResponse response = client.Execute(request);

            return Response.WriteAsJsonAsync(System.Text.Json.JsonSerializer.Deserialize<LoginResponse>(response.Content));
        }

        public class LoginDto
        {
            [Required]
            [MinLength(4)]
            public string Username { get; set; }

            [Required]
            [MinLength(4)]
            public string Password { get; set; }
        }

        public class LoginResponse
        {
            public int status { get; set; }
            public string token { get; set; }
        }
    }
}
