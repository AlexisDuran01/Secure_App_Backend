using System.ComponentModel.DataAnnotations;

namespace Secure_App_Backend.Dtos
{
    public class RegisterDto
    {
        [Required]
        [EmailAddress]
        public string EmailAddress { get; set; } = string.Empty;

        [Required]
        public string Fullname { get; set; } = string.Empty;

        public string Password { get; set; } = string.Empty;

        public List<string>? Roles { get; set; }


    }
}
