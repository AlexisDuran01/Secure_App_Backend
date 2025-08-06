using System.ComponentModel.DataAnnotations;

namespace Secure_App_Backend.Dtos
{
    public class ForgotPasswordDto
    {
        [Required]
        [EmailAddress]

        public string Email { get; set; } = string.Empty;
    }
}
