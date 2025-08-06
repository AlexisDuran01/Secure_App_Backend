using System.ComponentModel.DataAnnotations;

namespace Secure_App_Backend.Dtos
{
    public class CreateRoleDto
    {
        [Required(ErrorMessage = "Nombre Requerido")]
        public string RoleName { get; set; } = null!;
    }

}
