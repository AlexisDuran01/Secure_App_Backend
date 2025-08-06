using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Secure_App_Backend.Model;
using Secure_App_Backend.Dtos;

namespace Secure_App_Backend.Controllers
{
    [Authorize(Roles = "Admin")]
    [ApiController]
    [Route("api/[controller]")]
    public class RolesController : ControllerBase
    {
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly UserManager<AppUser> _userManager;

        public RolesController(RoleManager<IdentityRole> roleManager, UserManager<AppUser> userManager)
        {
            _roleManager = roleManager;
            _userManager = userManager;
        }

        [HttpPost]
        public async Task<IActionResult> CreateRole([FromBody] CreateRoleDto createRoleDto)
        {
            if (string.IsNullOrEmpty(createRoleDto.RoleName))
            {
                return BadRequest("Debe proporcionar un nombre de rol valido");
            }

            var roleExist = await _roleManager.RoleExistsAsync(createRoleDto.RoleName);
            if (roleExist)
            {
                return BadRequest("Este rol ya ha sido registrado previamente");
            }

            var roleResult = await _roleManager.CreateAsync(new IdentityRole(createRoleDto.RoleName));
            if (roleResult.Succeeded)
            {
                return Ok(new { message = "El rol se ha registrado exitosamente" });
            }

            return BadRequest("Ocurrio un error al intentar registrar el rol");

        }

        [AllowAnonymous]
        [HttpGet]
        public async Task<ActionResult<IEnumerable<RoleResponseDto>>> GetRoles()
        {
            var roles = await _roleManager.Roles.ToListAsync();
            var roleDtos = new List<RoleResponseDto>();

            foreach (var role in roles)
            {
                var usersInRole = await _userManager.GetUsersInRoleAsync(role.Name);
                roleDtos.Add(new RoleResponseDto
                {
                    Id = role.Id,
                    Name = role.Name,
                    TotalUsers = usersInRole.Count
                });
            }

            return Ok(roleDtos);
        }

        [HttpDelete("{id}")]

        public async Task<IActionResult> DeleteRole(string id)
        {
            var role = await _roleManager.FindByIdAsync(id);
            if (role is null)
            {
                return NotFound("No se encontro dicho rol");
            }
            var result = await _roleManager.DeleteAsync(role);
            if (result.Succeeded)
            {
                return Ok(new { message = "Rol elimimnado correctamente" });
            }
            return BadRequest("El Rol no se pudo eliminar correctamente");
        }
        [HttpPost("assing")]
        public async Task<IActionResult> AssignRole([FromBody] RolesAssingDto rolesAssingDto)
        {
            var user = await _userManager.FindByIdAsync(rolesAssingDto.UserId);
            if (user is null)
            {
                return NotFound("No se encontró el usuario especificado");
            }
            var role = await _roleManager.FindByNameAsync(rolesAssingDto.RoleId);
            if (role is null)
            {
                return NotFound("No se encontró el rol especificado para asignar");
            }

            var result = await _userManager.AddToRoleAsync(user, role.Name!);

            if (result.Succeeded)
            {
                return Ok(new { message = "El rol fue asignado al usuario correctamente" });
            }

            var error = result.Errors.FirstOrDefault();
            return BadRequest(error!.Description);
        }
    }
}
