using Microsoft.AspNetCore.Authorization;
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
    [Authorize]
    [ApiController]
    [Route("api/[controller]")]
    //api/account
    public class AccountController : ControllerBase
    {
        private readonly UserManager<AppUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;

        public AccountController(UserManager<AppUser> userManager, RoleManager<IdentityRole> roleManager, IConfiguration configuration)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
        }

        // api/account/register
        [AllowAnonymous]
        [HttpPost("register")]
        public async Task<ActionResult<string>> Register(RegisterDto registerDto)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var user = new AppUser
            {
                Email = registerDto.EmailAddress,
                FullName = registerDto.Fullname,
                UserName = registerDto.EmailAddress
            };

            var result = await _userManager.CreateAsync(user, registerDto.Password);

            if (!result.Succeeded)
            {
                return BadRequest(result.Errors);
            }

            if (registerDto.Roles is null)
            {
                await _userManager.AddToRoleAsync(user, "User");
            }
            else
            {
                foreach (var role in registerDto.Roles)
                {
                    await _userManager.AddToRoleAsync(user, role);
                }
            }

            return Ok(new AuthResponseDto
            {
                IsSuccess = true,
                Message = "Cuenta creada exitosamente!!!"
            });
        }

        //api/account/login
        [AllowAnonymous]
        [HttpPost("login")]
        public async Task<ActionResult<AuthResponseDto>> Login(LoginDto loginDto)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var user = await _userManager.FindByEmailAsync(loginDto.Email);

            if (user == null)
            {
                return Unauthorized(new AuthResponseDto
                {
                    IsSuccess = false,
                    Message = "Usuario no encontrado con este email"
                });
            }

            var result = await _userManager.CheckPasswordAsync(user, loginDto.Password);

            if (!result)
            {
                return Unauthorized(new AuthResponseDto
                {
                    IsSuccess = false,
                    Message = "Contraseña invalida"
                });
            }

            var token = await GenerateToken(user);
            var refreshToken = GenerateRefreshToken();
            _ = int.TryParse(_configuration.GetSection("JWTSettings").GetSection("RefreshTokenValidityIn").Value!, out int RefreshTokenValidityIn);
            user.RefreshToken = refreshToken;
            user.RefreshTokenExpiryTime = DateTime.UtcNow.AddMinutes(RefreshTokenValidityIn);
            await _userManager.UpdateAsync(user);


            return Ok(new AuthResponseDto
            {
                Token = token,
                IsSuccess = true,
                Message = "Inicio de sesión exitoso",
                RefreshToken = refreshToken
            });
        }


        private string GenerateRefreshToken()
        {
            var randomNumber = new byte[32];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }

        // api/account/forgot-password
        [AllowAnonymous]
        [HttpPost("forgot-password")]
        public async Task<ActionResult<AuthResponseDto>> ForgotPassword([FromBody] ForgotPasswordDto forgotPasswordDto)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var user = await _userManager.FindByEmailAsync(forgotPasswordDto.Email);

            if (user is null)
            {
                return Ok(new AuthResponseDto
                {
                    IsSuccess = false,
                    Message = "El usuario no existe con este correo electrónico"
                });
            }

            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            var resetLink = $"http://localhost:4200/reset-password?email={user.Email}&token={WebUtility.UrlEncode(token)}";

            // Leer configuración de correo
            var mailSettings = _configuration.GetSection("MailSettings");
            var email = mailSettings["SenderEmail"];
            var displayName = mailSettings["SenderName"];
            var smtpServer = mailSettings["Server"];
            var smtpPort = int.Parse(mailSettings["Port"]);
            var smtpUser = mailSettings["UserName"];
            var smtpPass = mailSettings["Password"];

            // Enviar correo con HTML
            var message = new MimeKit.MimeMessage();
            message.From.Add(new MimeKit.MailboxAddress(displayName, email));
            message.To.Add(new MimeKit.MailboxAddress(user.FullName ?? user.Email, user.Email));
            message.Subject = "Recuperación de contraseña";

            var htmlBody = $@"
               <div style='
                    font-family: \""Helvetica Neue\"", Helvetica, Arial, sans-serif;
                    background-color: #f0f4f8;
                    color: #2d2d2d;
                    padding: 40px;
                    max-width: 600px;
                    margin: auto;
                    border-radius: 10px;
                    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.05);
                '>
                    <h2 style='color: #4b3f72;'>Hola {user.FullName ?? user.Email},</h2>
        
                    <p>Recientemente se solicitó un cambio de contraseña para tu cuenta.</p>

                    <p>Si fuiste tú quien solicitó el cambio, puedes continuar haciendo clic en el siguiente botón:</p>

                    <p style='text-align: center; margin: 30px 0;'>
                        <a href='{resetLink}' style='
                            background-color: #6c63ff;
                            color: #ffffff;
                            padding: 12px 24px;
                            text-decoration: none;
                            border-radius: 6px;
                            font-size: 16px;
                            font-weight: bold;
                            display: inline-block;
                        '>Cambiar mi contraseña</a>
                    </p>

                    <p>Si no reconoces esta solicitud, te recomendamos ignorar este mensaje. Tu cuenta permanecerá segura.</p>

                    <p style='margin-top: 50px; font-size: 13px; color: #888888; text-align: center;'>
                        Este mensaje fue enviado automáticamente. No es necesario que respondas.
                        <br>
                         &copy; {DateTime.Now.Year}
                    </p>
                </div>";

            message.Body = new MimeKit.TextPart("html") { Text = htmlBody };

            using var client = new MailKit.Net.Smtp.SmtpClient();
            await client.ConnectAsync(smtpServer, smtpPort, MailKit.Security.SecureSocketOptions.StartTls);
            await client.AuthenticateAsync(smtpUser, smtpPass);
            await client.SendAsync(message);
            await client.DisconnectAsync(true);

            return Ok(new AuthResponseDto
            {
                IsSuccess = true,
                Message = "Revisa tu correo para restablecer tu contraseña"
            });
        }




        [HttpPost("change-password")]
        public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordDto change)
        {
            var user = await _userManager.FindByEmailAsync(change.Email);
            if (user is null)
            {
                return BadRequest(new AuthResponseDto
                {
                    IsSuccess = false,
                    Message = "El usuario no existe con este correo electrónico"
                });
            }

            var result = await _userManager.ChangePasswordAsync(user, change.CurrentPassword, change.NewPassword);
            if (result.Succeeded)
            {
                return Ok(new AuthResponseDto
                {
                    IsSuccess = true,
                    Message = "Contraseña cambiada exitosamente"
                });
            }

            return BadRequest(new AuthResponseDto
            {
                IsSuccess = false,
                Message = result.Errors.FirstOrDefault()?.Description ?? "Error al cambiar la contraseña"
            });
        }

        [AllowAnonymous]
        [HttpPost("reset-password")]
        public async Task<IActionResult> ResetPassword(ResetPasswordDto resetPasswordDto)
        {
            var user = await _userManager.FindByEmailAsync(resetPasswordDto.Email);

            if (user is null)
            {
                return BadRequest(new AuthResponseDto
                {
                    IsSuccess = false,
                    Message = "El usuario no existe con este correo"
                });
            }

            var result = await _userManager.ResetPasswordAsync(user, resetPasswordDto.Token, resetPasswordDto.NewPassword);
            if (result.Succeeded)
            {
                return Ok(new AuthResponseDto
                {
                    IsSuccess = true,
                    Message = "Se restablecio correctamente"
                });
            }

            return BadRequest(new AuthResponseDto
            {
                IsSuccess = false,
                Message = result.Errors.FirstOrDefault()!.Description


            });
        }

        private async Task<string> GenerateToken(AppUser user)
        {
            var tokenHandler = new JwtSecurityTokenHandler();

            var jwtSection = _configuration.GetSection("JWTSettings");
            var key = Encoding.ASCII.GetBytes(jwtSection["securityKey"]!);

            var roles = await _userManager.GetRolesAsync(user);

            var claims = new List<Claim>
            {
                new (JwtRegisteredClaimNames.Email, user.Email ?? ""),
                new (JwtRegisteredClaimNames.Name, user.FullName ?? ""),
                new (JwtRegisteredClaimNames.NameId, user.Id ?? ""),
                new (JwtRegisteredClaimNames.Aud, jwtSection["ValidAudience"]!),
                new (JwtRegisteredClaimNames.Iss, jwtSection["ValidIssuer"]!)
            };

            foreach (var role in roles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
            }

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddDays(1),
                SigningCredentials = new SigningCredentials(
                    new SymmetricSecurityKey(key),
                    SecurityAlgorithms.HmacSha256
                )
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);

            return tokenHandler.WriteToken(token);
        }

        //api/account/detail
        [Authorize] // Sirve para proteger el servicio
        [HttpGet("detail")]
        public async Task<ActionResult<UserDetailDto>> GetUserDetail()
        {
            var currentUserId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var user = await _userManager.FindByIdAsync(currentUserId!);

            if (user == null)
            {
                return NotFound(new AuthResponseDto
                {
                    IsSuccess = false,
                    Message = "Usuario no encontrado"
                });
            }

            return Ok(new UserDetailDto
            {
                Id = user.Id,
                Email = user.Email,
                FullName = user.FullName,
                Roles = [.. await _userManager.GetRolesAsync(user)],
                PhoneNumber = user.PhoneNumber,
                PhoneNumberConfirmed = user.PhoneNumberConfirmed,
                AccessFailedCount = user.AccessFailedCount
            });
        }

        [HttpGet]
        public async Task<ActionResult<IEnumerable<UserDetailDto>>> GetUsers()
        {
            var users = await _userManager.Users.ToListAsync();
            var userDtos = new List<UserDetailDto>();

            foreach (var user in users)
            {
                var roles = await _userManager.GetRolesAsync(user);
                userDtos.Add(new UserDetailDto
                {
                    Id = user.Id,
                    Email = user.Email,
                    FullName = user.FullName,
                    Roles = roles.ToArray(),
                    PhoneNumber = user.PhoneNumber,
                    PhoneNumberConfirmed = user.PhoneNumberConfirmed,
                    AccessFailedCount = user.AccessFailedCount
                });
            }

            return Ok(userDtos);
        }
    }
}
