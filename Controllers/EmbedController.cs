using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using MyBackend.Services;

namespace MyBackend.Controllers
{
    [ApiController]
    [Route("[controller]")]
    [Authorize]
    public class EmbedController : ControllerBase
    {
        private readonly IPowerBiService _powerBiService;
        private readonly IAuthorizationService _authorizationService;

        public EmbedController(IPowerBiService powerBiService, IAuthorizationService authorizationService)
        {
            _powerBiService = powerBiService;
            _authorizationService = authorizationService;
        }

        [HttpGet("getEmbedToken")]
        public async Task<IActionResult> GetEmbedToken()
        {
            try
            {
                var email = User.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Email)?.Value;
                var role = User.Claims.FirstOrDefault(c => c.Type == "role")?.Value;
                if (string.IsNullOrEmpty(email) || string.IsNullOrEmpty(role))
                    return Unauthorized(new { error = "Token inválido o expirado" });

                var user = new AuthenticatedUser
                {
                    Email = email,
                    Role = role
                };

                bool isAuthorizedToAccessReport = await IsUserAuthorizedForReport(user);

                if (!isAuthorizedToAccessReport)
                {
                    return Forbid("No autorizado para acceder a este informe.");
                }

                var embedInfo = await _powerBiService.GetEmbedInfoAsync(user);
                return Ok(new
                {
                    accessToken = embedInfo.AccessToken,
                    embedUrl = embedInfo.EmbedUrl,
                    expiry = embedInfo.Expiry,
                    datasetId = embedInfo.DatasetId
                });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { error = "Error interno del servidor", detalle = ex.Message });
            }
        }

        private Task<bool> IsUserAuthorizedForReport(AuthenticatedUser user)
        {
            if (user.Role == "FiltroMentor" || user.Role == "FiltroAlumno")
            {
                return Task.FromResult(true);
            }
            else
            {
                return Task.FromResult(false);
            }
        }
    }
}