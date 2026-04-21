using EnterpriseFlow.DTOs;
using EnterpriseFlow.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace EnterpriseFlow.Controllers;

[ApiController]
[Route("api/auth")]
public class AuthController : ControllerBase
{
    private readonly IAuthService _auth;
    private readonly ILogger<AuthController> _log;

    public AuthController(IAuthService auth, ILogger<AuthController> log)
    {
        _auth = auth;
        _log = log;
    }

    // POST /api/auth/register
    // Only Admins can create accounts (change [AllowAnonymous] to [Authorize(Roles="Admin")] after first run)
    [HttpPost("register")]
    [AllowAnonymous]
    public async Task<IActionResult> Register([FromBody] RegisterRequest req)
    {
        try
        {
            var result = await _auth.RegisterAsync(req, GetIp(), GetUa());
            return Ok(result);
        }
        catch (InvalidOperationException ex)
        {
            return Conflict(new MessageResponse(ex.Message));
        }
    }

    // POST /api/auth/login
    [HttpPost("login")]
    [AllowAnonymous]
    public async Task<IActionResult> Login([FromBody] LoginRequest req)
    {
        try
        {
            var result = await _auth.LoginAsync(req, GetIp(), GetUa());
            return Ok(result);
        }
        catch (UnauthorizedAccessException ex)
        {
            return Unauthorized(new MessageResponse(ex.Message));
        }
    }

    // POST /api/auth/refresh
    [HttpPost("refresh")]
    [AllowAnonymous]
    public async Task<IActionResult> Refresh([FromBody] RefreshTokenRequest req)
    {
        try
        {
            var result = await _auth.RefreshAsync(req.RefreshToken, GetIp(), GetUa());
            return Ok(result);
        }
        catch (UnauthorizedAccessException ex)
        {
            return Unauthorized(new MessageResponse(ex.Message));
        }
    }

    // POST /api/auth/logout
    [HttpPost("logout")]
    [Authorize]
    public async Task<IActionResult> Logout()
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier)
            ?? User.FindFirstValue("sub");

        if (userId is null) return Unauthorized();

        await _auth.RevokeAsync(userId, GetIp(), GetUa());
        return Ok(new MessageResponse("Logged out successfully."));
    }

    // POST /api/auth/change-password
    [HttpPost("change-password")]
    [Authorize]
    public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordRequest req)
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier)
            ?? User.FindFirstValue("sub");

        if (userId is null) return Unauthorized();

        try
        {
            await _auth.ChangePasswordAsync(userId, req);
            return Ok(new MessageResponse("Password changed. Please log in again."));
        }
        catch (UnauthorizedAccessException ex)
        {
            return Unauthorized(new MessageResponse(ex.Message));
        }
    }

    // GET /api/auth/me  — returns the current user from the JWT
    [HttpGet("me")]
    [Authorize]
    public IActionResult Me()
    {
        return Ok(new
        {
            Id = User.FindFirstValue(ClaimTypes.NameIdentifier) ?? User.FindFirstValue("sub"),
            Email = User.FindFirstValue(ClaimTypes.Email),
            Role = User.FindFirstValue(ClaimTypes.Role),
            FirstName = User.FindFirstValue("firstName"),
            LastName = User.FindFirstValue("lastName")
        });
    }

    // ── Helpers ───────────────────────────────────────────────
    private string? GetIp()
        => HttpContext.Connection.RemoteIpAddress?.ToString();

    private string? GetUa()
        => Request.Headers.UserAgent.ToString();
}