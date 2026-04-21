using EnterpriseFlow.Data;
using EnterpriseFlow.DTOs;
using EnterpriseFlow.Helpers;
using EnterpriseFlow.Models;
using Microsoft.EntityFrameworkCore;

namespace EnterpriseFlow.Services;

public interface IAuthService
{
    Task<AuthResponse> RegisterAsync(RegisterRequest req, string? ip, string? ua);
    Task<AuthResponse> LoginAsync(LoginRequest req, string? ip, string? ua);
    Task<AuthResponse> RefreshAsync(string rawRefreshToken, string? ip, string? ua);
    Task RevokeAsync(string userId, string? ip, string? ua);
    Task ChangePasswordAsync(string userId, ChangePasswordRequest req);
}

public class AuthService : IAuthService
{
    private readonly AppDbContext _db;
    private readonly IJwtHelper _jwt;
    private readonly ILogger<AuthService> _log;

    private static readonly TimeSpan RefreshLifetime = TimeSpan.FromDays(7);

    public AuthService(AppDbContext db, IJwtHelper jwt, ILogger<AuthService> log)
    {
        _db = db;
        _jwt = jwt;
        _log = log;
    }

    // ── Register ──────────────────────────────────────────────
    public async Task<AuthResponse> RegisterAsync(RegisterRequest req, string? ip, string? ua)
    {
        if (await _db.Users.AnyAsync(u => u.Email == req.Email.ToLower()))
            throw new InvalidOperationException("Email already in use.");

        var user = new User
        {
            Email = req.Email.ToLower().Trim(),
            PasswordHash = BCrypt.Net.BCrypt.HashPassword(req.Password, workFactor: 12),
            FirstName = req.FirstName.Trim(),
            LastName = req.LastName.Trim(),
            RoleId = req.RoleId
        };

        _db.Users.Add(user);
        await _db.SaveChangesAsync();

        await _db.Entry(user).Reference(u => u.Role).LoadAsync();

        return await IssueTokensAsync(user, ip, ua, "REGISTER");
    }

    // ── Login ─────────────────────────────────────────────────
    public async Task<AuthResponse> LoginAsync(LoginRequest req, string? ip, string? ua)
    {
        var user = await _db.Users
            .Include(u => u.Role)
            .FirstOrDefaultAsync(u => u.Email == req.Email.ToLower());

        // Always run BCrypt even on failure to prevent timing attacks
        var valid = user is not null
            && user.IsActive
            && BCrypt.Net.BCrypt.Verify(req.Password, user.PasswordHash);

        if (!valid)
        {
            await WriteAuditAsync(user?.Id, "LOGIN_FAIL", ip, ua,
                user is null ? "Unknown email" : "Wrong password or inactive");
            throw new UnauthorizedAccessException("Invalid credentials.");
        }

        return await IssueTokensAsync(user!, ip, ua, "LOGIN_SUCCESS");
    }

    // ── Refresh ───────────────────────────────────────────────
    public async Task<AuthResponse> RefreshAsync(string rawToken, string? ip, string? ua)
    {
        var hashed = _jwt.HashToken(rawToken);

        var stored = await _db.RefreshTokens
            .Include(rt => rt.User).ThenInclude(u => u.Role)
            .FirstOrDefaultAsync(rt => rt.Token == hashed);

        if (stored is null || stored.Revoked || stored.ExpiresAt < DateTime.UtcNow)
            throw new UnauthorizedAccessException("Invalid or expired refresh token.");

        if (!stored.User.IsActive)
            throw new UnauthorizedAccessException("Account is deactivated.");

        // Rotate: revoke old, issue new
        stored.Revoked = true;
        await _db.SaveChangesAsync();

        return await IssueTokensAsync(stored.User, ip, ua, "TOKEN_REFRESH");
    }

    // ── Logout (revoke all tokens for user) ───────────────────
    public async Task RevokeAsync(string userId, string? ip, string? ua)
    {
        await _db.RefreshTokens
            .Where(rt => rt.UserId == userId && !rt.Revoked)
            .ExecuteUpdateAsync(s => s.SetProperty(rt => rt.Revoked, true));

        await WriteAuditAsync(userId, "LOGOUT", ip, ua, null);
    }

    // ── Change password ───────────────────────────────────────
    public async Task ChangePasswordAsync(string userId, ChangePasswordRequest req)
    {
        var user = await _db.Users.FindAsync(userId)
            ?? throw new KeyNotFoundException("User not found.");

        if (!BCrypt.Net.BCrypt.Verify(req.CurrentPassword, user.PasswordHash))
            throw new UnauthorizedAccessException("Current password is incorrect.");

        user.PasswordHash = BCrypt.Net.BCrypt.HashPassword(req.NewPassword, workFactor: 12);
        user.UpdatedAt = DateTime.UtcNow;

        // Revoke all existing sessions on password change
        await _db.RefreshTokens
            .Where(rt => rt.UserId == userId && !rt.Revoked)
            .ExecuteUpdateAsync(s => s.SetProperty(rt => rt.Revoked, true));

        await _db.SaveChangesAsync();
    }

    // ── Private helpers ───────────────────────────────────────

    private async Task<AuthResponse> IssueTokensAsync(
        User user, string? ip, string? ua, string action)
    {
        var accessToken = _jwt.GenerateAccessToken(user);
        var rawRefresh = _jwt.GenerateRefreshToken();
        var hashedRefresh = _jwt.HashToken(rawRefresh);

        _db.RefreshTokens.Add(new RefreshToken
        {
            UserId = user.Id,
            Token = hashedRefresh,
            ExpiresAt = DateTime.UtcNow.Add(RefreshLifetime)
        });

        await WriteAuditAsync(user.Id, action, ip, ua, null);
        await _db.SaveChangesAsync();

        return new AuthResponse(
            AccessToken: accessToken,
            RefreshToken: rawRefresh,           // send plain to client
            AccessTokenExpiry: DateTime.UtcNow.AddMinutes(15),
            User: ToDto(user)
        );
    }

    private async Task WriteAuditAsync(
        string? userId, string action, string? ip, string? ua, string? note)
    {
        _db.AuthAuditLogs.Add(new AuthAuditLog
        {
            UserId = userId,
            Action = action,
            IpAddress = ip,
            UserAgent = ua,
            Note = note
        });

        await _db.SaveChangesAsync();
    }

    private static UserDto ToDto(User u) => new(
        u.Id, u.Email, u.FirstName, u.LastName, u.Role.Name);
}