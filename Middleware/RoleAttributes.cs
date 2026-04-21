using Microsoft.AspNetCore.Authorization;

namespace EnterpriseFlow.Middleware;

public static class Roles
{
    public const string Admin = "Admin";
    public const string Manager = "Manager";
    public const string Agent = "Agent";
    public const string Viewer = "Viewer";
    public const string AdminOrManager = "Admin,Manager";
    public const string AdminManagerOrAgent = "Admin,Manager,Agent";
}

public class AdminOnlyAttribute : AuthorizeAttribute
{
    public AdminOnlyAttribute() { Roles = Middleware.Roles.Admin; }
}

public class ManagerOrAboveAttribute : AuthorizeAttribute
{
    public ManagerOrAboveAttribute() { Roles = Middleware.Roles.AdminOrManager; }
}

public class AgentOrAboveAttribute : AuthorizeAttribute
{
    public AgentOrAboveAttribute() { Roles = Middleware.Roles.AdminManagerOrAgent; }
}