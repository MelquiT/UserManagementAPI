using Microsoft.AspNetCore.Authentication.JwtBearer;
using System.ComponentModel.DataAnnotations;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Microsoft.AspNetCore.Identity.Data;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();

var jwtSettings = builder.Configuration.GetSection("JwtSettings");
var secretKey = jwtSettings["SecretKey"];
var issuer = jwtSettings["Issuer"];
var audience = jwtSettings["Audience"];

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        // transmitter must be validated
        ValidateIssuer = true,
        ValidIssuer = issuer,

        // receiver must be validated
        ValidateAudience = true,
        ValidAudience = audience,

        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey!)),

        ValidateLifetime = true,
        ClockSkew = TimeSpan.Zero // No tolerance for the token expiration
    };
});

builder.Services.AddAuthorization();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.UseSwaggerUI(options =>
    {
        options.SwaggerEndpoint("/openapi/v1.json", "User Management API V1");
    });
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

// Audit Middleware
app.Use(async (context, next) =>
{
    //var logger = context.RequestServices.GetRequiredService<ILogger<Program>>();
    var loggerFactory = context.RequestServices.GetRequiredService<ILoggerFactory>();
    var logger = loggerFactory.CreateLogger("AuditMiddleware"); // It is best to use a specific category name for audit purposes

    var startTime = DateTime.UtcNow;

    var userId = context.User.Identity?.IsAuthenticated == true 
                ? context.User.FindFirstValue(ClaimTypes.NameIdentifier) ?? "Anonymous/No ID" : "Anonymous";

    // Log request details
    logger.LogInformation("HTTP {Method} {Path} by UserID: {UserId} started at {Time}",
        context.Request.Method,
        context.Request.Path,
        userId,
        startTime);

    await next(context);

    // Log response details
    var duration = DateTime.UtcNow - startTime;
    logger.LogInformation("HTTP {Method} {Path} responded {StatusCode} in {Duration}ms",
        context.Request.Method,
        context.Request.Path,
        context.Response.StatusCode,
        duration.TotalMilliseconds);
});

// Global Exception Handling Middleware
app.Use(async (context, next) =>
{
    var loggerFactory = context.RequestServices.GetRequiredService<ILoggerFactory>();
    var logger = loggerFactory.CreateLogger("GlobalExceptionHandler"); // New category for exception handling

    try
    {
        await next(context);
    }
    catch (Exception ex)
    {
        logger.LogError(ex, "An unhandled exception occurred during request processing for {Path}",
            context.Request.Path);

        context.Response.StatusCode = StatusCodes.Status500InternalServerError;
        context.Response.ContentType = "application/json";

        var errorResponse = new
        {
            Message = "An unexpected error occurred",
            Details = app.Environment.IsDevelopment() ? ex.Message : null,
            StackTrace = app.Environment.IsDevelopment() ? ex.StackTrace : null
        };

        await context.Response.WriteAsJsonAsync(errorResponse);
    }
});

var users = new Dictionary<int, User>
{
    {1, new User { Name = "John", LastName = "Doe", Email = "johndoe@gmail.com" } },
    {2, new User { Name = "Jane", LastName = "Smith", Email = "jsmith@gmail.com" } },
    {3, new User { Name = "Alice", LastName = "Johnson", Email = "alice@gmail.com" } },
    {4, new User { Name = "Bob", LastName = "Brown", Email = "bob@outlook.com" } }
};

var credentials = new Dictionary<string, string>
{
    { "admin@api.com", "Admin123!" },
    { "user@api.com", "User123!" }
};

app.MapPost("/auth/login", (LoginRequest request) =>
{
    if (credentials.TryGetValue(request.Email, out var password) && password == request.Password)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.UTF8.GetBytes(secretKey!);
        var userID = credentials.Keys.ToList().IndexOf(request.Email) + 1;

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new[]
            {
                new Claim(ClaimTypes.NameIdentifier, userID.ToString()),
                new Claim(ClaimTypes.Email, request.Email),
                new Claim(ClaimTypes.Name, request.Email),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            }),
            Expires = DateTime.UtcNow.AddHours(1),
            Issuer = issuer,
            Audience = audience,
            SigningCredentials = new SigningCredentials(
                new SymmetricSecurityKey(key),
                SecurityAlgorithms.HmacSha256Signature)
        };

        var token = tokenHandler.CreateToken(tokenDescriptor);
        var tokenString = tokenHandler.WriteToken(token);

        return Results.Ok(new
        {
            Token = tokenString,
            Expires = tokenDescriptor.Expires
        });
    }
    return Results.Unauthorized();
}).WithName("Login").AllowAnonymous();

app.MapGet("/users", (string? search) =>
{
    var filteredUsers = string.IsNullOrWhiteSpace(search)
        ? users
        : users.Where(u =>
            u.Value.Name.Contains(search, StringComparison.OrdinalIgnoreCase) ||
            u.Value.LastName.Contains(search, StringComparison.OrdinalIgnoreCase) ||
            u.Value.Email.Contains(search, StringComparison.OrdinalIgnoreCase));

    return filteredUsers.Select(u => new
    {
        Id = u.Key,
        Name = u.Value.Name,
        LastName = u.Value.LastName,
        Email = u.Value.Email
    });
}).WithName("GetAllUsers").RequireAuthorization();


app.MapGet("/users/{id}", (int id) =>
{
    if (users.TryGetValue(id, out var user))
    {
        return Results.Ok(new
        {
            Id = id,
            Name = user.Name,
            LastName = user.LastName,
            Email = user.Email
        });
    }
    return Results.NotFound(new { Message = "User not found" });
}).WithName("GetUserById").RequireAuthorization();

app.MapPost("/users", (User newUser) =>
{
    var (isValid, errors) = ValidationHelper.ValidateObject(newUser);

    if (!isValid)
    {
        return Results.BadRequest(new { Message = "Validation failed", Errors = errors });
    }

    var newId = users.Keys.Max() + 1;
    users[newId] = newUser;
    return Results.Created($"/users/{newId}", new { Id = newId, newUser.Name, newUser.LastName, newUser.Email });
}).WithName("CreateUser").RequireAuthorization();

app.MapPut("/users/{id}", (int id, User updatedUser) =>
{
    if (!users.ContainsKey(id))
    {
        return Results.NotFound(new { Message = "User not found" });
    }

    var (isValid, errors) = ValidationHelper.ValidateObject(updatedUser);

    if (!isValid)
    {
        return Results.BadRequest(new { Message = "Validation failed", Errors = errors });
    }

    users[id] = updatedUser;
    return Results.Ok(new { Id = id, updatedUser.Name, updatedUser.LastName, updatedUser.Email });
}).WithName("UpdateUser").RequireAuthorization();

app.MapDelete("/users/{id}", (int id) =>
{
    if (users.Remove(id))
    {
        return Results.Ok(new { Message = "User deleted successfully" });
    }
    return Results.NotFound(new { Message = "User not found" });
}).WithName("DeleteUser").RequireAuthorization();

app.Run();
public class User
{
    [Required(ErrorMessage = "Name is required")]
    [StringLength(50, MinimumLength = 2, ErrorMessage = "Name must be between 2 and 50 characters")]
    public string Name { get; set; }

    [Required(ErrorMessage = "LastName is required")]
    [StringLength(50, MinimumLength = 2, ErrorMessage = "LastName must be between 2 and 50 characters")]
    public string LastName { get; set; }

    [Required(ErrorMessage = "Email is required")]
    [EmailAddress(ErrorMessage = "Invalid email format")]
    public string Email { get; set; }
}
public static class ValidationHelper
{
    public static (bool IsValid, List<string> Errors) ValidateObject(object obj)
    {
        var context = new ValidationContext(obj);
        var results = new List<ValidationResult>();
        var isValid = Validator.TryValidateObject(obj, context, results, true);

        var errors = results.Select(r => r.ErrorMessage ?? "Validation error").ToList();
        return (isValid, errors);
    }
}