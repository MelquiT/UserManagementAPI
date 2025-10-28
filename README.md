# User Management API

A RESTful API built with .NET 9 and ASP.NET Core Minimal APIs for managing users with JWT authentication.

## Features

- 🔐 JWT Bearer Token Authentication
- 👥 Complete CRUD operations for users
- ✅ Data validation with Data Annotations
- 📝 Request/Response audit logging
- 🛡️ Global exception handling
- 🔍 User search functionality

## Technologies

- .NET 9
- C# 13.0
- ASP.NET Core Minimal APIs
- JWT Bearer Authentication
- OpenAPI/Swagger

## Middleware

### Audit Middleware
Logs all HTTP requests and responses with:
- HTTP Method
- Request Path
- User ID (if authenticated)
- Response Status Code
- Request Duration

### Global Exception Handler
Catches unhandled exceptions and returns standardized error responses.

## Development

Access Swagger UI in development mode at: `/swagger`

## License

MIT License