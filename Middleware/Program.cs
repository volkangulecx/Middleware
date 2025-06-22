using Middlewares.Extensions;
using Middlewares.Handlers;

var builder = WebApplication.CreateBuilder(args);
// Add services to the container.
//builder.Services.AddControllers(options =>
//{
//    options.Filters.Add<ValidateModelAttribute>(); // Add the custom validation attribute globally
//});

var app = builder.Build();
if (!app.Environment.IsDevelopment())
{
    // Configure the HTTP request pipeline.
    app.UseSecureHeaders(); // Use the custom middleware for secure headers
    app.UseStrictTransportSecurity(); // Use the custom middleware for HSTS
    //app.UseHsts(); // Use the built-in HSTS middleware (optional, can be used instead of custom middleware)
    app.UseCrossOriginPolicy(); // Use the custom middleware for CORS
    app.UseRequestSizeLimit(1024 * 1024 * 10); // Set request size limit to 10 MB
    app.UsePermissionPolicy(); // Use the custom middleware for permission policy
}
else
{
    app.UseDeveloperExceptionPage(); // Use developer exception page in development mode
}

app.UseMiddleware<GlobalExceptionHandlingMiddleware>(); // Use the global exception handling middleware

app.UseHttpsRedirection(); // Redirect HTTP requests to HTTPS

app.MapGet("/", () => "Hello World!");
app.Run();
