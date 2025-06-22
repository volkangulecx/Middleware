namespace Middlewares.Handlers
{
    public class GlobalExceptionHandlingMiddleware
    {
        private readonly RequestDelegate next;
        private readonly ILogger<GlobalExceptionHandlingMiddleware> logger;

        public GlobalExceptionHandlingMiddleware(RequestDelegate next, ILogger<GlobalExceptionHandlingMiddleware> logger)
        {
            this.next = next;
            this.logger = logger;
        }
        public async Task Invoke(HttpContext context)
        {
            try
            {
                await next(context);
            }
            catch (Exception ex)
            {
                // Log the exception
                logger.LogError(ex, "An unhandled exception occurred while processing the request.");

                // JSON response for the error
                context.Response.ContentType = "application/json";

                int statusCode;

                switch (ex)
                {
                    case UnauthorizedAccessException:
                        statusCode = StatusCodes.Status401Unauthorized;
                        break;
                    case ArgumentException:
                        statusCode = StatusCodes.Status400BadRequest;
                        break;
                    case KeyNotFoundException:
                        statusCode = StatusCodes.Status404NotFound;
                        break;
                    default:
                        statusCode = StatusCodes.Status500InternalServerError;
                        break;
                }

                context.Response.StatusCode = statusCode;

                var response = new
                {
                    Error = ex.GetType().Name,
                    StatusCode = statusCode,
                    Message = ex.Message,
                    Details = ex.StackTrace
                };

                await context.Response.WriteAsJsonAsync(response);
            }
        }
    }
}
