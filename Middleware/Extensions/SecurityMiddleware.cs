namespace Middlewares.Extensions
{
    public static class SecurityMiddleware
    {
        public static IApplicationBuilder UseSecureHeaders(this IApplicationBuilder app)
        {
            app.Use(async (context, next) =>
            {
                // X-Content-Type-Options
                // Tarayıcıya, içerik türünü tahmin etmeye çalışmasını veya yapmamasını söyler.
                // Bu, MIME türüyle ilgili güvenlik açıklarını önlemek için önemlidir.
                // Örneğin, tarayıcı bir dosyanın içeriğini yanlış yorumlayabilir ve bu da XSS saldırılarına yol açabilir. Bu alan eklenmezse "sniffing" işlemi yapılabilir. (Özellikle eski tarayıcılarda)
                // "nosniff" değeri, tarayıcının içeriği tahmin etmesini engeller ve bu da güvenliği artırır. Başka bir tanımlama yapılamaz.
                context.Response.Headers["X-Content-Type-Options"] = "nosniff"; //En güvenli hali

                // X-Frame-Options
                // Sayfanın iframe içinde yüklenip yüklenemeyeceğini kontrol eder. (Clickjacking saldırılarına karşı koruma sağlar)
                // "DENY" değeri, sayfanın hiçbir şekilde iframe içinde yüklenemeyeceğini belirtir.
                // "SAMEORIGIN" değeri, sayfanın yalnızca aynı kök alan adı altında iframe içinde yüklenebileceğini belirtir.
                // "ALLOW-FROM https://example.com" değeri, sayfanın yalnızca belirtilen URI'den iframe içinde yüklenebileceğini belirtir. (Sadece eski tarayıcılarda desteklenir)
                // Hiç yazılmazsa, tarayıcı varsayılan olarak "SAMEORIGIN" davranışını gösterir. (Özellikle client side JavaScript uygulamalarında bu durum sorun yaratabilir)
                context.Response.Headers["X-Frame-Options"] = "DENY"; //En güvenli hali, ayrıca SEO açısından da önemlidir.

                // X-XSS-Protection
                // Tarayıcıya, XSS saldırılarını algılaması ve engellemesi için bir talimat verir.
                // "1; mode=block" değeri, tarayıcının XSS saldırılarını algılamasını ve engellemesini sağlar. (Özellikle eski tarayıcılarda bu alan önemlidir)
                // "0" değeri, XSS korumasının devre dışı bırakılmasını sağlar. (Bu, güvenlik açığına neden olabilir)
                // Modern tarayıcılar (Chrome, Firefox, Edge) bu alanı dikkate almaz, ancak eski tarayıcılarda önemlidir.
                context.Response.Headers["X-XSS-Protection"] = "1; mode=block"; //En güvenli hali

                // Referrer-Policy
                // Tarayıcıların bağlantıyı verirken "nereden geldin?" bilgisini (Referrer) nasıl ileteceğini belirler.
                // "no-referrer" değeri, tarayıcının bağlantıyı verirken Referrer bilgisini hiç göndermemesini sağlar.
                // "no-referrer-when-downgrade" değeri, tarayıcının HTTPS'den HTTP'ye geçerken Referrer bilgisini göndermemesini sağlar.
                // "origin" değeri, tarayıcının yalnızca kök alan adını Referrer olarak göndermesini sağlar.
                // "strict-origin" değeri, tarayıcının yalnızca kök alan adını Referrer olarak göndermesini ve HTTPS'den HTTP'ye geçerken Referrer bilgisini göndermemesini sağlar.
                // "same-origin" değeri, tarayıcının yalnızca aynı kök alan adı altında Referrer bilgisini göndermesini sağlar.
                // "strict-origin-when-cross-origin" değeri, tarayıcının yalnızca kök alan adını Referrer olarak göndermesini ve HTTPS'den HTTP'ye geçerken Referrer bilgisini göndermemesini sağlar.
                // "unsafe-url" değeri, tarayıcının Referrer bilgisini tam olarak göndermesini sağlar. (Bu, güvenlik açığına neden olabilir)
                context.Response.Headers["Referrer-Policy"] = "no-referrer"; //En güvenli hali

                // Content-Security-Policy
                // Hangi kaynakların (JS,CSS, resim, font vb) yüklenebileceğini ve çalıştırılabileceğini belirler.
                // "default-src 'self'" değeri, yalnızca aynı kök alan adından kaynakların yüklenmesine izin verir.
                // "'self' https://cdn.example.com" değeri, yalnızca aynı kök alan adından ve belirtilen URI'den kaynakların yüklenmesine izin verir.
                // "'none'" değeri, hiçbir kaynağın yüklenmesine izin vermez.
                // "*" değeri, tüm kaynakların yüklenmesine izin verir. (Bu, güvenlik açığına neden olabilir)
                // "script-src 'self' https://cdn.example.com" değeri, yalnızca aynı kök alan adından ve belirtilen URI'den JavaScript kaynaklarının yüklenmesine izin verir.
                // "style-src 'self' https://cdn.example.com" değeri, yalnızca aynı kök alan adından ve belirtilen URI'den CSS kaynaklarının yüklenmesine izin verir.
                // "img-src 'self' https://cdn.example.com" değeri, yalnızca aynı kök alan adından ve belirtilen URI'den resim kaynaklarının yüklenmesine izin verir.
                // "font-src 'self' https://cdn.example.com" değeri, yalnızca aynı kök alan adından ve belirtilen URI'den font kaynaklarının yüklenmesine izin verir.
                // "connect-src 'self' https://api.example.com" değeri, yalnızca aynı kök alan adından ve belirtilen URI'den bağlantıların (AJAX, WebSocket vb) yapılmasına izin verir.
                // Birleşmiş olarak ise "script-src 'self' https://cdn.example.com; style-src 'self' https://cdn.example.com; img-src 'self' https://cdn.example.com; font-src 'self' https://cdn.example.com; connect-src 'self' https://api.example.com" şeklinde yazılabilir.
                // Yazılmazsa, tarayıcı varsayılan olarak tüm kaynakların yüklenmesine izin verir. (Bu, güvenlik açığına neden olabilir)
                context.Response.Headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'";


                await next();
            });
            return app;
        }

        public static IApplicationBuilder UseStrictTransportSecurity(this IApplicationBuilder app, int maxAgeInSeconds = 31536000, bool includeSubDomains = true, bool preload = false)
        {
            app.Use(async (context, next) =>
            {
                // Strict-Transport-Security
                // HTTPS bağlantılarının zorunlu kılınmasını sağlar.
                // "max-age" değeri, tarayıcının bu kuralı ne kadar süreyle geçerli sayacağını belirtir. (Örneğin, 31536000 saniye = 1 yıl)
                // "includeSubDomains" değeri, alt alan adlarının da bu kuraldan etkilenmesini sağlar.
                // "preload" değeri, tarayıcının bu kuralı önceden yüklemesini sağlar. (Bu, güvenlik açığına neden olabilir)
                context.Response.Headers["Strict-Transport-Security"] = $"max-age={maxAgeInSeconds}; {(includeSubDomains ? "includeSubDomains; " : "")}{(preload ? "preload" : "")}";

                // Hali hazırda UseHsts() middleware'i kullanılıyorsa, bu middleware'in etkisi olmayacaktır.
                // Ayrıca bu yapının sadece yayın ortamında (Production) kullanılması önerilir. Geliştirme ortamında (Development) bu yapı kullanılmamalıdır.
                await next();
            });
            return app;
        }

        public static IApplicationBuilder UsePermissionPolicy(this IApplicationBuilder app)
        {
            app.Use(async (context, next) =>
            {
                // Permissions-Policy
                // Tarayıcının hangi özellikleri kullanabileceğini belirler.
                // "geolocation=()" değeri, tarayıcının konum bilgisi erişimini devre dışı bırakır.
                // "camera=()" değeri, tarayıcının kamera erişimini devre dışı bırakır.
                // "microphone=()" değeri, tarayıcının mikrofon erişimini devre dışı bırakır.
                // "fullscreen=()" değeri, tarayıcının tam ekran moduna geçişini devre dışı bırakır.
                // "payment=()" değeri, tarayıcının ödeme işlemlerini devre dışı bırakır.
                // () parantezleri içine bir URI yazılabilir, bu durumda sadece belirtilen URI'den erişim izni verilir. Örneğin: "geolocation=(https://example.com)" şeklinde yazılabilir.
                // () yerine * yazılırsa, tüm URI'lerden erişim izni verilir. Örneğin: "geolocation=*" şeklinde yazılabilir.
                // Yazılmazsa, tarayıcı varsayılan olarak tüm özelliklere erişim izni verir. (Bu, güvenlik açığına neden olabilir)
                // none değeri, tüm özelliklerin erişimini devre dışı bırakır. (Bu, güvenlik açığına neden olabilir) (Örn: "geolocation=none")
                // self değeri, yalnızca aynı kök alan adından erişim izni verir. (Bu, güvenlik açığına neden olabilir) (Örn: "geolocation=self")

                context.Response.Headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=(), fullscreen=(), payment=()";
                await next();
            });
            return app;
        }

        public static IApplicationBuilder UseCrossOriginPolicy(this IApplicationBuilder app)
        {
            app.Use(async (context, next) =>
            {
                // Access-Control-Allow-Origin
                // Tarayıcının hangi kök alan adlarından gelen istekleri kabul edeceğini belirler.
                // "*" değeri, tüm kök alan adlarından gelen istekleri kabul eder. (Bu, güvenlik açığına neden olabilir)
                // "https://trusted.example.com" değeri, yalnızca belirtilen URI'den gelen istekleri kabul eder.
                // Yazılmazsa, tarayıcı varsayılan olarak hiçbir kök alan adından gelen istekleri kabul etmez. (Bu, güvenlik açığına neden olabilir)
                context.Response.Headers["Access-Control-Allow-Origin"] = "https://trusted.example.com";

                // Access-Control-Allow-Methods
                // Tarayıcının hangi HTTP yöntemlerini (GET, POST, PUT, DELETE vb.) kabul edeceğini belirler.
                // Yazılmazsa, tarayıcı varsayılan olarak GET ve POST yöntemlerini kabul eder. (Bu, güvenlik açığına neden olabilir)
                context.Response.Headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE";

                // Access-Control-Allow-Headers
                // Tarayıcının hangi özel başlıkları kabul edeceğini belirler. (örn: Authorization, Content-Type vb.)
                // Yazılmazsa tarayıcı varsayılan (tarayıcı) olarak bazı başlıkları kabul eder, ancak bu güvenlik açığına neden olabilir.
                context.Response.Headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type";
                await next();
            });
            return app;
        }
        /// <summary>
        /// Request Size Limit
        /// </summary>
        /// <param name="app"></param>
        /// <param name="maxBytes">Default: 1MB</param>
        /// <returns></returns>
        public static IApplicationBuilder UseRequestSizeLimit(this IApplicationBuilder app, long maxBytes = 1024 * 1024)
        {
            app.Use(async (context, next) =>
            {
                // Request Size Limit
                // İstek gelmeden önce istek boyutunu kontrol edip aşan durumlar için isteği reddeder.

                if (context.Request.ContentLength > maxBytes)
                {
                    context.Response.StatusCode = StatusCodes.Status413PayloadTooLarge;
                    context.Response.ContentType = "application/json";

                    var errorMessage = new
                    {
                        error = "Request size limit exceeded",
                        maxSize = maxBytes,
                        status = 413
                    };

                    var json = System.Text.Json.JsonSerializer.Serialize(errorMessage);
                    await context.Response.WriteAsync(json);
                    return;
                }
                //Eğer Content-Length başlığı yoksa veya limiti aşmıyorsa, isteği devam ettirir.
                await next();
            });
            return app;
        }
    }
}
