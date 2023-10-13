using LicenseData.Services;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddTransient<IWeatherForecastService, WeatherForecastService>();
builder.Services.AddTransient<ILicenseService, LicenseService>();

var app = builder.Build();

// Configure the HTTP request pipeline.
using var serviceScope = app.Services.CreateScope();
var service = serviceScope.ServiceProvider.GetRequiredService<ILicenseService>();

service.CheckLicense();

app.UseSwagger();
app.UseSwaggerUI();

app.UseHttpsRedirection();

app.UseAuthorization();

app.MapControllers();

app.Run();
