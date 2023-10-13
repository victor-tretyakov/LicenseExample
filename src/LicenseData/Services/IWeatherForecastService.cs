using LicenseData.Dto;

namespace LicenseData.Services
{
    public interface IWeatherForecastService
    {
        IEnumerable<WeatherForecast> Get();
    }
}