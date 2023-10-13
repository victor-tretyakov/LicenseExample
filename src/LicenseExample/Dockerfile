FROM mcr.microsoft.com/dotnet/aspnet:7.0-alpine AS base
WORKDIR /app
EXPOSE 8080
EXPOSE 8081

FROM mcr.microsoft.com/dotnet/sdk:7.0-alpine AS build
COPY ["src/LicenseExample/LicenseExample.csproj", "src/LicenseExample/"]
COPY ["src/LicenseData/LicenseData.csproj", "src/LicenseData/"]
RUN dotnet restore "src/LicenseExample/LicenseExample.csproj"
COPY . .
RUN dotnet build "src/LicenseExample/LicenseExample.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "src/LicenseExample/LicenseExample.csproj" -c Release -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "LicenseExample.dll"]