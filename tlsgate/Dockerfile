FROM mcr.microsoft.com/dotnet/sdk:5.0 AS build
WORKDIR /src

# copy csproj and restore as distinct layers
COPY tlsgate.csproj .
RUN dotnet restore

# copy everything else and build app
COPY . .
WORKDIR "/src/."
RUN dotnet publish -c release -o /app --no-restore

# final stage/image
FROM mcr.microsoft.com/dotnet/aspnet:5.0
WORKDIR /app
COPY --from=build /app ./
COPY concertoCA.pem /usr/local/share/ca-certificates/concertoCA.crt
RUN update-ca-certificates

ENTRYPOINT ["dotnet", "tlsgate.dll"]
