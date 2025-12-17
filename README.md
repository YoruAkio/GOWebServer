# GOWebServer

GOWebServer is a web server for Growtopia Private Server. It is written in Go and is designed to be fast and efficient.

## To-Do

- [x] Basic HTTP server
- [x] Handle `/growtopia/server_data.php` requests
- [x] Implementing rate limiting requests
- [x] Implementing cache server for Growtopia Client
- [x] Handling missing cache files
- [x] Geo Location checker to block certain countries

## Build

The following are required to build and run GOWebServer:

- [Golang](https://golang.org/dl/) (1.16+) - The Go Programming Language
- and little bit of brain cells (optional)

Building the server is simple, just run the following command:

1. Clone the repository:

```bash
# Clone the repository and its submodules for the requirements of geo location detection
git clone https://github.com/yoruakio/GOWebServer.git --recursive
```

2. Build the server:

```bash
go build

# or running the go file directly
go run main.go
```

3. Run the server:

```bash
./GOWebServer
```

> [!NOTE]
> **DDoS Protection (Optional but Recommended)**
> 
> The server includes built-in application-layer DDoS protection (connection rate limiting, concurrent connection limits).
> 
> For additional OS-level protection against TCP SYN floods, UDP floods, and ICMP floods, run:
> ```bash
> sudo ./scripts/setup-ddos-protection.sh
> ```
> 
> This configures kernel parameters and iptables rules for network-layer attack mitigation. Only required for Linux systems.

## Configuration

The server can be configured using the `config.json` file. The following are the default configuration:

```json
{
    "host": "127.0.0.1", // ENet Host
    "port": "17091", // ENet Port
    "serverCdn": "", // Growtopia CDN to handle missing files
    "loginUrl": "gtlogin-backend.vercel.app", // URI for client login
    "isLogging": false,
    "rateLimit": 300,
    "rateLimitDuration": 5,
    "enableGeo": false, // Enable Geo Location blocking
    "trustedRegions": [ // List of trusted regions that allow access to the server
        "ID",
        "SG",
        "MY"
    ]}
```

## Contact

If you have any questions or suggestions, feel free to contact me at:

- Discord: [@yoruakio](https://discord.com/users/919841186246692886)
- Telegram: [@yoruakio](https://t.me/yoruakio)

## Contributing

Contributions are welcome! If you would like to contribute to the project, please fork the repository and submit a pull request.

## Aknowledgements

- [GTPSWebServer](https://github.com/yoruakio/GTPSWebServer) - The original GOWebServer was inspired by this project.
- [Golang](https://golang.org/) - The Go Programming Language

## License

GOWebServer is licensed under the MIT License. See the [LICENSE](LICENSE) file for more information.
