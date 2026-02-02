# AI-Powered-YAML-Generator-POC-for-Vertica
AI Powered YAML Generator POC for Vertica
# Vertica MCP Server

A Model Context Protocol (MCP) server that enables AI assistants to manage Vertica database deployments through intelligent YAML configuration generation, validation, and modification.

## 🚀 Features

- **AI-Powered YAML Generation**: Generate complete VerticaDB Custom Resource definitions using natural language
- **Intelligent Configuration Updates**: Modify existing configurations with context-aware changes
- **Schema Validation**: Validate YAML against official Vertica CRD schemas (v25.1-v25.4)
- **Database Inspection**: Query and analyze live Vertica database state and share YAML
- **LLM Integration**: Supports both Ollama (local) and Google Gemini AI models

## 📋 Requirements

- Go 1.24.1+
- Vertica database (optional, for inspection features)
- Ollama server or Google Gemini API key (for AI features)

## 🛠️ Installation

```bash
# Clone the repository
git clone <repository-url>
cd vertica-mcp-server

# Build the server
go build -o vertica-mcp-server main.go

# Run the server
./vertica-mcp-server
```

## ⚙️ Configuration

Set environment variables:

```bash
# For Ollama (local LLM)
export OLLAMA_HOST="http://localhost:11434"

# For Google Gemini
export GEMINI_API_KEY="your-api-key"
export USE_GEMINI="true"

# Vertica database (optional)
export VERTICA_HOST="localhost"
export VERTICA_PORT="5433"
export VERTICA_DB="vertica"
export VERTICA_USER="dbadmin"
export VERTICA_PASSWORD="your-password"
```

## 🔧 MCP Tools

The server exposes four core tools:

1. **generate_yaml** - Create new VerticaDB configurations from natural language descriptions
2. **update_yaml** - Modify existing YAML configurations intelligently
3. **validate_yaml** - Validate YAML against Vertica CRD schemas
4. **inspect_database** - Query and analyze live Vertica database state and generates a YAML


## 🏗️ Architecture

```
vertica-mcp-server/
├── main.go                 # Server entry point
├── internal/               # Internal packages
│   ├── jobs/              # Background job management
│   └── state/             # State management
├── pkg/                   # Public packages
│   ├── config/            # Configuration handling
│   ├── database/          # Database operations
│   ├── llm/               # LLM integrations (Ollama, Gemini)
│   ├── models/            # Data models
│   ├── security/          # Security utilities
│   └── validation/        # YAML validation
└── schemas/               # Vertica CRD schemas (v25.1-25.4)
```

## 🤝 Integration with Claude Desktop

Add to your Claude Desktop MCP configuration:

```json
{
  "mcpServers": {
    "vertica": {
      "command": "/path/to/vertica-mcp-server",
      "args": [],
      "env": {
        "OLLAMA_HOST": "http://localhost:11434"
      }
    }
  }
}
```

## 📝 Example Usage

Once integrated with an MCP client like Claude Desktop:

- "Generate a VerticaDB configuration for a 3-node cluster with 2TB storage"
- "Update the YAML to use communal storage on S3"
- "Given the database connection information, connect to it and generate a YAML"

## 🔒 Security

- HTTP client with configurable timeouts and retry logic
- TLS support for secure database connections
- Environment-based credential management
- Input validation and sanitization

## 📊 Version

Current Version: **7.0.0**

## 👤 Author

Sruthi Anumula

## 📄 License

See LICENSE file for details.
