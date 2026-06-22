"""
Shared configuration for the SOC AI Agent system.
"""
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Service URLs
    SIEM_ENGINE_URL: str = "http://siem-engine:8001"
    TIP_PLATFORM_URL: str = "http://tip-platform:8002"
    AI_ORCHESTRATOR_URL: str = "http://ai-orchestrator:8003"
    RESPONSE_ENGINE_URL: str = "http://response-engine:8004"

    # Search / Intel
    ELASTICSEARCH_URL: str = "http://elasticsearch:9200"
    ELASTICSEARCH_ALERT_INDEX: str = "soc-alerts"
    ELASTICSEARCH_INCIDENT_INDEX: str = "soc-incidents"
    ELASTICSEARCH_REPORT_INDEX: str = "soc-reports"
    ELASTICSEARCH_IOC_INDEX: str = "soc-iocs"
    ELASTICSEARCH_ASSET_INDEX: str = "soc-assets"

    VIRUSTOTAL_BASE_URL: str = "https://www.virustotal.com/api/v3"
    VIRUSTOTAL_API_KEY: str = ""

    CROWDSTRIKE_BASE_URL: str = "https://api.crowdstrike.com"
    CROWDSTRIKE_CLIENT_ID: str = ""
    CROWDSTRIKE_CLIENT_SECRET: str = ""

    # Existing DBs
    NEO4J_URI: str = "bolt://neo4j:7687"
    NEO4J_USER: str = "neo4j"
    NEO4J_PASSWORD: str = "password"
    POSTGRES_URL: str = "postgresql+asyncpg://soc:soc@postgres:5432/soc_db"
    SQL_ECHO: bool = False
    RUN_MIGRATIONS_ON_STARTUP: bool = True
    MONGODB_URL: str = "mongodb://mongo:27017/soc"
    REDIS_URL: str = "redis://redis:6379"

    # AI Models
    OPENAI_API_KEY: str = ""
    ANTHROPIC_API_KEY: str = ""
    LLM_MODEL: str = "gpt-4"
    EMBEDDING_MODEL: str = "text-embedding-3-small"

    # Kafka
    KAFKA_BOOTSTRAP_SERVERS: str = "kafka:9092"

    # Security / Auth
    SECRET_KEY: str = "your-secret-key-change-in-production"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 480
    CORS_ALLOWED_ORIGINS: list[str] = ["http://localhost:8080", "http://localhost:3000"]

    # Shared secret services use to call each other (siem->orchestrator,
    # orchestrator->tip/response/siem). Separate from user JWTs so a leaked
    # user token can never be replayed as a service identity.
    INTERNAL_SERVICE_TOKEN: str = "internal-service-token-change-in-production"

    # First-run bootstrap admin account. Created once if the users table is
    # empty; has no effect after that, so rotating these later is safe.
    ADMIN_USERNAME: str = "admin"
    ADMIN_PASSWORD: str = "change-me-now"

    # Django Ticket Management System sync (Priority 1 item). Optional —
    # when DJANGO_BASE_URL is blank, ticket sync no-ops safely, same pattern
    # as the VirusTotal/CrowdStrike integrations.
    DJANGO_BASE_URL: str = ""
    DJANGO_API_TOKEN: str = ""
    DJANGO_TICKET_ENDPOINT: str = "/api/tickets/"
    DJANGO_WEBHOOK_SECRET: str = "django-webhook-secret-change-in-production"

    class Config:
        env_file = ".env"


settings = Settings()