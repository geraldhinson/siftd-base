package constants

const (
	DEBUGSIFTD_AUTH = "DEBUGSIFTD_AUTH"
)

const (
	SERVICE_INSTANCE_NAME  = "SERVICE_INSTANCE_NAME"
	DB_CONNECTION_STRING   = "DB_CONNECTSTRING"
	JOURNAL_PARTITION_NAME = "JOURNAL_PARTITION_NAME"
	IDENTITY_SERVICE       = "IDENTITY_SERVICE"
	LISTEN_ADDRESS         = "LISTEN_ADDRESS"
	CALLED_SERVICES        = "CALLED_SERVICES"
)

const (
	HTTP_GET    = "GET"
	HTTP_POST   = "POST"
	HTTP_PUT    = "PUT"
	HTTP_DELETE = "DELETE"
)

const (
	INTERNAL_SERVER_ERROR          = "a backend system error occurred - please check the service logs"
	PRIMARY_KEY_VIOLATION_SQL_CODE = "23505" // Conflict on primary key
	RESOURCE_NOT_FOUND_ERROR_CODE  = -404    // Resource not found (note similarity to HTTP status codes)
	RESOURCE_BAD_REQUEST_CODE      = -400    // Bad request (note similarity to HTTP status codes)
	RESOURCE_ALREADY_EXISTS_CODE   = -409    // Resource already exists (note similarity to HTTP status codes)
	RESOURCE_INTERNAL_ERROR_CODE   = -500    // Internal server error (note similarity to HTTP status codes)
	RESOURCE_OK_CODE               = 0       // OK
)

const (
	HEALTH_STATUS_UNHEALTHY = "UNHEALTHY"
	HEALTH_STATUS_HEALTHY   = "HEALTHY"
)
