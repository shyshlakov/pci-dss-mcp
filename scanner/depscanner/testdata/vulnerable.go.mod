module example.com/vulnerable-app

go 1.21

require (
	golang.org/x/net v0.20.0
	golang.org/x/text v0.14.0
	github.com/gin-gonic/gin v1.9.0
)

require (
	github.com/some/indirect v1.0.0 // indirect
)
