package main

import (
	"fmt"
	"log"
	"net/http"
	"regexp"

	"github.com/sirupsen/logrus"

	"github.com/gin-gonic/gin"

	adapter "github.com/gwatts/gin-adapter"
	"github.com/jesusvazquez/authboss-gin-sample/abclientstate"
	"github.com/volatiletech/authboss"
	"github.com/volatiletech/authboss/defaults"
)

var (
	host         = "127.0.0.1"
	port         = "3000"
	database     = NewMemStorer()
	sessionStore abclientstate.SessionStorer
	cookieStore  abclientstate.CookieStorer
)

func main() {

	gin.SetMode(gin.ReleaseMode)
	router := gin.Default()
	router.Use(gin.Recovery())

	// Setting up Authboss
	ab := initAuthBossParam()
	// Set up LoadClientStateMiddleware, required by the auth module
	router.Use(adapter.Wrap(ab.LoadClientStateMiddleware))

	// Init all the auth routes to go to authboss
	router.Any("/auth/*w", gin.WrapH(ab.Config.Core.Router))

	// Default endpoints
	router.GET("/status", status)

	// Initialize http server
	server := &http.Server{
		Addr:    host + ":" + port,
		Handler: router,
	}

	// DEBUG SECTION
	fmt.Println("## Variables at the top")
	fmt.Printf("- Host: %s - Port: %s\n", host, port)
	fmt.Println("## Debugging authboss")
	fmt.Printf("- ab.Config.Paths.RootURL: %s\n", ab.Config.Paths.RootURL)
	fmt.Printf("- ab.Config.Paths.Mount: %s\n", ab.Config.Paths.Mount)
	fmt.Printf("- Auth Module Loaded?: %v\n", ab.IsLoaded("auth"))
	fmt.Println("## Gin Routes loaded")
	routes := router.Routes()
	for route := range routes {
		fmt.Printf("- %s\n", routes[route].Path)
	}

	// Start serving traffic
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logrus.Fatalf("listen: %s\n", err)
	}

}

// initializes authboss parameters
func initAuthBossParam() *authboss.Authboss {
	ab := authboss.New()

	ab.Config.Paths.RootURL = "http://" + host + ":" + port
	ab.Config.Storage.Server = database
	// ab.Config.Storage.SessionState = sessionStore
	// ab.Config.Storage.CookieState = cookieStore
	ab.Config.Paths.Mount = "/auth"

	// Default to API usage
	ab.Config.Core.ViewRenderer = defaults.JSONRenderer{}
	defaults.SetCore(&ab.Config, true, false)

	emailRule := defaults.Rules{
		FieldName: "email", Required: true,
		MatchError: "Must be a valid e-mail address",
		MustMatch:  regexp.MustCompile(`.*@.*\.[a-z]{1,}`),
	}
	passwordRule := defaults.Rules{
		FieldName: "password", Required: true,
		MinLength: 4,
	}
	nameRule := defaults.Rules{
		FieldName: "name", Required: true,
		MinLength: 2,
	}

	ab.Config.Core.BodyReader = defaults.HTTPBodyReader{
		ReadJSON: true,
		Rulesets: map[string][]defaults.Rules{
			"register":    {emailRule, passwordRule, nameRule},
			"recover_end": {passwordRule},
		},
		Confirms: map[string][]string{
			"register":    {"password", authboss.ConfirmPrefix + "password"},
			"recover_end": {"password", authboss.ConfirmPrefix + "password"},
		},
		Whitelist: map[string][]string{
			"register": []string{"email", "name", "password"},
		},
	}

	// Note: here we could instantiate more modules like sms, oauth, twofactor...

	if err := ab.Init(); err != nil {
		// Handle error, don't let program continue to run
		log.Fatalln(err)
	}

	return ab
}

// status endpoint to expose service livenessprobe
func status(c *gin.Context) {
	c.Header("Content-Type", "application/json")
	c.JSON(http.StatusOK, gin.H{
		"status": "ok",
	})
}
