package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"github.com/justinas/alice"
	"github.com/lib/pq"
	"github.com/xeipuuv/gojsonschema"
	"golang.org/x/crypto/bcrypt"
)

type App struct {
	DB     *sql.DB
	JWTKey []byte
}

type Credentials struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

type Project struct {
	XataID         string   `json:"xata_id,omitempty"`
	UserID         string   `json:"user,omitempty"`
	Name           string   `json:"name,omitempty"`
	RepoURL        string   `json:"repo_url,omitempty"`
	SiteURL        string   `json:"site_url,omitempty"`
	Description    string   `json:"description,omitempty"`
	Dependencies   []string `json:"dependencies,omitempty"`
	DevDependencies []string `json:"dev_dependencies,omitempty"`
	Status         string   `json:"status,omitempty"`
}

type Claims struct {
	Username string `json:"username"`
	XataID   string `json:"xata_id"`
	jwt.RegisteredClaims
}

type UserResponse struct {
	XataID   string `json:"xata_id"`
	Username string `json:"username"`
	Token    string `json:"token"`
}

type ErrorResponse struct {
	Message string `json:"message"`
}

type RouteResponse struct {
	Message string `json:"message"`
	ID      string `json:"id,omitempty"`
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	// Load the schemas
	userSchema, loadErr := loadSchema("schemas/user.json")
	if loadErr != nil {
		log.Fatalf("Error loading user schema: %v", loadErr)
	}

	projectSchema, loadErr := loadSchema("schemas/project.json") // corrected project schema path
	if loadErr != nil {
		log.Fatalf("Error loading project schema: %v", loadErr)
	}

	JWTKey := []byte(os.Getenv("JWT_SECRET_KEY"))
	if len(JWTKey) == 0 {
		log.Fatal("Missing JWT_SECRET_KEY environment variable")
	}

	connStr := os.Getenv("XATA_PSQL_URL")
	if len(connStr) == 0 {
		log.Fatal("Missing XATA_PSQL_URL environment variable")
	}

	DB, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}
	defer DB.Close()

	app := &App{DB: DB, JWTKey: JWTKey}

	log.Println("Starting server ...")
	router := mux.NewRouter()

	// Middleware chain and routes for user auth
	userChain := alice.New(loggingMiddleware, validateMiddleware(userSchema))
	router.Handle("/register", userChain.ThenFunc(app.register)).Methods("POST")
	router.Handle("/login", userChain.ThenFunc(app.login)).Methods("POST")

	// Middleware chain for project requests
	projectChain := alice.New(loggingMiddleware, app.jwtMiddleware)
	router.Handle("/projects", projectChain.ThenFunc(app.getProjects)).Methods("GET")
	router.Handle("/projects/{xata_id}", projectChain.ThenFunc(app.getProject)).Methods("GET")
	router.Handle("/projects/{xata_id}", projectChain.ThenFunc(app.deleteProject)).Methods("DELETE")

	// Project creation and update with validation middleware
	projectChainWithValidation := projectChain.Append(validateMiddleware(projectSchema))
	router.Handle("/projects", projectChainWithValidation.ThenFunc(app.createProject)).Methods("POST")
	router.Handle("/projects/{xata_id}", projectChainWithValidation.ThenFunc(app.updateProject)).Methods("PUT")

	log.Println("Listening on port 5000")
	log.Fatal(http.ListenAndServe(":5000", router))
}

// loadSchema loads a JSON schema from a file
func loadSchema(filePath string) (string, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s %s\n", r.RemoteAddr, r.Method, r.URL)
		next.ServeHTTP(w, r)
	})
}

func (app *App) jwtMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			respondWithError(w, http.StatusUnauthorized, "No token provided")
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		claims := &Claims{}

		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return app.JWTKey, nil
		})

		if err != nil {
			if err == jwt.ErrSignatureInvalid {
				respondWithError(w, http.StatusUnauthorized, "Invalid token signature")
				return
			}
			respondWithError(w, http.StatusBadRequest, "Invalid token")
			return
		}

		if !token.Valid {
			respondWithError(w, http.StatusUnauthorized, "Invalid token")
			return
		}

		ctx := context.WithValue(r.Context(), "claims", claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func validateMiddleware(schema string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var body map[string]interface{}
			bodyBytes, err := io.ReadAll(r.Body)
			if err != nil {
				respondWithError(w, http.StatusBadRequest, "Invalid request payload")
				return
			}

			err = json.Unmarshal(bodyBytes, &body)
			if err != nil {
				respondWithError(w, http.StatusBadRequest, "Invalid request payload")
				return
			}

			schemaLoader := gojsonschema.NewStringLoader(schema)
			documentLoader := gojsonschema.NewGoLoader(body)
			result, err := gojsonschema.Validate(schemaLoader, documentLoader)
			if err != nil {
				respondWithError(w, http.StatusInternalServerError, "Error validating schema")
				return
			}

			if !result.Valid() {
				var errs []string
				for _, err := range result.Errors() {
					errs = append(errs, err.String())
				}
				respondWithError(w, http.StatusBadRequest, strings.Join(errs, ", "))
				return
			}

			r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
			next.ServeHTTP(w, r)
		})
	}
}

func respondWithError(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(ErrorResponse{Message: message})
}

func (app *App) generateToken(username, xataID string) (string, error) {
	expirationTime := time.Now().Add(1 * time.Hour)

	claims := &Claims{
		Username: username,
		XataID:   xataID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(app.JWTKey)
}

// Register function
func (app *App) register(w http.ResponseWriter, r *http.Request) {
	var creds Credentials

	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(creds.Password), bcrypt.DefaultCost)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Error hashing password")
		return
	}

	var xataID string
	err = app.DB.QueryRow("INSERT INTO users (username, password) VALUES ($1, $2) RETURNING xata_id", creds.Username, hashedPassword).Scan(&xataID)
	if err != nil {
		log.Printf("Error creating user: %v", err)
		respondWithError(w, http.StatusInternalServerError, "Error creating user")
		return
	}

	tokenString, err := app.generateToken(creds.Username, xataID)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Error generating token")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(UserResponse{XataID: xataID, Username: creds.Username, Token: tokenString})
}

// Login function
func (app *App) login(w http.ResponseWriter, r *http.Request) {
	var creds Credentials

	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	var storedUsername, storedPassword, xataID string
	err = app.DB.QueryRow("SELECT xata_id, username, password FROM users WHERE username=$1", creds.Username).Scan(&xataID, &storedUsername, &storedPassword)
	if err != nil {
		if err == sql.ErrNoRows {
			respondWithError(w, http.StatusUnauthorized, "User not found")
			return
		}
		respondWithError(w, http.StatusInternalServerError, "Error querying user")
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(creds.Password))
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	tokenString, err := app.generateToken(storedUsername, xataID)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Error generating token")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(UserResponse{XataID: xataID, Username: storedUsername, Token: tokenString})
}




// Create Project
func (app *App) createProject(w http.ResponseWriter, r *http.Request) {
	var project Project

	err := json.NewDecoder(r.Body).Decode(&project)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	claims, ok := r.Context().Value("claims").(*Claims)
	if !ok {
		respondWithError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	// Set the UserID to the current user's XataID from the token
	project.UserID = claims.XataID

	// Ensure the description is provided, default to an empty string if not
	if project.Description == "" {
		project.Description = "No description provided"
	}

	err = app.DB.QueryRow("INSERT INTO projects (user_id, name, repo_url, site_url, description, dependencies, dev_dependencies, status) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING xata_id",
		project.UserID, project.Name, project.RepoURL, project.SiteURL, project.Description, pq.Array(project.Dependencies), pq.Array(project.DevDependencies), project.Status).Scan(&project.XataID)

	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Error creating project")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(project)
}


// Get all Projects
func (app *App) getProjects(w http.ResponseWriter, r *http.Request) {
	claims, ok := r.Context().Value("claims").(*Claims)
	if !ok {
		respondWithError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	rows, err := app.DB.Query("SELECT xata_id, name, repo_url, site_url, description, dependencies, dev_dependencies, status FROM projects WHERE user_id = $1", claims.XataID)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Error fetching projects")
		return
	}
	defer rows.Close()

	var projects []Project
	for rows.Next() {
		var project Project
		var dependencies, devDependencies []string

		err := rows.Scan(&project.XataID, &project.Name, &project.RepoURL, &project.SiteURL, &project.Description, pq.Array(&dependencies), pq.Array(&devDependencies), &project.Status)
		if err != nil {
			respondWithError(w, http.StatusInternalServerError, "Error scanning project data")
			return
		}

		project.Dependencies = dependencies
		project.DevDependencies = devDependencies
		projects = append(projects, project)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(projects)
}

// Get a single Project by XataID
func (app *App) getProject(w http.ResponseWriter, r *http.Request) {
	claims, ok := r.Context().Value("claims").(*Claims)
	if !ok {
		respondWithError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	vars := mux.Vars(r)
	xataID := vars["xata_id"]

	var project Project
	var dependencies, devDependencies []string

	err := app.DB.QueryRow("SELECT xata_id, name, repo_url, site_url, description, dependencies, dev_dependencies, status FROM projects WHERE xata_id = $1 AND user_id = $2", xataID, claims.XataID).Scan(
		&project.XataID, &project.Name, &project.RepoURL, &project.SiteURL, &project.Description, pq.Array(&dependencies), pq.Array(&devDependencies), &project.Status)

	if err != nil {
		if err == sql.ErrNoRows {
			respondWithError(w, http.StatusNotFound, "Project not found")
			return
		}
		respondWithError(w, http.StatusInternalServerError, "Error fetching project")
		return
	}

	project.Dependencies = dependencies
	project.DevDependencies = devDependencies

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(project)
}

// Update a Project by XataID
func (app *App) updateProject(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	xataID := vars["xata_id"]

	var project Project

	err := json.NewDecoder(r.Body).Decode(&project)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	claims, ok := r.Context().Value("claims").(*Claims)
	if !ok {
		respondWithError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	// Ensure the project belongs to the logged-in user
	_, err = app.DB.Exec("UPDATE projects SET name=$1, repo_url=$2, site_url=$3, description=$4, dependencies=$5, dev_dependencies=$6, status=$7 WHERE xata_id=$8 AND user_id=$9",
		project.Name, project.RepoURL, project.SiteURL, project.Description, pq.Array(project.Dependencies), pq.Array(project.DevDependencies), project.Status, xataID, claims.XataID)

	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Error updating project")
		return
	}

	respondWithMessage(w, http.StatusOK, "Project updated successfully")
}

// Delete a Project by XataID
func (app *App) deleteProject(w http.ResponseWriter, r *http.Request) {
	claims, ok := r.Context().Value("claims").(*Claims)
	if !ok {
		respondWithError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	vars := mux.Vars(r)
	xataID := vars["xata_id"]

	// Delete the project if it belongs to the logged-in user
	result, err := app.DB.Exec("DELETE FROM projects WHERE xata_id = $1 AND user_id = $2", xataID, claims.XataID)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Error deleting project")
		return
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Error checking deletion status")
		return
	}

	if rowsAffected == 0 {
		respondWithError(w, http.StatusNotFound, "Project not found")
		return
	}

	respondWithMessage(w, http.StatusOK, "Project deleted successfully")
}

func respondWithMessage(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(RouteResponse{Message: message})
}













































// package main

// import (
// 	"database/sql"
// 	"encoding/json"
// 	"log"
// 	"net/http"
// 	"os"

// 	"github.com/gorilla/mux"
// 	"github.com/joho/godotenv"
// 	"github.com/justinas/alice"
// 	_ "github.com/lib/pq"
// 	"golang.org/x/crypto/bcrypt"
// )

// type App struct {
// 	DB *sql.DB
// }

// type Credentials struct {
// 	Username string `json:"username,omitempty"`
// 	Password string `json:"password,omitempty"`
// }

// type UserResponse struct {
// 	XataID   string `json:"xata_id"`
// 	Username string `json:"username"`
// }

// type ErrorResponse struct {
// 	Message string `json:"message"`
// }

// type RouteResponse struct {
// 	Message string `json:"message"`
// 	ID      string `json:"id,omitempty"`
// }

// func main() {
// 	err := godotenv.Load()
// 	if err != nil {
// 		log.Fatal("Error loading .env file")
// 	}

// 	connStr := os.Getenv("XATA_PSQL_URL")
// 	if len(connStr) == 0 {
// 		log.Fatal("Missing XATA_PSQL_URL environment variable")
// 	}

// 	DB, err := sql.Open("postgres", connStr)
// 	if err != nil {
// 		log.Fatal(err)
// 	}

// 	defer DB.Close()

// 	app := &App{DB: DB}

// 	log.Println("Starting server ...")

// 	router := mux.NewRouter()

// 	log.Println("Setting up routes ...")

// 	// Corrected the placement of the closing parenthesis
// 	router.Handle("/register", alice.New(loggingMiddleware).ThenFunc(app.register)).Methods("POST")
// 	router.Handle("/login", alice.New(loggingMiddleware).ThenFunc(login)).Methods("POST")
// 	router.Handle("/projects", alice.New(loggingMiddleware).ThenFunc(createProject)).Methods("POST")
// 	router.Handle("/projects/{id}", alice.New(loggingMiddleware).ThenFunc(updateProject)).Methods("PUT")
// 	router.Handle("/projects", alice.New(loggingMiddleware).ThenFunc(getProjects)).Methods("GET")
// 	router.Handle("/projects/{id}", alice.New(loggingMiddleware).ThenFunc(getProject)).Methods("GET")
// 	router.Handle("/projects/{id}", alice.New(loggingMiddleware).ThenFunc(deleteProject)).Methods("DELETE")

// 	log.Println("Listening on port 5000")
// 	log.Fatal(http.ListenAndServe(":5000", router))
// }

// func loggingMiddleware(next http.Handler) http.Handler {
// 	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 		log.Printf("%s %s %s\n", r.RemoteAddr, r.Method, r.URL)

// 		next.ServeHTTP(w, r)
// 	})
// }

// func respondWithError(w http.ResponseWriter, code int, message string) {
// 	w.Header().Set("Content-Type", "application/json")
// 	w.WriteHeader(code)
// 	json.NewEncoder(w).Encode(ErrorResponse{Message: message})
// }

// // register function to handle user registration
// func (app *App) register(w http.ResponseWriter, r *http.Request) {
// 	var creds Credentials

// 	err := json.NewDecoder(r.Body).Decode(&creds)
// 	if err != nil {
// 		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
// 		return
// 	}

// 	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(creds.Password), bcrypt.DefaultCost)
// 	if err != nil {
// 		respondWithError(w, http.StatusInternalServerError, "Error hashing password")
// 		return
// 	}

// 	var xata_id string
// 	err = app.DB.QueryRow("INSERT INTO \"user\" (username, password) VALUES ($1, $2) RETURNING xata_id", creds.Username, string(hashedPassword)).Scan(&xata_id)

// 	if err != nil {
// 		respondWithError(w, http.StatusInternalServerError, "Error creating user")
// 		return
// 	}

// 	w.Header().Set("Content-Type", "application/json")
// 	json.NewEncoder(w).Encode(UserResponse{XataID: xata_id, Username: creds.Username})

// }

// // login
// func login(w http.ResponseWriter, r *http.Request) {
// 	w.Header().Set("Content-Type", "application/json")
// 	json.NewEncoder(w).Encode(RouteResponse{Message: "Hello from login"})
// }

// // createProject
// func createProject(w http.ResponseWriter, r *http.Request) {
// 	w.Header().Set("Content-Type", "application/json")
// 	json.NewEncoder(w).Encode(RouteResponse{Message: "Hello from createProject"})
// }

// // updateProject
// func updateProject(w http.ResponseWriter, r *http.Request) {
// 	vars := mux.Vars(r)
// 	id := vars["id"]

// 	w.Header().Set("Content-Type", "application/json")
// 	json.NewEncoder(w).Encode(RouteResponse{Message: "Hello from updateProject", ID: id})
// }

// // getProjects
// func getProjects(w http.ResponseWriter, r *http.Request) {
// 	w.Header().Set("Content-Type", "application/json")
// 	json.NewEncoder(w).Encode(RouteResponse{Message: "Hello from getProjects"})
// }

// // getProject
// func getProject(w http.ResponseWriter, r *http.Request) {
// 	vars := mux.Vars(r)
// 	id := vars["id"]

// 	w.Header().Set("Content-Type", "application/json")
// 	json.NewEncoder(w).Encode(RouteResponse{Message: "Hello from getProject", ID: id})
// }

// // deleteProject
// func deleteProject(w http.ResponseWriter, r *http.Request) {
// 	vars := mux.Vars(r)
// 	id := vars["id"]

// 	w.Header().Set("Content-Type", "application/json")
// 	json.NewEncoder(w).Encode(RouteResponse{Message: "Hello from deleteProject", ID: id})
// }







































// TODO: 2:27:14

// package main

// import (
// 	"bytes"
// 	"database/sql"
// 	"encoding/json"
// 	"io"
// 	"log"
// 	"net/http"
// 	"os"
// 	"strings"
// 	"time"

// 	"context"

// 	"github.com/golang-jwt/jwt/v5"
// 	"github.com/gorilla/mux"
// 	"github.com/joho/godotenv"
// 	"github.com/justinas/alice"
// 	"github.com/lib/pq"
// 	"github.com/xeipuuv/gojsonschema"
// 	"golang.org/x/crypto/bcrypt"
// )

// type App struct {
// 	DB     *sql.DB
// 	JWTKey []byte
// }

// type Credentials struct {
// 	Username string `json:"username,omitempty"`
// 	Password string `json:"password,omitempty"`
// }

// type Project struct{
// 	XataID string `json:"xata_id,omitempty"`
// 	UserId string `json:"user,omitempty"` 
// 	Name string `json:"name,omitempty"`
// 	RepoURL string `json:"repo_url,omitempty"`
// 	SiteURL string `json:"site_url,omitempty"`
// 	Description string `json:"description,omitempty"`
// 	Dependencies []string `json:"dependencies,omitempty"`
// 	DevDependencies []string `json:"dev_dependencies,omitempty"`
// 	Status string `json:"status,omitempty"` 
// }


// type Claims struct {
// 	Username string `json:"username"`
// 	XataID   string `json:"xata_id"`
// 	jwt.RegisteredClaims
// }

// type UserResponse struct {
// 	XataID   string `json:"xata_id"`
// 	Username string `json:"username"`
// 	Token    string `json:"token"`
// }

// type ErrorResponse struct {
// 	Message string `json:"message"`
// }

// type RouteResponse struct {
// 	Message string `json:"message"`
// 	ID      string `json:"id,omitempty"`
// }

// func main() {
// 	err := godotenv.Load()
// 	if err != nil {
// 		log.Fatal("Error loading .env file")
// 	}

// 	var loadErr error
// 	userSchema, loadErr := loadSchema("schemas/user.json")
// 	if loadErr!= nil {
// 			log.Fatalf("Error loading user schema: %v", loadErr)
// 		}
	
// 	projectSchema, loadErr := loadSchema("schemas/user.json")
// 	if loadErr!= nil {
// 			log.Fatalf("Error loading user schema: %v", loadErr)
// 		}

// 	JWTKey := []byte(os.Getenv("JWT_SECRET_KEY")) // Changed to JWT_SECRET_KEY
// 	if len(JWTKey) == 0 {
// 		log.Fatal("Missing JWT_SECRET environment variable")
// 	}

// 	connStr := os.Getenv("XATA_PSQL_URL")
// 	if len(connStr) == 0 {
// 		log.Fatal("Missing XATA_PSQL_URL environment variable")
// 	}

// 	DB, err := sql.Open("postgres", connStr)
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	defer DB.Close()

// 	app := &App{DB: DB, JWTKey: JWTKey}

// 	log.Println("Starting server ...")
// 	router := mux.NewRouter()
// 	log.Println("Setting up routes ...")

// 	// Middleware chain and routes for user auth
// 	userChain := alice.New(loggingMiddleware, validateMiddleware(userSchema))
// 	router.Handle("/register", userChain).Methods("POST")
// 	router.Handle("/login", userChain).Methods("POST")

// 	// midlleware chain or routes for all project requests that do not requeare a request body
// 	projectChain := alice.New(loggingMiddleware, app.jwtMiddleware)
// 	router.Handle("/projects", projectChain.ThenFunc(app.getProjects)).Methods("GET")
// 	router.Handle("/projects/{xata_id}", projectChain.ThenFunc(app.getProject)).Methods("GET")
// 	router.Handle("/projects/{id}", projectChain.ThenFunc(deleteProject)).Methods("DELETE")


// 	// midlleware chain or routes for all project requests that  requeare a request body
// 	projectChainWithValidation := projectChain.Append(validateMiddleware(projectSchema))
// 	router.Handle("/projects", projectChainWithValidation.ThenFunc(app.createProject)).Methods("POST")
// 	router.Handle("/projects/{xata_id}", projectChainWithValidation.ThenFunc(app.updateProject)).Methods("PUT")


// 	log.Println("Listening on port 5000")
// 	log.Fatal(http.ListenAndServe(":5000", router))
// }

// // loadSchema loads a JSON schema from a file
// func loadSchema(filePath string) (string, error) {
// 	data, err := os.ReadFile(filePath)
// 	if err != nil {
// 		return "", err
// 	}
// 	return string(data), nil
// }

// func loggingMiddleware(next http.Handler) http.Handler {
// 	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 		log.Printf("%s %s %s\n", r.RemoteAddr, r.Method, r.URL)
// 		next.ServeHTTP(w, r)
// 	})
// }

// func (app *App) jwtMiddleware(next http.Handler) http.Handler {
// 	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 		authHeader := r.Header.Get("Authorization")
// 		if authHeader == "" {
// 			respondWithError(w, http.StatusUnauthorized, "No token provided")
// 			return
// 		}

// 		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
// 		claims := &Claims{}

// 		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
// 			return app.JWTKey, nil
// 		})

// 		if err != nil {
// 			if err == jwt.ErrSignatureInvalid {
// 				respondWithError(w, http.StatusUnauthorized, "Invalid token signature")
// 				return
// 			}
// 			respondWithError(w, http.StatusBadRequest, "Invalid token")
// 			return
// 		}

// 		if !token.Valid {
// 			respondWithError(w, http.StatusBadRequest, "Invalid token")
// 			return
// 		}

// 		ctx := context.WithValue(r.Context(), "claims", claims)
// 		next.ServeHTTP(w, r.WithContext(ctx))
// 	})
// }

// func validateMiddleware(schema string) func(http.Handler) http.Handler {
// 	return func(next http.Handler) http.Handler {
// 		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 			var body map[string]interface{}
// 			bodyBytes, err := io.ReadAll(r.Body)
// 			if err != nil {
// 				respondWithError(w, http.StatusBadRequest, "Invalid request payload")
// 				return
// 			}

// 			err = json.Unmarshal(bodyBytes, &body)
// 			if err != nil {
// 				respondWithError(w, http.StatusBadRequest, "Invalid request payload")
// 				return
// 			}

// 			schemaLoader := gojsonschema.NewStringLoader(schema)
// 			documentLoader := gojsonschema.NewGoLoader(body)
// 			result, err := gojsonschema.Validate(schemaLoader, documentLoader)
// 			if err != nil {
// 				respondWithError(w, http.StatusInternalServerError, "Error validating schema")
// 				return
// 			}

// 			if !result.Valid() {
// 				var errs []string
// 				for _, err := range result.Errors() {
// 					errs = append(errs, err.String())
// 				}
// 				respondWithError(w, http.StatusBadRequest, strings.Join(errs, ", "))
// 				return
// 			}

// 			r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
// 			next.ServeHTTP(w, r)
// 		})
// 	}
// }

// func respondWithError(w http.ResponseWriter, code int, message string) {
// 	w.Header().Set("Content-Type", "application/json")
// 	w.WriteHeader(code)
// 	json.NewEncoder(w).Encode(ErrorResponse{Message: message})
// }

// func (app *App) generateToken(username, xataID string) (string, error) {
// 	expirationTime := time.Now().Add(1 * time.Hour)

// 	claims := &Claims{
// 		Username: username,
// 		XataID:   xataID,
// 		RegisteredClaims: jwt.RegisteredClaims{
// 			ExpiresAt: jwt.NewNumericDate(expirationTime),
// 		},
// 	}
// 	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
// 	tokenString, err := token.SignedString(app.JWTKey)

// 	if err != nil {
// 		return "", err
// 	}
// 	return tokenString, nil
// }

// // Register function to handle user registration
// func (app *App) register(w http.ResponseWriter, r *http.Request) {
// 	var creds Credentials

// 	err := json.NewDecoder(r.Body).Decode(&creds)
// 	if err != nil {
// 		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
// 		return
// 	}

// 	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(creds.Password), bcrypt.DefaultCost)
// 	if err != nil {
// 		respondWithError(w, http.StatusInternalServerError, "Error hashing password")
// 		return
// 	}

// 	var xataID string
// 	err = app.DB.QueryRow("INSERT INTO users (username, password) VALUES ($1, $2) RETURNING xata_id", creds.Username, hashedPassword).Scan(&xataID)
// 	if err != nil {
// 		log.Printf("Error creating user: %v", err)
// 		respondWithError(w, http.StatusInternalServerError, "Error creating user")
// 		return
// 	}

// 	tokenString, err := app.generateToken(creds.Username, xataID)
// 	if err != nil {
// 		respondWithError(w, http.StatusInternalServerError, "Error generating token")
// 		return
// 	}

// 	w.Header().Set("Content-Type", "application/json")
// 	json.NewEncoder(w).Encode(UserResponse{XataID: xataID, Username: creds.Username, Token: tokenString})
// }

// // Login function to handle user login
// func (app *App) login(w http.ResponseWriter, r *http.Request) {
// 	var creds Credentials

// 	err := json.NewDecoder(r.Body).Decode(&creds)
// 	if err != nil {
// 		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
// 		return
// 	}

// 	var storedUsername, storedPassword, xataID string
// 	err = app.DB.QueryRow("SELECT xata_id, username, password FROM users WHERE username=$1", creds.Username).Scan(&xataID, &storedUsername, &storedPassword)
// 	if err != nil {
// 		if err == sql.ErrNoRows {
// 			respondWithError(w, http.StatusUnauthorized, "Invalid username or password")
// 			return
// 		}
// 		log.Printf("Error retrieving user: %v", err)
// 		respondWithError(w, http.StatusInternalServerError, "Error retrieving user")
// 		return
// 	}

// 	err = bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(creds.Password))
// 	if err != nil {
// 		respondWithError(w, http.StatusUnauthorized, "Invalid username or password")
// 		return
// 	}

// 	// Successful login: generate a token
// 	tokenString, err := app.generateToken(storedUsername, xataID)
// 	if err != nil {
// 		respondWithError(w, http.StatusInternalServerError, "Error generating token")
// 		return
// 	}

// 	w.Header().Set("Content-Type", "application/json")
// 	json.NewEncoder(w).Encode(UserResponse{XataID: xataID, Username: storedUsername, Token: tokenString})
// }




// // createProject
// func (app *App) createProject(w http.ResponseWriter, r *http.Request) {
// 	var project Project	

// 	err := json.NewDecoder(r.Body).Decode(&project)
// 	if err != nil {
// 		respondWithError(w, http.StatusBadRequest, "Invalid Request payload")
// 		return
// 	}

// 	cliams := r.Context().Value("claims").(*Cliams)
// 	userID:= claims.XataID

// 	var xataID string

// 	err = app.DB.QueryRow(
// 		"INSERT INTO projects (\"user\", name, repo_url, site_url, description, dependencies, dev_dependencies, status) VALUES($1, $2, $3, $4, $5, $6, $7, $8) RETURNING xata_id" userID, project.Name, project.RepoURL, project.SiteURL, project.Description, pq.Array(project.).Scan(&xataID)
// 	)
// 	if err != nil {
// 		respondWithError(w, http.StatusInternalServerError, "Error creating project ")
// 		return
// 	}

// 	project.XataID = xataID
// 	project.UserID = userID


// 	w.Header().Set("Content-Type", "application/json")
// 	json.NewEncoder(w).Encode(project)
// }

// // updateProject
// func (app *App) updateProject(w http.ResponseWriter, r *http.Request) {
// 	var project Project	

// 	err := json.NewDecoder(r.Body).Decode(&project)
// 	if err != nil {
// 		respondWithError(w, http.StatusBadRequest, "Invalid Request payload")
// 		return
// 	}

// 	cliams := r.Context().Value("claims").(*Cliams)
// 	userID:= claims.XataID

// 	vars := mux.Vars(r)
// 	xataID := vars["xata_id"]

// 	w.Header().Set("Content-Type", "application/json")
// 	json.NewEncoder(w).Encode(RouteResponse{Message: "Hello from updateProject", ID: id})
// }

// // getProjects handles getting all of specific users's projects
// func (app *App) getProjects(w http.ResponseWriter, r *http.Request) {
// 	claims := r.Context().Value("claims").(*Claims)
// 	userID := 	claims.XataID
// 	rows, err := app.DB.QueryRow("SELECT xata_id, \"user\", name, repo_url, site_url, description, dependencies, dev_dependencies, status FROM projects WHERE \"user\"=$1", userID)


// 	if err != nil {
// 		respondWithError(w, http.StatusInternalServerError, "Error fetching project ")
// 		return
// 	}
// 	deffer rows.Close()

// 	var projects []Project
// 	for rows.Next(){
// 		var project Projectapp
// 		var dependencies, DevDependencies []string
// 		err = rows.Scan(&project.XataID, &project.UserID, &project.Name, &project.RepoURL, &project.SiteURL, &project.Description, pq.Array(&dependencies), pq.Array(&devDependencies), &project.Status)
// 	}

// 	if err != nil {
// 		respondWithError(w, http.StatusInternalServerError, "Error scanning project ")
// 		return
// 	}

// 	project.Dependencies = dependencies
// 	project.DevDependencies = devDependencies
// 	project=append(project, project)


// 	err = rows.Err()
// 	if err != nil {
// 		respondWithError(w, http.StatusInternalServerError, "Error fetching project ")
// 		return
// 	}



// 	w.Header().Set("Content-Type", "application/json")
// 	json.NewEncoder(w).Encode(projects)
// }

// // getProject
// func (app *App) getProject(w http.ResponseWriter, r *http.Request) {
// 	vars := mux.Vars(r)
// 	xataID := vars["xata_id"]

// 	claims := r.Context().Value("claims").(*Claims)
// 	userID := 	claims.XataID

// 	var project Project
// 	var dependencies, devDependencies []string

// 	err := app.DB.Query("SELECT xata_id, \"user\", name, repo_url, site_url, description, dependencies, dev_dependencies, status FROM projects WHERE xata_id=$1 and \"user\"=$2", xataID, userID).Scan(&project.XataID, &project.UserID, &project.Name, &project.RepoURL, &project.SiteURL, &project.Description, pq.Array(&dependencies), pq.Array(&devDependencies), &project.Status)

// 	if err != nil {
// 		if err == sql.ErrNoRows {
// 			respondWithError(w, http.StatusNotFound, "Project not found ")
// 			return
// 		}
// 		respondWithError(w, http.StatusInternalServerError, "Error fetching project ")
// 		return
// 	}

// 	project.Dependencies = dependencies
// 	project.DevDependencies = devDependencies
// 	project=append(project, project)


	
// 	w.Header().Set("Content-Type", "application/json")
// 	json.NewEncoder(w).Encode(RouteResponse{Message: "Hello from getProject", ID: id})
// }

// // deleteProject
// func deleteProject(w http.ResponseWriter, r *http.Request) {
// 	vars := mux.Vars(r)
// 	id := vars["id"]

// 	w.Header().Set("Content-Type", "application/json")
// 	json.NewEncoder(w).Encode(RouteResponse{Message: "Hello from deleteProject", ID: id})
// }


















































































// TODO project does not work
// package main

// import (
// 	"bytes"
// 	"context"
// 	"database/sql"
// 	"encoding/json"
// 	"io"
// 	"log"
// 	"net/http"
// 	"os"
// 	"strings"
// 	"time"

// 	"github.com/golang-jwt/jwt/v5"
// 	"github.com/gorilla/mux"
// 	"github.com/joho/godotenv"
// 	"github.com/justinas/alice"
// 	"github.com/lib/pq"
// 	"github.com/xeipuuv/gojsonschema"
// 	"golang.org/x/crypto/bcrypt"
// )

// type App struct {
// 	DB     *sql.DB
// 	JWTKey []byte
// }

// type Credentials struct {
// 	Username string `json:"username,omitempty"`
// 	Password string `json:"password,omitempty"`
// }

// type Project struct {
// 	XataID         string   `json:"xata_id,omitempty"`
// 	UserID         string   `json:"user,omitempty"`
// 	Name           string   `json:"name,omitempty"`
// 	RepoURL        string   `json:"repo_url,omitempty"`
// 	SiteURL        string   `json:"site_url,omitempty"`
// 	Description    string   `json:"description,omitempty"`
// 	Dependencies   []string `json:"dependencies,omitempty"`
// 	DevDependencies []string `json:"dev_dependencies,omitempty"`
// 	Status         string   `json:"status,omitempty"`
// }

// type Claims struct {
// 	Username string `json:"username"`
// 	XataID   string `json:"xata_id"`
// 	jwt.RegisteredClaims
// }

// type UserResponse struct {
// 	XataID   string `json:"xata_id"`
// 	Username string `json:"username"`
// 	Token    string `json:"token"`
// }

// type ErrorResponse struct {
// 	Message string `json:"message"`
// }

// type RouteResponse struct {
// 	Message string `json:"message"`
// 	ID      string `json:"id,omitempty"`
// }

// func main() {
// 	err := godotenv.Load()
// 	if err != nil {
// 		log.Fatal("Error loading .env file")
// 	}

// 	// Load the schemas
// 	userSchema, loadErr := loadSchema("schemas/user.json")
// 	if loadErr != nil {
// 		log.Fatalf("Error loading user schema: %v", loadErr)
// 	}

// 	projectSchema, loadErr := loadSchema("schemas/project.json") // corrected project schema path
// 	if loadErr != nil {
// 		log.Fatalf("Error loading project schema: %v", loadErr)
// 	}

// 	JWTKey := []byte(os.Getenv("JWT_SECRET_KEY"))
// 	if len(JWTKey) == 0 {
// 		log.Fatal("Missing JWT_SECRET_KEY environment variable")
// 	}

// 	connStr := os.Getenv("XATA_PSQL_URL")
// 	if len(connStr) == 0 {
// 		log.Fatal("Missing XATA_PSQL_URL environment variable")
// 	}

// 	DB, err := sql.Open("postgres", connStr)
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	defer DB.Close()

// 	app := &App{DB: DB, JWTKey: JWTKey}

// 	log.Println("Starting server ...")
// 	router := mux.NewRouter()

// 	// Middleware chain and routes for user auth
// 	userChain := alice.New(loggingMiddleware, validateMiddleware(userSchema))
// 	router.Handle("/register", userChain.ThenFunc(app.register)).Methods("POST")
// 	router.Handle("/login", userChain.ThenFunc(app.login)).Methods("POST")

// 	// Middleware chain for project requests
// 	projectChain := alice.New(loggingMiddleware, app.jwtMiddleware)
// 	router.Handle("/projects", projectChain.ThenFunc(app.getProjects)).Methods("GET")
// 	router.Handle("/projects/{xata_id}", projectChain.ThenFunc(app.getProject)).Methods("GET")
// 	router.Handle("/projects/{xata_id}", projectChain.ThenFunc(app.deleteProject)).Methods("DELETE")

// 	// Project creation and update with validation middleware
// 	projectChainWithValidation := projectChain.Append(validateMiddleware(projectSchema))
// 	router.Handle("/projects", projectChainWithValidation.ThenFunc(app.createProject)).Methods("POST")
// 	router.Handle("/projects/{xata_id}", projectChainWithValidation.ThenFunc(app.updateProject)).Methods("PUT")

// 	log.Println("Listening on port 5000")
// 	log.Fatal(http.ListenAndServe(":5000", router))
// }

// // loadSchema loads a JSON schema from a file
// func loadSchema(filePath string) (string, error) {
// 	data, err := os.ReadFile(filePath)
// 	if err != nil {
// 		return "", err
// 	}
// 	return string(data), nil
// }

// func loggingMiddleware(next http.Handler) http.Handler {
// 	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 		log.Printf("%s %s %s\n", r.RemoteAddr, r.Method, r.URL)
// 		next.ServeHTTP(w, r)
// 	})
// }

// func (app *App) jwtMiddleware(next http.Handler) http.Handler {
// 	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 		authHeader := r.Header.Get("Authorization")
// 		if authHeader == "" {
// 			respondWithError(w, http.StatusUnauthorized, "No token provided")
// 			return
// 		}

// 		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
// 		claims := &Claims{}

// 		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
// 			return app.JWTKey, nil
// 		})

// 		if err != nil {
// 			if err == jwt.ErrSignatureInvalid {
// 				respondWithError(w, http.StatusUnauthorized, "Invalid token signature")
// 				return
// 			}
// 			respondWithError(w, http.StatusBadRequest, "Invalid token")
// 			return
// 		}

// 		if !token.Valid {
// 			respondWithError(w, http.StatusUnauthorized, "Invalid token")
// 			return
// 		}

// 		ctx := context.WithValue(r.Context(), "claims", claims)
// 		next.ServeHTTP(w, r.WithContext(ctx))
// 	})
// }

// func validateMiddleware(schema string) func(http.Handler) http.Handler {
// 	return func(next http.Handler) http.Handler {
// 		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 			var body map[string]interface{}
// 			bodyBytes, err := io.ReadAll(r.Body)
// 			if err != nil {
// 				respondWithError(w, http.StatusBadRequest, "Invalid request payload")
// 				return
// 			}

// 			err = json.Unmarshal(bodyBytes, &body)
// 			if err != nil {
// 				respondWithError(w, http.StatusBadRequest, "Invalid request payload")
// 				return
// 			}

// 			schemaLoader := gojsonschema.NewStringLoader(schema)
// 			documentLoader := gojsonschema.NewGoLoader(body)
// 			result, err := gojsonschema.Validate(schemaLoader, documentLoader)
// 			if err != nil {
// 				respondWithError(w, http.StatusInternalServerError, "Error validating schema")
// 				return
// 			}

// 			if !result.Valid() {
// 				var errs []string
// 				for _, err := range result.Errors() {
// 					errs = append(errs, err.String())
// 				}
// 				respondWithError(w, http.StatusBadRequest, strings.Join(errs, ", "))
// 				return
// 			}

// 			r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
// 			next.ServeHTTP(w, r)
// 		})
// 	}
// }

// func respondWithError(w http.ResponseWriter, code int, message string) {
// 	w.Header().Set("Content-Type", "application/json")
// 	w.WriteHeader(code)
// 	json.NewEncoder(w).Encode(ErrorResponse{Message: message})
// }

// func (app *App) generateToken(username, xataID string) (string, error) {
// 	expirationTime := time.Now().Add(1 * time.Hour)

// 	claims := &Claims{
// 		Username: username,
// 		XataID:   xataID,
// 		RegisteredClaims: jwt.RegisteredClaims{
// 			ExpiresAt: jwt.NewNumericDate(expirationTime),
// 		},
// 	}
// 	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
// 	return token.SignedString(app.JWTKey)
// }

// // Register function
// func (app *App) register(w http.ResponseWriter, r *http.Request) {
// 	var creds Credentials

// 	err := json.NewDecoder(r.Body).Decode(&creds)
// 	if err != nil {
// 		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
// 		return
// 	}

// 	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(creds.Password), bcrypt.DefaultCost)
// 	if err != nil {
// 		respondWithError(w, http.StatusInternalServerError, "Error hashing password")
// 		return
// 	}

// 	var xataID string
// 	err = app.DB.QueryRow("INSERT INTO users (username, password) VALUES ($1, $2) RETURNING xata_id", creds.Username, hashedPassword).Scan(&xataID)
// 	if err != nil {
// 		log.Printf("Error creating user: %v", err)
// 		respondWithError(w, http.StatusInternalServerError, "Error creating user")
// 		return
// 	}

// 	tokenString, err := app.generateToken(creds.Username, xataID)
// 	if err != nil {
// 		respondWithError(w, http.StatusInternalServerError, "Error generating token")
// 		return
// 	}

// 	w.Header().Set("Content-Type", "application/json")
// 	json.NewEncoder(w).Encode(UserResponse{XataID: xataID, Username: creds.Username, Token: tokenString})
// }

// // Login function
// func (app *App) login(w http.ResponseWriter, r *http.Request) {
// 	var creds Credentials

// 	err := json.NewDecoder(r.Body).Decode(&creds)
// 	if err != nil {
// 		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
// 		return
// 	}

// 	var storedUsername, storedPassword, xataID string
// 	err = app.DB.QueryRow("SELECT xata_id, username, password FROM users WHERE username=$1", creds.Username).Scan(&xataID, &storedUsername, &storedPassword)
// 	if err != nil {
// 		if err == sql.ErrNoRows {
// 			respondWithError(w, http.StatusUnauthorized, "User not found")
// 			return
// 		}
// 		respondWithError(w, http.StatusInternalServerError, "Error querying user")
// 		return
// 	}

// 	err = bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(creds.Password))
// 	if err != nil {
// 		respondWithError(w, http.StatusUnauthorized, "Invalid credentials")
// 		return
// 	}

// 	tokenString, err := app.generateToken(storedUsername, xataID)
// 	if err != nil {
// 		respondWithError(w, http.StatusInternalServerError, "Error generating token")
// 		return
// 	}

// 	w.Header().Set("Content-Type", "application/json")
// 	json.NewEncoder(w).Encode(UserResponse{XataID: xataID, Username: storedUsername, Token: tokenString})
// }




// // Create Project
// func (app *App) createProject(w http.ResponseWriter, r *http.Request) {
// 	var project Project

// 	err := json.NewDecoder(r.Body).Decode(&project)
// 	if err != nil {
// 		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
// 		return
// 	}

// 	claims, ok := r.Context().Value("claims").(*Claims)
// 	if !ok {
// 		respondWithError(w, http.StatusUnauthorized, "Unauthorized")
// 		return
// 	}

// 	// Set the UserID to the current user's XataID from the token
// 	project.UserID = claims.XataID

// 	err = app.DB.QueryRow("INSERT INTO projects (user_id, name, repo_url, site_url, description, dependencies, dev_dependencies, status) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING xata_id",
// 		project.UserID, project.Name, project.RepoURL, project.SiteURL, project.Description, pq.Array(project.Dependencies), pq.Array(project.DevDependencies), project.Status).Scan(&project.XataID)

// 	if err != nil {
// 		respondWithError(w, http.StatusInternalServerError, "Error creating project")
// 		return
// 	}

// 	w.Header().Set("Content-Type", "application/json")
// 	json.NewEncoder(w).Encode(project)
// }

// // Get all Projects
// func (app *App) getProjects(w http.ResponseWriter, r *http.Request) {
// 	claims, ok := r.Context().Value("claims").(*Claims)
// 	if !ok {
// 		respondWithError(w, http.StatusUnauthorized, "Unauthorized")
// 		return
// 	}

// 	rows, err := app.DB.Query("SELECT xata_id, name, repo_url, site_url, description, dependencies, dev_dependencies, status FROM projects WHERE user_id = $1", claims.XataID)
// 	if err != nil {
// 		respondWithError(w, http.StatusInternalServerError, "Error fetching projects")
// 		return
// 	}
// 	defer rows.Close()

// 	var projects []Project
// 	for rows.Next() {
// 		var project Project
// 		var dependencies, devDependencies []string

// 		err := rows.Scan(&project.XataID, &project.Name, &project.RepoURL, &project.SiteURL, &project.Description, pq.Array(&dependencies), pq.Array(&devDependencies), &project.Status)
// 		if err != nil {
// 			respondWithError(w, http.StatusInternalServerError, "Error scanning project data")
// 			return
// 		}

// 		project.Dependencies = dependencies
// 		project.DevDependencies = devDependencies
// 		projects = append(projects, project)
// 	}

// 	w.Header().Set("Content-Type", "application/json")
// 	json.NewEncoder(w).Encode(projects)
// }

// // Get a single Project by XataID
// func (app *App) getProject(w http.ResponseWriter, r *http.Request) {
// 	claims, ok := r.Context().Value("claims").(*Claims)
// 	if !ok {
// 		respondWithError(w, http.StatusUnauthorized, "Unauthorized")
// 		return
// 	}

// 	vars := mux.Vars(r)
// 	xataID := vars["xata_id"]

// 	var project Project
// 	var dependencies, devDependencies []string

// 	err := app.DB.QueryRow("SELECT xata_id, name, repo_url, site_url, description, dependencies, dev_dependencies, status FROM projects WHERE xata_id = $1 AND user_id = $2", xataID, claims.XataID).Scan(
// 		&project.XataID, &project.Name, &project.RepoURL, &project.SiteURL, &project.Description, pq.Array(&dependencies), pq.Array(&devDependencies), &project.Status)

// 	if err != nil {
// 		if err == sql.ErrNoRows {
// 			respondWithError(w, http.StatusNotFound, "Project not found")
// 			return
// 		}
// 		respondWithError(w, http.StatusInternalServerError, "Error fetching project")
// 		return
// 	}

// 	project.Dependencies = dependencies
// 	project.DevDependencies = devDependencies

// 	w.Header().Set("Content-Type", "application/json")
// 	json.NewEncoder(w).Encode(project)
// }

// // Update a Project by XataID
// func (app *App) updateProject(w http.ResponseWriter, r *http.Request) {
// 	vars := mux.Vars(r)
// 	xataID := vars["xata_id"]

// 	var project Project

// 	err := json.NewDecoder(r.Body).Decode(&project)
// 	if err != nil {
// 		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
// 		return
// 	}

// 	claims, ok := r.Context().Value("claims").(*Claims)
// 	if !ok {
// 		respondWithError(w, http.StatusUnauthorized, "Unauthorized")
// 		return
// 	}

// 	// Ensure the project belongs to the logged-in user
// 	_, err = app.DB.Exec("UPDATE projects SET name=$1, repo_url=$2, site_url=$3, description=$4, dependencies=$5, dev_dependencies=$6, status=$7 WHERE xata_id=$8 AND user_id=$9",
// 		project.Name, project.RepoURL, project.SiteURL, project.Description, pq.Array(project.Dependencies), pq.Array(project.DevDependencies), project.Status, xataID, claims.XataID)

// 	if err != nil {
// 		respondWithError(w, http.StatusInternalServerError, "Error updating project")
// 		return
// 	}

// 	respondWithMessage(w, http.StatusOK, "Project updated successfully")
// }

// // Delete a Project by XataID
// func (app *App) deleteProject(w http.ResponseWriter, r *http.Request) {
// 	claims, ok := r.Context().Value("claims").(*Claims)
// 	if !ok {
// 		respondWithError(w, http.StatusUnauthorized, "Unauthorized")
// 		return
// 	}

// 	vars := mux.Vars(r)
// 	xataID := vars["xata_id"]

// 	// Delete the project if it belongs to the logged-in user
// 	result, err := app.DB.Exec("DELETE FROM projects WHERE xata_id = $1 AND user_id = $2", xataID, claims.XataID)
// 	if err != nil {
// 		respondWithError(w, http.StatusInternalServerError, "Error deleting project")
// 		return
// 	}

// 	rowsAffected, err := result.RowsAffected()
// 	if err != nil {
// 		respondWithError(w, http.StatusInternalServerError, "Error checking deletion status")
// 		return
// 	}

// 	if rowsAffected == 0 {
// 		respondWithError(w, http.StatusNotFound, "Project not found")
// 		return
// 	}

// 	respondWithMessage(w, http.StatusOK, "Project deleted successfully")
// }

// func respondWithMessage(w http.ResponseWriter, code int, message string) {
// 	w.Header().Set("Content-Type", "application/json")
// 	w.WriteHeader(code)
// 	json.NewEncoder(w).Encode(RouteResponse{Message: message})
// }
























































































































































// package main

// import (
// 	"context"
// 	"database/sql"
// 	"encoding/json"
// 	"log"
// 	"net/http"
// 	"os"
// 	"strings"
// 	"time"

// 	"github.com/golang-jwt/jwt/v5"
// 	"github.com/gorilla/mux"
// 	"github.com/joho/godotenv"
// 	"github.com/justinas/alice"
// 	"github.com/lib/pq"
// 	"golang.org/x/crypto/bcrypt"
// )

// type App struct {
// 	DB     *sql.DB
// 	JWTKey []byte
// }

// type Credentials struct {
// 	Username string `json:"username,omitempty"`
// 	Password string `json:"password,omitempty"`
// }

// type Project struct {
// 	XataID          string   `json:"xata_id,omitempty"`
// 	UserID          string   `json:"user,omitempty"`
// 	Name            string   `json:"name,omitempty"`
// 	RepoURL         string   `json:"repo_url,omitempty"`
// 	SiteURL         string   `json:"site_url,omitempty"`
// 	Description     string   `json:"description,omitempty"`
// 	Dependencies    []string `json:"dependencies,omitempty"`
// 	DevDependencies []string `json:"dev_dependencies,omitempty"`
// 	Status          string   `json:"status,omitempty"`
// }

// type Claims struct {
// 	Username string `json:"username"`
// 	XataID   string `json:"xata_id"`
// 	jwt.RegisteredClaims
// }

// type UserResponse struct {
// 	XataID   string `json:"xata_id"`
// 	Username string `json:"username"`
// 	Token    string `json:"token"`
// }

// type ErrorResponse struct {
// 	Message string `json:"message"`
// }

// type RouteResponse struct {
// 	Message string `json:"message"`
// 	ID      string `json:"id,omitempty"`
// }

// func main() {
// 	err := godotenv.Load()
// 	if err != nil {
// 		log.Fatal("Error loading .env file")
// 	}

// 	JWTKey := []byte(os.Getenv("JWT_SECRET_KEY"))
// 	if len(JWTKey) == 0 {
// 		log.Fatal("Missing JWT_SECRET_KEY environment variable")
// 	}

// 	connStr := os.Getenv("XATA_PSQL_URL")
// 	if len(connStr) == 0 {
// 		log.Fatal("Missing XATA_PSQL_URL environment variable")
// 	}

// 	DB, err := sql.Open("postgres", connStr)
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	defer DB.Close()

// 	app := &App{DB: DB, JWTKey: JWTKey}

// 	log.Println("Starting server ...")
// 	router := mux.NewRouter()

// 	// Middleware chain and routes for user auth
// 	router.Handle("/register", alice.New(loggingMiddleware).ThenFunc(app.register)).Methods("POST")
// 	router.Handle("/login", alice.New(loggingMiddleware).ThenFunc(app.login)).Methods("POST")

// 	// Middleware chain for project requests
// 	projectChain := alice.New(loggingMiddleware, app.jwtMiddleware)
// 	router.Handle("/projects", projectChain.ThenFunc(app.getProjects)).Methods("GET")
// 	router.Handle("/projects", projectChain.ThenFunc(app.createProject)).Methods("POST")

// 	log.Println("Listening on port 5000")
// 	log.Fatal(http.ListenAndServe(":5000", router))
// }

// func loggingMiddleware(next http.Handler) http.Handler {
// 	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 		log.Printf("%s %s %s\n", r.RemoteAddr, r.Method, r.URL)
// 		next.ServeHTTP(w, r)
// 	})
// }

// func (app *App) jwtMiddleware(next http.Handler) http.Handler {
// 	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 		authHeader := r.Header.Get("Authorization")
// 		if authHeader == "" {
// 			respondWithError(w, http.StatusUnauthorized, "No token provided")
// 			return
// 		}

// 		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
// 		claims := &Claims{}

// 		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
// 			return app.JWTKey, nil
// 		})

// 		if err != nil {
// 			if err == jwt.ErrSignatureInvalid {
// 				respondWithError(w, http.StatusUnauthorized, "Invalid token signature")
// 				return
// 			}
// 			respondWithError(w, http.StatusBadRequest, "Invalid token")
// 			return
// 		}

// 		if !token.Valid {
// 			respondWithError(w, http.StatusUnauthorized, "Invalid token")
// 			return
// 		}

// 		ctx := context.WithValue(r.Context(), "claims", claims)
// 		next.ServeHTTP(w, r.WithContext(ctx))
// 	})
// }

// func respondWithError(w http.ResponseWriter, code int, message string) {
// 	w.Header().Set("Content-Type", "application/json")
// 	w.WriteHeader(code)
// 	json.NewEncoder(w).Encode(ErrorResponse{Message: message})
// }

// func (app *App) generateToken(username, xataID string) (string, error) {
// 	expirationTime := time.Now().Add(1 * time.Hour)

// 	claims := &Claims{
// 		Username: username,
// 		XataID:   xataID,
// 		RegisteredClaims: jwt.RegisteredClaims{
// 			ExpiresAt: jwt.NewNumericDate(expirationTime),
// 		},
// 	}
// 	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
// 	return token.SignedString(app.JWTKey)
// }

// // Register function
// func (app *App) register(w http.ResponseWriter, r *http.Request) {
// 	var creds Credentials

// 	err := json.NewDecoder(r.Body).Decode(&creds)
// 	if err != nil {
// 		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
// 		return
// 	}

// 	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(creds.Password), bcrypt.DefaultCost)
// 	if err != nil {
// 		respondWithError(w, http.StatusInternalServerError, "Error hashing password")
// 		return
// 	}

// 	var xataID string
// 	err = app.DB.QueryRow("INSERT INTO users (username, password) VALUES ($1, $2) RETURNING xata_id", creds.Username, hashedPassword).Scan(&xataID)
// 	if err != nil {
// 		log.Printf("Error creating user: %v", err)
// 		respondWithError(w, http.StatusInternalServerError, "Error creating user")
// 		return
// 	}

// 	tokenString, err := app.generateToken(creds.Username, xataID)
// 	if err != nil {
// 		respondWithError(w, http.StatusInternalServerError, "Error generating token")
// 		return
// 	}

// 	w.Header().Set("Content-Type", "application/json")
// 	json.NewEncoder(w).Encode(UserResponse{XataID: xataID, Username: creds.Username, Token: tokenString})
// }

// // Login function
// func (app *App) login(w http.ResponseWriter, r *http.Request) {
// 	var creds Credentials

// 	err := json.NewDecoder(r.Body).Decode(&creds)
// 	if err != nil {
// 		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
// 		return
// 	}

// 	var storedUsername, storedPassword, xataID string
// 	err = app.DB.QueryRow("SELECT xata_id, username, password FROM users WHERE username=$1", creds.Username).Scan(&xataID, &storedUsername, &storedPassword)
// 	if err != nil {
// 		if err == sql.ErrNoRows {
// 			respondWithError(w, http.StatusUnauthorized, "User not found")
// 			return
// 		}
// 		respondWithError(w, http.StatusInternalServerError, "Error querying user")
// 		return
// 	}

// 	err = bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(creds.Password))
// 	if err != nil {
// 		respondWithError(w, http.StatusUnauthorized, "Invalid credentials")
// 		return
// 	}

// 	tokenString, err := app.generateToken(storedUsername, xataID)
// 	if err != nil {
// 		respondWithError(w, http.StatusInternalServerError, "Error generating token")
// 		return
// 	}

// 	w.Header().Set("Content-Type", "application/json")
// 	json.NewEncoder(w).Encode(UserResponse{XataID: xataID, Username: storedUsername, Token: tokenString})
// }

// // Create Project function
// func (app *App) createProject(w http.ResponseWriter, r *http.Request) {
// 	var project Project

// 	err := json.NewDecoder(r.Body).Decode(&project)
// 	if err != nil {
// 		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
// 		return
// 	}

// 	claims, ok := r.Context().Value("claims").(*Claims)
// 	if !ok {
// 		respondWithError(w, http.StatusUnauthorized, "Unauthorized")
// 		return
// 	}

// 	// Set the UserID to the current user's XataID from the token
// 	project.UserID = claims.XataID

// 	err = app.DB.QueryRow("INSERT INTO projects (user_id, name, repo_url, site_url, description, dependencies, dev_dependencies, status) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING xata_id",
// 		project.UserID, project.Name, project.RepoURL, project.SiteURL, project.Description, pq.Array(project.Dependencies), pq.Array(project.DevDependencies), project.Status).Scan(&project.XataID)

// 	if err != nil {
// 		log.Printf("Error creating project: %v", err) // Log the error
// 		respondWithError(w, http.StatusInternalServerError, "Error creating project")
// 		return
// 	}

// 	w.Header().Set("Content-Type", "application/json")
// 	json.NewEncoder(w).Encode(project)
// }

// // Get all Projects function
// func (app *App) getProjects(w http.ResponseWriter, r *http.Request) {
// 	claims, ok := r.Context().Value("claims").(*Claims)
// 	if !ok {
// 		respondWithError(w, http.StatusUnauthorized, "Unauthorized")
// 		return
// 	}

// 	rows, err := app.DB.Query("SELECT xata_id, user_id, name, repo_url, site_url, description, dependencies, dev_dependencies, status FROM projects WHERE user_id = $1", claims.XataID)
// 	if err != nil {
// 		respondWithError(w, http.StatusInternalServerError, "Error retrieving projects")
// 		return
// 	}
// 	defer rows.Close()

// 	var projects []Project
// 	for rows.Next() {
// 		var project Project
// 		if err := rows.Scan(&project.XataID, &project.UserID, &project.Name, &project.RepoURL, &project.SiteURL, &project.Description, pq.Array(&project.Dependencies), pq.Array(&project.DevDependencies), &project.Status); err != nil {
// 			respondWithError(w, http.StatusInternalServerError, "Error scanning projects")
// 			return
// 		}
// 		projects = append(projects, project)
// 	}

// 	w.Header().Set("Content-Type", "application/json")
// 	json.NewEncoder(w).Encode(projects)
// }








































