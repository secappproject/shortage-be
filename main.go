package main

import (
    "database/sql"
    "encoding/json"
    "errors"
    "fmt"
    "log"
    "net/http"
    "os"
    "time"

    "github.com/gin-contrib/cors"
    "github.com/gin-gonic/gin"
    "github.com/joho/godotenv"
    _ "github.com/lib/pq"
)

func mustGetEnv(key string) string {
    value, ok := os.LookupEnv(key)
    if !ok || value == "" {
        log.Fatalf("❌ Missing required environment variable: %s", key)
    }
    return value
}

func max(nums ...int) int {
    if len(nums) == 0 {
        return 0
    }
    maxVal := nums[0]
    for _, num := range nums[1:] {
        if num > maxVal {
            maxVal = num
        }
    }
    return maxVal
}

func sum(nums ...int) int {
    total := 0
    for _, num := range nums {
        total += num
    }
    return total
}

type User struct {
    ID          int            `json:"id"`
    Username    string         `json:"username"`
    Password    string         `json:"-"`
    Role        string         `json:"role"`
    CompanyName sql.NullString `json:"companyName"`
    VendorType  sql.NullString `json:"vendorType"`
}

type UserRequest struct {
    Username    string         `json:"username" binding:"required"`
    Password    string         `json:"password,omitempty"`
    Role        string         `json:"role" binding:"required"`
    CompanyName sql.NullString `json:"companyName"`
    VendorType  sql.NullString `json:"vendorType"`
}

type LoginRequest struct {
    Username string `json:"username" binding:"required"`
    Password string `json:"password" binding:"required"`
}

type Vendor struct {
    ID          int       `json:"id"`
    CompanyName string    `json:"companyName" binding:"required"`
    VendorType  string    `json:"vendorType" binding:"required"`
    CreatedAt   time.Time `json:"createdAt"`
    UpdatedAt   time.Time `json:"updatedAt"`
}


type BOM struct {
    ID                  int       `json:"id"`
    BomCode             string    `json:"bomCode" binding:"required"`
    VersionTag          string    `json:"versionTag"` 
    PartReference       string    `json:"partReference"`
    Material            string    `json:"material" binding:"required"`
    MaterialDescription string    `json:"materialDescription"`
    Qty                 int       `json:"qty" binding:"required"`
    CreatedAt           time.Time `json:"createdAt"`
    UpdatedAt           time.Time `json:"updatedAt"`
}

type Project struct {
    ID          int            `json:"id"`
    WbsNumber   string         `json:"wbsNumber" binding:"required"`
    ProjectName string         `json:"projectName" binding:"required"`
    VendorName  sql.NullString `json:"vendorName"`
    CreatedAt   time.Time      `json:"createdAt"`
    UpdatedAt   time.Time      `json:"updatedAt"`
}

type ActualPart struct {
    Material string   `json:"material"`
    Qty      int      `json:"qty"`
    Views    []string `json:"views"`
}

type ProjectTrackingPayload struct {
    ID                int            `json:"id"`
    ProjectID         sql.NullInt64  `json:"projectId"`
    SwitchboardName   string         `json:"switchboardName" binding:"required"`
    CompartmentNumber string         `json:"compartmentNumber" binding:"required"`
    MechAssemblyBy    sql.NullString `json:"mechAssemblyBy"`
    WiringType        sql.NullString `json:"wiringType"`
    WiringBy          sql.NullString `json:"wiringBy"`
    StatusTest        string         `json:"statusTest" binding:"required"`
    TestedBy          sql.NullString `json:"testedBy"`
    DateTested        sql.NullTime   `json:"dateTested"`
    ActualParts       []ActualPart   `json:"actualParts"`
}

type ProjectTrackingView struct {
    ID                int             `json:"id"`
    ProjectID         sql.NullInt64   `json:"projectId"`
    ProjectName       sql.NullString  `json:"projectName"`
    WbsNumber         sql.NullString  `json:"wbsNumber"`
    SwitchboardName   string          `json:"switchboardName"`
    CompartmentNumber string          `json:"compartmentNumber"`
    MechAssemblyBy    sql.NullString  `json:"mechAssemblyBy"`
    WiringType        sql.NullString  `json:"wiringType"`
    WiringBy          sql.NullString  `json:"wiringBy"`
    StatusTest        string          `json:"statusTest"`
    TestedBy          sql.NullString  `json:"testedBy"`
    DateTested        sql.NullTime    `json:"dateTested"`
    ActualParts       json.RawMessage `json:"actualParts"`
    DetectionSettings json.RawMessage `json:"detectionSettings"`
    DetectionResults  json.RawMessage `json:"detectionResults"`
}

type DetectionSavePayload struct {
    Settings json.RawMessage `json:"settings"`
    Results  json.RawMessage `json:"results"`
}

type CompareItemDetail struct {
    Material   string `json:"material"`
    BomQty     int    `json:"bomQty"`
    ActualQty  int    `json:"actualQty"`
    Difference int    `json:"difference"`
    Status     string `json:"status"`
    PIC        string `json:"pic"`
}


type ComparisonPayload struct {
    BomCode    string `json:"bomCode" binding:"required"`
    VersionTag string `json:"versionTag"`
    TrackingID int    `json:"trackingId" binding:"required"`
}

type ComparisonView struct {
    ID                int             `json:"id"`
    BomCode           string          `json:"bomCode"`
    VersionTag        string          `json:"versionTag"`
    TrackingID        int             `json:"trackingId"`
    ProjectName       sql.NullString  `json:"projectName"`
    WbsNumber         sql.NullString  `json:"wbsNumber"`
    SwitchboardName   string          `json:"switchboardName"`
    CompartmentNumber string          `json:"compartmentNumber"`
    CreatedAt         time.Time       `json:"createdAt"`
    ShortageItems     json.RawMessage `json:"shortageItems"`
    ExcessItems       json.RawMessage `json:"excessItems"`
    UnlistedItems     json.RawMessage `json:"unlistedItems"`
}

type ComparisonDetailView struct {
    Comparison       ComparisonView  `json:"comparison"`
    DetectionResults json.RawMessage `json:"detectionResults"`
}

type ComparisonUpdatePayload struct {
    ShortageItems json.RawMessage `json:"shortageItems"`
    ExcessItems   json.RawMessage `json:"excessItems"`
    UnlistedItems json.RawMessage `json:"unlistedItems"`
}

type SetActiveVersionPayload struct {
	BomCode    string `json:"bomCode" binding:"required"`
	VersionTag string `json:"versionTag" binding:"required"`
}

var db *sql.DB

func getVersionTag(tag string) string {
    if tag == "" {
        return "default" 
    }
    return tag
}

func main() {
    if err := godotenv.Load(); err != nil {
        log.Println("⚠️  No .env file found — assuming production environment")
    }
    host := mustGetEnv("POSTGRES_HOST")
    user := mustGetEnv("POSTGRES_USER")
    password := mustGetEnv("POSTGRES_PASSWORD")
    dbname := mustGetEnv("POSTGRES_DB")
    port := mustGetEnv("POSTGRES_PORT")

    sslmode := "disable"
    if host == "localhost" || host == "127.0.0.1" || host == "shortage2_db" {
        sslmode = "disable"
    }

    connStr := fmt.Sprintf(
        "host=%s user=%s password=%s dbname=%s port=%s sslmode=%s",
        host, user, password, dbname, port, sslmode,
    )

    var err error
    db, err = sql.Open("postgres", connStr)
    if err != nil {
        log.Fatal("❌ Failed to open database connection:", err)
    }
    defer db.Close()

    if err := db.Ping(); err != nil {
        log.Fatal("❌ Database ping failed:", err)
    }


    log.Println("✅ Connected to PostgreSQL successfully!")
    createTablesInfo()

    router := gin.Default()
    router.RedirectTrailingSlash = true
    config := cors.Config{
        AllowOrigins:     []string{"http://178.18.249.69:3000", "http://localhost:3000", "http://localhost:3001"},
        AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
        AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization", "X-User-Role"},
        ExposeHeaders:    []string{"Content-Length"},
        AllowCredentials: true,
        MaxAge:           12 * time.Hour,
    }
    router.Use(cors.New(config))

    api := router.Group("/api")

    {
        api.POST("/login", loginUser)

        users := api.Group("/users")
        users.Use(AuthMiddleware())
        users.Use(AdminAuthMiddleware())
        {
            users.GET("/", getUsers)
            users.POST("/", createUser)
            users.PUT("/:id", updateUser)
            users.DELETE("/:id", deleteUser)
        }

        vendors := api.Group("/vendors")
        vendors.Use(AuthMiddleware())
        vendors.Use(AdminAuthMiddleware())
        {
            vendors.GET("/vendor-type", getVendorTypes)
            vendors.GET("/companies", getCompanies)
            vendors.GET("/", getVendors)
            vendors.POST("/", createVendor)
            vendors.PUT("/:id", updateVendor)
            vendors.DELETE("/:id", deleteVendor)
        }

        boms := api.Group("/boms")
        boms.Use(AuthMiddleware())
        boms.Use(AdminAuthMiddleware())
        {
            boms.POST("/", createBom)
            boms.GET("/", getBoms)
            boms.GET("/:id", getBom)
            boms.PUT("/:id", updateBom)
            boms.DELETE("/:id", deleteBom)
            boms.GET("/materials", getBomMaterials)
            boms.GET("/codes", getBomCodes)
            boms.GET("/versions/:bomCode", getBomVersions) 
            boms.GET("/active-version/:bomCode", getActiveBomVersion)
			boms.PUT("/active-version", setActiveBomVersion)
        }

        projects := api.Group("/projects")
        projects.Use(AuthMiddleware())
        projects.Use(AdminAuthMiddleware())
        {
            projects.GET("/", getProjects)
            projects.POST("/", createProject)
            projects.PUT("/:id", updateProject)
            projects.DELETE("/:id", deleteProject)
        }

        tracking := api.Group("/tracking")
        tracking.Use(AuthMiddleware())
        {
            tracking.GET("/", getProjectTrackingList)
            tracking.GET("/:id", getProjectTracking)
            tracking.POST("/", PicOrAdminAuthMiddleware(), createProjectTracking)
            tracking.PUT("/:id", PicOrAdminAuthMiddleware(), updateProjectTracking)
            tracking.DELETE("/:id", AdminAuthMiddleware(), deleteProjectTracking)
            tracking.PUT("/:id/detection-results", PicOrAdminAuthMiddleware(), saveDetectionResults)
            tracking.DELETE("/:id/detection-results", PicOrAdminAuthMiddleware(), resetDetectionResults)
        }


        comparisons := api.Group("/comparisons")
        comparisons.Use(AuthMiddleware())
        comparisons.Use(AdminAuthMiddleware())
        {
            comparisons.GET("/", getSavedComparisons)
            comparisons.POST("/", createSavedComparison)
            comparisons.GET("/:id", getSavedComparisonDetail)
            comparisons.PUT("/:id", updateComparisonTasks)
            comparisons.DELETE("/:id", deleteSavedComparison)
        }
        api.GET("/compare", AuthMiddleware(), getCompareResult)
    }
    router.GET("/", func(c *gin.Context) {
        c.JSON(200, gin.H{"status": "API running"})
    })

    port = os.Getenv("PORT")
    if port == "" {
        port = "8080"
    }

    fmt.Printf("🚀 Server Go berjalan di port %s\n", port)
    if err := router.Run(":" + port); err != nil {
        log.Fatal("❌ Failed to start server:", err)
    }

}

func createTablesInfo() {
    log.Println("--- INFO PEMBUATAN TABEL (SKEMA BARU) ---")
    log.Println("1. vendors, 2. users, 3. bom (DIUBAH! tambah kolom 'version_tag'), 4. projects") 
    log.Println("5. project_tracking (DIUBAH! kolom 'views_tested' dihapus)")
    log.Println("6. actual_parts (TABEL BARU! menggantikan 'detected_parts')")
    log.Println("7. comparison (DIUBAH! tambah kolom 'version_tag')") 
}

func loginUser(c *gin.Context) {
    var req LoginRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Username dan password dibutuhkan"})
        return
    }

    var user User
    err := db.QueryRow(
        "SELECT id, username, password, role, company_name, vendor_type FROM users WHERE username = $1",
        req.Username,
    ).Scan(&user.ID, &user.Username, &user.Password, &user.Role, &user.CompanyName, &user.VendorType)

    if err != nil {
        if errors.Is(err, sql.ErrNoRows) {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "Username atau password salah"})
            return
        }
        log.Printf("Error querying user: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal login"})
        return
    }

    if user.Password != req.Password {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Username atau password salah"})
        return
    }

    c.JSON(http.StatusOK, gin.H{
        "username":    user.Username,
        "role":        user.Role,
        "companyName": user.CompanyName.String,
        "vendorType":  user.VendorType.String,
    })
}

func AuthMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        if c.Request.Method == "OPTIONS" {
            c.Next()
            return
        }

        role := c.GetHeader("X-User-Role")
        if role == "" {
            c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Header X-User-Role dibutuhkan"})
            return
        }
        c.Next()
    }
}

func AdminAuthMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        role := c.GetHeader("X-User-Role")
        if role != "Admin" && role != "admin" {
            c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Akses ditolak: Hanya Admin yang diizinkan"})
            return
        }
        c.Next()
    }
}

func PicOrAdminAuthMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        role := c.GetHeader("X-User-Role")
        if role != "Admin" && role != "admin" && role != "PIC" {
            c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Akses ditolak: Hanya Admin atau PIC yang diizinkan"})
            return
        }
        c.Next()
    }
}

func getUsers(c *gin.Context) {
    rows, err := db.Query("SELECT id, username, role, company_name, vendor_type FROM users ORDER BY username")
    if err != nil {
        log.Printf("Error querying users: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal mengambil data pengguna"})
        return
    }
    defer rows.Close()

    users := make([]User, 0)
    for rows.Next() {
        var u User
        if err := rows.Scan(&u.ID, &u.Username, &u.Role, &u.CompanyName, &u.VendorType); err != nil {
            log.Printf("Error scanning user: %v", err)
            c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal memindai data pengguna"})
            return
        }
        users = append(users, u)
    }

    c.JSON(http.StatusOK, users)
}

func createUser(c *gin.Context) {
    var req UserRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Input tidak valid: " + err.Error()})
        return
    }

    if req.Password == "" {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Password dibutuhkan untuk pengguna baru"})
        return
    }
    if req.Role == "External/Vendor" && (!req.CompanyName.Valid || req.CompanyName.String == "") {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Nama Perusahaan (Company Name) dibutuhkan untuk role Vendor"})
        return
    }

    var newID int
    err := db.QueryRow(
        `INSERT INTO users (username, password, role, company_name, vendor_type)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING id`,
        req.Username, req.Password, req.Role, req.CompanyName, req.VendorType,
    ).Scan(&newID)

    if err != nil {
        log.Printf("Error creating user: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal membuat pengguna: " + err.Error()})
        return
    }

    var newUser User
    err = db.QueryRow(
        "SELECT id, username, role, company_name, vendor_type FROM users WHERE id = $1", newID,
    ).Scan(&newUser.ID, &newUser.Username, &newUser.Role, &newUser.CompanyName, &newUser.VendorType)
    if err != nil {
        log.Printf("Error fetching newly created user: %v", err)
        c.JSON(http.StatusCreated, gin.H{"id": newID, "username": req.Username, "role": req.Role, "companyName": req.CompanyName, "vendorType": req.VendorType})
        return
    }

    c.JSON(http.StatusCreated, newUser)
}

func updateUser(c *gin.Context) {
    id := c.Param("id")
    var req UserRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Input tidak valid: " + err.Error()})
        return
    }

    if req.Role == "External/Vendor" && (!req.CompanyName.Valid || req.CompanyName.String == "") {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Nama Perusahaan (Company Name) dibutuhkan untuk role Vendor"})
        return
    }

    if req.Password != "" {
        _, err := db.Exec(
            `UPDATE users SET username=$1, role=$2, company_name=$3, vendor_type=$4, password=$5
             WHERE id=$6`,
            req.Username, req.Role, req.CompanyName, req.VendorType, req.Password, id,
        )
        if err != nil {
            log.Printf("Error updating user with password: %v", err)
            c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal update pengguna: " + err.Error()})
            return
        }
    } else {
        _, err := db.Exec(
            `UPDATE users SET username=$1, role=$2, company_name=$3, vendor_type=$4
             WHERE id=$5`,
            req.Username, req.Role, req.CompanyName, req.VendorType, id,
        )
        if err != nil {
            log.Printf("Error updating user w/o password: %v", err)
            c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal update pengguna: " + err.Error()})
            return
        }
    }

    c.JSON(http.StatusOK, gin.H{"message": "Pengguna berhasil diupdate", "id": id, "username": req.Username, "role": req.Role})
}

func deleteUser(c *gin.Context) {
    id := c.Param("id")

    _, err := db.Exec("DELETE FROM users WHERE id = $1", id)
    if err != nil {
        log.Printf("Error deleting user: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal menghapus pengguna"})
        return
    }

    c.JSON(http.StatusOK, gin.H{"message": "Pengguna berhasil dihapus"})
}

func getCompanies(c *gin.Context) {
    rows, err := db.Query("SELECT DISTINCT company_name FROM vendors ORDER BY company_name")
    if err != nil {
        log.Printf("Error querying companies: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal mengambil daftar perusahaan"})
        return
    }
    defer rows.Close()

    companies := make([]string, 0)
    for rows.Next() {
        var company string
        if err := rows.Scan(&company); err != nil {
            log.Printf("Error scanning company: %v", err)
            c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal memindai nama perusahaan"})
            return
        }
        companies = append(companies, company)
    }

    c.JSON(http.StatusOK, companies)
}

func getVendorTypes(c *gin.Context) {
    rows, err := db.Query("SELECT DISTINCT vendor_type FROM vendors ORDER BY vendor_type")
    if err != nil {
        log.Printf("Error querying vendor types: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal mengambil daftar tipe vendor"})
        return
    }
    defer rows.Close()

    types := make([]string, 0)
    for rows.Next() {
        var vtype string
        if err := rows.Scan(&vtype); err != nil {
            log.Printf("Error scanning vendor type: %v", err)
            c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal memindai tipe vendor"})
            return
        }
        types = append(types, vtype)
    }

    c.JSON(http.StatusOK, types)
}

func getVendors(c *gin.Context) {
    rows, err := db.Query("SELECT id, company_name, vendor_type, created_at, updated_at FROM vendors ORDER BY company_name")
    if err != nil {
        log.Printf("Error querying vendors: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal mengambil data vendor"})
        return
    }
    defer rows.Close()

    vendors := make([]Vendor, 0)
    for rows.Next() {
        var v Vendor
        if err := rows.Scan(&v.ID, &v.CompanyName, &v.VendorType, &v.CreatedAt, &v.UpdatedAt); err != nil {
            log.Printf("Error scanning vendor: %v", err)
            c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal memindai data vendor"})
            return
        }
        vendors = append(vendors, v)
    }

    c.JSON(http.StatusOK, vendors)
}

func createVendor(c *gin.Context) {
    var v Vendor
    if err := c.ShouldBindJSON(&v); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Input tidak valid: " + err.Error()})
        return
    }

    err := db.QueryRow(
        `INSERT INTO vendors (company_name, vendor_type)
         VALUES ($1, $2)
         RETURNING id, created_at, updated_at`,
        v.CompanyName, v.VendorType,
    ).Scan(&v.ID, &v.CreatedAt, &v.UpdatedAt)

    if err != nil {
        log.Printf("Error creating vendor: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal membuat vendor: " + err.Error()})
        return
    }

    c.JSON(http.StatusCreated, v)
}

func updateVendor(c *gin.Context) {
    id := c.Param("id")
    var v Vendor
    if err := c.ShouldBindJSON(&v); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Input tidak valid: " + err.Error()})
        return
    }

    _, err := db.Exec(
        `UPDATE vendors SET company_name=$1, vendor_type=$2, updated_at=NOW()
         WHERE id=$3`,
        v.CompanyName, v.VendorType, id,
    )
    if err != nil {
        log.Printf("Error updating vendor: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal update vendor: " + err.Error()})
        return
    }

    c.JSON(http.StatusOK, gin.H{"message": "Vendor berhasil diupdate", "id": id})
}

func deleteVendor(c *gin.Context) {
    id := c.Param("id")

    _, err := db.Exec("DELETE FROM vendors WHERE id = $1", id)
    if err != nil {
        log.Printf("Error deleting vendor: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal menghapus vendor"})
        return
    }

    c.JSON(http.StatusOK, gin.H{"message": "Vendor berhasil dihapus"})
}


func createBom(c *gin.Context) {
    var bom BOM
    if err := c.ShouldBindJSON(&bom); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Input tidak valid: " + err.Error()})
        return
    }

    bom.VersionTag = getVersionTag(bom.VersionTag)

    err := db.QueryRow(
        `INSERT INTO bom (bom_code, version_tag, part_reference, material, material_description, qty)
         VALUES ($1, $2, $3, $4, $5, $6)
         RETURNING id, created_at, updated_at`,
        bom.BomCode, bom.VersionTag, bom.PartReference, bom.Material, bom.MaterialDescription, bom.Qty,
    ).Scan(&bom.ID, &bom.CreatedAt, &bom.UpdatedAt)

    if err != nil {
        log.Printf("Error creating BOM: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal membuat BOM: " + err.Error()})
        return
    }

    c.JSON(http.StatusCreated, bom)
}

func getBoms(c *gin.Context) {
    rows, err := db.Query(`
        SELECT id, bom_code, version_tag, part_reference, material, material_description, qty, created_at, updated_at 
        FROM bom 
        ORDER BY bom_code, version_tag, material
    `) // Query diubah
    if err != nil {
        log.Printf("Error querying BOMs: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal mengambil data BOM"})
        return
    }
    defer rows.Close()

    boms := make([]BOM, 0)
    for rows.Next() {
        var b BOM
        if err := rows.Scan(&b.ID, &b.BomCode, &b.VersionTag, &b.PartReference, &b.Material, &b.MaterialDescription, &b.Qty, &b.CreatedAt, &b.UpdatedAt); err != nil {
            log.Printf("Error scanning BOM: %v", err)
            c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal memindai data BOM"})
            return
        }
        boms = append(boms, b)
    }

    c.JSON(http.StatusOK, boms)
}

func getBom(c *gin.Context) {
    id := c.Param("id")
    var b BOM
    err := db.QueryRow(`
        SELECT id, bom_code, version_tag, part_reference, material, material_description, qty, created_at, updated_at 
        FROM bom 
        WHERE id = $1
    `, id).Scan(&b.ID, &b.BomCode, &b.VersionTag, &b.PartReference, &b.Material, &b.MaterialDescription, &b.Qty, &b.CreatedAt, &b.UpdatedAt) // Scan diubah

    if err != nil {
        if errors.Is(err, sql.ErrNoRows) {
            c.JSON(http.StatusNotFound, gin.H{"error": "BOM tidak ditemukan"})
            return
        }
        log.Printf("Error querying BOM: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal mengambil data BOM"})
        return
    }

    c.JSON(http.StatusOK, b)
}

func updateBom(c *gin.Context) {
    id := c.Param("id")
    var bom BOM
    if err := c.ShouldBindJSON(&bom); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Input tidak valid: " + err.Error()})
        return
    }

    bom.VersionTag = getVersionTag(bom.VersionTag)

    _, err := db.Exec(
        `UPDATE bom 
         SET bom_code=$1, version_tag=$2, part_reference=$3, material=$4, material_description=$5, qty=$6, updated_at=NOW()
         WHERE id=$7`,
        bom.BomCode, bom.VersionTag, bom.PartReference, bom.Material, bom.MaterialDescription, bom.Qty, id,
    )
    if err != nil {
        log.Printf("Error updating BOM: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal update BOM: " + err.Error()})
        return
    }

    c.JSON(http.StatusOK, gin.H{"message": "BOM berhasil diupdate", "id": id})
}

func deleteBom(c *gin.Context) {
    id := c.Param("id")

    _, err := db.Exec("DELETE FROM bom WHERE id = $1", id)
    if err != nil {
        log.Printf("Error deleting BOM: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal menghapus BOM: " + err.Error()})
        return
    }

    c.JSON(http.StatusOK, gin.H{"message": "BOM berhasil dihapus"})
}

func getBomMaterials(c *gin.Context) {
    rows, err := db.Query("SELECT material, MIN(material_description) as material_description FROM bom GROUP BY material ORDER BY material")
    if err != nil {
        log.Printf("Error querying bom materials: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal mengambil daftar material"})
        return
    }
    defer rows.Close()

    type BomMaterial struct {
        Material            string `json:"material"`
        MaterialDescription string `json:"materialDescription"`
    }
    materials := make([]BomMaterial, 0)
    for rows.Next() {
        var m BomMaterial
        if err := rows.Scan(&m.Material, &m.MaterialDescription); err != nil {
            log.Printf("Error scanning bom material: %v", err)
            continue
        }
        materials = append(materials, m)
    }
    c.JSON(http.StatusOK, materials)
}

func getBomCodes(c *gin.Context) {
    rows, err := db.Query("SELECT DISTINCT bom_code FROM bom ORDER BY bom_code")
    if err != nil {
        log.Printf("Error querying bom codes: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal mengambil daftar BOM code"})
        return
    }
    defer rows.Close()

    codes := make([]string, 0)
    for rows.Next() {
        var code string
        if err := rows.Scan(&code); err != nil {
            log.Printf("Error scanning bom code: %v", err)
            c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal memindai BOM code"})
            return
        }
        codes = append(codes, code)
    }

    c.JSON(http.StatusOK, codes)
}

func getBomVersions(c *gin.Context) {
    bomCode := c.Param("bomCode")
    rows, err := db.Query(`
        SELECT DISTINCT version_tag 
        FROM bom 
        WHERE bom_code = $1 
        ORDER BY version_tag
    `, bomCode)
    if err != nil {
        log.Printf("Error querying bom versions: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal mengambil daftar versi BOM"})
        return
    }
    defer rows.Close()

    versions := make([]string, 0)
    for rows.Next() {
        var v string
        if err := rows.Scan(&v); err != nil {
            log.Printf("Error scanning bom version: %v", err)
            continue
        }
        versions = append(versions, v)
    }

    c.JSON(http.StatusOK, versions)
}

func getActiveBomVersion(c *gin.Context) {
	bomCode := c.Param("bomCode")
	var activeVersion string

	err := db.QueryRow(
		`SELECT active_version_tag FROM bom_active_versions WHERE bom_code = $1`,
		bomCode,
	).Scan(&activeVersion)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusOK, gin.H{"bomCode": bomCode, "activeVersion": "default"})
			return
		}
		log.Printf("Error querying active BOM version: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal mengambil versi aktif"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"bomCode": bomCode, "activeVersion": activeVersion})
}

func setActiveBomVersion(c *gin.Context) {
	var payload SetActiveVersionPayload
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Input tidak valid: " + err.Error()})
		return
	}

	var exists bool
	err := db.QueryRow(
		`SELECT EXISTS(SELECT 1 FROM bom WHERE bom_code = $1 AND version_tag = $2)`,
		payload.BomCode, payload.VersionTag,
	).Scan(&exists)

	if err != nil || !exists {
		log.Printf("Error checking if version exists or it does not exist: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Versi yang dipilih tidak ada untuk BOM Code ini"})
		return
	}

	_, err = db.Exec(
		`INSERT INTO bom_active_versions (bom_code, active_version_tag)
         VALUES ($1, $2)
         ON CONFLICT (bom_code) DO UPDATE
         SET active_version_tag = EXCLUDED.active_version_tag`,
		payload.BomCode, payload.VersionTag,
	)

	if err != nil {
		log.Printf("Error setting active BOM version: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal menyimpan versi aktif"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"bomCode": payload.BomCode, "activeVersion": payload.VersionTag})
}
func createProject(c *gin.Context) {
    var p Project
    if err := c.ShouldBindJSON(&p); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Input tidak valid: " + err.Error()})
        return
    }

    err := db.QueryRow(
        `INSERT INTO projects (wbs_number, project_name, vendor_name)
         VALUES ($1, $2, $3)
         RETURNING id, created_at, updated_at`,
        p.WbsNumber, p.ProjectName, p.VendorName,
    ).Scan(&p.ID, &p.CreatedAt, &p.UpdatedAt)

    if err != nil {
        log.Printf("Error creating project: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal membuat project: " + err.Error()})
        return
    }

    c.JSON(http.StatusCreated, p)
}

func getProjects(c *gin.Context) {
    rows, err := db.Query(`
        SELECT id, wbs_number, project_name, vendor_name, created_at, updated_at 
        FROM projects 
        ORDER BY project_name
    `)
    if err != nil {
        log.Printf("Error querying projects: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal mengambil data project"})
        return
    }
    defer rows.Close()

    projects := make([]Project, 0)
    for rows.Next() {
        var p Project
        if err := rows.Scan(&p.ID, &p.WbsNumber, &p.ProjectName, &p.VendorName, &p.CreatedAt, &p.UpdatedAt); err != nil {
            log.Printf("Error scanning project: %v", err)
            c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal memindai data project"})
            return
        }
        projects = append(projects, p)
    }

    c.JSON(http.StatusOK, projects)
}

func updateProject(c *gin.Context) {
    id := c.Param("id")
    var p Project
    if err := c.ShouldBindJSON(&p); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Input tidak valid: " + err.Error()})
        return
    }

    _, err := db.Exec(
        `UPDATE projects 
         SET wbs_number=$1, project_name=$2, vendor_name=$3, updated_at=NOW()
         WHERE id=$4`,
        p.WbsNumber, p.ProjectName, p.VendorName, id,
    )
    if err != nil {
        log.Printf("Error updating project: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal update project: " + err.Error()})
        return
    }

    c.JSON(http.StatusOK, gin.H{"message": "Project berhasil diupdate", "id": id})
}

func deleteProject(c *gin.Context) {
    id := c.Param("id")

    var count int
    err := db.QueryRow("SELECT COUNT(*) FROM project_tracking WHERE project_id = $1", id).Scan(&count)
    if err == nil && count > 0 {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Gagal menghapus: Project masih digunakan di data tracking."})
        return
    }

    _, err = db.Exec("DELETE FROM projects WHERE id = $1", id)
    if err != nil {
        log.Printf("Error deleting project: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal menghapus project"})
        return
    }

    c.JSON(http.StatusOK, gin.H{"message": "Project berhasil dihapus"})
}

// PERBAIKAN: Konstanta yang hilang ditambahkan di sini
const projectTrackingQueryBase = `
    WITH aggregated_parts AS (
        SELECT
            tracking_id,
            COALESCE(jsonb_agg(jsonb_build_object(
                'material', material, 
                'qty', actual_qty, 
                'views', views
            )), '[]') AS actual_parts_data
        FROM actual_parts
        GROUP BY tracking_id
    )
    SELECT 
        t.id,
        t.project_id,
        p.project_name,
        p.wbs_number,
        t.switchboard_name,
        t.compartment_number,
        t.mech_assembly_by,
        t.wiring_type,
        t.wiring_by,
        t.status_test,
        t.tested_by,
        t.date_tested,
        COALESCE(ap.actual_parts_data, '[]') as actual_parts,
        COALESCE(t.detection_settings, 'null'::jsonb) as detection_settings,
        COALESCE(t.detection_results, 'null'::jsonb) as detection_results

    FROM project_tracking t
    LEFT JOIN projects p ON t.project_id = p.id
    LEFT JOIN aggregated_parts ap ON ap.tracking_id = t.id
`

func getProjectTrackingList(c *gin.Context) {
    query := projectTrackingQueryBase + `
        ORDER BY 
            p.project_name, t.switchboard_name, t.compartment_number
    `

    rows, err := db.Query(query)
    if err != nil {
        log.Printf("Error querying project tracking: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal mengambil data tracking: " + err.Error()})
        return
    }
    defer rows.Close()

    trackingList := make([]ProjectTrackingView, 0)
    for rows.Next() {
        var t ProjectTrackingView
        if err := rows.Scan(
            &t.ID,
            &t.ProjectID,
            &t.ProjectName,
            &t.WbsNumber,
            &t.SwitchboardName,
            &t.CompartmentNumber,
            &t.MechAssemblyBy,
            &t.WiringType,
            &t.WiringBy,
            &t.StatusTest,
            &t.TestedBy,
            &t.DateTested,
            &t.ActualParts,
            &t.DetectionSettings,
            &t.DetectionResults,
        ); err != nil {
            log.Printf("Error scanning tracking: %v", err)
            c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal memindai data tracking: " + err.Error()})
            return
        }
        trackingList = append(trackingList, t)
    }

    c.JSON(http.StatusOK, trackingList)
}
func getProjectTracking(c *gin.Context) {
    id := c.Param("id")

    query := projectTrackingQueryBase + `
        WHERE t.id = $1
    `

    var t ProjectTrackingView
    err := db.QueryRow(query, id).Scan(
        &t.ID,
        &t.ProjectID,
        &t.ProjectName,
        &t.WbsNumber,
        &t.SwitchboardName,
        &t.CompartmentNumber,
        &t.MechAssemblyBy,
        &t.WiringType,
        &t.WiringBy,
        &t.StatusTest,
        &t.TestedBy,
        &t.DateTested,
        &t.ActualParts,
        &t.DetectionSettings,
        &t.DetectionResults,
    )

    if err != nil {
        if errors.Is(err, sql.ErrNoRows) {
            c.JSON(http.StatusNotFound, gin.H{"error": "Data tracking tidak ditemukan"})
            return
        }
        log.Printf("Error querying single tracking: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal mengambil data tracking: " + err.Error()})
        return
    }

    c.JSON(http.StatusOK, t)
}

func createProjectTracking(c *gin.Context) {
	var p ProjectTrackingPayload
	if err := c.ShouldBindJSON(&p); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Input tidak valid: " + err.Error()})
		return
	}

	if p.ActualParts == nil {
		p.ActualParts = []ActualPart{}
	}

	tx, err := db.Begin()
	if err != nil {
		log.Printf("Error starting transaction: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal memulai transaksi"})
		return
	}

	if !p.ProjectID.Valid && p.NewProjectName.Valid && p.NewProjectName.String != "" && p.NewWbsNumber.Valid && p.NewWbsNumber.String != "" {
		var newProjectID int64
		err := tx.QueryRow(
			`INSERT INTO projects (project_name, wbs_number)
			 VALUES ($1, $2)
			 RETURNING id`,
			p.NewProjectName.String, p.NewWbsNumber.String,
		).Scan(&newProjectID)

		if err != nil {
			tx.Rollback()
			log.Printf("Error creating new project during tracking creation: %v", err)
			if pqErr, ok := err.(*pq.Error); ok && pqErr.Code == "23505" {
				c.JSON(http.StatusConflict, gin.H{"error": "Gagal membuat project baru: Nama Project atau WBS Number sudah ada."})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal membuat project baru: " + err.Error()})
			return
		}

		p.ProjectID = sql.NullInt64{Int64: newProjectID, Valid: true}

	} else if !p.ProjectID.Valid && (p.NewProjectName.Valid || p.NewWbsNumber.Valid) {
		tx.Rollback()
		c.JSON(http.StatusBadRequest, gin.H{"error": "Untuk project baru, Nama Project dan WBS Number wajib diisi."})
		return
	}

	var newTrackingID int
	err = tx.QueryRow(
		`INSERT INTO project_tracking (
            project_id, switchboard_name, compartment_number, mech_assembly_by, 
            wiring_type, wiring_by, status_test, tested_by, date_tested
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
         RETURNING id`,
		p.ProjectID, 
		p.SwitchboardName, p.CompartmentNumber, p.MechAssemblyBy,
		p.WiringType, p.WiringBy, p.StatusTest, p.TestedBy, p.DateTested,
	).Scan(&newTrackingID)

	if err != nil {
		tx.Rollback()
		log.Printf("Error creating tracking (step 1): %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal membuat tracking: " + err.Error()})
		return
	}

	if len(p.ActualParts) > 0 {
		stmt, err := tx.Prepare(`INSERT INTO actual_parts (tracking_id, material, actual_qty, views) VALUES ($1, $2, $3, $4)`)
		if err != nil {
			tx.Rollback()
			log.Printf("Error preparing statement (step 2): %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal menyiapkan insert parts"})
			return
		}
		defer stmt.Close()

		for _, part := range p.ActualParts {
			viewsJSON, err := json.Marshal(part.Views)
			if err != nil {
				tx.Rollback()
				log.Printf("Error marshalling views for part '%s': %v", part.Material, err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal memproses data views"})
				return
			}

			if _, err := stmt.Exec(newTrackingID, part.Material, part.Qty, viewsJSON); err != nil {
				tx.Rollback()
				log.Printf("Error inserting part '%s': %v", part.Material, err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal menyimpan actual part: " + err.Error()})
				return
			}
		}
	}

	if err := tx.Commit(); err != nil {
		log.Printf("Error committing transaction: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal menyelesaikan transaksi"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "Tracking berhasil dibuat", "id": newTrackingID})
}

func updateProjectTracking(c *gin.Context) {
    id := c.Param("id")
    var p ProjectTrackingPayload
    if err := c.ShouldBindJSON(&p); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Input tidak valid: " + err.Error()})
        return
    }

    if p.ActualParts == nil {
        p.ActualParts = []ActualPart{}
    }

    tx, err := db.Begin()
    if err != nil {
        log.Printf("Error starting transaction: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal memulai transaksi"})
        return
    }

    _, err = tx.Exec(
        `UPDATE project_tracking SET
            project_id=$1, switchboard_name=$2, compartment_number=$3, mech_assembly_by=$4, 
            wiring_type=$5, wiring_by=$6, status_test=$7, 
            tested_by=$8, date_tested=$9, updated_at=NOW()
         WHERE id=$10`,
        p.ProjectID, p.SwitchboardName, p.CompartmentNumber, p.MechAssemblyBy,
        p.WiringType, p.WiringBy, p.StatusTest, p.TestedBy, p.DateTested, id,
    )
    if err != nil {
        tx.Rollback()
        log.Printf("Error updating tracking (step 1): %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal update tracking: " + err.Error()})
        return
    }

    _, err = tx.Exec(`DELETE FROM actual_parts WHERE tracking_id = $1`, id)
    if err != nil {
        tx.Rollback()
        log.Printf("Error deleting old parts (step 2): %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal membersihkan parts lama"})
        return
    }

    if len(p.ActualParts) > 0 {
        stmt, err := tx.Prepare(`INSERT INTO actual_parts (tracking_id, material, actual_qty, views) VALUES ($1, $2, $3, $4)`)
        if err != nil {
            tx.Rollback()
            log.Printf("Error preparing statement (step 3): %v", err)
            c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal menyiapkan insert parts"})
            return
        }
        defer stmt.Close()

        trackingIDInt, _ := c.Params.Get("id")
        for _, part := range p.ActualParts {
            viewsJSON, err := json.Marshal(part.Views)
            if err != nil {
                tx.Rollback()
                log.Printf("Error marshalling views for part '%s': %v", part.Material, err)
                c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal memproses data views"})
                return
            }

            if _, err := stmt.Exec(trackingIDInt, part.Material, part.Qty, viewsJSON); err != nil {
                tx.Rollback()
                log.Printf("Error inserting part '%s': %v", part.Material, err)
                c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal menyimpan actual part: " + err.Error()})
                return
            }
        }
    }

    if err := tx.Commit(); err != nil {
        log.Printf("Error committing transaction: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal menyelesaikan transaksi"})
        return
    }

    c.JSON(http.StatusOK, gin.H{"message": "Tracking berhasil diupdate", "id": id})
}

func deleteProjectTracking(c *gin.Context) {
    id := c.Param("id")

    _, err := db.Exec("DELETE FROM project_tracking WHERE id = $1", id)
    if err != nil {
        log.Printf("Error deleting tracking: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal menghapus tracking: " + err.Error()})
        return
    }

    c.JSON(http.StatusOK, gin.H{"message": "Tracking berhasil dihapus"})
}

func saveDetectionResults(c *gin.Context) {
    id := c.Param("id")
    var payload DetectionSavePayload
    if err := c.ShouldBindJSON(&payload); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Input tidak valid: " + err.Error()})
        return
    }

    _, err := db.Exec(
        `UPDATE project_tracking 
         SET detection_settings=$1, detection_results=$2, updated_at=NOW()
         WHERE id=$3`,
        payload.Settings, payload.Results, id,
    )

    if err != nil {
        log.Printf("Error saving detection results: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal menyimpan hasil deteksi"})
        return
    }
    c.JSON(http.StatusOK, gin.H{"message": "Hasil deteksi berhasil disimpan"})
}

func resetDetectionResults(c *gin.Context) {
    id := c.Param("id")
    _, err := db.Exec(
        `UPDATE project_tracking 
         SET detection_settings=NULL, detection_results=NULL, updated_at=NOW()
         WHERE id=$1`,
        id,
    )

    if err != nil {
        log.Printf("Error resetting detection results: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal mereset hasil deteksi"})
        return
    }
    c.JSON(http.StatusOK, gin.H{"message": "Hasil deteksi berhasil direset"})
}


func runComparisonLogic(bomCode string, versionTag string, trackingId string) ([]CompareItemDetail, []CompareItemDetail, []CompareItemDetail, error) {
    query := `
        WITH bom_parts AS (
            SELECT material, qty AS bom_qty
            FROM bom
            WHERE bom_code = $1 AND version_tag = $2
        ),
        actual_parts_list AS (
            SELECT material, actual_qty
            FROM actual_parts
            WHERE tracking_id = $3
        )
        SELECT
            COALESCE(b.material, a.material) AS material,
            COALESCE(b.bom_qty, 0) AS bom_qty,
            COALESCE(a.actual_qty, 0) AS actual_qty,
            (COALESCE(a.actual_qty, 0) - COALESCE(b.bom_qty, 0)) AS difference
        FROM bom_parts b
        FULL OUTER JOIN actual_parts_list a ON b.material = a.material
        ORDER BY material;
    `

    rows, err := db.Query(query, bomCode, versionTag, trackingId)
    if err != nil {
        log.Printf("Error querying compare logic: %v", err)
        return nil, nil, nil, err
    }
    defer rows.Close()

    shortageItems := make([]CompareItemDetail, 0)
    excessItems := make([]CompareItemDetail, 0)
    unlistedItems := make([]CompareItemDetail, 0)

    for rows.Next() {
        var item CompareItemDetail
        if err := rows.Scan(&item.Material, &item.BomQty, &item.ActualQty, &item.Difference); err != nil {
            log.Printf("Error scanning compare row: %v", err)
            continue
        }

        item.Status = "Belum Ada Status"
        item.PIC = ""

        if item.Difference < 0 {
            shortageItems = append(shortageItems, item)
        } else if item.Difference > 0 {
            if item.BomQty == 0 {
                unlistedItems = append(unlistedItems, item)
            } else {
                excessItems = append(excessItems, item)
            }
        }
    }
    return shortageItems, excessItems, unlistedItems, nil
}

func getSavedComparisons(c *gin.Context) {
    query := `
        SELECT 
            comp.id, comp.bom_code, comp.version_tag, comp.tracking_id, comp.created_at,
            p.project_name, p.wbs_number, t.switchboard_name, t.compartment_number,
            COALESCE(comp.shortage_items, '[]'::jsonb) as shortage_items,
            COALESCE(comp.excess_items, '[]'::jsonb) as excess_items,
            COALESCE(comp.unlisted_items, '[]'::jsonb) as unlisted_items
        FROM comparison comp
        JOIN project_tracking t ON comp.tracking_id = t.id
        LEFT JOIN projects p ON t.project_id = p.id
        ORDER BY comp.created_at DESC
    ` 
    rows, err := db.Query(query)
    if err != nil {
        log.Printf("Error querying saved comparisons: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal mengambil data perbandingan"})
        return
    }
    defer rows.Close()

    comparisons := make([]ComparisonView, 0)
    for rows.Next() {
        var v ComparisonView
        if err := rows.Scan(
            &v.ID, &v.BomCode, &v.VersionTag, &v.TrackingID, &v.CreatedAt,
            &v.ProjectName, &v.WbsNumber, &v.SwitchboardName, &v.CompartmentNumber,
            &v.ShortageItems, &v.ExcessItems, &v.UnlistedItems,
        ); err != nil {
            log.Printf("Error scanning saved comparison: %v", err)
            continue
        }
        comparisons = append(comparisons, v)
    }
    c.JSON(http.StatusOK, comparisons)
}

func createSavedComparison(c *gin.Context) {
    var payload ComparisonPayload
    if err := c.ShouldBindJSON(&payload); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Input tidak valid: " + err.Error()})
        return
    }

    payload.VersionTag = getVersionTag(payload.VersionTag)

    shortage, excess, unlisted, err := runComparisonLogic(payload.BomCode, payload.VersionTag, fmt.Sprintf("%d", payload.TrackingID))
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal menjalankan logika perbandingan"})
        return
    }

    shortageJSON, _ := json.Marshal(shortage)
    excessJSON, _ := json.Marshal(excess)
    unlistedJSON, _ := json.Marshal(unlisted)

    var newID int
    err = db.QueryRow(
        `INSERT INTO comparison (bom_code, version_tag, tracking_id, shortage_items, excess_items, unlisted_items) 
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (bom_code, version_tag, tracking_id) DO UPDATE SET
            shortage_items = EXCLUDED.shortage_items,
            excess_items = EXCLUDED.excess_items,
            unlisted_items = EXCLUDED.unlisted_items,
            created_at = NOW()
         RETURNING id`,
        payload.BomCode, payload.VersionTag, payload.TrackingID, shortageJSON, excessJSON, unlistedJSON,
    ).Scan(&newID)

    if err != nil {
        log.Printf("Error creating saved comparison: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal menyimpan perbandingan"})
        return
    }

    c.JSON(http.StatusCreated, gin.H{"id": newID, "message": "Perbandingan berhasil disimpan/diperbarui"})
}

func getSavedComparisonDetail(c *gin.Context) {
    id := c.Param("id")

    var comparison ComparisonView
    var detectionResults json.RawMessage

    query := `
        SELECT 
            comp.id, comp.bom_code, comp.version_tag, comp.tracking_id, comp.created_at,
            p.project_name, p.wbs_number, t.switchboard_name, t.compartment_number,
            COALESCE(comp.shortage_items, '[]'::jsonb) as shortage_items,
            COALESCE(comp.excess_items, '[]'::jsonb) as excess_items,
            COALESCE(comp.unlisted_items, '[]'::jsonb) as unlisted_items,
            COALESCE(t.detection_results, 'null'::jsonb) as detection_results
        FROM comparison comp
        JOIN project_tracking t ON comp.tracking_id = t.id
        LEFT JOIN projects p ON t.project_id = p.id
        WHERE comp.id = $1
    ` 
    err := db.QueryRow(query, id).Scan(
        &comparison.ID, &comparison.BomCode, &comparison.VersionTag, &comparison.TrackingID, &comparison.CreatedAt, 
        &comparison.ProjectName, &comparison.WbsNumber, &comparison.SwitchboardName, &comparison.CompartmentNumber,
        &comparison.ShortageItems, &comparison.ExcessItems, &comparison.UnlistedItems,
        &detectionResults,
    )

    if err != nil {
        if errors.Is(err, sql.ErrNoRows) {
            c.JSON(http.StatusNotFound, gin.H{"error": "Data perbandingan tidak ditemukan"})
            return
        }
        log.Printf("Error querying comparison detail: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal mengambil data perbandingan"})
        return
    }

    response := ComparisonDetailView{
        Comparison:       comparison,
        DetectionResults: detectionResults,
    }

    c.JSON(http.StatusOK, response)
}

func updateComparisonTasks(c *gin.Context) {
    id := c.Param("id")
    var payload ComparisonUpdatePayload

    if err := c.ShouldBindJSON(&payload); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Input tidak valid: " + err.Error()})
        return
    }

    _, err := db.Exec(
        `UPDATE comparison 
         SET shortage_items = $1, excess_items = $2, unlisted_items = $3
         WHERE id = $4`,
        payload.ShortageItems, payload.ExcessItems, payload.UnlistedItems, id,
    )

    if err != nil {
        log.Printf("Error updating comparison tasks: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal menyimpan perubahan task"})
        return
    }

    c.JSON(http.StatusOK, gin.H{"message": "Perubahan berhasil disimpan"})
}

func deleteSavedComparison(c *gin.Context) {
    id := c.Param("id")
    _, err := db.Exec("DELETE FROM comparison WHERE id = $1", id)
    if err != nil {
        log.Printf("Error deleting saved comparison: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal menghapus perbandingan"})
        return
    }
    c.JSON(http.StatusOK, gin.H{"message": "Perbandingan berhasil dihapus"})
}

func getCompareResult(c *gin.Context) {
    bomCode := c.Query("bomCode")
    versionTag := getVersionTag(c.Query("versionTag")) 
    trackingId := c.Query("trackingId")

    if bomCode == "" || trackingId == "" {
        c.JSON(http.StatusBadRequest, gin.H{"error": "bomCode dan trackingId wajib diisi"})
        return
    }

    shortage, excess, unlisted, err := runComparisonLogic(bomCode, versionTag, trackingId) 
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal menjalankan logika perbandingan"})
        return
    }

    c.JSON(http.StatusOK, gin.H{
        "shortageItems": shortage,
        "excessItems":   excess,
        "unlistedItems": unlisted,
    })
}
