// El paquete server contiene el código del servidor.
// Interactúa con el cliente mediante una API JSON/HTTP
package server

import (
	"bytes"
	"compress/zlib"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"prac/pkg/api"
	"sync"

	"strconv"
	"strings"

	"prac/pkg/cifrado"

	"prac/pkg/store"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/joho/godotenv"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/argon2"
)

var currentHospital string
var currentSpecialty string

// server encapsula el estado de nuestro servidor
type server struct {
	db                 store.Store // base de datos
	log                *log.Logger // logger para mensajes de error e información
	tokenCounter       int64       // contador para generar tokens
	contadorIDPaciente int64
	contadorIDMedico   int64
}

var (
	CryptoKey         string     // Cambiar por una clave segura o leerla de configuración
	CryptoAlgorithm   = "AES256" // Algoritmo a usar
	CryptoCompression = true     // Usar compresión o no
)

type Usuario struct {
	Constraseña  string `json:"contraseña"`
	Apellido     string `json:"apellido"`
	Especialidad int    `json:"especialidad"`
	Hospital     int    `json:"hospital"`
}

type Hospital struct {
	Nombre string `json:"nombre"`
}

type Especialidad struct {
	Nombre string `json:"nombre"`
}

type Historial struct {
	Fecha_creacion string `json:"fecha_creacion"`
	Expedientes    []int  `json:"expedientes"` //tener en cuenta que para actualizarlos hay que coger la lista existente y añadirle uno nuevo
}

type LoginAttempt struct {
	Attempts   int       // Número de intentos fallidos consecutivos
	LastTry    time.Time // Hora del último intento
	Blocked    bool      // Si la cuenta está bloqueada
	BlockUntil time.Time // Hasta cuando está bloqueada
}

// Variables globales para el sistema de bloqueo
var (
	loginAttempts = make(map[string]*LoginAttempt) // Mapa para almacenar intentos por usuario
	loginMutex    sync.Mutex                       // Mutex para acceso concurrente seguro
	maxAttempts   = 3                              // Cantidad máxima de intentos antes de bloquear
	blockDuration = 1 * time.Minute                // Duración del bloqueo
)

// ------------------EMPIEZO CON HTTPS MODIFICACIONES---------------------------

type user struct { //name se usará como id en los namespaces
	Hash         []byte
	Salt         []byte
	Private      string
	Public       string
	Apellido     string `json:"apellido,omitempty"`
	Especialidad string `json:"especialidad,omitempty"`
	Hospital     string `json:"hospital,omitempty"`
	TOTPSecret   string `json:"totpSecret,omitempty"`
	IsAdmin      bool   `json:"isAdmin,omitempty"` //admin
}

func chk(e error) {
	if e != nil {
		panic(e)
	}
}

func (s *server) comprobarHospEsp(namespace string, id int) bool {
	id_int := strconv.Itoa(id)
	_, err := s.db.Get(namespace, []byte(id_int))
	if err != nil {
		return false
	}
	return true
}

// Run inicia la base de datos y arranca el servidor HTTP.
func Run() error {
	// Importaciones necesarias (añadir al inicio del archivo)
	// import "crypto/sha256"
	// import "encoding/hex"

	//Crear directorio de logs si no existe
	logDir := "logs"
	if err := os.MkdirAll(logDir, 0755); err != nil {
		fmt.Printf("Error creando directorio de logs: %v\n", err)
		return err
	}
	currentTime := time.Now().Format("2006-01-02")
	logFileName := filepath.Join(logDir, fmt.Sprintf("server_%s.log", currentTime))
	logFile, err := os.OpenFile(logFileName, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		fmt.Printf("Error abriendo archivo de log: %v\n", err)
		return err
	}

	serverLogger := log.New(logFile, "[srv] ", log.LstdFlags|log.Lmicroseconds)
	serverLogger.Println("**************************************************************************************************")
	serverLogger.Println("Iniciando servidor...")
	serverLogger.Println("Cargando variables de entorno...")

	errEnv := godotenv.Load()

	if errEnv != nil {
		serverLogger.Printf("ADVERTENCIA: No se puede cargar la variable de entorno desde un archivo .env: %v", errEnv)
	}

	CryptoKey = os.Getenv("MASTER_PASSWORD")

	if CryptoKey == "" {
		serverLogger.Fatalf("ERROR: La variable de entorno MASTER_PASSWORD no está definida.")
		return fmt.Errorf("no se ha definido la variable de entorno MASTER_PASSWORD")
	}

	// Verificar el hash de la clave maestra
	// IMPORTANTE: Reemplaza este hash con el de tu clave real
	expectedHash := "cb40ccb092951d4020ff31ad61f98e9dfb1de873517d6d0408ba23ee261bf1ff" // Hash ejemplo

	// Calcular hash de la clave proporcionada
	hasher := sha256.New()
	hasher.Write([]byte(CryptoKey))
	actualHash := hex.EncodeToString(hasher.Sum(nil))

	// Comparar hashes
	if actualHash != expectedHash {
		serverLogger.Fatalf("ERROR: La clave maestra proporcionada no coincide con la esperada. Verificar MASTER_PASSWORD")
		return fmt.Errorf("clave maestra incorrecta")
	}

	serverLogger.Println("MASTER_PASSWORD validada correctamente.")

	db, err := store.NewStore("bbolt", "data/server.db")
	if err != nil {
		serverLogger.Fatalf("ERROR: error abriendo base de datos: %v", err)
		return fmt.Errorf("error abriendo base de datos: %v", err)
	}

	srv := &server{
		db:  db,
		log: serverLogger,
	}

	// Al terminar, cerramos la base de datos y el archivo log
	defer func() {
		if err := srv.db.Close(); err != nil {
			srv.log.Fatalf("ERROR al cerrar la base de datos: %v", err)
		} else {
			srv.log.Println("Base de datos cerrada y cifrada correctamente.")
		}
		fmt.Println("Cerrando archivo de log...")
		if err := logFile.Close(); err != nil {
			srv.log.Fatalf("Error al cerrar archivo de log: %v\n", err)
		}
	}()

	// El resto del código continúa igual...
	http.HandleFunc("/", srv.handler)
	srv.log.Println("Iniciando servidor HTTPS en puerto 10443...")
	fmt.Printf("\nLogs del servidor se escriben en: %s\n", logFileName)

	if err := http.ListenAndServeTLS(":10443", "cert.pem", "key.pem", nil); err != nil {
		srv.log.Fatalf("FATAL: Error al iniciar servidor HTTPS: %v", err)
		return err
	}

	return nil
}

// apiHandler descodifica la solicitud JSON, la despacha
// a la función correspondiente y devuelve la respuesta JSON.
func (s *server) handler(w http.ResponseWriter, req *http.Request) {

	ip := req.RemoteAddr
	if forwardedFor := req.Header.Get("X-Forwarded-For"); forwardedFor != "" {
		ip = forwardedFor
	}

	req.ParseForm()
	w.Header().Set("Content-Type", "application/json")

	cmd := req.Form.Get("cmd")
	username := req.Form.Get("username")

	// Registrar solicitud entrante
	s.log.Printf("Solicitud recibida: IP=%s, Método=%s, Ruta=%s, Comando=%s, Usuario=%s",
		ip, req.Method, req.URL.Path, cmd, username)

	var res api.Response

	switch cmd {
	case "register":
		res := s.registerUser(req)
		response(w, res)
	case "login":
		res := s.loginUser(req)
		response(w, res)
	case "addPaciente":
		res := s.addPaciente(req)
		response(w, res)
	case "verHistorialPaciente":
		res := s.obtenerExpedientes(req)
		response(w, res)
	case "crearExpediente":
		res := s.anyadirExpediente(req)
		response(w, res)
	case "logout":
		res := s.logoutUser(req)
		response(w, res)
	case "modificarExpediente":
		res := s.anyadirObservaciones(req)
		response(w, res)
	case "verifyTOTP":
		res := s.verifyTOTP(req)
		response(w, res)
	case "listarPacientes":
		res := s.listarPacientes(req)
		response(w, res)
	case "eliminarPaciente":
		res := s.eliminarPaciente(req)
		response(w, res)
	default:
		s.log.Printf("Comando desconocido recibido: %s desde IP %s", cmd, ip)
		res := api.Response{Success: -1, Message: fmt.Sprintf("Comando desconocido: %s", cmd)}
		response(w, res)
	}

	s.log.Printf("Respuesta enviada para comando '%s' (Usuario: %s): Success=%d",
		cmd, username, res.Success)

}

func (s *server) obtenerUltimoID(namespace string) (string, error) {
	keys, err := s.db.ListKeys(namespace)
	if err != nil {
		return "", err
	}

	if len(keys) == 0 {
		return "1", nil
	}

	// Convertir todas las keys a números y encontrar el máximo
	maxID := 0
	for _, key := range keys {
		id, err := strconv.Atoi(string(key))
		if err == nil && id > maxID {
			maxID = id
		}
	}

	return strconv.Itoa(maxID + 1), nil
}

func (s *server) obtenerIdHospital(nombre string) int {
	listaKeys, err := s.db.ListKeys("Hospitales")
	if err != nil {
		return -1
	}
	var key int
	for i := 0; i < len(listaKeys); i++ {
		hospitalJson, errget := s.db.Get("Hospitales", []byte(listaKeys[i]))
		if errget != nil {
			return -1
		}

		var hospitalStruct Hospital

		errStruct := json.Unmarshal(hospitalJson, &hospitalStruct)
		if errStruct != nil {
			return -1
		}
		if hospitalStruct.Nombre == nombre {
			key = i + 1
			break
		}
	}
	return key
}

func response(w io.Writer, res api.Response) {
	r := res                       // formateamos respuesta
	rJSON, err := json.Marshal(&r) // codificamos en JSON
	chk(err)                       // comprobamos error
	w.Write(rJSON)                 // escribimos el JSON resultante
}

// función para comprimir
func compress(data []byte) []byte {
	var b bytes.Buffer      // b contendrá los datos comprimidos (tamaño variable)
	w := zlib.NewWriter(&b) // escritor que comprime sobre b
	w.Write(data)           // escribimos los datos
	w.Close()               // cerramos el escritor (buffering)
	return b.Bytes()        // devolvemos los datos comprimidos
}

// función para descomprimir
func decompress(data []byte) []byte {
	var b bytes.Buffer // b contendrá los datos descomprimidos

	r, err := zlib.NewReader(bytes.NewReader(data)) // lector descomprime al leer

	chk(err)         // comprobamos el error
	io.Copy(&b, r)   // copiamos del descompresor (r) al buffer (b)
	r.Close()        // cerramos el lector (buffering)
	return b.Bytes() // devolvemos los datos descomprimidos
}

// función para codificar de []bytes a string (Base64)
func encode64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data) // sólo utiliza caracteres "imprimibles"
}

// tryDecrypt intenta descifrar datos, manejando varios escenarios
func (s *server) tryDecrypt(data []byte) ([]byte, error) {
	// Intentamos primero descifrar con compresión
	decryptedData, err := cifrado.DecryptData(data, CryptoKey, CryptoAlgorithm, CryptoCompression)
	if err == nil {
		return decryptedData, nil
	}

	for _, algo := range []string{"AES256"} {
		if algo == CryptoAlgorithm {
			continue // Ya lo probamos
		}

		// Intentar con este algoritmo
		decryptedData, err = cifrado.DecryptData(data, CryptoKey, algo, CryptoCompression)
		if err == nil {
			fmt.Printf("Datos descifrados con algoritmo alternativo: %s", algo)
			return decryptedData, nil
		}

	}

	// Si nada funciona, asumimos que los datos no están cifrados
	return data, nil
}

func decode64(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s) // recupera el formato original
	chk(err)                                     // comprobamos el error
	return b                                     // devolvemos los datos originales
}

// Función de registro
func (s *server) registerUser(req *http.Request) api.Response {

	if req.Form.Get("username") == "" || req.Form.Get("password") == "" || req.Form.Get("apellido") == "" || req.Form.Get("especialidad") == "0" || req.Form.Get("hospital") == "0" {
		return api.Response{Success: -1, Message: "Faltan credenciales"}
	}

	exists, err := s.userExists(req.Form.Get("username"))
	if err != nil {
		return api.Response{Success: -1, Message: "Error verificando usuario"}
	}
	if exists {
		return api.Response{Success: -1, Message: "El usuario ya existe"}
	}

	name := req.Form.Get("username")               // nombre
	salt := make([]byte, 16)                       // sal (16 bytes == 128 bits)
	rand.Read(salt)                                // la sal es aleatoria
	private := req.Form.Get("prikey")              // clave privada
	public := req.Form.Get("pubkey")               // clave pública
	password := decode64(req.Form.Get("password")) // contraseña (keyLogin)
	isAdminFlag, _ := strconv.ParseBool(req.Form.Get("isAdmin"))

	hash := argon2.IDKey([]byte(password), salt, 16384, 8, 1, 32)

	// Generar TOTP
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "SistemaMedico",
		AccountName: name,
	})
	if err != nil {
		return api.Response{Success: -1, Message: fmt.Sprintf("Error generando TOTP: %v", err)}
	}
	u := user{
		Salt:         salt,
		Hash:         hash,
		Private:      private,
		Public:       public,
		Apellido:     req.Form.Get("apellidos"),
		Hospital:     req.Form.Get("hospital"),
		Especialidad: req.Form.Get("especialidad"),
		TOTPSecret:   key.Secret(),
		IsAdmin:      isAdminFlag,
	}

	// Convertir a JSON
	u_json, err := json.Marshal(u)
	if err != nil {
		return api.Response{Success: -1, Message: "Error creando datos de usuario"}
	}

	// Cifrar los datos del usuario
	encryptedData, err := cifrado.EncryptData(u_json, CryptoKey, CryptoAlgorithm, CryptoCompression)
	if err != nil {
		return api.Response{Success: -1, Message: "Error cifrando datos de usuario: " + err.Error()}
	}

	// Guardar los datos cifrados en la base de datos
	if err := s.db.Put("Usuarios", []byte(name), encryptedData); err != nil {
		return api.Response{Success: -1, Message: "Error al crear el usuario"}
	}

	otpauth := key.URL() // Genera otpauth://totp/SistemaMedico:username?secret=XXX&issuer=SistemaMedico
	return api.Response{
		Success: 1,
		Message: "Usuario creado. Configura TOTP con el siguiente secreto o escanea el QR.",
		Data:    otpauth,
	}

}

// checkLoginAttempts verifica si un usuario puede intentar iniciar sesión
// Devuelve: true si puede intentar, false si está bloqueado
// También devuelve el tiempo hasta el cual está bloqueado (si aplica)
func (s *server) checkLoginAttempts(username string) (bool, time.Time) {
	loginMutex.Lock()
	defer loginMutex.Unlock()

	// Si no hay registro previo para este usuario, permitir el intento
	attempt, exists := loginAttempts[username]
	if !exists {
		loginAttempts[username] = &LoginAttempt{Attempts: 0, LastTry: time.Now()}
		return true, time.Time{}
	}

	// Verificar si la cuenta está bloqueada
	if attempt.Blocked {
		// Si ya pasó el tiempo de bloqueo, desbloquear
		if time.Now().After(attempt.BlockUntil) {
			s.log.Printf("Cuenta de %s desbloqueada automáticamente después del periodo de bloqueo", username)
			attempt.Blocked = false
			attempt.Attempts = 0
			return true, time.Time{}
		}
		s.log.Printf("Intento de inicio de sesión para cuenta bloqueada: %s (bloqueada hasta %v)",
			username, attempt.BlockUntil.Format("15:04:05"))
		return false, attempt.BlockUntil
	}

	return true, time.Time{}
}

// recordLoginFailure registra un intento fallido de inicio de sesión
func (s *server) recordLoginFailure(username string, r *http.Request) {
	loginMutex.Lock()
	defer loginMutex.Unlock()

	// Obtener o crear el registro de intentos para este usuario
	attempt, exists := loginAttempts[username]
	if !exists {
		loginAttempts[username] = &LoginAttempt{Attempts: 1, LastTry: time.Now()}
		return
	}

	// Incrementar contador de intentos
	attempt.Attempts++
	attempt.LastTry = time.Now()

	// Log del intento fallido
	ip := r.RemoteAddr
	if forwardedFor := r.Header.Get("X-Forwarded-For"); forwardedFor != "" {
		ip = forwardedFor
	}

	s.log.Printf("Intento de inicio de sesión fallido para %s desde IP %s (intento %d de %d)",
		username, ip, attempt.Attempts, maxAttempts)

	// Bloquear después de alcanzar el máximo de intentos
	if attempt.Attempts >= maxAttempts {
		attempt.Blocked = true
		attempt.BlockUntil = time.Now().Add(blockDuration)
		s.log.Printf("ALERTA: Cuenta %s bloqueada por %v minutos después de %d intentos fallidos",
			username, blockDuration.Minutes(), maxAttempts)
	}
}

// recordLoginSuccess registra un inicio de sesión exitoso y resetea el contador
func (s *server) recordLoginSuccess(username string) {
	loginMutex.Lock()
	defer loginMutex.Unlock()

	// Resetear intentos después de un login exitoso
	loginAttempts[username] = &LoginAttempt{Attempts: 0, LastTry: time.Now()}
}

// loginUser valida credenciales en el namespace 'auth' y genera un token en 'sessions'.
func (s *server) loginUser(req *http.Request) api.Response {
	// Verificar credenciales básicas
	if req.Form.Get("username") == "" || req.Form.Get("password") == "" {
		s.log.Println("Faltan credenciales en el login")
		return api.Response{Success: -1, Message: "Faltan credenciales"}
	}

	username := req.Form.Get("username")

	// Verificar si la cuenta está bloqueada
	canLogin, blockedUntil := s.checkLoginAttempts(username)
	if !canLogin {
		// Formatear tiempo restante de bloqueo
		remaining := blockedUntil.Sub(time.Now()).Round(time.Minute)
		s.log.Printf("Cuenta de %s bloqueada temporalmente. Intentar nuevamente en %v minutos", username, remaining)
		return api.Response{
			Success: -2,
			Message: fmt.Sprintf("Cuenta bloqueada temporalmente. Intente nuevamente en %v minutos",
				remaining.Minutes()),
		}
	}

	// Verificar si el usuario existe
	userData, err := s.db.Get("Usuarios", []byte(username))
	if err != nil {
		// Registrar intento fallido - usuario no encontrado
		s.recordLoginFailure(username, req)
		s.log.Printf("Usuario no encontrado: %s", username)
		return api.Response{Success: -1, Message: "Usuario no encontrado"}
	}

	// Resto de tu lógica de verificación existente...
	// Intentar deserializar y descifrar los datos
	var datosUsuario user
	err = json.Unmarshal(userData, &datosUsuario)

	if err != nil {
		// Intentar descifrar
		decryptedData, err := cifrado.DecryptData(userData, CryptoKey, CryptoAlgorithm, CryptoCompression)
		if err != nil {
			s.recordLoginFailure(username, req)
			s.log.Println("Error descifrando datos del usuario")
			return api.Response{Success: -1, Message: "Error descifrando datos de usuario"}
		}

		// Deserializar datos descifrados
		err = json.Unmarshal(decryptedData, &datosUsuario)
		if err != nil {
			s.recordLoginFailure(username, req)
			s.log.Printf("Formato de datos de usuario inválido")
			return api.Response{Success: -1, Message: "Formato de datos de usuario inválido"}
		}
	}

	// Verificar contraseña
	password := decode64(req.Form.Get("password"))
	hash := argon2.IDKey([]byte(password), datosUsuario.Salt, 16384, 8, 1, 32)

	if bytes.Compare(datosUsuario.Hash, hash) != 0 {
		// Contraseña incorrecta - registrar intento fallido
		s.recordLoginFailure(username, req)
		s.log.Printf("Contraseña introducida en el login incorrecta")
		return api.Response{Success: -1, Message: "Contraseña incorrecta"}
	}

	// Si llegamos aquí, el login fue exitoso
	s.recordLoginSuccess(username)

	// Generar token y continuar con el proceso de login
	token := s.crearToken(username, 10)
	s.log.Printf("Token generado para el usuario %s", username)

	currentSpecialty = datosUsuario.Especialidad
	currentHospital = datosUsuario.Hospital

	// Registrar el login exitoso en los logs
	ip := req.RemoteAddr
	if forwardedFor := req.Header.Get("X-Forwarded-For"); forwardedFor != "" {
		ip = forwardedFor
	}
	s.log.Printf("--------------------Login exitoso para usuario %s desde IP %s-------------------", username, ip)

	return api.Response{Success: 1, Message: "Login exitoso", Token: token, TokenOTP: req.Form.Get("username"), IsAdmin: s.isUserAdmin(username)}
}

// Obtener expedientes de la especialidad del médico
func (s *server) obtenerExpedientes(req *http.Request) api.Response {
	if req.Form.Get("dni") == "" || req.Form.Get("token") == "" {
		s.log.Println("Faltan datos a introducir para obtener expedientes")
		return api.Response{Success: -1, Message: "Faltan datos"}
	}
	_, ok := s.isTokenValid(req.Form.Get("token"), req.Form.Get("username"))
	if !ok {
		s.log.Println("Token caducado o inválido en obtener expedientes")
		return api.Response{Success: 0, Message: "Error en las credenciales: Token inválido o caducado"}
	}

	// Obtener historial (potencialmente cifrado)
	historialData, err_hist := s.db.Get("Historiales", []byte(req.Form.Get("dni")))
	if err_hist != nil {
		s.log.Println("El DNI introducido no es correcto en obtener expedientes")
		return api.Response{Success: -1, Message: "El Dni introducido es incorrecto"}
	}

	// Intentar deserializar directamente
	var historial_json Historial
	err := json.Unmarshal(historialData, &historial_json)

	// Si falla, intentar descifrar
	if err != nil {
		// Intentar descifrar
		decryptedData, err := s.tryDecrypt(historialData)
		if err != nil {
			s.log.Println("Error descifrando el historial")
			return api.Response{Success: -1, Message: "Error descifrando historial: " + err.Error()}
		}

		// Deserializar datos descifrados
		err = json.Unmarshal(decryptedData, &historial_json)
		if err != nil {
			s.log.Println("Error decodificando el historial")
			return api.Response{Success: -1, Message: "Error decodificando historial"}
		}
	}

	lista_expedientes := historial_json.Expedientes
	var info_expedientes [][]byte

	for i := 0; i < len(lista_expedientes); i++ {
		expedienteKey := strconv.Itoa(lista_expedientes[i])

		expedienteData, errExp := s.db.Get("Expedientes", []byte(expedienteKey))
		if errExp != nil {
			s.log.Println("Los expedientes del paciente son incorrectos")
			return api.Response{Success: -1, Message: "Los expedientes del paciente son incorrectos"}
		}

		// Intentar deserializar directamente
		var expedienteStruct api.Expediente
		err = json.Unmarshal(expedienteData, &expedienteStruct)

		if err != nil {
			// Intentar descifrar
			decryptedData, err := s.tryDecrypt(expedienteData)
			if err != nil {
				s.log.Println("Error descifrando expediente")
				return api.Response{Success: -1, Message: "Error descifrando expediente: " + err.Error()}
			}

			info_expedientes = append(info_expedientes, decryptedData)

		} else {
			info_expedientes = append(info_expedientes, expedienteData)
		}
	}
	s.log.Println("Expedientes obtenidos")
	return api.Response{Success: 1, Message: "Expedientes obtenidos", Expedientes: info_expedientes}
}

func (s *server) addPaciente(req *http.Request) api.Response {

	if req.Form.Get("dni") == "" || req.Form.Get("nom_Paciente") == "" || req.Form.Get("apellido") == "" || req.Form.Get("fecha") == "" || req.Form.Get("username") == "" || req.Form.Get("sexo") == "" || req.Form.Get("token") == "" {
		s.log.Println("Faltan datos del paciente al añadir un paciente")
		return api.Response{Success: -1, Message: "Faltan datos del paciente"}
	}

	_, ok := s.isTokenValid(req.Form.Get("token"), req.Form.Get("username"))
	if !ok {
		s.log.Printf("Token inválido o caducado en añadir paciente del usuario %s", req.Form.Get("username"))
		return api.Response{Success: 0, Message: "Error en las credenciales: Token inválido o caducado"}
	}

	_, errDNI := s.db.Get("Pacientes", []byte(req.Form.Get("dni")))
	if errDNI == nil {
		s.log.Printf("El paciente %s ya existe.", req.Form.Get("nom_Paciente"))
		return api.Response{Success: -1, Message: "El paciente ya existe"}
	}

	fecha := time.Now()
	fechaStr := fecha.Format(time.DateOnly)
	lista_vacia_Expedientes := []int{}
	historial := Historial{
		Fecha_creacion: fechaStr,
		Expedientes:    lista_vacia_Expedientes,
	}

	historial_json, errJsonHist := json.Marshal(historial)

	if errJsonHist != nil {
		s.log.Println("Error creando json del historial")
		return api.Response{Success: -1, Message: "Error creando json del historial"}
	}

	errHist := s.db.Put("Historiales", []byte(req.Form.Get("dni")), []byte(historial_json))

	if errHist != nil {
		s.log.Println("Error creando historial en la base de datos")
		return api.Response{Success: -1, Message: "Error creando historial en la base de datos"}
	}

	paciente := api.Paciente{
		Nombre:           req.Form.Get("nom_Paciente"),
		Apellido:         req.Form.Get("apellido"),
		Fecha_nacimiento: req.Form.Get("fecha"),
		Hospital:         currentHospital,
		Sexo:             req.Form.Get("sexo"),
		Medico:           req.Form.Get("username"),
		Historial:        req.Form.Get("dni"),
	}

	paciente_json, errJson := json.Marshal(paciente)

	if errJson != nil {
		s.log.Printf("No se pueden convertir los datos del paciente %s a json", req.Form.Get("nom_Paciente"))
		return api.Response{Success: -1, Message: "No pueden convertirse los datos a json"}
	}

	encryptedData, err := cifrado.EncryptData(paciente_json, CryptoKey, CryptoAlgorithm, CryptoCompression)
	if err != nil {
		s.log.Println("Error cifrando datos del paciente")
		return api.Response{Success: -1, Message: "Error cifrando datos del paciente: " + err.Error()}
	}

	err1 := s.db.Put("Pacientes", []byte(req.Form.Get("dni")), []byte(encryptedData))

	if err1 != nil {
		s.log.Println("Error creando al paciente")
		return api.Response{Success: -1, Message: "Error creando al paciente"}
	}
	s.log.Printf("Paciente creado")
	return api.Response{Success: 1, Message: "Paciente creado"}
}

func (s *server) anyadirObservaciones(req *http.Request) api.Response {
	if req.Form.Get("username") == "" || req.Form.Get("token") == "" || req.Form.Get("fecha") == "" || req.Form.Get("diagnostico") == "" || req.Form.Get("id") == "" || req.Form.Get("tratamiento") == "" {
		s.log.Println("Faltan credenciales en añadir observaciones")
		return api.Response{Success: -1, Message: "Faltan credenciales"}
	}

	_, ok := s.isTokenValid(req.Form.Get("token"), req.Form.Get("username"))
	if !ok {
		s.log.Printf("Token inválido o caducado del usuario %s en añadir observaciones", req.Form.Get("username"))
		return api.Response{Success: 0, Message: "Token inválido o sesión expirada"}
	}

	// Obtener el expediente existente
	expedienteData, err := s.db.Get("Expedientes", []byte(string(req.Form.Get("id"))))
	if err != nil {
		s.log.Printf("No existen un expediente con el id %v", req.Form.Get("id"))
		return api.Response{Success: -1, Message: "No existe un expediente con ID: " + req.Form.Get("id")}
	}

	// Intentar deserializar directamente primero
	var expedienteStruct api.Expediente
	err = json.Unmarshal(expedienteData, &expedienteStruct)

	// Si falla, intentar descifrar
	if err != nil {
		// Intentar descifrar
		decryptedData, err := s.tryDecrypt(expedienteData)
		if err != nil {
			s.log.Println("Error descifrando el expediente")
			return api.Response{Success: -1, Message: "Error descifrando expediente: " + err.Error()}
		}

		// Deserializar datos descifrados
		err = json.Unmarshal(decryptedData, &expedienteStruct)
		if err != nil {
			s.log.Println("Error al convertir a estructura el expediente")
			return api.Response{Success: -1, Message: "Error al convertir a estructura el expediente: " + err.Error()}
		}
	}

	// Crear nueva observación
	observacion := api.Observaciones{
		Fecha_actualizacion: req.Form.Get("fecha"),
		Diagnostico:         req.Form.Get("diagnostico"),
		Tratamiento:         req.Form.Get("tratamiento"),
		Medico:              req.Form.Get("username"),
	}

	// Añadir la nueva observación al expediente
	observaciones_originales := expedienteStruct.Observaciones
	observaciones := append(observaciones_originales, observacion)

	expedienteModificado := api.Expediente{
		ID:            expedienteStruct.ID,
		Username:      req.Form.Get("username"),
		Observaciones: observaciones,
		FechaCreacion: expedienteStruct.FechaCreacion,
		Especialidad:  expedienteStruct.Especialidad,
	}

	// Convertir a JSON
	expedienteModificadoJson, errJson := json.Marshal(expedienteModificado)
	if errJson != nil {
		s.log.Println("Error al convertir expediente a JSON")
		return api.Response{Success: -1, Message: "Error al convertir expediente a Json"}
	}

	// Cifrar el expediente
	encryptedData, err := cifrado.EncryptData(expedienteModificadoJson, CryptoKey, CryptoAlgorithm, CryptoCompression)
	if err != nil {
		s.log.Println("Error cifrando el expediente")
		return api.Response{Success: -1, Message: "Error cifrando expediente: " + err.Error()}
	}

	// Guardar el expediente cifrado
	err = s.db.Put("Expedientes", []byte(string(req.Form.Get("id"))), encryptedData)
	if err != nil {
		s.log.Println("Error guardando el expediente")
		return api.Response{Success: -1, Message: "Error guardando expediente: " + err.Error()}
	}

	s.log.Println("Expediente modificado correctamente")
	return api.Response{Success: 1, Message: "Expediente modificado correctamente"}
}

func (s *server) anyadirExpediente(req *http.Request) api.Response {
	if req.Form.Get("username") == "" || req.Form.Get("diagnostico") == "" || req.Form.Get("dni") == "" || req.Form.Get("token") == "" {
		s.log.Println("Faltan credenciales al añadir expedientes")
		return api.Response{Success: -1, Message: "Faltan credenciales para añadir expedientes"}
	}

	_, ok := s.isTokenValid(req.Form.Get("token"), req.Form.Get("username"))
	if !ok {
		s.log.Printf("Token inválido o caducado en añadir expedientes del usuario %s", req.Form.Get("username"))
		return api.Response{Success: 0, Message: "Token inválido o sesión expirada"}
	}

	fecha := time.Now().Format("2006-01-02")

	ultimoId, err := s.obtenerUltimoID("Expedientes")
	if err != nil {
		s.log.Println("Error al generar ID del expediente")
		return api.Response{Success: -1, Message: "Error al generar ID de expediente"}
	}

	ultimoIdInt, err := strconv.Atoi(ultimoId)
	if err != nil {
		s.log.Println("Error en el formato del ID")
		return api.Response{Success: -1, Message: "Error en formato de ID"}
	}

	// Crear nuevo expediente
	expediente := api.Expediente{
		ID:       ultimoId,
		Username: req.Form.Get("username"),
		Observaciones: []api.Observaciones{
			{
				Fecha_actualizacion: fecha,
				Diagnostico:         req.Form.Get("diagnostico"),
				Medico:              req.Form.Get("username"),
			},
		},
		FechaCreacion: fecha,
		Especialidad:  currentSpecialty,
	}

	// Convertir a JSON
	expedienteJSON, errJson := json.Marshal(expediente)
	if errJson != nil {
		s.log.Println("Error convirtiendo a JSON el expediente")
		return api.Response{Success: -1, Message: "Error convirtiendo a json el expediente"}
	}

	// Cifrar datos del expediente
	encryptedExpediente, err := cifrado.EncryptData(expedienteJSON, CryptoKey, CryptoAlgorithm, CryptoCompression)
	if err != nil {
		s.log.Println("Error cifrando el expediente")
		return api.Response{Success: -1, Message: "Error cifrando expediente: " + err.Error()}
	}

	// Guardar expediente cifrado
	if err := s.db.Put("Expedientes", []byte(ultimoId), encryptedExpediente); err != nil {
		s.log.Println("Error guardando el expediente")
		return api.Response{Success: -1, Message: "Error guardando expediente"}
	}

	// Ahora actualizamos el historial del paciente
	historialData, errget := s.db.Get("Historiales", []byte(string(req.Form.Get("dni"))))
	if errget != nil {
		s.log.Println("Error al obtener el historial del paciente")
		return api.Response{Success: -1, Message: "Error al obtener el historial del paciente"}
	}

	// Intentar deserializar directamente
	var historialStruct Historial
	err = json.Unmarshal(historialData, &historialStruct)

	// Si falla, intentar descifrar
	if err != nil {
		// Intentar descifrar
		decryptedData, err := s.tryDecrypt(historialData)
		if err != nil {
			s.log.Println("Formato inválido del historial. Error al leer historial")
			return api.Response{Success: -1, Message: "Error al leer historial: formato inválido"}
		}

		// Deserializar datos descifrados
		err = json.Unmarshal(decryptedData, &historialStruct)
		if err != nil {
			s.log.Println("Error al convertir el historial a struct")
			return api.Response{Success: -1, Message: "Error al convertir el historial a struct"}
		}
	}

	// Añadir nuevo expediente al historial
	found := false
	for _, id := range historialStruct.Expedientes {
		if id == ultimoIdInt {
			found = true
			break
		}
	}

	if !found {
		historialStruct.Expedientes = append(historialStruct.Expedientes, ultimoIdInt)
	}

	// Crear nuevo historial
	nuevoHistorial := Historial{
		Fecha_creacion: fecha,
		Expedientes:    historialStruct.Expedientes,
	}

	// Convertir a JSON
	historialJSON, errJson := json.Marshal(nuevoHistorial)
	if errJson != nil {
		s.log.Println("Erron al convertir el historial a JSON")
		return api.Response{Success: -1, Message: "Error al convertir el historial en json"}
	}

	// Cifrar historial
	encryptedHistorial, err := cifrado.EncryptData(historialJSON, CryptoKey, CryptoAlgorithm, CryptoCompression)
	if err != nil {
		s.log.Println("Error cifrando el historial")
		return api.Response{Success: -1, Message: "Error cifrando historial: " + err.Error()}
	}

	// Guardar historial cifrado
	if err := s.db.Put("Historiales", []byte(req.Form.Get("dni")), encryptedHistorial); err != nil {
		s.log.Println("Error al guardar el historial actualizado")
		return api.Response{Success: -1, Message: "Error al guardar historial actualizado"}
	}
	s.log.Println("Expediente creado y añadido al historial correctamente")
	return api.Response{Success: 1, Message: "Expediente creado y añadido al historial correctamente"}
}

// logoutUser borra la sesión en 'sessions', invalidando el token.
func (s *server) logoutUser(req *http.Request) api.Response {
	// Chequeo de credenciales
	if req.Form.Get("username") == "" || req.Form.Get("token") == "" {
		s.log.Println("Faltan credenciales en cerrar sesión")
		return api.Response{Success: -1, Message: "Faltan credenciales"}
	}
	_, ok := s.isTokenValid(req.Form.Get("token"), req.Form.Get("username"))
	if !ok {
		s.log.Println("Token inválido o caducado en cerrar sesión")
		return api.Response{Success: 0, Message: "Token inválido o sesión expirada"}
	}
	s.log.Println("Sesión cerrada correctamente")
	return api.Response{Success: 1, Message: "Sesión cerrada correctamente"}
}

// userExists comprueba si existe un usuario con la clave 'username'
// en 'auth'. Si no se encuentra, retorna false.
func (s *server) userExists(username string) (bool, error) {
	_, err := s.db.Get("auth", []byte(username))
	if err != nil {
		// Si no existe namespace o la clave:
		if strings.Contains(err.Error(), "bucket no encontrado: auth") {
			return false, nil
		}
		if err.Error() == "clave no encontrada: "+username {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (s *server) getSecretoJwt() []byte {
	errEnv := godotenv.Load()

	if errEnv != nil {
		s.log.Printf("ADVERTENCIA: No se puede cargar la variable de entorno desde un archivo .env: %v", errEnv)
	}

	secreto := os.Getenv("MASTER_PASSWORD_JWT")

	if secreto == "" {
		s.log.Fatalf("ERROR: La variable de entorno MASTER_PASSWORD_JWT no está definida.")

	}
	return []byte(secreto)
}

func (s *server) crearToken(usuario string, minutos int) string {
	//Tiempo de expiración
	Hours := 0
	Mins := minutos
	Sec := 0

	Claim := Payload{
		usuario,
		time.Now().Local().Add(
			time.Hour*time.Duration(Hours) +
				time.Minute*time.Duration(Mins) +
				time.Second*time.Duration(Sec)).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, Claim)

	mySecret := s.getSecretoJwt()
	signedToken, err := token.SignedString(mySecret)
	chk(err)

	return signedToken
}

func (s *server) isTokenValid(receivedToken string, username string) (*Payload, bool) {
	token, _ := jwt.ParseWithClaims(receivedToken, &Payload{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			s.log.Fatalf("Methodo de firma erroneo: %v", token.Header["alg"])
			return nil, fmt.Errorf("Methodo de firma erroneo: %v", token.Header["alg"])
		}

		return s.getSecretoJwt(), nil
	})

	claim, ok := token.Claims.(*Payload)

	if ok && token.Valid {
		return claim, true
	}

	if claim.Id != username {
		return claim, false
	}

	return claim, false
}

type Payload struct {
	Id        string `json:"jti,omitempty"`
	ExpiresAt int64  `json:"exp,omitempty"`
}

func (c Payload) Valid() error {
	vErr := new(jwt.ValidationError)
	now := jwt.TimeFunc().Unix()

	if now > c.ExpiresAt {
		delta := time.Unix(now, 0).Sub(time.Unix(c.ExpiresAt, 0))
		vErr.Inner = fmt.Errorf("token is expired by %v", delta)
		vErr.Errors |= jwt.ValidationErrorExpired

		return vErr
	} else {
		return nil
	}

}

func (s *server) verifyTOTP(req *http.Request) api.Response {
	username := req.Form.Get("username")
	code := req.Form.Get("code")

	userData, err := s.db.Get("Usuarios", []byte(username))
	if err != nil {
		s.log.Printf("Usuario %s no encontrado en la verificación ToTP", username)
		return api.Response{Success: -1, Message: "Usuario no encontrado"}
	}

	userData, err = s.tryDecrypt(userData)

	var u user
	if err := json.Unmarshal(userData, &u); err != nil {
		s.log.Printf("Error procesando los datos del usuario en verificación de ToTP")
		return api.Response{Success: -1, Message: "Error procesando datos del usuario"}
	}

	valid := totp.Validate(code, u.TOTPSecret)
	if !valid {
		s.log.Printf("Código ToTP inválido para el usuario %s", username)
		return api.Response{Success: -1, Message: "\nCódigo TOTP inválido"}
	}

	// Generar token JWT final
	token := s.crearToken(username, 30)
	s.log.Println("Autenticación TOTP exitosa")
	return api.Response{
		Success: 1,
		Message: "Autenticación TOTP exitosa",
		Token:   token,
		IsAdmin: s.isUserAdmin(username),
	}
}

func (s *server) listarPacientes(req *http.Request) api.Response {
	if !s.isUserAdmin(req.Form.Get("username")) {
		return api.Response{Success: -1, Message: "Acceso denegado"}
	}

	keys, err := s.db.ListKeys("Pacientes")
	if err != nil {
		return api.Response{Success: -1, Message: "Error al listar pacientes"}
	}

	var pacientes []api.Paciente
	for _, key := range keys {
		pacienteData, err := s.db.Get("Pacientes", key)
		if err != nil {
			continue
		}

		decryptedData, err := s.tryDecrypt(pacienteData)
		if err != nil {
			continue
		}

		var p api.Paciente
		if err := json.Unmarshal(decryptedData, &p); err == nil {
			pacientes = append(pacientes, p)
		}
	}

	return api.Response{
		Success:   1,
		Pacientes: pacientes,
	}
}
func (s *server) eliminarPaciente(req *http.Request) api.Response {
	if !s.isUserAdmin(req.Form.Get("username")) {
		return api.Response{Success: -1, Message: "Acceso denegado"}
	}

	dni := req.Form.Get("dni")

	// Eliminar paciente
	if err := s.db.Delete("Pacientes", []byte(dni)); err != nil {
		return api.Response{Success: -1, Message: "Error al eliminar paciente"}
	}

	// Opcional: Eliminar historial asociado
	_ = s.db.Delete("Historiales", []byte(dni))

	return api.Response{Success: 1, Message: "Paciente eliminado"}
}

// Función auxiliar para verificar admin
func (s *server) isUserAdmin(username string) bool {
	userData, err := s.db.Get("Usuarios", []byte(username))
	if err != nil {
		s.log.Printf("Error obteniendo datos de usuario %s: %v", username, err)
		return false
	}

	// Intentar descifrar los datos
	decryptedData, err := s.tryDecrypt(userData)
	if err != nil {
		s.log.Printf("Error descifrando datos de usuario %s: %v", username, err)
		return false
	}

	var u user
	if err := json.Unmarshal(decryptedData, &u); err != nil {
		s.log.Printf("Error deserializando datos de usuario %s: %v", username, err)
		return false
	}

	return u.IsAdmin
}
