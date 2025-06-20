// El paquete api contiene las estructuras necesarias
// para la comunicación entre servidor y cliente.
package api

import "time"

type Token struct {
	Value     string
	ExpiresAt time.Time
}
type Observaciones struct {
	Fecha_actualizacion string `json:"fecha_actualizacion"`
	Diagnostico         string `json:"diagnostico"`
	Medico              string `json:"medico"`
	Tratamiento         string `json:"tratamiento"`
}

type Paciente struct {
	Nombre           string `json:"nombre"`
	Apellido         string `json:"apellido"`
	Fecha_nacimiento string `json:"fecha_nacimiento"`
	Sexo             string `json:"sexo"`
	Hospital         string `json:"hospital"`
	Historial        string `json:"historial"`
	Medico           string `json:"medico"`
}

type Expediente struct {
	ID            string          `json:"id"` // Añadido
	Username      string          `json:"medico"`
	Observaciones []Observaciones `json:"observaciones"`
	FechaCreacion string          `json:"fecha_creacion"`
	Especialidad  string          `json:"especialidad"`
}

const (
	ActionRegister            = "register"
	ActionLogin               = "login"
	ActionFetchData           = "fetchData"
	ActionUpdateData          = "updateData"
	ActionLogout              = "logout"
	ActionDarAlta             = "darAlta"
	ActionObtenerExpedientes  = "obtenerExpedientes"
	ActionModificarExpediente = "modificarExpediente"
	ActionCrearExpediente     = "crearExpediente"
)

// Request y Response como antes
type Request struct { //omitempty es para que no aparezca en el json del request cuando se haga esta acción
	Action       string `json:"action"`
	Username     string `json:"username"`
	Password     string `json:"password,omitempty"`
	Token        Token  `json:"token,omitempty"` //es el valor del token
	Data         string `json:"data,omitempty"`
	Especialidad string `json:"especialidad,omitempty"`
	Hospital     string `json:"hospital,omitempty"`
	Apellido     string `json:"apellido,omitempty"`
	Sexo         string `json:"sexo,omitempty"`
	Nombre       string `json:"nombre,omitempty"`
	Fecha        string `json:"Fecha;omitempty"`
	DNI          string `json:"dni;omitempty"`
	Diagnostico  string `json:"diagnostico;omitempty"`
	ID           int    `json:"id;omitempty"`
	IsAdmin      bool   `json:"isAdmin;omitempty"` //admin
}

type Response struct {
	Success     int        `json:"success"`
	Message     string     `json:"message"`
	Token       string     `json:"token,omitempty"`
	Data        string     `json:"data,omitempty"`
	Expedientes [][]byte   `json:"expedientes,omitempty"` //lista con el id de los pacientes que tienen algún historial con su médico
	Hospital    int        `json:"hospital,omitempty"`
	TokenOTP    string     `json:"tokenOTP, omitempty"`
	Pacientes   []Paciente `json:"pacientes,omitempty"`
	IsAdmin     bool       `json:"isAdmin,omitempty"` //admin
}
