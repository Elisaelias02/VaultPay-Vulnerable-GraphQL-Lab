/**
 * VaultPay API — Vulnerable Lab
 * ================================
 * [1] GraphQL Introspection habilitada en producción
 * [2] Batch Attack — PIN brute force bypasseando rate limiting
 * [3] Field Suggestion Attack — campos ocultos expuestos
 * [4] Information Disclosure — resetPassword filtra datos para ATO
 *
 * Elisa Elias — Cinn4mor0ll
 */

const express    = require('express');
const cors       = require('cors');
const bodyParser = require('body-parser');
const { ApolloServer } = require('@apollo/server');
const { expressMiddleware } = require('@apollo/server/express4');
const jwt        = require('jsonwebtoken');
const bcrypt     = require('bcryptjs');
const Datastore  = require('nedb');

const app    = express();
const PORT   = 4000;
const SECRET = 'vaultpay-jwt-secret-2026';

// ── In-memory DB con nedb ──────────────────────────────────────
const db = {
  usuarios:      new Datastore(),
  transacciones: new Datastore(),
  intentos:      new Datastore()
};

// ── Seed data ──────────────────────────────────────────────────
function seedDatabase() {
  const usuarios = [
    {
      _id: 'usr-vp-001', nombre: 'Carlos Mendoza Vega',
      email: 'c.mendoza@gmail.com',
      password: bcrypt.hashSync('Mendoza2026!', 10),
      telefono: '5512345678', curp: 'MEVC850312HDFNRL08',
      pin: bcrypt.hashSync('4821', 10),
      saldo: 12450.00, clabe: '012180045678901234',
      banco: 'BBVA', hint_seguridad: 'nombre de mi primera mascota',
      fraud_flag: false, internal_score: 82.5,
      admin_notes: 'Cliente premium desde 2023. Sin incidencias.',
      fecha_registro: '2023-03-15T10:22:00'
    },
    {
      _id: 'usr-vp-002', nombre: 'Sofia Herrera Leal',
      email: 's.herrera@outlook.com',
      password: bcrypt.hashSync('Herrera2026!', 10),
      telefono: '5523456789', curp: 'HELS920605MDFRRN02',
      pin: bcrypt.hashSync('7364', 10),
      saldo: 3820.50, clabe: '014180056789012345',
      banco: 'Santander', hint_seguridad: 'ciudad donde naci',
      fraud_flag: false, internal_score: 91.0,
      admin_notes: 'Cuenta verificada. KYC completo.',
      fecha_registro: '2023-06-20T14:15:00'
    },
    {
      _id: 'usr-vp-003', nombre: 'Miguel Torres Ruiz',
      email: 'm.torres@proton.me',
      password: bcrypt.hashSync('Torres2026!', 10),
      telefono: '5534567890', curp: 'TORM780901HDFRRG07',
      pin: bcrypt.hashSync('1593', 10),
      saldo: 28900.00, clabe: '021180067890123456',
      banco: 'Banamex', hint_seguridad: 'modelo de mi primer auto',
      fraud_flag: true, internal_score: 45.2,
      admin_notes: 'ALERTA: patron de transacciones sospechoso. En revision por compliance.',
      fecha_registro: '2024-01-10T09:30:00'
    },
    {
      _id: 'usr-vp-004', nombre: 'Ana Gutierrez Flores',
      email: 'ana.gutierrez@empresa.mx',
      password: bcrypt.hashSync('Gutierrez2026!', 10),
      telefono: '5545678901', curp: 'GUFA950215MDFLTL05',
      pin: bcrypt.hashSync('2048', 10),
      saldo: 7650.75, clabe: '006180078901234567',
      banco: 'Banorte', hint_seguridad: 'apodo de mi abuela',
      fraud_flag: false, internal_score: 78.3,
      admin_notes: '',
      fecha_registro: '2024-03-22T16:45:00'
    }
  ];

  const transacciones = [
    { _id: 'txn-001', emisor_id: 'usr-vp-001', receptor_id: 'usr-vp-002', monto: 500.00,  concepto: 'Cena del viernes',         estado: 'completada', fecha: '2026-05-20T20:15:00', referencia: 'VP-2026-05-001' },
    { _id: 'txn-002', emisor_id: 'usr-vp-002', receptor_id: 'usr-vp-001', monto: 250.00,  concepto: 'Mitad del Uber',           estado: 'completada', fecha: '2026-05-21T10:30:00', referencia: 'VP-2026-05-002' },
    { _id: 'txn-003', emisor_id: 'usr-vp-003', receptor_id: 'usr-vp-004', monto: 1200.00, concepto: 'Renta mes de mayo',        estado: 'completada', fecha: '2026-05-01T09:00:00', referencia: 'VP-2026-05-003' },
    { _id: 'txn-004', emisor_id: 'usr-vp-001', receptor_id: 'usr-vp-003', monto: 3500.00, concepto: 'Pago servicios freelance', estado: 'completada', fecha: '2026-05-15T14:20:00', referencia: 'VP-2026-05-004' },
    { _id: 'txn-005', emisor_id: 'usr-vp-004', receptor_id: 'usr-vp-002', monto: 180.00,  concepto: 'Libro de diseno',          estado: 'pendiente',  fecha: '2026-05-28T11:00:00', referencia: 'VP-2026-05-005' },
  ];

  for (const u of usuarios) db.usuarios.insert(u);
  for (const t of transacciones) db.transacciones.insert(t);

  console.log('✅ VaultPay — Base de datos inicializada con datos seed');
}

seedDatabase();

// ── Helpers ────────────────────────────────────────────────────
const findOne = (col, query) => new Promise((res, rej) =>
  db[col].findOne(query, (err, doc) => err ? rej(err) : res(doc))
);

const findAll = (col, query) => new Promise((res, rej) =>
  db[col].find(query, (err, docs) => err ? rej(err) : res(docs))
);

const insertDoc = (col, doc) => new Promise((res, rej) =>
  db[col].insert(doc, (err, d) => err ? rej(err) : res(d))
);

const updateDoc = (col, query, update) => new Promise((res, rej) =>
  db[col].update(query, update, {}, (err) => err ? rej(err) : res())
);

function generateToken(userId) {
  return jwt.sign({ userId }, SECRET, { expiresIn: '8h' });
}

async function getUserFromToken(token) {
  try {
    const { userId } = jwt.verify(token, SECRET);
    return await findOne('usuarios', { _id: userId });
  } catch { return null; }
}

async function getContext({ req }) {
  const auth  = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  const user  = token ? await getUserFromToken(token) : null;
  return { user };
}

// ── GraphQL Schema ─────────────────────────────────────────────
const typeDefs = `#graphql
  type Usuario {
    id: ID!
    nombre: String!
    email: String!
    telefono: String
    saldo: Float
    clabe: String
    banco: String
    fechaRegistro: String
  }

  type UsuarioInterno {
    id: ID!
    nombre: String!
    email: String!
    fraudFlag: Boolean
    internalScore: Float
    adminNotes: String
    curp: String
    telefono: String
  }

  type Transaccion {
    id: ID!
    emisorId: String!
    receptorId: String!
    monto: Float!
    concepto: String
    estado: String
    fecha: String
    referencia: String
  }

  type AuthPayload {
    token: String!
    usuario: Usuario!
  }

  type PinResult {
    exitoso: Boolean!
    mensaje: String
    token_confirmacion: String
  }

  type ResetInfo {
    existe: Boolean!
    hint: String
    telefono_parcial: String
    email_parcial: String
  }

  type Query {
    miPerfil: Usuario
    misTransacciones: [Transaccion!]!
    transaccion(id: ID!): Transaccion
    buscarUsuario(email: String!): Usuario
    perfilDetallado(userId: ID!): UsuarioInterno
  }

  type Mutation {
    login(email: String!, password: String!): AuthPayload
    registro(
      nombre: String!
      email: String!
      password: String!
      telefono: String!
      curp: String!
    ): AuthPayload
    # Configurar PIN después del registro desde ajustes de seguridad
    configurarPin(pin: String!): PinResult
    verifyPin(userId: ID!, pin: String!): PinResult
    iniciarTransferencia(
      receptorEmail: String!
      monto: Float!
      concepto: String
      pinToken: String!
    ): Transaccion
    resetPassword(email: String!): ResetInfo
  }
`;

// ── Resolvers ──────────────────────────────────────────────────
const resolvers = {
  Query: {
    miPerfil: async (_, __, { user }) => {
      if (!user) throw new Error('No autorizado');
      return user;
    },

    misTransacciones: async (_, __, { user }) => {
      if (!user) throw new Error('No autorizado');
      const txns = await findAll('transacciones', {
        $or: [{ emisor_id: user._id }, { receptor_id: user._id }]
      });
      return txns.sort((a, b) => new Date(b.fecha) - new Date(a.fecha));
    },

    transaccion: async (_, { id }, { user }) => {
      if (!user) throw new Error('No autorizado');
      return findOne('transacciones', { _id: id });
    },

    buscarUsuario: async (_, { email }, { user }) => {
      if (!user) throw new Error('No autorizado');
      return findOne('usuarios', { email });
    },

    perfilDetallado: async (_, { userId }, { user }) => {
      if (!user) throw new Error('No autorizado');
      const u = await findOne('usuarios', { _id: userId });
      if (!u) throw new Error('Usuario no encontrado');
      return {
        id: u._id, nombre: u.nombre, email: u.email,
        fraudFlag: u.fraud_flag, internalScore: u.internal_score,
        adminNotes: u.admin_notes, curp: u.curp, telefono: u.telefono
      };
    }
  },

  Mutation: {
    login: async (_, { email, password }) => {
      const user = await findOne('usuarios', { email });
      if (!user || !bcrypt.compareSync(password, user.password))
        throw new Error('Credenciales invalidas');
      return { token: generateToken(user._id), usuario: user };
    },

    registro: async (_, { nombre, email, password, telefono, curp }) => {
      const existe = await findOne('usuarios', { email });
      if (existe) throw new Error('El correo ya esta registrado');

      const id    = `usr-${Date.now()}`;
      const clabe = `0401800${Math.floor(Math.random() * 90000000000 + 10000000000)}`;
      const user  = {
        _id: id, nombre, email,
        password: bcrypt.hashSync(password, 10),
        telefono, curp,
        pin: null, // PIN se configura después desde ajustes de seguridad
        saldo: 0, clabe, banco: 'VaultPay',
        hint_seguridad: '', fraud_flag: false,
        internal_score: 50.0, admin_notes: '',
        fecha_registro: new Date().toISOString()
      };

      await insertDoc('usuarios', user);
      return { token: generateToken(id), usuario: user };
    },

    // Configurar PIN desde ajustes de seguridad post-registro
    configurarPin: async (_, { pin }, { user }) => {
      if (!user) throw new Error('No autorizado');
      if (pin.length !== 4 || !/^\d{4}$/.test(pin))
        return { exitoso: false, mensaje: 'El PIN debe ser de 4 digitos numericos' };

      await updateDoc('usuarios', { _id: user._id }, {
        $set: { pin: bcrypt.hashSync(pin, 10) }
      });

      return { exitoso: true, mensaje: 'PIN configurado correctamente' };
    },

    verifyPin: async (_, { userId, pin }) => {
      const user = await findOne('usuarios', { _id: userId });
      if (!user) return { exitoso: false, mensaje: 'Usuario no encontrado' };
      if (!user.pin) return { exitoso: false, mensaje: 'PIN no configurado' };

      const correcto = bcrypt.compareSync(pin, user.pin);
      await insertDoc('intentos', {
        usuario_id: userId, intento: pin,
        timestamp: new Date().toISOString(), exitoso: correcto
      });

      if (correcto) {
        const pinToken = jwt.sign(
          { userId, accion: 'transferencia' },
          SECRET, { expiresIn: '5m' }
        );
        return { exitoso: true, mensaje: 'PIN verificado', token_confirmacion: pinToken };
      }

      return { exitoso: false, mensaje: 'PIN incorrecto' };
    },

    iniciarTransferencia: async (_, { receptorEmail, monto, concepto, pinToken }, { user }) => {
      if (!user) throw new Error('No autorizado');
      try { jwt.verify(pinToken, SECRET); } catch { throw new Error('PIN token invalido'); }

      const receptor = await findOne('usuarios', { email: receptorEmail });
      if (!receptor) throw new Error('Receptor no encontrado');
      if (user.saldo < monto) throw new Error('Saldo insuficiente');

      await updateDoc('usuarios', { _id: user._id },  { $set: { saldo: user.saldo - monto } });
      await updateDoc('usuarios', { _id: receptor._id }, { $set: { saldo: receptor.saldo + monto } });

      const id  = `txn-${Date.now()}`;
      const txn = {
        _id: id, emisor_id: user._id, receptor_id: receptor._id,
        monto, concepto: concepto || '',
        estado: 'completada', fecha: new Date().toISOString(),
        referencia: `VP-${id.slice(-8)}`
      };
      await insertDoc('transacciones', txn);
      return txn;
    },

    resetPassword: async (_, { email }) => {
      const user = await findOne('usuarios', { email });
      if (!user) return { existe: false, hint: null, telefono_parcial: null, email_parcial: null };

      const tel = user.telefono || '';
      return {
        existe: true,
        hint: user.hint_seguridad,
        telefono_parcial: `****${tel.slice(-4)}`,
        email_parcial: email.replace(/(.{2}).*(@.*)/, '$1***$2')
      };
    }
  },

  Usuario: {
    id:             (u) => u._id,
    fechaRegistro:  (u) => u.fecha_registro,
  },

  UsuarioInterno: {
    id: (u) => u._id || u.id,
  },

  Transaccion: {
    id:         (t) => t._id,
    emisorId:   (t) => t.emisor_id,
    receptorId: (t) => t.receptor_id,
  }
};

// ── Start ──────────────────────────────────────────────────────
async function startServer() {
  const server = new ApolloServer({
    typeDefs,
    resolvers,
    introspection: true, 
  });

  await server.start();

  app.use(cors());
  app.use(bodyParser.json({ limit: '50mb' }));
  app.use('/graphql', expressMiddleware(server, { context: getContext }));
  app.get('/health', (_, res) => res.json({ status: 'ok', service: 'VaultPay API' }));

  app.listen(PORT, () => {
    console.log(`VaultPay API corriendo en http://localhost:${PORT}/graphql`);
  });
}

startServer().catch(console.error);
