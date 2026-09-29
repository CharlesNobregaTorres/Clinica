require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const crypto = require('crypto');
const path = require('path');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const isProd = process.env.NODE_ENV === 'production';
const db = new Database(path.join(__dirname, 'data', 'app.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  phone TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'client' CHECK(role IN ('client','admin')),
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS bookings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  date TEXT NOT NULL,
  time TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'Pendente' CHECK(status IN ('Pendente','Confirmado','Recusado')),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
  UNIQUE(date, time)
);
CREATE TABLE IF NOT EXISTS sessions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  token_hash TEXT NOT NULL UNIQUE,
  user_id INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
`);

const adminEmail = String(process.env.ADMIN_EMAIL || '').trim().toLowerCase();
const adminPassword = String(process.env.ADMIN_PASSWORD || '');
if (!adminEmail || !adminPassword || adminPassword.length < 10) {
  console.warn('Configure ADMIN_EMAIL e ADMIN_PASSWORD (mínimo 10 caracteres) no .env antes de usar o admin.');
} else {
  const existing = db.prepare('SELECT id FROM users WHERE email=?').get(adminEmail);
  if (!existing) {
    const hash = bcrypt.hashSync(adminPassword, 12);
    db.prepare('INSERT INTO users(name,phone,email,password_hash,role,created_at) VALUES(?,?,?,?,?,?)')
      .run('Administrador', '', adminEmail, hash, 'admin', new Date().toISOString());
    console.log(`Admin criado: ${adminEmail}`);
  } else {
    const role = db.prepare('SELECT role FROM users WHERE email=?').get(adminEmail);
    if (role && role.role !== 'admin') db.prepare('UPDATE users SET role=\'admin\' WHERE email=?').run(adminEmail);
  }
}

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: false }));

function hashToken(token) { return crypto.createHash('sha256').update(token).digest('hex'); }
function newToken() { return crypto.randomBytes(32).toString('hex'); }
function setSessionCookie(res, token) {
  res.setHeader('Set-Cookie', `rt_session=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${60*60*24*7}${isProd ? '; Secure' : ''}`);
}
function clearSessionCookie(res) { res.setHeader('Set-Cookie', 'rt_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0'); }
function getCookie(req, name) {
  const raw = req.headers.cookie || '';
  const part = raw.split(';').map(x=>x.trim()).find(x=>x.startsWith(name+'='));
  return part ? decodeURIComponent(part.slice(name.length+1)) : null;
}
function currentUser(req) {
  const token = getCookie(req, 'rt_session');
  if (!token) return null;
  const row = db.prepare(`SELECT u.id,u.name,u.phone,u.email,u.role FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?`).get(hashToken(token), Date.now());
  return row || null;
}
function requireAuth(req,res,next) { const user=currentUser(req); if(!user) return res.status(401).json({error:'Não autenticado.'}); req.user=user; next(); }
function requireAdmin(req,res,next) { const user=currentUser(req); if(!user || user.role!=='admin') return res.status(403).json({error:'Acesso administrativo não autorizado.'}); req.user=user; next(); }
function normalizeEmail(v) { return String(v||'').trim().toLowerCase(); }
function validDateTime(date,time) {
  const hours = ['08:00','09:00','10:00','11:00','14:00','15:00','16:00','17:00'];
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date) || !hours.includes(time)) return false;
  const d = new Date(`${date}T${time}:00`);
  return !Number.isNaN(d.getTime()) && d.getTime() > Date.now();
}
function cleanupSessions(){ db.prepare('DELETE FROM sessions WHERE expires_at<=?').run(Date.now()); }
setInterval(cleanupSessions, 60*60*1000).unref();

app.post('/api/auth/register', (req,res)=>{
  const name=String(req.body.name||'').trim(); const phone=String(req.body.phone||'').trim(); const email=normalizeEmail(req.body.email); const password=String(req.body.password||'');
  if(name.length<3) return res.status(400).json({error:'Informe seu nome completo.'});
  if(phone.replace(/\D/g,'').length<10) return res.status(400).json({error:'Informe um WhatsApp válido.'});
  if(!/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({error:'Informe um e-mail válido.'});
  if(password.length<8) return res.status(400).json({error:'A senha precisa ter pelo menos 8 caracteres.'});
  if(db.prepare('SELECT id FROM users WHERE email=?').get(email)) return res.status(409).json({error:'Este e-mail já possui cadastro. Faça login.'});
  const hash=bcrypt.hashSync(password,12); const now=new Date().toISOString();
  const info=db.prepare('INSERT INTO users(name,phone,email,password_hash,role,created_at) VALUES(?,?,?,?,?,?)').run(name,phone,email,hash,'client',now);
  const token=newToken(); db.prepare('INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)').run(hashToken(token),info.lastInsertRowid,Date.now()+7*24*60*60*1000); setSessionCookie(res,token);
  res.status(201).json({user:{id:info.lastInsertRowid,name,phone,email,role:'client'}});
});

app.post('/api/auth/login',(req,res)=>{
  const email=normalizeEmail(req.body.email); const password=String(req.body.password||'');
  const user=db.prepare('SELECT * FROM users WHERE email=?').get(email);
  if(!user || !bcrypt.compareSync(password,user.password_hash)) return res.status(401).json({error:'E-mail ou senha inválidos.'});
  const token=newToken(); db.prepare('INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)').run(hashToken(token),user.id,Date.now()+7*24*60*60*1000); setSessionCookie(res,token);
  res.json({user:{id:user.id,name:user.name,phone:user.phone,email:user.email,role:user.role}});
});

app.post('/api/auth/logout',(req,res)=>{ const token=getCookie(req,'rt_session'); if(token) db.prepare('DELETE FROM sessions WHERE token_hash=?').run(hashToken(token)); clearSessionCookie(res); res.json({ok:true}); });
app.get('/api/auth/me',(req,res)=>{ const user=currentUser(req); res.json({authenticated:!!user,user:user||null}); });

app.get('/api/availability',(req,res)=>{
  const rows=db.prepare("SELECT date,time FROM bookings WHERE status IN ('Pendente','Confirmado')").all();
  const occupied={}; for(const r of rows){ (occupied[r.date] ||= []).push(r.time); }
  res.json({occupied});
});

app.get('/api/bookings',requireAuth,(req,res)=>{
  const rows=req.user.role==='admin'
    ? db.prepare(`SELECT b.id,b.date,b.time,b.status,b.created_at,b.updated_at,u.id user_id,u.name,u.phone,u.email FROM bookings b JOIN users u ON u.id=b.user_id ORDER BY b.date,b.time`).all()
    : db.prepare(`SELECT b.id,b.date,b.time,b.status,b.created_at,b.updated_at FROM bookings b WHERE b.user_id=? ORDER BY b.date,b.time`).all(req.user.id);
  res.json({bookings:rows});
});

app.post('/api/bookings',requireAuth,(req,res)=>{
  const date=String(req.body.date||''); const time=String(req.body.time||'');
  if(req.user.role!=='client') return res.status(403).json({error:'Administradores não fazem agendamentos de cliente.'});
  if(!validDateTime(date,time)) return res.status(400).json({error:'Data ou horário inválido.'});
  const exists=db.prepare("SELECT id FROM bookings WHERE date=? AND time=? AND status IN ('Pendente','Confirmado')").get(date,time);
  if(exists) return res.status(409).json({error:'Este horário acabou de ser ocupado.'});
  const now=new Date().toISOString();
  try {
    const info=db.prepare('INSERT INTO bookings(user_id,date,time,status,created_at,updated_at) VALUES(?,?,?,?,?,?)').run(req.user.id,date,time,'Pendente',now,now);
    res.status(201).json({booking:{id:info.lastInsertRowid,date,time,status:'Pendente'}});
  } catch(e){ if(String(e.message).includes('UNIQUE')) return res.status(409).json({error:'Este horário já está ocupado.'}); throw e; }
});

app.patch('/api/admin/bookings/:id/status',requireAdmin,(req,res)=>{
  const status=String(req.body.status||''); if(!['Confirmado','Recusado'].includes(status)) return res.status(400).json({error:'Status inválido.'});
  const booking=db.prepare('SELECT * FROM bookings WHERE id=?').get(req.params.id); if(!booking) return res.status(404).json({error:'Agendamento não encontrado.'});
  const now=new Date().toISOString();
  if(status==='Confirmado'){
    const conflict=db.prepare("SELECT id FROM bookings WHERE date=? AND time=? AND status='Confirmado' AND id<>?").get(booking.date,booking.time,booking.id);
    if(conflict) return res.status(409).json({error:'Esse horário já foi confirmado em outro agendamento.'});
  }
  db.prepare('UPDATE bookings SET status=?,updated_at=? WHERE id=?').run(status,now,booking.id);
  res.json({ok:true});
});

app.get('/api/admin/clients',requireAdmin,(req,res)=>{
  const rows=db.prepare(`SELECT u.id,u.name,u.phone,u.email,u.created_at,COUNT(b.id) booking_count FROM users u LEFT JOIN bookings b ON b.user_id=u.id WHERE u.role='client' GROUP BY u.id ORDER BY u.created_at DESC`).all();
  res.json({clients:rows});
});

app.get('/api/admin/stats',requireAdmin,(req,res)=>{
  const clients=db.prepare("SELECT COUNT(*) c FROM users WHERE role='client'").get().c;
  const pending=db.prepare("SELECT COUNT(*) c FROM bookings WHERE status='Pendente'").get().c;
  const confirmed=db.prepare("SELECT COUNT(*) c FROM bookings WHERE status='Confirmado'").get().c;
  res.json({clients,pending,confirmed});
});

app.use(express.static(path.join(__dirname,'public'),{extensions:['html']}));
app.get('/admin',(req,res)=>res.sendFile(path.join(__dirname,'public','admin.html')));

app.use((err,req,res,next)=>{ console.error(err); res.status(500).json({error:'Erro interno do servidor.'}); });
app.listen(PORT,()=>console.log(`Rebecca Torres: http://localhost:${PORT} | Admin: http://localhost:${PORT}/admin`));
