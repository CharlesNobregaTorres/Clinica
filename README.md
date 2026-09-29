# Rebecca Torres — Agendamento com Área do Cliente e Admin

## Recursos
- Cadastro e login real de clientes.
- Sessão persistente por cookie HTTP-only.
- Senhas de clientes e admin armazenadas com bcrypt.
- Cliente vê somente os próprios agendamentos.
- Solicitações de agendamento entram como `Pendente`.
- Admin entra em `/admin` e vê clientes e todos os agendamentos.
- Admin pode confirmar ou recusar solicitações.
- Horários confirmados/pedidos bloqueiam o slot no calendário.
- SQLite para persistência local.

## Instalação
1. Instale Node.js 20+.
2. Abra o terminal nesta pasta.
3. Execute `npm install`.
4. Copie `.env.example` para `.env`.
5. Defina `SESSION_SECRET`, `ADMIN_EMAIL` e `ADMIN_PASSWORD`.
6. Execute `npm start`.
7. Site: `http://localhost:3000`
8. Admin: `http://localhost:3000/admin`

O admin é criado automaticamente na primeira inicialização usando as variáveis do `.env`.

## Produção
Use HTTPS, um `SESSION_SECRET` forte e um domínio. Faça backup do `data/app.db`. Para hospedagem em múltiplas instâncias, use um banco/armazenamento de sessão compartilhado.

## Acesso inicial do admin (somente para instalação local)
- E-mail: `admin@rebeccatorres.com`
- Senha: `RT_Admin!2026#Secure`

Troque a senha no `.env` antes de publicar o sistema. O servidor grava somente o hash bcrypt da senha no banco.
