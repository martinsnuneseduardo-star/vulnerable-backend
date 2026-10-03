# Vulnerable Backend

Backend em Node.js/Express **propositalmente vulnerável**, criado para estudo de segurança de aplicações (estilo DVWA / Juice Shop).

> ⚠️ **AVISO:** não execute em servidores públicos, não use em produção e não reutilize este código. Rode apenas localmente ou em ambiente isolado (laboratório, VM, container sem exposição). O servidor escuta em `127.0.0.1` por padrão.

## Como rodar

```bash
npm install
npm start
# ou
docker build -t vuln-backend . && docker run --rm -p 127.0.0.1:3000:3000 vuln-backend
```

## Vulnerabilidades

| # | Endpoint | Vulnerabilidade | OWASP Top 10 (2021) |
|---|----------|-----------------|---------------------|
| 1 | `POST /api/register` | Mass assignment (cliente define `role`), senha em texto puro | A04 / A02 |
| 2 | `POST /api/login` | SQL Injection | A03 |
| 3 | `GET /api/users/:id` | IDOR + vazamento de senha | A01 / A02 |
| 4 | JWT | Segredo fraco e hardcoded, sem expiração | A02 / A07 |
| 5 | middleware `auth` | `jwt.decode` sem verificar assinatura (token forjável) | A07 |
| 6 | `GET /api/products/search` | SQL Injection (UNION) | A03 |
| 7 | `GET /api/greet` | XSS refletido | A03 |
| 8 | `GET /api/ping` | Command Injection | A03 |
| 9 | `GET /api/files` | Path Traversal | A01 |
| 10 | Global | CORS aberto para qualquer origem | A05 |
| 11 | Erros | Stack trace e SQL expostos | A05 |
| 12 | `GET /api/fetch` | SSRF | A10 |
| 13 | `GET /api/admin/users` | Controle de acesso quebrado (role vem do token forjável) | A01 |
| 14 | `GET /api/debug` | Exposição de variáveis de ambiente e segredos | A05 |
| 15 | Global | Sem rate limiting (brute force) | A07 |

## Por onde começar

Tente descobrir e explorar cada falha sozinho antes de olhar as correções. Algumas dicas:

- **Login:** o que acontece se o username contiver uma aspa simples (`'`)?
- **Busca:** como a query é montada? Dá para concatenar um `UNION SELECT` na tabela `users`?
- **Token:** o servidor realmente confere a assinatura do JWT?
- **Files:** o parâmetro `name` aceita `../`?

## Como corrigir (exercício)

- **SQL Injection:** usar prepared statements (`?`) em todas as queries.
- **Senhas:** hash com `bcrypt` ou `argon2`.
- **JWT:** `jwt.verify` com segredo forte vindo de variável de ambiente, e expiração.
- **Mass assignment:** ignorar `role` vindo do cliente (allowlist de campos).
- **IDOR:** conferir se `req.user.id === req.params.id` ou se o usuário é admin.
- **XSS:** escapar saída ou retornar JSON, e usar CSP.
- **Command Injection:** não usar `exec` com input; usar `execFile` com validação, ou evitar.
- **Path Traversal:** `path.resolve` + checar se o caminho final continua dentro de `files/`.
- **SSRF:** allowlist de hosts e bloqueio de IPs internos.
- **CORS, erros e debug:** restringir origens, mensagens genéricas, remover `/api/debug`.
- **Brute force:** `express-rate-limit` e bloqueio de contas.

## Licença

MIT. Uso educacional, por sua conta e risco.

## Pipeline de segurança (DevSecOps)

Os workflows em `.github/workflows/` cobrem as categorias abaixo. Os jobs **não falham o build** de propósito, pois o objetivo é gerar achados.

| Categoria | Ferramenta | Onde |
|-----------|-----------|------|
| SAST | Semgrep, CodeQL | `security.yml` |
| SCA | Trivy, `npm audit`, Dependabot, Dependency Review | `security.yml`, `dependabot.yml` |
| Secrets | Gitleaks | `security.yml` |
| IaC | Trivy config, Checkov (Dockerfile / Actions) | `security.yml` |
| Container | Trivy image | `security.yml` |
| DAST | OWASP ZAP baseline, Nuclei | `security.yml` |
| License | Trivy license | `security.yml` |
| End of Life | endoflife.date (`scripts/check-eol.sh`) | `security.yml` |
| Posture / SDLC | OpenSSF Scorecard | `scorecard.yml` |

Os resultados aparecem em **Security → Code scanning** (SARIF). Para o Scorecard publicar resultados, o repositório precisa ser público. Em repositório privado, Code Scanning exige GitHub Advanced Security.
