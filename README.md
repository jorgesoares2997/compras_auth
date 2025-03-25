# Compras Auth Service

Serviço de autenticação para a aplicação Compras, suportando login com Google e GitHub.

## Requisitos

- Java 17
- Maven
- PostgreSQL
- Docker (opcional, para containerização)

## Configuração Local

1. Clone o repositório
2. Configure as variáveis de ambiente no arquivo `.env`:
   ```
   SPRING_DATASOURCE_URL=jdbc:postgresql://localhost:5432/compras_auth
   SPRING_DATASOURCE_USERNAME=seu_usuario
   SPRING_DATASOURCE_PASSWORD=sua_senha
   PORT=8080
   
   # Credenciais do Google OAuth2
   GOOGLE_CLIENT_ID=seu_client_id
   GOOGLE_CLIENT_SECRET=seu_client_secret
   GOOGLE_REDIRECT_URI=http://localhost:8080/api/auth/google/callback
   
   # Credenciais do GitHub OAuth2
   GITHUB_CLIENT_ID=seu_client_id
   GITHUB_CLIENT_SECRET=seu_client_secret
   GITHUB_REDIRECT_URI=http://localhost:8080/api/auth/github/callback
   ```

3. Execute o projeto:
   ```bash
   ./mvnw spring-boot:run
   ```

## Deploy com Docker

1. Construa a imagem:
   ```bash
   docker build -t compras-auth .
   ```

2. Execute o container:
   ```bash
   docker run -p 8080:8080 --env-file .env compras-auth
   ```

## Endpoints

### Autenticação Social

- Google:
  - Login: `GET /api/auth/google/login?name={name}&email={email}&message={message}`
  - Callback: `GET /api/auth/google/callback`

- GitHub:
  - Login: `GET /api/auth/github/login?name={name}&email={email}&message={message}`
  - Callback: `GET /api/auth/github/callback`

### Autenticação JWT

- Registro: `POST /api/auth/register`
- Login: `POST /api/auth/login`

## Configuração do OAuth2

### Google

1. Acesse o [Google Cloud Console](https://console.cloud.google.com)
2. Crie um novo projeto ou selecione um existente
3. Ative a API do Google+ API
4. Configure as credenciais OAuth2:
   - Tipo: Web Application
   - URIs de redirecionamento autorizados: `http://localhost:8080/api/auth/google/callback`
   - Escopos: `email`, `profile`

### GitHub

1. Acesse as [Configurações de Desenvolvedor do GitHub](https://github.com/settings/developers)
2. Crie um novo OAuth App
3. Configure:
   - Homepage URL: `http://localhost:8080`
   - Authorization callback URL: `http://localhost:8080/api/auth/github/callback`
   - Escopos: `user:email`, `read:user`

## Segurança

- Todas as senhas são hasheadas com BCrypt
- Tokens JWT são usados para autenticação
- CORS está configurado para permitir apenas origens específicas
- Headers de segurança são configurados automaticamente 