# ADR 0021 — Tokens pessoais restritos de leitura

- **Status:** Fatia inicial de leitura; publicação e contas de serviço pendentes
- **Data:** 2026-11-07

## Contexto

Clientes não interativos precisam acessar conteúdo sem reutilizar cookies de sessão. Tokens pessoais continuam representando a pessoa, não uma conta de serviço, e não podem conservar acesso depois que seu usuário, membership ou grant de leitura deixa de estar ativo.

## Decisão

- Emitir inicialmente somente tokens pessoais de leitura para um repositório. Cada token contém ID opaco e 32 bytes aleatórios; o banco guarda somente SHA-256 do segredo, metadados, escopo e expiração. O valor completo é mostrado uma única vez e nunca em URLs ou logs.
- A emissão exige sessão humana, MFA recente e grant `reader` explícito atual, dentro da transação de autorização. O prazo inicial é no máximo 30 dias; prazo configurável e rotação com sobreposição controlada continuam pendentes.
- Toda validação verifica segredo em tempo constante, expiração e revogação. O token fica vinculado ao ID do grant `reader` ativo na emissão; a validação verifica usuário, membership e esse grant específico. Revogá-lo invalida o token mesmo que outro grant seja concedido depois; o token nunca amplia acesso. A validação e a leitura subsequente são operações separadas: requisições já autenticadas podem concluir após revogação individual, inclusive se ainda não abriram o storage.
- A transição de usuário ativo para suspenso ou desprovisionado revoga os tokens em trigger transacional nos dois bancos, impedindo reativação automática posterior. Futuras operações de suspensão ainda precisam coordenar sessões/grants, auditoria e a mesma ordem de locks; o trigger isolado não constitui implementação de SCIM ou de toda a política de suspensão.
- O usuário pode listar metadados de seus tokens e revogar um token seu mesmo depois de perder o grant do repositório, desde que ainda tenha sessão humana válida. Se a resposta de criação for perdida, o segredo não pode ser recuperado: listar, revogar o token órfão e emitir outro é o caminho seguro; não afirmar idempotência de emissão.
- A primeira integração bearer será específica de manifesto e download genérico privado, com header Authorization e download na origem separada. Publicação por token, contas de serviço, integração com clientes nativos e trusted publishing permanecem desabilitados até seus contratos próprios existirem.
- A emissão usa `POST /api/v1/workspaces/{workspaceID}/repositories/{repositoryID}/personal-read-tokens` com `ttl_seconds` opcional; listagem e revogação usam `/api/v1/personal-read-tokens`. O manifesto por bearer fica em `/api/v1/token/workspaces/{workspaceID}/repositories/{repositoryID}/artifacts/{artifactVersionID}` na origem canônica; bytes ficam em `.../files/{fileID}` na origem de assets. Bearers são aceitos somente no header `Authorization`, nunca em path/query; essas rotas não habilitam CORS. Emissões e revogações são auditadas sem segredos.
- Falhas de autenticação bearer usam bucket persistente separado por IP observado (20 tentativas por 15 minutos, limpo após autenticação bem-sucedida) e admissão simultânea limitada por processo. O reset por sucesso pode reduzir a efetividade sob solicitações concorrentes do mesmo IP; não é uma proteção de justiça entre tenants nem substitui limites distribuídos.

## Limites

Não armazenar secrets do cliente, não copiar tokens para arquivos de configuração do produto, não expor em logs/URLs e não repassá-los por redirects. Autorização e rate limits de clientes nativos, rotação, telemetria de último uso, revogação por suspensão/SCIM e recovery operacional completo continuam obrigatórios. A capacidade inicial não é suporte Pub/Go/Cargo/npm/Hex/OCI.
