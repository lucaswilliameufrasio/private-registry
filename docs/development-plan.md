# Plano de desenvolvimento — Registry privado de pacotes e artefatos

**Data original:** 02/10/2026; decisões consolidadas em 04/10/2026

**Estado:** especificação revisada; fase 0 em execução, com spikes SQLite local e roundtrip S3/Floci comprovados; atomicidade concorrente do storage ainda pendente

**Nome de trabalho:** Private Registry; nome comercial ainda não escolhido  
**Repositório sugerido:** `artifact-registry` — sugestão técnica, sem pressupor disponibilidade
**Distribuição atual:** repositório privado, sem licença definida; definir termos antes de distribuir para terceiros

## 1. Objetivo e decisões consolidadas

Construir um registry self-hosted para hospedar, publicar e consumir pacotes privados de Dart/Flutter, Go, Rust, Node.js, Elixir/Erlang e imagens Docker/OCI, além de arquivos genéricos versionados para distribuição por URLs próprias.

A primeira instalação atende aos projetos do proprietário. O produto deve ser instalável por outras equipes e empresas, preservando simplicidade operacional, segurança e capacidade real de recuperação. Hospedagem gerenciada ou SaaS são evoluções possíveis, não requisitos para a primeira versão.

### 1.1 Decisões obrigatórias

| Tema | Decisão |
| --- | --- |
| Implantação inicial | Self-hosted, uma instância ativa por instalação |
| Backend | Go, com módulos bem delimitados no mesmo projeto |
| Frontend | SvelteKit com TypeScript |
| Banco padrão | SQLite |
| Banco opcional | PostgreSQL, com paridade funcional e testes próprios |
| Artefatos | Filesystem local ou S3 compatible, incluindo R2; Floci para desenvolvimento |
| Publicação | Responsabilidade da fonte: desenvolvedor, repositório ou pipeline prepara e envia |
| Registry | Autentica, autoriza, valida, armazena, indexa e disponibiliza; não constrói código de clientes |
| Pacotes privados | Necessidade principal; padrão de novos repositórios |
| Pacotes públicos | Permitidos por configuração explícita |
| Proxy de registries públicos | Fora do primeiro escopo; nenhuma busca pública automática de nomes privados |
| Arquivos estáticos | Publicação explícita de bundles e assets já prontos |
| CDN | O produto oferece origem de conteúdo; distribuição geográfica depende de CDN externa |
| Backup | Online, criptografado antes do envio automático ao S3, com restauração validada |
| Autenticação | Senha opcional; OIDC próprio; Google, Apple e GitHub configuráveis |
| CAPTCHA | Turnstile, reCAPTCHA e hCaptcha configuráveis |
| Emails temporários | Bloqueio opcional, lista atualizável, regras manuais e exceções |
| Automação | Contas de serviço, tokens restritos e publicação confiável via OIDC de CI |
| Segurança | Imutabilidade, auditoria, detecção de anomalias, alertas por email e políticas de supply chain |
| Escopo da v1 | Os sete formatos: Pub, Go, Cargo, npm, Hex, OCI e genéricos; entregas parciais não são a v1 completa |
| Rede isolada | Instalação, atualização, operação e recuperação offline são requisitos da v1 |
| Plataformas do servidor | Linux amd64/arm64, por Docker Compose ou binário/systemd |
| CLI de publicação | Linux, Windows e macOS; compatibilidade comprovada por testes |
| Provisionamento corporativo | OIDC + SCIM 2.0, com Authentik como primeira integração de referência, opcional |
| MFA | TOTP, códigos de recuperação e passkeys na v1 |
| Revisão humana | Opcional por repositório, sem autoaprovação, distinta de recebimento e publicação |
| Limites de tráfego/downloads | Fora da v1; métricas e análise autorizada de consumo entram na v1 |
| Recursos adiados | Registro explícito em [roadmap.md](roadmap.md), com motivo e condição de retomada |

### 1.2 Princípios

1. A instalação é simples; a consistência, a recuperação e o isolamento são rigorosos.
2. Compatibilidade é comprovada com clientes reais, não apenas com respostas HTTP semelhantes.
3. Credenciais humanas e de automação são diferentes.
4. Permissão de operar a instalação não equivale a permissão de ler pacotes privados.
5. Uma versão publicada nunca muda de bytes; recebimento não equivale a publicação.
6. Backup enviado e backup restaurado são estados distintos.
7. Origem aparente de rede é um sinal de risco, não identidade comprovada.
8. Recursos futuros não justificam microserviços, filas externas ou infraestrutura desnecessária no início.
9. Integrações externas devem ter disponibilidade e comportamento de falha explícitos.
10. Logs, alertas e métricas não podem expor segredos ou nomes privados a pessoas sem acesso.
11. Restrição de política para operações futuras e aplicação ao estado existente são ações diferentes.
12. Recursos não entregues têm limitações honestas e registro no roadmap; não há opções de segurança sem efeito.

## 2. Terminologia e escopo do produto

| Termo | Significado |
| --- | --- |
| Instalação | Instância self-hosted com banco, configuração e armazenamento próprios |
| Workspace | Fronteira de colaboração e autorização; exemplo: pessoal ou TixNow; participar não concede leitura automática |
| Repositório | Coleção de um formato, dentro de um workspace; não é um repositório Git |
| Pacote | Identidade lógica do pacote, crate, módulo ou coleção de assets |
| Versão | Identificador aceito segundo as regras do formato |
| Blob | Conteúdo binário identificado por algoritmo/digest |
| Manifest | Documento que referencia arquivos ou blobs; inclui manifests OCI |
| Tag/alias | Referência mutável ou protegida para uma versão/digest |
| Publicador confiável | Identidade de CI explicitamente vinculada a um destino de publicação |
| Proveniência | Declaração verificável da origem e produção de um artefato |
| Quarentena | Restrição de distribuição por incidente ou verificação pendente |
| Conta gerenciada | Conta cujo estado de acesso é controlado por integração de diretório SCIM |
| Concessão delegável | Autorização explícita para conceder uma capacidade; distinta de poder exercê-la |
| Recebimento | Envio aceito para processamento/revisão, sem garantir publicação ou download disponível |

### 2.1 Resultado esperado

- Compartilhar SDKs, componentes e bibliotecas internas sem publicar nos registries oficiais.
- Consumir dependências com `dart pub`, `flutter pub`, `go`, `cargo`, clientes npm e `mix`.
- Publicar e consumir imagens com clientes Docker/OCI.
- Publicar bundles como o Scalar, widgets, CSS, fontes, WASM, documentação estática e binários por URLs versionadas.
- Gerenciar permissões e credenciais numa interface comum.
- Recuperar a instalação em outra máquina usando backups reais e chaves independentes.

### 2.2 Fora do escopo inicial

- Build remoto de pacotes, transformação npm para ESM ou bundling automático.
- Importação de tags/commits de GitHub/GitLab pelo servidor.
- Espelhamento completo, proxy ou cache de registries públicos.
- CDN mundial própria, edge computing e execução de código de usuários.
- Billing, marketplace, cobrança de terceiros e SaaS compartilhado.
- Kubernetes como pré-requisito; Valkey, NATS ou Kafka como dependências obrigatórias.
- Cluster SQLite, active-active, sharding e múltiplos escritores em hosts distintos.
- Garantia de que uma dependência não é utilizada em nenhum projeto externo.
- Garantia de ausência de malware ou vulnerabilidades só por possuir assinatura.
- Scanners de vulnerabilidades, segredos e SBOM; verificação de assinaturas/proveniência não substitui scanners.
- Limites de downloads/tráfego, papéis personalizados e transferências entre workspaces.
- Servidor oficialmente suportado em Windows/macOS; isso não exclui a CLI nessas plataformas.
- Trusted publishing Gitea sem segredo persistente, enquanto não houver mecanismo comprovado.

Essas exclusões não removem as interfaces de extensão necessárias, mas não devem gerar infraestrutura antecipada.

Toda funcionalidade discutida e adiada deve constar no [roadmap](roadmap.md). Este registro não promete prazo nem transforma um recurso futuro em suporte atual. Rede isolada, passkeys, aprovação humana, verificador externo e sincronização contínua de usuários/grupos pertencem à v1 e não podem ser adiados silenciosamente.

## 3. Stack e decisões técnicas

### 3.1 Backend

| Componente | Direção de implementação |
| --- | --- |
| HTTP | `net/http` + Chi; middleware comum de identidade, autorização e limites |
| SQL | `database/sql`; driver SQLite e `pgx` via stdlib para PostgreSQL |
| Queries | SQL explícito; sqlc onde reduzir erros, com geração independente por dialeto |
| Migrations | Goose com diretórios específicos por banco e histórico verificável |
| SQLite | Avaliar `modernc.org/sqlite` para distribuição sem CGO; comprovar backup online no spike inicial |
| S3 | AWS SDK for Go v2, endpoints configuráveis, multipart e cancelamento |
| OIDC | Biblioteca mantida de verificação OIDC/JWT, discovery e JWKS; não escrever o protocolo do zero |
| Senhas | Argon2id com parâmetros versionados e rehash progressivo |
| Criptografia de backup | `filippo.io/age`, sem formato criptográfico próprio |
| Jobs | Fila persistida no banco com leases e retries |
| Observabilidade | Logs estruturados, métricas Prometheus e tracing opcional |
| IDs | UUIDv7 ou outra identidade opaca consistente; não usar slugs como chave de autorização |

Fixar versões das dependências na implementação. Selecionar versões estáveis suportadas; registrar atualizações e manter lockfiles. As bibliotecas citadas são direção técnica, não uma promessa de compatibilidade ainda testada.

### 3.2 Frontend

- SvelteKit + TypeScript, componentes acessíveis e interface responsiva.
- Priorizar `adapter-static` para a administração autenticada, com API Go e frontend servido pelo executável. Confirmar deep links e fallback apenas nas rotas da UI.
- Não aplicar fallback de SPA aos endpoints de pacotes, assets ou OCI.
- Se houver necessidade concreta de SSR, documentar ADR e custo de operar Node separado; o SSR não é pré-requisito do produto.
- Não duplicar decisões de autorização no frontend; toda operação é autorizada no Go.
- Sessão humana em cookie HttpOnly; tokens de automação nunca em localStorage.
- Preparar traduções pt-BR e en, com chaves de mensagem desde o início.

### 3.3 Estrutura sugerida

```text
artifact-registry/
  cmd/
    registry/                 # servidor + comandos de administração
    registryctl/              # publicação auxiliar e recuperação
  internal/
    identity/
    authorization/
    workspaces/
    repositories/
    catalog/
    publication/
    storage/
    protocols/
      pub/
      gomod/
      cargo/
      npm/
      hex/
      oci/
      generic/
    security/
    backup/
    jobs/
    notifications/
    audit/
    admin/
    config/
    database/
      sqlite/
      postgres/
  migrations/
    sqlite/
    postgres/
  web/                        # aplicação SvelteKit
  tests/
    fixtures/
    compatibility/
    recovery/
  deploy/
  docs/
    adr/
    runbooks/
  go.mod
  go.sum
```

Interfaces pequenas junto de quem as consome. Reutilizar regras de domínio sem forçar consultas dos dois bancos a serem idênticas. Não criar abstração genérica para toda operação de qualquer protocolo.

## 4. Arquitetura e fronteiras

### 4.1 Componentes

1. **API e administração:** workspaces, usuários, políticas, catálogo e configuração.
2. **Adapters de protocolo:** apresentam respostas e autenticação exigidas por cada cliente.
3. **Serviço de publicação:** coordena validação, armazenamento e commit.
4. **Armazenamento:** filesystem/S3, com streams, digests e reconciliação.
5. **Jobs persistentes:** emails, backup, verificação, limpeza, indexação e coleta de métricas.
6. **CLI:** configuração assistida, publicação Go/Hex/genérica e recuperação local.
7. **Motor OCI:** componente dedicado opcional para a fase Docker, integrado às políticas centrais.

Não existe transação distribuída entre SQL e S3. O desenho usa estados, objetos imutáveis e reconciliação; nunca simula atomicidade inexistente.

### 4.2 Endpoints e domínios

Exemplos ilustrativos, usando `example.com`:

| Superfície | Exemplo |
| --- | --- |
| Administração | `registry.example.com` |
| API administrativa | `registry.example.com/api/v1/` |
| Pub | `registry.example.com/pub/{workspace}/{repository}/` |
| Go | `registry.example.com/go/{workspace}/{repository}/` |
| Cargo sparse | `registry.example.com/cargo/{workspace}/{repository}/index/` |
| npm | `registry.example.com/npm/{workspace}/{repository}/` |
| Hex | `registry.example.com/hex/{workspace}/{repository}/` |
| OCI | `containers.example.com/v2/` |
| Assets executáveis | `assets.example.com/{workspace}/{repository}/{package}/{version}/{file}` |

Paths são propostas internas; os adapters devem obedecer às rotas reais de seus protocolos. Configurar URL externa canônica, proxy confiável e origens permitidas. O namespace OCI deve ser resolvido no servidor, por exemplo `{workspace}/{repository}/{image}`.

Assets HTML/JS e documentação enviados por usuários ficam fora da origem da administração. Rejeitar configuração que coloque conteúdo executável de clientes na mesma origem das sessões administrativas.

### 4.3 Identidades, nomes e endereços

- Nome de exibição de workspace/repositório é editável; slug usado nas URLs é imutável após criação. Avisar antes de criar.
- IDs opacos continuam sendo a identidade de autorização, independentemente de nomes e paths.
- Renomear identidade de pacote obedece às regras do formato; não há redirecionamento genérico entre nomes na v1.
- Trocar responsáveis dentro do workspace é permitido e auditado. Mover pacote/repositório entre workspaces não entra na v1; URLs, permissões, quotas e credenciais não são transferidas implicitamente.

## 5. Modelagem e invariantes

### 5.1 Entidades

| Grupo | Entidades principais |
| --- | --- |
| Identidade | users, external_identities, password_credentials, mfa_credentials, recovery_codes, sessions |
| Colaboração | workspaces, memberships, teams, team_members, invitations |
| Repositórios | repositories, repository_grants, package_grants, namespace_reservations |
| Catálogo | packages, package_versions, version_files, dependency_metadata, aliases |
| Conteúdo | blobs, blob_locations, upload_sessions, blob_references |
| Automação | service_accounts, credentials, credential_scopes, trusted_publishers |
| Segurança | security_events, incidents, credential_baselines, rule_policies |
| Publicação | publications, publication_checks, attestations, signatures |
| Operação | settings, encrypted_secrets, job_queue, outbox, audit_events |
| Recuperação | backup_jobs, backup_manifests, backup_references, restore_validations |

O modelo comum é complementado por metadados próprios de cada formato. Não exigir SemVer em qualquer artefato genérico nem representar todo manifest OCI como uma versão de biblioteca.

### 5.2 Campos e restrições essenciais

- workspace e repository em toda entidade que pertença a um domínio de acesso.
- Índices únicos para identidade canônica do pacote por repositório e versão canônica por pacote.
- Normalização conforme cada protocolo, com prevenção de colisões de nomes e paths.
- Identidade externa única por `(provider_id, issuer, subject)`; email não é chave de autenticação.
- Credenciais com identificador público, hash do segredo, validade, revogação, finalidade e escopos.
- Não persistir tokens bearer completos nem argumentos que os contenham.
- Blobs com algoritmo, digest, tamanho, estado e localizações verificadas.
- Campos de auditoria: ator, tipo, alvo, resultado, request ID, timestamp e contexto mínimo.
- Estados de jobs com lease owner, lease expiry, contador de tentativas e próxima execução.
- Chaves estrangeiras, validação de integridade e constraints equivalentes nos dois bancos.

### 5.3 Invariantes

1. Download autorizado aponta apenas para objeto completo e verificado.
2. Depois de publicada, a mesma identidade de versão não aceita conteúdo diferente, mesmo depois de exclusão. Tentativa rejeitada antes da publicação não torna a versão permanentemente consumida.
3. Um blob conhecido globalmente não concede direito de baixar seu conteúdo.
4. Operações por digest, busca, listas e mensagens de erro respeitam isolamento.
5. Upload sem commit não entra nos índices dos clientes.
6. Permissões são rechecadas ao finalizar upload, não apenas ao iniciá-lo.
7. Quotas são reservadas atomicamente; concorrência não permite exceder o limite silenciosamente.
8. Exclusão, backup e GC compartilham regras explícitas de retenção.
9. Mudanças sensíveis geram auditoria e evento de notificação de forma transacional.

Preferir deduplicação dentro do workspace no início. Deduplicação entre workspaces exige análise de side channels, quota, isolamento e autorização de cross-mount; não implementá-la implicitamente.

## 6. Fluxo de publicação

### 6.1 Pipeline comum

1. Autenticar identidade e resolver destino autorizado.
2. Validar restrições, tamanho declarado e reserva de quota.
3. Criar sessão de upload com expiração e identificador opaco.
4. Receber conteúdo em streaming, calcular digest e impor limites reais.
5. Validar arquivo, metadados e correspondência de nome/versão.
6. Aplicar verificações e exigências de assinatura/proveniência; se houver revisão humana, persistir a pendência e só liberar após aprovação e revalidação.
7. Tornar objetos duráveis e verificar disponibilidade no storage.
8. Ao publicar, em transação, tornar definitiva a reserva da versão, registrar referências, auditoria e outbox. Reserva enquanto pendente é recuperável por rejeição anterior à publicação.
9. Expor a versão nos endpoints nativos e disparar jobs derivados.

### 6.2 Estados

```mermaid
stateDiagram-v2
    [*] --> receiving
    receiving --> validating
    receiving --> expired
    validating --> rejected
    validating --> pending_review
    validating --> published
    pending_review --> rejected
    pending_review --> published
    published --> quarantined
    quarantined --> published
    published --> deletion_pending
    deletion_pending --> published
    deletion_pending --> deleted
```

Depreciação e retirada da resolução são atributos específicos de ecossistema, não sinônimos de exclusão física. Restaurar da quarentena ou de exclusão pendente exige decisão autorizada e justificada.

### 6.3 Falhas e concorrência

- Upload concluído no S3, mas commit SQL falhou: objeto órfão fica retido por grace period e é reconciliado.
- Dois publicadores enviaram a mesma versão: constraint decide um vencedor; retry só é idempotente com os mesmos bytes e metadados protegidos.
- Enquanto uma publicação estiver pendente, reservar a identidade de versão para impedir disputa concorrente. Rejeição anterior à publicação libera essa identidade para envio corrigido, preservando histórico e recibos da tentativa. Repetição de um recibo rejeitado não ressuscita a tentativa antiga.
- Timeout depois do commit: operação pode consultar recibo ou repetir de forma idempotente.
- Multipart abandonado: job aborta, libera quota e registra resultado.
- Usuário perdeu permissão durante upload: finalização negada.
- Job de scanner atrasou: publicação obrigatoriamente verificada permanece indisponível; não liberar por timeout.
- ÍNDICE e conteúdo: resposta de sucesso não pode preceder a disponibilidade exigida pelo cliente.

O registry nunca executa `npm install`, `mix compile`, `cargo build`, hooks de pacote ou comandos arbitrários de README. Extração e inspeção são operações limitadas, preferencialmente em ambiente isolado.

### 6.4 Aprovação humana

- Política opcional por repositório, desativada por padrão; aprovação exige capacidade específica.
- Publicador não aprova a própria publicação; rejeição exige motivo e auditoria.
- Conteúdo pendente não aparece nos índices nativos nem pode ser baixado. Checks obrigatórios continuam necessários; aprovação humana não os substitui.
- Revalidar políticas e autorizações atuais imediatamente antes de publicar. Alteração de política ou revogação de acesso invalida a elegibilidade anterior; checks desatualizados precisam ser refeitos. Não há direito adquirido às regras do recebimento.
- Usuário desativado ou sem autorização vigente não tem sua publicação pendente liberada; a UI explica o impedimento e preserva o histórico.
- Quando o protocolo permitir com segurança, confirmar recebimento sem prometer disponibilidade; status fica disponível na UI/API/CLI. O comando não espera uma decisão humana indefinidamente.
- Testar esse comportamento com clientes reais de cada formato, inclusive OCI. Se o cliente/protocolo não permitir separar recebimento de publicação com segurança, declarar a limitação e usar envio pela CLI/API; não responder sucesso de publicação nativa fictício.
- Desativar aprovação vale para novos envios, sem liberar a fila existente. Liberação em lote é ação separada, com prévia, confirmação, autorização, auditoria e revalidação das demais exigências.

## 7. Compatibilidade por formato

Cada adapter precisa de contrato, fixtures, testes com cliente e matriz de versões suportadas. O dashboard deve declarar comandos compatíveis e limitações concretas; não usar um selo genérico de suporte antes desses testes.

A matriz da v1 será fixada antes da release, usando a versão estável atual e a linha anterior ainda mantida quando houver, respeitando o ciclo próprio de cada cliente. Não há requisito de compatibilidade com versões antigas dos projetos do proprietário. Versões fora da matriz podem funcionar, mas não recebem garantia; novas versões entram após testes reais.

### 7.1 Dart e Flutter — Pub

- Implementar Hosted Pub Repository API, incluindo consulta, download e publicação autenticada.
- Validar pacote e `pubspec.yaml`, limites do archive e correspondência de versão.
- Suportar tokens e configuração `publish_to`/hosted por dependência.
- Gerar instruções para `dart pub` e `flutter pub`; não substituir globalmente pub.dev quando só se quer dependências privadas.
- Tratar URLs de archive, erros e metadados conforme o cliente.
- Manter retirada/depreciação de versões nos recursos suportados pelo Pub.
- Não exigir Flutter no servidor nem compilar plugins nativos.

Aceite: publicar uma biblioteca Dart e um pacote Flutter, instalar ambos com clientes reais, resolver dependência transitiva privada e impedir acesso sem credencial. Referências: [R1], [R2].

### 7.2 Go — módulos

- Consumo por `GOPROXY`: listagem, latest, `.info`, `.mod` e `.zip`.
- Publicação própria autenticada: a fonte envia o conjunto da versão; nenhuma leitura de Git pelo servidor.
- Usar `golang.org/x/mod` no empacotamento/validação e respeitar regras de módulo e ZIP.
- Validar compatibilidade entre module path, versão e major version, além de escaping do path.
- A CLI empacota localmente e envia; aceitar publicação por API sem a CLI.
- Pseudo-versions exigem suporte explícito e testes; não inventar origem VCS a partir de timestamp.

Configuração ilustrativa quando todos os módulos do cliente passam por este destino privado:

```text
GOPROXY=https://registry.example.com/go/pessoal/modules
GONOPROXY=none
GONOSUMDB=go.example.com
```

A UI deve gerar configuração compatível com a estratégia do cliente, documentar autenticação suportada pela versão do Go e preservar checksum público para módulos públicos. Não recomendar `GOSUMDB=off` global. Fallback externo não deve consultar nomes privados: usar proxy interno que falha de forma terminal para namespaces reservados, ou encaminhamento exclusivamente privado; testar também descoberta por prefixos. Referências: [R3], [R4].

No uso misto, o cliente pode consultar primeiro o registry e depois o proxy público, sem que o registry espelhe conteúdo público. O adapter retorna indisponibilidade com fallback apenas para caminhos não privados; namespaces privados ausentes produzem erro terminal compatível com o cliente. Não usar fallback por qualquer erro nem configurar `GOPRIVATE` sem ajustar `GONOPROXY` quando o módulo deve passar pelo registry.

Aceite: `go mod download`, `go get`, versão major v2, dependência privada transitiva e ausência de consulta pública do namespace privado em testes com rede observada.

### 7.3 Rust — Cargo

- Índice sparse autenticado, `config.json`, archive `.crate` e API de publicação.
- Metadata de dependências, features e registries preservada segundo o protocolo.
- Yanking por versão; o comportamento de lockfiles deve ser demonstrado com Cargo real.
- Configuração de credential provider e tokens compatível com os clientes suportados.
- URLs de índice com `sparse+` e configuração por registry nomeado.
- Não hospedar índice Git na primeira entrega, salvo necessidade comprovada.

Aceite: `cargo publish`, `cargo build`, crate com features e dependência privada transitiva, yank e uso com lockfile. Referências: [R5], [R6].

### 7.4 Node.js, TypeScript e SvelteKit — npm

- Metadata/packuments, tarballs, versões, integridade, scopes e dist-tags.
- Publicar e consumir pacotes como `@tixnow/ui`, `@tixnow/api-client` e `@tixnow/shared`.
- `.npmrc` por scope e credencial vinculada ao host/path correto.
- Suportar token pré-configurado; login interativo apenas nos modos efetivamente implementados.
- Permissões de publicação separadas de mover dist-tags e de remover versões.
- Preservar `exports`, tipos, dependências e campos necessários para pacotes Svelte.
- Compatibilidade npm obrigatória; pnpm, Yarn e Bun entram na matriz somente após testes.
- Sem promessa de API de audit de registry público; exibir claramente se não implementada.

Aceite: `npm publish`, `npm ci`, integridade, atualização protegida de dist-tag e consumo de componente Svelte em um projeto SvelteKit. Referências: [R7], [R8].

### 7.5 Elixir/Erlang — Hex

- Repositório autenticado, tarballs e registry assinado com chave gerenciada.
- Indexação e distribuição compatíveis com Mix/Hex e metadados de dependências.
- Primeiro caminho de publicação: fonte executa `mix hex.build` e envia tarball pela API/CLI.
- Gerar instruções de registro do repository, autenticação e chave pública confiável.
- A geração de metadados de distribuição assinados é responsabilidade do registry, não build do pacote.
- Compatibilidade com publicação nativa `mix hex.publish` depende da API/configuração Hex efetivamente implementada. Não pressupor uma opção `--repo` inexistente nem considerar self-hosting estático uma API completa de publicação.
- Primeiro consumo: `mix deps.get`; suporte adicional a rebar3 e docs precisa de testes separados.
- Mudança da chave de assinatura exige distribuição de confiança e preservação das chaves necessárias à recuperação.

Aceite: publicar tarball já construído, instalar com Mix, resolver pacote privado transitivo, rejeitar metadata alterada e validar restauração de repositório assinado. Referências: [R9], [R10].

### 7.6 Docker/OCI

**Direção inicial:** integrar CNCF Distribution como data plane OCI opcional, em processo/container separado, sem escrever um registry completo do zero. Esta escolha precisa de um spike antes de implementação definitiva.

- Compatibilidade com push/pull, HEAD, manifests, blobs, tags, uploads interrompidos e imagens multiplataforma.
- Token service central com audience, escopos push/pull e expiração curta.
- Todas as requisições passam por gateway confiável; o motor OCI não é exposto diretamente.
- Gateway verifica autorização/revogação atual e aplica quotas, bloqueios e auditoria.
- Configurar storage local/S3 do motor pela administração com mudanças controladas e validação.
- Catálogo da UI é projeção reconciliável; manifests no motor são a fonte de verdade OCI.
- Upload de manifest só é liberado depois das verificações obrigatórias; guardar recibo e reconciliar projeção se o commit no catálogo falhar.
- Não contar somente eventos de push: incluir reconciliação de manifests/tags reais.
- Referrers, assinaturas e SBOM devem ser testados na versão escolhida do motor.
- Cross-repository mount exige acesso ao destino e à origem; entre workspaces fica desabilitado inicialmente.

**Decisão de aceite do spike:** comprovar gate de publicação, isolamento, quotas, revogação, exportação/restauração e integração de GC. Se o motor não permitir as garantias, registrar ADR e adotar adapter OCI próprio ou backend alternativo; não entregar um bypass de segurança silencioso.

O formato interno do storage OCI não se mistura implicitamente ao CAS dos demais pacotes. Backup e GC têm adapters próprios e coordenação central. Referências: [R11], [R12].

### 7.7 Artefatos genéricos e assets

- Publicação de coleção versionada com manifest de arquivos: path, tamanho, MIME, digest e política de acesso.
- Paths relativos normalizados; impedir traversal e colisões; não servir arquivos fora da coleção.
- Upload de arquivo individual ou archive com extração limitada.
- Downloads via GET/HEAD, ETag e Range nos casos suportados.
- URLs de versões imutáveis com cache longo para conteúdo público; aliases mutáveis têm cache curto e proteção própria.
- CORS e Content-Type configurados com defaults restritos; `nosniff`.
- HTML/JS/SVG enviados por usuários nunca na origem da administração.
- URL privada exige credencial compatível ou link assinado de vida curta. Nunca colocar token permanente num `<script src>`. Visibilidade é herdada do repositório, não escolhida individualmente por arquivo.
- UI oferece URL de cada arquivo, snippet, hash/SRI quando aplicável e opção de download.
- Origem própria pode estar atrás de CDN externa, sem cache compartilhado de conteúdo privado por default.

Aceite: servir bundle pré-construído do Scalar e um widget próprio por versão, validar integridade, Range e separação de origem. O registry não precisa resolver dependências nem transformar arquivos. Referência contextual: [R13].

Downloads privados passam pelo registry por padrão, com autorização vigente. Links assinados diretos são opção explícita por repositório: validade padrão de 5 minutos, teto inicial de 15 minutos configurável pelo administrador da instalação; workspace pode reduzir, não ultrapassar o teto. Quem obtiver o link pode usá-lo enquanto válido. Revogação/quarentena pode não invalidar links emitidos, e expiração normalmente impede novas requisições, não necessariamente um download já iniciado. Exibir essa janela e não prometer bloqueio imediato universal.

## 8. Autenticação humana e cadastro

### 8.1 Bootstrap

1. Instalação inicia em modo de configuração, com segredo de bootstrap entregue por canal local.
2. Primeiro administrador define URL externa, conta inicial, banco e armazenamento.
3. Criar material de chave e exportar kit de recuperação.
4. Testar configuração antes de ativar métodos externos.
5. Encerrar bootstrap definitivamente; impedir tomada da instalação por nova visita pública.

Cadastro fechado por padrão. Opções: somente administradores, convites, ou cadastro aberto. Convites têm expiração, escopo, uso único e estado verificável. Convites para workspaces diferentes não concedem acesso à instalação inteira.

Cadastro e criação de workspaces são configurações independentes do administrador da instalação. Criação de workspaces pode ser restrita ao administrador, a usuários explicitamente autorizados ou a qualquer usuário cadastrado, sujeita aos limites definidos. Abrir cadastro não libera automaticamente criação de workspace.

Cadastro aberto local, com senha/passkey, exige email verificado e transporte de email funcional; impedir sua ativação sem esse transporte. Login federado pode aceitar email verificado pelo IdP conforme política explícita. Contas criadas por administrador e convites seguem política separada, permitindo operação interna sem email. Verificação não concede acesso a workspace nem vincula contas automaticamente.

### 8.2 Métodos

| Método | Requisito |
| --- | --- |
| Senha local | Opcional; senha forte, hash Argon2id, reset de uso único e rate limit |
| OIDC próprio | Configuração de issuer, client ID/secret, scopes e mapeamento de claims |
| Google | Adapter configurável com identidade estável e callbacks registrados |
| Apple | Adapter com configurações e rotação de credenciais próprias do provedor |
| GitHub | OAuth configurável; consultar identidade estável e email verificado quando exigido |
| Passkeys/TOTP | Ambos na v1; passkey pode autenticar sem senha com verificação do usuário; TOTP com senha e códigos de recuperação |

OIDC próprio significa integrar um provedor externo controlado pelo operador, como um IdP corporativo. Não significa construir um servidor de identidade próprio. GitHub para login humano e OIDC de GitHub Actions são integrações distintas.

Fluxos de login: authorization code, PKCE onde suportado, `state`, `nonce` em OIDC, redirect URI fixa e validação dos tokens. Validar emissor, assinatura, audiência e validade usando biblioteca mantida. Não aceitar algoritmos arbitrários nem URLs de discovery fornecidas por usuários comuns. Referência normativa: [R14].

### 8.3 Contas e sessões

- Vinculação de provedor exige sessão recente e confirmação explícita.
- Nunca mesclar contas automaticamente só porque o email coincide.
- Grupos do diretório podem mapear para equipes; mapeamentos são allowlists controladas, com origem de cada concessão registrada. OIDC autentica; SCIM mantém continuamente o provisionamento de contas gerenciadas, sem depender de novo login.
- Exigir regras explícitas para privilégios elevados; não interpretar qualquer claim como administração.
- Desativar senha somente após testar login alternativo de administrador e confirmar recuperação local.
- Verificação de email quando a política exigir; suporte a email relay da Apple sem classificá-lo automaticamente como temporário.
- Sessões revogáveis, cookie Secure/HttpOnly/SameSite e defesa CSRF nos endpoints humanos.
- Rotacionar sessão no login, MFA e mudança de privilégio.
- Duração padrão: 12 horas absolutas e 1 hora de inatividade; ajustável.
- Reautenticação recente para alterar IdP, credenciais, permissões, backups, chaves e visibilidade.
- Banimento/suspensão revoga sessões, tokens pessoais e acessos dependentes. Contas de serviço independentes não são suspensas automaticamente; alertar para designar responsável e avaliar rotação quando o usuário suspenso era o único responsável ativo.
- Não confiar em logout federado como única revogação local.

### 8.4 MFA, passkeys e recuperação

- Administrador da instalação pode exigir MFA de todos; por padrão, exigir de administradores da instalação e proprietários/administradores de workspace.
- TOTP, passkeys e códigos de recuperação entram na v1. Contas de serviço usam políticas de credencial próprias, não MFA humano.
- Passkey pode substituir senha + segundo fator quando a autenticação exigir e comprovar verificação do usuário pelo autenticador, como PIN/biometria. Presença/toque sem essa verificação não satisfaz MFA.
- MFA federado só satisfaz a política com evidência verificável do IdP segundo configuração explícita, não por inferência de que qualquer login externo é multifator.
- Recuperação começa por códigos de uso único. Sem códigos, administrador da instalação pode iniciar reset local de MFA com reautenticação própria, justificativa, auditoria e notificação ao usuário.
- Reset não entrega sessão; usuário comprova identidade novamente e cadastra novo fator. Email sozinho não remove MFA.
- Fatores do IdP são recuperados nele; o registry não os reseta. Último administrador sem acesso usa procedimento local autorizado de recuperação.
- Conta local de emergência é separada e não gerenciada por SCIM; preservar seu uso auditado para falhas de integração.

### 8.5 Provisionamento contínuo de usuários e grupos

- OIDC + endpoint SCIM 2.0 interoperável na v1. Authentik é a primeira integração testada e documentada, opcional; não é dependência obrigatória da instalação.
- SCIM provisiona usuários, grupos, associação e desativação independentemente do login. Não confundir suporte SCIM de entrada de um IdP com capacidade de enviar mudanças para aplicações.
- Testar mudanças incrementais, reconciliação completa, remoção de grupos, desativação, retries e recuperação de conectividade com versão fixada do Authentik.
- Correlacionar identidades por identificadores estáveis e vínculo explícito validado; não adotar conta local existente apenas por coincidência de email/nome. Credencial SCIM é de alto privilégio, restrita à integração e a mapeamentos autorizados; não concede administração global arbitrária.
- Remoção de grupo retira concessões originadas daquele mapeamento, preservando concessões manuais independentes. Desativação da conta gerenciada bloqueia todos os seus métodos de login, inclusive senha, passkey e outro provedor vinculado.
- Aplicar mudança recebida imediatamente; meta de entrega e aplicação em condições normais: até 1 minuto, a comprovar em testes. Documentar limitações reais, sem garantia instantânea universal.
- Desativação revoga sessões e tokens pessoais e impede liberação de publicações pendentes sob aquela identidade. Contas de serviço independentes exigem avaliação própria, não suspensão automática.
- Outros IdPs são possíveis por protocolos interoperáveis, mas suporte oficial depende de testes; conectores específicos adicionais têm registro no roadmap.

### 8.6 Falha de sincronização e bloqueios

- Silêncio sem eventos não prova falha. Medir saúde por reconciliação/sinal verificável, com contrato técnico e teste de falha; ausência de eventos não serve de heartbeat.
- Falha comprovada gera alerta e, após prazo configurável com default de 1 hora, bloqueia acessos humanos das contas gerenciadas pela integração, incluindo sessões, tokens pessoais e métodos alternativos da mesma conta.
- Não apagar usuários nem interpretar falha de comunicação como remoção de grupos. Não permitir expansão de acesso baseada em estado incompleto.
- Área de saúde das integrações e bloqueios mostra causa, integração, última reconciliação completa bem-sucedida, início da falha, prazo, usuários afetados e ações para testar/reconciliar/desbloquear.
- Reconciliação completa bem-sucedida remove automaticamente apenas bloqueios de indisponibilidade, respeitando estado/permissões atuais. Usuários desativados continuam bloqueados; sessões revogadas não são reativadas, exigindo novo login.
- Exceção durante a falha exige administrador local autorizado, reautenticação, justificativa, validade e auditoria. Não restaura acesso comprovadamente revogado.
- Conta local de emergência, contas de serviço independentes, outros usuários não afetados e downloads públicos continuam funcionando. Links privados assinados já emitidos respeitam a janela de validade documentada.
- Comprovar observação de saúde e recuperação sem transformar o requisito em polling genérico fictício: SCIM sozinho não garante detecção de canal indisponível, e o mecanismo do Authentik precisa ser validado no spike.

### 8.7 CAPTCHA e domínio temporário

- Providers: Turnstile, reCAPTCHA e hCaptcha; opção de desligar.
- Seleção de versão/modalidade do reCAPTCHA é explícita e testada; não tratar v2, v3 e Enterprise como equivalentes.
- Verificação server-side, hostname/action quando aplicável, validade e replay conforme provedor.
- Aplicar em cadastro, recuperação e login suspeito; nunca exigir challenge HTML de `cargo`, `go`, npm ou Docker.
- Falha do provider: default negar o fluxo protegido com mensagem clara; administrador pode configurar política alternativa documentada.
- Bloqueio de domínios temporários opcional; normalização, listas versionadas, atualizações verificadas, inclusões e exceções.
- Não remover acesso de conta existente silenciosamente quando a lista mudar.
- Teste de conexão e challenge antes de ativar política global.

Referências de CAPTCHA: [R15], [R16], [R17].

## 9. Autorização e privacidade

### 9.1 Papéis

| Papel | Capacidades |
| --- | --- |
| Administrador da instalação | Saúde, configurações, armazenamento, backups e operação |
| Proprietário do workspace | Ler e gerir todos os repositórios do workspace; autoridade máxima para concessões explícitas |
| Administrador do workspace | Ler e gerir todos os repositórios do workspace, com delegação restrita de permissões |
| Leitor | Listar e baixar conteúdo autorizado |
| Publicador | Publicar em pacotes permitidos; sem gerir membros ou apagar versões |
| Mantenedor | Depreciar, retirar da resolução e gerir referências dentro do escopo |
| Responsável de segurança | Investigar incidentes e quarentenar conforme concessões explícitas |

Permissões específicas: criar pacote, publicar versão, mover alias, mudar visibilidade, transferir ownership, quarentenar, restaurar, excluir definitivamente e gerir credenciais. Papéis prontos reduzem configuração repetitiva; exceções por pacote são possíveis, não obrigatórias.

Na v1, papéis predefinidos têm capacidades fixas e são combináveis por escopo; permissões específicas, como publicar/aprovar, podem ser concedidas separadamente. Papéis personalizados ficam no roadmap. A UI explica acesso efetivo e origem de cada concessão.

Proprietário e administrador do workspace não recebem publicação automaticamente: precisam de concessão própria. Demais membros não recebem leitura só por participar. Permissões por workspace/repositório/pacote são aditivas, sem negação por pacote; conteúdo mais restrito deve ficar em outro repositório.

Usar e delegar uma permissão são capacidades distintas. Gestão de membros não autoriza autoelevação: administrador só concede capacidades explicitamente delegáveis por ele, não qualquer capacidade que possua. Concessões acima disso exigem proprietário. Proprietário pode conceder a si próprio por ação explícita e auditada, sem herança automática de publicação.

### 9.2 Propriedade e continuidade do workspace

- Permitir vários proprietários; exigir ao menos um ativo.
- Último proprietário não pode sair, ser rebaixado/removido ou excluir sua conta sem transferir propriedade ou usar o fluxo de exclusão do workspace.
- Suspensão de segurança continua permitida, mesmo se atingir o último proprietário. Recuperação de propriedade é explícita e auditada; não concede automaticamente acesso a conteúdo ao administrador da instalação.
- Criação de pacote é capacidade separada de publicar versão. UI/API podem reservar a identidade; primeira publicação humana pode criá-la apenas com ambas as permissões.
- Automação por conta de serviço/trusted publisher só publica em identidades previamente reservadas por alguém autorizado. Permissão de publicar não reserva nomes novos nem autoriza namespace arbitrário.

### 9.3 Visibilidade e descoberta

Visibilidade é definida no repositório inteiro; pacotes, versões e arquivos herdam. Permissões específicas por pacote não mudam visibilidade pública. Modos da v1:

| Modo | Acesso e descoberta |
| --- | --- |
| Privado | Só conteúdo autorizado; nenhuma descoberta anônima |
| Público não listado | Acesso anônimo pelo endereço/protocolo, sem inclusão em catálogo/busca públicos |
| Público listado | Acesso, navegação e busca anônimos |

Não listado não é segredo: endereço conhecido pode ser acessado e compartilhado; endpoints nativos necessários continuam funcionando. Novos repositórios são privados.

Administrador da instalação define modos disponíveis: somente privado; privado + público não listado; ou os três. Restringir opções impede novas escolhas proibidas, sem converter existentes; a UI mostra exceções. Aplicar restrição aos existentes é operação adicional explícita, com prévia dos afetados, aviso de quebra de consumidores, reautenticação, confirmação, auditoria e notificação aos responsáveis.

Na conversão explícita, modos proibidos passam ao mais permissivo ainda permitido: listado → não listado quando permitido; qualquer público → privado quando somente privado. Aplicar controles/invalidação de cache da instalação; cópias externas não podem ser recolhidas. Reabilitar modo não republica conteúdo automaticamente.

Alterar visibilidade exige capacidade própria, inicialmente exclusiva do proprietário e explicitamente delegável; administrador/mantenedor não a recebe automaticamente. Tornar público exige reautenticação e confirmação do alcance. Em incidente localizado, usar quarentena ou mudança do repositório, não converter toda a instalação por acidente.

### 9.4 Regras

- Negar por padrão e resolver contexto antes de qualquer leitura de storage.
- Administração da instalação não concede download automático de conteúdo privado.
- O operador do host/storage tecnicamente pode acessar bytes e backups: a separação da UI é controle de autorização, não criptografia ponta a ponta.
- Qualquer acesso administrativo excepcional a conteúdo exige procedimento auditado e concessão explícita; não adicionar endpoint universal de impersonation.
- Pacotes públicos continuam exigindo autenticação para publicação e gestão.
- Busca, paginação, tamanho, contadores e erros não revelam existência de pacotes privados.
- Credencial de uma conta de serviço não herda tudo que o criador pode fazer.
- Mudança privado → público exige confirmação, reautenticação e aviso de irreversibilidade de cópias externas.
- Mudança público → privado não recolhe cópias já baixadas/cacheadas; requer invalidação controlada das rotas da instalação.

## 10. Contas de serviço, tokens e trusted publishing

### 10.1 Tokens persistentes

- Secret aleatório de alta entropia com prefixo/ID identificável e segredo exibido uma vez.
- Hash/HMAC verificável para armazenamento; tokens de alta entropia não precisam do mesmo KDF lento das senhas.
- Validade obrigatória por padrão; default de 30 dias, teto configurável.
- Separar leitura, publicação e manutenção; sem emissão de token administrativo amplo por default.
- Escopos por workspace/repository/package e operações permitidas.
- Restrições opcionais de CIDR, janela de horário e ambientes esperados.
- Rotação com breve sobreposição explicitamente configurada; revogação independente das chaves antigas.
- Last-used atualizado de forma agregada para evitar uma escrita SQL por download.
- Nenhum token em logs, URLs, exemplos persistidos, emails ou respostas posteriores.

Tokens pessoais restritos são permitidos para publicação manual com clientes nativos, sem exigir conta de serviço por desenvolvedor. São diferentes de credenciais de automação e limitados tanto pelo escopo emitido quanto pelas permissões atuais do usuário. Revogar/remover acesso humano retira acesso correspondente dos tokens; nunca registrar autoria de token pessoal como serviço independente. Pipelines usam contas de serviço ou trusted publishing.

### 10.2 OIDC de CI

1. Administrador cadastra publisher e destino autorizado.
2. Pipeline obtém JWT do issuer permitido.
3. Registry verifica JWKS, algoritmo, issuer, audience, tempo e claims.
4. Comparar identidade estável de owner/repository quando disponível, workflow e branch/tag/environment permitidos.
5. Emitir credencial curta compatível com o cliente de publicação.
6. Restringir credencial ao pacote/repositório e operação necessária.

Default: 5 minutos, com limite máximo ajustável de 15 minutos. Prever duração suficiente para uploads autorizados sem prolongar a credencial arbitrariamente; rechecagem no commit e autorização limitada da sessão de upload.

- Não aceitar qualquer repository da mesma organização automaticamente.
- Regras para PRs e forks são restritas por padrão; releases confiáveis vêm de refs autorizadas.
- Cache de JWKS limitado e atualização controlada; falha de validação nunca libera publicação.
- Mitigar replay do JWT de troca quando houver identificador/hash estável, guardando uso até expirar.
- OIDC não garante que cada uso posterior do bearer vem do runner: o bearer ainda pode ser roubado e monitorado.
- Suportar runners self-hosted; país diferente ou IP doméstico não torna identidade inválida.
- Credencial emitida não permite alterar configurações, criar outra credencial ou trocar visibilidade.

Referência GitHub: [R18]. Clientes com tokens próprios recebem a credencial curta no formato suportado; não precisam aprender OIDC diretamente.

### 10.3 Provedores de CI da v1 e gap Gitea

- GitHub Actions: trusted publishing via OIDC, incluindo runners self-hosted com as mesmas verificações de identidade/claims.
- Gitea Actions: publicação com token restrito de conta de serviço armazenado nos secrets do pipeline, com exemplos e testes reais.
- **Gap explícito:** publicação Gitea sem segredo persistente não é entregue na v1. Compatibilidade com workflows GitHub não comprova emissão de JWT OIDC de job. Confirmar capacidade na versão adotada antes de prometer integração.
- Headers declarados pelo runner, IP e User-Agent não substituem evidência criptográfica. Mecanismo futuro sem segredo persistente fica no roadmap, com contrato e testes de identidade, escopo e replay.
- OIDC de login humano e OIDC de CI permanecem integrações distintas.

## 11. Detecção de abuso e notificações de segurança

### 11.1 Modelo de evento

Guardar identificador de credencial/conta, resultado de autenticação, operação, recurso autorizado, IP observado, ASN/país aproximados, timestamp e sinais disponíveis. Contexto de OIDC verificado é marcado separadamente de headers declarados pelo cliente.

Capturar endereço remoto; aceitar `Forwarded`/`X-Forwarded-For` somente de proxies cadastrados. Não confiar no primeiro IP de um header arbitrário. Usar base GeoIP local atualizável como direção inicial, com licença e data de atualização registradas.

### 11.2 Regras iniciais determinísticas

| Sinal | Default | Observações |
| --- | --- | --- |
| País/ASN novo após baseline | Alerta agrupado | Não comprova comprometimento |
| Uso simultâneo em redes muito distintas | Alta prioridade | Considerar paralelismo legítimo de CI |
| Violação de CIDR explicitamente permitido | Negar + alertar | Restrição vinculante |
| Tentativa de publicar fora do escopo | Negar + auditar | Agrupar repetição |
| Token revogado/expirado em uso repetido | Negar + alertar | Pode ser pipeline desatualizado |
| Credencial de download tentando administrar | Negar + alertar | Violação objetiva |
| Pico de volume/egress | Alertar + limites | Baseline e quota por conta |
| JWT OIDC inválido ou publisher diferente | Negar + alertar | Não confundir tentativa sem token com identidade reconhecida |
| Troca de políticas, chaves ou ownership | Notificar | Evento administrativo sensível |

Baseline começa em modo de observação; mostrar quando não há dados suficientes. Mudanças de baseline precisam de aprovação ou histórico confiável, não aprendizagem automática irrestrita que normalize um ataque. IP de GitHub/cloud e User-Agent são sinais fracos; não provam repository ou workflow. Referência operacional: [R19].

### 11.3 Ações

- Observar; notificar; limitar; suspender publicação; suspender credencial; quarentenar uma publicação.
- Violações explícitas são bloqueadas imediatamente.
- Mudança geográfica isolada só alerta por padrão.
- Suspensão automática por risco elevado exige política configurada, simulação e exceções visíveis.
- Ação humana para reativação exige reautenticação e justificativa.
- Suspender identidade suspeita não apaga automaticamente suas publicações anteriores.

### 11.4 Email e entrega

- Destinatários: responsáveis da conta de serviço e equipe de segurança autorizada.
- Conteúdo: ID/nome da credencial, workspace, ação, horário, IP, região aproximada, motivo, medida aplicada e link autenticado.
- Não incluir bearer, reset token, chave privada ou conteúdo do pacote.
- Outbox transacional, jobs idempotentes, retry com backoff/jitter e dead-letter visível na UI.
- Cooldown, agrupamento e severidade evitam inundação; incidentes críticos não ficam escondidos em resumos diários.
- Entrega aceita pelo provider não significa leitura/chegada à caixa; registrar status correto.
- Alertas aparecem na UI mesmo quando o email falha; falha contínua de notificação é evento operacional.
- Webhooks futuros podem usar HMAC e retry, mas não são requisito da primeira instalação.

## 12. Segurança de supply chain

### 12.1 Controles obrigatórios

- Imutabilidade de identidade de versão, conteúdo e digest.
- Namespace reservado mesmo após exclusão; sem takeover automático.
- Credencial não pode criar pacotes arbitrários fora da allowlist ou mover referências protegidas.
- Limites de archive: bytes comprimidos/descomprimidos, número de entradas, profundidade e tempo.
- Rejeitar traversal, caminhos absolutos, entradas duplicadas, links perigosos e nomes conflitantes.
- Sanitizar README/changelog; conteúdo ativo de clientes fica em origem separada.
- Não seguir URLs de upload/download/attestation fornecidas pelo pacote sem validação; preferir envio de bytes.
- Configurações externas de admins exigem limites de egress/SSRF apropriados. Storage S3 privado legítimo é permitido explicitamente, não por bypass global.
- Separar upload, publicação aprovada e download disponível.
- Implementar proteção de alias/tag e propriedade do pacote.
- Mensagens e metadata de protocolo não revelam tokens nem rotas internas.

### 12.2 Assinaturas e proveniência

- Armazenar assinatura/attestation associada ao digest real recebido.
- Verificar identidade, cadeia de confiança e política de builder antes de aceitar como verificada.
- Campos declarados pelo próprio publicador, como commit SHA, não recebem selo de origem verificada sem evidência.
- Permitir política por repositório: opcional, alertar ou obrigatória.
- Default de novos repositórios: opcional. Distinguir sem evidência, evidência fornecida não verificada e evidência verificada sob política de confiança explícita. Não oferecer exigência obrigatória onde ainda não houver verificação funcional.
- Essa política trata evidências adicionais de supply chain; não desativa assinaturas nativas necessárias ao formato, como metadata Hex, nem validação obrigatória de integridade/digest.
- OIDC de CI autentica o publicador, mas sozinho não comprova artefato assinado nem proveniência verificada.
- Escolher ecossistema de verificação interoperável, como Sigstore/in-toto/SLSA, depois de spike e threat model.
- Suportar verificação offline com bundles quando apropriado; não tornar transparency log público um vazamento obrigatório de metadata privada.
- Proveniência comprova afirmações verificadas sobre origem; não garante ausência de vulnerabilidade.
- Consumidores também devem verificar quando seu cliente/ferramenta permite; um servidor comprometido não é neutralizado por metadata servida por ele mesmo.

Referência de modelo de ameaça: [R20]. O produto não deve anunciar nível SLSA sem avaliação dos requisitos aplicáveis ao processo de build da fonte.

### 12.3 Scanners — pós-v1

Integrações para vulnerabilidades, segredos e SBOM ficam fora da v1, com registro no roadmap. A v1 não afirma detectar malware, segredos ou vulnerabilidades. Um worker futuro separado e isolado inspeciona conteúdo sem executar scripts do pacote. Definir versão do scanner, timestamp da base, resultados, atualização offline, bypass autorizado com prazo e comportamento de falha.

Quando implementados, scanners obrigatórios para um repositório impedem publicação até resultado válido; resultados desconhecidos não viram aprovação. Na v1, a interface não oferece opção de exigir um scanner inexistente.

### 12.4 Cadeia de entrega do próprio registry

- CI do produto com permissões mínimas, dependências fixadas e actions de release fixadas por commit.
- Releases do binário e containers com checksums, assinaturas e SBOM.
- Testar upgrades e recuperação antes de promover release.
- Sem auto-update remoto silencioso ou execução de script externo pela UI.
- Canal documentado de reporte de vulnerabilidades e política de atualização.

## 13. Armazenamento, quotas e consistência

### 13.1 Drivers

Interface mínima: abrir, escrever staging, finalizar objeto, HEAD/verificar, ler range, listar para reconciliação, apagar autorizado e abortar multipart. Opções específicas de S3 permanecem específicas; não fingir que filesystem e object store têm o mesmo modelo.

- Local: diretório persistente, staging separado, escrita temporária + rename atômico no mesmo filesystem e política de durabilidade.
- S3: endpoint, region, bucket, prefix, path-style quando necessário, TLS, credenciais e testes de capacidades.
- Segredos armazenados criptografados com chave externa ao banco.
- Verificar digest próprio; ETag de multipart não é SHA-256 do conteúdo.
- Sem carregar pacote/imagem inteira em RAM.
- Pre-signed upload somente com commit que verifica tamanho/digest e limita destino; upload direto não publica automaticamente.
- Revogação de URL assinada depende de TTL/medidas no storage; mostrar essa janela na UI.

### 13.2 Quotas e contabilização

- Quota de workspace/repositório, upload individual e concorrência.
- Administrador pode limitar workspaces criados por usuário, membros/repositórios por workspace, armazenamento, upload individual e uploads simultâneos. Tetos da instalação prevalecem; limites de workspace podem ser menores ou receber exceção explicitamente autorizada.
- Reduzir limite abaixo do uso atual não apaga dados: bloquear apenas operações que ampliem o excesso, apresentando motivo e uso atual.
- Quota de armazenamento usa bytes lógicos: cada versão conta seu conteúdo completo, mesmo com blobs compartilhados. Mostrar bytes físicos reais separadamente, sem somar storage físico fictício por referência deduplicada.
- Publicações pendentes e exclusões recuperáveis continuam consumindo quota; backups têm contabilização própria, separada da quota de conteúdo do workspace.
- Reservar orçamento de upload; ajustar pelo tamanho real e liberar em abort/reject.
- Limites de downloads/tráfego ficam fora da v1. Métricas de consumo entram na v1; limites operacionais de segurança/requisições não equivalem a quota de tráfego.
- Billing não é implementado; métricas não precisam de precisão financeira.

### 13.3 Mudança de storage

Mudança de bucket/path não move objetos por mágica. Implementar job de cópia/verificação, leitura de ambas localizações durante transição, atualização de referências e remoção final só após validação. Se esse recurso ainda não estiver pronto, permitir apenas procedimento offline documentado e impedir alteração destrutiva pela UI.

## 14. SQLite, PostgreSQL e migrations

### 14.1 SQLite

- Arquivo em volume local persistente; WAL, foreign keys, busy timeout e configuração de durabilidade.
- Default conservador `synchronous=FULL`; tuning futuro é explícito e medido.
- Uma instância ativa; separar conexões/leitura e serializar escrita conforme driver escolhido.
- Transações curtas, checkpoint monitorado e queries indexadas.
- Não hospedar WAL em filesystem de rede nem compartilhar banco entre hosts. Referência: [R21].
- Testar backup online com driver real antes de escolher o driver definitivamente.
- Não considerar locks do banco uma substituição para invariantes transacionais de quota/versionamento.

### 14.2 PostgreSQL

- Mesmas regras de domínio, diferenças SQL encapsuladas em adapter.
- Pool configurável, TLS e usuário da aplicação com privilégios mínimos.
- Usuário de migration pode ser separado do runtime.
- CI com PostgreSQL para migrations e regras críticas desde a fundação.
- Suporte PostgreSQL não significa que múltiplas instâncias já são suportadas; leases, rate limit e caches compartilhados precisam de validação própria para isso.

### 14.3 Migrations e upgrades

- Arquivos versionados por dialeto com equivalência de schema e constraints.
- Checksum, lock de exclusão de migration e histórico de sucesso/falha.
- Instalação nova pode migrar durante bootstrap; upgrade de produção por comando explícito/controlado.
- Executável verifica intervalo de schema compatível e recusa iniciar se incompatível.
- Antes de migration destrutiva, exigir backup completo validado e espaço/tempo suficiente.
- Se backup obrigatório falha, upgrade falha de forma segura; não continuar automaticamente.
- Migration não transacional exige plano de retomada documentado.
- Não prometer rollback por migration down; preferir forward-fix ou restaurar backup compatível.
- Voltar binário é permitido somente dentro da compatibilidade declarada de schema.
- Backup pós-upgrade e validação com cliente real completam o procedimento.

### 14.4 Troca SQLite → PostgreSQL

Recurso separado, não confundir com migrations normais. Exportar dados em formato lógico versionado, entrar em manutenção de escrita, importar em banco vazio, preservar IDs/referências, validar contagens/digests e trocar configuração com backup preservado. Inicialmente pode ser CLI; não anunciar migração online entre bancos sem implementação e testes.

## 15. Backups online criptografados para S3

### 15.1 Garantias e limites

Backup deve recuperar a instalação sem depender do banco ou bucket original. Default: **backup completo**, incluindo banco, configuração recuperável, chaves internas necessárias e todos os artefatos referenciados, em destino S3 separado.

Não chamar de completo um backup que só guarda caminhos do bucket de produção. Uma modalidade futura baseada em snapshots/version IDs do storage precisa de classificação própria, retenção coordenada e aviso de dependências externas.

Online significa que leitura e operação continuam disponíveis. Pequenas barreiras de commit podem ser necessárias para coordenar metadados mutáveis e OCI; informar duração e medir impacto. Não prometer zero espera em toda publicação.

### 15.2 SQLite: snapshot antes do envio

A Online Backup API gera snapshot consistente em um banco destino e pode copiar incrementalmente enquanto a origem permanece em uso. Usar arquivo temporário protegido e limitado; depois comprimir quando útil, criptografar em streaming e enviar ao S3. Nunca copiar apenas o `.db` ativo ignorando WAL. Referência: [R22].

**Correção técnica da ideia preliminar:** não exigir que páginas do SQLite em alteração sejam transmitidas diretamente ao S3 sem snapshot estável. O envio é direto/automático ao destino remoto; não há exportação manual. A implementação inicial usa espaço temporário limitado para o snapshot do banco, não uma cópia local de todos os artefatos.

- Verificar espaço livre antes de começar, quotas do temporário e permissões 0600.
- Backup em passos pequenos com timeout, progresso e cancelamento.
- Reinícios por escrita concorrente tratados; se houver starvation, falhar com estado claro ou aplicar janela de coordenação configurada.
- Limpar temporários em falha/restart; não prometer secure erase em SSD.

### 15.3 PostgreSQL

Backup lógico consistente com `pg_dump`/`pg_restore`, binários compatíveis e warnings tratados. O adapter pode enviar a saída para criptografia/upload sem arquivo local completo do dump. Não colocar senha em argumentos de processo.

Referência: [R23]. Backup lógico da aplicação não fornece PITR nem backup de cluster/roles globais; para instalações maiores, documentar integração complementar de backup físico/WAL do operador.

### 15.4 Consistência entre banco e blobs

1. Criar job durável e adquirir proteção de GC/deletes físicos.
2. Capturar snapshot consistente do banco e inventário OCI coordenado.
3. Derivar conjunto de objetos referenciados pelo snapshot, não pelo banco vivo posterior.
4. Fixar essas referências com pins duráveis do job.
5. Liberar barreira curta de metadados; manter pins até finalizar/abortar.
6. Ler objetos imutáveis, validar digests, criptografar e copiar ao destino.
7. Persistir manifest e marcador de conclusão somente depois de todos os uploads.
8. Registrar recibo, resultado e elegibilidade para validação.

GC e backup usam locks/leases que sobrevivem a restart. Job expirado não libera referências sem reconciliação de seu estado. Lifecycle externo do bucket não pode apagar objetos protegidos: validar/documentar esse requisito.

Para OCI, exportar inventário consistente de manifests, tags, configurações e blobs alcançáveis. O gateway bloqueia operações mutáveis necessárias durante a captura e mantém GC do motor coordenado. A validação deve conseguir reconstruir o motor a partir do export; índices do dashboard sozinhos não são backup OCI.

### 15.5 Formato de backup

Prefixo remoto por installation ID e backup ID. Manifest lógico versionado contendo:

- engine/schema/app version e timestamps da captura/conclusão;
- snapshot do banco e inventário de objetos, digests e tamanhos;
- configuração exportada e catálogo de chaves internas;
- recipient/key IDs e identificação da política criptográfica;
- dependências externas que precisem ser reconfiguradas;
- número de arquivos, bytes, erros e status da validação posterior.

Banco, manifest sensível e objetos são criptografados. Metadados externos mínimos não revelam nomes privados. Manifest de conclusão autenticado impede que conjunto incompleto pareça utilizável. Integridade/autenticação de ciphertext não prova quem criou o backup: validar origem pelo destino autorizado/recibo e, quando necessário, assinatura separada com chave confiável.

### 15.6 Chaves e criptografia

- Preferir age com recipients explícitos, sem criptografia caseira. Referência: [R24].
- Chave pública de backup fica na instalação; chave privada de recuperação pode ficar fora dela.
- Exportar kit de recuperação no setup e testar sua utilização.
- Chave que decripta o backup não pode existir somente dentro dele.
- Secrets da aplicação e chaves de assinatura Hex/OCI necessários à restauração entram no backup protegidos; chave raiz externa da aplicação precisa de cópia envolvida recuperável ou provisão separada documentada.
- Rotação: novos backups usam novos recipients; antigos continuam recuperáveis até expirar.
- Não excluir chaves antigas ainda usadas por backups retidos.
- Automação da validação exige acesso protegido à chave de decriptação num verificador. Modo com chave offline só valida após fornecimento manual; não alegar validação automática sem essa capacidade.

### 15.7 Operação e defaults

Defaults configuráveis: backup completo diário; retenção de 7 diários, 4 semanais e 3 mensais; validação automática completa do mais recente ao menos semanal quando houver verificador, e validação antes de upgrade destrutivo. As regras selecionam backups por ID sem duplicar desnecessariamente.

- Informar custo estimado em bytes e dependência de tráfego, sem inventar preço do provider.
- Destino separado e credenciais restritas; configuração de write e prune pode usar credenciais diferentes.
- Multipart com retries/cancelamento; abortar partes órfãs e não concluir manifest em falha.
- Object Lock/versionamento quando disponíveis são proteção adicional, não dependência universal.
- Não rodar prune se não houver backup válido e recuperável mais recente conforme política.
- Notificar falha, atraso e ausência de restauração validada; job interrompido nunca vira sucesso.

### 15.8 Prontidão para produção

Instalação e testes são permitidos sem backup, com aviso persistente de recuperação não configurada/validada. Declarar a instalação pronta para produção exige destino, material de recuperação e primeira restauração validada. Falha posterior gera alerta crítico, mas não bloqueia automaticamente publicação/download. Upgrade destrutivo continua bloqueado sem backup completo validado conforme a política.

## 16. Restauração e comprovação de recuperação

### 16.1 Estados visíveis

`preparing → snapshotting → uploading → completed → validating → validated`.

Estados de falha/cancelamento com motivo e etapa. `completed` significa upload concluído; `validated` exige leitura do backup remoto e restauração real. Validação parcial é marcada como parcial.

### 16.2 Verificador isolado

Dois modos na v1:

- **Chave offline:** validação completa manual quando o operador fornecer a chave por canal seguro; não anunciar validação automática nesse modo.
- **Verificador externo:** validação automática agendada com chave protegida fora da instalação e acesso apenas ao destino de backup e ambiente isolado de restauração. Não guardar a chave privada de recuperação no próprio registry por padrão. Verificador funciona também em rede isolada com destinos internos autorizados.

Sem verificador configurado, a UI distingue backup enviado de restauração validada. A configuração, distribuição e autenticação do verificador têm contrato e testes próprios; acesso a chave não concede administração da produção.

- Baixar ciphertext do destino remoto, não reutilizar apenas o snapshot local.
- Decriptar com credencial de recuperação e verificar todos os arquivos/digests.
- Restaurar banco vazio e storage isolado, sem tocar produção.
- Executar integridade SQLite ou verificações equivalentes PostgreSQL, foreign keys, schema e referências.
- Validar disponibilidade e bytes de todos os objetos inventariados numa validação completa.
- Executar smoke tests de metadados/download de cada formato presente no backup.
- Verificar assinatura Hex, OCI manifests/layers e assets.
- Bloquear envio de emails, webhooks, cron de produção e acesso a destinos reais no ambiente de validação.
- Limitar recursos e limpar ambiente; registrar relatório, versão do verificador e duração.

Pode usar processo/container isolado. Docker não é requisito da instalação básica; validação SQLite/local pode rodar em subprocesso isolado, enquanto PostgreSQL/OCI requerem recursos explicitamente disponibilizados pelo operador.

### 16.3 Restaurar instalação nova

1. Iniciar em modo recovery sem cadastro público.
2. Fornecer destino, backup e material de chave por canal seguro.
3. Verificar origem/integridade e compatibilidade de versões antes de aplicar.
4. Restaurar banco e objetos em destinos vazios/staging.
5. Validar e testar protocolos.
6. Reconfigurar hostnames/callbacks externos necessários.
7. Revogar sessões humanas e credenciais curtas; por padrão suspender tokens persistentes até decisão do operador.
8. Manter account/service identities, mas renovar segredos potencialmente comprometidos.
9. Promover destinos e liberar serviço somente após validação.

Na recuperação, limpar leases antigos, invalidar sessões de upload temporárias e suprimir emails/webhooks pendentes do snapshot. Jobs agendados só são reativados após o operador confirmar destinos e políticas. Reconstruir projeções e inventários a partir dos dados restaurados antes de liberar escrita.

Backup anterior à revogação pode conter token antes válido: o modo recovery não deve reativá-lo silenciosamente. Não restaurar por cima do banco aberto. Restauração de produção existente exige manutenção e backup de segurança do estado atual.

### 16.4 Metas de recuperação

RPO inicial depende do backup diário: até 24 horas para dados posteriores ao último snapshot, se não houver mecanismo complementar. RTO é medido no hardware/volume reais, não prometido antecipadamente. A UI mostra último backup concluído, último restaurado, idade e tempo real de recuperação.

## 17. Exclusão, retenção, quarentena e GC

### 17.1 Política proposta

| Operação | Regra inicial |
| --- | --- |
| Sobrescrever versão | Sempre proibido |
| Repetir publicação idêntica | Idempotência apenas se digest e metadata protegida coincidem |
| Depreciar | Permitido a mantenedor; registrar motivo |
| Retirar da resolução | Conforme semântica suportada pelo cliente |
| Quarentenar | Bloquear distribuição pela instalação e referências públicas locais |
| Apagar versão | Marcar exclusão pendente, com recuperação padrão de 30 dias |
| Apagar definitivamente | Permissão específica, reautenticação e justificativa; respeitar pins |
| Apagar pacote inteiro | Mesmos controles, reserva de nome preservada |
| Alias de produção | Proteção configurável contra movimentação/exclusão |
| Retenção de bibliotecas | Preservar por padrão; sem expurgo por ausência de downloads |
| Upload incompleto | Expirar automaticamente; default de 24 horas |
| Artefato descartável | Política explícita por coleção/repositório |

Retirada da resolução não é garantia universal de comportamento idêntico em Pub, Cargo, npm, Go e Hex. Implementar o mecanismo próprio do formato e explicar seu efeito. Quarentena pode bloquear até downloads fixados em lockfile. Cópias em caches externos não podem ser recolhidas pelo registry.

### 17.2 Dependências e nomes

Mostrar referências conhecidas dentro da instalação, versões/digests e backups que mantêm o objeto. Não afirmar que grafo interno representa todos os consumidores externos. Mudança de ownership e transferência de pacote são ações sensíveis; namespace reservado só é liberado por procedimento explícito, nunca por GC.

### 17.3 Garbage collection

- Marcar objetos alcançáveis por versões, manifests, aliases, uploads ativos, backups e exclusões recuperáveis.
- Aplicar grace period; revalidar referências e leases imediatamente antes de apagar.
- Nenhum contador isolado de referências autoriza apagar: recomputação/reconciliação deve detectar divergência.
- GC do motor OCI coordenado; job separado não apaga layers em paralelo com backup ou push.
- Dry-run mostra bytes e alvos ao administrador autorizado.
- Exclusão idempotente, com estados intermediários e retry; storage apagado/banco falhou é reconciliado.
- Após prune de backup, liberar pins somente quando o backup remoto tiver sido removido corretamente.
- Políticas de produção e backup são separadas; apagar produção não apaga cópia de recuperação retida.

Em incidente, bloquear distribuição imediatamente sem exigir exclusão física. Remoção de um segredo presente num pacote envolve também cópias, backups e retenção configurada; não oferecer um botão que prometa recolher todas as cópias.

### 17.4 Exclusão de workspace e repositório

- Exclusão recuperável também para workspace/repositório, com default de 30 dias.
- Bloquear imediatamente acesso, publicação e emissão de novas credenciais; manter conteúdo contabilizado e protegido contra GC durante recuperação.
- Restauração exige proprietário autorizado, reautenticação e auditoria, por fluxo de gestão que não libere leitura do conteúdo excluído antes da restauração.
- Restaurar não reativa credenciais revogadas nem torna repositórios públicos automaticamente.
- Exclusão definitiva preserva reserva de slug/nome e respeita pins; backups seguem sua política própria, sem remoção automática fora dela.

## 18. Interface e experiência de uso

### 18.1 Áreas

| Área | Funcionalidades |
| --- | --- |
| Início | Workspaces acessíveis, atividade, consumo e avisos |
| Repositórios | Criar formato, visibilidade herdada, políticas, quotas e membros; prévia de conversões em lote |
| Pacote | README sanitizado, versões, dependências, arquivos e instalação |
| Versão | Digest, publicador, evidências, checks, retirada/quarentena e download |
| Configurar cliente | Snippets corretos para cada cliente, sem token incorporado |
| Contas de serviço | Escopos, credenciais, baseline, uso e rotação |
| Publishers OIDC | Identidades/claims permitidos e teste da política |
| Segurança | Incidentes, eventos, suspensão, explicação e investigação |
| Auditoria | Busca autorizada, filtros e exportação redigida |
| Administração | Saúde, banco, storage, jobs, notificações e configuração |
| Backups | Agendamento, recipients, destino, histórico e validação |
| Recuperação | Fluxo controlado de nova instalação e compatibilidade |
| Revisão | Fila pendente, checks, aprovar/rejeitar, motivos e liberação explícita em lote |
| Diretório e bloqueios | Saúde OIDC/SCIM, reconciliação, contas afetadas, prazo de falha e desbloqueio auditado |
| Consumo | Downloads/bytes, totais e maiores consumidores, com detalhamento autorizado |

### 18.2 Fluxos essenciais

**Primeiro pacote:** criar repositório → escolher formato → receber instruções → criar credencial restrita/publisher → publicar na fonte → verificar versão → instalar em projeto de teste.

**Token suspeito:** alerta → abrir incidente → visualizar sinais e contexto verificado → suspender/revogar → identificar publicações do período → quarentenar se necessário → emitir nova credencial restrita → encerrar com justificativa.

**Configuração externa:** preencher → testar sem ativar globalmente → apresentar resultado/limitações → confirmar → auditar. Segredos existentes são mascarados; alteração por substituição, não consulta do plaintext.

**Acessibilidade:** navegação por teclado, rótulos, foco, contraste e estados vazios/erro. Paginação por cursor onde necessário; filtros preservados na URL sem carregar segredos.

## 19. Configuração, segredos e comunicação

### 19.1 Bootstrap versus UI

Configuração operacional cotidiana pela UI: providers de login/CAPTCHA, regras de cadastro, mail, S3, backup, retenção, limites, papéis e políticas. Parâmetros necessários antes de abrir o banco continuam externos: data dir, engine/DSN, listen address, master key, bootstrap/recovery mode e trusted proxy inicial.

- Environment/file overrides têm prioridade explícita e aparecem como bloqueados na UI.
- Alteração de engine/DSN/storage envolve procedimento próprio, não simples salvar de formulário.
- Configuração persistida com versão; detectar alterações concorrentes.
- Configurar timezone por instalação para agendas; guardar timestamps UTC e exibir timezone.
- Eventos que mudam chaves/providers só entram em vigor após teste e validação do acesso administrativo.

### 19.2 Segredos

- Chave raiz por arquivo montado com permissões restritas ou mecanismo externo; não no banco junto do ciphertext.
- Criptografia autenticada de secrets com biblioteca/primitiva estabelecida, nonces seguros e contexto do registro.
- IDs de chave e rotação suportados; recriptografia de registros em job retomável.
- Respostas administrativas não retornam secret armazenado; só estado, identificador e opção substituir.
- Dump de suporte sempre redigido; panic/report não inclui variáveis de ambiente completas.
- Backup inclui material recuperável necessário conforme seção 15, sem circularidade da chave de decriptação.

### 19.3 Rede isolada e política de saída

- Operação em rede isolada é requisito da v1: instalação, atualização, publicação/consumo, administração, backup e recuperação sem downloads públicos obrigatórios.
- Núcleo funciona com contas locais/passkeys, filesystem ou S3 interno, SMTP interno quando configurado e backups em destino interno separado. IdP/SCIM externo à aplicação pode estar na mesma rede isolada.
- Saída de rede do servidor é negada por padrão. Administrador libera explicitamente destinos para S3, SMTP, IdPs, discovery/JWKS, CAPTCHA e atualizações de bases.
- Validar destino e limites de SSRF em redirects/resolução/conexões; acesso legítimo a storage S3/IdP privado exige autorização explícita, não bypass global. Workers/verificador obedecem ao escopo de rede de seu papel.
- Falhas de integrações opcionais não bloqueiam operações independentes; fluxos protegidos seguem sua política de falha. CAPTCHA público/social login indisponível em isolamento não impede métodos locais configurados.
- Bases GeoIP, listas de domínios e evidências/bundles de assinatura podem ser importados offline quando o recurso permitir, com versão, origem/integridade e data. Não anunciar funcionalidade offline sem caminho de atualização/verificação testado.
- Dependências públicas são responsabilidade dos clientes; registry não as consulta, resolve, baixa nem espelha. Testes de isolamento observam também tráfego inesperado.
- Releases e documentação incluem procedimento offline, ferramentas compatíveis necessárias e checksums/assinaturas verificáveis sem fetch obrigatório na inicialização. Pacotes de instalação não precisam incluir toolchains de clientes de todos os formatos.

### 19.4 Defaults consolidados da v1

Os valores abaixo foram aceitos como defaults configuráveis, não apenas sugestões. Alterações preservam as garantias de isolamento, recuperação e autorização descritas no plano.

| Política | Default |
| --- | --- |
| Cadastro | Fechado; criação de workspace configurada independentemente |
| Novo repositório | Privado; aprovação humana desativada; assinatura/proveniência opcional |
| MFA | Obrigatório para administradores da instalação e proprietários/administradores de workspace; pode ser exigido de todos |
| Sessão humana | 12 horas absolutas; 1 hora de inatividade |
| Token persistente | 30 dias; validade obrigatória por padrão e teto configurável |
| Credencial OIDC de CI | 5 minutos; teto ajustável inicialmente de 15 minutos |
| Link privado assinado | 5 minutos; teto inicial de 15 minutos controlado pela instalação, workspace só pode reduzir |
| Upload incompleto | Expiração em 24 horas |
| Exclusão recuperável | 30 dias para versões, repositórios e workspaces |
| Eventos detalhados de rede | Retenção de 30 dias |
| Auditoria administrativa | Retenção de 180 dias |
| Backup | Completo diário; 7 diários, 4 semanais e 3 mensais |
| Validação completa de backup | Semanal com verificador automático; também antes de upgrade destrutivo; modo com chave offline exige fornecimento manual |
| Sincronização corporativa saudável | Meta de até 1 minuto para entregar/aplicar mudanças, a comprovar nos testes |
| Bloqueio por sincronização | Após 1 hora de falha comprovada; prazo configurável |
| Saída de rede do servidor | Negada; destinos liberados explicitamente |

Valores concretos de quota de armazenamento, upload, concorrência e colaboração são configuração operacional; limites seguros de recursos e capacidade serão medidos nos benchmarks, não deduzidos apenas do hardware de referência.

### 19.5 Email

Interface de transporte desacoplada. SMTP é caminho genérico inicial; adapters HTTP de provedores podem ser adicionados sem alterar regras de domínio. Cada adapter precisa de teste de envio, timeout, idempotência quando suportada e status claro.

Eventos: convite, verificação/reset, vinculação de provider, emissão/rotação/revogação de credencial, mudança de permissão/visibilidade, incidentes e falhas de backup/validação.

Links usam a URL canônica e levam a telas autenticadas quando apropriado. Tokens de verificação/reset são de uso único, expirados rapidamente e armazenados por hash. Não enviar pacotes privados como anexo nem incluir secrets em emails de segurança.

## 20. Jobs, auditoria e observabilidade

### 20.1 Jobs

- Job persistente e outbox transacional evitam perda entre commit e notificação.
- Lease com expiração, heartbeat, retry exponencial limitado e jitter.
- Workers retomam jobs interrompidos; operações externas não são exatamente-once por promessa.
- Idempotência por evento/ação; limites de concorrência por tipo e storage.
- Dead-letter com motivo, próxima ação, retry manual e permissões.
- Jobs longos reportam progresso e permitem cancelamento seguro.
- Shutdown para aceitar novas requisições e drenar trabalho; multipart/backup retêm estado recuperável.

### 20.2 Pressão de recursos e operação compartilhada

- Downloads e operações interativas têm prioridade. Sob pressão de CPU/memória/I/O, reduzir concorrência de backup, GC e verificações, sem dispensar checks obrigatórios nem comprometer consistência.
- Falta de espaço seguro bloqueia novos uploads com erro claro; não apaga conteúdo existente para abrir espaço automaticamente.
- Jobs adiados aparecem com motivo, progresso e prazo; atraso acima da política gera alerta, especialmente backup/validação. Não deixar trabalho pesado adiado indefinidamente sem sinalização.
- Documentar comportamento, limites operacionais, diagnóstico e ações de recuperação nos runbooks, incluindo coexistência com outros serviços.

### 20.3 Auditoria

Append-only no fluxo normal, com retenção configurada. Registrar ator humano/serviço, autorização aplicada, recurso, resultado, IP confiável e request ID. Não registrar segredos.

Administrador do host/banco pode alterar dados: tabela append-only não é prova inviolável. Para requisitos mais fortes, exportar lotes assinados/checkpoints a destino separado protegido. Hash chain sem ancoragem externa não impede reescrita completa por operador privilegiado.

### 20.4 Saúde e métricas

- `/livez`: processo vivo; `/readyz`: condições mínimas de servir, sem expor detalhes sensíveis.
- Dependência opcional de email indisponível não impede downloads; storage necessário indisponível afeta readiness apropriada.
- Monitorar latência/erros por protocolo, uploads, bytes, filas, backup age, última validação, GC e quota.
- SQLite: tamanho de DB/WAL, busy/lock wait e duração de checkpoint; PostgreSQL: pool e queries lentas.
- Labels sem token, package path privado, email, IP ou cardinalidade ilimitada.
- Logs de download agregados onde possível; segurança preserva contexto mínimo para investigação.
- Retenção padrão: eventos detalhados de rede 30 dias, auditoria administrativa 180 dias, ajustáveis ao volume e necessidade.
- Não ligar analytics/telemetria para serviço externo por padrão.

### 20.5 Métricas de downloads e tráfego

- Na v1, medir quantidade de downloads e bytes transferidos por período, com totais e identificação dos maiores consumidores. Não implementar quota de downloads/tráfego.
- Administrador da instalação vê totais por workspace e instalação, sem nomes de pacotes privados nem identidade dos consumidores quando não tiver concessão explícita de acesso.
- Proprietário/administrador do workspace vê detalhamento autorizado por repositório/pacote/versão, usuário/conta de serviço quando identificado e país/ASN aproximados. Localização não é identidade; acesso público anônimo não é atribuído a usuário inventado.
- Dados detalhados ficam no domínio de métricas autorizado, não em labels Prometheus de alta cardinalidade ou que exponham nomes privados.
- Definir contrato de contagem para GET/HEAD/Range, retries, cache e download parcial nos testes; não confundir egress efetivo do registry com tamanho lógico do artefato.
- Para links S3/CDN diretos, emissão de link não prova download. Usar dados verificáveis do storage quando disponíveis; caso contrário marcar cobertura parcial e separar estimativa de bytes realmente observados. Não prometer total completo de tráfego externo invisível.

## 21. APIs e CLI

### 21.1 API administrativa

OpenAPI versionado, erros padronizados, request IDs e paginação. Operações longas retornam job ID. Idempotency-Key nas mutações de publicação/backup onde faça sentido. Controle otimista de concorrência em políticas/configuração.

Famílias: `/api/v1/workspaces`, `repositories`, `packages`, `versions`, `service-accounts`, `credentials`, `trusted-publishers`, `security/incidents`, `audit`, `admin/settings`, `admin/health`, `admin/backups` e `jobs`.

Estas são rotas propostas para gestão. Não alterar respostas dos protocolos nativos para caber no envelope JSON da API administrativa.

### 21.2 CLI proposta

```text
registry serve
registry migrate
registry doctor
registry backup create
registry backup validate
registry restore
registry recover-admin

registryctl configure <ecosystem>
registryctl publish go
registryctl publish hex
registryctl publish generic
registryctl publication status <id>
```

Nomes são especificação a implementar, não comandos já existentes. Segredos por prompt seguro, arquivo/secret store ou variável de ambiente apropriada; nunca por argumento obrigatório visível na lista de processos. `recover-admin` é local, exige posse de material autorizado, gera auditoria e não abre endpoint remoto de bypass.

## 22. Testes e validação

### 22.1 Matriz

| Dimensão | Cobertura |
| --- | --- |
| Banco | SQLite e PostgreSQL em regras de domínio/migrations |
| Storage | Filesystem e S3 via Floci em desenvolvimento/integração; garantias de backend real validadas separadamente |
| Clientes | Pub/Flutter, Go, Cargo, npm, Mix e Docker |
| Artefatos | Biblioteca simples, transitive private deps, archive inválido e pacote grande |
| Recuperação | Cada engine e storage usados pelo produto |
| Auth | Senha, TOTP, passkeys, códigos de recuperação, IdP OIDC de teste, Authentik/SCIM, OAuth adapters e CAPTCHA integração controlada |
| Revisão | Recebimento pendente, proibição de autoaprovação, mudança de política e liberação em lote |
| Offline | Instalação/upgrade/restore em rede isolada, saída negada e destinos internos explicitamente permitidos |
| Plataformas | Servidor Linux amd64/arm64; CLI Linux/Windows/macOS e instalação Compose/systemd |
| Concorrência | Publicação mesma versão, quota, revogação durante upload, GC e backup |

PRs executam suítes afetadas e base dos dois bancos; releases executam matriz de formatos/bancos/storages suportados. Suítes mais pesadas podem ser agendadas, mas nenhuma combinação anunciada fica sem cobertura de release.

### 22.2 Cenários obrigatórios de segurança

- Usuário/workspace A tenta listar/baixar/publicar em B por ID, path, search ou digest.
- Token de leitura tenta publicar, mover alias ou administrar.
- Token revogado durante upload/uso OCI não finaliza nova publicação.
- OAuth state/nonce/callback inválidos; tentativa de vincular conta com mesmo email.
- JWT OIDC com issuer/audience/assinatura/claims incorretos e replay da troca.
- Headers de proxy falsificados não mudam IP confiável.
- Mudança de país gera alerta, não bloqueio injustificado; CIDR explícito é bloqueado.
- Zip/tar traversal, decompression bomb, links, MIME ativo e XSS em README.
- URL privada não é servida por cache público/CDN compartilhada.
- Mudança privado/público segue confirmação e controles de cache.
- Artifact digest/attestation divergentes são rejeitados.
- Conta de serviço não amplia próprio escopo nem aceita publisher arbitrário.
- Cadastro aberto não libera criação de workspace nem acesso; email verificado não vincula conta automaticamente.
- Administrador não se autoeleva nem delega capacidade não autorizada; proprietário publica só com concessão explícita.
- Automação não cria pacote não reservado; rejeição pré-publicação libera versão sem perder histórico; versão publicada/excluída não pode mudar de bytes.
- Modos de visibilidade indisponíveis não alteram existentes; conversão em lote é explícita e reabilitar opção não republica conteúdo.
- SCIM remove apenas concessões do mapeamento afetado; desativação não é contornada por passkey/senha/outro provedor ou token pessoal.
- Falha comprovada de sincronização bloqueia após prazo; silêncio sem eventos não bloqueia; reconciliação não reativa sessões/contas revogadas; exceção temporária é auditada.
- Revogação/quarentena de download privado via link direto respeita a janela documentada; expiração não é garantia de interromper conexão aberta.

### 22.3 Cenários de falha e recuperação

- Processo morto entre upload e commit; retry depois de timeout pós-commit.
- S3 indisponível, upload truncado, erro multipart, checksum errado e falta de espaço temporário.
- Backup enquanto publica/exclui; GC concorrente; restart com lease de backup.
- Backup sem objeto ou ciphertext alterado nunca recebe status validado.
- Restauração em host novo sem bucket de produção e com kit externo.
- Backup anterior à revogação não reativa tokens silenciosamente.
- Migration falha, schema incompatível e tentativa de downgrade não autorizado.
- Verificador não envia email/webhook nem conecta ao bucket de produção para reparar dados faltantes.
- Motor OCI restaurado consegue pull de imagem multiplataforma com os mesmos digests.
- Restaurar workspace/repositório não reativa credenciais nem visibilidade pública; reserva de slug permanece após exclusão definitiva.
- Verificador externo não depende da produção, usa chave fora da instalação e funciona com S3 interno em rede isolada; modo offline manual não recebe status automático fictício.
- Falta de espaço bloqueia uploads sem apagar conteúdo; pressão de recursos adia jobs de forma visível e gera alerta por atraso.
- Falha IdP/SCIM não interrompe conteúdo público, conta local de emergência ou contas de serviço independentes.

### 22.4 Performance

Medir, não assumir capacidade pelo número de requests. Registrar CPU/RAM, tipo de disco, banco, tamanho dos objetos, concorrência e latências p50/p95/p99. Incluir downloads pequenos, imagens grandes, uploads concorrentes e backup ativo.

Critério estrutural: memória de upload/download limitada por buffers/concurrency, sem crescer proporcionalmente ao tamanho total do artefato. Definir orçamento concreto de latência e throughput após benchmark do hardware-alvo; resultados com memória/cache quente não substituem testes frios.

Referência de benchmark: Linux com orçamento de 4 vCPU/8 GiB de RAM, SSD local para SQLite, filesystem e S3 medidos separadamente. Não é requisito mínimo nem garantia de capacidade. Incluir perfis menores/maiores e coexistência com outros serviços.

Benchmarks podem rodar na máquina de desenvolvimento com recursos limitados e sem interromper trabalho existente. Inventário observado durante a revisão: Ryzen 9 7900, 12 núcleos/24 threads e aproximadamente 61 GiB de RAM total; uso/swap variam e devem ser recapturados a cada execução. Registrar carga concorrente, pressão de memória/swap, condições de disco e limites efetivos. Nenhum teste de carga ou capacidade foi executado durante a definição do plano.

## 23. Roteiro de implementação por entregas

Nenhuma fase está marcada como implementada. Entregar verticalmente, demonstrando publicação e consumo reais, e ampliar depois. Datas dependem de implementação e dos spikes; não estimar cronograma fictício.

As fases são entregas internas incrementais. A v1 completa exige os sete formatos e os requisitos consolidados, inclusive rede isolada, passkeys, revisão humana, verificador externo e sincronização contínua. Não anunciar entrega parcial como v1 completa nem adiar recurso acordado por conveniência técnica. Recursos pós-v1 e gaps têm registro explícito no roadmap.

### Fase 0 — spikes e contratos

- ADRs de banco/driver, backup, URLs, OCI e auth.
- Provar online backup SQLite com writes concorrentes e restauração.
- Provar snapshot PostgreSQL e envio criptografado.
- Spike OCI de autorização/revogação/backup/GC e Hex de consumo assinado.
- Fixtures por formato e threat model inicial.
- Contrato de OIDC/SCIM com Authentik: identidade estável, mudanças/reconciliação, saúde verificável, atraso e recuperação de falha.
- Compatibilidade dos clientes com publicação pendente de aprovação, incluindo limites do gateway OCI.
- Contratos de rede isolada, saída autorizada, passkeys/MFA, métricas de links diretos e verificador externo.

**Aceite:** relatório técnico com limitações, testes reproduzíveis e escolhas justificadas; nenhuma incompatibilidade encoberta.

### Fase 1 — fundação

- Projeto Go/SvelteKit, migrations SQLite/PostgreSQL, config, logs e CI.
- Bootstrap, usuários locais, sessões, workspace e autorização.
- Políticas independentes de cadastro/criação de workspace; propriedade, permissões aditivas e delegação sem autoelevação.
- Slugs imutáveis, limites de colaboração e visibilidade com três modos/restrição de opções independente de conversão.
- Jobs/outbox e primeiros eventos de auditoria.
- Health endpoints e instalação local em volume persistente.

**Aceite:** reiniciar sem perder dados, isolar dois workspaces e executar migrations nos dois engines.

### Fase 2 — conteúdo e artefatos genéricos

- Drivers filesystem/S3, staging, digest, quota, commit idempotente e reconciliação.
- Assets em origem separada, download e aliases protegidos.
- Catálogo básico e publicação CLI/API.
- Reserva prévia de pacote para automação, tokens pessoais, revisão humana e recibos distintos de publicação.
- Quota lógica, exclusão recuperável e métricas autorizadas de consumo; links privados assinados opcionais com janela explícita.

**Aceite:** upload privado e público, distribuição de bundle pronto, falhas recuperáveis e ausência de buffering integral.

### Fase 3 — backup e restore antes do uso real

- Snapshot dos dois engines, pins/GC, criptografia age e destino separado.
- Agendamento, retenção, kit de recuperação e verificador.
- Verificador externo automático e modo manual com chave offline, incluindo destinos internos em rede isolada.
- Aviso de recuperação pendente e critério de prontidão para produção sem bloqueio automático por falha posterior.
- Recovery mode e suspensão de credenciais restauradas.

**Aceite:** recuperar em instalação vazia usando apenas o backup remoto e o kit; corromper/remover um objeto deve reprovar validação.

### Fase 4 — Dart/Flutter

- Adapter Pub completo para comandos declarados.
- UI de configuração, tokens e fixtures de pacote transitivo.

**Aceite:** publicar e instalar biblioteca Dart e pacote Flutter privados com clientes reais.

### Fase 5 — Go

- Endpoints de proxy, API de publicação e CLI local.
- Validação de módulo/ZIP e configuração segura de cliente.

**Aceite:** publicação pela fonte, `go mod download`, major versions e testes de ausência de vazamento de namespace.

### Fase 6 — Rust

- Sparse index, API Cargo, credential providers e yank.

**Aceite:** `cargo publish` e `cargo build` com features/dependências privadas e isolamento.

### Fase 7 — identidades externas e proteção de acesso

- OIDC próprio, Google, Apple, GitHub, vinculação e MFA.
- TOTP, passkeys com verificação do usuário, códigos e reset de MFA auditado sem bypass por email.
- SCIM 2.0 contínuo com Authentik, saúde/reconciliação, prazo de bloqueio, área de bloqueios, recuperação e conta local de emergência.
- Senha opcional, convites/email, CAPTCHA providers e lista temporária.
- Testes antes de ativar e recuperação local auditada.

**Aceite:** configuração errada não elimina acesso local de emergência; fluxos externos/MFA verificados; desativação e grupos sincronizam sem novo login; falha comprovada bloqueia no prazo, reconciliação libera apenas contas elegíveis e nenhum método alternativo contorna o bloqueio.

### Fase 8 — trusted publishing e alertas

- OIDC de CI, tokens curtos, regras de rede, baseline e incidentes.
- Emails de segurança com retries, cooldown e gestão.
- GitHub Actions OIDC e Gitea Actions com token restrito, com documentação explícita do gap Gitea sem segredo persistente.

**Aceite:** publisher autorizado publica; outro repo/workflow falha; token suspeito gera incidente/email sem vazar segredo; violação de CIDR bloqueia.

### Fase 9 — npm e SvelteKit

- Packuments, tarballs, scopes, dist-tags e clientes.

**Aceite:** biblioteca/componentes internos consumidos por projeto SvelteKit usando registry privado.

### Fase 10 — Hex

- Tarballs, registry assinado, publicação explícita pela fonte e adapter de backup.

**Aceite:** Mix instala privado e valida integridade; restaurar preserva confiança e conteúdo. Publicação nativa só entra no suporte declarado se testada.

### Fase 11 — Docker/OCI

- Motor escolhido, token service, gateway, quotas, catálogo reconciliado, export/restore e GC integrado.

**Aceite:** push/pull/multiplataforma, revogação e isolamento; backup restaura motor sem depender do original.

### Fase 12 — políticas avançadas de supply chain

- Assinaturas/proveniência verificáveis, exigências por repository, evidências e proteção de releases.
- Default opcional, status de evidência honesto e exigência somente onde houver implementação interoperável; testar bundles offline quando suportados.
- Scanners de vulnerabilidades/segredos/SBOM são pós-v1 e não aparecem como exigência funcional na interface.

**Aceite:** artefato alterado ou origem não confiável é negado sob política obrigatória; OIDC não recebe selo indevido de assinatura/proveniência; nenhum scanner inexistente é anunciado como ativo.

### Fase 13 — operação e release instalável

- Admin completo, retenção/GC, quotas, export redigido de suporte e runbooks.
- Builds amd64/arm64, imagem container assinada e instalação systemd/Docker Compose.
- Upgrades/migrations, matriz de compatibilidade e restauração em ambiente limpo.
- Servidor Linux amd64/arm64, CLI também Windows/macOS; procedimentos de instalação/upgrade/restore offline.
- Runbooks de pressão de recursos, falha SCIM/bloqueio/desbloqueio, aprovação, mudança de visibilidade e cobertura de métricas diretas.
- Benchmarks com orçamento 4 vCPU/8 GiB, perfis menores/maiores e carga compartilhada; limitações e resultados publicados sem garantia fictícia.

**Aceite:** operador consegue instalar, configurar, publicar, investigar, atualizar e recuperar seguindo documentação.

### Marcos de utilização

| Marco | Condição |
| --- | --- |
| Protótipo interno | Fases 0–2; dados descartáveis |
| Uso pessoal com dados importantes | Fases 0–6 concluídas, backup validado e acesso restrito |
| Uso por equipe com autenticação externa | Fases 7–8 mais testes de autorização e operação |
| Suporte a cada formato adicional | Respectiva fase com matriz de cliente e recovery |
| V1 completa | Fases 0–13, sete formatos e todos os requisitos acordados comprovados; sem exclusão silenciosa de formato |
| Distribuição/instalação por terceiros | V1 comprovada e termos/licença definidos antes de distribuição; repositório atualmente privado |

Identidade/segurança pode ser antecipada conforme exposição da instalação. Não expor uma fase incompleta à internet para depois adicionar proteção.

## 24. Critérios de pronto para a primeira release completa

- [ ] SQLite padrão e PostgreSQL opcionais com paridade demonstrada.
- [ ] Filesystem/S3 testados, digests e quotas consistentes.
- [ ] Sete formatos do plano entregues: Pub, Go, Cargo, npm, Hex, OCI e genéricos; entrega parcial não é v1 completa.
- [ ] Publicação feita pela fonte, sem build de código de cliente no servidor.
- [ ] Controle de acesso em metadata, blobs, search e todos os endpoints.
- [ ] OIDC próprio, Google/Apple/GitHub, senha opcional, TOTP, passkeys e recuperação de MFA auditada.
- [ ] Authentik OIDC/SCIM testado: usuários/grupos sincronizados continuamente, estado de conta vinculante, saúde verificável, bloqueio após prazo e desbloqueio auditado sem bypass.
- [ ] Cadastro e criação de workspace independentes; email verificado para cadastro aberto local.
- [ ] Papéis fixos, permissões aditivas, publicação explícita, delegação separada e proteção do último proprietário.
- [ ] Três modos de visibilidade herdados do repositório, política da instalação e conversão de existentes como ação separada.
- [ ] CAPTCHA providers e domínio temporário configuráveis e testados.
- [ ] Contas de serviço, revogação, tokens curtos e publishers OIDC restritos.
- [ ] Tokens pessoais restritos, pacote reservado para automação, GitHub Actions OIDC e Gitea com token; gap sem segredo persistente documentado.
- [ ] Revisão humana sem autoaprovação, recebimento distinto de publicação, política vigente revalidada e liberação em lote explícita.
- [ ] Incidentes, emails de segurança, agrupamento/retries e contexto confiável.
- [ ] Imutabilidade, quarentena, exclusão recuperável, nomes reservados e GC coordenado.
- [ ] Slugs imutáveis; exclusão recuperável de versões/workspaces/repositórios sem reativação automática de credenciais/visibilidade.
- [ ] Backup remoto completo criptografado e restaurado num ambiente vazio.
- [ ] Chaves recuperáveis sem depender da instalação original.
- [ ] Chave offline com validação manual e verificador externo automático, sem chave privada no registry por padrão.
- [ ] Restore não reativa credenciais antigas por padrão.
- [ ] Migrations/upgrades testados e compatibilidade de schema declarada.
- [ ] Assets executáveis separados da administração; cache privado correto.
- [ ] Links privados assinados opcionais, TTL configurado e janela de revogação explicitada.
- [ ] Quota lógica, limites de colaboração/upload, métricas de downloads/tráfego e detalhamento sem exposição a administrador não autorizado.
- [ ] Pressão de recursos prioriza operações interativas, adia jobs com alerta e bloqueia uploads sem apagar dados.
- [ ] Instalação/upgrade/operação/restore em rede isolada, saída negada por padrão e destinos explicitamente autorizados.
- [ ] Linux amd64/arm64 e CLI Linux/Windows/macOS com matriz de clientes fixada e testada.
- [ ] Assinaturas/proveniência com status honesto e sem selo de garantia absoluta.
- [ ] Releases próprias assinadas, dependências fixadas e runbooks entregues.
- [ ] Roadmap registra todos os recursos/gaps adiados; scanners e demais itens pós-v1 não aparecem como suporte implementado.

## 25. ADRs e riscos que precisam de resolução técnica

| ADR/risco | Decisão a registrar | Como encerrar |
| --- | --- | --- |
| Driver SQLite | Modernc ou alternativa com backup comprovado | Spike online + recuperação |
| Motor OCI | Distribution/gateway ou alternativa | Isolamento, gate, GC e restore demonstrados |
| Hex publicação | API/CLI primeiro; nativo só com contrato completo | Cliente real e docs sem flags inventadas |
| Criptografia | age recipients + gestão de root secrets | Kit recupera instalação nova |
| Verificador automático | Externo automático + chave offline manual; mecanismo de autenticação/isolamento | Restauração do remoto sem acesso indevido |
| SCIM e saúde Authentik | Contrato de reconciliação/health verificável, identidade e revogação | Testes de mudança, atraso, canal interrompido e recuperação sem login |
| Aprovação nativa | Separar recebimento/revisão/publicação por protocolo | Cliente real, sem sucesso falso nem conteúdo pendente distribuído |
| Métricas diretas | Downloads/bytes observados em S3/CDN e cobertura parcial | Comparar tráfego observado com dados do storage, sem contar emissão como download |
| Rede isolada | Empacotamento, atualização offline e controle de saída | Instalação/upgrade/restore sem rede pública e com egress observado |
| Frontend | Static embed ou SSR justificado | Deep links, CSP e instalação testados |
| Proveniência | Biblioteca/ecossistema de verificação | Políticas de identidade e digest verificadas |
| PostgreSQL tools | Distribuir ou exigir ferramentas compatíveis | Doctor e imagem de release testados |
| Migração entre bancos | Export lógico controlado | Comparação de dados e rollback operacional |
| Email transport | SMTP e adapters adicionais | Entrega e falhas testadas |
| SaaS/gerenciado | Futuro após validação de uso | ADR de negócio, sem afetar bootstrap inicial |

Esses itens não são perguntas pendentes ao usuário para iniciar desenvolvimento. São tarefas técnicas delimitadas, com direção e critérios de aceite. Se um spike contrariar uma garantia, corrigir arquitetura antes de marcar o recurso como suportado.

Decisões de produto já fechadas não são substituídas pelos spikes: verificador externo e chave offline, frontend estático como direção, Authentik/SCIM contínuo, sete formatos, rede isolada e MFA com passkeys permanecem requisitos. O spike define o mecanismo e comprova limites; se inviabilizar um requisito, discutir mudança de escopo antes de anunciar a v1.

## 26. Orientações para iniciar pelo Codex

1. Ler este plano inteiro e criar `docs/adr` e checklist de implementação.
2. Começar pela fase 0 e comprovar backup/driver; não construir todas as telas antes do domínio.
3. Implementar fase 1 nos dois bancos, com autorização e migrations.
4. Entregar artefato genérico completo para validar storage/publicação/recovery.
5. Completar backup e restauração antes de colocar pacotes importantes na instalação.
6. Adicionar protocolos em fatias verticais, com cliente real e documentação do suporte.
7. Não criar placeholders de segurança que aparentam funcionar sem efeito.
8. Para cada entrega, registrar mudanças, testes, limitações e próxima etapa.
9. Manter README de instalação, desenvolvimento, testes, backup, recuperação e upgrade atualizados.
10. Não implementar SaaS/billing/proxy público sem nova decisão de escopo.
11. Manter `docs/roadmap.md` atualizado para todo recurso discutido e adiado, distinguindo gap conhecido, escopo pós-v1 e tarefa técnica ainda necessária à v1.

### Primeira sequência concreta de tarefas

- [ ] Criar projeto e contratos de configuração/DB/storage.
- [x] Spike SQLite online backup com escritas entre passos e recuperação age local; [evidência e limites](spikes/sqlite-backup.md). Roundtrip remoto é comprovado separadamente na tarefa seguinte; pins/GC e recuperação completa continuam pendentes.
- [x] Spike age em streaming → multipart S3/Floci → restore sem origem/snapshot, com digests/integridade e falhas; [evidência e limites](spikes/s3-backup.md). Atomicidade de conclusão concorrente, pins/GC e recuperação completa continuam pendentes.
- [x] Spike PostgreSQL snapshot exportado/dump age/restore sem origem, tools do mesmo major e falhas; [evidência e limites](spikes/postgres-backup.md). Distribuição de tools, matriz de versões e backup completo continuam pendentes.
- [x] Composição PostgreSQL age → objeto S3/Floci → banco vazio após excluir origem/ciphertext local, com falhas e digests; [evidência e limites](spikes/postgres-remote-backup.md). Fixture pequena com `PutObject` e spool ciphertext, não streaming direto pg_dump→multipart ou verificador externo completo.
- [ ] ADR do motor OCI e formato de export/backup.
- [x] Prova inicial Distribution 3.1.2/ORAS 1.3.4: push/pull de artefato, escopos e gate experimental de revogação por requisição; [evidência e limites](spikes/oci-auth.md). Não conclui ADR nem aceite OCI: quotas, gate de manifest/revisão, concorrência de commit, Docker/multiplataforma, export/restore e GC pendentes.
- [x] Export/restore de raiz OCI amd64/arm64 com seis blobs e digests preservados, seleção de plataformas e GC conservador em read-only; [evidência e limites](spikes/oci-recovery-gc.md). Inventário global/referrers, Docker real e coordenação online durável de publicação/backup/GC continuam pendentes; não conclui ADR/aceite OCI.
- [x] Prova de limites de revisão OCI/ORAS: negar manifest falha nativamente, mas blob pendente continua legível; gate experimental de alcance publicado mitiga GET/HEAD e exige permissão atual após aprovação. [Evidência](spikes/oci-review.md). Workflow real, autoaprovação/auditoria, projeção durável, matriz Docker/métodos e composição segura continuam obrigatórios.
- [x] Prova de mount OCI: motor liga blob pendente e o expõe no destino; gate experimental exige permissões nas duas pontas e fonte publicada, sem conceder distribuição pelo simples mount. [Evidência](spikes/oci-mount.md). Composição JWT/RBAC/revisão/alcance durável e revalidação durante commit continuam pendentes.
- [x] Caracterização determinística da janela de revogação durante commit remoto OCI: revalidação no gateway não impede commit após revogação ocorrida no upstream. [Evidência](spikes/oci-commit-revocation.md). Lacuna reproduzida, **não resolvida**; não conclui aceite de revogação/coordenação.
- [x] Prova SQLite de receipt/reconciliação e alcance OCI persistido: conteúdo remoto pendente oculto após reabertura, liberação com permissão atual e rollback de rotas/fase em falha SQL. [Evidência](spikes/oci-durable-release.md). Não resolve corrida remota, crash/multi-host, revisão/RBAC ou coordenação produtiva.
- [x] Prova de ordenação SQL entre conexões SQLite independentes: contenção real, visibilidade após commit, rollback e liberação/revogação concorrentes. [Evidência](spikes/oci-release-ordering.md). Não é prova de commit remoto, PostgreSQL ou coordenação multi-host.
- [x] Comparação PostgreSQL real: predicado de policy não ordena escritores distintos; lock da linha compartilhada serializa liberação/revogação e preserva rollback. [Evidência](spikes/postgres-release-ordering.md). Schema/recursos limitados; coordenador produtivo e commit remoto seguem pendentes.
- [ ] Spike Authentik OIDC/SCIM com saúde/reconciliação verificável, grupos, desativação, bloqueio e recuperação.
- [ ] Migrations de identidade/workspaces/roles nos dois engines.
- [ ] Bootstrap seguro e sessão local.
- [ ] Serviço de publicação genérica com constraints/idempotência/quotas.
- [ ] Drivers local/S3, reconciliação e download autorizado.
- [ ] Backup completo com manifest/pins/criptografia/S3.
- [ ] Verificador isolado que lê e restaura o backup remoto.
- [ ] Caminhos de verificação externa automática e manual com chave offline; contratos de saída de rede.

### Progresso comprovado — 04/10/2026

Primeira fatia executada: módulo Go e experimento isolado de backup SQLite pela API do driver modernc, criptografia age em streaming e restauração local com digests, integridade/foreign keys e escritas/leitura durante a cópia. Build sem CGO, formatação, vet, testes reais repetidos três vezes e race detector passaram. O spike não é o serviço de backup completo, não acessa S3 e não marca validação remota; nenhuma fase inteira nem suporte de protocolo é anunciado como concluído.

Essa entrega foi commitada em `23257e4` e enviada para `origin/main` antes de continuar a execução; o plano no ai-memory foi atualizado com o commit. Segunda fatia: cliente AWS SDK Go v2 e fixture MinIO real, upload multipart de ciphertext em streaming e restore pelo objeto remoto após remoção da origem/snapshot. Integridade, cancelamento/aborto, corrupção, limites e proteção contra sobrescrita passaram; verificação completa inclui integração real repetida três vezes e race detector. Continuação posterior a `23257e4`, ainda sem novo commit neste registro. Backup completo/pins/GC, PostgreSQL e demais contratos permanecem abertos.

Por decisão do usuário, MinIO foi substituído por Floci no desenvolvimento. Fixture atual: Floci 2.1.0 em Docker com digest fixado, limites de recursos, loopback e verificação SigV4 S3 explícita; nenhuma dependência MinIO no setup/testes atuais. Revalidado roundtrip, multipart/aborto, corrupção, autenticação e rejeição sequencial de sobrescrita. Probe concorrente reproduziu dois vencedores em uma corrida de `CompleteMultipartUpload` condicional: limitação do emulador, não garantia aprovada. Não mascarar com lock local nem considerar atomicidade concluída; validar storage real antes de produção. Esse gap permanece trabalho obrigatório da v1, não adiamento.

Terceira fatia: PostgreSQL 18.6 real em container sem rede/portas, com imagem fixada e tools do mesmo major. Snapshot read-only exportado preservou 128 linhas/geração 1 após outro cliente confirmar 129 linhas/geração 2; dump custom transmitido diretamente ao age e restaurado em banco vazio após exclusão da origem. Restore autentica todo archive e digest em staging privado limitado antes de executar `pg_restore --single-transaction --exit-on-error`. Casos de corrupção, rollback, limites, cancelamento em lock e versões divergentes exercitados. Sequences não são MVCC: próximo ID foi 130, incluindo avanço posterior ao snapshot; não prometer sequência congelada/sem gaps. Sem alegar upload PostgreSQL remoto, globals, upgrades ou backup completo. Detalhes no [spike 0.3](spikes/postgres-backup.md).

Quarta fatia: composição real do dump age PostgreSQL com upload S3/Floci e restore pelo objeto remoto, removendo banco original e ciphertext local antes do GET. Recuperados exatamente 128 registros/payloads e foreign key; falhas remotas rejeitadas sem criar tabelas no alvo. Transporte valida digest/limite ciphertext, restore valida age/digest plaintext antes da tool, sem plaintext staging remanescente. Usa ciphertext temporário e `PutObject` de fixture pequena; não declara streaming direto pg_dump→multipart, manifest autenticado, DR multi-host, verificador externo ou backup completo. Detalhes no [spike 0.4](spikes/postgres-remote-backup.md).

Quinta fatia: Distribution/ORAS reais por Unix socket privado, com emissor JWT/gateway experimentais apenas em teste. Push/pull de artefato e scopes/issuer/audience/expiry comprovados. Revogar emissão não invalidou JWT em cache no motor; gate de estado atual negou pull e finalização de upload iniciados antes da revogação, sem afetar leitor distinto. Bypass case-sensitive de `Bearer` reproduzido e corrigido. Não comprova mudança de permissão durante requisição upstream, quotas, revisão, Docker/multiplataforma, backup ou GC; ADR/aceite do motor permanecem abertos. Detalhes no [spike 0.5](spikes/oci-auth.md).

Sexta fatia: OCI layout de índice amd64/arm64 exportado com ORAS, todos os seis blobs alcançáveis verificados por digest/tamanho, backup age restaurado em motor vazio após remover storage e exports de origem. ORAS seleciona cada plataforma preservando seus três blobs. GC padrão real em servidor read-only negou upload com 405, removeu órfão (HEAD 200→404) e preservou índice/filhos/configs/layer sem restart posterior ao GC. Prova com gateway de storage pass-through separado da prova de auth; não inventário global, Docker runtime, pins/leases duráveis ou coordenação online SQL/OCI/GC. Detalhes no [spike 0.6](spikes/oci-recovery-gc.md).

Spikes 0.2–0.6 commitados em `a514b6d` e enviados para `origin/main` após verificação completa; plano no ai-memory atualizado depois do push. As notas anteriores sem novo commit são históricas. Continuação seguinte ainda não faz parte desse commit.

Sétima fatia: ORAS/Distribution reais sob gate experimental de manifest. Publicação sem aprovação falha nativamente e tag fica ausente, mas blob pendente pôde ser baixado por digest — gate só de manifest é insuficiente. Gate experimental por alcance publicado qualificado pelo repositório oculta GET/HEAD de pendentes, preserva conteúdo antigo e exige aprovação mais permissão atual para retry bem-sucedido. Não implementa fila/reviewer/autoaprovação/auditoria nem projeção durável ou atomicidade com o motor; composição completa continua pendente. Detalhes no [spike 0.7](spikes/oci-review.md).

Verificação completa da sétima fatia passou após falhas intermediárias documentadas: retry limitado/cleanup de container criado no bind RootlessKit compartilhado, com regressão determinística; conexão PostgreSQL terminada não reproduzida, causa ainda desconhecida, captura de logs/estado antes de cleanup adicionada. Não repetir operações SQL para mascarar estado de commit incerto. Continuação 0.7 permanece posterior ao commit `a514b6d`.

Sétima fatia e ajustes de fixtures commitados em `0b90614`, enviados para `origin/main` após nova verificação completa; ai-memory atualizado após push. Notas anteriores de continuação não commitada são históricas.

Oitava fatia: mount real Distribution comprovou que blob pendente pode ser ligado e baixado no destino (201/200), sem conhecer revisão. Digest ausente usa fallback 202, não mount/publicação. Gate experimental nega ausência de permissão em qualquer ponta, origem não autorizada/query ambígua e conteúdo pendente; permite mount publicado mas mantém GET/HEAD do destino ocultos sem publicação ali. Downloads da origem preservados; revogação atual nega novo mount. Flags/descritor sintéticos, não composição JWT/RBAC/durable reachability; ADR/aceite OCI permanecem abertos. Detalhes no [spike 0.8](spikes/oci-mount.md).

Oitava fatia commitada em `136d61c` e enviada para `origin/main` após nova verificação completa; plano ai-memory atualizado após push. Continuação seguinte não está nesse commit.

Nona fatia: corrida de revogação/commit remoto reproduzida com channels e motor real. Checagem inicial seguida de revogação reconhecida antes do envio ainda publicou; revalidar no dispatch nega revogação anterior, mas revogação após esse dispatch e antes do motor novamente publicou (201/manifest conferido). Testes 201 são caracterização de lacuna, não aceite. Nenhuma coordenação/lease local foi adotada como solução; contrato de ordenação, estado durável e reconciliação de commit incerto continuam necessários. Detalhes no [spike 0.9](spikes/oci-commit-revocation.md).

Nona fatia commitada em `68c341d` e enviada para `origin/main` após verificação completa; plano ai-memory atualizado após push. Continuação seguinte não está nesse commit.

Décima fatia (06/10/2026): SQLite real persiste tentativa/receipt e alcance qualificado por repositório, mantendo conteúdo remoto oculto após fechar/reabrir banco e gateway. Reconciliação compara digest esperado e verifica grafo real; liberação transacional exige permissão atual e faz rollback de fase/rotas quando falha a segunda inserção. Rejeitado não revive com permissão restaurada; banco indisponível nega sem bypass; ORAS consome seis blobs apenas após liberação. Inputs/layout/tabelas limitados à fixture, não workflow/RBAC de produção nem crash/multi-host. Corrida remota 0.9 continua não resolvida. Detalhes no [spike 0.10](spikes/oci-durable-release.md).

Décima fatia commitada em `1c9f042` e enviada para `origin/main`; plano ai-memory atualizado após push. Validação intermediária perdeu container PostgreSQL (exit255/OOMKilled=false), causa desconhecida; execução completa posterior passou sem retry SQL. Continuação seguinte não está nesse commit.

Fatia 0.11: duas conexões SQLite independentes exercitam ordens de commit de revogação/liberação, contenção SQLITE_BUSY, leitura WAL sem rotas não commitadas e rollback. Vinte corridas por execução admitem apenas resultados equivalentes à ordem serial commitada; nenhuma escrita em contenção é contada como revogação reconhecida. Prova SQL, não commit remoto OCI nem PostgreSQL/multi-host. Detalhes no [spike 0.11](spikes/oci-release-ordering.md).

Fatia 0.11 commitada em `c1916d7`, enviada para `origin/main` após nova verificação completa; ai-memory atualizado após push. Continuação seguinte não está nesse commit.

Fatia 0.12: PostgreSQL real read committed permitiu revogação commitada enquanto liberação condicional em outra linha ainda estava aberta, seguida de liberação obsoleta. `FOR UPDATE` em policy compartilhada ordenou os escritores, com espera real observada em pg_stat_activity, commit/rollback e tentativa posterior negada. Teste falhou sem lock. Não generalizar singleton de fixture para RBAC produtivo/ordem de locks nem afirmar solução da corrida remota OCI. Detalhes no [spike 0.12](spikes/postgres-release-ordering.md).

## 27. Referências técnicas

Fontes consultadas em 02/10/2026. Especificações fundamentam compatibilidade; requisitos de operação e defaults deste documento são decisões de projeto. Fixar versões e repetir os testes ao atualizar clientes/bibliotecas.

Referências adicionais de Gitea/Authentik/Keycloak consultadas durante a revisão de 03–04/10/2026. Confirmar capacidades na versão efetivamente fixada; suporte anunciado pelo IdP não comprova, sozinho, o contrato ponta a ponta do registry.

- **[R1]** Dart — custom repositories: https://dart.dev/tools/pub/custom-package-repositories
- **[R2]** Pub — Hosted Repository Specification: https://github.com/dart-lang/pub/blob/master/doc/repository-spec-v2.md
- **[R3]** Go — Modules Reference: https://go.dev/ref/mod
- **[R4]** Go — validação/produção de module ZIP: https://pkg.go.dev/golang.org/x/mod/zip
- **[R5]** Cargo — Registry Index: https://doc.rust-lang.org/cargo/reference/registry-index.html
- **[R6]** Cargo — Registry Web API: https://doc.rust-lang.org/cargo/reference/registry-web-api.html
- **[R7]** npm — scopes/registries: https://docs.npmjs.com/cli/v11/using-npm/scope/
- **[R8]** npm — `.npmrc` e escopo de credenciais: https://docs.npmjs.com/cli/v11/configuring-npm/npmrc/
- **[R9]** Hex — self-hosting: https://hex.pm/docs/self-hosting
- **[R10]** Hex — publicação nativa: https://hex.hexdocs.pm/Mix.Tasks.Hex.Publish.html
- **[R11]** OCI — Distribution Specification: https://github.com/opencontainers/distribution-spec/blob/main/spec.md
- **[R12]** CNCF Distribution — configuração: https://distribution.github.io/distribution/about/configuration/
- **[R13]** Scalar — geração/entrega de assets próprios: https://scalar.com/products/api-references/server-side-rendering
- **[R14]** OpenID Connect Core: https://openid.net/specs/openid-connect-core-1_0.html
- **[R15]** Turnstile — validação server-side: https://developers.cloudflare.com/turnstile/get-started/server-side-validation/
- **[R16]** hCaptcha — integração: https://docs.hcaptcha.com/
- **[R17]** reCAPTCHA — validação: https://developers.google.com/recaptcha/docs/verify
- **[R18]** GitHub Actions — referência OIDC: https://docs.github.com/en/actions/reference/security/oidc
- **[R19]** GitHub — rede dos runners: https://docs.github.com/en/actions/reference/runners/github-hosted-runners
- **[R20]** SLSA — ameaças e mitigação: https://slsa.dev/spec/v1.1/threats
- **[R21]** SQLite — WAL: https://www.sqlite.org/wal.html
- **[R22]** SQLite — Online Backup API: https://www.sqlite.org/backup.html
- **[R23]** PostgreSQL — `pg_dump`: https://www.postgresql.org/docs/current/app-pgdump.html
- **[R24]** age — biblioteca/formato: https://pkg.go.dev/filippo.io/age
- **[R25]** Gitea Actions — diferenças e permissões: https://docs.gitea.com/usage/actions/comparison/
- **[R26]** Authentik — SCIM provider de saída e reconciliação: https://docs.goauthentik.io/add-secure-apps/providers/scim
- **[R27]** Keycloak — API SCIM de realm em preview, distinta de provisionamento de saída: https://www.keycloak.org/2026/07/keycloak-2670-released

---

Este plano especifica o produto a desenvolver. Nenhum protocolo, teste ou garantia operacional aqui descrito deve ser apresentado como já implementado antes da evidência de aceite correspondente.
