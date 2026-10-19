# Roadmap — recursos adiados e gaps conhecidos

**Atualizado:** 18/10/2026

**Estado:** fase 0 em andamento e fase 1 ainda aberta; Authentik OIDC/SCIM 0.18 caracterizado em fixture, health e full-sync reconciliation após 503 não aceitos. Existe esqueleto `registry serve`, migrations v1–v3, serviço interno de criação de workspace, CLI local one-shot de bootstrap do primeiro administrador e inicialização Linux da chave mestra; login/sessões/MFA, APIs e autorização de conteúdo ainda não existem. O envelope criptográfico não está integrado à persistência. Não há servidor/release utilizável nem suporte de protocolo anunciado.

Spike PostgreSQL lógico com tools do mesmo major também comprovado; [limites](spikes/postgres-backup.md). Distribuição de tools/aceitação das versões suportadas e backup completo continuam obrigatórios; PITR permanece adiamento separado, sem confundir os dois.

Composição PostgreSQL → age → S3/Floci → restore sem origem/ciphertext local comprovada no [spike 0.4](spikes/postgres-remote-backup.md). Usa objeto pequeno e spool ciphertext; streaming direto/multipart PostgreSQL, manifest completo e verificador externo permanecem não comprovados, sem adiamento silencioso.

OCI avançou com export/restore de índice amd64/arm64 e GC conservador read-only no [spike 0.6](spikes/oci-recovery-gc.md). Inventário global/referrers, Docker real, quotas/revisão/mount e coordenação durável online ainda são trabalho obrigatório, não features adiadas. Procedimento de manutenção da fixture não substitui pins/leases/barreira de produção.

Novo limite OCI obrigatório: gate apenas no manifest não oculta blob pendente por digest. [Spike 0.7](spikes/oci-review.md) comprova a falha e mitigação experimental por alcance publicado qualificado pelo repositório. Workflow, projeção durável/reconciliação e todos os métodos/aliases/mount continuam obrigatórios; nenhum requisito de revisão foi adiado por limitação do cliente.

[Spike 0.8](spikes/oci-mount.md): mount nativo também liga/expõe conteúdo pendente no destino. Gate experimental exige ambas as permissões e origem publicada; mount não concede alcance publicado no destino. Composição durável/autenticada nas duas pontas, quotas/revisão/GC e commit concorrente seguem obrigatórios, não adiados.

[Spike 0.9](spikes/oci-commit-revocation.md): revalidar no gateway antes de dispatch não impede commit após revogação reconhecida enquanto request está no upstream. Janela reproduzida determinísticamente, não resolvida. Contrato de ordenação/reconciliação e coordenação durável continuam obrigatórios para aceite OCI; não prometer garantia derivada de checagem isolada ou cancelamento de conexão.

[Spike 0.10](spikes/oci-durable-release.md): receipt/alcance em SQLite persistem separação entre conteúdo no motor e liberação no gateway; reabertura, reconciliação de digest/grafo, permissão atual e rollback de rotas/fase foram exercitados. Não resolve corrida 0.9 nem comprova crash, multi-host ou coordenador completo. Esses requisitos continuam obrigatórios, sem adoção definitiva do motor.

[Spike 0.11](spikes/oci-release-ordering.md) comprova ordenação/atomicidade SQL em conexões SQLite independentes, não a ordem do commit remoto. Contenção não equivale a revogação reconhecida. Coordenação produtiva, recovery/multi-host e PostgreSQL continuam obrigatórios.

[Spike 0.12](spikes/postgres-release-ordering.md) demonstra no PostgreSQL que ler policy no predicado de UPDATE não ordena seus escritores. Lock de linha compartilhada funcionou na fixture, mas modelagem/ordem de locks para todas as permissões, failure/recovery e commit remoto continuam trabalho obrigatório; não port automático de garantia SQLite.

[Spike 0.13](spikes/external-backup-verifier.md) prova restauração/validação SQLite em processo separado sem origem e sem identidade privada entregue ao produtor. Verificador externo operacional, remote GET, canal/manifest/relatório autenticados, kit e backup completo continuam obrigatórios; não adiados pela prova local.

[Spike0.14](spikes/signed-backup-receipt.md) autentica receipt de snapshot via Ed25519/contexto e chave confiada separadamente. Não manifest completo/trust store/rotação, relatório autenticado/freshness/anti-rollback; esses requisitos seguem obrigatórios.

[Spike 0.15](spikes/remote-signed-backup-verifier.md) amplia a prova para GET real via SDK S3/Floci do receipt e ciphertext em subprocesso separado. Isso não fecha verificador externo operacional, backup total, PostgreSQL/OCI, kit, jobs/leases/crash recovery, egress ou atomicidade de S3 real; requisitos continuam obrigatórios.

[Spike 0.16](spikes/postgres-remote-external-verifier.md) repete essa composição para um logical dump PostgreSQL 18 e pg_restore em database descartável. Não cobre roles/PITR/cluster, instalação, trust store operacional, isolação de produção, relatório autenticado, kit ou scheduler; os requisitos de backup/verificador completos continuam obrigatórios.

[Spike 0.17](spikes/hex-signed-registry.md) prova Mix 1.19.5/Hex 2.5.1 consumindo registry read-only assinado, autenticado e transitivo, e rejeitando payload de metadata adulterado. Não implementa API de publicação, servidor Hex, gestão/rotação de chave ou aceite Rebar3/docs; itens da fase Hex permanecem obrigatórios.

[Spike 0.18](spikes/authentik-oidc-scim.md) prova OIDC authorization-code + PKCE/JWKS, provisionamento Authentik 2026.8.3, remoção seletiva de membership e desativação em fixture. Sob HTTP 503, status ficou `info`, `last_successful_sync` permaneceu imóvel, uma task ficou `queued` e não houve log de erro/health. O comportamento após recuperação variou: algumas full syncs leram Users sem `PUT/PATCH` e deixaram drift; numa observação houve uma atualização e o drift foi corrigido, sem causalidade determinística demonstrada. O target SCIM permissivo reportou 4–6 cópias sintéticas excedentes de Groups; a unicidade real e a semântica de duplicatas permanecem sem prova. Health/freshness, reconciliação autoritativa, bloqueio após 1 hora e desbloqueio auditado continuam requisitos obrigatórios, sem adiamento.

[Spike 0.19](spikes/go-module-proxy.md) valida um cliente Go 1.27.1 Linux/amd64 real contra um proxy HTTP privado local, com major v2, dependências transitivas, path escaping e endpoints de leitura. Isso não implementa nem anuncia Go; publicação, validação, toolchain/OS matrix e demais controles da fase Go continuam obrigatórios.

[Spike 0.20](spikes/cargo-sparse-registry.md) valida Cargo 1.99.0 real em publicação via API, consumo de sparse registry autenticado, dependência transitiva/features e yank com preservação do lockfile existente. Não é adapter produtivo nem aceita Cargo; auth/RBAC/review, versão duplicada concorrente, validação robusta, restore, plataformas e credenciais de produção continuam obrigatórios.

[Spike 0.21](spikes/npm-registry.md) valida Node/npm reais em publicação scoped, `npm ci` com dependência privada transitiva, integridade e dist-tag. Não é server npm nem aceite do formato; ACL de publicação/dist-tag, concorrência, revisão, fixture adversarial, restore e matriz dos clientes seguem obrigatórios.

[Spike 0.22](spikes/pub-hosted-repository.md) caracteriza Dart Pub 3.13.5 publicando e consumindo pacotes sintéticos v2, incluindo transitiva e token inválido. Usa a exceção HTTP localhost e não demonstra TLS; Flutter CLI, Windows/macOS, autorização/RBAC, concorrência, aprovação e recuperação seguem obrigatórios. Não é adapter nem aceite de Pub.

Gap da execução (obrigatório antes de produção, não adiamento): Floci 2.1.0 admite corrida com dois vencedores em conclusão multipart `If-None-Match: *`. Desenvolvimento usa Floci por decisão do usuário; atomicidade precisa de aceitação separada contra backend S3 real. Ver [evidência](spikes/s3-backup.md).

O escopo obrigatório e os critérios da v1 estão em [development-plan.md](development-plan.md). Este roadmap registra explicitamente o que não entra na v1, por quê e o que permite retomar a discussão. Não estabelece datas, ordem de entrega nem autorização para implementar recursos futuros.

## 1. Adiamentos acordados na revisão

| Recurso ou gap | Na v1 | Motivo do adiamento | Condição de retomada |
| --- | --- | --- | --- |
| Limites de downloads e tráfego | Métricas de quantidade/bytes, totais e maiores consumidores com isolamento de acesso; sem quotas de tráfego | Entender consumo antes de impor limites que possam quebrar builds | Dados reais, contrato de contagem e políticas de bloqueio/exceção definidas |
| Papéis personalizados | Papéis fixos combináveis, concessões específicas e delegação explícita | Evitar mudanças amplas e pouco visíveis ao editar papel compartilhado | Necessidade real, prévia de impacto e testes de autorização/auditoria |
| Transferência entre workspaces | Troca de responsáveis só dentro do mesmo workspace | Muda fronteiras de acesso, URLs, quotas, credenciais e histórico | Fluxo explícito de origem/destino, validação de referências e recuperação |
| Gitea Actions sem segredo persistente | Publicação com token restrito de conta de serviço; exemplos e testes | Não pressupor emissão OIDC de job por compatibilidade com GitHub Actions | Capacidade comprovada na versão adotada e contrato de identidade/claims, escopo, validade e replay |
| Servidor em Windows/macOS | Servidor Linux amd64/arm64; CLI também Windows/macOS | Concentrar instalação, persistência, durabilidade e recuperação em plataformas comprovadas | Demanda e matriz própria de instalação, storage, backup, upgrade e restore |
| Scanners de vulnerabilidades | Sem scanner nem promessa de ausência de vulnerabilidades | Exige worker isolado, base mantida e política de falha | Scanner escolhido, atualização offline e testes de timeout, bypass e resultados desconhecidos |
| Scanners de segredos | Validação de arquivos/limites e aprovação; não detecção de segredos | Detecção requer ferramenta e processo de resposta próprios | Regras/resultados versionados, isolamento e tratamento de falsos positivos |
| Scanners/integrações de SBOM | Verificação de assinaturas/proveniência não equivale a scanner de SBOM | Escopo separado, sem opção de exigência fictícia | Formatos e ferramenta definidos, vínculo ao digest e processamento offline seguro |
| Outros IdPs com suporte oficial de sincronização | OIDC/SCIM interoperável, Authentik como referência testada | Cada integração tem comportamento próprio de entrega, saúde e reconciliação | Testes reais de provisionamento, desativação, grupos, falha e recuperação; Keycloak/Entra/Okta não recebem selo automático |
| Outros provedores de trusted publishing de CI | GitHub Actions OIDC; Gitea com token | Claims e capacidade de emissão precisam de validação por provedor | Issuer e identidade estável testados, incluindo forks/PRs, replay e falhas |

## 2. Evoluções e limitações já previstas no plano original

Estas possibilidades continuam fora do escopo ou condicionadas a evidência. Não são compromissos de entrega pós-v1.

| Possibilidade | Limite atual / motivo | Condição para reconsiderar |
| --- | --- | --- |
| SaaS, hospedagem gerenciada, billing e marketplace | Instalação self-hosted, uma instância ativa; sem cobrança de terceiros | Decisão de negócio, termos/licença e desenho de operação/isolamento |
| Cluster, active-active e múltiplas instâncias | Uma instância ativa mesmo com PostgreSQL; sem SQLite entre hosts | Necessidade comprovada e validação de coordenação, caches, rate limits, leases e recuperação |
| Proxy/cache/espelhamento público | Registry não busca dependências públicas; não vazar nomes privados | Nova decisão de escopo e threat model de namespaces/fallback |
| Build remoto, bundling/transformação e importação automática de Git | Fonte prepara bytes; registry não executa código de cliente | Nova decisão de escopo, isolamento e modelo de ameaça; não extensão implícita do servidor |
| CDN própria/edge | Origem própria, CDN externa opcional; métricas externas podem ter cobertura parcial | Necessidade de distribuição, operação e políticas de cache privado |
| Deduplicação entre workspaces | Inicialmente dentro do workspace | Análise de side channels, autorização, quotas e cross-mount |
| Cargo com índice Git | Sparse primeiro | Cliente/caso de uso que justifique custo adicional e testes próprios |
| npm: pnpm, Yarn, Bun, login interativo e audit público | npm obrigatório; outros comandos/clientes só anunciados quando testados; sem promessa de audit público | Matriz real e contrato funcional do recurso; não inferir suporte a partir de npm |
| Hex: publicação nativa, rebar3 e distribuição de docs | API/CLI recebe tarball preparado; Mix consome registry assinado | API/configuração e clientes reais comprovados; ausência fica declarada, sem flags inventadas |
| Go: pseudo-versions | Suporte depende de contrato explícito; não fabricar evidência VCS | Empacotamento/validação e clientes reais testados; definir origem e limites |
| Webhooks de notificação | UI/email com outbox e retry | Necessidade, HMAC, idempotência, política de egress e testes de entrega |
| Transportes HTTP de email | SMTP genérico inicial | Provedor escolhido, teste de envio/erro, timeout e idempotência |
| Backup dependente de snapshots/version IDs do storage | Backup completo independente do bucket de produção na v1 | Classificação própria, retenção coordenada e dependências externas explícitas |
| PITR/backup físico PostgreSQL | Backup lógico da aplicação não fornece PITR nem roles globais | Integração operacional do proprietário; não anunciar como cobertura do backup lógico |
| Migração online entre engines | Export/import controlado com manutenção, inicialmente CLI | Prova de consistência e retomada; não confundir com migrations de schema |
| Migração de storage pela UI sem cópia validada | Se job completo ainda não existir, só procedimento offline seguro | Cópia/verificação retomável, leitura de duas localizações e remoção final segura |
| Frontend SSR com Node separado | Direção: frontend estático embutido | Necessidade concreta, ADR e custo operacional justificado |
| Auditoria resistente a operador privilegiado | Append-only normal não é prova inviolável | Exportação assinada/checkpoints ancorados em destino separado protegido |

## 3. Restrições deliberadas, não promessas de evolução

- Visibilidade única por repositório; não há mistura de público/privado por pacote ou arquivo.
- Permissões aditivas; conteúdo mais restrito fica em outro repositório, sem regras de negação por pacote.
- Slugs de workspace/repositório imutáveis. Nome de exibição pode mudar; não há redirecionamento genérico de identidade de pacote.
- Sem execução de scripts/hooks de pacotes, microserviços/filas externas obrigatórios, Kubernetes obrigatório ou atualização remota silenciosa.
- Cópias baixadas/cacheadas externamente não podem ser recolhidas; assinatura/proveniência não garante ausência de malware/vulnerabilidades.

Revisitar essas restrições exige decisão explícita de produto e análise de impacto; não basta tratar como tarefa pendente.

## 4. Pendências que continuam obrigatórias à v1

Não confundir falta de implementação atual com adiamento de escopo:

- Sete formatos com publicação/consumo e recuperação comprovados; OCI e Hex continuam exigindo spikes.
- Passkeys, TOTP, códigos de recuperação e fluxos de MFA.
- Aprovação humana, reserva de identidade, revalidação de política e recibo de recebimento.
- Verificador externo automático e modo manual com chave offline.
- Rede isolada, atualização/importação offline onde aplicável e saída negada por padrão.
- Authentik OIDC/SCIM contínuo, meta de até 1 minuto em condições normais e bloqueio após 1 hora de falha comprovada, com configuração e recuperação visível.
- Métricas com autorização, quota lógica e comportamento sob pressão de recursos documentado.
- Testes Linux amd64/arm64, CLI Linux/Windows/macOS, matriz dos clientes e benchmarks com recursos limitados/carga compartilhada.

Os mecanismos e limitações precisam ser comprovados na fase 0 e nas respectivas entregas. Se um spike inviabilizar um requisito, discutir mudança de escopo antes de anunciar a v1, não movê-lo silenciosamente para este roadmap.

## 5. Distribuição e manutenção deste registro

Repositório permanece privado e sem licença definida. Definir termos/licença antes de distribuir para terceiros; não há decisão atual por código aberto ou licença comercial.

Para cada novo adiamento, registrar recurso, alternativa disponível, motivo, condição de retomada e limitação visível ao usuário. Ao implementar, atualizar o plano, documentação de suporte e testes antes de mudar o status; nunca apresentar este roadmap como lista de funcionalidades existentes.
