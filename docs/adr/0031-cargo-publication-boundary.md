# ADR 0031 — Confirmação experimental de publicação Cargo

- **Status:** Em implementação isolada; sem adapter produtivo
- **Data:** 2026-11-08

## Contexto

O recibo Cargo verificado é imutável e permanece `uploaded`, enquanto decisões de revisão o referenciam. Uma versão publicada deve preservar esse histórico sem contabilizar duas vezes o mesmo archive na quota. O cliente nativo não deve receber sucesso enquanto revisão estiver pendente.

## Direção experimental

Usar uma ligação imutável, única por recibo e versão, gravada na mesma transação coordenada que cria o catálogo e a auditoria. Nessa transação, revalidar credencial, grant exato do publisher, revisão atual, identidade e quota. As consultas de quota contam versões e recibos ainda não vinculados; uma falha de qualquer etapa reverte catálogo e ligação. A alternativa de reescrever o estado `uploaded` exigiria reconstruir uma tabela com referências de revisão e enfraquecer sua imutabilidade.

A ligação não comprova integridade do objeto nem substitui backup. O recibo só é elegível se já tiver sido validado e verificado; restauração parcial continua recusando conteúdo Cargo. Retry deve conferir autorização atual e a correspondência exata, nunca reviver grants revogados. Este desenho permanece experimental até testes de concorrência, revogação, quota, auditoria, recovery, cliente real e gate integral; não habilita criação de repositórios nem serving.

## Evidência parcial

No worktree isolado, testes SQLite/PostgreSQL exercitam confirmação concorrente, retry idêntico, rejeição de outro conteúdo ou credencial, quota cruzada, revisão, revogação, yank e leitura de conteúdo publicado. SQLite também cobre rollback de auditoria e recusa de recovery parcial, sem alterar a origem. Um router opt-in com TLS foi exercitado com Cargo 1.99.0 real: publicação pendente retorna erro, aprovação permite retry, consumo funciona, yank preserva download para lockfile com `CARGO_HOME` novo e impede resolução nova, e unyank permite nova resolução. A fixture usa provider sintético que escolhe tokens separados conforme a operação; `cargo:token` com apenas o token de escrita falha na leitura inicial do índice, como esperado pela separação de privilégios. O provider sintético não é mecanismo operacional de custódia nem prova da matriz Windows/macOS. Rotas permanecem desabilitadas por padrão; faltam provider seguro, backup e restore completos, verificação integral integrada e demais aceites v1.

O inventário Cargo e seu conjunto assinado em domínio próprio foram exercitados com captura e restauração criptografadas. Um teste SQLite sintético preparou um catálogo com recibo publicado e restaurou seu objeto Cargo em diretório isolado; ausência do objeto ou divergência no inventário falhou mantendo `RECOVERY_INCOMPLETE`. Outro snapshot SQLite de fixture reuniu objetos genéricos, Go e Cargo, cujos conjuntos foram verificados e restaurados juntos. Essa evidência não cobre todas as combinações reais, configuração e chaves, outros formatos, retenção contra GC, anti-rollback, verificador externo ou promoção; não constitui backup integral.

## Índice por repositório

O validador de recibos pode receber uma origem HTTPS explícita e derivar o índice sparse a partir dos UUIDs canônicos de workspace e repositório. Isso evita tratar um único índice fixo como atual para todos os repositórios. O índice fixo preexistente continua disponível para fixtures; as duas opções são mutuamente exclusivas. Não há descoberta de rede nem confiança no cabeçalho da requisição para construir o índice.

As provas focadas passaram três vezes com race: o índice de outro repositório não é aceito como atual e os fluxos de recibo SQLite/PostgreSQL usam a origem explícita. Passaram build, formatação, lint, unitários, integrações com `-count=3` e integrações com `-race -count=1`, usando `-timeout=40m` por pacote. A habilitação opcional posterior está descrita abaixo; o provider seguro para leitura/escrita continua pendente.

## Composição experimental no servidor

`REGISTRY_EXPERIMENTAL_CARGO=true` habilita explicitamente o protocolo Cargo no `serve`, com filesystem local e staging privado em `cargo-staging`; o padrão é `false`, e valores diferentes de `true` ou `false` são recusados. O arquivo comprimido é limitado pelo menor entre `REGISTRY_MAX_UPLOAD_BYTES` e 500 MiB; a concorrência usa o menor entre `REGISTRY_MAX_CONCURRENT_UPLOADS` e 16. O limite descomprimido é 1 GiB, com até 10.000 arquivos e manifesto de 1 MiB. O `serve` não executa migrations.

Uma prova do processo `serve` passou três vezes com race, verificando rota ausente por padrão e recusa sem credencial quando habilitada. Passaram build, formatação, lint, unitários, integrações com `-count=3` e integrações com `-race -count=1`, usando `-timeout=40m` por pacote. Isso não prova publicação pelo processo real, provider operacional para tokens separados, recuperação integral ou cleanup após crash.

Uma prova adicional passou três vezes com race usando Cargo real através do `serve` e proxy TLS local: publicou dois crates, incluindo uma dependência privada no índice do próprio repositório, e compilou um consumidor com ambos no lockfile. A fixture preparou usuário, grants e tokens diretamente e usou provider sintético com tokens em ambiente isolado; não comprova custódia operacional, jornada administrativa, recovery integral ou suporte a outras plataformas. Passaram build, formatação, lint, unitários, integrações com `-count=3` e integrações com `-race -count=1`, usando `-timeout=40m` por pacote.
