# ADR 0042 — Catálogo Pub experimental

- **Status:** Experimental; Pub indisponível na API
- **Data:** 2026-11-08

## Limite

A migration v34 reserva identidades imutáveis de pacotes e versões Pub por repositório, armazenando manifesto, digest e tamanho. A identidade de versão remove build metadata; esta fatia não disponibiliza emissão de credenciais, upload, publicação, leitura ou rotas Pub. O schema, isoladamente, não comprova que um arquivo existe, foi inspecionado ou pode ser recuperado.

O consumo lógico de versões Pub participa da quota do workspace para reservas genéricas, Go, Cargo e npm. Enquanto o recovery Pub não estiver integrado, recoveries parciais recusam snapshots com versões Pub e preservam o marcador de recuperação incompleta.

## Evidência e pendências

O upgrade e rollback injetado da migration passaram três vezes com race em SQLite e PostgreSQL. Os testes de quota cruzada passaram três vezes com race em ambos os bancos. Testes de recovery SQLite recusaram versões Pub nos fluxos genérico, Go, Cargo e npm sem modificar a origem, também três vezes com race. O `make verify` integral desta fatia passou, incluindo integrações repetidas e race.

Recebimento de conteúdo validado, credenciais, reserva, revisão, publicação, serving, recovery completo, clientes Dart reais, autorização contínua e demais aceites da v1 permanecem obrigatórios. Esta decisão não os declara concluídos.

## Credencial de publicação experimental

A migration v35 e o serviço interno permitem emitir, listar e revogar uma credencial Pub limitada a um repositório e ao grant de publicação original. O token armazena apenas verificador, expira, exige conta e membership ativos e não revive quando o grant é revogado e concedido novamente. Quando um grant de leitura existe na emissão, sua identidade também fica vinculada para uso posterior; a credencial de publicação, por si só, não concede leitura. Não há rota de emissão, upload ou publicação habilitada nesta fatia; futuros endpoints devem exigir MFA recente e CSRF.

O upgrade e rollback injetado da v35, o ciclo de vida do token e as verificações de isolamento passaram três vezes com race em SQLite e PostgreSQL. O recovery SQLite isolado invalidou o token restaurado e preservou o original, também em três execuções com race. O `make verify` integral passou, incluindo integrações repetidas e race, após corrigir uma colisão de portas na fixture DNS. A invalidação de tokens não torna o recovery completo nem substitui a restauração de todos os formatos.

## Reservas experimentais

A migration v36 adiciona reservas limitadas por identidade Pub e credencial de publicação, com expiração lazy, cancelamento auditado e quota compartilhada com os formatos já implementados. Retentativa idêntica reconcilia a mesma reserva; metadados diferentes para a mesma identidade não são aceitos. A reserva não recebe nem verifica conteúdo, não cria publicação e não habilita rotas. A cópia de recovery isolado expira e invalida reservas ativas, sem alterar a origem.

Os testes focados de migration, quota, concorrência e recovery passaram três vezes com race em SQLite e PostgreSQL, incluindo a quota Pub → Go. O `make verify` integral passou após a inclusão dessa regressão. Upload, revisão, publicação, leitura e recovery completo continuam obrigatórios.

## Recebimento experimental

A v37 acrescenta inspeção limitada de arquivo e manifesto, staging privado, leitura de volta do objeto e recibo auditado após nova autorização. Um recibo não é publicação e não habilita rotas. Uploads interrompidos podem deixar uma reivindicação não verificada até expiração; recoveries parciais recusam recibos Pub verificados, preservando o marcador de recuperação incompleta.

As provas focadas do schema v37 passaram três vezes com race em SQLite e PostgreSQL, incluindo upgrade e rollback injetado com preservação das reservas, autorização antes da leitura, concorrência, quota em `uploading` e `uploaded`, auditoria e recovery parcial; Floci foi usado como fixture de armazenamento. O `make verify` integral passou no checkout conciliado, incluindo integrações repetidas e race. Floci não comprova atomicidade de S3 real.

## Revisão experimental

A v38 separa o grant de revisão dos grants de leitura e publicação, proíbe autoaprovação e associa decisões imutáveis ao grant de revisor, ao grant de publicador e à revisão da política. A alteração de política e a revogação do revisor invalidam aprovações anteriores; reconceder o grant não as reativa. A aprovação não publica conteúdo, e a v38 não depende da tabela de publicações v39.

As provas focadas de migration e revisão passaram três vezes com race em SQLite e PostgreSQL, com Floci para o arquivo de revisão. Elas cobrem leitura apenas após autorização, autoaprovação, alteração de política, revogação, reconcessão, rollback da decisão quando a auditoria falha e concorrência entre aprovação e rejeição. A rejeição final não foi revertida nem permitiu abertura do arquivo. No checkout conciliado passaram build, formatação, lint, unitários, `go test -p=1 -timeout=40m -tags=integration -count=3 ./...` e `go test -p=1 -race -timeout=40m -tags=integration -count=1 ./...`. O timeout maior foi necessário após falhas intermitentes no gate original; sua causa não foi comprovada. Ainda não há rotas Pub habilitadas no servidor.

## Publicação experimental

A v39 vincula um recibo verificado a uma versão imutável na mesma transação que a auditoria, revalidando token, grant e revisão atual. A ligação evita contar duas vezes recibo e versão na quota. Primitivas internas permitem ler metadata e arquivo publicado mediante grant vinculado à credencial, sem expor recibos pendentes. Esta fatia não inclui sessões nativas, rotas Pub ou recovery integral.

As provas focadas passaram três vezes com race no checkout conciliado em SQLite e PostgreSQL, usando também Floci: publicação de recibo rejeitado foi recusada, falha da auditoria reverteu o vínculo, publicações concorrentes retornaram a mesma versão e a quota não contou o recibo publicado duas vezes. A leitura recusou recibo pendente e credenciais ou escopo sem grant atual antes de acessar storage; reconcessão não reviveu tokens antigos. Passaram build, formatação, lint, unitários, `go test -p=1 -timeout=40m -tags=integration -count=3 ./...` e `go test -p=1 -race -timeout=40m -tags=integration -count=1 ./...`.

## Sessões nativas experimentais

A v40 prepara sessões de upload temporárias vinculadas ao token e repositório originais, com vínculo idempotente a uma reserva e revalidação na transação de publicação. Revisão pendente não equivale a publicação. O recovery isolado invalida sessões da cópia restaurada, sem mudar a origem. As migrations continuam explícitas via Goose; o servidor não executa migrations nem expõe essas sessões por padrão.

No worktree isolado, migrations SQLite/PostgreSQL e provas de sessão, revisão e publicação passaram três vezes com race; o recovery SQLite isolado também passou três vezes com race. No checkout conciliado passaram build, formatação, lint, unitários, `go test -p=1 -timeout=40m -tags=integration -count=3 ./...` e `go test -p=1 -race -timeout=40m -tags=integration -count=1 ./...`, usando cache Go dedicado após falhas anteriores de infraestrutura. Não há ainda prova de uma jornada nativa Pub ponta a ponta nesta fatia.

## Protocolo HTTP experimental

O handler pode receber explicitamente os serviços Pub e habilitar as rotas de leitura e escrita; essa opção ainda não é configurada pelo `serve`. A reserva e o vínculo à sessão nativa ocorrem na mesma transação. Uma publicação pendente de revisão não retorna sucesso de publicação nem fica disponível para download.

As provas focadas passaram três vezes com race em SQLite, PostgreSQL e Floci quando aplicável, incluindo conflito sem reserva órfã e teste com cliente Dart real em TLS local: publicação, consumo de dependências e recusa de publicação pendente de revisão. Passaram build, formatação, lint, unitários, `go test -p=1 -timeout=40m -tags=integration -count=3 ./...` e `go test -p=1 -race -timeout=40m -tags=integration -count=1 ./...`. Isso não comprova seleção no `serve`, recuperação integral ou operação produtiva.

O handler experimental também disponibiliza emissão, listagem e revogação de credenciais Pub, vinculadas ao repositório; emissão e revogação exigem MFA recente e CSRF. A prova HTTP passou três vezes com race, incluindo segredo ausente na listagem e recusa após revogação. Passaram build, formatação, lint, unitários, `go test -p=1 -timeout=40m -tags=integration -count=3 ./...` e `go test -p=1 -race -timeout=40m -tags=integration -count=1 ./...`, após falhas intermitentes de infraestrutura em execuções anteriores.

O handler experimental oferece gestão de política e revisores, listagem e inspeção de recibos e decisões de revisão. A prova HTTP passou três vezes com race: exige MFA e CSRF para mutações, permite que um revisor diferente do publicador aprove o recibo e só então permite sua publicação. Passaram build, formatação, lint, unitários, `go test -p=1 -timeout=40m -tags=integration -count=3 ./...` e `go test -p=1 -race -timeout=40m -tags=integration -count=1 ./...`. O `serve` ainda não habilita essas rotas.
