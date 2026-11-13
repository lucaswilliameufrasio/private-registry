# ADR 0025 — Evolução do formato imutável de repositório

- **Status:** Em implementação; Cargo ainda indisponível na API
- **Data:** 2026-11-07

## Contexto

A v17 registrou o formato imutável no próprio repositório e limitou o `CHECK` a `generic` e `go`. A migration aplicada e seu checksum não podem ser reescritos. Diversas tabelas dependem de chaves estrangeiras para a identidade e o formato do repositório. SQLite não suporta alterar esse `CHECK` diretamente; uma tentativa sintética de reconstrução com `defer_foreign_keys` e a proteção normal ativa falhou no commit mesmo após a tabela ser restaurada.

## Decisão

- A v18 amplia o schema para reconhecer `cargo`, sem disponibilizar o formato na API nem anunciar o adapter. A imutabilidade do formato e a validação de autorização permanecem obrigatórias. Formatos ainda não implementados seguem indisponíveis.
- PostgreSQL altera o `CHECK` em migration transacional. SQLite reconstrói a tabela, preserva todos os campos, índices e triggers, e verifica todas as chaves estrangeiras antes do commit. A migration falha fechada se não estiver na conexão com as configurações esperadas.
- O executor cria uma conexão SQLite dedicada, isolada do pool da aplicação, para a v18. Somente nela desativa temporariamente a validação imediata de chaves e ativa o comportamento legado de rename; o provedor Goose executa schema e registro de versão na mesma transação e a conexão é fechada ao término. A verificação de integridade dentro da transação força rollback se houver referências inválidas. O lock de migration continua obrigatório; não executar `migrate` com `serve` ou outros escritores ativos.
- A rotina de recovery só aceita o schema atual conhecido; atualizar sua fronteira para v18 não representa backup completo ou autorização para promover uma instalação restaurada.

## Evidência e limites

Testes sintéticos em SQLite exercitam schema v17 com grant e namespace Go existentes, migração pelo executor real, rollback por falha injetada, verificação de integridade, imutabilidade, recusa fora da conexão dedicada e pool normal com chaves ativas. Um subprocesso encerrado durante uma transação sintética de reconstrução também deixou o schema e as referências anteriores intactos; isso não cobre todas as interrupções do executor. Testes PostgreSQL exercitam upgrade de dados existentes. A aplicação ainda não possui persistência, credenciais, revisão ou endpoints Cargo. Arquivos danificados, writers não cooperativos, outras interrupções e diferentes versões de SQLite exigem verificação adicional; a migration não substitui backup e procedimento seguro de upgrade.
