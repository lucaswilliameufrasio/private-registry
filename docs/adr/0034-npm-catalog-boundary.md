# ADR 0034 — Catálogo npm experimental

- **Status:** Em implementação isolada; não exposto
- **Data:** 2026-11-08

## Contexto e decisão

O schema precisa reservar nomes e versões dentro do repositório npm sem permitir referências cruzadas entre workspaces ou outros formatos. O npm 11.19.0 observado envia a versão sem build metadata no envelope e recusa republicar a mesma versão normalizada no cenário testado. Como direção conservadora experimental, a identidade de versão remove apenas o sufixo `+build`, preservando prerelease; outras normalizações e toda a semântica npm continuam sem aceite. Nomes só serão aceitos pelo validador npm conservador já documentado.

Pacotes e versões são imutáveis, vinculados por chaves estrangeiras compostas ao repositório e workspace. A versão contém manifesto limitado, digest e tamanho de objeto, e integridade SHA-512; isso não autoriza leitura ou publicação, nem prova que o arquivo existe ou foi verificado. Dist-tags, credenciais, grants específicos, reservas, revisão e transações de publicação permanecem ausentes. O catálogo não deve ser exposto nem popular dados por fluxos normais nesta fatia.

Contabilidade de quota deve incluir versões do catálogo em todas as portas de entrada existentes; recovery parcial deve recusar qualquer catálogo npm com versões até que a restauração npm completa seja implementada. A schema v26 é forward-only. Esta fundação exige testes de isolamento, integridade, concorrência, quotas cruzadas, migração SQLite/PostgreSQL e gate integral; não é suporte npm nem aceite da v1.

## Evidência parcial

Testes focalizados repetidos três vezes com race em SQLite e PostgreSQL cobriram upgrade v25–v26, rollback com falha injetada, rejeição de checksum divergente, isolamento, imutabilidade e colisão concorrente de versões. As entradas genérica, Go e Cargo contabilizaram uma versão npm sintética na quota de workspace; os testes genérico e Go também verificaram o saldo exato. Recovery parcial SQLite recusou catálogo com versão npm e preservou a origem e o marcador incompleto. Ainda faltam gate integral integrado, catálogo e publicação operacionais, quota de novas reservas npm, recovery npm e todos os demais requisitos do formato.
