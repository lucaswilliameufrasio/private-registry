# ADR 0042 — Catálogo Pub experimental

- **Status:** Experimental; Pub indisponível na API
- **Data:** 2026-11-08

## Limite

A migration v34 reserva identidades imutáveis de pacotes e versões Pub por repositório, armazenando manifesto, digest e tamanho. A identidade de versão remove build metadata; esta fatia não disponibiliza emissão de credenciais, upload, publicação, leitura ou rotas Pub. O schema, isoladamente, não comprova que um arquivo existe, foi inspecionado ou pode ser recuperado.

O consumo lógico de versões Pub participa da quota do workspace para reservas genéricas, Go, Cargo e npm. Enquanto o recovery Pub não estiver integrado, recoveries parciais recusam snapshots com versões Pub e preservam o marcador de recuperação incompleta.

## Evidência e pendências

O upgrade e rollback injetado da migration passaram três vezes com race em SQLite e PostgreSQL. Os testes de quota cruzada passaram três vezes com race em ambos os bancos. Testes de recovery SQLite recusaram versões Pub nos fluxos genérico, Go, Cargo e npm sem modificar a origem, também três vezes com race. O `make verify` integral desta fatia passou, incluindo integrações repetidas e race.

Recebimento de conteúdo validado, credenciais, reserva, revisão, publicação, serving, recovery completo, clientes Dart reais, autorização contínua e demais aceites da v1 permanecem obrigatórios. Esta decisão não os declara concluídos.
