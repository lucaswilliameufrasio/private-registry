# ADR 0026 — Fundação experimental do catálogo Cargo

- **Status:** Em implementação; Cargo continua indisponível na API
- **Data:** 2026-11-07

## Contexto

O índice sparse Cargo precisa preservar identidade de pacote, versão e archive em um repositório autorizado. As regras de colisão e a ligação tenant/formato precisam sobreviver a concorrência, mas validar e gravar registros não constitui publicação segura.

## Decisão e limites

- A v19 introduz identidades de pacote e versão vinculadas por chaves estrangeiras ao workspace e a um repositório de formato `cargo`. O nome possui chave canônica por repositório; a versão possui chave que ignora SemVer build metadata. Os registros preservam digest e tamanho do archive e o índice projetado, com identidade e conteúdo imutáveis. O único campo mutável da versão nesta fundação é o estado de yank; qualquer operação futura deverá aplicar autorização e auditoria transacional.
- A chave de nome e a identidade de versão devem ser derivadas e validadas pelo servidor, nunca aceitas como verdade fornecida pelo cliente. As constraints de unicidade operam sobre as chaves recebidas: isoladamente, elas não comprovam que uma chave foi corretamente derivada nem que o índice/arquivo são válidos. A projeção servida terá de refletir o estado de yank atual sem alterar os metadados imutáveis.
- Nenhuma rota ou operação de produto cria ou serve esses registros nesta fatia. Continuam obrigatórios: credencial de publicação separada, autorização com grants atuais, reservas duráveis, quota, revisão humana, tratamento de concorrência e respostas perdidas, leitura e auditoria de yank, e recovery completo.
- Enquanto o inventário e restore Cargo não existirem, a preparação SQLite parcial de genéricos/Go rejeita snapshots com versões Cargo, preserva o marcador de incompleto e não promove o destino. Isso é bloqueio conservador, não backup ou restore Cargo.

## Evidência e trabalho restante

Testes sintéticos de SQLite e PostgreSQL exercitam chaves estrangeiras por tenant/formato, colisões, imutabilidade, yank e disputas concorrentes em que apenas uma identidade vence. Um teste de recovery parcial rejeita catálogo Cargo e verifica que a origem permanece inalterada. Os testes inserem dados diretamente no banco para exercitar constraints: não comprovam grants, API, quota, revisão, integridade física ou recovery Cargo. Esses controles precisam ser implementados e testados antes de habilitar o formato. Ver [ADR 0023](0023-cargo-protocol-boundary.md) e [ADR 0025](0025-repository-format-migration.md).
