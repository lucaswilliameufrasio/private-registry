# ADR 0023 — Fronteira experimental do protocolo Cargo

- **Status:** Em implementação; sem adapter nem aceite da v1
- **Data:** 2026-11-07

## Contexto

O registry recebe a publicação nativa do Cargo como metadata JSON e arquivo `.crate` em um framing binário. A identidade, o checksum e o índice sparse não devem ser inferidos de dados não verificados. A publicação exige grants específicos, reserva durável, quota, revisão, auditoria, proteção contra colisões e recuperação, ainda não conectados a este formato.

## Decisão e limites

- Ler os comprimentos little-endian e o conteúdo em streaming limitado, rejeitar truncamento e bytes adicionais e calcular SHA-256 sobre o `.crate`. A saída parcial pertence ao chamador e deve ser descartada em erro. O parser não autentica nem publica.
- Inspecionar gzip/tar sem extrair, com limites explícitos de tamanho comprimido/descomprimido, quantidade de entradas e manifesto. Rejeitar caminhos inseguros, duplicatas, links, conteúdo após o tar e membros gzip adicionais; verificar o checksum gzip. A validação estrutural não prova segurança ou autenticidade do código.
- Ler o `Cargo.toml` com parser TOML e comparar `package.name`/`package.version`, `links`, `rust-version`, features explícitas e identidades, origens, flags e requisitos textuais de dependências aos metadados da publicação. As origens são comparadas com os índices atual e padrão fornecidos independentemente pelo chamador, sem contato de rede. Somente a equivalência entre requisito default e caret inicial é normalizada; outras equivalências podem ser recusadas conservadoramente. Isso não autoriza destinos externos nem valida a semântica completa dos requisitos ou de `rust-version`.
- Rejeitar JSON ambíguo com chaves duplicadas, surrogates UTF-16 isolados e variantes de caixa dos campos tipados consumidos pelo decoder Go, e limitar profundidade antes de projetar metadados. Nomes de features continuam sensíveis a caixa. A projeção traduz alias da API de publicação para `name`/`package` no índice e inclui o digest calculado, sem criar índice persistente ou liberar conteúdo.
- A validação conjunta relê os bytes staged, confere tamanho e SHA-256 com o framing recebido e executa as verificações estruturais e de manifesto antes de produzir a projeção. O chamador deve manter o arquivo imutável até o armazenamento; o resultado não é autorização, reserva nem publicação.
- A identidade da versão segue SemVer completo e ignora build metadata para unicidade, mas a reserva transacional ainda não existe. O Cargo 1.99.0 usa posições de bytes no índice; nomes que cortariam um caractere UTF-8 nessas posições são recusados. `café_fixture` foi empacotado localmente, mas o cliente entrou em pânico ao calcular seu caminho sparse antes de realizar requisição; isso caracteriza apenas esse nome e toolchain. Nomes Unicode minúsculos com limites seguros são aceitos experimentalmente; mudanças de caixa não ASCII continuam recusadas até haver prova de equivalência.
- Não expor endpoints Cargo enquanto token de publicação, grants, quota, indexação, revisão humana, recuperação e demais invariantes não forem integrados. A API nativa não deve responder sucesso de publicação para um recibo ainda pendente de revisão.

## Evidência e trabalho restante

Testes sintéticos cobrem framing, limites, arquivos hostis, TOML e JSON ambíguos, aliases, paths e SemVer; fuzzing curto exercitou os limites dos parsers. O cliente Cargo 1.99.0 real publica e resolve dependência privada com alias e features `dep:` e `?/`, além de consumir um nome Unicode com fronteiras seguras, na fixture local. Após yank, um lockfile existente continua funcional mesmo em `CARGO_HOME` novo, enquanto resolução nova recusa a versão yankada. O cliente também rejeita um crate adulterado por checksum e não reporta sucesso quando a fixture exige revisão. Isso não é adapter produtivo nem implementação da fila de revisão. Faltam validação integral de metadados e dependências, Unicode e colisões, persistência, exclusão/yank, autenticação específica de escrita, concorrência, recuperação, matriz de clientes/plataformas, egress e gate integral. Fontes: [Cargo Web API](https://doc.rust-lang.org/cargo/reference/registry-web-api.html), [Cargo index](https://doc.rust-lang.org/cargo/reference/registry-index.html) e [spike local](../spikes/cargo-sparse-registry.md).
