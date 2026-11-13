# ADR 0024 — Fronteira experimental do protocolo npm

- **Status:** Em implementação; sem adapter nem aceite da v1
- **Data:** 2026-11-07

## Contexto

O npm publica um documento JSON com identidade, metadados, dist-tags e um attachment codificado em base64. O registry precisa validar o conteúdo recebido antes de disponibilizá-lo, sem tratar o documento como autorização ou aceitar inconsistências entre o packument e o tarball.

## Decisão e limites

- Ler o documento sob limites explícitos, com deadline e staging exclusivo fornecido pelo chamador. Recusar JSON com chaves duplicadas, profundidade excessiva, UTF-8 inválido, surrogates isolados ou variantes de caixa ambíguas nos campos tipados. Decodificar um único attachment limitado e calcular sua integridade SHA-512. Em qualquer erro, o staging parcial pertence ao chamador e deve ser descartado.
- O nome aceito experimentalmente é um subconjunto ASCII minúsculo dos nomes npm para novos pacotes, com limite de 214 bytes e recusa conservadora de nomes reservados e caminhos inválidos. Isso não constitui validação completa de todos os clientes, reserva transacional nem autorização.
- A versão no envelope deve ser SemVer completo com três componentes numéricos dentro do limite inteiro seguro do cliente JavaScript. A validação é conservadora e não implementa reserva ou política completa de unicidade.
- Inspecionar gzip/tar sem extração, com limites de bytes comprimidos/descomprimidos, entradas e `package.json`. Recusar caminhos inseguros, colisões de caixa, links, duplicatas, gzip concatenado, bytes extras e checksum inválido. Validar nome e versão do `package.json` contra o envelope.
- Comparar conservadoramente os campos de identidade, dependências, exports/imports, browser, tipos, binários, engines, plataformas e scripts entre o envelope e o manifesto arquivado. Em `exports`, `imports` e `typesVersions`, comparar tokens JSON preservando a ordem das chaves e aceitando escapes equivalentes; outras representações equivalentes podem ser recusadas. Campos de infraestrutura adicionados pelo npm não são comparados. O npm 11.19.0 envia `1.0.0` no envelope quando o manifesto arquivado contém `1.0.0+build.1`; essa equivalência específica é aceita somente com SemVer válido. Outras normalizações equivalentes ainda podem ser recusadas; não há prova de semântica completa nem política de unicidade de versão.
- A validação conjunta relê o staging, verifica tamanho e integridade e compara os manifestos. O chamador deve manter os bytes imutáveis até o armazenamento e não confiar em `dist` fornecido pelo cliente como URL ou integridade de publicação. Nenhuma dessas primitivas concede acesso, reserva versão, aprova revisão, publica, autoriza dist-tags ou declara conteúdo seguro.

## Evidência e trabalho restante

Em uma execução adicional limitada a 15 segundos por alvo, os fuzzers do envelope, archive e comparação de manifesto concluíram sem falhas. Isso é apenas evidência adicional das primitivas, não demonstra segurança exaustiva ou suporte do adapter.

Testes sintéticos cobrem limites, duplicatas, integridade, arquivos hostis e divergência de metadados; fuzzing curto exercitou as fronteiras. O npm 11.19.0 real publicou e instalou pacotes scoped com dependência transitiva e `exports` condicional ordenado na fixture local, usando o envelope e a inspeção experimentais. Ele também recusou tarball adulterado por integridade e não reportou sucesso quando a fixture exigiu revisão. Ao tentar republicar uma versão que diferia apenas em build metadata, o cliente recusou a tentativa antes de enviar outro PUT; isso não comprova proteção de concorrência no servidor. Essa fixture não é adapter produtivo nem fila de revisão. Permanecem obrigatórios validação completa de nomes/versões e normalizações, autenticação de escrita separada, grants, quota, persistência, concorrência, revisão, dist-tags protegidas, recovery, política offline, cliente SvelteKit real e gate integral. Ver [spike npm](../spikes/npm-registry.md).
