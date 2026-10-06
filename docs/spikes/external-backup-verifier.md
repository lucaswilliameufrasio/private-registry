# Spike 0.13 — produtor e verificador SQLite em processos separados

**Data:** 06/10/2026

**Estado:** prova do mecanismo local independente da origem. Verificador externo operacional, manifest autenticado/kit de recovery e backup completo continuam pendentes.

## Reprodução

```sh
GOMAXPROCS=4 go test -tags=integration -count=3 -run '^TestExternal' -v ./internal/spikes/sqlitebackup
GOMAXPROCS=4 make verify
```

SQLite/age reais com dependências já fixadas; subprocessos do executável de teste, sem subprocesso mock ou fonte em memória. Sem alteração de Floci/S3, sem novo serviço de produção.

## Separação de entradas e dados

O processo pai da fixture gera a chave. O subprocesso **produtor recebe somente recipient público age**, paths próprios e limites internos: cria SQLite sintético com 128 entradas/262144 bytes de payload, usa Online Backup API real e age, emite receipt e remove banco original, WAL/SHM e snapshot plaintext antes de terminar.

Outro subprocesso recebe ciphertext e receipt, com **identidade privada por stdin**, não em argv/env/arquivo persistido. A chave não é enviada ao produtor. Ambiente restrito, GOMAXPROCS=2/GOMEMLIMIT=256MiB (não limite RSS rígido), contexto e WaitDelay; PIDs de produtor/verificador/pai distintos são verificados. Outputs não incluem chave ou dados do payload.

Produtor e verificador executam no mesmo host/usuário e usam o mesmo código/bibliotecas do projeto. Essa separação de inputs não é sandbox contra processo hostil com o mesmo usuário nem independência de implementação criptográfica. O pai é controlador do experimento, não o servidor registry.

## Validação antes do relatório de sucesso

Verificador impõe orçamento de ciphertext de 2 MiB para a fixture regular/imutável, confere SHA-256/size, autentica **todo** o age antes de abrir SQLite e confere digest plaintext. Em staging exclusivo 0700/arquivo restaurado 0600, abre SQLite read-only e verifica integrity, foreign keys, contagem e bytes de payload. Cleanup conclui antes do JSON de sucesso.

No sucesso: 128 linhas/262144 bytes, SHA-256 igual ao snapshot, nenhuma origem remanescente e nenhum plaintext no diretório de staging. O receipt é informação fornecida pelo controlador; **não** manifest versionado/autenticado da instalação. A resposta JSON não é relatório assinado nem canal autenticado de aceitação pelo registry.

## Negativas reais em outro processo

Sem relatório de sucesso para chave errada, corrupção, truncamento, plaintext/ciphertext digest divergente, arquivo ausente ou ciphertext acima do orçamento. Nos casos corrupção/truncamento, receipt ciphertext é recalculado para chegar à autenticação age, sem parar apenas no digest do transporte.

Dois archives age válidos/digests corretos contêm conteúdo não SQLite ou SQLite com foreign key inválida; o verificador os rejeita pela validação restaurada, não por envelope danificado. Ao final de sucesso/falhas normais, staging permanece vazio.

## Limites e contrato ainda obrigatório

- Fixture SQLite pequena/local; sem GET S3/Floci pelo verificador, PostgreSQL/OCI/CAS/config/credenciais ou inventário completo.
- Arquivos próprios e estáveis: não é parser geral robusto de entrada externa nem prova contra substituição concorrente/symlinks/TOCTOU de arquivos hostis. Sem descompressão de arquivo container.
- Sem SIGKILL/power-loss ou prova de limpeza após morte do processo; janitor/reserva de disco/quotas continuam necessários.
- Sem scheduler externo independente, identidade/token restrito, canal/relatório autenticado, retenção, alertas ou prova inicial de prontidão de produção.
- Chave efêmera no controlador/verificador; recovery kit offline, armazenamento persistente fora do registry, rotação e procedimento manual ainda necessários.
- Não executar código/pacotes restaurados; não colocar plaintext/chave no receipt, logs ou arquivo de entrada persistente.

Não declarar backup completo, verificador operacional obrigatório entregue, instalação offline ou isolamento de egress apenas porque o processo local conseguiu restaurar.

## Verificação

`GOPROXY=off GOSUMDB=off GOMAXPROCS=4 make verify` completo passou: build sem CGO, formatação, vet normal/integration, sintaxe Bash, testes sem cache, integrações reais três vezes e race detector. Tools/imagens/caches previamente preparados. Continuação0.13 posterior ao commit/push `82b4842`, ainda não commitada.
