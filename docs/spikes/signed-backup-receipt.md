# Spike 0.14 — autenticação de receipt do snapshot

**Data:** 06/10/2026

**Estado:** assinatura/validação de receipt de snapshot em processos separados. Não é manifest completo da instalação nem verificador operacional completo.

## Reprodução

```sh
GOMAXPROCS=4 go test -count=1 ./internal/spikes/backupreceipt
GOMAXPROCS=4 go test -tags=integration -count=3 -run '^TestExternalVerifierAuthenticates' -v ./internal/spikes/sqlitebackup
GOMAXPROCS=4 make verify
```

Complementa a [prova externa local](external-backup-verifier.md). Sem novos serviços/dependências; usa Ed25519 da biblioteca padrão Go e age/SQLite reais. Floci permanece S3 de desenvolvimento, sem participação nesta fatia local.

## Receipt assinado e confiança

O produtor recebe **chave privada de assinatura Ed25519**, diferente da identidade privada X25519 de recuperação. Continua recebendo apenas recipient público age para criptografar; a chave age privada só chega ao verificador via stdin.

Receipt experimental inclui versão, instalação, identificador do backup, SHA-256 plaintext/ciphertext e tamanho ciphertext. Assinatura cobre bytes exatos de JSON do perfil, com domínio `private-registry/phase0/sqlite-receipt/v1` separado por NUL. Não usa criptografia/signature caseira.

Envelope contém somente payload e assinatura: **não** escolhe sua chave de confiança. Verificador recebe chave pública fixada e contexto esperado por canal separado do envelope — neste teste, pelo controlador. Não confiar em chave fornecida pelo próprio receipt, nem tratar sua validade como prova de que o conteúdo é benigno.

Limites do perfil: payload até 4 KiB, IDs ASCII restritos até 128 bytes, digests SHA-256 lowercase, versão única e ciphertext até 2 MiB. Depois de verificar assinatura, valida schema e representação exata; campos desconhecidos/duplicados, trailing data, representação ambígua, versão não suportada e valores inválidos são negados mesmo se assinados por chave confiada. É perfil de fixture, não formato de interoperabilidade final.

## Evidências

- Produtor real assina receipt depois de snapshot age e cleanup da origem; verificador em outro processo valida assinatura/contexto **antes** de aceitar digests ou abrir o archive.
- Caminho válido restaura/verifica 128 linhas, com staging removido e PIDs distintos.
- Envelope adulterado, assinatura ausente, chave não confiada, outra instalação e outro backup são negados, usando archive/key válidos para que bypass de autenticação fosse detectável.
- Unit tests rejeitam assinatura em domínio errado, keys/tamanhos inválidos e payloads conhecidos/assinados com schema inválido, duplicatas ou trailing data.
- Teste de chave não confiada falhou ao desativar verificação Ed25519; verificação restaurada antes do gate completo.

O cenário sem assinatura do spike 0.13 permanece separado como caracterização histórica/local, **não fallback** do modo `verifier_signed`. O modo assinado não aceita receipt unsigned.

## Limites obrigatórios

- Snapshot SQLite único e pequeno; não inventário de SQL/OCI/CAS/config/credenciais nem manifest/kit de instalação.
- Chaves/contexto provisionados pelo controlador da fixture, não trust store/rotação/revogação/chaves offline implementados no produto.
- Contexto vincula instalação e backup esperados, mas **não** impede replay dentro do mesmo identificador, não prova freshness/último backup, retenção ou anti-rollback. Essas políticas ainda exigem estado confiável e contrato explícito.
- Relatório de verificação continua JSON sem assinatura/canal de autenticação; assinatura do receipt não autentica o resultado do verificador.
- Não remote GET, scheduler externo, crash cleanup, isolamento de processo contra mesmo usuário ou independência de implementação. Caminhos/ciphertext são próprios e estáveis da fixture, não entrada arbitrária hostil.
- Chave de assinatura comprometida pode assinar receipts novos; criptografia age protege destinatário mas não substitui política de confiança/manifests completo.

Não concluir verificador operacional v1, backup completo ou ADR/formato definitivo a partir deste experimento.

## Verificação

`GOPROXY=off GOSUMDB=off GOMAXPROCS=4 make verify` completo passou: build semCGO, formatação, vet normal/integration, sintaxe Bash, testes semcache, integrações reais três vezes e race detector. Tools/imagens/caches preparados não são prova de instalação offline/egress. Continuação0.14 posterior ao commit/push `7996243`, ainda não commitada.

O [spike 0.15](remote-signed-backup-verifier.md) posteriormente compõe receipt/objeto armazenados no Floci com GET e validação em outro subprocesso. Isso não altera os limites deste spike nem faz o receipt de snapshot virar manifest completo.
