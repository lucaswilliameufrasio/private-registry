# ADR 0010 — Chave mestra local e envelopes de segredos

- **Status:** Aceito; persistência TOTP integrada parcialmente; kit de recuperação e rotação continuam pendentes
- **Data:** 2026-10-18

## Contexto

Seeds TOTP e outros segredos persistentes não devem ser armazenados em claro no banco. A instalação precisa operar offline, e manter a chave no mesmo banco ou diretório de dados anularia a separação para snapshots e backups. A decisão foi usar um arquivo local privado, separado dos dados da instalação.

## Decisões

- `REGISTRY_MASTER_KEY_FILE` contém somente o caminho do arquivo. `registry init-master-key` gera a chave localmente, não recebe material secreto por argumento/ambiente, não imprime/loga os bytes, não exige banco/migrations e recusa sobrescrever qualquer arquivo existente.
- A chave é 32 bytes aleatórios de `crypto/rand`, em formato binário. O comando é suportado no servidor Linux; o arquivo deve ficar fora do `REGISTRY_DATA_DIR` e ser acessível somente ao usuário efetivo do processo.
- O diretório do arquivo e seus ancestrais devem pertencer ao usuário efetivo ou a root e não permitir escrita por grupo/outros, exceto diretório sticky protegido, como `/tmp`. O arquivo é criado como regular, com link único, pertencente ao usuário efetivo e modo `0600`; a leitura não segue symlink e rejeita arquivos compartilhados.
- Segredos são cifrados por XChaCha20-Poly1305 da dependência mantida `golang.org/x/crypto`. O envelope v1 é `versão (1 byte) || nonce (24 bytes) || ciphertext || tag`. Cada chamada exige um contexto não vazio como AAD; o chamador deve usar contexto estável, específico ao tipo e à identidade do registro.
- A chave mestra fica fora do banco, storage de conteúdo e backup dos dados. O operador é responsável por preservar uma cópia separada antes de qualquer uso produtivo. Não há fallback em claro.
- Secret manager/env com bytes da chave e KMS externo foram rejeitados como fonte padrão porque podem exigir serviços indisponíveis em instalações offline. Uma futura integração pode ser adicionada por decisão separada, sem alterar o envelope sem migração.

## Alternativas rejeitadas

- **Armazenar a chave no banco ou em `REGISTRY_DATA_DIR`:** um backup/snapshot levaria chave e ciphertext juntos; rejeitado.
- **Passar os bytes da chave por variável de ambiente ou argumento:** aumenta exposição em configuração, ambiente de processo, diagnóstico e automação; somente o caminho do arquivo é configurado.
- **Exigir KMS remoto:** inviabiliza a operação isolada e introduz dependência de rede na autenticação; não é o padrão offline.
- **Implementar criptografia própria ou formato sem versão:** aumenta risco de protocolo e impede evolução controlada; rejeitado.

## Consequências e limites

- Perder a chave torna irreversíveis os dados cifrados. Backup/restore da chave, recovery kit, rotação e migração entre chaves precisam de procedimentos próprios e ainda não existem.
- A migration v4 e `internal/mfa` persistem e recuperam o seed TOTP cifrado; isso é usado pelo fluxo interno de login/MFA, mas ainda não constitui autenticação exposta ou utilizável pelo produto. Rotas HTTP e operação de backup da chave continuam ausentes.
- Antes de persistir segredos, o servidor deverá falhar fechado se a chave estiver ausente, inválida ou inacessível. A política de startup e recuperação deve ser testada junto da persistência.
- A chave não cifra o banco inteiro nem substitui Argon2id para senhas. O administrador do host continua tecnicamente capaz de ler arquivo, memória e dados do processo.

## Referências

- [Plano — bootstrap, autenticação e MFA](../development-plan.md#8-autenticação-humana-e-cadastro)
- [ADR 0003 — backup e restore](0003-backup-and-restore-boundaries.md)
- [ADR 0009 — bootstrap local e credenciais](0009-local-bootstrap-and-credentials.md)
- [ADR 0011 — autenticação humana, MFA e sessões](0011-human-authentication-mfa-and-sessions.md)
- [Modelo de ameaças inicial](../threat-model.md)
