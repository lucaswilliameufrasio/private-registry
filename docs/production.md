# Uso em produção

**Resumo: não use em produção ainda.** O Private Registry está em desenvolvimento, antes da 1.0. Não há versão publicada, o schema e a API mudam entre commits sem aviso, e nenhum canal de correções de segurança está garantido. Serve para avaliação e para um piloto com pacotes que você consegue reconstruir de outra fonte.

Esta página diz o que foi comprovado, o que não foi e o que fazer se você decidir rodar um piloto mesmo assim. O passo a passo de instalação está em [usable-delivery.md](usable-delivery.md).

## O que foi comprovado

Tudo abaixo foi verificado localmente: build, `go vet`, testes unitários e de integração repetidos três vezes e uma rodada com o race detector.

- **Clientes reais contra o `serve`:** `cargo`, `npm`, `dart pub`, `go` e ORAS publicando e baixando pacotes, com storage em disco e em S3 compatível (Floci).
- **Bancos:** SQLite e PostgreSQL reais, incluindo migrações, backups cifrados, verificação e restauração.
- **Autenticação:** senha, TOTP, passkeys (Chromium com autenticador virtual), sessões, CSRF, limites de tentativa, recuperação de conta e convites.
- **Interface web:** percorrida num Chromium real, do login com TOTP até o "esqueci minha senha" por e-mail (Mailpit).
- **arm64:** testes executados sob emulação QEMU.

## O que não foi comprovado

- **Serviços externos reais:**
  - Cloudflare R2, Backblaze B2 e AWS S3;
  - login real no Muira;
  - OIDC real do GitHub Actions;
  - envio real por Sabiá, Resend e MillionSend.

  Todos foram testados contra simuladores locais.
- **Docker e containerd** com OCI (só ORAS foi usado).
- **Outros navegadores e autenticadores:** Safari, Firefox e chaves físicas para passkeys.
- **Hardware arm64 real.** A replicação do SQLite não roda em arm64.
- **Mais de uma instância** com os mesmos dados não é suportado. A trava no diretório de dados só impede duas instâncias no mesmo host; com PostgreSQL compartilhado entre hosts, nada impede.
- **Desempenho:** não há benchmark nem teste de carga.
- **Segurança:** não houve auditoria externa nem teste de intrusão. O modelo de ameaças em [threat-model.md](threat-model.md) é um rascunho.

## O que falta para a 1.0

- **Formatos e identidade:** adapter Hex e SCIM contínuo.
- **Rede:** bloqueio de saída de rede para todo o processo. Hoje cada integração tem a sua lista de redes permitidas.
- **Versionamento:** versões publicadas, política de atualização e notas de mudança.
- **Validação:** testes contra os provedores reais listados acima e numa matriz de plataformas.

O acompanhamento está em [roadmap.md](roadmap.md).

## Se for rodar um piloto

1. **Isole a rede.** Prefira deixar o registry atrás de VPN ou de uma lista de IPs permitidos, não aberto para a internet.
2. **Proxy TLS.** Termine o TLS num proxy reverso e informe o IP dele em `REGISTRY_TRUSTED_PROXIES`. Use uma origem separada para downloads em `REGISTRY_ASSET_ORIGIN`.
3. **Chave mestra.** Guarde uma cópia offline do arquivo de `REGISTRY_MASTER_KEY_FILE`, separada dos backups. Sem ela, os segredos de TOTP e os e-mails na fila não podem ser abertos, e um backup restaurado não fica utilizável.
4. **Backups.**
   - Agende `registry backup` e, em outro host, `registry verify-backup`.
   - Faça uma restauração de teste num diretório vazio antes de confiar neles.
   - Guarde a identidade `age` fora do servidor.
5. **Atualizações.** As migrações só avançam e não têm volta. Antes de atualizar o binário:
   - faça e verifique um backup;
   - pare o `serve` e rode `registry migrate`;
   - suba de novo.

   Fixe o commit que está rodando.
6. **Monitoramento.**
   - `GET /livez` e `GET /readyz` para o processo.
   - Com sessão de administrador: `GET /api/v1/admin/replication` (campo `health`) e `GET /api/v1/admin/email` (`ok`, `failing` ou `stalled`).
7. **Fonte de verdade fora do registry.** Mantenha os pacotes reconstruíveis a partir do código e do CI. Uma perda do registry não pode ser a perda dos pacotes.
8. **Contas.** Mantenha pelo menos dois administradores com segundo fator e códigos de recuperação guardados. `registry recover-admin` existe para quando nenhum consegue entrar.

## Segurança

Para reportar uma vulnerabilidade, veja [SECURITY.md](../SECURITY.md). Não abra issue pública.
