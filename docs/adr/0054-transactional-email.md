# ADR 0054 — E-mail transacional

- **Status:** Implementado; envio real pelos provedores pendente de validação
- **Data:** 2026-11-12

## Contexto

Convites e links de recuperação eram entregues à mão pelo administrador, e ninguém recebia aviso de mudanças na própria conta. O proprietário pediu envio por Sabiá, MillionSend e Resend em produção e Mailpit em desenvolvimento.

## Decisão

- **Provedores:** `REGISTRY_EMAIL_PROVIDER` escolhe um, e o envio fica desligado sem ele:
  - `sabia`: `POST /v1/messages` com chave de idempotência. O Sabiá renderiza os templates publicados a partir de `sabia/templates.json` e usa o remetente do perfil de canal.
  - `resend` e `millionsend`: um único adaptador, porque o MillionSend é compatível com o Resend em `POST /emails`, nas respostas, nos erros e no `Idempotency-Key`.
  - `smtp`: STARTTLS por padrão, TLS implícito ou, só para IP de loopback, sem TLS (Mailpit em desenvolvimento).
- **Templates:** os quatro templates (convite, recuperação, confirmação de e-mail, aviso de segurança) são definidos em Go, em pt-BR. O manifesto do Sabiá é gerado das mesmas fontes, e um teste falha se `sabia/templates.json` estiver desatualizado. Para Resend, MillionSend e SMTP, o registry renderiza o mesmo texto e escapa os valores no HTML. As variáveis são exatamente as declaradas, sem caracteres de controle, e os links precisam ser http(s).
- **Outbox:** a mensagem entra na fila de jobs (`email.send`) na mesma transação da mudança que a gera, então só existe se a mudança for gravada. O conteúdo é cifrado com a chave mestra, porque contém destinatário e link de uso único, e nem o banco nem os backups o mostram em claro. Um worker do `serve` envia com lease de 2 min e repete erros temporários (429, 5xx, 408, rede, SMTP 4xx) com espera de 30 s a 1 h, com jitter e respeitando `Retry-After`, até 10 tentativas. Erros permanentes (outros 4xx, SMTP 5xx, falha ao abrir o conteúdo) encerram o job como `dead` sem nova tentativa. A chave de idempotência nomeia o evento (por exemplo `email:recovery:<id>`) e se repete em toda tentativa. No SMTP ela também define o `Message-ID`.
- **Rede:** HTTP pelo cliente restrito de egress (origem exata, `REGISTRY_EMAIL_ALLOWED_NETWORKS`, DNS e CA opcionais); SMTP por um dialer restrito novo (`egress.NewTCPDialer`) com as mesmas regras. As chaves vêm de arquivos privados. Logs registram provedor, template, job e código de erro, nunca destinatário, link ou resposta do provedor.
- **Confirmação de endereço:** `PUT /api/v1/account/email` (mesma exigência de segundo fator do cadastro de passkey) envia um link `prver_…` válido por 24 h, no máximo 5 por hora. A conta mantém o endereço anterior até `POST /api/v1/auth/email/confirm`, que não exige sessão e é limitado por origem. A interface só confirma com um clique, então um scanner de e-mail que abra o link não confirma nada. Um endereço confirmado anterior recebe aviso da troca.
- **Convite por e-mail:** `email` opcional no convite. O token não é devolvido ao administrador, e criar a conta por um convite enviado por e-mail confirma esse endereço. Convite sem e-mail continua como antes.
- **Recuperação pela própria pessoa:** `POST /api/v1/auth/recovery/request` com o login responde 202 sempre, exista ou não a conta, tenha ou não e-mail confirmado, e conta como tentativa da origem. Só envia para e-mail confirmado de conta local ativa, no máximo um link a cada 5 min. O link vale 1 h e **só redefine a senha**: o segundo fator continua sendo exigido. Um pedido novo invalida só os links pedidos pela própria pessoa, nunca o que um administrador emitiu.
- **Recuperação pelo administrador:** `send_email` envia o link ao e-mail confirmado da pessoa sem mostrá-lo ao administrador.
- **Avisos de segurança** ao e-mail confirmado: senha redefinida ou fator removido pela recuperação, administrador recuperado no servidor, TOTP cadastrado, passkey cadastrada ou removida e troca de e-mail. Se o aviso não puder ser montado, a mudança acontece mesmo assim.
- **Falhas e reenvio:** quando um e-mail é abandonado (erro permanente ou as 10 tentativas esgotadas), `registry_email_failures` (migração 47) guarda template, provedor e um código curto (`http_404:TEMPLATE_NOT_FOUND`, `http_503`, `smtp_550`, `unreachable`). Destinatário e link continuam cifrados no job. `GET /api/v1/admin/email`, só para administradores da instância, devolve `health` (`ok`; `failing` quando há falha não reenviada; `stalled` quando uma mensagem espera há mais de 30 min), contagens e as últimas falhas com o destinatário mascarado (`a…@example.com`). Um monitor externo pode alertar com base nesse campo. Na interface, o menu Administração ganha uma marca enquanto a saúde não for `ok`, e o painel de e-mail lista as falhas. `POST /api/v1/admin/email/failures/{job}/resend` (MFA recente) põe a mesma mensagem na fila com uma chave nova (`…:resend:N`), porque o provedor pode ter guardado a resposta de erro da chave antiga. A falha fica marcada como reenviada, e o reenvio é auditado. Se o reenvio também falhar, ele aparece como uma falha nova.

## Limites

- Nenhum envio real por Sabiá, Resend ou MillionSend foi feito. Os contratos foram testados contra servidores falsos, e o SMTP contra o Mailpit.
- O Sabiá exige a publicação dos templates (plan/apply com chave de deploy) e um perfil de canal com remetente verificado. Isso fica com o operador.
- Não há cadastro aberto por e-mail (política `open`, decidido pelo proprietário), nem preferências de notificação.
- O alerta é passivo: aparece na interface e na API de status, e nenhum e-mail ou push sai quando o próprio envio falha. Links de recuperação e confirmação podem expirar antes do reenvio; nesse caso, gere um novo.

## Evidência

`internal/email`: validação e escape dos templates, manifesto Sabiá em dia, contratos Sabiá e Resend/MillionSend (cabeçalhos, corpo, 429 com `Retry-After`, 5xx temporário, 4xx permanente sem ecoar a resposta), SMTP sem TLS recusado fora do loopback e `Message-ID` estável, e outbox cifrada com retry pela mesma chave, abandono em erro permanente e rollback junto com a transação. Em SQLite e PostgreSQL: falha registrada com o código, destinatário mascarado, reenvio com chave nova, reenvio duplicado recusado, auditoria e tentativas esgotadas registradas como falha. Avisos de TOTP cadastrado e de passkey removida. `internal/auth` em SQLite e PostgreSQL: confirmação, reuso recusado, recuperação com espera, sem remover fatores, aviso, troca avisando o endereço antigo, envio pelo administrador, link do administrador preservado e limite de confirmações. `internal/workspaces` em SQLite e PostgreSQL: convite por e-mail confirmando o endereço e convite manual sem efeito no e-mail. `cmd/registry`: `serve` real com SMTP para Mailpit (pedido, link, nova senha, link reusado recusado, aviso e banco sem conteúdo em claro) e jornada no Chromium (confirmar e-mail pelo link recebido, "esqueci minha senha" e segundo fator ainda exigido).
