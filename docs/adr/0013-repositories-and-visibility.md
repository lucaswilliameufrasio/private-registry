# ADR 0013 — Repositórios e política de visibilidade

- **Status:** Aceito para a fundação; serving público e autorização de conteúdo seguem pendentes
- **Data:** 2026-10-22

## Contexto

Workspace define a fronteira de tenancy, mas o conteúdo precisa de um escopo menor para visibilidade, grants, formatos e políticas. O plano estabelece slug imutável, visibilidade herdada pelo repositório, três modos, restrição central de modos sem conversão implícita e mudança para público com reautenticação e confirmação.

## Decisões

- Repositório pertence a exatamente um workspace, tem ID opaco, slug único e imutável dentro do workspace e nome de exibição mutável. Mover entre workspaces não é suportado.
- Owner e administrador ativos do workspace podem criar/listar metadados de repositórios. A membership, por si só, não concede leitura/publicação a outros membros; grants explícitos são limitados à membership ativa e seguem o ADR 0014.
- Todo repositório nasce `private`. A visibilidade (`private`, `unlisted` ou `listed`) pertence ao repositório e será herdada por pacotes, versões e arquivos quando os adapters existirem.
- A política da instalação (`private_only`, `private_and_unlisted` ou `all`) determina os destinos permitidos para futuras mudanças explícitas. O default é `private_only`, por menor privilégio. Restringir modos não converte visibilidades existentes; reabilitar um modo não republica nada.
- Somente owner do workspace pode alterar visibilidade. Toda mudança exige sessão MFA recente; transição para `unlisted`/`listed` também exige confirmação explícita do alcance. O administrador da instalação pode alterar a política global com MFA, mas isso não concede leitura de conteúdo nem administração do workspace.
- Esta etapa expõe somente configuração e metadados autenticados. Não há distribuição anônima, listagem pública, busca ou rota de conteúdo até autorização por request e testes de isolamento dos adapters.
- SQLite e PostgreSQL recebem schema equivalente por migration SQL versionada e explícita; `registry serve` não migra.

## Alternativas rejeitadas

- **Permitir modos públicos por padrão:** amplia exposição numa instalação ainda sem UI/fluxos de confirmação; não segue o default deny.
- **Definir visibilidade em cada pacote/versão:** diverge do plano, cria exceções difíceis de auditar e pode expor arquivos inconsistentes.
- **Conceder leitura de repositórios por membership:** torna participação em workspace um grant implícito, contrariando o ADR 0008 e a autorização aditiva.
- **Converter automaticamente repositórios existentes ao restringir a política:** causaria quebra silenciosa de consumidores e conflitaria com a operação explícita exigida pelo plano.

## Consequências e limites

- Os endpoints administrativos podem exibir configuração de visibilidade antes de o protocolo correspondente existir; esse campo não é prova de que conteúdo público está sendo servido.
- Grants explícitos de repositório existem pela migration v8 e pelo serviço/rotas descritos no ADR 0014; equipes, UI e conversão explícita de instalações existentes são trabalho posterior. Não há rotas de conteúdo, então os grants ainda não abrem acesso a bytes.
- Migrações são forward-only; backup/restore e aceite de upgrade ainda precisam ser completados conforme o ADR 0007.
- Reavaliar o default de política apenas após configuração inicial guiada e fluxo completo de serving público, confirmação e invalidação de cache.

## Referências

- [Plano — identidades, nomes e endereços](../development-plan.md#43-identidades-nomes-e-endereços)
- [Plano — autorização e privacidade](../development-plan.md#9-autorização-e-privacidade)
- [ADR 0008 — identidade e fundação de workspaces](0008-identity-and-workspace-foundation.md)
- [ADR 0007 — migrations versionadas](0007-versioned-database-migrations.md)
- [ADR 0014 — grants aditivos de repositório](0014-repository-grants.md)
