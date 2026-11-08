# ADR 0032 — Fronteira experimental de HTTP de saída

- **Status:** Experimental, não integrado
- **Data:** 2026-11-08

## Contexto e direção

A v1 exige saída negada por padrão e liberação explícita por integração. Clientes HTTP precisam conferir destino, resolução e conexão, inclusive em redirects, sem aceitar proxies implícitos do ambiente. Uma autorização de rede interna não é um bypass para destinos arbitrários.

Esta fatia prepara uma fronteira restrita a HTTPS: origens e redes de destino são configuradas explicitamente, a resolução é revalidada por conexão e o socket conecta ao endereço validado, mantendo a validação TLS do hostname original. Redirects não são seguidos automaticamente. A ausência de regras nega todas as conexões. Cada integração deverá ter seu próprio cliente e política; permitir uma origem não implica autorização para outra integração.

Sem um servidor DNS explicitamente configurado por integração, somente endereços IP literais podem ser resolvidos. Quando autorizado, DNS usa exclusivamente o IP e porta configurados; os endereços retornados ainda passam pelas redes permitidas. Isto não impõe restrições globais ao processo, ao DNS de outros clientes, SMTP, subprocessos, workers ou clientes que não usem esta fronteira. Ainda faltam adoção pelas demais integrações, configuração e autorização administrativas, isolamento de rede fora do processo, verificação de tráfego observado e procedimentos offline. Nenhum aceite de egress ou de v1 é afirmado por esta fundação.

## Evidência parcial

Testes de loopback exercitam negação com política vazia, redes permitidas e negadas, resolução em conexões novas, falha DNS, fallback DNS de UDP para TCP no mesmo servidor explícito, TLS não confiável, host sobrescrito, recusa de redirects automáticos e ausência de proxy implícito. Uma fixture HTTPS usa a fronteira no cliente do driver S3 experimental e comprova que o request negado não chega ao servidor, enquanto uma origem e rede autorizadas permitem gravação e leitura sintéticas. O provider de credenciais do SDK pode realizar suas próprias conexões e não está protegido automaticamente por esse cliente. Floci, backend S3 real, atomicidade, processo completo e isolamento de rede não são comprovados aqui.

No worktree isolado, `database.Open` usa uma configuração pgx que restringe TCP a um hostname/porta e redes explícitas, exige TLS com verificação do hostname e rejeita fallbacks. Socket Unix local é limitado ao caminho configurado, sem DNS ou fallback TCP. A rede TCP é negada quando `REGISTRY_DATABASE_ALLOWED_NETWORKS` não está definido; nomes exigem `REGISTRY_DATABASE_DNS_SERVER`. Testes PostgreSQL reais em container sem rede, usando proxy loopback apenas de fixture, passaram para consulta e cancelamento com TLS; um teste separado exercita consulta e cancelamento pelo socket Unix. Redes não autorizadas foram recusadas antes do proxy. Testes de fixture também verificaram hostname HTTPS e PostgreSQL com DNS explícito e falha sem ele. A mudança ainda precisa de gate integral e conciliação; credentials providers, outras integrações, DNS de outros clientes e a imposição global continuam sem cobertura.

Um teste Linux isolado por Bubblewrap executa migrations SQLite, inicia a chave e o servidor, consulta readiness e prepara um recovery criptografado com marcador incompleto. O namespace de rede é inspecionado e contém apenas loopback ativo; uma tentativa TCP para endereço externo falha. O teste exige Bubblewrap e namespaces de usuário/rede disponíveis, filesystem e binário temporários, e não altera a rede do host. Isso não prova que o processo não tentou outras conexões nem cobre instalação, publicação, consumo, promoção ou recovery completo.
