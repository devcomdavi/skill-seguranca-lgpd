# LGPD aplicada ao sistema

Lei nº 13.709/2018 (LGPD) e regulamentos da ANPD, traduzidos em requisitos de produto e de código. Para cada tema: o que a lei pede, como fica no sistema e que evidência coletar na auditoria. Não é parecer jurídico; em casos de alto risco, recomende validar com advogado ou encarregado (DPO). Confirme o texto vigente em https://www.planalto.gov.br/ccivil_03/_ato2015-2018/2018/lei/l13709.htm e https://www.gov.br/anpd.

## Sumário
1. Papéis e porte
2. Princípios → requisitos
3. Inventário de dados (registro das operações)
4. Bases legais
5. Consentimento e cookies
6. Transparência e política de privacidade
7. Direitos do titular
8. Retenção e eliminação
9. Dados sensíveis
10. Crianças e adolescentes (LGPD art. 14 + ECA Digital)
11. Segurança e privacy by design
12. Operadores e fornecedores
13. Transferência internacional
14. Encarregado (DPO)
15. RIPD
16. Incidentes de segurança
17. Sanções
18. Checklist rápido de auditoria

---

## 1. Papéis e porte

- **Controlador:** quem decide por que e como os dados são tratados. O dono do SaaS ou da empresa que usa o sistema.
- **Operador:** quem trata em nome do controlador. O desenvolvedor ou agência que hospeda e opera o sistema para um cliente, e fornecedores como Supabase, Vercel, provedores de e-mail e de IA.
- Defina isso no início: muda quem assina a política, quem comunica incidente (o controlador) e que contrato é necessário.
- **Agente de pequeno porte** (Resolução CD/ANPD nº 2/2022: microempresas, empresas de pequeno porte, startups, MEIs, que não façam tratamento de alto risco): regras simplificadas, como registro de operações simplificado, dispensa de indicar encarregado (mas com canal de comunicação com o titular obrigatório) e prazos em dobro, incluindo o de comunicação de incidente. Tratamento de alto risco (dados sensíveis ou de crianças em larga escala, vigilância, decisões automatizadas relevantes) tira esses benefícios.

## 2. Princípios → requisitos (art. 6º)

| Princípio | No sistema |
|---|---|
| Finalidade | Cada dado coletado tem finalidade escrita no inventário; não reaproveitar para outra finalidade incompatível (ex.: e-mail de cadastro usado para marketing sem base). |
| Adequação | Os dados combinam com o serviço (formulário de newsletter não pede CPF). |
| Necessidade | Coletar o mínimo; campos opcionais de fato opcionais; respostas de API enxutas (medida 17); não guardar o que não precisa. |
| Livre acesso | Titular consegue ver e exportar seus dados de forma fácil e gratuita. |
| Qualidade | Titular consegue corrigir; validação de dados. |
| Transparência | Política de privacidade clara; avisos no momento da coleta. |
| Segurança | Medidas técnicas (OWASP, 20 medidas). |
| Prevenção | Avaliar risco antes de lançar funcionalidade nova (modo A). |
| Não discriminação | Atenção a decisões automatizadas e perfis. |
| Responsabilização | Conseguir **demonstrar**: inventário, registros de consentimento, logs, relatório de auditoria. |

## 3. Inventário de dados / registro das operações (art. 37)

Controlador e operador devem manter registro das operações de tratamento. É também a base de tudo o resto (política, bases legais, retenção, resposta a incidente).

Monte a partir de `scripts/mapear_dados_pessoais.py --md` e confirme com o usuário. Uma tabela por atividade de tratamento, guardada no repositório (ex.: `docs/lgpd/inventario-dados.md`) para evoluir com o código. Para cada atividade (cadastro, pagamento, suporte, marketing, analytics, IA): dados, titulares, finalidade, base legal, onde ficam (tabela/serviço/país), quem acessa, com quem é compartilhado, retenção, medidas de segurança.

Fontes de dados pessoais esquecidas com frequência: logs, ferramentas de analytics e session replay, pixels de anúncio, e-mails transacionais, uploads, backups, planilhas exportadas, prompts enviados a IA, ferramentas de suporte e CRM, n8n/Make/Zapier.

## 4. Bases legais (arts. 7º e 11)

Todo tratamento precisa de uma base legal. Consentimento é só uma delas e muitas vezes não é a melhor.

| Atividade típica | Base usual (art. 7º) |
|---|---|
| Cadastro e prestação do serviço contratado | Execução de contrato (V) |
| Nota fiscal, guarda de registros exigida por lei (Marco Civil art. 15, obrigações fiscais) | Cumprimento de obrigação legal (II) |
| Segurança, prevenção a fraude, logs de segurança | Legítimo interesse (IX) ou obrigação legal; prevenção à fraude também aparece no art. 11, II, "g" para dados sensíveis |
| Marketing por e-mail para clientes | Legítimo interesse com opt-out fácil, ou consentimento |
| Marketing para não clientes, cookies de publicidade, compartilhamento com parceiros | Consentimento (I) |
| Analytics de uso | Legítimo interesse (avaliar e documentar) ou consentimento, conforme a intrusividade |
| Defesa em processo | Exercício regular de direitos (VI) |
| Análise de crédito | Proteção do crédito (X) |

Legítimo interesse exige avaliação documentada (teste de balanceamento) e transparência, e não serve para dados sensíveis. Para **dados sensíveis**, as bases são as do art. 11 (consentimento específico e destacado, ou hipóteses como obrigação legal, tutela da saúde por profissional de saúde, prevenção à fraude na identificação).

Achado típico: o sistema pede consentimento para tudo (inclusive para o que é contrato) e, se o usuário recusa, o serviço não funciona. Isso torna o consentimento não livre.

## 5. Consentimento e cookies (arts. 8º e 9º)

Quando o consentimento é a base:
- livre, informado, inequívoco e para finalidade específica; nada de caixa pré-marcada;
- granular (marketing separado de compartilhamento separado de analytics);
- **registrado** com prova: quem, quando, qual versão do texto, qual finalidade, de onde (tabela `consentimentos` com `user_id`, `finalidade`, `versao_texto`, `concedido_em`, `revogado_em`, `origem`);
- revogável tão facilmente quanto foi dado, com efeito real (parar de enviar ao parceiro, remover da lista);
- mudança de finalidade exige novo consentimento.

**Cookies:** o Guia Orientativo da ANPD sobre cookies (2022) indica que cookies não necessários dependem de base legal, normalmente consentimento. No sistema: banner com opções por categoria, botão de rejeitar com o mesmo destaque do de aceitar, scripts de analytics e publicidade **carregados só depois** do aceite (verificar na aba Network que nada dispara antes), e um link permanente para mudar a escolha. Ver também `medidas/09-proteger-cookies.md`.

## 6. Transparência e política de privacidade (art. 9º)

A política deve informar, em linguagem clara: identidade e contato do controlador e do encarregado (ou canal); quais dados, para quais finalidades e com quais bases legais; forma e duração do tratamento; com quem compartilha (categorias e, quando relevante, nomes, como provedores de IA); transferência internacional; direitos do titular e como exercê-los; uso de cookies; decisões automatizadas; data da última atualização.

Gere a partir do inventário, seguindo a lista acima como estrutura de seções. Na auditoria, **compare a política com o código**: cada integração de terceiros no código (SDKs de analytics, pixels, IA, e-mail, pagamento) deve aparecer na política. Divergência é achado.

Avisos no ponto de coleta: formulários dizem para que serve o dado e linkam a política.

## 7. Direitos do titular (arts. 18 a 20)

Direitos: confirmação de tratamento, acesso, correção, anonimização/bloqueio/eliminação de dados desnecessários ou tratados em desconformidade, portabilidade, eliminação dos dados tratados com consentimento, informação sobre compartilhamento, informação sobre a possibilidade de não consentir, revogação do consentimento, revisão de decisões automatizadas (art. 20), e petição à ANPD.

**Prazos (art. 19):** confirmação e acesso em formato simplificado imediatamente; declaração completa em até 15 dias do requerimento.

No sistema:
- área "Meus dados" ou canal com fluxo definido: exportar (JSON/CSV legível), corrigir, excluir conta, gerenciar consentimentos;
- **verificação de identidade** antes de atender (usuário logado, ou confirmação pelo e-mail cadastrado): um pedido falso de exportação é um vazamento;
- exclusão que alcança todos os lugares: tabelas relacionadas, storage, provedor de e-mail, CRM, analytics, embeddings de IA; o que precisar ser mantido por obrigação legal fica bloqueado e com prazo, e isso é explicado ao titular;
- registro de cada pedido e resposta (data, tipo, prazo, resultado) para prestação de contas;
- se houver decisões automatizadas relevantes, um caminho para pedir revisão e explicação dos critérios.

Teste na auditoria: crie uma conta de teste, peça exportação e exclusão, e confirme o resultado no banco e nos serviços integrados.

## 8. Retenção e eliminação (arts. 15 e 16)

Os dados devem ser eliminados ao fim do tratamento (finalidade alcançada, fim do prazo, pedido do titular, determinação da ANPD), salvo exceções como obrigação legal.

No sistema: prazo de retenção por categoria no inventário; rotina agendada (cron/job) que apaga ou anonimiza o que venceu (contas inativas, leads antigos, logs além do prazo, arquivos temporários); backups com prazo de expiração; "soft delete" não é exclusão, então precisa de purga posterior. Anonimização de verdade (não reversível com meios razoáveis), não só trocar o nome.

## 9. Dados sensíveis (art. 5º, II e art. 11)

Origem racial ou étnica, convicção religiosa, opinião política, filiação a sindicato ou organização religiosa, filosófica ou política, dado referente à saúde ou à vida sexual, dado genético ou biométrico.

Exigem: base do art. 11; minimização rigorosa; cifra por campo (medida 5); acesso restrito e registrado; RIPD recomendado; atenção ao enviar para IA e analytics. Dado de saúde não pode ser compartilhado para obter vantagem econômica, salvo exceções do art. 11, §4º. Apps de saúde, bem-estar, terapia, academias, clínicas e RH frequentemente tratam dados sensíveis sem perceber (ex.: campo "observações" com diagnóstico, foto de documento usada como biometria).

## 10. Crianças e adolescentes

**LGPD art. 14:** tratamento sempre no melhor interesse; dados de crianças (até 12 anos incompletos) com consentimento específico e em destaque de pelo menos um dos pais ou responsável, com esforço razoável para verificar que quem consentiu é o responsável; não condicionar jogos e aplicações a fornecer dados além do estritamente necessário; informações em linguagem adequada.

**ECA Digital (Lei nº 15.211/2025, em vigor desde 17/03/2026):** aplica-se a produtos e serviços digitais direcionados a crianças e adolescentes ou de acesso provável por eles. Entre as obrigações divulgadas: proteção desde a concepção e por padrão, mecanismos confiáveis de verificação de idade (análises publicadas indicam que a autodeclaração isolada não basta), supervisão parental, restrições a perfilamento para publicidade dirigida e a mecanismos como loot boxes, com sanções que chegam a multa de até 10% do faturamento no Brasil, limitada a R$ 50 milhões por infração. A regulamentação ainda está sendo detalhada (ANPD e decretos): **se o sistema pode ser usado por menores, sinalize como risco alto e recomende avaliação jurídica específica**, confirmando o texto atual.

No sistema: decidir e documentar se o público inclui menores; se não inclui, termos e fluxo coerentes com isso; se inclui, fluxo de consentimento parental, configurações mais protetivas por padrão, sem publicidade comportamental, coleta mínima.

## 11. Segurança e privacy by design (arts. 46 a 49)

Os agentes devem adotar medidas de segurança, técnicas e administrativas, aptas a proteger os dados de acessos não autorizados e de situações acidentais ou ilícitas (art. 46), **desde a fase de concepção do produto ou serviço até a sua execução** (art. 46, §2º). A parte técnica é o restante desta skill (OWASP e 20 medidas). A parte administrativa, para sistemas pequenos: quem tem acesso ao painel de produção (com MFA), revisão periódica de acessos, política de senhas e de segredos, backup testado, plano de incidente.

## 12. Operadores e fornecedores (arts. 37 a 40)

Liste todo serviço que recebe dados pessoais (hospedagem, banco, auth, e-mail, SMS/WhatsApp, pagamento, analytics, monitoramento de erros, IA, automação, suporte). Para cada um: que dados recebe, país, se o contrato/termos (DPA) cobre proteção de dados, se usa os dados para fins próprios (ex.: treino de IA; desligar quando possível). Ferramentas de monitoramento de erros (Sentry etc.) e session replay costumam capturar dados pessoais por padrão: configurar mascaramento.

## 13. Transferência internacional (art. 33)

Sistemas vibecodados quase sempre transferem dados para fora do Brasil (Supabase, Vercel, AWS, OpenAI, Anthropic, Google com servidores nos EUA ou na Europa). A transferência só é permitida nas hipóteses do art. 33. A Resolução CD/ANPD nº 19/2024 regulamentou o tema e aprovou cláusulas-padrão contratuais, com prazo de adequação que terminou em agosto de 2025; em janeiro de 2026 a ANPD reconheceu a União Europeia como de nível adequado de proteção (Resolução CD/ANPD nº 32/2026). Para destinos sem adequação (como os EUA), o caminho usual são as cláusulas-padrão da ANPD no contrato com o fornecedor.

No sistema: escolher a região do projeto quando possível (ex.: região São Paulo no Supabase/AWS), registrar no inventário os países, citar a transferência na política, e verificar o mecanismo contratual. Recomende validação jurídica, pois depende dos contratos de cada fornecedor.

## 14. Encarregado / DPO (art. 41)

O controlador indica um encarregado (Resolução CD/ANPD nº 18/2024 detalha a atuação), com identidade e contato divulgados de forma clara, de preferência no site. Agentes de pequeno porte podem ser dispensados de indicar, mas precisam manter um canal de comunicação com o titular. No sistema: e-mail ou formulário do encarregado/canal na política e no rodapé; fluxo para os pedidos chegarem a alguém.

## 15. Relatório de Impacto (RIPD, art. 38)

A ANPD pode exigir; é recomendado quando o tratamento é de alto risco (dados sensíveis ou de crianças em escala, vigilância, decisões automatizadas relevantes, tecnologias novas como IA com dados pessoais, legítimo interesse em larga escala). Conteúdo mínimo: descrição dos dados, metodologia de coleta e de segurança, análise de riscos e medidas de mitigação. Sinalize no relatório quando o sistema se enquadra.

## 16. Incidentes de segurança (art. 48 e Resolução CD/ANPD nº 15/2024)

- Incidente com dados pessoais que **possa acarretar risco ou dano relevante** aos titulares deve ser comunicado pelo controlador à ANPD e aos titulares em **até 3 dias úteis** do conhecimento (prazo em dobro para agentes de pequeno porte). É possível comunicar de forma preliminar e complementar depois.
- Risco relevante, segundo a resolução, considera se o incidente afeta significativamente interesses e direitos fundamentais e envolve, por exemplo, dados sensíveis, de crianças/adolescentes/idosos, financeiros, de autenticação, protegidos por sigilo, ou em larga escala.
- Todo incidente, comunicado ou não, deve ser **registrado e o registro mantido por pelo menos 5 anos**.
- Dados cifrados com chave protegida reduzem a gravidade (art. 48, §3º).

O plano de resposta a incidentes deve existir antes do incidente: quem decide, como conter, como preservar evidências (logs), como avaliar o risco, modelos de comunicação, onde registrar. Quando a auditoria encontra uma exposição que **já pode ter sido explorada** (ex.: tabela pública há meses, chave no repositório público), trate como possível incidente: conter, verificar logs de acesso do provedor e avaliar com o usuário a necessidade de comunicar, deixando claro o prazo.

## 17. Sanções (art. 52)

Advertência, multa simples de até 2% do faturamento da pessoa jurídica no Brasil limitada a R$ 50 milhões por infração, multa diária, publicização da infração, bloqueio ou eliminação dos dados, suspensão do banco de dados ou da atividade, proibição de tratamento. A ANPD considera, entre outros, a boa-fé, as medidas de segurança adotadas e a adoção de boas práticas: por isso a documentação (inventário, relatório de auditoria, correções) tem valor concreto. Além da ANPD, há risco de ações judiciais dos titulares e do consumidor (CDC).

## 18. Checklist rápido de auditoria

| Item | Evidência |
|---|---|
| Papéis definidos (controlador/operador) e porte | Declaração do usuário |
| Inventário de dados completo, inclusive terceiros e logs | `inventario-dados-modelo.md` preenchido |
| Base legal por finalidade; dados sensíveis com base do art. 11 | Inventário |
| Consentimento granular, registrado e revogável (onde for a base) | Tabela de consentimentos, tela de preferências |
| Cookies não essenciais só após aceite | Aba Network antes do aceite |
| Política de privacidade completa e coerente com o código | Política × integrações encontradas no código |
| Canal do titular e do encarregado | Link na política e no rodapé |
| Exportação, correção e exclusão funcionando de ponta a ponta | Teste com conta de teste |
| Retenção definida e rotina de eliminação | Job agendado, configuração de backups |
| Operadores mapeados, contratos/DPA, treino de IA desligado | Lista de fornecedores |
| Transferência internacional mapeada e com mecanismo | Regiões dos serviços, contratos |
| Público infantil avaliado (LGPD art. 14, ECA Digital) | Decisão documentada |
| Plano de resposta a incidentes e registro de incidentes | `plano-resposta-incidentes.md` |
| Segurança técnica (art. 46) | Seções OWASP do relatório |
| RIPD quando alto risco | Documento ou recomendação |
