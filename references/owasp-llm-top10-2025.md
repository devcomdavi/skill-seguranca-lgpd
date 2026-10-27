# OWASP Top 10 para aplicações com LLM (2025): controles

Fonte: OWASP Top 10 for LLM Applications 2025 (genai.owasp.org). Use quando o sistema tem chatbot, agente com ferramentas, RAG, geração de conteúdo ou qualquer chamada a modelo de linguagem. O princípio central: **trate o modelo como um usuário não confiável**. Ele pode ser induzido a qualquer coisa, então nenhum controle de segurança pode depender dele obedecer.

| Risco | Controles a verificar ou implementar |
|---|---|
| **LLM01 Prompt Injection** | Não existe prevenção completa; limite o estrago. O modelo só tem as permissões mínimas, ações de alto impacto exigem aprovação humana, conteúdo externo (páginas, documentos, e-mails) é separado e marcado como não confiável, a saída tem formato definido e validado por código. |
| **LLM02 Divulgação de informação sensível** | Não envie ao modelo dados pessoais além do necessário (minimização; mascarar CPF, e-mail etc.). Confira os termos do provedor: retenção, uso para treino (desligue), região. Contexto de um usuário nunca entra na conversa de outro. Política de privacidade informa o uso de IA e o compartilhamento com o provedor. |
| **LLM03 Supply chain** | Modelos, bibliotecas e plugins de fontes oficiais; versões fixadas; avaliação do provedor como operador (LGPD). |
| **LLM04 Envenenamento de dados e modelo** | Se houver fine-tuning ou base de conhecimento alimentada por usuários: validar a origem, revisar o que entra, permitir remoção. |
| **LLM05 Tratamento inadequado da saída** | Saída do modelo é input não confiável: escape antes de renderizar (sem `dangerouslySetInnerHTML` de saída crua; sanitizar Markdown), queries parametrizadas se a saída for usada em banco, nunca executar como código ou comando, CSP restritiva. |
| **LLM06 Agência excessiva** | Ferramentas mínimas e específicas (nada de "executar comando" ou "buscar qualquer URL"); permissões mínimas na credencial que a ferramenta usa (ex.: só leitura na tabela necessária); ações executadas com a identidade e as permissões do usuário que pediu; autorização feita no sistema chamado, não pelo modelo; aprovação humana para enviar, pagar, excluir ou publicar. |
| **LLM07 Vazamento do system prompt** | Nada secreto no system prompt (chaves, nomes de tabelas, regras de permissão). Controles críticos fora do modelo, de forma determinística. |
| **LLM08 Fraquezas em vetores e embeddings (RAG)** | Base vetorial com controle de acesso por usuário/empresa (filtro por `tenant_id` na busca, aplicado no servidor); documentos validados antes de entrar; logs de recuperação. Exclusão de dados do titular precisa apagar também os embeddings derivados. |
| **LLM09 Desinformação** | Para respostas que embasam decisões (saúde, jurídico, financeiro), citar fontes, deixar claro que é gerado por IA e manter revisão humana. |
| **LLM10 Consumo sem limites** | Rate limit e cota por usuário e por plano; limite de tamanho de entrada e de `max_tokens`; timeout; teto de gasto no painel do provedor; alerta de custo. Chave do provedor só no servidor (ver `medidas/11-rate-limit.md`, seção "Limite por custo"). |

## LGPD e IA

- Enviar dados pessoais a um provedor de LLM é compartilhamento com operador e, em geral, transferência internacional (ver `lgpd.md`).
- Decisões tomadas unicamente por tratamento automatizado que afetem interesses do titular (aprovar crédito, classificar candidato, definir preço) dão direito a pedir revisão e a receber informações sobre os critérios (art. 20). Prever esse fluxo.
- Dados sensíveis (saúde, biometria etc.) em prompts exigem base legal do art. 11 e cuidado redobrado; prefira anonimizar antes de enviar.
