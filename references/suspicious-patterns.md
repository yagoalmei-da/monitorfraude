# Padrões de Identificação de Fraude: Débitos Veiculares

## 1. Padrões de Domínio Suspeito
- Domínios genéricos imitando órgãos oficiais: ipva-sp.com, detranbr.net, detran-online.com
- Uso de palavras-chave sem domínio .gov.br: consultaplaca.io, pagardebito.com, debitoveiculo.net
- Domínios com hífen ou variações: detran-sp.com, sefaz-online.net
- Domínios registrados há menos de 1 ano
- TLDs incomuns para serviços brasileiros: .io, .net, .info, .online, .site, .xyz

## 2. Cobranças Indevidas
- Cobrar taxa de "consulta" (consulta oficial é GRATUITA no Detran/Sefaz)
- Cobrar "taxa de processamento" para emitir boleto (boleto oficial é gratuito)
- Planos de assinatura para "consultas ilimitadas"
- Cobrar para "desbloquear" informações do veículo

## 3. Imitação Visual (Phishing)
- Layout idêntico ao site do Detran ou Sefaz estadual
- Uso de logos e brasões oficiais sem autorização
- Cores e fontes que imitam portais governamentais
- URL diferente mas visual igual ao site oficial

## 4. Ausência de Elementos de Legitimidade
- Sem CNPJ visível no rodapé
- CNPJ inválido ou que não confere na Receita Federal
- Sem endereço físico da empresa
- Sem política de privacidade (LGPD)
- Sem termos de uso
- Certificado SSL ausente (HTTP em vez de HTTPS)
- Certificado SSL de domínio diferente do site

## 5. Solicitação de Dados Sensíveis Indevidos
- Pedir CPF + dados de cartão de crédito para "consulta"
- Solicitar dados bancários para verificação
- Pedir senha do Gov.br ou de outros portais
- Coletar dados além do necessário para o serviço

## 6. Sinais de Alerta Adicionais
- Reclamações no Reclame Aqui sobre não entrega do serviço
- Sem SAC ou canal de atendimento identificado
- Links de redes sociais quebrados ou inexistentes
- Erros ortográficos e gramaticais no conteúdo
- Pop-ups agressivos de "oferta por tempo limitado"
- Countdown timer falso para pressionar pagamento

## 7. Classificação de Risco
- ⚠️ Suspeito Leve: 0-2 flags identificadas - monitorar
- 🟠 Suspeito Moderado: 3-4 flags identificadas - investigar com prioridade
- 🔴 Provável Fraude: 5+ flags identificadas - reportar e bloquear

## 8. Ações Recomendadas por Classificação
### Suspeito Leve
- Manter em watchlist
- Re-avaliar em 30 dias
- Verificar reclamações no Reclame Aqui

### Suspeito Moderado  
- Notificar equipe de segurança
- Verificar registro do domínio (WHOIS)
- Verificar CNPJ na Receita Federal
- Buscar reclamações e notícias sobre o site

### Provável Fraude
- Reportar ao CERT.br (cert.br)
- Reportar ao Procon estadual
- Notificar o Detran/Sefaz imitado
- Incluir na blacklist imediatamente
- Considerar notificação ao MP/Polícia
