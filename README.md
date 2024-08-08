Monitor de Integridade de Arquivos em Tempo Real
aplicativo que monitora a integridade de arquivos críticos no sistema em tempo real, usando algoritmos de hash para detectar qualquer alteração não autorizada. Ele utiliza uma interface gráfica para exibir alertas em caso de detecção de modificações.
Funcionalidades:
Configurar arquivos ou diretórios para monitoramento.
Gerar e armazenar hashes criptográficos dos arquivos monitorados.
Monitorar continuamente e alertar o usuário via interface gráfica em caso de alterações.

Bibliotecas: cryptography, tkinter, watchdog (para monitoramento de arquivos), hashlib.


TODO LIST:
Registro de logs das alterações detectadas.
Ambiente com varios arquivos sendo monitorados.
Alertas Por email.
