# Pythomic

**Pythomic** é um projeto experimental de rede social inspirado em plataformas como o Instagram, desenvolvido em Python usando **ReactPy** para a interface e **Flask** como servidor web. O projeto está organizado em um único arquivo principal (`pythomic.py`), com banco de dados SQLite criado localmente.

> **Estado do projeto:** projeto em desenvolvimento/estudo. Não o exponha diretamente à internet nem o use para armazenar dados reais ou sensíveis sem uma revisão de segurança e testes adicionais.

## Funcionalidades

Entre as funcionalidades implementadas no código estão:

- Cadastro e login de usuários.
- Publicações de texto e mídia, com validação de uploads.
- Feed de publicações.
- Curtidas e opção de seguir/deixar de seguir usuários.
- Alteração de senha.
- Interface com opção de tema claro/escuro.
- Armazenamento local com SQLite.
- Proteções de aplicação, como hash de senhas, limitação de tentativas de login e cabeçalhos HTTP de segurança.

A interface e as funcionalidades podem mudar conforme o projeto evoluir.

## Tecnologias

- **Python 3**
- **ReactPy** — criação da interface com componentes Python.
- **Flask** — servidor web.
- **SQLite** — banco de dados local, incluído na biblioteca padrão do Python.
- **cryptography** — criptografia dos campos sensíveis armazenados pelo aplicativo.

## Estrutura dos arquivos

```text
Pythomic/
├── pythomic.py          # Aplicação
├── requirements.txt     # Dependências Python
├── .gitignore           # Arquivos que não devem ser enviados ao Git
├── database.db          # Banco de dados criado durante a execução
├── .pythomic_secret     # Segredo local gerado pelo aplicativo
└── uploads/             # Mídias enviadas pelos usuários
```

Os três últimos itens são gerados localmente quando necessários; não precisam estar presentes no repositório inicialmente. O arquivo `.pythomic_secret` é sensível e não deve ser publicado.

## Requisitos

- Python **3.10 ou superior** (recomendado).
- `pip`.
- Conexão com a internet na primeira instalação, para baixar as dependências.

Confira a instalação do Python:

```bash
python --version
python -m pip --version
```

Em alguns sistemas Linux, o comando é `python3` em vez de `python`.

## Instalação e execução no Windows (CMD)

Abra o **Prompt de Comando (CMD)** e navegue até a pasta onde salvou ou clonou o projeto. Por exemplo:

```bat
cd %USERPROFILE%\projetos\Pythomic
```

Se ainda não baixou o repositório, pode cloná-lo com Git:

```bat
git clone https://github.com/Letra-Arcania/Pythomic.git
cd Pythomic
```

Crie um ambiente virtual:

```bat
py -m venv .venv
```

Ative-o:

```bat
.venv\Scripts\activate
```

Atualize o `pip` e instale as dependências do projeto:

```bat
py -m pip install --upgrade pip
py -m pip install -r requirements.txt
```

Inicie a aplicação:

```bat
py pythomic.py
```

Abra o navegador em:

**http://localhost:5000**

Para sair, pressione `Ctrl+C` no terminal. Para sair do ambiente virtual, execute `deactivate`.

> Se o comando `py` não existir, instale o Python pelo site oficial e marque a opção para adicioná-lo ao `PATH`. Depois tente usar `python` no lugar de `py`.

## Instalação e execução no Linux

Primeiro, clone o repositório ou entre na pasta que contém `pythomic.py` e `requirements.txt`:

```bash
git clone https://github.com/Letra-Arcania/Pythomic.git
cd Pythomic
```

### Debian / Ubuntu

Instale Python, `pip` e o suporte a ambientes virtuais:

```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv git
```

### Arch Linux / derivados

```bash
sudo pacman -Syu
sudo pacman -S --needed python python-pip git
```

### Fedora

```bash
sudo dnf install -y python3 python3-pip git
```

### Criar o ambiente virtual e instalar as bibliotecas

Estando na pasta do projeto, execute em qualquer uma das distribuições acima:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Inicie a aplicação:

```bash
python pythomic.py
```

Acesse **http://127.0.0.1:5000** no navegador. Para parar o servidor, pressione `Ctrl+C`. Para sair do ambiente virtual, execute:

```bash
deactivate
```

### Quais bibliotecas são instaladas?

As dependências estão listadas em `requirements.txt`:

- `reactpy[flask]` — ReactPy e integração com Flask.
- `Flask` — servidor web.
- `cryptography` — fornece criptografia autenticada para campos sensíveis.

O `sqlite3`, além de módulos como `os`, `secrets` e `hashlib`, faz parte da biblioteca padrão do Python e não precisa ser instalado com `pip`.

## Banco de dados, segredo e arquivos locais

Na primeira execução, a aplicação cria o banco `database.db` e pode criar a pasta `uploads/` para arquivos enviados. O segredo mestre é guardado em `.pythomic_secret` caso a variável de ambiente `PYTHOMIC_SECRET` não esteja definida.

**Guarde o segredo mestre com segurança.** Se perder ou substituir esse segredo, os campos que foram criptografados com o segredo antigo podem ficar impossíveis de descriptografar. Não compartilhe nem publique `.pythomic_secret`, o banco de dados ou uploads privados.

Se `cryptography` não estiver disponível, o código tem um modo alternativo baseado em Base64. **Base64 não é criptografia**; instale as dependências do `requirements.txt` para usar o recurso de criptografia previsto.

## Solução de problemas

### `python` ou `python3` não encontrado

Instale Python seguindo as instruções da sua distribuição. No Windows, tente `py --version`.

### `No module named ...`

Confirme que o ambiente virtual está ativado e instale as dependências novamente:

```bash
python -m pip install -r requirements.txt
```

No Windows CMD, use `py -m pip install -r requirements.txt` se esse for o comando Python disponível.

### `externally-managed-environment` no Linux

Não force a instalação de pacotes no Python do sistema. Crie e ative o ambiente virtual conforme as instruções acima e instale as bibliotecas dentro dele.

### Não consigo abrir a página

Confirme que o servidor continua em execução e que o terminal não mostrou um erro. Abra `http://localhost:5000` no mesmo computador. Por padrão, o endereço local não disponibiliza o site publicamente na rede.

## Segurança

- Use apenas para desenvolvimento local enquanto o projeto não tiver sido revisado e preparado para produção.
- Não ative o modo de depuração em um servidor público.
- Não publique `.pythomic_secret`, credenciais, banco de dados ou conteúdo de usuários.
- A proteção por senha e a criptografia de campos não substituem uma auditoria de segurança, testes e configuração adequada para implantação.

## Licença

Nenhuma licença foi especificada neste repositório até o momento. Consulte o responsável pelo projeto antes de reutilizar ou redistribuir o código.
