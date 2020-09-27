#!/usr/bin/env python
import keyring
import re
import fdb
import os
import os.path
# import datetime
from time import sleep
from pathlib import Path
from shutil import copyfile
from fdb import services


# Bibliotecas acrescentadas
# pip install -U pip
# pip install keyring
# pip install datetime
# pip install fdb
# https://firebirdsql.org/file/documentation/drivers_documentation/python/fdb/usage-guide.html#

# Callback function para exibir as linhas de cmd do backup/restore
def fetchline(line):
    print(line)
    return None


def file_info_error(def_file_info: str, def_msg: str):
    print('Foi encontrado um erro "{}" no arquivo "{}":'.format(def_msg, def_file_info))
    print('Este arquivo deve estar no seguinte formato:')
    print('# producao = desenvolvimento')
    print('# host; usuario; senha; database = host; usuario; senha; database')
    print(r'server01;sysdba;c:\\local\\remoto\\para\\os\\dados\\acad.fdb=localhost;sysdba;c:\\local\\para\\os\\dados\\acad.fdb')
    print(r'server01;sysdba;c:\\local\\remoto\\para\\os\\dados\\vidy15.fdb=localhost;sysdba;c:\\local\\para\\os\\dados\\vidy15.fdb')
    print('Onde:')
    print('  a esqueda do sinal de igualdade "=" está o banco de dados de origem(ex. produção)')
    print('  a direita fica o banco de dados de destino(ex. desenvolvimento)')
    print('  Por motivo de segurança, o destino só poderá ser "localhost".')
    print('No terminal python, use os comandos:')
    print('keyring.set_password("system", "sysdba@dc01", "password") para definir a senha de "sysdba" no host "server01"')
    print('e repita esta operação para todos os hosts que forem mencionados.')
    return None


def find_backup_recent(def_location: str, def_mask: str) -> str:
    latest_file: str = ''
    latest_file_timestamp = 0
    try:
        count_files = 0
        for filename in Path(def_location).rglob(def_mask):
            count_files = count_files + 1
            print('Encontrando: {}'.format(filename), end=' ')
            current_file_date = os.path.getmtime(filename)
            if current_file_date > latest_file_timestamp:
                latest_file = filename
                latest_file_timestamp = current_file_date
                print('superou o anterior')
            else:
                print('superado')
    except Exception as e:
        print('Falha ao procurar backup recente em {} com a mascara {}:\n{}.'.format(def_location, def_mask, str(e)))

    return latest_file

def try_connect_and_write_password(def_host_and_user: str) -> str:
    return_password = ''
    sys_last_error = ''
    list_params = def_host_and_user.split('@')
    def_host_user = list_params[0]
    def_host_name = list_params[1]
    def_host_connected = False
    if sys_last_error == '' and def_host_name == '':
        sys_last_error = 'Nao foi definido o hostname em {}.'.format(def_host_and_user)
    if sys_last_error == '' and def_host_user == '':
        sys_last_error = 'Nao foi definido o user_name em {}.'.format(def_host_and_user)
    if sys_last_error == '':
        return_password = keyring.get_password("system", def_host_and_user)
        if return_password == None:
            return_password = ''

        if return_password != '':
            try:
                con = services.connect(host=def_host_name, user=def_host_user, password=return_password)
                def_host_connected = True
                con.close()
            except Exception as e:
                print('Falha ao conectar {} com a senha memorizada: '.format(str(e)))

    if (sys_last_error == '') and (not def_host_connected):
        return_password = 'senha'
        while (return_password != "") and (not def_host_connected):
            return_password = input('Qual a senha para {}: '.format(def_host_and_user))
            if return_password != '':
                # Testando conexão
                try:
                    con = services.connect(host=def_host_name, user=def_host_user, password=return_password)
                    def_host_connected = True
                    con.close()
                except Exception as e:
                    sys_last_error = 'Falha ao conectar {} com a senha fornecida "{}": {}'.format(def_host_and_user, return_password, str(e))
                    print(sys_last_error)

        if def_host_connected:
            sys_last_error = ''

    if sys_last_error != '':
        return_password = ''
        print('Erro: {}'.format(sys_last_error))
    if sys_last_error == '':
        keyring.set_password("system", def_host_and_user, return_password)
    return return_password


def backup_realizar(con_host: str='localhost', con_user: str='SYSDBA', con_password: str='masterkey', def_location_ori: str='',
                    def_location_dest: str='', result_value: str=False):
    print('Crindo backup de ', con_host, 'em', def_location_ori, 'para', def_location_dest)
    try:
        con = services.connect(host=con_host, user=con_user, password=con_password)
        con.backup(def_location_ori, def_location_dest, callback=fetchline)
        con.close()
        print('Sucesso ao criar backup de {} en {} para {}.'.format(con_host, def_location_ori, def_location_dest))
    except Exception as e:
        print(
            'Falha  ao criar backup de {} en {} para {}.'.format(con_host, def_location_ori, def_location_dest, str(e)))
    return result_value


def backup_restaurar(con_host='localhost', con_user='SYSDBA', con_password='masterkey', def_location_ori='',
                     def_location_dest='', result_value=False):
    sys_last_error = ''
    print('Restaurando backup de ', def_location_ori, 'para', con_host, 'em', def_location_dest)
    try:
        con = services.connect(host=con_host, user=con_user, password=con_password)
        print('Conectado a {}.'.format(con_host))
    except Exception as e:
        sys_last_error = 'Falha ao conectar-se em "{}" usando a conta "{}" (senha="{}"): {}.'.format(con_host, con_user,
                                                                                                     con_password,
                                                                                                     str(e))

    if sys_last_error == '':
        try:
            con.restore(def_location_ori, def_location_dest, callback=fetchline)
            print('Sucesso ao restaurar de {} em {} para {}.'.format(con_host, def_location_ori, def_location_dest))
            result_value = True
        except Exception as e:
            sys_last_error = 'Falha ao restaurar de "{}" em "{}" para "{}": {}.'.format(con_host, def_location_ori,
                                                                                        def_location_dest, str(e))

        con.close()

    if sys_last_error != '':
        print(sys_last_error)

    return result_value


def fdb_count_connections(con_host='localhost', con_user='SYSDBA', con_password='masterkey', def_location_ori='',
                          def_location_dest=''):
    try:
        con = services.connect(host=con_host, user=con_user, password=con_password)
        result_value = con.get_connection_count()
        result_value = result_value - 1  # tenho que remover da conta a conexao que fiz acima
        con.close()
    except Exception as e:
        print('Falha ao acessar em {} para resgatar o numero de conexões ativas:\n{}.'.format(con_host, str(e)))
        result_value = 0
    return result_value


def fdb_set_machine_is_dev(con_dsn, con_user='SYSDBA', con_password='masterkey', set_password='masterkey',
                           result_value=False):
    sys_last_error = ''
    set_password = set_password.strip()
    print('Criando a conta *SYS_MACHINE_IS_DEV* para indicar que', con_dsn, 'é um host de desenvolvimento.')
    try:
        con = fdb.connect(dsn=con_dsn, user=con_user, password=con_password)
        cur = con.cursor()
        st = con.cursor()
        select = \
            "SELECT a.SEC$USER_NAME FROM SEC$USERS a\
             WHERE a.SEC$USER_NAME = 'SYS_MACHINE_IS_DEV' "
        cur.execute(select)
        cur.fetchone()
        if (cur.rowcount <= 0):
            sql_add_user = "CREATE USER SYS_MACHINE_IS_DEV PASSWORD '" + set_password + "';"
            st.execute(sql_add_user)
            print('Usuario SYS_MACHINE_IS_DEV foi criado com a senha', set_password, '.')
        else:
            sql_alter_user = "ALTER USER SYS_MACHINE_IS_DEV PASSWORD '" + set_password + "';"
            st.execute(sql_alter_user)
            print('Usuario SYS_MACHINE_IS_DEV ja existia e por isso não foi necessario criá-lo, apenas sua senha foi '
                  'atualizada.')
        con.commit()
        print('Sucesso com SYS_MACHINE_IS_DEV, indicando que esse banco de dados é para desenvolvimento.')
        result_value = True
        con.close()
    except Exception as e:
        sys_last_error = 'Falha ao criar/modificar a conta SYS_MACHINE_IS_DEV em {} com a senha {}:\n{}.'.format(con_dsn,
           set_password, str(e))
    if sys_last_error != '':
        print(sys_last_error)
    return result_value


def fdb_set_convidado(con_dsn, con_user='SYSDBA', con_password='masterkey', set_password='vidy',
                      result_value=False):
    sys_last_error = ''
    set_password = set_password.strip()
    print('Criando a conta *CONVIDADO* para queas funções internas não dependam do login do usuário.')
    try:
        con = fdb.connect(dsn=con_dsn, user=con_user, password=con_password)
        cur = con.cursor()
        st = con.cursor()
        select = \
            "SELECT a.SEC$USER_NAME FROM SEC$USERS a\
             WHERE a.SEC$USER_NAME = 'CONVIDADO' "
        cur.execute(select)
        cur.fetchone()
        if (cur.rowcount <= 0):
            sql_add_user = "CREATE USER CONVIDADO PASSWORD '" + set_password + "';"
            st.execute(sql_add_user)
            print('Usuario CONVIDADO foi criado com a senha', set_password, '.')
        else:
            sql_alter_user = "ALTER USER CONVIDADO PASSWORD '" + set_password + "';"
            st.execute(sql_alter_user)
            print(
                'Usuario CONVIDADO ja existia e por isso não foi necessario criá-lo, apenas sua senha foi atualizada.')
        con.commit()
        print('Sucesso com a conta CONVIDADO.')
        result_value = True
        con.close()
    except Exception as e:
        sys_last_error = 'Falha ao criar/modificar a conta CONVIDADO em {} com a senha {}:\n{}.'.format(con_dsn, set_password,
                                                                                             str(e))

    if sys_last_error != '':
        print(sys_last_error)
    return result_value


def fdb_reset_all_password(con_dsn, con_user='SYSDBA', con_password='masterkey', set_password='masterkey',
                           result_value=False):
    sys_last_error = ''
    set_password = set_password.strip()
    print('Modificando a senha de todos os usuarios em', con_dsn, 'para', set_password)
    try:
        con = fdb.connect(dsn=con_dsn, user=con_user, password=con_password)
        print('Conexoes estabelecidas com este servidor:')
        print(con.db_info(fdb.isc_info_user_names))
        cur = con.cursor()
        st = con.cursor()
        select = \
            'SELECT a.SEC$USER_NAME FROM SEC$USERS a\
             WHERE a.SEC$USER_NAME NOT IN(\
               SELECT SEC$USER_NAME FROM SEC$USERS\
               WHERE SEC$USER_NAME LIKE \'SYSDBA\') \
            AND a.SEC$USER_NAME NOT IN (\
               SELECT SEC$USER_NAME FROM SEC$USERS\
               WHERE SEC$USER_NAME LIKE \'RDB$%\')\
            AND a.SEC$USER_NAME NOT IN (\
               SELECT SEC$USER_NAME FROM SEC$USERS\
               WHERE SEC$USER_NAME LIKE \'CONVIDADO\')\
            AND a.SEC$USER_NAME NOT IN (\
              SELECT SEC$USER_NAME FROM SEC$USERS\
              WHERE SEC$USER_NAME LIKE \'SYS_%\')\
            AND a.SEC$USER_NAME NOT IN (\
              SELECT SEC$USER_NAME FROM SEC$USERS\
              WHERE SEC$USER_NAME LIKE \'REPL_%\')'
        cur.execute(select)
        records = cur.fetchall()
        for row in records:
            db_username = row[0].strip()
            sql_change_password = "ALTER USER " + db_username + " PASSWORD '" + set_password + "';"
            st.execute(sql_change_password)
            print('Usuario {} teve sua senha modificada para {}.'.format(db_username, set_password))
        con.commit()
        print('Sucesso ao modificar as senhas em {} para {}.'.format(con_dsn, set_password))
        result_value = True
        con.close()
    except Exception as e:
        sys_last_error = 'Falha ao modificar as senhas em {} para {}:\n{}.'.format(con_dsn, set_password, str(e))
    if sys_last_error != '':
        print(sys_last_error)
    return result_value


def fdb_execute_script(set_file, con_dsn, con_user='SYSDBA', con_password='masterkey', result_value=False):
    sys_last_error = ''
    set_file = set_file.strip()
    # fdb_execute_script(r'C:\Fontes\Vidy15\Source\_database\vidy15-scripts\manutencao\Glad_Custos_AsDev.sql', con_dsn)
    print('Executando o script {} em {}...'.format(set_file, con_dsn))
    try:
        con = fdb.connect(dsn=con_dsn, user=con_user, password=con_password)
        st = con.cursor()
        # Abre o arquivo inteiro de uma só vez
        fd = open(set_file, 'r')
        input_file = fd.read()
        fd.close()

        # Remove comentarios entre /* e */
        start = input_file.find('/*')
        if (start > 0):
            input_file = re.sub('(?<=\/\*)[\s\S]*?(?=\*\/)', '', input_file)
            # os comentarios ficaram assim /**/ e devem ser substituidos por vazio
            start = input_file.find('/**/')
            while (start > 0):
                input_file = input_file.replace('/**/', '')
                start = input_file.find('/**/')
            # limpa os espaços
            input_file = input_file.strip()
        # Quebra os comandos quando encontra ; (split on ';')
        sqlCommands = input_file.split(';')
        # Execute every command from the input file
        for command in sqlCommands:
            # vamos remover \n no final
            command = command.strip()
            command = command[::-1]
            command = command.replace('\n', '', 1)
            command = command[::-1]
            try:
                if (command != ''):
                    st.execute(command)
                    print('Sucesso ao executar a instrução:\n{}'.format(command))
            except Exception as e:
                print(str(e) + '\n', command)
        con.commit()
        print('Sucesso ao executar o script {} em {}.'.format(set_file, con_dsn))
        result_value = True
        con.close()
    except Exception as e:
        sys_last_error = 'Falha ao executar o script {} em {}:\n{}.'.format(set_file, con_dsn, str(e))
    if sys_last_error != '':
        print(sys_last_error)
    return result_value

def criar_reversao(def_location_ori, def_location_dest, result_value=False):
    print('Copiando arquivo de {} para {}.'.format(def_location_ori, def_location_dest))
    try:
        copyfile(def_location_ori, def_location_dest)
        print('Sucesso ao copiar arquivo de {} para {}.'.format(def_location_ori, def_location_dest))
        result_value = True
    except Exception as e:
        print('Falha ao copiar arquivo de {} para {}:\n{}.'.format(def_location_ori, def_location_dest, str(e)))

    return result_value


def restaurar_reversao(def_location_ori, def_location_dest, result_value=False):
    print('Revertendo arquivo de {} para {}...'.format(def_location_ori, def_location_dest))
    try:
        copyfile(def_location_ori, def_location_dest)
        print('Sucesso ao reverter arquivo de {} para {}.'.format(def_location_ori, def_location_dest))
        result_value = True
    except Exception as e:
        print('Falha ao reverter arquivo de {} para {}\n: {}'.format(def_location_ori, def_location_dest, str(e)))

    return result_value


def main():
    # esta seção do programa define variaives, pode mexer e ajustar as variaveis a vontade.
    # secao: variaives
    sys_last_error = ''

    # Parametro que indica a definição dos bancos de dados a serem restaurados para a area de desenvolvimento
    file_info = r'c:\\local\\onde\a\\lista\\sera\\salva\FDBReverter.inf'
    print('Lendo o arquivo de configuração: {}'.format(file_info))
    if (not Path(file_info).is_file()):
        sys_last_error = 'Arquivo de configuração não exisste: {}'.format(file_info)

    # Parametros que identificam a pasta onde estão os backups
    fbk_local_dir = r'c:\vidy15\backups'
    fbk_remote_dir = r'\\arca1\bak-firebird'
    fbk_backup_recent = ''

    # Parametros que identificam o desenvolvimento
    fdb_dev_host = ''
    fdb_dev_user = ''
    fdb_dev_password = ''

    # Parametros que identificam a producao
    fdb_prd_host = ''
    fdb_prd_user = ''
    fdb_prd_password = ''

    if sys_last_error != '':
        print(sys_last_error)
        quit()

    # boas vindas
    print('*' * 80)
    print("""A função deste programa é ajudar ao desenvolver que usa banco de dados a criar arquivos de reversão 
    reverter arquivos de banco de dados ou revertê-los. Para ser executado adequadamente este script precisa de 3 
    arquivos importantes:""")
    print("""
1. Local dos arquivos de backup do firebird, normalmente *.fbk 
2. Arquivo de banco de dados original, normalmente *.fdb 
3. Arquivo de banco de dados original acrescido de .reverso""")
    print("""Se nenhuma das opções acima for atendida, então este script não terá o que fazer. Mas quando uma delas for 
verdadeira, este script executará uma dessas opções:""")
    print("""Método 1: quando não existem os arquivo de dados e nem a reversao, nesse caso optará por restaurar o backup se este 
também existir.""")
    print("""Método 2: quando o arquivo de dados existe, mas a reversão não, então executa-se o procedimento de criar o arquivo de 
reversão usando o arquivo de dados como referencia. O arquivo original será mantido.""")
    print("""Método 3: quando o arquivo de dados e a reversao existem, nesse caso o procedimento será excluir o arquivo original e 
colocar o arquivo de reversão em seu lugar. O mesmo tambem acontece com o arquivo de dados não existe, mas a reversão existe.""")
    print(' ' * 80)

    #for fdb_prd_ori in fdb_prd_list:
    # Capiturando a senha que fica em arquivo externo
    fileIN = open(file_info, "r")
    line = fileIN.readline()
    while line:
        # dc01,sysdba,masterkey;c:\vidy15\dados\acad.fdb=localhost,sysdba,masterkey;c:\vidy15\dados\acad.fdb
        # pula as linhas comentadas ou vazias
        line = line.strip()
        while line[0] == '#' or line == '':
          line = fileIN.readline()

        list_param = line.split('=')

        try:
            line_param1 = list_param[0]
            line_param2 = list_param[1]
            if line_param1 != '' and line_param1 != '':
                list_param_prd = line_param1.split(';')
                fdb_prd_host = list_param_prd[0].strip()
                fdb_prd_user = list_param_prd[1].strip()
                #fdb_prd_password = list_param_prd[2].strip()
                fdb_prd_ori = list_param_prd[2].strip()
                list_param_dev = line_param2.split(';')
                fdb_dev_host = list_param_dev[0].strip()
                fdb_dev_user = list_param_dev[1].strip()
                #fdb_dev_password = list_param_dev[2].strip()
                fdb_dev_ori = list_param_dev[2].strip()
                fbk_backup_recent_prefixo = os.path.basename(fdb_prd_ori).strip()
                fbk_backup_recent_prefixo = os.path.splitext(fbk_backup_recent_prefixo)[0].strip()

        except Exception as e:
            sys_last_error = str(e)

        if (sys_last_error == '') and (fdb_prd_host == '' or fdb_prd_user == ''):
            sys_last_error = '[origem=] Nao encontrei o parametro de host ou user_name na linha: {}'.format(line)

        if (sys_last_error == '') and (fdb_dev_host == '' or fdb_dev_user == ''):
            sys_last_error = '[=destino] Nao encontrei o parametro de host ou user_name na linha: {}'.format(line)

        # testando as senhas previamente gravadas, se falharem entao pergunta a senha correta
        host_and_user = fdb_prd_user+'@'+fdb_prd_host
        fdb_prd_password = try_connect_and_write_password(host_and_user)
        if (sys_last_error == '') and (fdb_prd_password == ''):
            sys_last_error = 'Falha de conexão usando {}.'.format(host_and_user)

        host_and_user = fdb_dev_user + '@' + fdb_dev_host
        fdb_dev_password = try_connect_and_write_password(host_and_user)
        if (sys_last_error == '') and (fdb_dev_password == ''):
            sys_last_error = 'Falha de conexão usando {}.'.format(host_and_user)

        if sys_last_error != '':
            file_info_error(file_info, sys_last_error)

        fdb_dev_rev = fdb_dev_ori + '.reverter'
        fdb_dev_dsn = fdb_dev_host + ':' + fdb_dev_ori
        res = False
        do_criar_reversao = False

        procedimento = 0  # 0 = nao permitirá prosseguir
        if sys_last_error == '':
            # detectando método procedimento=1 é quando não existe o arquivo de dados e nem a reversao existem, nesse caso
            # deve restaurar o backup se este também existir
            if (not Path(fdb_dev_ori).is_file()) and (not Path(fdb_dev_rev).is_file()):
                procedimento = 1
            # procedimento=2 é quando o arquivo de dados existe, mas a reversão não, então cria-se a reversão
            if (Path(fdb_dev_ori).is_file()) and (not Path(fdb_dev_rev).is_file()):
                procedimento = 2
            # procedimento=3 é quando o arquivo de dados e a reversao existem, nesse caso é reverter
            if (Path(fdb_dev_ori).is_file()) and (Path(fdb_dev_rev).is_file()):
                procedimento = 3
            if (not Path(fdb_dev_ori).is_file()) and (Path(fdb_dev_rev).is_file()):
                procedimento = 3

            # resummo
            print('*' * 80)
            print('Origem: {}@{}\\{} Senha:{}'.format(fdb_prd_host, fdb_prd_user, fdb_prd_ori, '*' * len(fdb_prd_password)))
            print(
                'Destino: {}@{}\\{} Senha:{}'.format(fdb_dev_host, fdb_dev_user, fdb_dev_ori, '*' * len(fdb_dev_password)))
            print('Reversão: {}@{}\\{} '.format(fdb_dev_host, fdb_dev_user, fdb_dev_rev))
            print('Dados do ambiente de desenvolvimento:')
            print('{:>25}\n\t{}'.format('Pasta onde fica os backups remotos:', fbk_remote_dir))
            print('{:>25}\n\t{}'.format('Arquivo de backup remoto  mais recente', fbk_backup_recent))
            print('{:>25}{}'.format('Procedimento escolhido: Método #', procedimento))
            print('*' * 80)
            sleep(3)


            if (sys_last_error == '') and (procedimento == 1):
                # a restauracao só é possivel do diretorio local, entao vamos copiar do diretorio remoto para o novo, mas
                #   apenas se este for mais recente do que eu já tenho no diretorio local
                if '' != fbk_backup_recent_prefixo:
                    fbk_backup_recent = find_backup_recent(fbk_remote_dir, fbk_backup_recent_prefixo + '-*.fbk')
                    if '' == fbk_backup_recent:
                        sys_last_error = 'Arquivo de backup não foi encontrado em {} com o prefixo {}.'.format(
                            fbk_remote_dir, fbk_backup_recent_prefixo)
                    if not Path(fbk_backup_recent).is_file():
                        sys_last_error = 'Arquivo de backup não foi encontrado em {}'.format(fbk_backup_recent)

                fbk_local_file = fbk_local_dir + '\\' + os.path.basename(fbk_backup_recent)

                if (not os.path.exists(fbk_local_file)) or (
                        os.stat(fbk_backup_recent).st_mtime - os.stat(fbk_local_file).st_mtime > 1):
                    print('Copiando o arquivo mais recente em {} para {}...'.format(fbk_backup_recent, fbk_local_file),
                          end=' ')
                    try:
                        copyfile(fbk_backup_recent, fbk_local_file)
                        print('[sucesso]')
                    except Exception as e:
                        sys_last_error = '[falha]\nFalha ao copíar arquivo de {} para {}\n: {}'.format(fbk_backup_recent,
                                                                                                       fbk_local_file,
                                                                                                       str(e))

                if sys_last_error == '':
                    res = backup_restaurar(con_host=fdb_dev_host, con_user=fdb_dev_user, con_password=fdb_dev_password,
                                           def_location_ori=fbk_local_file, def_location_dest=fdb_dev_ori)
                    if res:
                        do_criar_reversao = True

            if (sys_last_error == '') and (procedimento == 2):
                do_criar_reversao = True

            if (sys_last_error == '') and (procedimento == 3):
                connections = fdb_count_connections(fdb_dev_host)
                if connections > 0:
                    sys_last_error = 'Não posso reverter porque há {} conexoes ao {}'.format(connections, fdb_dev_dsn)
                else:
                    res = restaurar_reversao(fdb_dev_rev, fdb_dev_ori)
                    if res:
                        print('Foi restaurada a reversao de {} como {}'.format(fdb_dev_rev, fdb_dev_ori))

            if procedimento == 0:
                sys_last_error = 'Devido a erros não posso prosseguir.'

            if (sys_last_error == '') and (do_criar_reversao):
                connections = fdb_count_connections(fdb_dev_host)
                if connections > 0:
                    sys_last_error = 'Não posso criar a reversão porque há {} conexões ao {}'.format(connections,
                                                                                                     fdb_dev_dsn)
                else:
                    res = criar_reversao(fdb_dev_ori, fdb_dev_rev)
                    if res:
                        print('Foi criada a reversao a partir de {} como {}'.format(fdb_dev_ori, fdb_dev_rev))

            if res:
                res = fdb_reset_all_password(con_dsn=fdb_dev_dsn)
                if res:
                    res = fdb_set_machine_is_dev(con_dsn=fdb_dev_dsn)
                    if res:
                        res: bool = fdb_set_convidado(con_dsn=fdb_dev_dsn)
                        if res:
                            res = fdb_execute_script(
                                r'C:\Fontes\Vidy15\Source\_database\vidy15-scripts\manutencao\Glad_Custos_AsDev.sql', \
                                con_dsn=fdb_dev_dsn)
            if '' != sys_last_error:
                print(sys_last_error)
        line = fileIN.readline()
    print('fim do procedimento')

#
# Inicio de tudo
#
main()
print('Processo concluído.\nPreessione [ENTER] para fechar este script.')
sleep(3)
