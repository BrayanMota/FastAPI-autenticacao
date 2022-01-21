from autenticacao import schemas, models, security

from fastapi import HTTPException, status

import json


def mostrar_usuarios():
    """Método de consulta na banco e trás todos os usuários

    Returns
    -------
    JSON
        Retorna todos os usuários
    """
    lista_usuarios = json.loads(models.Usuario.objects().to_json())
    
    usuarios = []
    for usuario in lista_usuarios:
        lista_grupos = usuario['grupos']
        
        grupos = []
        permissoes = []
        for grupo_id in lista_grupos:
            
            grupo = json.loads(models.Grupo.objects(id__exact=grupo_id['$oid']).first().to_json())
            grupos.append(grupo)
            
            lista_permissoes = grupo['permissoes']
            
            #Verificando as permissões dos grupos daquele usuário
            for permissao_id in lista_permissoes:
                permissao = json.loads(models.Permissao.objects(id__exact=permissao_id['$oid']).first().to_json())
                permissoes.append(permissao)
        
        #Verificando as permissões próprias do usuário
        try:
            for permissao_id in usuario['permissoes']:
                permissao = json.loads(models.Permissao.objects(id__exact=permissao_id['$oid']).first().to_json())
                permissoes.append(permissao)
        except:
            pass
        
        lista_auxiliar = [usuario, grupos, permissoes]
        usuarios.append(lista_auxiliar)
        
    return usuarios


def mostrar_usuario(busca: str):
    """Método de consulta no banco e trás o usuário buscado

    Parameters
    ----------
    busca : str
        Nome do usuário passado por parâmetro pelo endpoint

    Returns
    -------
    JSON
        Retorna um usuário
    """
    try:
        usuario = json.loads(models.Usuario.objects(nome_usuario__exact=busca).first().to_json())
        lista_grupos = usuario['grupos']
        
        grupos = []
        permissoes = []
        for grupo_id in lista_grupos:
            
            grupo = json.loads(models.Grupo.objects(id__exact=grupo_id['$oid']).first().to_json())
            grupos.append(grupo)
            
            lista_permissoes = grupo['permissoes']
            
            #Verificando as permissões dos grupos daquele usuário
            for permissao_id in lista_permissoes:
                permissao = json.loads(models.Permissao.objects(id__exact=permissao_id['$oid']).first().to_json())
                permissoes.append(permissao)
        
        #Verificando as permissões próprias do usuário
        try:
            for permissao_id in usuario['permissoes']:
                permissao = json.loads(models.Permissao.objects(id__exact=permissao_id['$oid']).first().to_json())
                permissoes.append(permissao)
        except:
            pass
        
        lista_usuario = [usuario, grupos, permissoes]
        
        return lista_usuario
    except:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="Usuário não encontrado")


def mostrar_grupos_usuario(busca: str):
    """Método de consulta no banco e trás os grupos do usuário buscado

    Parameters
    ----------
    busca : str
        Nome do usuário passado por parâmetro pelo endpoint

    Returns
    -------
    JSON
        Retorna os grupos do usuário
    """
    try:
        permissoes = []
        grupos = []
        usuario = json.loads(models.Usuario.objects(nome_usuario__exact=busca).first().to_json())
        lista_grupos = usuario['grupos']
        
        for grupo_id in lista_grupos:
            
            grupo = json.loads(models.Grupo.objects(id__exact=grupo_id['$oid']).first().to_json())
            grupos.append(grupo)
            
            lista_permissoes = grupo['permissoes']
            
            #Verificando as permissões dos grupos daquele usuário
            for permissao_id in lista_permissoes:
                permissao = json.loads(models.Permissao.objects(id__exact=permissao_id['$oid']).first().to_json())
                permissoes.append(permissao)

        lista_usuario = [grupos, permissoes]
        
        return lista_usuario
    except:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="Usuário não encontrado")


def mostrar_permissoes_usuario(busca: str):
    """Método de consulta no banco e trás as permissões do usuário buscado

    Parameters
    ----------
    busca : str
        Nome do usuário passado por parâmetro pelo endpoint

    Returns
    -------
    JSON
        Retorna as permissões do usuário
    """
    try:
        permissoes = []
        
        usuario = json.loads(models.Usuario.objects(nome_usuario__exact=busca).first().to_json())
        lista_grupos = usuario['grupos']
        
        for grupo_id in lista_grupos:    
            grupo = json.loads(models.Grupo.objects(id__exact=grupo_id['$oid']).first().to_json())
            
            lista_permissoes = grupo['permissoes']
            
            #Verificando as permissões dos grupos daquele usuário
            for permissao_id in lista_permissoes:
                permissao = json.loads(models.Permissao.objects(id__exact=permissao_id['$oid']).first().to_json())
                permissoes.append(permissao)
        
        #Verificando as permissões próprias do usuário
        for permissao_id in usuario['permissoes']:
            permissao = json.loads(models.Permissao.objects(id__exact=permissao_id['$oid']).first().to_json())
            permissoes.append(permissao)
        
        return permissoes
    except:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="Usuário não encontrado")


def criar_usuario(usuario: schemas.CriarUsuario):
    """Método de criação de usuário

    Parameters
    ----------
    usuario : schemas.CriarUsuario
        O parâmetro recebe os schemas de CriarUsuario com todos os campos informados no endpoint para cadastrar no banco

    Returns
    -------
    JSON
        Retorna um schema dos dados salvos
    """
    hashed_senha = security.gerar_senha_hash(usuario.senha)
    return models.Usuario(nome_usuario=usuario.nome_usuario, ativo=usuario.ativo, senha=hashed_senha).save()


def editar_usuario(busca: str, usuario: schemas.CriarUsuario):
    """Método de edição de usuário

    Parameters
    ----------
    busca : str
        Nome do usuário passado por parâmetro pelo endpoint
    usuario : schemas.CriarUsuario
        O parâmetro recebe os schemas de CriarUsuario com todos os campos informados no endpoint para atualizar no banco

    Returns
    -------
    str
        Retorna uma mensagem de confirmação de edição
    """
    if models.Usuario.objects(nome_usuario__exact=busca).first():
        hashed_senha = security.gerar_senha_hash(usuario.senha)
        models.Usuario.objects(nome_usuario__exact=busca).first().update(nome_usuario=usuario.nome_usuario, ativo=usuario.ativo, senha=hashed_senha)
        raise HTTPException(status_code=status.HTTP_200_OK,
                                detail="Usuário atualizado")
    else:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="Usuário não encontrado")


def deletar_usuario(busca: str):
    """Método de exclusão de usuário

    Parameters
    ----------
    busca : str
        Nome do usuário passado por parâmetro pelo endpoint

    Returns
    -------
    str
        Retorna uma mensagem de confirmação de exclusão
    """
    if models.Usuario.objects(nome_usuario__exact=busca).first():
        models.Usuario.objects(nome_usuario__exact=busca).first().delete()
        raise HTTPException(status_code=status.HTTP_200_OK,
                                detail="Usuário deletado")
    else:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="Usuário não encontrado")


def criar_usuario_grupos(usuario_grupos: schemas.CriarUsuarioGrupos):
    """Método para relacionar um usuário a um grupo

    Parameters
    ----------
    usuario_grupos : schemas.CriarUsuarioGrupos
        O parâmetro recebe os schemas de CriarUsuarioGrupos com todos os campos informados no endpoint criar o relaciomento no banco

    Returns
    -------
    str
        Retorna um schema dos dados salvos
    """
    db_usuario = models.Usuario.objects(nome_usuario__exact=usuario_grupos.nome_usuario).first()
    db_grupo = models.Grupo.objects(grupo__exact=usuario_grupos.grupo).first()
    
    if db_usuario and db_grupo:
        models.Usuario.objects(nome_usuario__exact=usuario_grupos.nome_usuario).first().update(push__grupos=db_grupo)
        return usuario_grupos
    
    raise HTTPException(status_code=404, detail="Usuário ou grupo informado não consta no sistema")


def criar_usuario_permissoes(usuario_permissoes: schemas.CriarUsuarioPermissoes):
    """Método para relacionar um usuário a uma permissão

    Parameters
    ----------
    usuario_permissoes : schemas.CriarUsuarioPermissoes
        O parâmetro recebe os schemas de CriarUsuarioPermissoes com todos os campos informados no endpoint criar o relaciomento no banco

    Returns
    -------
    str
        Retorna um schema dos dados salvos
    """
    db_usuario = models.Usuario.objects(nome_usuario__exact=usuario_permissoes.nome_usuario).first()
    db_permissao = models.Permissao.objects(permissao__exact=usuario_permissoes.permissao).first()
    
    if db_usuario and db_permissao:
        models.Usuario.objects(nome_usuario__exact=usuario_permissoes.nome_usuario).first().update(push__permissoes=db_permissao)
        return usuario_permissoes
    
    raise HTTPException(status_code=404, detail="Usuário ou permissao informado não consta no sistema")


def mostrar_grupos():
    """Método de consulta de grupos.

    Returns
    -------
    JSON
        Retorna todos os grupos.
    """
    return json.loads(models.Grupo.objects().to_json())        


def mostrar_grupo(busca: str):
    """Método de consulta de um grupo.

    Parameters
    ----------
    busca : str
        Nome do grupo passado por parâmetro pelo endpoint.

    Returns
    -------
    JSON
        Retorna apenas um grupo.
    """
    try:
        return json.loads(models.Grupo.objects(grupo__exact=busca).first().to_json())
    except:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="Grupo não encontrado")


def criar_grupo(grupo: schemas.CriarGrupo):
    """Método de cadastro de grupo

    Parameters
    ----------
    grupo : schemas.CriarGrupo
        O parâmetro recebe os schemas de CriarGrupo com todos os campos informados no endpoint para salvar no banco

    Returns
    -------
    str
        Retorna um schema com os dados salvos
    """
    return models.Grupo(**grupo.dict()).save()


def editar_grupo(busca: str, grupo: schemas.CriarGrupo):
    """Método de edição de grupo

    Parameters
    ----------
    busca : str
        Nome do usuário passado por parâmetro pelo endpoint
    grupo : schemas.CriarGrupo
        O parâmetro recebe os schemas de CriarGrupo com todos os campos informados no endpoint para atualizar no banco

    Returns
    -------
    str
        Retorna uma mensagem de confirmação de edição
    """
    if models.Grupo.objects(grupo__exact=busca).first():
        models.Grupo.objects(grupo__exact=busca).first().update(**grupo.dict())
        raise HTTPException(status_code=status.HTTP_200_OK,
                                detail="Grupo atualizado")
    else:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="Grupo não encontrado")


def deletar_grupo(busca: str):
    """Método de exclusão de grupo

    Parameters
    ----------
    busca : str
        Nome do usuário passado por parâmetro pelo endpoint

    Returns
    -------
    str
        Retorna uma mensagem de confirmação de exclusão
    """
    if models.Grupo.objects(grupo__exact=busca).first():
        models.Grupo.objects(grupo__exact=busca).first().delete()
        raise HTTPException(status_code=status.HTTP_200_OK,
                                detail="Grupo deletado")
    else:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="Grupo não encontrado")


def criar_grupo_permissoes(grupo_permissoes: schemas.CriarGrupoPermissoes):
    """Método para relacionar um grupo a uma permissão

    Parameters
    ----------
    grupo_permissoes : schemas.CriarGrupoPermissoes
        O parâmetro recebe os schemas de CriarGrupoPermissoes com todos os campos informados no endpoint criar o relaciomento no banco

    Returns
    -------
    str
        Retorna um schema dos dados salvos
    """
    db_grupo = models.Grupo.objects(grupo__exact=grupo_permissoes.grupo).first()
    db_permissao = models.Permissao.objects(permissao__exact=grupo_permissoes.permissao).first()
    
    if db_permissao and db_grupo:
        models.Grupo.objects(grupo__exact=grupo_permissoes.grupo).first().update(push__permissoes=db_permissao)
        return grupo_permissoes
    
    raise HTTPException(status_code=404, detail="Grupo ou permissão informado não consta no sistema")


def mostrar_permissoes():
    """Método de consulta no banco de todas as permissões

    Returns
    -------
    str
        Retorna todas as permissões
    """
    return json.loads(models.Permissao.objects().to_json())


def mostrar_permissao(busca: str):
    """Método de consulta no banco de uma permissão

    Parameters
    ----------
    busca : str
        Nome da permissão passado por parâmetro pelo endpoint

    Returns
    -------
    str
        Retorna uma permissão
    """
    try:
        return json.loads(models.Permissao.objects(permissao__exact=busca).first().to_json())
    except:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="Permissão não encontrada")


def criar_permissao(permissao: schemas.CriarPermissao):
    """Método de crição de permissão

    Parameters
    ----------
    grupo : schemas.CriarPermissao
        O parâmetro recebe os schemas de CriarPermissao com todos os campos informados no endpoint para salvar no banco

    Returns
    -------
    str
        Retorna um schema dos dados salvos
    """
    return models.Permissao(**permissao.dict()).save()


def editar_permissao(busca: str, permissao: schemas.CriarPermissao):
    """Método de edição de permissao

    Parameters
    ----------
    busca : str
        Nome da permissao passada por parâmetro pelo endpoint
    permissao : schemas.CriarPermissao
        O parâmetro recebe os schemas de CriarPermissao com todos os campos informados no endpoint para atualizar no banco

    Returns
    -------
    str
        Retorna uma mensagem de confirmação de edição
    """
    if models.Permissao.objects(permissao__exact=busca).first():
        models.Permissao.objects(permissao__exact=busca).first().update(**permissao.dict())
        raise HTTPException(status_code=status.HTTP_200_OK,
                                detail="Permissão atualizada")
    else:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="Permissão não encontrada")


def deletar_permissao(busca: str):
    """Método de exclusão de permissão

    Parameters
    ----------
    busca : str
        Nome do usuário passado por parâmetro pelo endpoint
    
    Returns
    -------
    str
        Retorna uma mensagem de confirmação de exclusão
    """
    if models.Permissao.objects(permissao__exact=busca).first():
        models.Permissao.objects(permissao__exact=busca).first().delete()
        raise HTTPException(status_code=status.HTTP_200_OK,
                                detail="Permissão deletada")
    else:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="Permissão não encontrada")
