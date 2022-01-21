from typing import List
from datetime import timedelta

from autenticacao import schemas, models, security, cruds

from fastapi import Depends, APIRouter, status
from fastapi.exceptions import HTTPException
from fastapi.security.oauth2 import OAuth2PasswordRequestForm
from fastapi.param_functions import Security


router_autenticacao = APIRouter(tags=['Autenticação'])


@router_autenticacao.post("/v1/autenticacao")
async def autenticacao(usuario: OAuth2PasswordRequestForm = Depends()):
    """Método de login usado pelo protocolo de autenticação oauth2_scheme

    Parameters
    ----------
    usuario : OAuth2PasswordRequestForm
        O parâmetro usa a classe do fastapi que gera uma modal de autenticação, fazendo uma verificação de login. O Depends indica que esse parãmetro deve ser
        atendido primeiro para a continuação do método

    Returns
    -------
    JSON
        O retorno trará um dicionário com o token criado ao usuário se autenticar
    """
    
    login = models.Usuario.objects(nome_usuario__exact=usuario.username).first()
    
    if not login:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND ,detail='Usuário inválido')
    
    if not security.verificar_senha(login.senha, usuario.password):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND ,detail='Senha inválida')
    
    if not login.ativo:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Usuário inativo')
    
    tempo_expiracao_token = timedelta(minutes=security.ACCESS_TOKEN_EXPIRE_MINUTES)
    token = security.criar_token_acesso(data={"sub": login.nome_usuario}, expires_delta=tempo_expiracao_token)

    return {"access_token": token, "token_type": "bearer"}


router_usuario = APIRouter(tags=['Usuário'])


@router_usuario.get('/v1/usuario')
async def mostrar_usuarios(current_user: schemas.UsuarioBase = Security(security.get_usuario_atual, scopes=[])):
    """Endpoint que mostra todos os usuários

    Parameters
    ----------
    current_user : schemas.UsuarioBase
        O parâmetro usa a subclasse Security do Depends, que aceita um parãmetro a mais que é o scopes.
        Dentro da subclasse Security, o parâmetro vai chamar um método para verificar as permissões e o usuário.
        O scopes determina quais permissões o usuário deve ter para pode acessar esse endpoint

    Returns
    -------
    JSON
        O retorno trás o resultado do método mostrar_usuarios()
    """
    return cruds.mostrar_usuarios()


@router_usuario.get('/v1/usuario/{nome}')
def mostrar_usuario(nome: str, current_user: schemas.UsuarioBase = Security(security.get_usuario_atual, scopes=[])):
    """Endpoint que mostra apenas um usuário

    Parameters
    ----------
    nome : str
        O parâmetro recebe o nome do usuário e passa para o método que ira fazer as validações
    current_user : schemas.UsuarioBase
        [O parâmetro usa a subclasse Security do Depends, que aceita um parãmetro a mais que é o scopes.
        Dentro da subclasse Security, o parâmetro vai chamar um método para verificar as permissões e o usuário.
        O scopes determina quais permissões o usuário deve ter para pode acessar esse endpoint

    Returns
    -------
    JSON
        O retorno trás o resultado do método mostrar_usuario()
    """
    return cruds.mostrar_usuario(nome)


@router_usuario.get('/v1/usuario/{nome}/grupos')
def mostrar_grupos_usuario(nome: str, current_user: schemas.UsuarioBase = Security(security.get_usuario_atual, scopes=[])):
    """Endpoint que mostra todos os grupos de apenas um usuário

    Parameters
    ----------
    nome : str
        O parâmetro recebe o nome do usuário e passa para o método que ira fazer as validações
    current_user : schemas.UsuarioBase
        O parâmetro usa a subclasse Security do Depends, que aceita um parãmetro a mais que é o scopes.
        Dentro da subclasse Security, o parâmetro vai chamar um método para verificar as permissões e o usuário.
        O scopes determina quais permissões o usuário deve ter para pode acessar esse endpoint

    Returns
    -------
    JSON
        O retorno trás o resultado do método mostrar_grupos_usuario()
    """
    return cruds.mostrar_grupos_usuario(nome)


@router_usuario.get('/v1/usuario/{nome}/permissoes')
def mostrar_permissoes_usuario(nome: str, current_user: schemas.UsuarioBase = Security(security.get_usuario_atual, scopes=[])):
    """Endpoint que mostra todas as permissões de apenas um usuário

    Parameters
    ----------
    nome : str
        O parâmetro recebe o nome do usuário e passa para o método que ira fazer as validações
    current_user : schemas.UsuarioBase
        O parâmetro usa a subclasse Security do Depends, que aceita um parãmetro a mais que é o scopes.
        Dentro da subclasse Security, o parâmetro vai chamar um método para verificar as permissões e o usuário.
        O scopes determina quais permissões o usuário deve ter para pode acessar esse endpoint

    Returns
    -------
    JSON
        O retorno trás o resultado do método mostrar_permissao_usuario()
    """
    return cruds.mostrar_permissoes_usuario(nome)


@router_usuario.post('/v1/usuario', response_model=schemas.UsuarioBase)
# def criar_usuario(modelo: schemas.CriarUsuario, current_user: schemas.UsuarioBase = Security(security.get_usuario_atual, scopes=[])):
def criar_usuario(modelo: schemas.CriarUsuario):
    """Endpoint que cria um usuário

    Parameters
    ----------
    modelo : schemas.CriarUsuario
        O parâmetro recebe os schemas de CriarUsuario com todos os campos necessários para realizar o cadastro
        e passa para o método que ira fazer o cadastro
    current_user : schemas.UsuarioBase
        O parâmetro usa a subclasse Security do Depends, que aceita um parãmetro a mais que é o scopes.
        Dentro da subclasse Security, o parâmetro vai chamar um método para verificar as permissões e o usuário.
        O scopes determina quais permissões o usuário deve ter para pode acessar esse endpoint

    Returns
    -------
    JSON
        O retorno trás o resultado do método criar_usuario()
    """
    return cruds.criar_usuario(modelo)


@router_usuario.put('/v1/usuario/{nome}')
def editar_usuario(nome: str, modelo: schemas.CriarUsuario, current_user: schemas.UsuarioBase = Security(security.get_usuario_atual, scopes=[])):
    """Endpoint que edita um usuário

    Parameters
    ----------
    nome : str
        O parâmetro recebe o nome do usuário e passa para o método que ira fazer as validações
    modelo : schemas.CriarUsuario
        O parâmetro recebe os schemas de CriarUsuario com todos os campos necessários para realizar a edição
        e passa para o método que ira fazer a atualização
    current_user : schemas.UsuarioBase
        O parâmetro usa a subclasse Security do Depends, que aceita um parãmetro a mais que é o scopes.
        Dentro da subclasse Security, o parâmetro vai chamar um método para verificar as permissões e o usuário.
        O scopes determina quais permissões o usuário deve ter para pode acessar esse endpoint

    Returns
    -------
    JSON
        O retorno trás o resultado do método editar_usuario()
    """
    return cruds.editar_usuario(nome, modelo)


@router_usuario.delete('/v1/usuario/{nome}')
def deletar_usuario(nome: str, current_user: schemas.UsuarioBase = Security(security.get_usuario_atual, scopes=[])):
    """Endpoint que exclui um usuário

    Parameters
    ----------
    nome : str
        O parâmetro recebe o nome do usuário e passa para o método que ira fazer as validações
    current_user : schemas.UsuarioBase
        O parâmetro usa a subclasse Security do Depends, que aceita um parãmetro a mais que é o scopes.
        Dentro da subclasse Security, o parâmetro vai chamar um método para verificar as permissões e o usuário.
        O scopes determina quais permissões o usuário deve ter para pode acessar esse endpoint

    Returns
    -------
    JSON
        O retorno trás o resultado do método deletar_usuario()
    """
    return cruds.deletar_usuario(nome)


router_usuarios_grupos = APIRouter(tags=['Usuários e Grupos'])


@router_usuarios_grupos.post('/v1/usuario_grupos', response_model=schemas.CriarUsuarioGrupos)
def criar_usuario_grupos(modelo: schemas.CriarUsuarioGrupos, current_user: schemas.UsuarioBase = Security(security.get_usuario_atual, scopes=[])):
    """Endpoint que relaciona um grupo a um usuário

    Parameters
    ----------
    modelo : schemas.CriarUsuarioGrupos
        O parâmetro recebe os schemas de CriarUsuarioGrupos com todos os campos necessários para realizar o relaciomento
        e passa para o método que ira fazer o cadastro
    current_user : schemas.UsuarioBase
        O parâmetro usa a subclasse Security do Depends, que aceita um parãmetro a mais que é o scopes.
        Dentro da subclasse Security, o parâmetro vai chamar um método para verificar as permissões e o usuário.
        O scopes determina quais permissões o usuário deve ter para pode acessar esse endpoint

    Returns
    -------
    JSON
        O retorno trás o resultado do método criar_usuario_grupos()
    """
    return cruds.criar_usuario_grupos(modelo)


router_usuarios_permissoes = APIRouter(tags=['Usuários e Permissões'])


@router_usuarios_permissoes.post('/v1/usuario_permissoes', response_model=schemas.CriarUsuarioPermissoes)
def criar_usuario_permissoes(modelo: schemas.CriarUsuarioPermissoes, current_user: schemas.UsuarioBase = Security(security.get_usuario_atual, scopes=[])):
    """Endpoint que relaciona uma permissão a um usuário
    
    Parameters
    ----------
    modelo : schemas.CriarUsuarioPermissoes
        O parâmetro recebe os schemas de CriarUsuarioPermissoes com todos os campos necessários para realizar o relaciomento
        e passa para o método que ira fazer o cadastro
    current_user : schemas.UsuarioBase
        O parâmetro usa a subclasse Security do Depends, que aceita um parãmetro a mais que é o scopes.
        Dentro da subclasse Security, o parâmetro vai chamar um método para verificar as permissões e o usuário.
        O scopes determina quais permissões o usuário deve ter para pode acessar esse endpoint

    Returns
    -------
    JSON
        O retorno trás o resultado do método criar_usuario_permissoes()
    """
    return cruds.criar_usuario_permissoes(modelo)


router_grupo = APIRouter(tags=['Grupo'])


@router_grupo.get('/v1/grupo')
def mostrar_grupos(current_user: schemas.UsuarioBase = Security(security.get_usuario_atual, scopes=[])):
    """Endpoint que mostra todos os grupos

    Parameters
    ----------
    current_user : schemas.UsuarioBase
        O parâmetro usa a subclasse Security do Depends, que aceita um parãmetro a mais que é o scopes.
        Dentro da subclasse Security, o parâmetro vai chamar um método para verificar as permissões e o usuário.
        O scopes determina quais permissões o usuário deve ter para pode acessar esse endpoint

    Returns
    -------
    JSON
        O retorno trás o retorno do método mostrar_grupos)
    """
    return cruds.mostrar_grupos()


@router_grupo.get('/v1/grupo/{grupo}')
def mostrar_grupo(grupo: str, current_user: schemas.UsuarioBase = Security(security.get_usuario_atual, scopes=[])):
    """Endpoint que mostra apenas um grupo

    Parameters
    ----------
    grupo : str
        O parâmetro recebe o nome do grupo e passa para o método que ira fazer as validações
    current_user : schemas.UsuarioBase
        O parâmetro usa a subclasse Security do Depends, que aceita um parãmetro a mais que é o scopes.
        Dentro da subclasse Security, o parâmetro vai chamar um método para verificar as permissões e o usuário.
        O scopes determina quais permissões o usuário deve ter para pode acessar esse endpoint

    Returns
    -------
    JSON
        O retorno trás o resultado do método mostrar_grupo()
    """
    return cruds.mostrar_grupo(grupo)


@router_grupo.post('/v1/grupo', response_model=schemas.GrupoBase)
def criar_grupo(modelo: schemas.CriarGrupo, current_user: schemas.UsuarioBase = Security(security.get_usuario_atual, scopes=[])):
    """Endpoint que cria um grupo

    Parameters
    ----------
    modelo : schemas.CriarGrupo
        O parâmetro recebe os schemas de CriarGrupo com todos os campos necessários para realizar o cadastro
        e passa para o método que ira fazer o cadastro
    current_user : schemas.UsuarioBase
        O parâmetro usa a subclasse Security do Depends, que aceita um parãmetro a mais que é o scopes.
        Dentro da subclasse Security, o parâmetro vai chamar um método para verificar as permissões e o usuário.
        O scopes determina quais permissões o usuário deve ter para pode acessar esse endpoint

    Returns
    -------
    JSON
        O retorno trás o resultado do método criar_grupo()
    """
    return cruds.criar_grupo(modelo)


@router_grupo.put('/v1/grupo/{grupo}')
def editar_grupo(grupo: str, modelo: schemas.CriarGrupo, current_user: schemas.UsuarioBase = Security(security.get_usuario_atual, scopes=[])):
    """Endpoint que edita um grupo

    Parameters
    ----------
    grupo : str
        O parâmetro recebe o nome do grupo e passa para o método que ira fazer as validações
    modelo : schemas.CriarGrupo
        O parâmetro recebe os schemas de CriarGrupo com todos os campos necessários para realizar a edição
        e passa para o método que ira fazer a atualização
    current_user : schemas.UsuarioBase
        O parâmetro usa a subclasse Security do Depends, que aceita um parãmetro a mais que é o scopes.
        Dentro da subclasse Security, o parâmetro vai chamar um método para verificar as permissões e o usuário.
        O scopes determina quais permissões o usuário deve ter para pode acessar esse endpoint

    Returns
    -------
    JSON
        O retorno trás o resultado do método editar_grupo()
    """
    return cruds.editar_grupo(grupo, modelo)


@router_grupo.delete('/v1/grupo/{grupo}')
def deletar_grupo(grupo: str, current_user: schemas.UsuarioBase = Security(security.get_usuario_atual, scopes=[])):
    """Endpoint que exclui um grupo

    Parameters
    ----------
    nome : str
        O parâmetro recebe o nome do grupo e passa para o método que ira fazer as validações
    current_user : schemas.UsuarioBase
        O parâmetro usa a subclasse Security do Depends, que aceita um parãmetro a mais que é o scopes.
        Dentro da subclasse Security, o parâmetro vai chamar um método para verificar as permissões e o usuário.
        O scopes determina quais permissões o usuário deve ter para pode acessar esse endpoint

    Returns
    -------
    JSON
        O retorno trás o resultado do método deletar_grupo()
    """
    return cruds.deletar_grupo(grupo)


router_grupos_permissoes = APIRouter(tags=['Grupos e Permissões'])


@router_grupos_permissoes.post('/v1/grupo_permissoes/', response_model=schemas.CriarGrupoPermissoes)
def criar_grupo_permissoes(modelo: schemas.CriarGrupoPermissoes, current_user: schemas.UsuarioBase = Security(security.get_usuario_atual, scopes=[])):
    """Endpoint que relaciona um grupo a uma permissão

    Parameters
    ----------
    modelo : schemas.CriarGrupoPermissoes
        O parâmetro recebe os schemas de CriarGrupoPermissoes com todos os campos necessários para realizar o relaciomento
        e passa para o método que ira fazer o cadastro
    current_user : schemas.UsuarioBase
        O parâmetro usa a subclasse Security do Depends, que aceita um parãmetro a mais que é o scopes.
        Dentro da subclasse Security, o parâmetro vai chamar um método para verificar as permissões e o usuário.
        O scopes determina quais permissões o usuário deve ter para pode acessar esse endpoint

    Returns
    -------
    JSON
        O retorno trás o resultado do método criar_grupo_permissoes()
    """
    return cruds.criar_grupo_permissoes(modelo)


router_permissao = APIRouter(tags=['Permissão'])


@router_permissao.get('/v1/permissao', response_model=List[schemas.PermissaoBase])
def mostrar_permissoes(current_user: schemas.UsuarioBase = Security(security.get_usuario_atual, scopes=[])):
    """Endpoint que mostra todos as permissões

    Parameters
    ----------
    current_user : schemas.UsuarioBase
        O parâmetro usa a subclasse Security do Depends, que aceita um parãmetro a mais que é o scopes.
        Dentro da subclasse Security, o parâmetro vai chamar um método para verificar as permissões e o usuário.
        O scopes determina quais permissões o usuário deve ter para pode acessar esse endpoint

    Returns
    -------
    JSON
        O retorno trás o retorno do método mostrar_permissoes)
    """
    return cruds.mostrar_permissoes()


@router_permissao.get('/v1/permissao/{permissao}', response_model=schemas.PermissaoBase)
def mostrar_permissao(permissao: str, current_user: schemas.UsuarioBase = Security(security.get_usuario_atual, scopes=[])):
    """Endpoint que mostra apenas uma permissão

    Parameters
    ----------
    permissao : str
        O parâmetro recebe o nome da permissao e passa para o método que ira fazer as validações
    current_user : schemas.UsuarioBase
        O parâmetro usa a subclasse Security do Depends, que aceita um parãmetro a mais que é o scopes.
        Dentro da subclasse Security, o parâmetro vai chamar um método para verificar as permissões e o usuário.
        O scopes determina quais permissões o usuário deve ter para pode acessar esse endpoint

    Returns
    -------
    JSON
        O retorno trás o resultado do método mostrar_permissao()
    """
    return cruds.mostrar_permissao(permissao)


@router_permissao.post('/v1/permissao', response_model=schemas.PermissaoBase)
def criar_permissao(modelo: schemas.CriarPermissao, current_user: schemas.UsuarioBase = Security(security.get_usuario_atual, scopes=[])):
    """Endpoint que cria uma permissão

    Parameters
    ----------
    modelo : schemas.CriarPermissao
        O parâmetro recebe os schemas de CriarPermissao com todos os campos necessários para realizar o cadastro
        e passa para o método que ira fazer o cadastro
    current_user : schemas.UsuarioBase
        O parâmetro usa a subclasse Security do Depends, que aceita um parãmetro a mais que é o scopes.
        Dentro da subclasse Security, o parâmetro vai chamar um método para verificar as permissões e o usuário.
        O scopes determina quais permissões o usuário deve ter para pode acessar esse endpoint

    Returns
    -------
    JSON
        O retorno trás o resultado do método criar_permissao()
    """
    return cruds.criar_permissao(modelo)


@router_permissao.put('/v1/permissao/{id}')
def editar_permissao(permissao: str, modelo: schemas.CriarPermissao, current_user: schemas.UsuarioBase = Security(security.get_usuario_atual, scopes=[])):
    """Endpoint que edita uma permissão

    Parameters
    ----------
    permissão : str
        O parâmetro recebe o nome da permissão e passa para o método que ira fazer as validações
    modelo : schemas.CriarPermissao
        O parâmetro recebe os schemas de CriarPermissao com todos os campos necessários para realizar a edição
        e passa para o método que ira fazer a atualização
    current_user : schemas.UsuarioBase
        O parâmetro usa a subclasse Security do Depends, que aceita um parãmetro a mais que é o scopes.
        Dentro da subclasse Security, o parâmetro vai chamar um método para verificar as permissões e o usuário.
        O scopes determina quais permissões o usuário deve ter para pode acessar esse endpoint

    Returns
    -------
    JSON
        O retorno trás o resultado do método editar_permissao()
    """
    return cruds.editar_permissao(permissao, modelo)


@router_permissao.delete('/v1/permissao/{id}')
def deletar_permissao(permissao: str, current_user: schemas.UsuarioBase = Security(security.get_usuario_atual, scopes=[])):
    """Endpoint que exclui uma permissão

    Parameters
    ----------
    permissao : str
        O parâmetro recebe o nome da permissao e passa para o método que ira fazer as validações
    current_user : schemas.UsuarioBase
        O parâmetro usa a subclasse Security do Depends, que aceita um parãmetro a mais que é o scopes.
        Dentro da subclasse Security, o parâmetro vai chamar um método para verificar as permissões e o usuário.
        O scopes determina quais permissões o usuário deve ter para pode acessar esse endpoint

    Returns
    -------
    JSON
        O retorno trás o resultado do método deletar_permissao()
    """
    return cruds.deletar_permissao(permissao)
