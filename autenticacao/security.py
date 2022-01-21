from datetime import datetime, timedelta
from typing import Optional

from autenticacao import models

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, SecurityScopes

from passlib.context import CryptContext

from jose import jwt, JWTError, ExpiredSignatureError

SECRET_KEY = 'd41988ea8dbc99a14401f9739361caf15a2951431c83103686f80ac87d4cd65b'
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 100


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/v1/autenticacao")


def gerar_senha_hash(senha):
    """Gerando o hash da senha

    Parameters
    ----------
    senha : str
        O parâmetro espera a senha informada pelo usuário

    Returns
    -------
    str
        Retorna a senha informa na forma de hash
    """
    return pwd_context.hash(senha)


def verificar_senha(hashed_senha, senha):
    """Verificando a senha com a hash

    Parameters
    ----------
    hashed_senha : bool
        Senha salva no banco
    senha : str
        Senha informada pelo usuário

    Returns
    -------
    bool
        Retorna um booleano dizendo se as senhas coincidem
    """
    return pwd_context.verify(senha, hashed_senha)  


def criar_token_acesso(data: dict, expires_delta: Optional[timedelta] = None):
    """Criar token de acesso do usuário

    Parameters
    ----------
    data : dict
        Recebendo um dicionário trazendo o nome do usuário autenticado

    Returns
    -------
    str
        Retorna o token, criado através do nome do usuário, o tempo de expiração
        a chave secreta é o algoritmo HS256
    """
    
    to_encode = data.copy()
    # Cria um tempo de expiração do token padrão caso não tenha um valor definido
    if expires_delta:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

    return encoded_jwt


def verificar_token(token: str, credentials_exception):
    """Verificar o usuário pelo token

    Parameters
    ----------
    token : str
        O token criado na autenticação

    Returns
    -------
    str
        Usuário do token
    """
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        nome_usuario: str = payload.get("sub")
        # tempo_expiracao: datetime = payload.get("")
        if nome_usuario is None:
            raise credentials_exception
        return nome_usuario
    except ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='Token expirado')
    except JWTError:
        raise credentials_exception
    except Exception as e:
        raise e

#TODO: Fazer validações
def get_usuario(nome_usuario: str):
    """Pegar o usuário salvo no banco

    Parameters
    ----------
    nome_usuario : str
        Nome do usuário para ser buscado na base de dados

    Returns
    -------
    dict
        Trazendo o usuário completo da base
    """
    db_usuario = models.Usuario.objects(nome_usuario__exact=nome_usuario).first()
    return db_usuario


#TODO: Trocar o valor do parâmetro para um dict
def get_permissoes(usuario: models.Usuario):
    """Pegando as permissões

    Parameters
    ----------
    usuario : models.Usuario
        Usuário do banco

    Returns
    -------
    list
        Lista com todas as permissões do usuário
    """
    lista = []
    for grupos in usuario.grupos:
        for permissoes in grupos.permissoes:
            lista.append(permissoes.permissao)
    
    for permissoes in usuario.permissoes:
        lista.append(permissoes.permissao)

    return lista


def get_usuario_atual(security: SecurityScopes, token: str = Depends(oauth2_scheme)):
    """Pegar o usuário atual e validar as permissões

    Parameters
    ----------
    security : SecurityScopes
        Permissões passadas no endpoint
    data : str
        Depende do usuário estar autenticado
    """
    
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Não se pode validar as credenciais",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    usuario_verificado = verificar_token(token, credentials_exception)
    
    usuario = get_usuario(usuario_verificado)
    lista_scopes = get_permissoes(usuario)
    
    for scopes in security.scopes:
        if not scopes in lista_scopes:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Vocẽ não tem permissão para acessar tal conteúdo"
            )
