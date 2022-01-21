from pydantic import BaseModel

"""
Os schemas servem para validar os dados passados pelos endpoints, tanto para validar uma requisição quanto para um retorno de dado.
"""
class CriarUsuarioGrupos(BaseModel):
    nome_usuario: str
    grupo: str


class CriarUsuarioPermissoes(BaseModel):
    nome_usuario: str
    permissao: str


class CriarGrupoPermissoes(BaseModel):
    grupo: str
    permissao: str


class PermissaoBase(BaseModel):
    permissao: str
    
    class Config():
        orm_mode = True


class CriarPermissao(PermissaoBase):
    pass


class GrupoBase(BaseModel):
    grupo: str

    class Config():
        orm_mode = True    


class CriarGrupo(GrupoBase):
    pass


class UsuarioBase(BaseModel):
    nome_usuario: str
    ativo: bool

    class Config():
        orm_mode = True


class CriarUsuario(UsuarioBase):
    senha: str


# class MostrarUsuario(UsuarioBase):
#     pass


# class MostrarGrupo(GrupoBase):
#     pass
