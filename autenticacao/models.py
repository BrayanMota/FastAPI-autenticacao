from mongoengine import connect
from mongoengine.document import Document
from mongoengine.fields import StringField, BooleanField, ListField, ReferenceField
from mongoengine import PULL

connect(db="mydb", host="localhost", port=27017, alias="mydb-alias")


class Permissao(Document):
    permissao = StringField()

    meta = {"db_alias" : "mydb-alias" , "collection" : "permissao"}


class Grupo(Document):
    grupo = StringField()
    
    permissoes = ListField(ReferenceField('Permissao', reverse_delete_rule=PULL))
    
    meta = {"db_alias" : "mydb-alias" , "collection" : "grupo"}


class Usuario(Document):
    nome_usuario = StringField()
    ativo = BooleanField()
    senha = StringField()
    
    grupos = ListField(ReferenceField('Grupo', reverse_delete_rule=PULL))
    permissoes = ListField(ReferenceField('Permissao', reverse_delete_rule=PULL))

    meta = {"db_alias" : "mydb-alias" , "collection" : "usuario"}
