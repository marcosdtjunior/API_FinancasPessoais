create database dindin;

create table usuarios (
    id serial primary key unique,
    nome varchar(60) not null,
    email varchar(60) not null unique,
    senha text not null
);

create table categorias (
   id serial primary key unique,
   descricao varchar(40) not null
);

create table transacoes (
   id serial primary key unique,
   descricao text not null,
   valor integer not null,
   data timestamp not null default now(),
   categoria_id integer not null,
   usuario_id integer not null,
   foreign key (categoria_id) references categorias(id),
   foreign key (usuario_id) references usuarios(id),
   tipo varchar(20) not null
);

insert into categorias (descricao) values ('Alimentação');
insert into categorias (descricao) values ('Assinaturas e Serviços');
insert into categorias (descricao) values ('Casa');
insert into categorias (descricao) values ('Mercado');
insert into categorias (descricao) values ('Cuidados Pessoais');
insert into categorias (descricao) values ('Educação');
insert into categorias (descricao) values ('Família');
insert into categorias (descricao) values ('Lazer');
insert into categorias (descricao) values ('Pets');
insert into categorias (descricao) values ('Presentes');
insert into categorias (descricao) values ('Roupas');
insert into categorias (descricao) values ('Saúde');
insert into categorias (descricao) values ('Transporte');
insert into categorias (descricao) values ('Salário');
insert into categorias (descricao) values ('Vendas');
insert into categorias (descricao) values ('Outras receitas');
insert into categorias (descricao) values ('Outras despesas');