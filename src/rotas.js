const express = require('express');
const usuarios = require('./controladores/usuarios');
const verificaLogin = require('./filtros/verificaLogin');
const categorias = require('./controladores/categorias');
const transacoes = require('./controladores/transacoes');

const rotas = express();

// usuários
rotas.post('/usuario', usuarios.cadastrarUsuario);
rotas.post('/login', usuarios.efetuarLogin);

rotas.use(verificaLogin);

// A partir daqui, todas as rotas necessitam de autenticação do usuário
rotas.get('/usuario', usuarios.detalharPerfilUsuario);
rotas.put('/usuario', usuarios.atualizarPerfilUsuario);

// categorias
rotas.get('/categoria', categorias.listarCategorias);

// transações
rotas.get('/transacao', transacoes.listarTransacoes);
rotas.get('/transacao/extrato', transacoes.obterExtrato);
rotas.get('/transacao/:id', transacoes.detalharTransacao);
rotas.post('/transacao', transacoes.cadastrarTransacao);
rotas.put('/transacao/:id', transacoes.atualizarTransacao);
rotas.delete('/transacao/:id', transacoes.excluirTransacao);

module.exports = rotas;