const knex = require('../conexao');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const cadastrarUsuario = async (req, res) => {
    const { nome, email, senha } = req.body;

    if (!nome) {
        return res.status(400).json({ mensagem: 'O campo nome é obrigatório!' });
    }

    if (!email) {
        return res.status(400).json({ mensagem: 'O campo email é obrigatório!' });
    }

    if (!senha) {
        return res.status(400).json({ mensagem: 'O campo senha é obrigatório!' });
    }

    try {
        const consulta = await knex('usuarios').where('email', email);

        if (consulta.length > 0) {
            return res.status(400).json({ mensagem: 'Já existe usuário com o e-mail informado.' });
        }

        const senhaCriptografada = await bcrypt.hash(senha, 10);

        const insercao = await knex('usuarios').insert({ nome, email, senha: senhaCriptografada });

        if (insercao.rowCount === 0) {
            return res.status(400).json({ mensagem: 'Não foi possível cadastrar o usuário.' });
        }

        const usuario = await knex('usuarios').where('email', email).first();

        const { senha: senhaUsuario, ...dadosUsuario } = usuario;

        return res.status(200).json(dadosUsuario);

    } catch (error) {
        return res.status(400).json(error.message);
    }
}

const efetuarLogin = async (req, res) => {
    const { email, senha } = req.body;

    if (!email || !senha) {
        return res.status(400).json({ mensagem: 'E-mail e senha são obrigatórios!' });
    }

    try {
        const usuario = await knex('usuarios').where('email', email).first();

        if (!usuario) {
            return res.status(404).json({ mensagem: 'Usuário não encontrado.' });
        }

        const senhaVerificada = await bcrypt.compare(senha, usuario.senha);

        if (!senhaVerificada) {
            return res.status(401).json({ mensagem: 'Usuário e/ou senha inválido(s).' });
        }

        const token = jwt.sign({ id: usuario.id }, process.env.JWT_SECRET, { expiresIn: '8h' });

        const { senha: senhaUsuario, ...dadosUsuario } = usuario;

        return res.status(200).json({
            usuario: dadosUsuario,
            token
        });

    } catch (error) {
        return res.status(400).json(error.message);
    }
}

const detalharPerfilUsuario = async (req, res) => {
    const { usuario } = req;

    try {
        return res.status(200).json(usuario);
    } catch (error) {
        return res.status(400).json(error.message);
    }
}

const atualizarPerfilUsuario = async (req, res) => {
    const { nome, email, senha } = req.body;
    const { usuario } = req;

    if (!nome) {
        return res.status(400).json({ mensagem: 'O campo nome é obrigatório!' });
    }

    if (!email) {
        return res.status(400).json({ mensagem: 'O campo email é obrigatório!' });
    }

    if (!senha) {
        return res.status(400).json({ mensagem: 'O campo senha é obrigatório!' });
    }

    try {
        const consulta = await knex('usuarios').where('id', '!=', usuario.id).andWhere('email', email);

        if (consulta.length > 0) {
            return res.status(400).json({ mensagem: 'O e-mail informado já está sendo utilizado por outro usuário.' });
        }

        const senhaCriptografada = await bcrypt.hash(senha, 10);

        const update = await knex('usuarios').update({ nome, email, senha: senhaCriptografada }).where('id', usuario.id).returning('*');

        if (update.length === 0) {
            return res.status(400).json({ mensagem: 'Não foi possível atualizar o usuário.' });
        }

        return res.status(200).json();

    } catch (error) {
        return res.status(400).json(error.message);
    }
}

module.exports = {
    cadastrarUsuario,
    efetuarLogin,
    detalharPerfilUsuario,
    atualizarPerfilUsuario
}