const conexao = require('../conexao');

const listarTransacoes = async (req, res) => {
    const { usuario } = req;

    try {
        const transacoes = await conexao.query('select t.id, t.tipo, t.descricao, t.valor, t.data, t.usuario_id, t.categoria_id, c.descricao as categoria_nome from transacoes t join categorias c on t.categoria_id = c.id where t.usuario_id = $1 order by t.id', [usuario.id]);

        return res.status(200).json(transacoes.rows);
    } catch (error) {
        return res.status(400).json(error.message);
    }
}

const detalharTransacao = async (req, res) => {
    const { usuario } = req;
    const { id: idTransacao } = req.params;

    try {

        const transacaoId = await conexao.query('select * from transacoes where id = $1', [idTransacao]);

        if (transacaoId.rowCount === 0) {
            return res.status(404).json({ mensagem: 'Esta transação não existe no banco de dados.' });
        }

        const transacaoUsuario = await conexao.query('select * from transacoes where usuario_id = $1', [usuario.id]);

        if (transacaoUsuario.rowCount === 0) {
            return res.status(404).json({ mensagem: 'Não existe transação para o usuário autenticado.' });
        }

        const consulta = await conexao.query('select t.id, t.tipo, t.descricao, t.valor, t.data, t.usuario_id, t.categoria_id, c.descricao as categoria_nome from transacoes t join categorias c on t.categoria_id = c.id where t.id = $1 and t.usuario_id = $2', [idTransacao, usuario.id]);

        if (consulta.rowCount === 0) {
            return res.status(404).json({ mensagem: 'Esta transação não pertence ao usuário autenticado.' });
        }

        return res.status(200).json(consulta.rows[0]);
    } catch (error) {
        return res.status(400).json(error.message);
    }
}

const cadastrarTransacao = async (req, res) => {
    const { descricao, valor, data, categoria_id, tipo } = req.body;
    const { usuario } = req;

    if (!descricao || !valor || !data || !categoria_id || !tipo) {
        return res.status(400).json({ mensagem: 'Todos os campos obrigatórios devem ser informados.' });
    }

    if (tipo !== 'entrada' && tipo !== 'saida') {
        return res.status(400).json({ mensagem: `O campo 'tipo' aceita apenas os valores 'entrada' ou 'saida'.` });
    }

    try {
        const consultaCategoria = await conexao.query('select * from categorias where id = $1', [categoria_id]);

        if (consultaCategoria.rowCount === 0) {
            return res.status(404).json({ mensagem: 'Categoria não encontrada.' });
        }

        const insercao = await conexao.query('insert into transacoes (descricao, valor, data, categoria_id, tipo, usuario_id) values ($1, $2, $3, $4, $5, $6)', [descricao, valor, data, categoria_id, tipo, usuario.id]);

        if (insercao.rowCount === 0) {
            return res.status(400).json({ mensagem: 'Não foi possível cadastrar a transação.' });
        }

        const consultaTransacao = await conexao.query('select t.id, t.tipo, t.descricao, t.valor, t.data, t.usuario_id, t.categoria_id, c.descricao as categoria_nome from transacoes t join categorias c on t.categoria_id = c.id where t.usuario_id = $1 order by t.id desc limit 1', [usuario.id]);

        return res.status(200).json(consultaTransacao.rows[0]);
    } catch (error) {
        return res.status(400).json(error.message);
    }
}

const atualizarTransacao = async (req, res) => {
    const { descricao, valor, data, categoria_id, tipo } = req.body;
    const { usuario } = req;
    const { id: idTransacao } = req.params;

    if (!descricao || !valor || !data || !categoria_id || !tipo) {
        return res.status(400).json({ mensagem: 'Todos os campos obrigatórios devem ser informados.' });
    }

    if (tipo !== 'entrada' && tipo !== 'saida') {
        return res.status(400).json({ mensagem: `O campo 'tipo' aceita apenas os valores 'entrada' ou 'saida'.` });
    }

    try {
        const consultaId = await conexao.query('select * from transacoes where id = $1', [idTransacao]);

        if (consultaId.rowCount === 0) {
            return res.status(404).json({ mensagem: 'Esta transação não existe no banco de dados.' });
        }

        const consultaUsuario = await conexao.query('select * from transacoes where id = $1 and usuario_id = $2', [idTransacao, usuario.id]);

        if (consultaUsuario.rowCount === 0) {
            return res.status(404).json({ mensagem: 'Esta transação não pertence ao usuário autenticado.' });
        }

        const consultaCategoria = await conexao.query('select * from categorias where id = $1', [categoria_id]);

        if (consultaCategoria.rowCount === 0) {
            return res.status(404).json({ mensagem: 'Categoria não encontrada.' });
        }

        const atualizacao = await conexao.query('update transacoes set descricao = $1, valor = $2, data = $3, categoria_id = $4, tipo = $5 where id = $6 and usuario_id = $7', [descricao, valor,
            data, categoria_id, tipo, idTransacao, usuario.id]);

        if (atualizacao.rowCount === 0) {
            return res.status(404).json({ mensagem: 'Não foi possível atualizar a transação.' });
        }

        return res.status(200).json();
    } catch (error) {
        return res.status(400).json(error.message);
    }
}

const excluirTransacao = async (req, res) => {
    const { usuario } = req;
    const { id: idTransacao } = req.params;

    try {
        const transacaoId = await conexao.query('select * from transacoes where id = $1', [idTransacao]);

        if (transacaoId.rowCount === 0) {
            return res.status(404).json({ mensagem: 'Esta transação não existe no banco de dados.' });
        }

        const transacaoUsuario = await conexao.query('select * from transacoes where id = $1 and usuario_id = $2', [idTransacao, usuario.id]);

        if (transacaoUsuario.rowCount === 0) {
            return res.status(404).json({ mensagem: 'Esta transação não pertence ao usuário autenticado.' });
        }

        const exclusao = await conexao.query('delete from transacoes where id = $1 and usuario_id = $2', [idTransacao, usuario.id]);

        if (exclusao.rowCount === 0) {
            return res.status(400).json({ mensagem: 'Não foi possível excluir a transação.' });
        }

        return res.status(200).json();
    } catch (error) {
        return res.status(400).json(error.message);
    }
}

const obterExtrato = async (req, res) => {
    const { usuario } = req;

    try {
        const entradas = await conexao.query(`select sum(valor) as total from transacoes where usuario_id = $1 and tipo = 'entrada'`, [usuario.id]);

        let somaEntradas = 0;
        if (entradas.rows[0].total !== null) {
            somaEntradas = Number.parseInt(entradas.rows[0].total);
        }

        const saidas = await conexao.query(`select sum(valor) as total from transacoes where usuario_id = $1 and tipo = 'saida'`, [usuario.id]);

        let somaSaidas = 0;
        if (saidas.rows[0].total !== null) {
            somaSaidas = Number.parseInt(saidas.rows[0].total);
        }

        const extrato = {
            entrada: somaEntradas,
            saida: somaSaidas
        };

        return res.status(200).json(extrato);
    } catch (error) {
        return res.status(400).json(error.message);
    }
}

module.exports = {
    listarTransacoes,
    detalharTransacao,
    cadastrarTransacao,
    atualizarTransacao,
    excluirTransacao,
    obterExtrato
}